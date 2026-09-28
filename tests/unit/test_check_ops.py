"""check reconcile / version / verify-chain (NFR-7, FR-48, §17.1), with a fake HTTP layer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from audit_logging import check
from audit_logging.semantic import integrity
from audit_logging.semantic.integrity import Chain
from audit_logging.semantic.model import SCHEMA_VERSION


class Resp:
    def __init__(self, status: int, body: Any) -> None:
        self.status_code, self._body, self.text = status, body, json.dumps(body)

    def json(self) -> Any:
        return self._body


class FakeHTTP:
    """`counts` maps pid -> indexed; `template` is the installed _meta (None: 404);
    `hits` are the _source documents a search returns."""

    def __init__(self, counts: dict[int, int] | None = None, template: dict[str, Any] | None = None,
                 hits: list[dict[str, Any]] | None = None, page: int = 1000) -> None:
        self.counts, self.template, self.hits, self.page = counts or {}, template, hits or [], page
        self.calls: list[tuple[str, Any]] = []
        self.closed = False

    def get(self, path: str, **kw: Any) -> Resp:
        self.calls.append((path, None))
        if self.template is None:
            return Resp(404, {})
        return Resp(200, {"index_templates": [{"name": "t", "index_template": {"_meta": self.template}}]})

    def post(self, path: str, json: Any = None, **kw: Any) -> Resp:
        self.calls.append((path, json))
        if path.endswith("/_count"):
            terms = {k: v for f in json["query"]["bool"]["filter"] for k, v in f.get("term", {}).items()}
            return Resp(200, {"count": self.counts.get(terms["process.pid"], 0)})
        start = 0 if "search_after" not in json else json["search_after"][0]
        chunk = self.hits[start:start + self.page]
        return Resp(200, {"hits": {"hits": [
            {"_source": h, "sort": [start + i + 1]} for i, h in enumerate(chunk)]}})

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AUDIT_SERVICE_NAME", "ops-api")
    monkeypatch.setenv("AUDIT_DATASET", "ops_api")
    monkeypatch.setenv("AUDIT_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_ELASTICSEARCH_URL", "http://es.invalid:9200")
    return tmp_path


def use(monkeypatch: pytest.MonkeyPatch, http: FakeHTTP) -> FakeHTTP:
    monkeypatch.setattr(check, "_client", lambda config: http)
    return http


def write(path: Path, docs: list[Any], tail: str = "") -> None:
    with path.open("a") as fh:
        for d in docs:
            fh.write((d if isinstance(d, str) else json.dumps(d)) + "\n")
        fh.write(tail)


# -- reconcile ---------------------------------------------------------------


def test_reconcile_counts_per_pid_and_passes_when_all_indexed(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write(env / "ops-api-11.jsonl", [{"process": {"pid": 11}}] * 3, tail='{"partial')
    write(env / "ops-api-11.jsonl.1", [{"process": {"pid": 11}}])
    write(env / "ops-api-22.jsonl", ["not json", {"n": 1}])      # pid from the file name
    write(env / "other-api-33.jsonl", [{"process": {"pid": 33}}])  # another service: ignored
    http = use(monkeypatch, FakeHTTP(counts={11: 4, 22: 2}))
    assert check.main(["reconcile"]) == 0
    out = capsys.readouterr().out
    assert [line.split() for line in out.splitlines()[1:3]] == [
        ["11", "4", "4", "0"], ["22", "2", "2", "0"]]
    assert "33" not in out
    assert http.closed
    assert {c[0] for c in http.calls} == {"/logs-ops_api-dev/_count"}


def test_reconcile_counts_only_this_host_service_and_time_span(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pids repeat across pods and restarts: the count is scoped to this service, the
    host that wrote the files, and the time span still on disk (review: pid-only)."""
    write(env / "ops-api-7.jsonl", [
        {"process": {"pid": 7}, "host": {"hostname": "pod-a"}, "@timestamp": "2026-09-28T10:00:00.000Z"},
        {"process": {"pid": 7}, "host": {"hostname": "pod-a"}, "@timestamp": "2026-09-28T09:00:00.000999Z"},
        {"process": {"pid": 7}, "host": {"hostname": "pod-a"}, "@timestamp": "2026-09-28T11:00:00.000Z"},
    ])
    http = use(monkeypatch, FakeHTTP(counts={7: 3}))
    assert check.main(["reconcile"]) == 0
    (query,) = [c[1]["query"] for c in http.calls if c[0].endswith("/_count")]
    assert query == {"bool": {"filter": [
        {"term": {"process.pid": 7}},
        {"term": {"service.name": "ops-api"}},
        {"term": {"host.hostname": "pod-a"}},
        {"range": {"@timestamp": {"gte": "2026-09-28T09:00:00.000Z", "lte": "2026-09-28T11:00:00.000Z"}}},
    ]}}


def test_reconcile_fails_beyond_tolerance(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write(env / "ops-api-11.jsonl", [{"process": {"pid": 11}}] * 5)
    use(monkeypatch, FakeHTTP(counts={11: 3}))
    assert check.main(["reconcile"]) == 1
    assert "FAIL" in capsys.readouterr().out
    assert check.main(["reconcile", "--tolerance", "2"]) == 0


def test_reconcile_an_unreachable_cluster_fails_cleanly(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write(env / "ops-api-11.jsonl", [{"process": {"pid": 11}}])

    class Down(FakeHTTP):
        def post(self, path: str, json: Any = None, **kw: Any) -> Resp:
            raise OSError("connection refused")

    use(monkeypatch, Down())
    assert check.main(["reconcile"]) == 1
    assert "cannot count" in capsys.readouterr().out


def test_reconcile_needs_an_elasticsearch_url(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AUDIT_ELASTICSEARCH_URL", "none")
    assert check.main(["reconcile"]) == 1


# -- version -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("template", "code", "shown"),
    [
        ({"schema_version": SCHEMA_VERSION}, 0, SCHEMA_VERSION),
        ({"schema_version": "1"}, 1, "1"),
        ({}, 1, "none (0.1 template)"),
        (None, 1, "not installed"),
    ],
)
def test_version_reports_installed_vs_package(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    template: dict[str, Any] | None, code: int, shown: str,
) -> None:
    http = use(monkeypatch, FakeHTTP(template=template))
    assert check.main(["version"]) == code
    out = capsys.readouterr().out
    assert f"installed : {shown}" in out and f"package   : {SCHEMA_VERSION}" in out
    assert http.calls[0][0] == "/_index_template/logs-ops_api"


# -- verify-chain ------------------------------------------------------------


def chained(n: int) -> list[dict[str, Any]]:
    chain = Chain("ops-api", 11, 1)
    return [chain.stamp({"n": i, "event": {"id": f"e{i}"}}) for i in range(n)]


def test_verify_chain_from_files(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write(env / "ops-api-11.jsonl", chained(3))
    assert check.main(["verify-chain", "--from-files"]) == 0
    assert "every chain verifies" in capsys.readouterr().out

    docs = chained(3)
    docs[1]["n"] = 99  # tampered
    (env / "ops-api-11.jsonl").write_text("".join(json.dumps(d) + "\n" for d in docs))
    assert check.main(["verify-chain", "--from-files"]) == 1
    assert "BROKEN   ops-api-11-1:2 hash mismatch" in capsys.readouterr().out


def test_verify_chain_a_rotated_away_head_is_info_unless_genesis_is_required(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write(env / "ops-api-11.jsonl", chained(5)[2:])  # ops-api-11.jsonl.1 was pruned
    assert check.main(["verify-chain", "--from-files"]) == 0
    assert "TRUNCATED ops-api-11-1 starts at seq 3" in capsys.readouterr().out
    assert check.main(["verify-chain", "--from-files", "--require-genesis"]) == 1


def test_verify_chain_from_files_works_without_elasticsearch(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUDIT_ELASTICSEARCH_URL", "none")
    write(env / "ops-api-11.jsonl", chained(2))
    assert check.main(["verify-chain", "--from-files"]) == 0


def test_verify_chain_from_elasticsearch_pages_and_undoes_the_skew_tag(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    docs = chained(5)
    for d in docs:
        d["event"]["ingested"] = "2026-09-28T06:00:00.000Z"
    docs[2]["audit"]["clock_skew_ms"] = 600000   # what the shipper adds (FR-41)
    docs[2]["tags"] = ["clock_skew"]
    http = use(monkeypatch, FakeHTTP(hits=docs[::-1], page=2))
    monkeypatch.setattr(check, "_PAGE", 2)
    assert check.main(["verify-chain"]) == 0
    out = capsys.readouterr().out
    assert "documents : 5" in out and "every chain verifies" in out
    searches = [body for path, body in http.calls if path.endswith("/_search")]
    assert len(searches) == 3 and "search_after" in searches[1]
    assert searches[0]["query"] == {"exists": {"field": "audit.integrity.chain"}}


def test_unship_keeps_other_tags() -> None:
    doc = {"audit": {"clock_skew_ms": 1, "x": 1}, "tags": ["enrich_timeout", "clock_skew"]}
    assert check._unship(doc) == {"audit": {"x": 1}, "tags": ["enrich_timeout"]}
    assert doc["audit"]["clock_skew_ms"] == 1, "the input must not be mutated"


def test_verify_chain_with_no_chained_documents_warns(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write(env / "ops-api-11.jsonl", [{"n": 1}])
    assert check.main(["verify-chain", "--from-files"]) == 0
    assert "AUDIT_INTEGRITY_ENABLED" in capsys.readouterr().out


def test_verify_chain_reports_an_unbuilt_integrity_module(
    env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def stub(docs: Any, **kw: Any) -> Any:
        raise NotImplementedError

    monkeypatch.setattr(integrity, "verify", stub)
    write(env / "ops-api-11.jsonl", chained(1))
    assert check.main(["verify-chain", "--from-files"]) == 2
    assert "not implemented" in capsys.readouterr().out
