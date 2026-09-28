"""FR-35 — the built-in shipper, without a cluster.

The shipper's whole point is that it does not change the promise the package
makes: records reach a local file first, and Elasticsearch being unreachable
must not reach the application. These tests hold it to that.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from audit_logging.config import AuditConfig
from audit_logging.metrics import InMemoryMetrics
from audit_logging.shipper import ElasticsearchShipper, _pid_is_alive


def cfg(tmp_path: Path, **kw: Any) -> AuditConfig:
    values: dict[str, Any] = {
        "service_name": "ship-api",
        "dataset": "ship_api",
        "log_dir": tmp_path,
        "elasticsearch_url": "http://127.0.0.1:59999",  # nothing listens here
        "ship_interval_seconds": 0.05,
    }
    values.update(kw)
    return AuditConfig(**values)


class FakeResponse:
    def __init__(self, status: int = 200, body: dict | None = None) -> None:
        self.status_code = status
        self._body = body if body is not None else {"errors": False, "items": []}
        self.text = json.dumps(self._body)

    def json(self) -> dict:
        return self._body


class FakeClient:
    """Records what would have been sent."""

    def __init__(self, response: FakeResponse | None = None) -> None:
        self.posts: list[bytes] = []
        self.puts: list[str] = []
        self._response = response or FakeResponse()

    async def post(self, path: str, content: bytes = b"", **kw: Any) -> FakeResponse:
        self.posts.append(content)
        return self._response

    async def put(self, path: str, **kw: Any) -> FakeResponse:
        self.puts.append(path)
        return FakeResponse()

    async def get(self, path: str, **kw: Any) -> FakeResponse:
        return FakeResponse(404, {"index_templates": []})

    async def aclose(self) -> None:
        return None

    @property
    def lines(self) -> list[dict]:
        out = []
        for payload in self.posts:
            for raw in payload.split(b"\n"):
                if raw.strip() and b'"create"' not in raw:
                    out.append(json.loads(raw))
        return out


def write_log(tmp_path: Path, pid: int, count: int, name: str = "ship-api") -> Path:
    path = tmp_path / f"{name}-{pid}.jsonl"
    with path.open("w") as fh:
        for i in range(count):
            fh.write(json.dumps({"n": i, "trace": {"id": f"t{i}"}}) + "\n")
    return path


async def test_FR_35_ships_the_lines_the_sink_already_wrote(tmp_path: Path) -> None:
    import os

    write_log(tmp_path, os.getpid(), 3)
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    client = FakeClient()
    shipper._client = client
    shipper._bootstrapped = True
    await shipper._tick()
    assert [d["n"] for d in client.lines] == [0, 1, 2]


async def test_FR_35_a_second_pass_does_not_resend(tmp_path: Path) -> None:
    """Progress is by (device, inode), so a rotation cannot cause a replay."""
    import os

    write_log(tmp_path, os.getpid(), 3)
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    shipper._client = FakeClient()
    shipper._bootstrapped = True
    await shipper._tick()
    client = FakeClient()
    shipper._client = client
    await shipper._tick()
    assert client.lines == [], "already-shipped lines were sent again"


async def test_FR_35_a_partial_line_is_left_for_the_next_tick(tmp_path: Path) -> None:
    """The sink may be mid-write; half a document must never be shipped."""
    import os

    path = tmp_path / f"ship-api-{os.getpid()}.jsonl"
    path.write_text('{"n":0}\n{"n":1}\n{"n":2,"incompl')
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    client = FakeClient()
    shipper._client = client
    shipper._bootstrapped = True
    await shipper._tick()
    assert [d["n"] for d in client.lines] == [0, 1]


async def test_FR_35_an_unreachable_cluster_is_survivable(tmp_path: Path) -> None:
    """The real failure mode. Nothing raises; the offset does not advance, so
    the lines are still there when the cluster comes back."""
    import os

    write_log(tmp_path, os.getpid(), 5)
    metrics = InMemoryMetrics()
    shipper = ElasticsearchShipper(cfg(tmp_path), metrics)
    shipper._bootstrapped = True
    await shipper._tick()  # nothing is listening on port 59999
    assert shipper._state == {} or all(v == 0 for v in shipper._state.values())

    client = FakeClient()
    shipper._client = client
    await shipper._tick()
    assert [d["n"] for d in client.lines] == [0, 1, 2, 3, 4], "records were lost"


async def test_FR_35_it_refuses_to_ship_until_the_template_exists(
    tmp_path: Path,
) -> None:
    """D-11 is unrecoverable, so this is the one failure it will not push past.

    Shipping into a cluster without the template creates a data stream with a
    dynamic mapping, and only a reindex fixes that.
    """
    import os

    write_log(tmp_path, os.getpid(), 2)

    class RefusingClient(FakeClient):
        async def put(self, path: str, **kw: Any) -> FakeResponse:
            self.puts.append(path)
            return FakeResponse(400, {"error": "nope"})

    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    client = RefusingClient()
    shipper._client = client
    await shipper._tick()
    assert shipper._bootstrapped is False
    assert client.posts == [], "shipped despite the template install failing"


async def test_FR_35_does_not_steal_a_live_workers_file(tmp_path: Path) -> None:
    """One file per PID, several workers per pod. Shipping another live
    worker's file would duplicate every one of its records."""
    import os

    write_log(tmp_path, os.getpid(), 2)
    write_log(tmp_path, 1, 2)  # pid 1 is alive in every namespace
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    claimed = {p.name for p in shipper._claimable_files()}
    assert f"ship-api-{os.getpid()}.jsonl" in claimed
    assert "ship-api-1.jsonl" not in claimed


async def test_FR_35_adopts_a_dead_workers_file(tmp_path: Path) -> None:
    """...but a crashed worker's tail must not sit on disk forever."""
    dead = 2**22 - 1  # above /proc/sys/kernel/pid_max on any normal system
    write_log(tmp_path, dead, 2)
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    assert not _pid_is_alive(dead)
    assert f"ship-api-{dead}.jsonl" in {p.name for p in shipper._claimable_files()}


async def test_FR_35_a_rejected_document_does_not_block_the_ones_behind_it(
    tmp_path: Path,
) -> None:
    """A document Elasticsearch will never accept must not wedge the stream."""
    import os

    write_log(tmp_path, os.getpid(), 3)
    metrics = InMemoryMetrics()
    shipper = ElasticsearchShipper(cfg(tmp_path), metrics)
    shipper._bootstrapped = True
    shipper._client = FakeClient(
        FakeResponse(200, {"errors": True, "items": [{"create": {"status": 400, "error": {"reason": "bad"}}}]})
    )
    await shipper._tick()
    assert metrics.snapshot().get("audit_ship_rejected_total", 0) >= 1
    # The offset advanced, so the next tick moves on rather than retrying.
    assert any(v > 0 for v in shipper._state.values())


def test_FR_35_no_shipper_without_a_url(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="elasticsearch_url"):
        ElasticsearchShipper(
            AuditConfig(service_name="s", dataset="s", elasticsearch_url=None, log_dir=tmp_path)
        )


async def test_rollover_and_retention_reach_the_installed_policy(tmp_path: Path) -> None:
    """The knobs are useless if the shipper installs the file's defaults."""
    import os

    write_log(tmp_path, os.getpid(), 1)
    sent: list[dict] = []

    class Capturing(FakeClient):
        async def put(self, path: str, **kw: Any) -> FakeResponse:
            self.puts.append(path)
            if "_ilm" in path:
                sent.append(kw["json"])
            return FakeResponse()

    shipper = ElasticsearchShipper(
        cfg(tmp_path, rollover_max_age="1d", rollover_max_size="10gb", retention_days=30)
    )
    shipper._client = Capturing()
    await shipper._tick()
    hot = sent[0]["policy"]["phases"]["hot"]["actions"]["rollover"]
    assert hot["max_age"] == "1d"
    assert hot["max_primary_shard_size"] == "10gb"
    assert sent[0]["policy"]["phases"]["delete"]["min_age"] == "30d"


@pytest.mark.parametrize(
    ("retention", "expect_delete"),
    [(90, True), (None, False), ("never", False), (0, False), (365, True)],
)
async def test_retention_never_drops_the_delete_phase(
    tmp_path: Path, retention: Any, expect_delete: bool
) -> None:
    """An audit trail under a retention obligation must be able to keep everything.

    Deleting evidence on a timer is the one failure here you cannot undo, so
    "never" has to be expressible — not approximated with a large number.
    """
    import os

    write_log(tmp_path, os.getpid(), 1)
    sent: list[dict] = []

    class Capturing(FakeClient):
        async def put(self, path: str, **kw: Any) -> FakeResponse:
            if "_ilm" in path:
                sent.append(kw["json"])
            return FakeResponse()

    shipper = ElasticsearchShipper(cfg(tmp_path, retention_days=retention))
    shipper._client = Capturing()
    await shipper._tick()
    phases = sent[0]["policy"]["phases"]
    assert ("delete" in phases) is expect_delete
    if expect_delete:
        assert phases["delete"]["min_age"] == f"{int(retention)}d"


async def test_size_only_rollover_drops_max_age(tmp_path: Path) -> None:
    """Weekly, daily, or purely by size — all three have to be expressible."""
    import os

    write_log(tmp_path, os.getpid(), 1)
    sent: list[dict] = []

    class Capturing(FakeClient):
        async def put(self, path: str, **kw: Any) -> FakeResponse:
            if "_ilm" in path:
                sent.append(kw["json"])
            return FakeResponse()

    shipper = ElasticsearchShipper(
        cfg(tmp_path, rollover_max_age=None, rollover_max_size="20gb")
    )
    shipper._client = Capturing()
    await shipper._tick()
    rollover = sent[0]["policy"]["phases"]["hot"]["actions"]["rollover"]
    assert rollover == {"max_primary_shard_size": "20gb"}


def test_both_rollover_triggers_off_is_refused(tmp_path: Path) -> None:
    """One backing index taking every document forever hits Lucene's 2.1bn
    document limit and then refuses writes, far too late to reindex."""
    with pytest.raises(ValidationError, match="cannot both be disabled"):
        AuditConfig(
            service_name="s", dataset="s", elasticsearch_url=None, log_dir=tmp_path,
            rollover_max_age=None, rollover_max_size=None,
        )


async def test_state_is_per_process_not_per_directory(tmp_path: Path) -> None:
    """Several uvicorn workers share a log directory.

    A single shared state file was overwritten by each worker from its own
    in-memory copy every tick, so they clobbered each other's offsets —
    records re-shipped or skipped, and the file churned constantly.
    """
    import os

    a = ElasticsearchShipper(cfg(tmp_path))
    assert str(os.getpid()) in a._state_path.name


async def test_state_is_only_written_when_it_changed(tmp_path: Path) -> None:
    """An idle service rewrote this file every tick, forever."""
    import os

    write_log(tmp_path, os.getpid(), 2)
    shipper = ElasticsearchShipper(cfg(tmp_path))
    shipper._client = FakeClient()
    shipper._bootstrapped = True
    await shipper._tick()
    assert shipper._state_path.exists()
    first = shipper._state_path.stat().st_mtime_ns

    await shipper._tick()          # nothing new to ship
    await shipper._tick()
    assert shipper._state_path.stat().st_mtime_ns == first, "rewrote an unchanged file"


async def test_only_one_worker_adopts_an_orphaned_file(tmp_path: Path) -> None:
    """Otherwise every live worker ships a dead worker's file — one copy each."""
    dead = 2**22 - 1
    write_log(tmp_path, dead, 3)

    a = ElasticsearchShipper(cfg(tmp_path))
    b = ElasticsearchShipper(cfg(tmp_path))
    claimed_a = {p.name for p in a._claimable_files()}
    claimed_b = {p.name for p in b._claimable_files()}

    orphan = f"ship-api-{dead}.jsonl"
    assert (orphan in claimed_a) != (orphan in claimed_b), (
        "exactly one shipper must take the orphan, not both and not neither"
    )


async def test_upgrading_inherits_offsets_instead_of_reshipping(tmp_path: Path) -> None:
    """The per-process split must not duplicate everything already indexed.

    Older versions wrote one shared `.audit-shipper-state.json`. Without
    inheriting it, the first tick after an upgrade reads every existing file
    from offset 0 and re-sends every record already in Elasticsearch.
    """
    import os

    path = write_log(tmp_path, os.getpid(), 5)
    already = path.stat().st_size
    key = f"{path.stat().st_dev}:{path.stat().st_ino}"
    (tmp_path / ".audit-shipper-state.json").write_text(json.dumps({key: already}))

    shipper = ElasticsearchShipper(cfg(tmp_path))
    client = FakeClient()
    shipper._client = client
    shipper._bootstrapped = True
    shipper._load_state()
    await shipper._tick()
    assert client.lines == [], "re-shipped records that were already sent"


async def test_an_adopted_orphan_resumes_where_the_dead_worker_stopped(tmp_path: Path) -> None:
    """Four gunicorn workers per pod, and every restart orphans four files.

    The dead worker's offsets are in its own `.audit-shipper-{pid}.json`. Read
    from zero instead, and every record already indexed from that file is sent
    again -- the bulk action carries no `_id`, so Elasticsearch keeps both.
    """
    dead = 2**22 - 1
    path = write_log(tmp_path, dead, 5)
    with path.open("rb") as fh:
        shipped = len(fh.readline()) + len(fh.readline())
    key = f"{path.stat().st_dev}:{path.stat().st_ino}"
    (tmp_path / f".audit-shipper-{dead}.json").write_text(json.dumps({key: shipped}))

    shipper = ElasticsearchShipper(cfg(tmp_path))
    client = FakeClient()
    shipper._client = client
    shipper._bootstrapped = True
    shipper._load_state()
    await shipper._tick()

    assert [d["n"] for d in client.lines] == [2, 3, 4], "re-sent what the dead worker had already shipped"


async def test_an_orphan_with_no_state_left_behind_ships_whole(tmp_path: Path) -> None:
    """Adoption must not swallow a file whose worker died before shipping any of it."""
    dead = 2**22 - 2
    write_log(tmp_path, dead, 3)

    shipper = ElasticsearchShipper(cfg(tmp_path))
    client = FakeClient()
    shipper._client = client
    shipper._bootstrapped = True
    shipper._load_state()
    await shipper._tick()

    assert [d["n"] for d in client.lines] == [0, 1, 2]


async def test_a_dead_workers_state_file_goes_only_once_its_logs_do(tmp_path: Path) -> None:
    """Otherwise it is one more stale JSON per restart, forever, beside the logs.

    It cannot go earlier than that: the offsets in it are what an orphan is
    adopted at, and another worker may not have claimed its share of that
    worker's files yet.
    """
    still_has_logs = 2**22 - 3
    write_log(tmp_path, still_has_logs, 2)
    kept = tmp_path / f".audit-shipper-{still_has_logs}.json"
    kept.write_text(json.dumps({"1:2": 10}))

    logs_all_rotated_away = 2**22 - 4
    reaped = tmp_path / f".audit-shipper-{logs_all_rotated_away}.json"
    reaped.write_text(json.dumps({"3:4": 10}))

    legacy = tmp_path / ".audit-shipper-state.json"
    legacy.write_text(json.dumps({"5:6": 10}))

    shipper = ElasticsearchShipper(cfg(tmp_path))
    shipper._client = FakeClient()
    shipper._bootstrapped = True
    shipper._load_state()
    await shipper._tick()

    assert not reaped.exists(), "kept a dead worker's state file with no files left to adopt"
    assert kept.exists(), "deleted the offsets an unclaimed orphan is still adopted at"
    assert legacy.exists(), "deleted the file older versions' offsets are inherited from"
    assert shipper._state_path.exists(), "reaped its own state file"


async def test_a_fresh_install_with_no_legacy_file_still_ships(tmp_path: Path) -> None:
    """The inheritance must not swallow a genuinely new file."""
    import os

    write_log(tmp_path, os.getpid(), 3)
    shipper = ElasticsearchShipper(cfg(tmp_path))
    client = FakeClient()
    shipper._client = client
    shipper._bootstrapped = True
    shipper._load_state()
    await shipper._tick()
    assert [d["n"] for d in client.lines] == [0, 1, 2]


async def test_state_forgets_files_that_no_longer_exist(tmp_path: Path) -> None:
    """Rotation deletes files constantly. Without pruning, the state file grows
    by one entry per file forever — daily rollover with no retention means a
    new entry every day, in a file rewritten on every change."""
    import os

    path = write_log(tmp_path, os.getpid(), 2)
    shipper = ElasticsearchShipper(cfg(tmp_path))
    shipper._client = FakeClient()
    shipper._bootstrapped = True
    await shipper._tick()
    assert len(shipper._state) == 1

    path.unlink()
    await shipper._tick()
    assert shipper._state == {}, "kept an offset for a file that is gone"


async def test_pruning_keeps_another_live_workers_offset(tmp_path: Path) -> None:
    """Prune on existence, not on claimability.

    Another live worker's file is not claimable by us — but when that worker
    dies we adopt it, and a pruned offset restarts it from zero and duplicates
    every record it holds.
    """
    import os

    write_log(tmp_path, os.getpid(), 2)
    other = write_log(tmp_path, 1, 4)          # pid 1 is alive everywhere
    other_key = f"{other.stat().st_dev}:{other.stat().st_ino}"

    shipper = ElasticsearchShipper(cfg(tmp_path))
    shipper._client = FakeClient()
    shipper._bootstrapped = True
    shipper._state[other_key] = 999            # as if inherited
    await shipper._tick()

    assert other_key in shipper._state, "dropped a live worker's offset"
    assert shipper._state[other_key] == 999


# -- 0.2 delivery guarantees (FR-36, FR-37, FR-41) ---------------------------


def write_v2_log(tmp_path: Path, ids: list[str]) -> Path:
    import os

    path = tmp_path / f"ship-api-{os.getpid()}.jsonl"
    with path.open("a") as fh:
        for i, doc_id in enumerate(ids):
            fh.write(json.dumps({"n": i, "event": {"id": doc_id, "action": "a.b"}}) + "\n")
    return path


def actions(client: FakeClient) -> list[dict]:
    return [
        json.loads(raw)
        for payload in client.posts
        for raw in payload.split(b"\n")
        if b'"create"' in raw
    ]


class FakeES(FakeClient):
    """Keeps the _ids it has indexed; answers a repeat with 409, and any
    document whose `n` is in `refuse` with a mapping error."""

    def __init__(self, refuse: frozenset[int] = frozenset()) -> None:
        super().__init__()
        self.indexed: dict[str, dict] = {}
        self.refuse = refuse

    async def post(self, path: str, content: bytes = b"", **kw: Any) -> FakeResponse:
        self.posts.append(content)
        rows = [json.loads(r) for r in content.split(b"\n") if r.strip()]
        items = []
        for action, doc in zip(rows[::2], rows[1::2]):
            doc_id = action["create"].get("_id")
            if doc.get("n") in self.refuse:
                items.append({"create": {"status": 400, "error": {
                    "type": "mapper_parsing_exception", "reason": "failed to parse field [n] of wrong type"}}})
            elif doc_id in self.indexed:
                items.append({"create": {"status": 409, "error": {"type": "version_conflict_engine_exception"}}})
            else:
                self.indexed[doc_id or f"auto{len(self.indexed)}"] = doc
                items.append({"create": {"status": 201}})
        errors = any(i["create"]["status"] >= 300 for i in items)
        return FakeResponse(200, {"errors": errors, "items": items})


def shipper_with(tmp_path: Path, client: FakeClient) -> tuple[ElasticsearchShipper, InMemoryMetrics]:
    metrics = InMemoryMetrics()
    shipper = ElasticsearchShipper(cfg(tmp_path), metrics)
    shipper._client = client
    shipper._bootstrapped = True
    return shipper, metrics


async def test_FR_36_event_id_is_sent_as_the_bulk_id(tmp_path: Path) -> None:
    write_v2_log(tmp_path, ["id-a", "id-b"])
    client = FakeClient()
    shipper, _ = shipper_with(tmp_path, client)
    await shipper._tick()
    index = shipper.config.index_name
    assert actions(client) == [
        {"create": {"_index": index, "_id": "id-a"}},
        {"create": {"_index": index, "_id": "id-b"}},
    ]


async def test_FR_36_a_0_1_line_without_event_id_has_no_bulk_id(tmp_path: Path) -> None:
    import os

    write_log(tmp_path, os.getpid(), 2)
    client = FakeClient()
    shipper, _ = shipper_with(tmp_path, client)
    await shipper._tick()
    assert actions(client) == [{"create": {"_index": shipper.config.index_name}}] * 2


async def test_FR_36_a_409_counts_as_delivered_not_rejected(tmp_path: Path) -> None:
    write_v2_log(tmp_path, ["dup"])
    es = FakeES()
    es.indexed["dup"] = {}
    shipper, metrics = shipper_with(tmp_path, es)
    await shipper._tick()
    snap = metrics.snapshot()
    assert snap["audit_ship_documents_total"] == 1
    assert snap["audit_ship_rejected_total"] == 0
    assert not (tmp_path / "dead-letter").exists()


async def test_FR_36_a_replay_of_the_same_lines_creates_no_second_document(
    tmp_path: Path,
) -> None:
    write_v2_log(tmp_path, ["r1", "r2", "r3"])
    es = FakeES()
    first, _ = shipper_with(tmp_path, es)
    await first._tick()
    # A lost state file: a fresh shipper reads the whole file again.
    for state in tmp_path.glob(".audit-shipper-*.json"):
        state.unlink()
    second, metrics = shipper_with(tmp_path, es)
    await second._tick()
    assert sorted(es.indexed) == ["r1", "r2", "r3"]
    assert metrics.snapshot()["audit_ship_rejected_total"] == 0
    assert metrics.snapshot()["audit_ship_documents_total"] == 3


async def test_X_8_a_refused_document_is_counted_lost_and_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """X-8: no dead-letter file. A refused document is warned about once per
    error type with the ES error, counted rejected + lost, and skipped."""
    import logging

    write_v2_log(tmp_path, ["ok0", "bad1", "ok2"])
    shipper, metrics = shipper_with(tmp_path, FakeES(refuse=frozenset({1})))
    with caplog.at_level(logging.WARNING, logger="audit_logging.shipper"):
        await shipper._tick()
    snap = metrics.snapshot()
    assert snap["audit_ship_rejected_total"] == 1
    assert snap["audit_documents_lost_total"] == 1
    assert snap["audit_ship_documents_total"] == 2
    assert "audit_ship_dead_lettered_total" not in snap
    assert not (tmp_path / "dead-letter").exists()
    warned = [r.getMessage() for r in caplog.records]
    assert len(warned) == 1 and "mapper_parsing_exception" in warned[0]
    assert "field [n] of wrong type" in warned[0], "the ES reason must be in the log"

    # Skipped, not retried: the offset moved past it, and a second refusal of
    # the same error type is counted but not logged again.
    write_v2_log(tmp_path, ["bad-again"])  # n == 0, refuse {0} below
    shipper._client = FakeES(refuse=frozenset({0}))
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="audit_logging.shipper"):
        await shipper._tick()
    assert caplog.records == []
    assert metrics.snapshot()["audit_documents_lost_total"] == 2


async def test_X_8_each_error_type_is_warned_once_and_the_reason_is_truncated(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    class TwoKinds(FakeClient):
        async def post(self, path: str, content: bytes = b"", **kw: Any) -> FakeResponse:
            self.posts.append(content)
            items = [
                {"create": {"status": 400, "error": {"type": "mapper_parsing_exception", "reason": "x" * 1000}}},
                {"create": {"status": 400, "error": {"type": "mapper_parsing_exception", "reason": "again"}}},
                {"create": {"status": 400, "error": {"type": "illegal_argument_exception", "reason": "bad"}}},
            ]
            return FakeResponse(200, {"errors": True, "items": items})

    write_v2_log(tmp_path, ["a", "b", "c"])
    shipper, metrics = shipper_with(tmp_path, TwoKinds())
    with caplog.at_level(logging.WARNING, logger="audit_logging.shipper"):
        await shipper._tick()
    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 2
    assert any("illegal_argument_exception" in m and "bad" in m for m in messages)
    long = next(m for m in messages if "mapper_parsing_exception" in m)
    assert "x" * 400 in long and "x" * 401 not in long
    assert metrics.snapshot()["audit_documents_lost_total"] == 3
    assert metrics.snapshot()["audit_ship_rejected_total"] == 3


async def test_X_8_the_dead_letter_code_is_gone() -> None:
    from audit_logging import shipper as shipper_module

    assert not hasattr(shipper_module, "DEAD_LETTER_MAX_BYTES")
    assert not hasattr(ElasticsearchShipper, "_dead_letter")



async def test_FR_41_event_ingested_is_set_at_ship_time(tmp_path: Path) -> None:
    import os
    import re

    write_v2_log(tmp_path, ["i1"])
    path = tmp_path / f"ship-api-{os.getpid()}.jsonl"
    with path.open("a") as fh:
        fh.write("not json at all\n")
    client = FakeClient()
    shipper, _ = shipper_with(tmp_path, client)
    await shipper._tick()
    sent = [r for r in client.posts[0].split(b"\n") if r and b'"create"' not in r]
    doc = json.loads(sent[0])
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", doc["event"]["ingested"])
    assert doc["event"]["id"] == "i1"
    assert sent[1] == b"not json at all", "an unparseable line must ship unchanged"




def write_timed_log(tmp_path: Path, stamps: list[str], **extra: Any) -> None:
    import os

    path = tmp_path / f"ship-api-{os.getpid()}.jsonl"
    with path.open("a") as fh:
        for i, ts in enumerate(stamps):
            doc = {"@timestamp": ts, "n": i, "event": {"id": f"ts{i}"}, **extra}
            fh.write(json.dumps(doc) + "\n")


async def test_FR_41_a_skewed_record_is_tagged_with_its_signed_skew(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from audit_logging import shipper as shipper_module

    monkeypatch.setattr(shipper_module, "_now_iso_ms", lambda: "2026-09-28T06:00:00.000Z")
    write_timed_log(tmp_path, [
        "2026-09-28T05:59:59.500Z",   # 500 ms: fine
        "2026-09-28T05:50:00.000Z",   # shipped 10 min late: +600000
        "2026-09-28T06:10:00.250Z",   # clock ahead: -600250
        "not a date",
    ])
    client = FakeClient()
    shipper, _ = shipper_with(tmp_path, client)
    await shipper._tick()
    docs = client.lines
    assert "tags" not in docs[0] and "audit" not in docs[0]
    assert docs[1]["audit"]["clock_skew_ms"] == 600000 and docs[1]["tags"] == ["clock_skew"]
    assert docs[2]["audit"]["clock_skew_ms"] == -600250 and docs[2]["tags"] == ["clock_skew"]
    assert "tags" not in docs[3]


async def test_FR_41_skew_keeps_existing_tags_and_audit_and_honours_the_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from audit_logging import shipper as shipper_module

    monkeypatch.setattr(shipper_module, "_now_iso_ms", lambda: "2026-09-28T06:00:00.000Z")
    write_timed_log(tmp_path, ["2026-09-28T05:59:00.000Z"],
                    tags=["enrich_timeout"], audit={"route": "/x"})
    config = cfg(tmp_path)
    object.__setattr__(config, "max_clock_skew_s", 30)
    client = FakeClient()
    shipper = ElasticsearchShipper(config, InMemoryMetrics())
    shipper._client, shipper._bootstrapped = client, True
    await shipper._tick()
    doc = client.lines[0]
    assert doc["tags"] == ["enrich_timeout", "clock_skew"]
    assert doc["audit"] == {"route": "/x", "clock_skew_ms": 60000}


class TemplateES(FakeClient):
    """Answers GET /_index_template with a template carrying `version`, or 404."""

    def __init__(self, version: str | None) -> None:
        super().__init__()
        self.version = version

    async def get(self, path: str, **kw: Any) -> FakeResponse:
        if self.version is None:
            return FakeResponse(404, {"index_templates": []})
        meta = {"schema_version": self.version} if self.version != "absent" else {}
        return FakeResponse(200, {"index_templates": [
            {"name": "logs-ship_api", "index_template": {"_meta": meta}}]})


async def test_FR_48_a_template_of_another_schema_version_is_not_overwritten(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import logging
    import os

    write_log(tmp_path, os.getpid(), 2)
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    client = TemplateES("3")
    shipper._client = client
    with caplog.at_level(logging.ERROR, logger="audit_logging.shipper"):
        await shipper._tick()
        await shipper._tick()
    assert shipper._bootstrapped is False
    assert client.puts == [], "overwrote a template of another schema version"
    assert client.posts == [], "shipped under a foreign template"
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "schema_version" in errors[0].getMessage()


async def test_FR_48_schema_upgrade_overwrites_it(tmp_path: Path) -> None:
    import os

    write_log(tmp_path, os.getpid(), 1)
    config = cfg(tmp_path)
    object.__setattr__(config, "schema_upgrade", True)
    shipper = ElasticsearchShipper(config, InMemoryMetrics())
    client = TemplateES("3")
    shipper._client = client
    await shipper._tick()
    assert shipper._bootstrapped is True
    assert "/_index_template/logs-ship_api" in client.puts
    assert len(client.lines) == 1


@pytest.mark.parametrize("existing", [None, "2", "absent"])
async def test_FR_48_same_version_missing_template_or_0_1_template_installs(
    tmp_path: Path, existing: str | None
) -> None:
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    client = TemplateES(existing)
    shipper._client = client
    await shipper._tick()
    assert shipper._bootstrapped is True
    assert "/_index_template/logs-ship_api" in client.puts


async def test_FR_48_an_unreadable_existing_template_is_not_overwritten(tmp_path: Path) -> None:
    class Broken(FakeClient):
        async def get(self, path: str, **kw: Any) -> FakeResponse:
            return FakeResponse(503, {"error": "busy"})

    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    client = Broken()
    shipper._client = client
    await shipper._tick()
    assert shipper._bootstrapped is False and client.puts == []


async def test_NFR_3_bulk_stamping_runs_off_the_event_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    from audit_logging import shipper as shipper_module

    seen: list[int] = []
    real = shipper_module._stamp

    def spy(*args: Any) -> tuple[bytes, str | None]:
        seen.append(threading.get_ident())
        return real(*args)

    monkeypatch.setattr(shipper_module, "_stamp", spy)
    write_v2_log(tmp_path, ["s1"])
    shipper, _ = shipper_with(tmp_path, FakeClient())
    await shipper._tick()
    assert seen and threading.get_ident() not in seen


# --- FR-60: a template change reaches the live data stream ---------------------

class _MappingClient(FakeClient):
    def __init__(self, mapping_status: int = 200) -> None:
        super().__init__()
        self.mapping_status = mapping_status
        self.bodies: dict[str, Any] = {}

    async def put(self, path: str, **kw: Any) -> FakeResponse:
        self.puts.append(path)
        self.bodies[path] = kw.get("json")
        if "/_mapping" in path:
            return FakeResponse(self.mapping_status, {"acknowledged": self.mapping_status < 300})
        return FakeResponse()


async def test_FR_60_the_template_mapping_is_pushed_onto_the_existing_write_index(tmp_path: Path) -> None:
    """A template applies only when a backing index is CREATED. Seen live on
    2026-09-28: audit.context was in every stored document and in the template,
    but not in the data stream's current backing index, so it was not
    searchable and a folder-scoped reader saw nothing until the next rollover."""
    config = cfg(tmp_path)
    shipper = ElasticsearchShipper(config, InMemoryMetrics())
    client = _MappingClient()
    shipper._client = client
    await shipper._bootstrap()
    path = f"/{config.index_name}/_mapping?write_index_only=true"
    assert path in client.puts
    body = client.bodies[path]
    assert "context" in body["properties"]["audit"]["properties"]
    assert set(body) <= {"properties", "dynamic", "date_detection", "numeric_detection", "_meta"}
    assert shipper._bootstrapped


async def test_FR_60_no_data_stream_yet_is_fine(tmp_path: Path) -> None:
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    shipper._client = _MappingClient(mapping_status=404)
    await shipper._bootstrap()
    assert shipper._bootstrapped


async def test_FR_60_a_mapping_conflict_does_not_stop_shipping(tmp_path: Path, caplog: Any) -> None:
    """New fields are still stored (dynamic:false); only their search waits for
    the next rollover. That is worse than ideal, far better than not shipping."""
    shipper = ElasticsearchShipper(cfg(tmp_path), InMemoryMetrics())
    shipper._client = _MappingClient(mapping_status=400)
    with caplog.at_level("WARNING"):
        await shipper._bootstrap()
    assert shipper._bootstrapped
    assert "mapping" in caplog.text


async def test_FR_60_constant_keywords_are_not_pushed(tmp_path: Path) -> None:
    """Seen live: data_stream.namespace is a constant_keyword whose value the
    first document fixed ("live"); the template carries none, so pushing it
    failed the whole update with 'Cannot update parameter [value]'. A constant
    can never change anyway, so it is left out."""
    config = cfg(tmp_path)
    shipper = ElasticsearchShipper(config, InMemoryMetrics())
    client = _MappingClient()
    shipper._client = client
    await shipper._bootstrap()
    body = client.bodies[f"/{config.index_name}/_mapping?write_index_only=true"]

    def constants(props: dict[str, Any]) -> list[str]:
        found = []
        for name, spec in props.items():
            if spec.get("type") == "constant_keyword":
                found.append(name)
            found += constants(spec.get("properties", {}))
        return found

    assert constants(body["properties"]) == []
    assert "audit" in body["properties"]


# --- FR-61: lines left from an earlier dataset follow the current one ------------

async def test_FR_61_a_line_written_under_an_old_dataset_is_shipped_under_the_current_one(
    tmp_path: Path,
) -> None:
    """Seen live on 2026-09-28: ownercheck ran with AUDIT_DATASET=fortress, then
    was switched to ownercheck. The unshipped old lines went first into the new
    data stream, fixed its constant_keyword data_stream.dataset to "fortress",
    and every new record was then refused. The config decides where this
    service's records go, so every line is shipped with the current values."""
    import os

    config = cfg(tmp_path)
    path = tmp_path / f"ship-api-{os.getpid()}.jsonl"
    old = {"n": 0, "data_stream": {"type": "logs", "dataset": "fortress", "namespace": "old"},
           "event": {"id": "e0"}}
    new = {"n": 1, "data_stream": {"type": "logs", "dataset": config.data_stream_dataset,
                                   "namespace": config.data_stream_namespace}, "event": {"id": "e1"}}
    path.write_text(json.dumps(old) + "\n" + json.dumps(new) + "\n")
    shipper = ElasticsearchShipper(config, InMemoryMetrics())
    client = FakeClient()
    shipper._client = client
    shipper._bootstrapped = True
    await shipper._tick()
    shipped = {d["n"]: d["data_stream"] for d in client.lines}
    want = {"type": "logs", "dataset": config.data_stream_dataset,
            "namespace": config.data_stream_namespace}
    assert shipped == {0: want, 1: want}
