"""Round-2 gate: a real uvicorn app shipping to a real Elasticsearch 8.13.4.

Run through ``scripts/live_es_gate.sh``, which starts the container, exports
``GATE_ES_URL`` / ``GATE_ES_PASSWORD`` and removes everything afterwards.
Without ``GATE_ES_URL`` the module skips.

The tests share one scenario and run in file order: requests -> stored once ->
field checks -> restart without shipper offsets -> ``check`` CLI -> a document
Elasticsearch refuses.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
ES_URL = os.environ.get("GATE_ES_URL", "")
ES_PASSWORD = os.environ.get("GATE_ES_PASSWORD", "")
SERVICE = "gate2-api"
INDEX = "logs-gate2-dev"
XFF_CLIENT = "203.0.113.7"
SESSION_ID = "sess-gate2-001"
TRACE_ID = "trace-gate2-001"


# ---------------------------------------------------------------------------
# The application under test (imported by uvicorn: --factory ...:create_app)
# ---------------------------------------------------------------------------


def create_app() -> Any:
    from fastapi import FastAPI, HTTPException

    from audit_logging import AuditConfig, AuditMiddleware, QueryClause, TargetSpec, audit, audited
    from audit_logging.metrics import InMemoryMetrics

    def user(scope: dict[str, Any]) -> dict[str, Any]:
        return {"id": "u-7", "name": "sardor", "full_name": "Sardor Karimov", "roles": ["Admin"]}

    config = AuditConfig(user_resolver=user)  # type: ignore[call-arg]  # rest from AUDIT_*
    metrics = InMemoryMetrics()
    app = FastAPI()

    @app.put("/users/{user_id}")
    @audited(
        "admin.user.updated",
        uz="{actor} «{target}» foydalanuvchisini tahrirladi",
        category="admin",
        risk="high",
        target=TargetSpec(type="user", id="path.user_id"),
        diff=True,
    )
    async def update_user(user_id: int) -> dict[str, Any]:
        audit.target(label="Aliyev Vali")
        audit.diff({"role": "Operator"}, {"role": "Admin"}, labels={"role": "Rol"})
        audit.identify(pinpp="12345678901234", msisdn="90 123 45 67")
        return {"ok": True}

    @app.get("/profiles/search")
    @audited("profile.list.searched", uz="{actor} profillarni qidirdi", category="search", risk="normal")
    async def search() -> dict[str, Any]:
        audit.query(
            [
                QueryClause(field="region", operator="eq", value="Toshkent", label="Viloyat"),
                QueryClause(field="age", operator="gte", value=30, label="Yosh"),
            ],
            datasource="clickhouse",
            tables=["profiles"],
        )
        return {"hits": 0}

    @app.get("/secret")
    async def secret() -> None:
        raise HTTPException(status_code=403, detail="no")

    @app.post("/jobs")
    async def jobs() -> dict[str, Any]:
        audit.emit("system.job.started", uz="Eksport vazifasi boshlandi", category="system")
        return {"queued": True}

    @app.get("/_gate/metrics")
    async def gate_metrics() -> dict[str, float]:
        return metrics.snapshot()

    app.add_middleware(AuditMiddleware, config=config, metrics=metrics)
    return app


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class Gate:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.log_dir = tmp / "audit"
        self.log_dir.mkdir()
        self.proc: subprocess.Popen[bytes] | None = None
        self.port = 0
        self.logs: list[Path] = []
        self.es = httpx.Client(base_url=ES_URL, auth=("elastic", ES_PASSWORD), verify=False, timeout=30)
        self.ids: dict[str, str] = {}  # scenario name -> event.id

    @property
    def env(self) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("AUDIT_")}
        env.update(
            AUDIT_SERVICE_NAME=SERVICE,
            AUDIT_DATASET="gate2",
            AUDIT_ELASTICSEARCH_URL=ES_URL,
            AUDIT_ELASTICSEARCH_USERNAME="elastic",
            AUDIT_ELASTICSEARCH_PASSWORD=ES_PASSWORD,
            AUDIT_ELASTICSEARCH_VERIFY_CERTS="false",
            AUDIT_LOG_DIR=str(self.log_dir),
            AUDIT_INTEGRITY_ENABLED="true",
            AUDIT_TRUSTED_PROXIES="127.0.0.1/32",
            AUDIT_EXCLUDE_PATHS="/_gate",
            AUDIT_FLUSH_INTERVAL_SECONDS="0.1",
            AUDIT_SHIP_INTERVAL_SECONDS="0.5",
        )
        return env

    def start(self) -> None:
        self.port = 59810 + len(self.logs)
        log = self.tmp / f"app-{len(self.logs)}.log"
        self.logs.append(log)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "--factory",
             "tests.integration.test_semantic_live_es:create_app",
             "--host", "127.0.0.1", "--port", str(self.port), "--log-level", "warning",
             # uvicorn's default proxy_headers rewrites scope["client"] from XFF for
             # 127.0.0.1 itself; the package then sees the client as the peer and
             # reports ip_source "peer". Off, so AUDIT_TRUSTED_PROXIES does the work.
             "--no-proxy-headers"],
            cwd=ROOT, env=self.env, stdout=log.open("wb"), stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                httpx.get(f"{self.url}/_gate/metrics", timeout=1)
                return
            except httpx.HTTPError:
                time.sleep(0.2)
        raise AssertionError("app did not start: " + log.read_text()[-500:])

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def call(self, method: str, path: str, **kw: Any) -> httpx.Response:
        return httpx.request(method, f"{self.url}{path}", timeout=10, **kw)

    def metrics(self) -> dict[str, float]:
        return dict(self.call("GET", "/_gate/metrics").json())

    def disk_docs(self) -> list[dict[str, Any]]:
        docs = []
        for path in sorted(self.log_dir.glob("*.jsonl*")):
            docs += [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        return docs

    def search(self, body: dict[str, Any]) -> dict[str, Any]:
        self.es.post(f"/{INDEX}/_refresh")
        response = self.es.post(f"/{INDEX}/_search", json=body)
        assert response.status_code == 200, response.text[:300]
        return dict(response.json())

    def es_count(self) -> int:
        self.es.post(f"/{INDEX}/_refresh")
        response = self.es.get(f"/{INDEX}/_count")
        return int(response.json().get("count", -1)) if response.status_code == 200 else -1

    def wait_count(self, expected: int, timeout: float = 60) -> int:
        deadline = time.monotonic() + timeout
        count = -1
        while time.monotonic() < deadline:
            count = self.es_count()
            if count >= expected:
                time.sleep(1.5)  # one more ship tick: would anything extra arrive?
                return self.es_count()
            time.sleep(0.5)
        return count

    def all_hits(self) -> list[dict[str, Any]]:
        return list(self.search({"size": 1000, "query": {"match_all": {}}})["hits"]["hits"])

    def by_id(self, event_id: str) -> dict[str, Any]:
        hits = self.search({"query": {"term": {"event.id": event_id}}})["hits"]["hits"]
        assert len(hits) == 1, f"{event_id}: {len(hits)} hits"
        return dict(hits[0])

    def check(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "audit_logging.check", *args],
            cwd=self.tmp, env=self.env, capture_output=True, text=True, timeout=60,
        )


@pytest.fixture(scope="module")
def gate(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Gate]:
    if not ES_URL:
        pytest.skip("GATE_ES_URL not set (run scripts/live_es_gate.sh)")
    g = Gate(tmp_path_factory.mktemp("gate2"))
    g.start()
    try:
        xff = {"X-Forwarded-For": f"{XFF_CLIENT}, 127.0.0.1"}
        g.call("PUT", "/users/2", json={"role": "Admin"}, headers={
            **xff, "X-Session-Id": SESSION_ID, "X-Trace-Id": TRACE_ID})
        g.call("GET", "/profiles/search", params={"region": "Toshkent"}, headers=xff)
        assert g.call("GET", "/secret", headers=xff).status_code == 403
        g.call("POST", "/jobs", headers=xff)
        time.sleep(0.5)
        for doc in g.disk_docs():
            key = doc.get("event", {}).get("action") or "?"
            g.ids[key] = doc["event"]["id"]
        g.wait_count(len(g.disk_docs()))
        yield g
    finally:
        g.stop()
        g.es.close()


def _leaves(value: Any, prefix: str = "") -> Iterator[str]:
    if isinstance(value, dict):
        for key, sub in value.items():
            yield from _leaves(sub, f"{prefix}.{key}" if prefix else key)
    elif isinstance(value, list):
        for sub in value:
            yield from _leaves(sub, prefix)
    else:
        yield prefix


def _mapped(mapping: dict[str, Any], path: str) -> bool:
    node: dict[str, Any] = {"properties": mapping}
    for part in path.split("."):
        if node.get("enabled") is False or node.get("type") in ("flattened", "object") and "properties" not in node:
            return True  # stored-only / flattened subtree: mapped by design
        props = node.get("properties") or {}
        if part not in props:
            return False
        node = props[part]
    return True


# ---------------------------------------------------------------------------
# Criteria
# ---------------------------------------------------------------------------


def test_every_record_stored_exactly_once(gate: Gate) -> None:
    disk = gate.disk_docs()
    assert gate.es_count() == len(disk) >= 5
    hits = gate.all_hits()
    assert sorted(h["_id"] for h in hits) == sorted(d["event"]["id"] for d in disk)
    assert all(h["_id"] == h["_source"]["event"]["id"] for h in hits)


def test_msisdn_normalised(gate: Gate) -> None:
    src = gate.by_id(gate.ids["admin.user.updated"])["_source"]
    assert src["audit"]["target"]["msisdn"] == "+998901234567"
    assert src["audit"]["target"]["pinpp"] == "12345678901234"
    found = gate.search({"query": {"term": {"audit.target.msisdn": "+998901234567"}}})
    assert found["hits"]["total"]["value"] == 1


def test_nested_query_clause_searchable(gate: Gate) -> None:
    body: dict[str, Any] = {"query": {"nested": {"path": "audit.query.normalized", "query": {"bool": {"must": [
        {"term": {"audit.query.normalized.field": "region"}},
        {"term": {"audit.query.normalized.operator": "eq"}},
    ]}}}}}
    hits = gate.search(body)["hits"]["hits"]
    assert [h["_id"] for h in hits] == [gate.ids["profile.list.searched"]]
    # nested really is nested: field of one clause + operator of the other must not match
    body["query"]["nested"]["query"]["bool"]["must"][1]["term"]["audit.query.normalized.operator"] = "gte"
    assert gate.search(body)["hits"]["total"]["value"] == 0


def test_session_and_trace_ids(gate: Gate) -> None:
    src = gate.by_id(gate.ids["admin.user.updated"])["_source"]
    assert src["audit"]["session"]["id"] == SESSION_ID
    assert src["trace"]["id"] == TRACE_ID
    assert gate.search({"query": {"term": {"audit.session.id": SESSION_ID}}})["hits"]["total"]["value"] == 1
    assert gate.search({"query": {"term": {"trace.id": TRACE_ID}}})["hits"]["total"]["value"] == 1


def test_client_ip_from_trusted_proxy(gate: Gate) -> None:
    for key in ("admin.user.updated", "profile.list.searched"):
        src = gate.by_id(gate.ids[key])["_source"]
        assert src["client"]["ip"] == XFF_CLIENT
        assert src["audit"]["client"]["ip_source"] == "x_forwarded_for"


def test_denied_and_emit_records(gate: Gate) -> None:
    denied = [h["_source"] for h in gate.all_hits() if h["_source"].get("http", {}).get("response", {}).get("status_code") == 403]
    assert len(denied) == 1 and denied[0]["audit"]["result"] == "denied"
    emitted = gate.by_id(gate.ids["system.job.started"])["_source"]
    assert emitted["audit"]["level"] == "emit"


def test_no_unmapped_leaves(gate: Gate) -> None:
    mapping = gate.es.get(f"/{INDEX}/_mapping").json()
    props: dict[str, Any] = {}
    for index in mapping.values():
        props.update(index["mappings"]["properties"])
    unmapped = sorted({p for h in gate.all_hits() for p in _leaves(h["_source"]) if not _mapped(props, p)})
    assert unmapped == []


def test_message_brace_free_uzbek(gate: Gate) -> None:
    messages = [h["_source"].get("message", "") for h in gate.all_hits()]
    assert all(m and "{" not in m and "}" not in m for m in messages), messages
    assert "foydalanuvchisini tahrirladi" in gate.by_id(gate.ids["admin.user.updated"])["_source"]["message"]


def test_restart_without_offsets_no_duplicates(gate: Gate) -> None:
    before = gate.es_count()
    gate.stop()
    states = list(gate.log_dir.glob(".audit-shipper-*.json"))
    assert states, "no shipper offset file to delete"
    for state in states:
        state.unlink()
    gate.start()
    gate.call("GET", "/profiles/search", headers={"X-Forwarded-For": XFF_CLIENT})
    time.sleep(0.5)  # flush interval
    disk = gate.disk_docs()
    assert len(disk) == before + 1
    assert gate.wait_count(len(disk)) == len(disk)
    # the new process re-read the old file from offset 0 (409s count as delivered)
    assert gate.metrics().get("audit_ship_documents_total", 0) >= len(disk)
    dupes = gate.search({"size": 0, "aggs": {"d": {"terms": {"field": "event.id", "min_doc_count": 2}}}})
    assert dupes["aggregations"]["d"]["buckets"] == []


def test_check_verify_chain(gate: Gate) -> None:
    out = gate.check("verify-chain")
    assert out.returncode == 0 and "every chain verifies" in out.stdout, out.stdout[-400:]
    assert "chains    : 2" in out.stdout  # one per process (before and after restart)


def test_check_reconcile(gate: Gate) -> None:
    out = gate.check("reconcile")
    assert out.returncode == 0, out.stdout[-400:]


def test_check_version(gate: Gate) -> None:
    out = gate.check("version")
    assert out.returncode == 0, out.stdout[-400:]
    lines = dict(line.split(":", 1) for line in out.stdout.splitlines() if ":" in line)
    assert lines["installed "].strip() == lines["package   "].strip() == "2"


def test_refused_document_skipped_not_dead_lettered(gate: Gate) -> None:
    assert gate.proc is not None
    before = gate.es_count()
    active = gate.log_dir / f"{SERVICE}-{gate.proc.pid}.jsonl"
    assert active.exists(), sorted(p.name for p in gate.log_dir.iterdir())
    bad_id = uuid.uuid4().hex
    bad = {"@timestamp": "not-a-date", "event": {"id": bad_id}, "message": "gate2 injected"}
    fd = os.open(active, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, (json.dumps(bad) + "\n").encode())
    finally:
        os.close(fd)
    gate.call("GET", "/profiles/search")
    gate.call("POST", "/jobs")
    time.sleep(0.5)
    assert gate.wait_count(before + 3) == before + 3  # search + job request + emitted job record
    assert gate.search({"query": {"term": {"event.id": bad_id}}})["hits"]["total"]["value"] == 0
    snap = gate.metrics()
    assert snap.get("audit_ship_rejected_total") == 1
    assert snap.get("audit_documents_lost_total", 0) >= 1
    assert "refused a document" in gate.logs[-1].read_text()
    names = [p.name for p in gate.log_dir.iterdir()]
    assert not [n for n in names if "dead" in n.lower() or "reject" in n.lower()], names
