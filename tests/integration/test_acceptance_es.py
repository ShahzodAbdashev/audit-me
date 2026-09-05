"""Tier 1 — the acceptance criteria asserted against a real Elasticsearch.

Covers AC-01…AC-17 plus AC-18, AC-20 and AC-21 — the three of the post-review
criteria whose *point* is a behaviour only a cluster and a shipper have. The
rest of AC-18…AC-26 are decided in Tier 2 (`test_acceptance_local.py`), which
runs; see `tests/AC-matrix.md` §2 for which is which.

**This tier has NOT been executed.** The Docker daemon is unreachable from the
environment these tests were written in (``docker ps`` →
``permission denied ... /var/run/docker.sock``; the user is not in the
``docker`` group and ``sudo`` needs a password). Every test below is written to
run, and every test below is unverified. Treat a first green run as new
information, not as a formality — see ``tests/AC-matrix.md``.

What this tier covers that Tier 2 structurally cannot:

* **Filebeat.** The ``filestream`` input, the ``ndjson`` parser with
  ``target: ""`` and ``overwrite_keys: true`` (without which ``@timestamp``
  becomes the moment Filebeat read the line and every latency query is wrong),
  ``message_max_bytes`` and the **quarantine route that replaced
  ``drop_event``** — which is where review M-3 actually happened and where
  AC-20 is really settled — and the registry following a file across rotation
  (AC-12).
* **Routing.** ``index: "%{[data_stream.type]}-%{[dataset]}-%{[namespace]}"``
  resolving to a real data stream, and the data stream picking up the
  ``logs-apiaudit`` template rather than a dynamic mapping (D-11, R-1).
* **Elasticsearch itself.** ``dynamic: false`` really dropping a field,
  ``flattened`` really costing one mapping entry, and ``GET _mapping``'s field
  count — AC-10 against the thing that actually counts fields.

Run it::

    export AUDIT_TEST_LOG_DIR="$PWD/tests/integration/.stack/logs"
    mkdir -p "$AUDIT_TEST_LOG_DIR"
    docker compose -f tests/integration/docker-compose.test.yml up -d
    ./.venv/bin/python -m pytest tests/integration -q -m integration

See ``tests/integration/README.md`` for the full procedure and for what to look
at when a document does not arrive.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from audit_logging.config import AuditConfig
from audit_logging.metrics import InMemoryMetrics
from audit_logging.middleware import AuditMiddleware
from audit_logging.sinks.file_sink import FileSink

from ._apps import STREAM_CHUNKS, make_app, make_wide_app, wide_body
from ._es_double import ILM_PATH, TEMPLATE_PATH, load_template
from .conftest import IS_ROOT

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Where the stack is
# ---------------------------------------------------------------------------

ES_URL = os.environ.get("AUDIT_TEST_ES_URL", "http://127.0.0.1:9200").rstrip("/")
DEFAULT_LOG_DIR = Path(__file__).resolve().parent / ".stack" / "logs"
LOG_DIR = Path(os.environ.get("AUDIT_TEST_LOG_DIR", str(DEFAULT_LOG_DIR)))

INDEX_PATTERN = "logs-apiaudit.*-*"
ILM_POLICY_NAME = "apiaudit-ilm"
INDEX_TEMPLATE_NAME = "logs-apiaudit"

#: Generous on purpose (plan R-9: flakiness in this tier is the top schedule
#: risk). A line has to be noticed by `filestream`, batched, bulk-indexed, and
#: then made visible by a `refresh_interval: 10s` index. Nothing here sleeps a
#: fixed amount — every wait polls for the document it actually wants.
SHIP_TIMEOUT = float(os.environ.get("AUDIT_TEST_SHIP_TIMEOUT", "120"))
POLL_INTERVAL = 0.5

SKIP_REASON = (
    f"the acceptance stack is not up: nothing answered at {ES_URL}. "
    "Start it with `docker compose -f tests/integration/docker-compose.test.yml "
    "up -d` (see tests/integration/README.md), or set AUDIT_TEST_ES_URL."
)


# ---------------------------------------------------------------------------
# Elasticsearch, over plain HTTP — the package must not import a client (NFR-4)
# and neither, gratuitously, should its tests.
# ---------------------------------------------------------------------------


class Elasticsearch:
    """The eight REST calls these tests need. Not a client library."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.http = httpx.Client(base_url=url, timeout=30.0)

    def close(self) -> None:
        self.http.close()

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return self.http.request(method, path, **kwargs)

    def json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = self.request(method, path, **kwargs)
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        return payload

    # -- readiness ----------------------------------------------------------

    def wait_until_ready(self, timeout: float = 180.0) -> None:
        """Poll cluster health until it is at least yellow.

        Yellow, not green: the index template asks for one replica and the test
        stack is a single node, so every index is permanently yellow. Waiting
        for green would hang forever.
        """
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                health = self.json(
                    "GET", "/_cluster/health", params={"wait_for_status": "yellow", "timeout": "5s"}
                )
                if health.get("status") in ("yellow", "green"):
                    return
            except Exception as exc:  # noqa: BLE001 - a cold cluster fails many ways
                last = exc
            time.sleep(1.0)
        raise TimeoutError(f"Elasticsearch at {self.url} never became ready: {last}")

    # -- searching ----------------------------------------------------------

    def refresh(self) -> None:
        """Make everything indexed so far visible without waiting 10 s."""
        self.request("POST", f"/{INDEX_PATTERN}/_refresh", params={"ignore_unavailable": "true"})

    def search(self, body: dict[str, Any], size: int = 10) -> list[dict[str, Any]]:
        response = self.request(
            "POST",
            f"/{INDEX_PATTERN}/_search",
            params={"ignore_unavailable": "true", "size": size},
            json=body,
        )
        if response.status_code == 404:
            return []
        response.raise_for_status()
        hits: list[dict[str, Any]] = response.json()["hits"]["hits"]
        return [hit["_source"] for hit in hits]

    def by_trace(self, trace_id: str, size: int = 10) -> list[dict[str, Any]]:
        return self.search({"query": {"term": {"trace.id": trace_id}}}, size=size)

    def count(self, query: dict[str, Any] | None = None) -> int:
        body = {"query": query} if query else {}
        response = self.request(
            "POST", f"/{INDEX_PATTERN}/_count", params={"ignore_unavailable": "true"}, json=body
        )
        if response.status_code == 404:
            return 0
        response.raise_for_status()
        counted: int = response.json()["count"]
        return counted

    def wait_for_trace(
        self, trace_id: str, timeout: float = SHIP_TIMEOUT, expected: int = 1
    ) -> list[dict[str, Any]]:
        """Poll until *expected* documents carry this ``trace.id``.

        Polls for the document instead of sleeping for a guessed interval — the
        one thing that keeps this tier from being flaky (plan R-9).
        """
        deadline = time.monotonic() + timeout
        seen = 0
        while time.monotonic() < deadline:
            self.refresh()
            hits = self.by_trace(trace_id, size=max(expected, 10))
            seen = len(hits)
            if seen >= expected:
                return hits
            time.sleep(POLL_INTERVAL)
        raise AssertionError(
            f"trace.id={trace_id!r}: expected {expected} document(s) in Elasticsearch "
            f"within {timeout:.0f}s, found {seen}. "
            "Check `docker compose logs filebeat` and "
            "`curl localhost:5066/stats | jq .libbeat.output.events`."
        )

    def one_by_trace(self, trace_id: str, timeout: float = SHIP_TIMEOUT) -> dict[str, Any]:
        hits = self.wait_for_trace(trace_id, timeout=timeout, expected=1)
        assert len(hits) == 1, f"expected exactly one document for {trace_id}, got {len(hits)}"
        return hits[0]

    def existing_traces(self, trace_ids: list[str]) -> set[str]:
        """Which of these ``trace.id`` values are in the index, in few round trips.

        One `terms` query per 500 ids rather than one `_search` per id: AC-15
        checks a thousand of them and AC-12 a few hundred.
        """
        found: set[str] = set()
        for start in range(0, len(trace_ids), 500):
            chunk = trace_ids[start : start + 500]
            hits = self.search({"query": {"terms": {"trace.id": chunk}}}, size=len(chunk))
            found.update(str(hit["trace"]["id"]) for hit in hits if "trace" in hit)
        return found

    def assert_never_arrives(self, trace_ids: list[str], marker: str) -> None:
        """Assert these traces are absent, *after* a later marker has landed.

        Absence is only meaningful once something submitted afterwards has made
        it all the way through, otherwise this asserts nothing but latency.
        """
        self.wait_for_trace(marker)
        time.sleep(2.0)  # one more Filebeat tick, purely as belt and braces
        self.refresh()
        for trace_id in trace_ids:
            hits = self.by_trace(trace_id)
            assert hits == [], f"trace.id={trace_id!r} should never have been logged: {hits}"

    # -- mapping ------------------------------------------------------------

    def field_caps(self) -> dict[str, Any]:
        return self.json(
            "GET",
            f"/{INDEX_PATTERN}/_field_caps",
            params={"fields": "*", "ignore_unavailable": "true"},
        )

    def data_streams(self) -> list[dict[str, Any]]:
        response = self.request("GET", f"/_data_stream/{INDEX_PATTERN}")
        if response.status_code == 404:
            return []
        response.raise_for_status()
        streams: list[dict[str, Any]] = response.json()["data_streams"]
        return streams


# ---------------------------------------------------------------------------
# Session fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def es() -> Iterator[Elasticsearch]:
    """A ready Elasticsearch, or a skip that says exactly what to start."""
    client = Elasticsearch(ES_URL)
    try:
        client.request("GET", "/", timeout=5.0)
    except Exception:  # noqa: BLE001 - any failure to connect means "not up"
        client.close()
        pytest.skip(SKIP_REASON, allow_module_level=False)
    try:
        client.wait_until_ready()
        yield client
    finally:
        client.close()


@pytest.fixture(scope="session", autouse=True)
def bootstrap_elasticsearch(es: Elasticsearch) -> None:
    """Install A5's ILM policy and index template. **Step 1, always.**

    Plan §10 / D-11 / R-1: a data stream created before its template exists
    gets a dynamic mapping and cannot be fixed without a reindex. So this runs
    before any test writes a line, and it installs the *actual* files from
    ``infra/elasticsearch/`` rather than a copy — the whole point is to test
    what ships.

    ``infra/elasticsearch/bootstrap.py`` does this properly for a real cluster,
    with a diff and a dynamic:false guard, but its ``ES_URL`` is a literal in a
    CONFIG block with no environment override, so it cannot be pointed at a
    throwaway container from here. The README documents the two-line edit if
    you would rather exercise that path.
    """
    ilm = json.loads(ILM_PATH.read_text(encoding="utf-8"))
    retention_days = int(ilm.get("_meta", {}).get("RETENTION_DAYS", 90))
    policy = {"policy": ilm["policy"]}
    policy["policy"]["phases"]["delete"]["min_age"] = f"{retention_days}d"
    es.json("PUT", f"/_ilm/policy/{ILM_POLICY_NAME}", json=policy)

    template = load_template(TEMPLATE_PATH)
    # The same hard guard bootstrap.py refuses to run without.
    assert template["template"]["mappings"]["dynamic"] is False
    es.json("PUT", f"/_index_template/{INDEX_TEMPLATE_NAME}", json=template)

    # A5's README §3, "THE check": what would a new index actually get?
    simulated = es.json("POST", "/_index_template/_simulate_index/logs-apiaudit.probe-test")
    mappings = simulated["template"]["mappings"]
    assert mappings["dynamic"] == "false", "the installed template is not dynamic:false"
    settings = simulated["template"]["settings"]["index"]
    assert settings["mapping"]["total_fields"]["limit"] == "200"
    assert settings["lifecycle"]["name"] == ILM_POLICY_NAME


@pytest.fixture(scope="session")
def stack_log_dir() -> Path:
    """The directory Filebeat is watching, per ``docker-compose.test.yml``."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR


@pytest.fixture(scope="session")
def namespace() -> str:
    """A per-run ``data_stream.namespace``, so runs cannot contaminate runs."""
    return "test" + uuid.uuid4().hex[:8]


@dataclass
class StackApp:
    """An audited app writing into the directory Filebeat watches."""

    app: FastAPI
    config: AuditConfig
    sink: FileSink
    metrics: InMemoryMetrics
    client: httpx.AsyncClient
    received: Any

    async def get(self, url: str, trace_id: str, **kwargs: Any) -> httpx.Response:
        return await self._call("GET", url, trace_id, **kwargs)

    async def post(self, url: str, trace_id: str, **kwargs: Any) -> httpx.Response:
        return await self._call("POST", url, trace_id, **kwargs)

    async def _call(
        self, method: str, url: str, trace_id: str, **kwargs: Any
    ) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}) or {})
        # FR-23: an incoming X-Request-ID is reused as trace.id, which is what
        # makes every assertion in this tier a precise lookup rather than a
        # scan of whatever happens to be in the index.
        headers["x-request-id"] = trace_id
        return await self.client.request(method, url, headers=headers, **kwargs)


@pytest.fixture
async def stack(
    stack_log_dir: Path, namespace: str
) -> AsyncIterator[Any]:
    """Factory for audited apps that ship through the real stack."""
    built: list[StackApp] = []

    async def factory(
        app: FastAPI | None = None, *, service_name: str = "orders-api", **overrides: Any
    ) -> StackApp:
        values: dict[str, Any] = {
            "service_name": service_name,
            "service_version": "1.4.2",
            "environment": namespace,
            "log_dir": stack_log_dir,
            "flush_interval_seconds": 0.2,
            "shutdown_flush_timeout": 5.0,
            "exclude_paths": ["/health", "/metrics"],
        }
        values.update(overrides)
        config = AuditConfig(**values)
        metrics = InMemoryMetrics()
        sink = FileSink(config, metrics)
        received = None
        if app is None:
            app, received = make_app()
        app.add_middleware(AuditMiddleware, config=config, sink=sink, metrics=metrics)
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://audit.test"
        )
        wired = StackApp(app, config, sink, metrics, client, received)
        built.append(wired)
        return wired

    yield factory

    for wired in built:
        try:
            await wired.client.aclose()
        finally:
            await wired.sink.close()


def trace() -> str:
    """A fresh, well-formed ``X-Request-ID`` (FR-23: printable ASCII ≤ 200)."""
    return uuid.uuid4().hex


# ===========================================================================
# AC-01 (FR-01)
# ===========================================================================


async def test_AC_01_one_document_per_request(es: Elasticsearch, stack: Any) -> None:
    app = await stack()
    trace_id = trace()

    response = await app.get("/items/42", trace_id)
    assert response.status_code == 200
    assert response.headers["x-request-id"] == trace_id, "FR-24"
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)

    assert doc["http"]["request"]["method"] == "GET"
    assert doc["audit"]["route"] == "/items/{item_id}"
    assert doc["http"]["response"]["status_code"] == 200
    assert doc["event"]["outcome"] == "success"
    # Filebeat routed it from the document's own data_stream.* fields.
    assert doc["data_stream"]["dataset"] == app.config.data_stream_dataset
    assert doc["data_stream"]["namespace"] == app.config.environment
    # `overwrite_keys: true` did its job: @timestamp is the request's, not the
    # moment Filebeat read the line.
    assert doc["@timestamp"].endswith("Z")


async def test_AC_01_the_data_stream_uses_our_template_not_a_dynamic_one(
    es: Elasticsearch, stack: Any
) -> None:
    """Plan §10 / D-11: the failure that is only visible here, and is fatal."""
    app = await stack()
    trace_id = trace()
    await app.get("/items/1", trace_id)
    await app.sink.flush()
    es.wait_for_trace(trace_id)

    streams = es.data_streams()
    assert streams, "no data stream was created"
    for stream in streams:
        assert stream["template"] == INDEX_TEMPLATE_NAME, (
            f"data stream {stream['name']} was created from template "
            f"{stream['template']!r}: its backing indices have a dynamic mapping "
            "and the only fix is a reindex"
        )


async def test_AC_01_filebeat_dropped_its_own_metadata(
    es: Elasticsearch, stack: Any
) -> None:
    """`drop_fields` in filebeat.yml — and `host.hostname` surviving it."""
    app = await stack()
    trace_id = trace()
    await app.get("/items/1", trace_id)
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)

    for dropped in ("agent", "ecs", "input", "log"):
        assert dropped not in doc, f"filebeat.yml should drop {dropped!r}"
    assert doc["host"]["hostname"], "host.hostname is ours and must not be overwritten"


# ===========================================================================
# AC-02 (FR-02)
# ===========================================================================


async def test_AC_02_excluded_path_produces_no_document(
    es: Elasticsearch, stack: Any
) -> None:
    app = await stack()
    excluded = [trace() for _ in range(10)]
    for trace_id in excluded:
        assert (await app.get("/health", trace_id)).status_code == 200

    marker = trace()
    await app.get("/items/1", marker)
    await app.sink.flush()

    es.assert_never_arrives(excluded, marker)
    assert app.metrics.get("audit_documents_submitted_total") == 1.0


# ===========================================================================
# AC-03 (FR-04)
# ===========================================================================


async def test_AC_03_json_body_is_replayed_and_parsed(
    es: Elasticsearch, stack: Any
) -> None:
    app = await stack()
    trace_id = trace()
    payload = {"sku": "A-11", "qty": 3, "notes": "x" * 3000}
    raw = json.dumps(payload).encode()

    response = await app.post(
        "/echo", trace_id, content=raw, headers={"content-type": "application/json"}
    )

    assert response.status_code == 200
    assert app.received.last == raw, "FR-04: byte-identical replay"
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)
    assert doc["audit"]["request"]["body"] == payload
    assert doc["audit"]["request"]["body_parse_failed"] is False
    assert doc["http"]["request"]["bytes"] == len(raw)


async def test_AC_03_the_flattened_body_is_searchable_by_subkey(
    es: Elasticsearch, stack: Any
) -> None:
    """What `flattened` buys and what it costs (schema §2.8), in Elasticsearch.

    Sub-keys are queryable — as ``keyword``, and only as ``keyword``: the `3`
    below matches as the *string* "3", and a range query on it would not work.
    """
    app = await stack()
    trace_id = trace()
    await app.post("/ingest", trace_id, json={"sku": "A-11", "qty": 3})
    await app.sink.flush()
    es.wait_for_trace(trace_id)

    hits = es.search(
        {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"trace.id": trace_id}},
                        {"term": {"audit.request.body.sku": "A-11"}},
                    ]
                }
            }
        }
    )
    assert len(hits) == 1, "a flattened sub-key must still be a term query"

    numeric = es.search(
        {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"trace.id": trace_id}},
                        {"term": {"audit.request.body.qty": "3"}},
                    ]
                }
            }
        }
    )
    assert len(numeric) == 1, "flattened values are keywords: 3 is matched as '3'"


async def test_AC_03_body_raw_is_stored_but_not_searchable(
    es: Elasticsearch, stack: Any
) -> None:
    """`index: false, doc_values: false` — retrievable, never queryable.

    Re-aligned to `docs/schema.md` §2.9 (FR-30). This used to POST *valid* JSON
    and expect a marker in `body_raw`, which was the superseded D-10 behaviour
    where both fields were written. Parseable JSON now emits `body` and no
    `body_raw` at all, so exercising `body_raw` needs a body that genuinely
    cannot be represented as an object — the FR-09 parse-failure path.
    """
    app = await stack()
    trace_id = trace()
    # Deliberately broken JSON, so §2.9's third row applies: body_raw, verbatim.
    await app.post(
        "/ingest",
        trace_id,
        content=b'{"sku": "UNIQUE-BODY-RAW-MARKER"',
        headers={"content-type": "application/json"},
    )
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)
    request = doc["audit"]["request"]
    assert request["body_parse_failed"] is True
    assert "UNIQUE-BODY-RAW-MARKER" in request["body_raw"]
    assert "body" not in request, "FR-30 / schema §2.9: never both"

    response = es.request(
        "POST",
        f"/{INDEX_PATTERN}/_search",
        params={"ignore_unavailable": "true"},
        json={"query": {"term": {"audit.request.body_raw": request["body_raw"]}}},
    )
    assert response.status_code == 400, (
        "body_raw is index:false; querying it must be an error, not a silent miss"
    )


async def test_AC_03_parseable_json_emits_no_body_raw_at_all(
    es: Elasticsearch, stack: Any
) -> None:
    """The other side of FR-30, asserted against `_source` in Elasticsearch.

    Storing both doubled every line and put a second full serialisation of an
    attacker-sized body on the request path (review M-3, M-2). What arrives
    here is what Filebeat shipped, so this is the only place "single storage"
    is settled rather than modelled.
    """
    app = await stack()
    trace_id = trace()
    await app.post("/ingest", trace_id, json={"sku": "A-11", "qty": 3})
    await app.sink.flush()

    request = es.one_by_trace(trace_id)["audit"]["request"]
    assert request["body"] == {"sku": "A-11", "qty": 3}
    assert "body_raw" not in request, (
        "schema §2.9 row 1: for parseable JSON the flattened body IS the "
        "content; body_raw would be 100% more storage for key order alone"
    )
    assert request["body_parse_failed"] is False
    assert "body_skipped" not in request


# ===========================================================================
# AC-04 (FR-08)
# ===========================================================================


async def test_AC_04_oversized_body_is_truncated_but_replayed_in_full(
    es: Elasticsearch, stack: Any
) -> None:
    cap = 1_048_576
    app = await stack(max_body_bytes=cap)
    trace_id = trace()
    raw = json.dumps({"blob": "y" * (2 * 1024 * 1024)}).encode("ascii")

    response = await app.post(
        "/echo", trace_id, content=raw, headers={"content-type": "application/json"}
    )

    assert response.status_code == 200
    assert app.received.total_bytes == len(raw), "the app receives all 2 MB"
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)
    request = doc["audit"]["request"]
    assert request["body_truncated"] is True
    assert request["body_bytes"] == cap
    assert "body" not in request, "FR-30: a body cut mid-JSON has nothing to parse"
    # AC-04's own clause is "stored raw body ≤ 1 MiB". The parse-failure path
    # now clips at 4096 *characters* (`document._MAX_UNPARSED_BODY_RAW`, review
    # S-2: this is the one unredacted field in the document), so asserting the
    # AC's 1 MiB would pass on a 1 MiB body_raw and test nothing.
    assert len(request["body_raw"]) <= 4096, (
        f"body_raw is {len(request['body_raw'])} characters, over the clip"
    )
    assert len(request["body_raw"].encode("utf-8")) <= cap, "AC-04's own bound"
    assert doc["http"]["request"]["bytes"] == len(raw)


# ===========================================================================
# AC-05 (FR-10, FR-11)
# ===========================================================================


async def test_AC_05_denylisted_values_are_replaced_everywhere(
    es: Elasticsearch, stack: Any
) -> None:
    app = await stack()
    trace_id = trace()
    await app.post(
        "/ingest",
        trace_id,
        json={"password": "p", "nested": {"api_key": "k"}, "items": [{"token": "t"}]},
    )
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)
    assert doc["audit"]["request"]["body"] == {
        "password": "[REDACTED]",
        "nested": {"api_key": "[REDACTED]"},
        "items": [{"token": "[REDACTED]"}],
    }


async def test_AC_05_no_secret_is_anywhere_in_the_indexed_document(
    es: Elasticsearch, stack: Any
) -> None:
    """Sentinels, because AC-05's own `p`/`k`/`t` match by accident."""
    app = await stack()
    trace_id = trace()
    secrets = [
        "SENTINEL-PASSWORD-9f2c1a7d",
        "SENTINEL-APIKEY-4e8b4f0a",
        "SENTINEL-TOKEN-a1c3d5e7",
        "SENTINEL-QUERY-f9b0c2d4",
        "SENTINEL-HEADER-1234",
        "SENTINEL-COOKIE-5678",
    ]
    await app.post(
        "/ingest",
        trace_id,
        json={
            "password": secrets[0],
            "nested": {"api_key": secrets[1]},
            "items": [{"token": secrets[2]}],
        },
        params={"access_token": secrets[3]},
        headers={
            "authorization": f"Bearer {secrets[4]}",
            "cookie": f"session={secrets[5]}",
        },
    )
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)
    serialised = json.dumps(doc)
    for secret in secrets:
        assert secret not in serialised, f"AC-05: {secret} survived into Elasticsearch"
    assert "[REDACTED]" in serialised


# ===========================================================================
# AC-06 (FR-12)
# ===========================================================================


async def test_AC_06_credential_headers_never_appear(
    es: Elasticsearch, stack: Any
) -> None:
    app = await stack()
    trace_id = trace()
    await app.post(
        "/ingest",
        trace_id,
        json={"ok": True},
        headers={
            "authorization": "Bearer abc123",
            "cookie": "session=xyz",
            "x-internal-thing": "should-vanish",
        },
    )
    await app.sink.flush()

    headers = es.one_by_trace(trace_id)["audit"]["request"]["headers"]
    assert "authorization" not in headers
    assert "cookie" not in headers
    assert "x-internal-thing" not in headers
    assert headers["content-type"].startswith("application/json")
    assert "user-agent" in headers


# ===========================================================================
# AC-07 (FR-03)
# ===========================================================================


async def test_AC_07_unmatched_route_is_logged_with_its_404(
    es: Elasticsearch, stack: Any
) -> None:
    app = await stack()
    trace_id = trace()
    response = await app.get("/no/such/endpoint", trace_id)
    assert response.status_code == 404
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)
    assert doc["audit"]["route"] == "unmatched"
    assert doc["http"]["response"]["status_code"] == 404
    assert doc["event"]["outcome"] == "success", "a 4xx is not a failure (schema §2.2)"


# ===========================================================================
# AC-08 (FR-01, NFR-3)
# ===========================================================================


async def test_AC_08_application_exception_propagates_and_is_logged(
    es: Elasticsearch, stack: Any
) -> None:
    app = await stack()
    trace_id = trace()

    with pytest.raises(ValueError, match="kaboom") as raised:
        await app.get("/boom", trace_id)
    assert type(raised.value) is ValueError

    await app.sink.flush()

    doc = es.one_by_trace(trace_id)
    assert doc["event"]["outcome"] == "failure"
    assert doc["http"]["response"]["status_code"] == 500
    assert doc["error"]["type"] == "ValueError"
    assert doc["error"]["message"] == "kaboom"
    # `error.message` is a legitimate field of our schema, and filebeat.yml's
    # drop_event keys on data_stream.dataset precisely so documents like this
    # one are not the ones thrown away.
    assert "stack" not in json.dumps(doc).lower()


# ===========================================================================
# AC-09 (FR-19)
# ===========================================================================


async def test_AC_09_full_queue_drops_documents_and_serves_every_request(
    es: Elasticsearch, stack: Any
) -> None:
    app = await stack(
        service_name="drop-api",
        queue_max_bytes=4096,
        flush_max_bytes=4096,
        flush_interval_seconds=30.0,
    )
    traces = [trace() for _ in range(200)]
    statuses = []
    for index, trace_id in enumerate(traces):
        statuses.append((await app.post("/ingest", trace_id, json={"n": index})).status_code)

    assert statuses == [200] * 200
    dropped = app.metrics.get("audit_documents_dropped_total")
    submitted = app.metrics.get("audit_documents_submitted_total")
    assert dropped > 0
    assert submitted + dropped == 200
    assert app.metrics.get("audit_middleware_errors_total") == 0.0

    # Drain first, so the marker itself cannot be one of the dropped ones.
    await app.sink.flush()
    marker = trace()
    await app.post("/ingest", marker, json={"marker": True})
    await app.sink.flush()
    es.wait_for_trace(marker)
    es.refresh()

    # What survived is in Elasticsearch; what was dropped is nowhere. That the
    # two numbers reconcile is what makes the drop counter trustworthy.
    found = es.existing_traces(traces)
    assert len(found) == int(submitted), (
        f"{submitted:.0f} documents were submitted but {len(found)} reached "
        f"Elasticsearch ({dropped:.0f} were dropped at the queue)"
    )


# ===========================================================================
# AC-10 (mapping bound) — the real `GET _mapping`
# ===========================================================================


async def test_AC_10_fifty_endpoints_two_hundred_requests_stay_under_the_bound(
    es: Elasticsearch, stack_log_dir: Path, namespace: str
) -> None:
    """50 endpoints x 200 requests, then ask Elasticsearch how many fields it has."""
    endpoints, per_endpoint = 50, 200
    config = AuditConfig(
        service_name="wide-api",
        service_version="1.0.0",
        environment=namespace,
        log_dir=stack_log_dir,
        flush_interval_seconds=0.2,
        queue_max_bytes=256 * 1024 * 1024,
        flush_max_bytes=16 * 1024 * 1024,
        file_max_bytes=1024 * 1024 * 1024,
    )
    metrics = InMemoryMetrics()
    sink = FileSink(config, metrics)
    app = make_wide_app(endpoints)
    app.add_middleware(AuditMiddleware, config=config, sink=sink, metrics=metrics)

    last_trace = trace()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://audit.test") as client:
        try:
            for endpoint in range(endpoints):
                await asyncio.gather(
                    *(
                        client.post(f"/e{endpoint}/{i}", json=wide_body(endpoint, i))
                        for i in range(per_endpoint)
                    )
                )
            # A final, identifiable request: when this one is in Elasticsearch,
            # everything before it has been shipped too (Filebeat reads a file
            # in order).
            await client.post(
                "/e0/final", json={"final": True}, headers={"x-request-id": last_trace}
            )
            await sink.flush()
        finally:
            await sink.close()

    expected = endpoints * per_endpoint + 1
    assert metrics.get("audit_documents_submitted_total") == float(expected)
    assert metrics.get("audit_documents_dropped_total") == 0.0

    # 10k documents through a bulk-200 shipper takes a while; be patient.
    es.wait_for_trace(last_trace, timeout=max(SHIP_TIMEOUT, 300.0))

    caps = es.field_caps()["fields"]
    field_count = len(caps)
    assert field_count <= 200, (
        f"AC-10: _field_caps reports {field_count} fields, over the 200-field limit"
    )
    # `flattened` did the absorbing: the body's keys are not fields of their own.
    assert not any(f.startswith("audit.request.body.") for f in caps), (
        "a body sub-key became a real mapping field — flattened is not in effect"
    )
    assert "audit.request.body" in caps

    mapping = es.json("GET", f"/{INDEX_PATTERN}/_mapping")
    for index_name, body in mapping.items():
        assert body["mappings"]["dynamic"] == "false", f"{index_name} is not dynamic:false"

    # Nothing was rejected on the way in.
    stats = es.json("GET", "/_nodes/stats/indices/indexing")
    for node in stats["nodes"].values():
        assert node["indices"]["indexing"]["index_failed"] == 0, "Elasticsearch rejected writes"

    print(f"\nAC-10 (Tier 1): {expected} documents -> {field_count} fields in _field_caps")


# ===========================================================================
# AC-11 (FR-15)
# ===========================================================================


async def test_AC_11_kill_switch_produces_no_document_and_no_file(
    es: Elasticsearch,
    stack_log_dir: Path,
    namespace: str,
    monkeypatch: pytest.MonkeyPatch,
    stack: Any,
) -> None:
    monkeypatch.setenv("AUDIT_ENABLED", "false")
    monkeypatch.setenv("AUDIT_SERVICE_NAME", "killed-api")
    monkeypatch.setenv("AUDIT_ENVIRONMENT", namespace)
    monkeypatch.setenv("AUDIT_LOG_DIR", str(stack_log_dir))
    config = AuditConfig()  # type: ignore[call-arg]
    assert config.enabled is False

    metrics = InMemoryMetrics()
    app, _ = make_app()
    app.add_middleware(AuditMiddleware, config=config, metrics=metrics)

    silent = [trace() for _ in range(10)]
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://audit.test") as client:
        for index, trace_id in enumerate(silent):
            response = await client.get(f"/items/{index}", headers={"x-request-id": trace_id})
            assert response.status_code == 200

    assert not any(stack_log_dir.glob("killed-api-*.jsonl")), "FR-15: no file was opened"
    assert metrics.snapshot() == InMemoryMetrics().snapshot()

    # A different, *enabled* app provides the marker that makes the absence
    # above mean something.
    live = await stack()
    marker = trace()
    await live.get("/items/1", marker)
    await live.sink.flush()
    es.assert_never_arrives(silent, marker)


# ===========================================================================
# AC-12 (FR-22)
# ===========================================================================


async def test_AC_12_every_line_survives_three_rotations(
    es: Elasticsearch, stack: Any
) -> None:
    """Rotation vs Filebeat: `filestream` follows the open file across renames.

    This is the AC that only Tier 1 can really answer. `filebeat.yml` excludes
    `*.jsonl.1` … `.8` from the glob on purpose, so if the harvester did *not*
    follow the rename, the lines written just before each rotation would be
    lost for good and this test is the only thing that would notice.
    """
    app = await stack(
        service_name="rotate-api",
        file_max_bytes=64 * 1024,
        file_backup_count=8,
        flush_interval_seconds=30.0,
    )

    traces: list[str] = []
    deadline = time.monotonic() + 120.0
    while app.metrics.get("audit_file_rotations_total") < 3.0:
        assert time.monotonic() < deadline, "rotation never happened"
        for _ in range(10):
            trace_id = trace()
            traces.append(trace_id)
            response = await app.post(
                "/ingest", trace_id, json={"seq": len(traces), "pad": "z" * 200}
            )
            assert response.status_code == 200
        await app.sink.flush()

    assert app.metrics.get("audit_file_rotations_total") == 3.0
    await app.sink.flush()

    base = app.sink.path
    for index in (1, 2, 3):
        assert Path(f"{base}.{index}").exists(), f"FR-22: {base}.{index} is missing"
    assert not Path(f"{base}.4").exists()

    # Every single line, including the ones written either side of a rename.
    es.wait_for_trace(traces[-1], timeout=max(SHIP_TIMEOUT, 240.0))
    es.refresh()
    present = es.existing_traces(traces)
    missing = [t for t in traces if t not in present]
    assert missing == [], (
        f"{len(missing)} of {len(traces)} documents were lost across rotation "
        f"(first missing: {missing[0]}) — check whether filestream followed the "
        "file across the rename; the rotated .1….8 files are excluded from the glob"
    )


# ===========================================================================
# AC-13 (FR-06)
# ===========================================================================


async def test_AC_13_streaming_duration_reaches_the_last_chunk(
    es: Elasticsearch, stack: Any
) -> None:
    app = await stack()
    trace_id = trace()
    response = await app.get("/stream", trace_id)
    assert response.status_code == 200
    expected_bytes = sum(len(f"chunk-{i};".encode()) for i in range(STREAM_CHUNKS))
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)
    # Nanoseconds (ECS). Kibana formats this as ms; a raw _search does not.
    assert doc["event"]["duration"] >= 400_000_000
    assert doc["http"]["response"]["bytes"] == expected_bytes

    # And it is a number in Elasticsearch, not a string: the field is `long`.
    hits = es.search(
        {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"trace.id": trace_id}},
                        {"range": {"event.duration": {"gte": 400_000_000}}},
                    ]
                }
            }
        }
    )
    assert len(hits) == 1, "event.duration must be a queryable long"


# ===========================================================================
# AC-14 (FR-09)
# ===========================================================================


async def test_AC_14_broken_json_keeps_the_raw_text(
    es: Elasticsearch, stack: Any
) -> None:
    app = await stack()
    trace_id = trace()
    raw = b"{not json"

    response = await app.post(
        "/echo", trace_id, content=raw, headers={"content-type": "application/json"}
    )

    assert response.status_code == 200
    assert app.received.last == raw
    await app.sink.flush()

    request = es.one_by_trace(trace_id)["audit"]["request"]
    assert request["body_parse_failed"] is True
    assert request["body_raw"] == "{not json"
    assert "body" not in request


# ===========================================================================
# AC-15 (FR-20r)
# ===========================================================================


async def test_AC_15_a_thousand_documents_land_within_the_interval(
    es: Elasticsearch, stack: Any, stack_log_dir: Path, namespace: str
) -> None:
    """On disk within 1.5 s (FR-20r), and then all the way to Elasticsearch."""
    seed = await stack(service_name="burst-seed")
    seed_trace = trace()
    await seed.post("/ingest", seed_trace, json={"sku": "A-11", "qty": 3})
    await seed.sink.flush()
    prototype = json.loads(seed.sink.path.read_text().splitlines()[-1])

    config = AuditConfig(
        service_name="burst-api",
        service_version="1.0.0",
        environment=namespace,
        log_dir=stack_log_dir,
        flush_interval_seconds=1.0,
        queue_max_bytes=64 * 1024 * 1024,
        flush_max_bytes=4 * 1024 * 1024,
    )
    metrics = InMemoryMetrics()
    sink = FileSink(config, metrics)
    await sink.start()
    try:
        started = time.monotonic()
        ids = [f"burst-{i:04d}-{uuid.uuid4().hex[:8]}" for i in range(1000)]
        for identifier in ids:
            document = dict(prototype)
            document["trace"] = {"id": identifier}
            document["data_stream"] = dict(prototype["data_stream"])
            document["data_stream"]["dataset"] = config.data_stream_dataset
            document["data_stream"]["namespace"] = namespace
            assert sink.submit(document) is True
        submit_seconds = time.monotonic() - started
        assert submit_seconds < 0.1

        deadline = started + submit_seconds + 1.5
        lines: list[str] = []
        while time.monotonic() < deadline:
            if sink.path.exists():
                lines = [x for x in (l.strip() for l in sink.path.read_text().splitlines()) if x]
                if len(lines) >= 1000:
                    break
            await asyncio.sleep(0.02)
    finally:
        await sink.close()

    assert len(lines) == 1000, f"only {len(lines)} lines were on disk after 1.5 s"
    assert [json.loads(x)["trace"]["id"] for x in lines] == ids, "FR-20r: submission order"

    es.wait_for_trace(ids[-1], timeout=max(SHIP_TIMEOUT, 180.0))
    es.refresh()
    present = es.existing_traces(ids)
    missing = [i for i in ids if i not in present]
    assert missing == [], f"{len(missing)} of 1000 documents never reached Elasticsearch"


# ===========================================================================
# AC-16 (FR-21r)
# ===========================================================================


@pytest.mark.skipif(IS_ROOT, reason="root ignores file-mode bits, so nothing fails")
async def test_AC_16_unwritable_log_dir_never_reaches_the_request_path(
    es: Elasticsearch, stack: Any, tmp_path: Path, namespace: str
) -> None:
    """The first 50 reach Elasticsearch; the next 50 are counted, not crashed.

    The log directory here is a **private** one, not the directory Filebeat is
    watching: chmod-ing the shared stack directory read-only would break every
    test that runs afterwards. That means the ES half of this AC is asserted
    only for the documents written before the failure — the ones written after
    are, by construction, nowhere to be shipped from. See tests/AC-matrix.md.
    """
    private = tmp_path / "audit"
    private.mkdir()
    app = await stack(
        service_name="failing-api",
        log_dir=private,
        file_max_bytes=4096,
        file_backup_count=8,
        flush_interval_seconds=30.0,
    )

    for index in range(50):
        assert (await app.post("/ingest", trace(), json={"n": index})).status_code == 200
        if index % 10 == 9:
            await app.sink.flush()
    await app.sink.flush()
    assert app.metrics.get("audit_documents_failed_total") == 0.0

    active = app.sink.path
    try:
        os.chmod(active, 0o400)
        os.chmod(private, 0o500)

        statuses = []
        for index in range(50, 100):
            statuses.append((await app.post("/ingest", trace(), json={"n": index})).status_code)
            if index % 10 == 9:
                await app.sink.flush()
        await app.sink.flush()

        assert statuses == [200] * 50, "FR-21r: the API is unaffected"
        assert app.metrics.get("audit_documents_failed_total") >= 50.0
        assert app.metrics.get("audit_middleware_errors_total") == 0.0
    finally:
        os.chmod(private, 0o700)
        os.chmod(active, 0o600)

    assert (await app.get("/items/1", trace())).status_code == 200


# ===========================================================================
# AC-17 (FR-25)
# ===========================================================================


def _exploding_resolver(scope: dict[str, Any]) -> dict[str, Any] | None:
    raise RuntimeError("the identity service is down")


async def test_AC_17_raising_user_resolver_still_produces_the_document(
    es: Elasticsearch, stack: Any
) -> None:
    app = await stack(user_resolver=_exploding_resolver)
    trace_id = trace()

    assert (await app.get("/whoami", trace_id)).status_code == 200
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)
    assert "user" not in doc, "FR-25: the document exists, without user.*"
    assert app.metrics.get("audit_middleware_errors_total") == 1.0


# ===========================================================================
# AC-18 (FR-28) — the M-1 regression, against the index rather than the file
#
# Tier 2 asserts the secret is not in the JSONL line. Only here can it be
# asserted that it is not in Elasticsearch — which is where it would have been
# queryable, exportable and retained for the ILM policy's full 90 days.
# ===========================================================================


AC_18_CONTENT_TYPES = ["text/plain", "application/xml", None]


@pytest.mark.parametrize("content_type", AC_18_CONTENT_TYPES, ids=["text", "xml", "none"])
async def test_AC_18_a_body_the_denylist_cannot_reach_never_reaches_the_index(
    es: Elasticsearch, stack: Any, content_type: str | None
) -> None:
    """`{"password":"p"}` as text: `body_skipped`, and `p` nowhere in `_source`."""
    app = await stack()
    trace_id = trace()
    secret = f"SENTINEL-M1-{uuid.uuid4().hex}"
    raw = json.dumps({"password": secret}).encode()
    headers = {"content-type": content_type} if content_type else {}

    response = await app.post("/echo", trace_id, content=raw, headers=headers)
    assert response.status_code == 200
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)
    request = doc["audit"]["request"]
    assert request["body_skipped"] == "content_type", "FR-28 / schema §2.9"
    assert "body" not in request and "body_raw" not in request
    assert secret not in json.dumps(doc), (
        f"M-1: Content-Type {content_type!r} put an unredacted secret in the "
        "audit index, where it is retained for the full ILM lifetime"
    )

    # And it is not findable by any query either, not merely absent from
    # `_source` — `query.default_field` covers audit.route/url.path/error.message.
    es.refresh()
    assert es.search({"query": {"query_string": {"query": f'"{secret}"'}}}) == []


# ===========================================================================
# AC-20 (FR-30) — the M-3 regression. This tier is where it is really settled.
#
# M-3 was not a serialisation bug: the line was written correctly and then
# **truncated by Filebeat**, failed ndjson decode, and was discarded by a
# `drop_event` processor with no counter on either side. Nothing in Tier 2
# touches `message_max_bytes`, the ndjson parser, or the quarantine route that
# replaced `drop_event`. Only these tests do.
# ===========================================================================


async def test_AC_20_a_1MiB_body_survives_the_whole_pipeline(
    es: Elasticsearch, stack: Any
) -> None:
    """The line M-3 lost: a 1 MiB body, stored once, indexed intact."""
    mib = 1024 * 1024
    # 2 MiB, so the 1 MiB body is captured whole and really is stored. At the
    # 1 MiB default it would be truncated mid-JSON and take the clip path,
    # which is not the case M-3 was about.
    app = await stack(max_body_bytes=2 * mib)
    trace_id = trace()
    marker = f"BLOB-{uuid.uuid4().hex}"
    payload = json.dumps({"marker": marker, "blob": "y" * mib}).encode()
    assert len(payload) > mib

    response = await app.post(
        "/ingest", trace_id, content=payload, headers={"content-type": "application/json"}
    )
    assert response.status_code == 200
    await app.sink.flush()

    line_bytes = max(
        len(line.encode("utf-8")) + 1
        for line in app.sink.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    assert line_bytes < 2 * mib, (
        f"M-3: the 1 MiB body produced a {line_bytes} B line. Under D-10's "
        "'both' this was 2 097 957 B — body and body_raw are both being written"
    )

    doc = es.one_by_trace(trace_id)
    request = doc["audit"]["request"]
    assert request["body"]["marker"] == marker, "the largest record still arrived"
    assert "body_raw" not in request, "FR-30 / schema §2.9"
    assert request["body_truncated"] is False

    # It is queryable, not merely present: a truncated line that failed ndjson
    # decode would have landed in the quarantine stream with no `body` at all.
    es.refresh()
    hits = es.search(
        {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"trace.id": trace_id}},
                        {"term": {"audit.request.body.marker": marker}},
                    ]
                }
            }
        }
    )
    assert len(hits) == 1


async def test_AC_20_nothing_was_quarantined_as_undecodable(
    es: Elasticsearch, stack: Any, namespace: str
) -> None:
    """The counter M-3 said did not exist. It exists now; it must read zero.

    `filebeat.yml` routes a line that did not decode to
    `logs-apiaudit.undecodable-<namespace>` instead of dropping it, precisely so
    the loss is countable. A non-zero count here after the AC-20 traffic above
    means a line was truncated at `message_max_bytes` — M-3, live.
    """
    app = await stack()
    trace_id = trace()
    await app.post("/ingest", trace_id, json={"probe": True})
    await app.sink.flush()
    es.one_by_trace(trace_id)  # a marker that this run's lines have been shipped

    quarantined = es.count({"term": {"data_stream.dataset": "apiaudit.undecodable"}})
    assert quarantined == 0, (
        f"{quarantined} line(s) reached logs-apiaudit.undecodable-{namespace}. "
        "A line failed Filebeat's ndjson decode — check its size against "
        "message_max_bytes (infra/filebeat/filebeat.yml, SIZING INVARIANTS) and "
        "`docker compose logs filebeat | grep -i 'exceeds\\|truncat'`."
    )
    assert es.count({"term": {"data_stream.dataset": "apiaudit.orders_api"}}) > 0, (
        "the premise: this run indexed something, so the zero above means "
        "'nothing was lost' and not 'nothing was shipped'"
    )


# ===========================================================================
# AC-21 (FR-31) — the M-5 regression. Elasticsearch is the only real oracle.
#
# `index.mapping.ignore_malformed` covers numerics, boolean, date, ip and geo —
# never `keyword`. An uncoerced `user.roles` is a mapper_parsing_exception and
# the WHOLE document is rejected. Tier 2 now models that; this settles it.
# ===========================================================================


async def test_AC_21_a_hostile_user_resolver_does_not_cost_the_document(
    es: Elasticsearch, stack: Any
) -> None:
    """AC-21's literal resolver: `{"id": 7, "roles": {"a": "b"}}`."""

    def resolver(scope: dict[str, Any]) -> dict[str, Any] | None:
        return {"id": 7, "name": 3.5, "roles": {"a": "b"}}

    app = await stack(user_resolver=resolver)
    trace_id = trace()
    assert (await app.get("/whoami", trace_id)).status_code == 200
    await app.sink.flush()

    doc = es.one_by_trace(trace_id)  # M-5: this is what used to never arrive
    user = doc.get("user", {})
    assert user.get("id") == "7", "FR-31: keyword, so 7 is coerced to '7'"
    assert user.get("name") == "3.5"
    assert "roles" not in user, "a dict will not coerce to list[str], so it is dropped"
    assert app.metrics.get("audit_middleware_errors_total") == 0.0

    # Coerced *and* indexed: a value merely present in `_source` is not enough.
    es.refresh()
    assert len(es.search({"query": {"term": {"user.id": "7"}}})) >= 1


def test_AC_21_the_uncoerced_shape_really_is_rejected_by_elasticsearch(
    es: Elasticsearch, namespace: str
) -> None:
    """Proof AC-21 is not passing vacuously — and the verification M-5 needs.

    Indexes the pre-FR-31 document shape directly, bypassing the package. If
    Elasticsearch accepts it, `ignore_malformed` covers `keyword` after all and
    both M-5 and the strengthened Tier 2 double are wrong about the same thing.
    """
    doc = {
        "@timestamp": "2026-09-05T11:22:33.123456Z",
        "data_stream": {
            "type": "logs",
            "dataset": "apiaudit.probe",
            "namespace": namespace,
        },
        "event": {"kind": "event", "outcome": "success"},
        "trace": {"id": uuid.uuid4().hex},
        "user": {"id": "u-1", "roles": {"a": "b"}},
    }
    response = es.request(
        "POST",
        f"/logs-apiaudit.probe-{namespace}/_doc",
        params={"refresh": "true"},
        json=doc,
    )
    assert response.status_code >= 400, (
        "Elasticsearch accepted an object in user.roles. If this ever passes, "
        "review M-5 and tests/integration/_es_double.py both need revisiting."
    )
    assert "mapper_parsing_exception" in response.text or "illegal_argument" in response.text


def test_AC_21_a_flattened_key_over_the_lucene_term_limit_is_rejected(
    es: Elasticsearch, namespace: str
) -> None:
    """Review N-9, verified rather than reasoned about — the one POST it needs.

    `FlattenedFieldParser.addField` indexes a leaf as `key + NUL + value` and
    throws before it looks at `index`/`doc_values`, so no template setting can
    avoid it. `redact.sanitize_key` bounds keys at 1024 UTF-8 bytes precisely
    because of this; if this test fails, that bound is unnecessary, and if it
    passes, the bound is load-bearing.
    """
    base = {
        "@timestamp": "2026-09-05T11:22:33.123456Z",
        "data_stream": {
            "type": "logs",
            "dataset": "apiaudit.probe",
            "namespace": namespace,
        },
        "event": {"kind": "event", "outcome": "success"},
    }
    index = f"/logs-apiaudit.probe-{namespace}/_doc"

    over = dict(base, trace={"id": uuid.uuid4().hex})
    over["audit"] = {"request": {"body": {"k" * 40_000: "v"}}}
    rejected = es.request("POST", index, params={"refresh": "true"}, json=over)
    assert rejected.status_code >= 400, (
        "a 40 KB flattened key indexed cleanly; N-9 is not real and "
        "redact.MAX_KEY_BYTES can go"
    )

    under = dict(base, trace={"id": uuid.uuid4().hex})
    under["audit"] = {"request": {"body": {"k" * 1024: "v"}}}
    accepted = es.request("POST", index, params={"refresh": "true"}, json=under)
    assert accepted.status_code < 400, (
        f"a key at redact.MAX_KEY_BYTES was rejected too: {accepted.text}. "
        "The bound is in the wrong place."
    )

    # The NUL case, found in the A5 fix pass rather than in the review: 15 bytes
    # of body cost the whole record.
    nul = dict(base, trace={"id": uuid.uuid4().hex})
    nul["audit"] = {"request": {"body": {"a\x00b": 1}}}
    response = es.request("POST", index, params={"refresh": "true"}, json=nul)
    assert response.status_code >= 400, "a NUL in a flattened key indexed cleanly"
