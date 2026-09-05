"""Tier 2 — AC-01 … AC-26 without Docker. Runs in this environment.

Every test here drives the **real** stack minus the network hop: a FastAPI app,
the real ``AuditMiddleware``, the real ``redact.py``, the real ``FileSink``
writing real JSONL to a real directory. The lines are then pushed through
``_es_double.InProcessElasticsearch``, which applies the rules in the actual
``infra/elasticsearch/template-apiaudit.json`` — ``dynamic: false``,
``flattened``, ``total_fields.limit: 200``, ``constant_keyword`` pins.

What that buys, and what it does not:

* A document that indexes cleanly here is a document Elasticsearch would index
  and make searchable. A field the template does not declare fails **here**,
  where it is loud, instead of vanishing silently into ``_source`` in
  production.
* AC-10's field bound is genuinely decided here (§AC-10), not deferred to a
  stack nobody can run.
* Since the adversarial review the double also models the two things it used to
  green-light: a ``keyword`` type mismatch, which ``ignore_malformed`` does not
  cover and which loses the **whole document** (M-5), and Lucene's
  ``MAX_TERM_LENGTH`` on a ``flattened`` leaf (N-9). Both are now decided here.
* What is *not* covered: Filebeat's ndjson decode, ``message_max_bytes``, its
  ``drop_fields`` and quarantine processors, the ``%{[data_stream.*]}`` index
  routing, the data stream itself, ILM, and everything about real
  Elasticsearch's ingest path. That is Tier 1's job — see
  ``test_acceptance_es.py``.

Numbering matches ``docs/REQUIREMENTS.md`` §2 exactly. Same numbers, same
Given/When/Then, in both tiers. AC-18…AC-26 were added by the orchestrator
after the review; where this tier cannot reach a clause of one, the test says
which clause and ``tests/AC-matrix.md`` §4.3 records it rather than quietly
asserting something weaker.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import tracemalloc
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

import audit_logging.document as document_module
from audit_logging.config import AuditConfig
from audit_logging.metrics import InMemoryMetrics
from audit_logging.middleware import AuditMiddleware
from audit_logging.sinks.file_sink import FileSink

from ._apps import STREAM_CHUNKS, make_app, make_wide_app, wide_body
from ._es_double import (
    DocumentRejectedError,
    InProcessElasticsearch,
    UnmappedFieldError,
    dynamic_leaf_paths,
)
from .conftest import IS_ROOT, Audited, build_config

# ---------------------------------------------------------------------------
# The shipper's own numbers, read off the artefact rather than copied into a
# constant here. AC-20's "under Filebeat's message_max_bytes" means the value
# `infra/filebeat/filebeat.yml` actually ships; a test that hardcodes 8 MiB
# keeps passing after A5 lowers it.
# ---------------------------------------------------------------------------

_INFRA = Path(__file__).resolve().parents[2] / "infra"
FILEBEAT_YML = _INFRA / "filebeat" / "filebeat.yml"
COMPOSE_YML = Path(__file__).resolve().parent / "docker-compose.test.yml"


def _filebeat_message_max_bytes() -> int:
    """`message_max_bytes` as `infra/filebeat/filebeat.yml` sets it today."""
    match = re.search(
        r"^\s*message_max_bytes:\s*(\d+)", FILEBEAT_YML.read_text(encoding="utf-8"), re.M
    )
    assert match is not None, "filebeat.yml no longer sets message_max_bytes"
    return int(match.group(1))


def _size_to_bytes(text: str) -> int:
    """`64MB` / `200MB` / `8388608` as a byte count, Filebeat's spelling."""
    match = re.fullmatch(r"(\d+)\s*(KB|MB|GB)?", text.strip(), re.I)
    assert match is not None, f"not a Filebeat size: {text!r}"
    scale = {None: 1, "kb": 1000, "mb": 1000 * 1000, "gb": 1000 * 1000 * 1000}
    return int(match.group(1)) * scale[(match.group(2) or "").lower() or None]


# ===========================================================================
# AC-01 (FR-01) — exactly one document, with the right five fields
# ===========================================================================


async def test_AC_01_one_document_per_request(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """GET /items/{item_id} → 200 → exactly one indexed document."""
    response = await audited.client.get("/items/42")
    assert response.status_code == 200

    documents = await audited.indexed(es)

    assert es.count() == 1, "FR-01: exactly one document per request"
    doc = documents[0]
    assert doc["http"]["request"]["method"] == "GET"
    assert doc["audit"]["route"] == "/items/{item_id}"
    assert doc["http"]["response"]["status_code"] == 200
    assert doc["event"]["outcome"] == "success"
    # The document indexed cleanly: nothing malformed, nothing unmapped.
    assert es.malformed == []


async def test_AC_01_the_document_is_fully_mapped(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """Every field a plain request produces is declared by the template."""
    await audited.client.get("/items/7")
    await audited.flush()
    line = audited.lines()[0]
    outcome = es.index_line(line)  # raises UnmappedFieldError if dynamic:false bites

    assert outcome.unmapped == []
    assert outcome.malformed == []
    assert "audit.request.body" not in outcome.fields  # a GET has no body
    assert "trace.id" in outcome.fields


# ===========================================================================
# AC-02 (FR-02) — excluded paths produce nothing at all
# ===========================================================================


async def test_AC_02_excluded_path_produces_no_document(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """`/health` is on `exclude_paths`; ten calls must leave no trace."""
    for _ in range(10):
        assert (await audited.client.get("/health")).status_code == 200

    await audited.indexed(es)

    assert es.count() == 0
    assert es.search(**{"url.path": "/health"}) == []
    assert audited.metrics.get("audit_documents_submitted_total") == 0.0


async def test_AC_02_an_audited_path_still_works_alongside(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """Exclusion is per-path, not a global off switch."""
    await audited.client.get("/health")
    await audited.client.get("/items/1")
    await audited.client.get("/health")

    await audited.indexed(es)

    assert es.count() == 1
    assert es.documents[0]["url"]["path"] == "/items/1"


# ===========================================================================
# AC-03 (FR-04) — a 3 KB JSON body, replayed byte-identically and parsed
# ===========================================================================


async def test_AC_03_json_body_is_replayed_and_parsed(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """The handler gets the exact bytes; the document gets the parsed object."""
    payload = {"sku": "A-11", "qty": 3, "notes": "x" * 3000}
    raw = json.dumps(payload).encode()
    assert len(raw) > 3000, "AC-03 asks for a body over 3 KB"

    response = await audited.client.post("/echo", content=raw, headers={
        "content-type": "application/json"
    })

    assert response.status_code == 200
    assert audited.received.last == raw, "FR-04: byte-identical replay"
    assert response.content == raw, "the app's own echo came back unchanged"

    documents = await audited.indexed(es)
    doc = documents[0]
    assert doc["audit"]["request"]["body"] == payload
    assert doc["audit"]["request"]["body_parse_failed"] is False
    assert doc["audit"]["request"]["body_truncated"] is False
    assert doc["audit"]["request"]["body_bytes"] == len(raw)
    assert doc["http"]["request"]["bytes"] == len(raw)
    assert doc["http"]["request"]["mime_type"] == "application/json"
    assert es.malformed == []


async def test_AC_03_the_body_costs_exactly_one_mapping_field(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """`flattened`: a body with N keys is still one field (D-10, schema §2.8)."""
    body = {f"key_{i}": i for i in range(60)}
    await audited.client.post("/echo", json=body)
    await audited.flush()

    result = es.index_line(audited.lines()[0])
    body_fields = {f for f in result.fields if f.startswith("audit.request.body")}

    assert "audit.request.body" in body_fields
    assert not any(f.startswith("audit.request.body.") for f in body_fields)


# ===========================================================================
# AC-04 (FR-08) — 2 MB body against a 1 MiB cap
# ===========================================================================


async def test_AC_04_oversized_body_is_truncated_but_replayed_in_full(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """2 MB in, 1 MiB stored, 2 MB delivered to the handler."""
    cap = 1_048_576
    audited: Audited = await make_audited(max_body_bytes=cap)
    filler = "y" * (2 * 1024 * 1024)
    raw = json.dumps({"blob": filler}).encode("ascii")
    assert len(raw) > 2 * 1024 * 1024

    response = await audited.client.post(
        "/echo", content=raw, headers={"content-type": "application/json"}
    )

    assert response.status_code == 200
    assert audited.received.total_bytes == len(raw), "the app receives all 2 MB"
    assert audited.received.last == raw

    documents = await audited.indexed(es)
    request = documents[0]["audit"]["request"]
    assert request["body_truncated"] is True
    assert request["body_bytes"] == cap
    # A body cut mid-JSON cannot parse; FR-09 says so honestly rather than
    # inventing a half-object.
    assert request["body_parse_failed"] is True
    assert "body" not in request, "FR-30 / schema §2.9: not both"

    # AC-04's own clause is "stored raw body ≤ 1 MiB", which the parse-failure
    # path now beats by three orders of magnitude: it clips at 4096 *characters*
    # (`document._MAX_UNPARSED_BODY_RAW`, review S-2 — this is the one
    # unredacted field in the document, so what it keeps is bounded). Asserting
    # the AC's 1 MiB here would pass on a 1 MiB body_raw and test nothing.
    assert document_module._MAX_UNPARSED_BODY_RAW == 4096, (
        "the clip moved; this test and docs/REQUIREMENTS.md §2.2 DEV-2 must move with it"
    )
    assert len(request["body_raw"]) <= 4096, (
        f"the unparseable body_raw is {len(request['body_raw'])} characters, "
        "over the 4096-character clip"
    )
    assert len(request["body_raw"].encode("utf-8")) <= cap, "AC-04's own bound, still true"
    # DEV-2: `body_truncated` now carries both meanings — the max_body_bytes cap
    # and the 4096-character clip. Here both fired.
    assert request["body_raw"] == raw.decode()[:4096]
    # http.request.bytes is what arrived, not what was kept (schema §2.4).
    assert documents[0]["http"]["request"]["bytes"] == len(raw)
    assert es.malformed == []


# ===========================================================================
# AC-05 (FR-10, FR-11) — no denylisted value survives, at any depth
# ===========================================================================


async def test_AC_05_denylisted_values_are_replaced_everywhere(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """The literal AC body: password, nested api_key, token inside a list."""
    await audited.client.post(
        "/ingest", json={"password": "p", "nested": {"api_key": "k"}, "items": [{"token": "t"}]}
    )

    documents = await audited.indexed(es)
    body = documents[0]["audit"]["request"]["body"]

    assert body == {
        "password": "[REDACTED]",
        "nested": {"api_key": "[REDACTED]"},
        "items": [{"token": "[REDACTED]"}],
    }, "FR-11: the keys survive, the values do not"


async def test_AC_05_no_secret_appears_anywhere_in_the_document(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """The same shape with values distinctive enough to grep the whole line for.

    ``p``/``k``/``t`` from the AC are single characters and match half the
    document by accident, so the "appears nowhere" half of AC-05 is asserted
    with sentinels standing in for them.
    """
    secrets = {
        "p": "SENTINEL-PASSWORD-9f2c1a7d",
        "k": "SENTINEL-APIKEY-4e8b4f0a",
        "t": "SENTINEL-TOKEN-a1c3d5e7",
    }
    await audited.client.post(
        "/ingest",
        json={
            "password": secrets["p"],
            "nested": {"api_key": secrets["k"]},
            "items": [{"token": secrets["t"]}],
        },
        params={"access_token": "SENTINEL-QUERY-f9b0c2d4"},
        headers={
            "authorization": "Bearer SENTINEL-HEADER-1234",
            "cookie": "session=SENTINEL-COOKIE-5678",
        },
    )

    await audited.flush()
    line = audited.lines()[0]

    for label, secret in secrets.items():
        assert secret not in line, f"AC-05: the {label} secret survived into the document"
    assert "SENTINEL-QUERY" not in line, "FR-14: query values use the same denylist"
    assert "SENTINEL-HEADER" not in line, "FR-12: Authorization is not allowlisted"
    assert "SENTINEL-COOKIE" not in line, "FR-12: Cookie is not allowlisted"
    assert "[REDACTED]" in line

    es.index_line(line)
    assert es.malformed == []


async def test_AC_05_the_application_object_is_not_mutated(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """FR-10: redaction is pure — the app's echo still carries the real value."""
    raw = json.dumps({"password": "SENTINEL-PURE-abc"}).encode()
    response = await audited.client.post(
        "/echo", content=raw, headers={"content-type": "application/json"}
    )

    assert response.content == raw, "the handler's own bytes are untouched"
    await audited.flush()
    assert "SENTINEL-PURE-abc" not in audited.lines()[0]


# ===========================================================================
# AC-06 (FR-12) — headers are an allowlist, and dropped ones vanish
# ===========================================================================


async def test_AC_06_credential_headers_never_appear(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    await audited.client.post(
        "/ingest",
        json={"ok": True},
        headers={
            "authorization": "Bearer abc123",
            "cookie": "session=xyz",
            "x-internal-thing": "should-vanish",
        },
    )

    documents = await audited.indexed(es)
    headers = documents[0]["audit"]["request"]["headers"]

    assert "authorization" not in headers, "FR-12: not even as a placeholder"
    assert "cookie" not in headers
    assert "x-internal-thing" not in headers
    assert headers["content-type"].startswith("application/json")
    assert "user-agent" in headers
    assert "[REDACTED]" not in json.dumps(headers), "dropped, not redacted"


# ===========================================================================
# AC-07 (FR-03) — an unrouted path is logged as "unmatched"
# ===========================================================================


async def test_AC_07_unmatched_route_is_logged_with_its_404(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    response = await audited.client.get("/no/such/endpoint")
    assert response.status_code == 404

    documents = await audited.indexed(es)
    doc = documents[0]

    assert doc["audit"]["route"] == "unmatched"
    assert doc["http"]["response"]["status_code"] == 404
    assert doc["url"]["path"] == "/no/such/endpoint"
    # A 4xx is the app doing its job (schema §2.2), not a failure.
    assert doc["event"]["outcome"] == "success"


# ===========================================================================
# AC-08 (FR-01, NFR-3) — an application exception is logged and re-raised
# ===========================================================================


async def test_AC_08_application_exception_propagates_and_is_logged(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    with pytest.raises(ValueError, match="kaboom") as raised:
        await audited.client.get("/boom")

    assert type(raised.value) is ValueError, "NFR-3: propagates unchanged"

    documents = await audited.indexed(es)
    doc = documents[0]

    assert doc["event"]["outcome"] == "failure"
    assert doc["http"]["response"]["status_code"] == 500
    assert doc["error"]["type"] == "ValueError"
    assert doc["error"]["message"] == "kaboom"
    assert "stack" not in json.dumps(doc).lower(), "schema §2.6: no stack trace"
    assert es.malformed == []


# ===========================================================================
# AC-09 (FR-19) — a full queue drops documents, never requests
# ===========================================================================


async def test_AC_09_full_queue_drops_documents_and_serves_every_request(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """`queue_max_bytes` below one batch: the API is unaffected, the log is not."""
    audited: Audited = await make_audited(
        queue_max_bytes=4096,
        flush_max_bytes=4096,
        # Long enough that nothing drains during the test: the queue really is
        # the bound being tested, not the flusher's speed.
        flush_interval_seconds=30.0,
    )

    statuses = []
    for index in range(200):
        response = await audited.client.post("/ingest", json={"n": index})
        statuses.append(response.status_code)

    assert statuses == [200] * 200, "FR-19: the request path is never affected"

    dropped = audited.metrics.get("audit_documents_dropped_total")
    submitted = audited.metrics.get("audit_documents_submitted_total")
    assert dropped > 0, "the byte bound must actually bite"
    assert submitted + dropped == 200, "every request was accounted for"
    assert audited.metrics.get("audit_middleware_errors_total") == 0.0

    # What did survive is still a valid, fully-mapped document.
    await audited.indexed(es)
    assert es.malformed == []


# ===========================================================================
# AC-10 (mapping bound) — 50 endpoints x 200 requests, ≤ 200 mapped fields
# ===========================================================================


async def test_AC_10_fifty_endpoints_two_hundred_requests_stay_under_the_bound(
    audit_log_dir: Path, es: InProcessElasticsearch
) -> None:
    """The field-budget test. This is what `flattened` is for (D-10, plan §8.3).

    50 routes x 200 requests, every request carrying keys no other request
    uses. Under a ``dynamic: true`` mapping each of those keys would become a
    field; here they all land inside ``audit.request.body``, which costs one.
    """
    endpoints, per_endpoint = 50, 200
    config = build_config(
        audit_log_dir,
        service_name="wide-api",
        flush_interval_seconds=0.05,
        queue_max_bytes=256 * 1024 * 1024,
        flush_max_bytes=16 * 1024 * 1024,
        file_max_bytes=1024 * 1024 * 1024,
    )
    metrics = InMemoryMetrics()
    sink = FileSink(config, metrics)
    app = make_wide_app(endpoints)
    app.add_middleware(AuditMiddleware, config=config, sink=sink, metrics=metrics)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://audit.test") as client:
        try:
            for endpoint in range(endpoints):
                await asyncio.gather(
                    *(
                        client.post(
                            f"/e{endpoint}/{index}", json=wide_body(endpoint, index)
                        )
                        for index in range(per_endpoint)
                    )
                )
            await sink.flush()
        finally:
            await sink.close()

    expected = endpoints * per_endpoint
    assert metrics.get("audit_documents_submitted_total") == float(expected)
    assert metrics.get("audit_documents_dropped_total") == 0.0

    lines = [raw for raw in (l.strip() for l in sink.path.read_text().splitlines()) if raw]
    assert len(lines) == expected, "every document reached the file"

    dynamic_would_be: set[str] = set()
    for line in lines:
        es.index_line(line)  # raises if any field is outside the template
        dynamic_would_be |= dynamic_leaf_paths(json.loads(line))

    field_count = es.mapping_field_count()
    limit = es.template.total_fields_limit
    assert limit == 200, "the template's own bound is what AC-10 quotes"
    assert field_count <= limit, (
        f"AC-10: {expected} documents reached {field_count} mapped fields, "
        f"over the {limit}-field limit"
    )
    # The template is dynamic:false, so the ceiling is a constant, not a race.
    assert len(es.template.declared_field_paths()) <= limit

    # And the counterfactual, which is the whole point: without `flattened`,
    # this exact traffic is a mapping explosion.
    assert len(dynamic_would_be) > limit, (
        "the fan-out was too small to prove anything: a dynamic mapping would "
        f"only have created {len(dynamic_would_be)} fields"
    )
    print(
        f"\nAC-10: {expected} docs / {endpoints} endpoints -> "
        f"{field_count} mapped fields (limit {limit}); "
        f"a dynamic:true mapping would have created {len(dynamic_would_be)}"
    )


# ===========================================================================
# AC-11 (FR-15) — the kill switch produces nothing and opens no file
# ===========================================================================


async def test_AC_11_kill_switch_produces_no_document_and_no_file(
    audit_log_dir: Path, monkeypatch: pytest.MonkeyPatch, es: InProcessElasticsearch
) -> None:
    """`AUDIT_ENABLED=false` from the environment, as a restart would set it."""
    monkeypatch.setenv("AUDIT_ENABLED", "false")
    monkeypatch.setenv("AUDIT_SERVICE_NAME", "orders-api")
    monkeypatch.setenv("AUDIT_LOG_DIR", str(audit_log_dir))
    config = AuditConfig()  # type: ignore[call-arg]  # everything comes from env
    assert config.enabled is False

    metrics = InMemoryMetrics()
    app, _ = make_app()
    # No `sink=`: with the kill switch on, a FileSink would be constructed and
    # a file opened. FR-15 says neither happens.
    app.add_middleware(AuditMiddleware, config=config, metrics=metrics)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://audit.test") as client:
        for index in range(10):
            assert (await client.get(f"/items/{index}")).status_code == 200
        assert (await client.post("/ingest", json={"a": 1})).status_code == 200

    assert list(audit_log_dir.iterdir()) == [], "FR-15: no log file is created"
    assert metrics.snapshot() == InMemoryMetrics().snapshot(), "no counter moved"
    assert es.count() == 0


# ===========================================================================
# AC-12 (FR-22) — three rotations, and not one line lost
# ===========================================================================


async def test_AC_12_rotation_keeps_every_line(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """64 KiB files, three rotations, every line still indexable."""
    audited: Audited = await make_audited(
        file_max_bytes=64 * 1024,
        file_backup_count=8,
        flush_interval_seconds=30.0,  # rotation is driven by explicit flushes
    )

    sent = 0
    deadline = time.monotonic() + 60.0
    while audited.metrics.get("audit_file_rotations_total") < 3.0:
        assert time.monotonic() < deadline, "rotation never happened"
        for _ in range(10):
            response = await audited.client.post("/ingest", json={"seq": sent, "pad": "z" * 200})
            assert response.status_code == 200
            sent += 1
        await audited.flush()

    assert audited.metrics.get("audit_file_rotations_total") == 3.0
    await audited.flush()

    rotated = audited.rotated_paths()
    assert [p.name for p in rotated] == [
        f"{audited.path.name}.1",
        f"{audited.path.name}.2",
        f"{audited.path.name}.3",
    ]
    assert not Path(f"{audited.path}.4").exists()

    lines = audited.lines(include_rotated=True)
    assert len(lines) == sent, (
        f"AC-12: {sent} documents submitted, {len(lines)} lines survived rotation"
    )
    for line in lines:
        es.index_line(line)
    assert es.count() == sent
    assert es.malformed == []
    # Order across the rotation boundary is submission order (FR-20r).
    sequences = [d["audit"]["request"]["body"]["seq"] for d in es.documents]
    assert sequences == list(range(sent))


# ===========================================================================
# AC-13 (FR-06) — a streaming response is timed to its last chunk
# ===========================================================================


async def test_AC_13_streaming_duration_reaches_the_last_chunk(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """Five chunks 100 ms apart: `event.duration` must clear 400 ms."""
    response = await audited.client.get("/stream")
    assert response.status_code == 200

    expected_bytes = sum(len(f"chunk-{i};".encode()) for i in range(STREAM_CHUNKS))
    assert len(response.content) == expected_bytes

    documents = await audited.indexed(es)
    doc = documents[0]

    # event.duration is NANOSECONDS (ECS, schema §2.2). 400 ms = 4e8 ns.
    assert doc["event"]["duration"] >= 400_000_000, (
        f"FR-06: duration {doc['event']['duration']} ns is under 400 ms — "
        "the clock stopped before the last chunk"
    )
    assert doc["http"]["response"]["bytes"] == expected_bytes
    assert doc["event"]["outcome"] == "success"


# ===========================================================================
# AC-14 (FR-09) — unparseable JSON keeps the raw text, verbatim
# ===========================================================================


async def test_AC_14_broken_json_keeps_the_raw_text(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    raw = b"{not json"

    response = await audited.client.post(
        "/echo", content=raw, headers={"content-type": "application/json"}
    )

    assert response.status_code == 200
    assert audited.received.last == raw, "FR-09: the handler's bytes are unchanged"
    assert response.content == raw

    documents = await audited.indexed(es)
    request = documents[0]["audit"]["request"]

    assert request["body_parse_failed"] is True
    assert request["body_raw"] == "{not json"
    assert "body" not in request, "there is no object to put in the flattened field"
    assert es.malformed == []


async def test_AC_14_a_parse_failure_is_the_only_unredacted_body_raw(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """The documented consequence of AC-14 (schema §10, docs/redaction.md).

    ``body_raw`` is normally the *redacted re-dump*; a body that never parsed
    has nothing to re-dump, so its text is kept verbatim — secrets included.
    This test pins that trade-off so it stays a decision, not a surprise.
    """
    await audited.client.post(
        "/echo",
        content=b'{"password": "SENTINEL-UNPARSEABLE-9",',
        headers={"content-type": "application/json"},
    )
    await audited.flush()
    line = audited.lines()[0]

    assert "SENTINEL-UNPARSEABLE-9" in line, (
        "if this ever starts passing, AC-14's known limitation was fixed — "
        "update docs/redaction.md and this test together"
    )
    es.index_line(line)


# ===========================================================================
# AC-15 (FR-20r) — 1000 documents, on disk in order, within 1.5 s
# ===========================================================================


async def test_AC_15_a_thousand_documents_land_within_the_interval(
    audited: Audited, audit_log_dir: Path, es: InProcessElasticsearch
) -> None:
    """`flush_interval_seconds = 1.0`; nothing else may be doing the work.

    The batch is ~1 MB, well under the 4 MiB `flush_max_bytes` trigger, so this
    really does test the interval and not the size path.
    """
    # A real document, so what is written is what production writes.
    await audited.client.post("/ingest", json={"sku": "A-11", "qty": 3})
    await audited.flush()
    prototype = json.loads(audited.lines()[0])

    config = build_config(
        audit_log_dir,
        service_name="burst-api",
        flush_interval_seconds=1.0,
        queue_max_bytes=64 * 1024 * 1024,
        flush_max_bytes=4 * 1024 * 1024,
    )
    metrics = InMemoryMetrics()
    sink = FileSink(config, metrics)
    await sink.start()
    try:
        started = time.monotonic()
        for index in range(1000):
            document = dict(prototype)
            document["trace"] = {"id": f"burst-{index:04d}"}
            assert sink.submit(document) is True
        submit_seconds = time.monotonic() - started
        assert submit_seconds < 0.1, (
            f"the premise failed: submitting 1000 documents took {submit_seconds * 1e3:.1f} ms"
        )
        assert sink.held_bytes < 4 * 1024 * 1024, "the size trigger must not fire"

        deadline = started + submit_seconds + 1.5
        lines: list[str] = []
        while time.monotonic() < deadline:
            if sink.path.exists():
                lines = [
                    raw for raw in (l.strip() for l in sink.path.read_text().splitlines()) if raw
                ]
                if len(lines) >= 1000:
                    break
            await asyncio.sleep(0.02)
        landed_after = time.monotonic() - (started + submit_seconds)
    finally:
        await sink.close()

    assert len(lines) == 1000, (
        f"AC-15: only {len(lines)} of 1000 lines were on disk after 1.5 s"
    )
    assert landed_after <= 1.5
    order = [json.loads(line)["trace"]["id"] for line in lines]
    assert order == [f"burst-{i:04d}" for i in range(1000)], "FR-20r: submission order"
    for line in lines:
        es.index_line(line)
    assert es.malformed == []
    print(f"\nAC-15: 1000 documents submitted in {submit_seconds * 1e3:.1f} ms, "
          f"on disk {landed_after * 1e3:.0f} ms later")


# ===========================================================================
# AC-16 (FR-21r) — an unwritable log directory costs documents, not requests
# ===========================================================================


@pytest.mark.skipif(IS_ROOT, reason="root ignores file-mode bits, so nothing fails")
async def test_AC_16_unwritable_log_dir_never_reaches_the_request_path(
    make_audited: Callable[..., Any],
    audit_log_dir: Path,
    restore_modes: list[tuple[Path, int]],
) -> None:
    """50 documents, then the directory goes read-only, then 50 more.

    The sink holds an open descriptor, so the permission change only bites when
    it next needs to open a file — which is exactly what rotation does. Small
    `file_max_bytes` makes that happen on the first flush after the change,
    with no test access to the sink's internals.
    """
    audited: Audited = await make_audited(
        file_max_bytes=4096,
        file_backup_count=8,
        flush_interval_seconds=30.0,
    )

    for index in range(50):
        assert (await audited.client.post("/ingest", json={"n": index})).status_code == 200
        if index % 10 == 9:
            await audited.flush()
    await audited.flush()
    assert audited.metrics.get("audit_documents_failed_total") == 0.0
    assert audited.path.exists()

    active = audited.path
    restore_modes.append((audit_log_dir, audit_log_dir.stat().st_mode & 0o7777))
    restore_modes.append((active, active.stat().st_mode & 0o7777))
    try:
        os.chmod(active, 0o400)  # cannot be reopened for writing
        os.chmod(audit_log_dir, 0o500)  # cannot be renamed, created or unlinked

        statuses = []
        for index in range(50, 100):
            statuses.append((await audited.client.post("/ingest", json={"n": index})).status_code)
            if index % 10 == 9:
                await audited.flush()
        await audited.flush()

        assert statuses == [200] * 50, "FR-21r: a dead disk is not the API's problem"
        failed = audited.metrics.get("audit_documents_failed_total")
        assert failed >= 50.0, f"AC-16: only {failed} documents were counted as failed"
        assert audited.metrics.get("audit_middleware_errors_total") == 0.0
    finally:
        os.chmod(audit_log_dir, 0o700)
        os.chmod(active, 0o600)

    # The process is obviously still alive: it just ran the assertions above.
    assert (await audited.client.get("/items/1")).status_code == 200


# ===========================================================================
# AC-17 (FR-25) — a resolver that raises costs a counter, never the document
# ===========================================================================


def _exploding_resolver(scope: dict[str, Any]) -> dict[str, Any] | None:
    raise RuntimeError("the identity service is down")


async def test_AC_17_raising_user_resolver_still_produces_the_document(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    audited: Audited = await make_audited(user_resolver=_exploding_resolver)

    response = await audited.client.get("/whoami")
    assert response.status_code == 200

    documents = await audited.indexed(es)

    assert es.count() == 1, "FR-25: the document is still emitted"
    assert "user" not in documents[0], "…without user.*"
    assert audited.metrics.get("audit_middleware_errors_total") == 1.0
    assert es.malformed == []


async def test_AC_17_a_working_resolver_populates_only_id_name_roles(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """The other half of FR-25, so the AC-17 counter means something."""

    def resolver(scope: dict[str, Any]) -> dict[str, Any] | None:
        return {"id": "u-8813", "name": "a.karimov", "roles": ["operator"], "email": "x@y.z"}

    audited: Audited = await make_audited(user_resolver=resolver)
    await audited.client.get("/whoami")

    documents = await audited.indexed(es)

    assert documents[0]["user"] == {
        "id": "u-8813",
        "name": "a.karimov",
        "roles": ["operator"],
    }, "schema §2.5: user.* is not dynamic, so `email` must be dropped"
    assert audited.metrics.get("audit_middleware_errors_total") == 0.0
    assert es.malformed == []


# ===========================================================================
# AC-18 (FR-28) — the M-1 regression: text bodies store NOTHING by default
#
# The defect: a client sending `Content-Type: text/plain` (or no content type
# at all) got its body stored with the key denylist never applied, because
# there were no keys to apply it to. One header defeated the entire denylist.
# ===========================================================================


AC_18_CONTENT_TYPES = [
    pytest.param("text/plain", id="text-plain"),
    pytest.param("application/xml", id="application-xml"),
    pytest.param(None, id="no-content-type"),
]


@pytest.mark.parametrize("content_type", AC_18_CONTENT_TYPES)
async def test_AC_18_a_body_the_denylist_cannot_reach_is_not_stored(
    audited: Audited, es: InProcessElasticsearch, content_type: str | None
) -> None:
    """`{"password":"p"}` as text: no `p`, `body_skipped`, and neither body field."""
    secret = "SENTINEL-M1-9f2c1a7d"
    raw = json.dumps({"password": secret}).encode()
    headers = {"content-type": content_type} if content_type else {}

    response = await audited.client.post("/echo", content=raw, headers=headers)

    assert response.status_code == 200
    assert audited.received.last == raw, "FR-04 still holds: the app gets its bytes"

    await audited.flush()
    line = audited.lines()[0]
    assert secret not in line, (
        f"M-1: the denylist was defeated by Content-Type {content_type!r} — "
        "the body was stored with no key-based redaction possible"
    )

    documents = await audited.indexed(es)
    request = documents[0]["audit"]["request"]
    assert request["body_skipped"] == "content_type", "FR-28 / schema §2.9"
    assert "body" not in request
    assert "body_raw" not in request
    # The metadata FR-07 does keep is still there, so the record is not blind.
    assert request["body_bytes"] == len(raw)
    assert documents[0]["http"]["request"]["bytes"] == len(raw)
    assert es.malformed == []


async def test_AC_18_capture_text_bodies_is_the_only_way_in_and_it_scrubs(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """The FR-28 opt-in, and its documented weakness, both pinned.

    `capture_text_bodies` is a *best-effort textual* scrub, explicitly weaker
    than the structured path. It catches `"password": "..."` in a JSON-shaped
    text body; it is not claimed to catch everything, and this test says which
    of the two it is rather than implying the strong guarantee.
    """
    audited: Audited = await make_audited(capture_text_bodies=True)
    raw = json.dumps({"password": "SENTINEL-SCRUBBED-1", "note": "kept"}).encode()

    await audited.client.post("/echo", content=raw, headers={"content-type": "text/plain"})

    documents = await audited.indexed(es)
    request = documents[0]["audit"]["request"]

    assert "body_raw" in request, "the opt-in stores the text"
    assert "body" not in request, "FR-30: still never both"
    assert "body_skipped" not in request
    assert "SENTINEL-SCRUBBED-1" not in json.dumps(documents[0]), (
        "the best-effort scrub missed a quoted denylisted key"
    )
    assert "kept" in request["body_raw"], "the scrub is not a blanket redaction"
    assert es.malformed == []


# ===========================================================================
# AC-19 (FR-29) — a shape bomb costs a `too_complex` flag, not the event loop
# ===========================================================================


async def test_AC_19_a_1MiB_shape_bomb_is_refused_as_too_complex(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """1 MiB of `[[],[],…]`: no body stored, and the request does not stall.

    Review M-2 measured 140 ms on the event loop for this body, which stalls
    every concurrent request in the worker at ~9 req/s. FR-29 refuses it from
    the raw bytes, before the parse, so the cost is a scan and nothing more.
    """
    payload = b"[" + b"[]," * 350_000 + b"[]]"
    assert len(payload) > 1024 * 1024, "AC-19 asks for a 1 MiB body"

    started = time.monotonic()
    response = await audited.client.post(
        "/echo", content=payload, headers={"content-type": "application/json"}
    )
    elapsed = time.monotonic() - started

    assert response.status_code == 200
    documents = await audited.indexed(es)
    request = documents[0]["audit"]["request"]

    assert request["body_skipped"] == "too_complex", "FR-29 / schema §2.9"
    assert "body" not in request and "body_raw" not in request, "no body is stored"
    assert es.malformed == []

    # AC-19's "< 5 ms" is about `build_document` alone and is asserted at unit
    # level. What this tier can honestly say is that the whole round trip —
    # 1 MiB through ASGI, the node scan, the document, the sink — is nowhere
    # near M-2's 140 ms of *parsing*, so the refusal really did happen early.
    assert elapsed < 0.25, (
        f"the request took {elapsed * 1e3:.0f} ms; FR-29 refuses before parsing, "
        "so a shape bomb must not be paid for"
    )
    print(f"\nAC-19: 1 MiB shape bomb refused in {elapsed * 1e3:.1f} ms round trip")


# ===========================================================================
# AC-20 (FR-30) — the M-3 regression: never both, and the line always fits
#
# Storing `body` *and* `body_raw` doubled every line. A 1 MiB body produced a
# 2,097,957-byte line, 805 bytes past Filebeat's then `message_max_bytes`; the
# line was truncated, failed ndjson decode, and was discarded by `drop_event`.
# The largest and most interesting audit records never reached Elasticsearch
# and no counter recorded the loss.
# ===========================================================================


async def test_AC_20_body_and_body_raw_are_never_both_present(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """Every row of schema §2.9's nine-row table, in one sweep."""
    audited: Audited = await make_audited(capture_text_bodies=True)
    client = audited.client
    json_ct = {"content-type": "application/json"}

    await client.post("/echo", content=b'{"a":1}', headers=json_ct)  # parseable
    await client.post("/echo", content=b"[1,2]", headers=json_ct)  # non-object
    await client.post(
        "/echo",
        content=b"a=1&b=2",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    await client.post("/echo", content=b"{not json", headers=json_ct)  # parse failure
    await client.post("/echo", content=b"hello", headers={"content-type": "text/plain"})
    await client.post("/echo", files={"f": ("a.txt", b"hello", "text/plain")})  # multipart
    await client.post(
        "/echo", content=b"\x00\x01", headers={"content-type": "application/octet-stream"}
    )
    await client.post("/echo", content=b"[" + b"[]," * 262_000 + b"[]]", headers=json_ct)
    await client.post("/echo", content=b"", headers=json_ct)  # empty
    await client.get("/items/1")  # no body at all

    documents = await audited.indexed(es)
    assert len(documents) == 10

    for doc in documents:
        request = doc["audit"]["request"]
        present = [key for key in ("body", "body_raw") if key in request]
        assert len(present) <= 1, (
            f"FR-30 / schema §2.9: {doc['http']['request'].get('mime_type')!r} "
            f"emitted both {present}"
        )
    # The table is not vacuously satisfied: both fields really are reachable.
    kinds = {tuple(k for k in ("body", "body_raw") if k in d["audit"]["request"]) for d in documents}
    assert ("body",) in kinds and ("body_raw",) in kinds and () in kinds
    assert es.malformed == []


async def test_AC_20_a_1MiB_body_produces_a_line_under_message_max_bytes(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """The other half of AC-20, against the shipper's own number.

    Four 1 MiB bodies covering both halves of schema §2.9 and the expansion
    factors A5 re-derived in `filebeat.yml`'s SIZING INVARIANTS block:

    * ``stored_ascii`` / ``stored_quotes`` — captured whole and parsed, so the
      line carries a full ``body``. This is the case M-3 was about: under
      D-10's "both" the same body was stored twice and the line was 2,097,957 B
      against a then 2 MiB ``message_max_bytes``.
    * ``clipped_cut`` — a body larger than ``max_body_bytes``, cut mid-JSON, so
      it takes the FR-09 parse-failure path.
    * ``clipped_control`` — raw control characters, which are illegal inside a
      JSON string. Also a parse failure, and the path where A5's worst case
      lives: 1 MiB of ``0x01`` JSON-escapes to ``\\u0001`` six bytes at a time,
      6,292,571 B, which A8's 2-3x estimate missed.
    """
    limit = _filebeat_message_max_bytes()
    assert limit == 8 * 1024 * 1024, (
        f"filebeat.yml now ships message_max_bytes={limit}; re-derive the worst "
        "case in its SIZING INVARIANTS block before relaxing this test"
    )
    mib = 1024 * 1024
    # 2 MiB, so a 1 MiB body is captured *whole* and really is stored. At
    # max_body_bytes == 1 MiB every case below would be truncated mid-JSON and
    # take the clip path, and the stored-body half of AC-20 would go untested.
    audited: Audited = await make_audited(max_body_bytes=2 * mib)

    cases = {
        "stored_ascii": b'{"blob":"' + b"y" * mib + b'"}',
        "stored_quotes": b'{"blob":"' + b'\\"' * (mib // 2) + b'"}',
        "clipped_cut": b'{"blob":"' + b"y" * (3 * mib) + b'"}',
        "clipped_control": b'{"blob":"' + b"\x01" * mib + b'"}',
    }
    for label, payload in cases.items():
        response = await audited.client.post(
            "/echo", content=payload, headers={"content-type": "application/json"}
        )
        assert response.status_code == 200, label

    await audited.flush()
    lines = audited.lines()
    assert len(lines) == len(cases)

    sizes = {}
    for label, line in zip(cases, lines):
        size = len(line.encode("utf-8")) + 1  # + the newline Filebeat reads
        sizes[label] = size
        assert size <= limit, (
            f"M-3: a 1 MiB {label} body produced a {size}-byte JSONL line, over "
            f"Filebeat's message_max_bytes of {limit}. That line is truncated, "
            "fails ndjson decode, and is quarantined instead of indexed."
        )
        print(f"\nAC-20: {label:16s} -> {size:9d} B line "
              f"({size / mib:.2f}x the body, {100 * size / limit:.1f}% of "
              "message_max_bytes)")

    # The premise: the stored cases really do carry a megabyte of body, so the
    # bound above is being tested and not merely satisfied by a clipped line.
    assert sizes["stored_ascii"] > mib, "the 1 MiB body was not actually stored"
    assert sizes["stored_ascii"] < 2 * mib, (
        f"M-3: a 1 MiB body produced a {sizes['stored_ascii']} B line — that is "
        "the doubled line D-10 used to produce, i.e. body and body_raw are both "
        "being written again"
    )

    documents = await audited.indexed(es)
    stored = [d for d in documents if "body" in d["audit"]["request"]]
    clipped = [d for d in documents if "body_raw" in d["audit"]["request"]]
    assert len(stored) == 2 and len(clipped) == 2, "both halves of §2.9 exercised"
    for doc in documents:
        request = doc["audit"]["request"]
        assert not ("body" in request and "body_raw" in request)
    assert es.malformed == []


def test_AC_20_the_acceptance_stacks_disk_queue_can_hold_that_line() -> None:
    """The layer under M-3: Filebeat's disk queue drops an oversized event too.

    `diskqueue.handleProducerWriteRequest` (beats v8.13.4 `core_loop.go`)
    refuses any event larger than `segment_size - segmentHeaderSize` with a
    `Warnf` and **drops it** — the same quiet loss as M-3, one layer down. The
    invariants in `filebeat.yml` require `segment_size >= 2 x message_max_bytes`
    and `max_size >= 2 x segment_size`; the compose stack overrides both, so
    the overrides are what have to satisfy them.
    """
    compose = COMPOSE_YML.read_text(encoding="utf-8")
    overrides = dict(
        re.findall(r"queue\.disk\.(max_size|segment_size)=([0-9]+[KMG]?B?)", compose)
    )
    assert set(overrides) == {"max_size", "segment_size"}, (
        f"the compose stack no longer overrides both: {overrides}"
    )
    segment = _size_to_bytes(overrides["segment_size"])
    max_size = _size_to_bytes(overrides["max_size"])
    message_max = _filebeat_message_max_bytes()

    assert segment >= 2 * message_max, (
        f"queue.disk.segment_size={overrides['segment_size']} ({segment} B) is under "
        f"2 x message_max_bytes ({2 * message_max} B). A worst-case line is accepted "
        "by the input and then silently dropped by the disk queue with only a warn."
    )
    assert max_size >= 2 * segment, (
        f"Filebeat validates max_size >= 2 x segment_size; {overrides} fails it and "
        "the shipper will not start"
    )


# ===========================================================================
# AC-21 (FR-31) — `user.*` is coerced, because a bad value costs the document
# ===========================================================================


async def test_AC_21_user_values_are_coerced_to_the_types_the_schema_declares(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """AC-21's literal resolver: `{"id": 7, "roles": {"a": "b"}}`."""

    def resolver(scope: dict[str, Any]) -> dict[str, Any] | None:
        return {"id": 7, "name": 3.5, "roles": {"a": "b"}}

    audited: Audited = await make_audited(user_resolver=resolver)
    await audited.client.get("/whoami")

    documents = await audited.indexed(es)
    user = documents[0]["user"]

    assert user["id"] == "7", "FR-31: keyword, so an int is coerced to str"
    assert user["name"] == "3.5"
    assert "roles" not in user, "a dict will not coerce to list[str], so it is dropped"
    assert audited.metrics.get("audit_middleware_errors_total") == 0.0
    assert es.rejected == [], "M-5: the document must not be rejectable"
    assert es.malformed == []


async def test_AC_21_every_user_value_matches_schema_2_5(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """The general clause, over the shapes a hostile resolver can return."""

    def resolver(scope: dict[str, Any]) -> dict[str, Any] | None:
        return {
            "id": ["a", "list"],
            "name": None,
            "roles": ["operator", 7, {"nope": 1}, None],
        }

    audited: Audited = await make_audited(user_resolver=resolver)
    await audited.client.get("/whoami")

    documents = await audited.indexed(es)
    user = documents[0].get("user", {})

    for key, value in user.items():
        assert key in ("id", "name", "roles"), "schema §2.5 declares three fields"
        if key == "roles":
            assert isinstance(value, list) and all(isinstance(x, str) for x in value)
        else:
            assert isinstance(value, str)
    assert es.rejected == []


def test_AC_21_the_uncoerced_shape_really_would_have_lost_the_document(
    es: InProcessElasticsearch,
) -> None:
    """Proof the AC-21 tests above are not passing vacuously (review M-5).

    If `_user_block` ever stops coercing, this is the document that reaches
    Elasticsearch — and Elasticsearch answers it with a
    `mapper_parsing_exception` and drops the whole audit record, because
    `index.mapping.ignore_malformed` does not cover `keyword`.
    """
    uncoerced = {
        "@timestamp": "2026-09-05T11:22:33.123456Z",
        "user": {"id": "u-1", "roles": {"a": "b"}},
    }
    with pytest.raises(DocumentRejectedError, match="user.roles"):
        es.index(uncoerced)
    assert es.count() == 0, "the whole record is lost, not just user.roles"


# ===========================================================================
# AC-22 (FR-08, M-4) — buffering costs the body, not the number of chunks
#
# The defect: the capture buffer was a list of chunks, and the *client* picks
# the chunk size. 1 MiB dribbled in 2-byte chunks became 524 288 `bytes`
# objects at ~35 B of object overhead each — 28 MB of RSS for a 1 MiB body,
# times every concurrent request. `max_body_bytes` bounded the wrong number.
# ===========================================================================


def _dribble_scope(content_type: str) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/dribble",
        "raw_path": b"/dribble",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", content_type.encode())],
        "client": ("10.0.0.1", 51234),
        "server": ("audit.test", 80),
    }


async def _sink_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    """Reads the whole body and answers small — the AC-22 app under audit."""
    while True:
        message = await receive()
        if not message.get("more_body"):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def _dribble(middleware: Any, payload: bytes, chunk: int, content_type: str) -> None:
    """Feed *payload* to *middleware* `chunk` bytes at a time.

    Deliberately index-based: materialising the chunk list up front would
    allocate the very thing this test exists to measure.
    """
    total = len(payload)
    cursor = 0

    async def receive() -> dict[str, Any]:
        nonlocal cursor
        if cursor >= total:
            return {"type": "http.request", "body": b"", "more_body": False}
        piece = payload[cursor : cursor + chunk]
        cursor += chunk
        return {"type": "http.request", "body": piece, "more_body": cursor < total}

    async def send(message: dict[str, Any]) -> None:
        return None

    await middleware(_dribble_scope(content_type), receive, send)


async def _peak_bytes(
    middleware: Any, payload: bytes, *, chunk: int, concurrency: int, content_type: str
) -> int:
    """Peak Python heap while *concurrency* dribbles are simultaneously in flight."""
    await _dribble(middleware, payload, chunk, content_type)  # warm the caches
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        await asyncio.gather(
            *(_dribble(middleware, payload, chunk, content_type) for _ in range(concurrency))
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return int(peak)


AC_22_BODY = 128 * 1024
AC_22_CONCURRENCY = 4


@pytest.fixture
async def dribbled(audit_log_dir: Path) -> AsyncIterator[Any]:
    """A middleware over a real FileSink, callable as a bare ASGI app."""
    sinks: list[FileSink] = []

    def factory(**overrides: Any) -> Any:
        config = build_config(audit_log_dir, **overrides)
        sink = FileSink(config, InMemoryMetrics())
        sinks.append(sink)
        return AuditMiddleware(
            _sink_app, config=config, sink=sink, metrics=InMemoryMetrics()
        )

    yield factory
    for sink in sinks:
        await sink.close()


async def test_AC_22_buffering_a_dribbled_body_stays_under_twice_the_cap(
    dribbled: Callable[..., Any]
) -> None:
    """The AC-22 clause, isolated to the buffer it is about.

    An `application/octet-stream` body is captured and then *not* stored
    (FR-07), so nothing is parsed, redacted or re-serialised and the only
    allocation left is the capture buffer itself — which is precisely what M-4
    was about. 2-byte chunks, four requests in flight.
    """
    middleware = dribbled(max_body_bytes=AC_22_BODY)
    payload = b"y" * AC_22_BODY

    peak = await _peak_bytes(
        middleware,
        payload,
        chunk=2,
        concurrency=AC_22_CONCURRENCY,
        content_type="application/octet-stream",
    )

    budget = 2 * AC_22_BODY * AC_22_CONCURRENCY
    list_of_chunks = (AC_22_BODY // 2) * AC_22_CONCURRENCY * 33  # ~33 B/bytes object
    assert peak <= budget, (
        f"M-4: {AC_22_CONCURRENCY} x {AC_22_BODY} B dribbled in 2-byte chunks "
        f"peaked at {peak / 1e6:.2f} MB, over the 2 x max_body_bytes per request "
        f"budget of {budget / 1e6:.2f} MB"
    )
    assert list_of_chunks > budget * 4, "the premise: a chunk list really would blow this"
    print(
        f"\nAC-22: {AC_22_CONCURRENCY} x {AC_22_BODY // 1024} KiB in 2-byte chunks "
        f"peaked at {peak / 1e6:.2f} MB (budget {budget / 1e6:.2f} MB; a list of "
        f"chunks would have been ~{list_of_chunks / 1e6:.0f} MB)"
    )


async def test_AC_22_the_client_does_not_choose_our_memory(
    dribbled: Callable[..., Any]
) -> None:
    """The M-4 regression proper: peak must not scale with the chunk count.

    Same body, same concurrency, chunk size varied by 32 768x. Under a list of
    chunks the 2-byte arm costs ~4 000x the 64 KiB arm; under a `bytearray`
    the two are the same number.
    """
    payload = b'{"blob":"' + b"y" * (AC_22_BODY - 20) + b'"}'
    peaks = {}
    for chunk in (2, 65536):
        middleware = dribbled(max_body_bytes=AC_22_BODY)
        peaks[chunk] = await _peak_bytes(
            middleware,
            payload,
            chunk=chunk,
            concurrency=AC_22_CONCURRENCY,
            content_type="application/json",
        )

    ratio = peaks[2] / max(peaks[65536], 1)
    assert ratio <= 1.5, (
        f"peak allocation grew {ratio:.1f}x when the client shrank its chunks from "
        f"64 KiB to 2 B ({peaks[65536] / 1e6:.2f} MB -> {peaks[2] / 1e6:.2f} MB). "
        "That is review M-4: the client is choosing our memory."
    )
    print(
        f"\nAC-22: peak with 64 KiB chunks {peaks[65536] / 1e6:.2f} MB, with 2 B "
        f"chunks {peaks[2] / 1e6:.2f} MB ({ratio:.2f}x)"
    )


# ===========================================================================
# AC-23 (FR-05, FR-24) — a bodiless response, and exactly one X-Request-ID
# ===========================================================================


async def test_AC_23_a_204_and_a_HEAD_are_logged_with_zero_response_bytes(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    no_body = await audited.client.delete("/gone")
    head = await audited.client.request("HEAD", "/ping")

    assert no_body.status_code == 204 and no_body.content == b""
    assert head.status_code == 200 and head.content == b""

    for response in (no_body, head):
        ids = response.headers.get_list("x-request-id")
        assert len(ids) == 1, (
            f"FR-24: X-Request-ID appears {len(ids)} times on a "
            f"{response.status_code}; it is the only mutation and it is made once"
        )

    documents = await audited.indexed(es)
    assert len(documents) == 2, "FR-01: a bodiless response is still one document"
    by_trace = {doc["trace"]["id"]: doc for doc in documents}
    assert set(by_trace) == {
        no_body.headers["x-request-id"],
        head.headers["x-request-id"],
    }

    deleted = by_trace[no_body.headers["x-request-id"]]
    assert deleted["http"]["response"]["status_code"] == 204
    assert deleted["http"]["response"]["bytes"] == 0, "FR-05: nothing was emitted"
    assert deleted["event"]["outcome"] == "success"

    # `/ping` is registered for HEAD and answers with no body, so the zero here
    # is the application's, which is what FR-05 counts ("total response body
    # bytes **emitted**"). A HEAD against a body-returning GET route would show
    # a non-zero count in this tier and be right to: stripping that body is the
    # HTTP server's job (uvicorn/h11) and there is no uvicorn in this venv.
    # See tests/AC-matrix.md §4.3.
    got_head = by_trace[head.headers["x-request-id"]]
    assert got_head["http"]["request"]["method"] == "HEAD"
    assert got_head["http"]["response"]["bytes"] == 0, "FR-05"
    assert got_head["event"]["outcome"] == "success"
    assert es.malformed == []


# ===========================================================================
# AC-24 (FR-13, FR-14) — extension is additive, and reaches the query too
# ===========================================================================


async def test_AC_24_an_extra_key_redacts_in_both_the_query_and_the_body(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """AC-24's literal case: `?tenant_ref=X` and `{"tenant_ref": "Y"}`."""
    audited: Audited = await make_audited(extra_redact_keys=["tenant_ref"])

    await audited.client.post(
        "/ingest",
        json={"tenant_ref": "SENTINEL-Y", "password": "SENTINEL-DEFAULT"},
        params={"tenant_ref": "SENTINEL-X", "access_token": "SENTINEL-Q"},
    )

    await audited.flush()
    line = audited.lines()[0]
    for sentinel in ("SENTINEL-X", "SENTINEL-Y", "SENTINEL-DEFAULT", "SENTINEL-Q"):
        assert sentinel not in line, f"AC-24: {sentinel} survived"

    documents = await audited.indexed(es)
    request = documents[0]["audit"]["request"]
    assert request["body"]["tenant_ref"] == "[REDACTED]", "FR-13: the extra key"
    assert request["body"]["password"] == "[REDACTED]", "FR-13: additive, never replacing"
    assert request["query"]["tenant_ref"] == "[REDACTED]", "FR-14: the same list"
    assert request["query"]["access_token"] == "[REDACTED]"
    # `url.query` is the raw query string with the values already replaced
    # (schema §2.4), so the marker arrives percent-encoded — exactly as the
    # worked example in schema §1 shows it.
    assert documents[0]["url"]["query"].count("%5BREDACTED%5D") == 2
    assert es.malformed == []


async def test_AC_24_every_default_denylist_key_still_redacts_alongside_an_extra(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """"Extension is additive" as a sweep, not as one example (D-12).

    A config that *replaced* the defaults with `["tenant_ref"]` passes the test
    above and fails this one.
    """
    from audit_logging.redact import DEFAULT_REDACT_KEYS

    audited: Audited = await make_audited(extra_redact_keys=["tenant_ref"])
    body = {key: f"SENTINEL-{key}" for key in sorted(DEFAULT_REDACT_KEYS)}
    body["tenant_ref"] = "SENTINEL-EXTRA"

    await audited.client.post("/ingest", json=body)

    await audited.flush()
    line = audited.lines()[0]
    survivors = [key for key in body if f"SENTINEL-{key}" in line]
    assert survivors == [], f"these default denylist keys stopped redacting: {survivors}"
    assert "SENTINEL-EXTRA" not in line

    documents = await audited.indexed(es)
    stored = documents[0]["audit"]["request"]["body"]
    assert set(stored) == set(body), "FR-11: the keys survive, the values do not"
    assert set(stored.values()) == {"[REDACTED]"}
    assert es.malformed == []


# ===========================================================================
# AC-25 (FR-22, FR-26) — the S-10 regression, in its two separable clauses
#
# The AC is explicit that "every line survives" and "no file exceeds the bound"
# cannot both be tested at the same `file_backup_count`: 2000 x ~940 B needs
# 1.87 MB of retention and 9 generations x 64 KiB holds 590 KiB. Retaining less
# is FR-22 doing its job. So the clauses are tested at different counts, and
# the arithmetic is asserted rather than assumed.
# ===========================================================================


AC_25_DOCUMENTS = 2000
AC_25_FILE_MAX = 64 * 1024


async def _write_ac25_documents(audited: Audited) -> int:
    """2000 documents in one batch — `flush_max_bytes` (4 MiB) must not fire.

    The AC quotes ~940 B per document. Through this app the real line is
    ~1380 B: `/ingest` carries a user-agent, a host header, a 32-hex trace id
    and a route template that the AC's estimate did not. The tests below
    therefore do the retention arithmetic from the **measured** line, not from
    the AC's constant — the AC's *shape* of argument is right and its number is
    a little light.
    """
    for index in range(AC_25_DOCUMENTS):
        response = await audited.client.post(
            "/ingest", json={"seq": index, "pad": "z" * 200}
        )
        assert response.status_code == 200
    await audited.flush()
    return AC_25_DOCUMENTS


async def test_AC_25_no_file_exceeds_file_max_bytes_by_more_than_one_line(
    make_audited: Callable[..., Any]
) -> None:
    """The bound clause, at the default `file_backup_count` (S-10).

    The defect: `file_max_bytes` was checked once per *batch*, so a 1.87 MB
    batch landed whole in a 64 KiB file. `flush_max_bytes` defaults to 4 MiB —
    deliberately larger than the file here, which is what broke it — so this
    really is one oversized write and not 2000 small ones.
    """
    audited: Audited = await make_audited(
        file_max_bytes=AC_25_FILE_MAX,
        file_backup_count=8,
        flush_max_bytes=4 * 1024 * 1024,
        flush_interval_seconds=30.0,  # one batch, on the explicit flush
    )
    await _write_ac25_documents(audited)

    files = [audited.path, *audited.rotated_paths()]
    sizes = {path.name: path.stat().st_size for path in files if path.exists()}
    assert sizes, "nothing was written at all"

    longest = max(
        len(line.encode("utf-8")) + 1 for line in audited.lines(include_rotated=True)
    )
    for name, size in sizes.items():
        assert size <= AC_25_FILE_MAX + longest, (
            f"AC-25: {name} is {size} B, over file_max_bytes ({AC_25_FILE_MAX}) by "
            f"more than one line ({longest} B). This is S-10: the size check ran "
            "once per batch, not once per line."
        )
    assert audited.metrics.get("audit_file_rotations_total") > 0, "FR-22: counted"
    assert len(audited.rotated_paths()) <= 8, "file_backup_count is a hard bound"
    print(
        f"\nAC-25 bound: {len(sizes)} files, largest {max(sizes.values())} B "
        f"against a {AC_25_FILE_MAX} B cap + one {longest} B line; "
        f"{audited.metrics.get('audit_file_rotations_total'):.0f} rotations"
    )


async def test_AC_25_every_line_survives_when_the_backup_count_can_hold_them(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """The survival clause, at a `file_backup_count` that can actually hold it.

    At `file_backup_count=8` this is unsatisfiable and asserting it would be
    asserting a defect: 9 generations x 64 KiB is 590 KiB of retention against
    1.87 MB of documents. The AC says so; this test does the arithmetic first
    and then asserts survival at a count that clears it.
    """
    needed = 64
    audited: Audited = await make_audited(
        file_max_bytes=AC_25_FILE_MAX,
        file_backup_count=needed,
        flush_max_bytes=4 * 1024 * 1024,
        flush_interval_seconds=30.0,
    )
    sent = await _write_ac25_documents(audited)

    lines = audited.lines(include_rotated=True)
    # Every document from this route is within a few bytes of every other, so
    # the mean surviving line is a sound estimate of the line that was written.
    # Deriving `written` from `lines` alone would be circular — lose half the
    # lines and the premise gets easier, which is how a survival test passes
    # while silently testing nothing.
    per_line = sum(len(line.encode("utf-8")) + 1 for line in lines) / max(len(lines), 1)
    written = int(per_line * sent)
    retention = (needed + 1) * AC_25_FILE_MAX
    assert retention > written, (
        f"the premise failed: {needed + 1} generations hold {retention} B and the "
        f"run wrote ~{written} B — raise file_backup_count, do not relax the assert"
    )
    assert 9 * AC_25_FILE_MAX < written, (
        "the premise failed the other way: this run would have fitted inside the "
        "default file_backup_count, so it does not test the AC's arithmetic at all"
    )

    on_disk = sorted(
        (path.name, path.stat().st_size) for path in audited.log_dir.iterdir()
    )
    assert len(lines) == sent, (
        f"AC-25: {sent} documents written, {len(lines)} lines survived rotation. "
        f"active={audited.path.name} rotations="
        f"{audited.metrics.get('audit_file_rotations_total'):.0f} "
        f"dropped={audited.metrics.get('audit_documents_dropped_total'):.0f} "
        f"failed={audited.metrics.get('audit_documents_failed_total'):.0f} "
        f"on_disk={on_disk}"
    )
    # D-A6-5, recorded rather than asserted: `_rotate` intermittently leaves a
    # gap in the `.N` numbering, and the generation on either side of it holds
    # two files' worth. No line is lost by it — which is why this is a print
    # and not a failure here — but it is a real FR-22 bound violation, and
    # AC-25's bound clause structurally cannot see it (§7 explains why).
    indices = audited.rotated_indices()
    if indices != list(range(1, len(indices) + 1)):
        missing = sorted(set(range(1, max(indices) + 1)) - set(indices))
        print(
            f"\nAC-25: D-A6-5 reproduced — rotation numbering has gaps at {missing}; "
            f"largest file {max(size for _, size in on_disk)} B against a "
            f"{AC_25_FILE_MAX} B cap. Every line is still present."
        )
    sequences = [json.loads(line)["audit"]["request"]["body"]["seq"] for line in lines]
    assert sequences == list(range(sent)), "FR-20r: submission order across rotations"
    for line in lines:
        es.index_line(line)
    assert es.count() == sent
    assert es.malformed == [] and es.rejected == []
    print(
        f"\nAC-25 survival: {sent} documents / ~{written} B ({per_line:.0f} B/line) "
        f"held across {len(audited.rotated_paths())} rotated files at "
        f"file_backup_count={needed}"
    )


# ===========================================================================
# AC-26 (FR-18, FR-27) — close() under a failing disk: bounded, and honest
# ===========================================================================


@pytest.mark.skipif(IS_ROOT, reason="root ignores file-mode bits, so nothing fails")
async def test_AC_26_close_returns_in_time_and_counts_each_lost_document_once(
    audit_log_dir: Path, restore_modes: list[tuple[Path, int]]
) -> None:
    """The D-A6-1 / S-9 regression, plus FR-27's timeout and FR-18's bound.

    `audit_documents_failed_total` used to be incremented on the first failure
    **and** again on the one retry, so 180 lost documents were reported as 360.
    An operator reading that counter sizes the incident from it.
    """
    config = build_config(
        audit_log_dir,
        service_name="closing-api",
        file_max_bytes=2048,
        file_backup_count=2,
        flush_interval_seconds=30.0,
        shutdown_flush_timeout=2.0,
        queue_max_bytes=1024 * 1024,
        flush_max_bytes=64 * 1024,
    )
    metrics = InMemoryMetrics()
    sink = FileSink(config, metrics)
    await sink.start()

    restore_modes.append((audit_log_dir, audit_log_dir.stat().st_mode & 0o7777))
    accepted = 0
    try:
        for index in range(20):  # while the disk still works
            assert sink.submit({"trace": {"id": f"ok-{index}"}}) is True
            if index % 2 == 1:
                await sink.flush()
        await sink.flush()
        landed = len([x for x in sink.path.read_text().splitlines() if x.strip()])

        os.chmod(audit_log_dir, 0o500)  # nothing can be created, renamed or unlinked
        for index in range(180):
            if sink.submit({"trace": {"id": f"lost-{index}"}}):
                accepted += 1
            if index % 2 == 1:
                await sink.flush()

        started = time.monotonic()
        await sink.close()
        closed_in = time.monotonic() - started
    finally:
        os.chmod(audit_log_dir, 0o700)

    assert closed_in < config.shutdown_flush_timeout, (
        f"FR-27: close() took {closed_in:.2f} s against a "
        f"{config.shutdown_flush_timeout} s timeout"
    )

    surviving = len([x for x in sink.path.read_text().splitlines() if x.strip()])
    lost = accepted - (surviving - landed)
    failed = metrics.get("audit_documents_failed_total")
    dropped = metrics.get("audit_documents_dropped_total")

    assert lost > 0, "the premise failed: the read-only directory cost nothing"
    assert failed == float(lost), (
        f"AC-26 / D-A6-1: {lost} documents were actually lost and the counter says "
        f"{failed:.0f}. A retried batch must be counted once, not twice."
    )
    assert accepted + dropped == 180, "every submission is accounted for"

    # FR-18: the queue never held more than its byte bound, retry batch included.
    assert sink.held_bytes == 0, "close() left bytes in the queue"
    assert sink.queued_bytes + sink.inflight_bytes <= 2 * config.queue_max_bytes
    print(
        f"\nAC-26: {lost} documents lost, counter {failed:.0f}, "
        f"{dropped:.0f} dropped at the byte bound, close() in {closed_in * 1e3:.0f} ms"
    )


# ===========================================================================
# Schema conformance — every body kind, against the real mapping
#
# `dynamic: false` is silent in production (infra/README.md §5): a field the
# template does not declare is stored and never indexed, and nothing errors.
# These sweep every shape the middleware can emit past the template at once,
# which is the only cheap way to notice.
# ===========================================================================


async def test_every_body_kind_indexes_cleanly(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """FR-05, FR-07, FR-09 and the §3 edge cases, all against the mapping."""
    client = audited.client
    await client.get("/items/1")
    await client.post("/echo", content=b"", headers={"content-type": "application/json"})
    await client.post("/echo", files={"f": ("a.txt", b"hello", "text/plain")})
    await client.post(
        "/echo",
        content=b"a=1&password=x",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    await client.post(
        "/echo", content=b"\x00\x01\x02", headers={"content-type": "application/octet-stream"}
    )
    await client.post("/echo", content=b"<x/>", headers={"content-type": "application/xml"})
    await client.post("/echo", content=b"[1,2]", headers={"content-type": "application/json"})
    await client.post("/echo", content=b"null", headers={"content-type": "application/json"})
    await client.request("HEAD", "/items/1")
    await client.get("/items/notanint")  # 422 from FastAPI's own validation
    await client.get("/items/1", params={"token": "abc", "a": ["1", "2"]})

    documents = await audited.indexed(es)  # strict: raises on an unmapped field

    assert len(documents) == 11
    assert es.malformed == [], f"the mapping would silently drop: {es.malformed}"
    assert es.mapping_field_count() <= es.template.total_fields_limit

    by_mime = {}
    for doc in documents:
        by_mime.setdefault(doc["http"]["request"].get("mime_type"), []).append(doc)

    # FR-07 / D-5: multipart is metadata, never bytes.
    multipart = by_mime["multipart/form-data"][0]["audit"]["request"]
    assert multipart["body_skipped"] == "content_type"
    assert "body_raw" not in multipart and "body" not in multipart
    assert multipart["multipart"]["parts"] == [
        {"size": 5, "name": "f", "filename": "a.txt", "content_type": "text/plain"}
    ]
    assert b"hello" not in json.dumps(multipart).encode()

    # FR-07: an opaque content type stores nothing either.
    binary = by_mime["application/octet-stream"][0]["audit"]["request"]
    assert binary["body_skipped"] == "content_type"
    assert "body_raw" not in binary

    # FR-28: `application/xml` is text, and text is not stored by default.
    xml = by_mime["application/xml"][0]["audit"]["request"]
    assert xml["body_skipped"] == "content_type"
    assert "body_raw" not in xml and "body" not in xml

    # FR-09: a non-object top level is wrapped so `flattened` sees an object.
    #
    # Selected on `body`, not on `body_raw`: under FR-30 / schema §2.9 these
    # two parse fine, so they get a `body` and **no** `body_raw` at all. The
    # old selector keyed on `body_raw in ("[1,2]", "null")`, which is the
    # superseded both-are-present behaviour and now matches nothing.
    wrapped = [
        d["audit"]["request"]
        for d in by_mime["application/json"]
        if isinstance(d["audit"]["request"].get("body"), dict)
        and set(d["audit"]["request"]["body"]) == {"_value"}
    ]
    assert {json.dumps(r["body"]) for r in wrapped} == {'{"_value": [1, 2]}', '{"_value": null}'}
    assert all("body_raw" not in r for r in wrapped), "FR-30: parseable JSON emits no body_raw"

    # FR-14: query redaction, including a repeated key.
    query = [d for d in documents if d["url"]["query"]][0]
    assert query["audit"]["request"]["query"] == {"token": "[REDACTED]", "a": ["1", "2"]}
    assert "abc" not in query["url"]["query"]


async def test_a_response_with_no_body_still_produces_a_document(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """§3: a 204 — `http.response.bytes = 0`, document emitted normally."""
    response = await audited.client.delete("/gone")
    assert response.status_code == 204
    assert response.content == b""

    documents = await audited.indexed(es)
    assert len(documents) == 1
    assert documents[0]["http"]["response"]["status_code"] == 204
    assert documents[0]["http"]["response"]["bytes"] == 0
    assert documents[0]["event"]["outcome"] == "success"
    assert documents[0]["audit"]["request"]["body_skipped"] == "empty"
    assert es.malformed == []


# ===========================================================================
# FRs with no numbered acceptance criterion
#
# AC-01 … AC-17 do not cover FR-05, FR-07, FR-13, FR-14, FR-18, FR-23, FR-24,
# FR-26 or FR-27 (see tests/AC-matrix.md §3). They are unit-tested, but nothing
# checked them end to end, which is where a wiring mistake would live. These
# close that, integration-side.
# ===========================================================================


async def test_FR_05_response_bodies_are_never_stored(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """D-3: ~3x the storage and the main PII leak vector. Not one byte of it."""
    marker = "RESPONSE-BODY-MARKER-c0ffee"
    raw = json.dumps({"note": marker}).encode()

    response = await audited.client.post(
        "/echo", content=raw, headers={"content-type": "application/json"}
    )
    assert marker in response.text, "the app really did return the marker"

    await audited.flush()
    line = audited.lines()[0]
    document = json.loads(line)

    # The marker is legitimately in the *request* copy; it must be nowhere in
    # any response-side field, and there must be no response-body field at all.
    assert document["audit"]["request"]["body"]["note"] == marker
    assert marker not in json.dumps(document["audit"]["response"])
    assert set(document["audit"]["response"]) == {"headers"}
    assert set(document["http"]["response"]) == {"bytes", "status_code"}
    assert document["http"]["response"]["bytes"] == len(raw)
    es.index_line(line)


async def test_FR_13_extra_redact_keys_and_headers_are_additive(
    make_audited: Callable[..., Any], es: InProcessElasticsearch
) -> None:
    """D-12: services extend both lists; there is no way to remove a default."""
    audited: Audited = await make_audited(
        extra_redact_keys=["Internal-Ref"],  # normalised to `internalref`
        extra_header_allowlist=["X-Tenant-Id"],
    )

    await audited.client.post(
        "/ingest",
        json={"internal_ref": "SENTINEL-EXTRA-KEY", "password": "SENTINEL-DEFAULT-KEY"},
        headers={"x-tenant-id": "acme", "authorization": "Bearer SENTINEL-STILL-DROPPED"},
    )

    documents = await audited.indexed(es)
    request = documents[0]["audit"]["request"]

    assert request["body"]["internal_ref"] == "[REDACTED]", "the extra key applies"
    assert request["body"]["password"] == "[REDACTED]", "the defaults still apply"
    assert request["headers"]["x-tenant-id"] == "acme", "the extra header is allowed"
    assert "authorization" not in request["headers"], "a default cannot be removed"
    assert "SENTINEL-STILL-DROPPED" not in json.dumps(documents[0])


async def test_FR_23_and_FR_24_the_trace_id_round_trips(
    audited: Audited, es: InProcessElasticsearch
) -> None:
    """An incoming X-Request-ID becomes trace.id and comes back on the response."""
    incoming = "req-9f2c1a7d4e8b4f0a"

    response = await audited.client.get("/items/1", headers={"x-request-id": incoming})

    assert response.headers["x-request-id"] == incoming, "FR-24"
    documents = await audited.indexed(es)
    assert documents[0]["trace"]["id"] == incoming, "FR-23"

    # A malformed one is replaced by a generated UUID4 hex, not propagated.
    bad = await audited.client.get("/items/2", headers={"x-request-id": "has a space"})
    assert bad.headers["x-request-id"] != "has a space"
    await audited.flush()
    second = audited.lines()[1]
    generated = json.loads(second)["trace"]["id"]
    assert len(generated) == 32 and generated == bad.headers["x-request-id"]
    es.index_line(second)
    assert es.malformed == []


#: FR-26's two legal file names. The plain form is what a lone sink takes; the
#: ``-{6 hex}`` form is what a *second live sink* on the same path takes so the
#: two do not destroy each other's lines (review S-11).
FR_26_NAME = re.compile(r"^[a-z0-9_.\-]+-\d+(?:-[0-9a-f]{6})?\.jsonl$")

#: A5's Filebeat glob and its rotation exclude, as `infra/filebeat/filebeat.yml`
#: writes them. Both name forms must satisfy both.
FILEBEAT_GLOB = "*/*.jsonl"
FILEBEAT_ROTATED = re.compile(r"\.jsonl\.\d+$")


async def test_FR_26_the_file_is_named_for_the_service_and_the_pid(
    audited: Audited,
) -> None:
    """A-5: several uvicorn workers in one pod must not share a file."""
    await audited.client.get("/items/1")
    await audited.flush()

    assert audited.path.name == f"orders-api-{os.getpid()}.jsonl", (
        "the first sink on a path keeps FR-26's documented name verbatim; only a "
        "contending one takes the -{6 hex} suffix"
    )
    assert FR_26_NAME.match(audited.path.name)
    assert audited.path.parent == audited.log_dir
    assert audited.path.exists()


async def test_FR_26_a_second_live_sink_takes_a_collision_suffix(
    audit_log_dir: Path,
) -> None:
    """FR-26 as amended: two live sinks, two files, no lines destroyed (S-11).

    Before the amendment both sinks opened ``{service}-{pid}.jsonl``, each
    tracked ``_file_bytes`` for its own writes only, and one sink's rotation
    ``os.replace``d the file the other still held an fd on: 120 documents in,
    78 lines out. The suffix is what stops that, and the constraint on the
    suffix is that Filebeat must still find it.
    """
    config = build_config(audit_log_dir, service_name="orders-api")
    first = FileSink(config, InMemoryMetrics())
    second = FileSink(config, InMemoryMetrics())
    try:
        await first.start()
        await second.start()
        for index in range(60):
            assert first.submit({"trace": {"id": f"a-{index}"}}) is True
            assert second.submit({"trace": {"id": f"b-{index}"}}) is True
        await first.flush()
        await second.flush()
    finally:
        await first.close()
        await second.close()

    assert first.path != second.path, "two live sinks must not share one file"
    assert first.path.name == f"orders-api-{os.getpid()}.jsonl"
    assert re.fullmatch(rf"orders-api-{os.getpid()}-[0-9a-f]{{6}}\.jsonl", second.path.name), (
        f"the contending sink took {second.path.name!r}, not FR-26's "
        "{service}-{pid}-{6 hex}.jsonl"
    )

    # Not one line destroyed — the whole point of the suffix.
    for sink, prefix in ((first, "a-"), (second, "b-")):
        lines = [x for x in sink.path.read_text().splitlines() if x.strip()]
        assert len(lines) == 60, f"{sink.path.name}: {len(lines)} of 60 lines survived"
        assert [json.loads(x)["trace"]["id"] for x in lines] == [
            f"{prefix}{i}" for i in range(60)
        ]


def test_FR_26_both_name_forms_survive_filebeats_glob_and_rotation_exclude(
    tmp_path: Path,
) -> None:
    """Either name must be picked up, and neither must be picked up when rotated.

    ``infra/filebeat/filebeat.yml`` globs ``/var/log/audit/*/*.jsonl`` (plus
    ``*.jsonl.[0-9]`` deliberately, review S-13) and its rotation pattern is
    ``\\.jsonl\\.\\d+$``. A suffix that broke either would silently stop
    shipping every line the contending sink writes — the exact failure S-11 was
    about, one layer further out.
    """
    pod = tmp_path / "testpod"
    pod.mkdir()
    plain = pod / f"orders-api-{os.getpid()}.jsonl"
    suffixed = pod / f"orders-api-{os.getpid()}-a1b2c3.jsonl"
    for path in (plain, suffixed):
        path.write_text("{}\n", encoding="utf-8")
        Path(f"{path}.1").write_text("{}\n", encoding="utf-8")

    globbed = {p.name for p in tmp_path.glob(FILEBEAT_GLOB)}
    assert globbed == {plain.name, suffixed.name}, (
        f"Filebeat's {FILEBEAT_GLOB} glob would ship {sorted(globbed)}"
    )
    for name in globbed:
        assert FR_26_NAME.match(name)
        assert not FILEBEAT_ROTATED.search(name), "an active file must not look rotated"
    for path in (plain, suffixed):
        assert FILEBEAT_ROTATED.search(f"{path.name}.1"), (
            "a rotated file must match the rotation pattern for either name form"
        )


async def test_FR_27_close_drains_what_is_queued(
    audit_log_dir: Path, es: InProcessElasticsearch
) -> None:
    """Shutdown must not lose the documents already accepted."""
    config = build_config(audit_log_dir, service_name="drain-api", flush_interval_seconds=30.0)
    metrics = InMemoryMetrics()
    sink = FileSink(config, metrics)
    app, _ = make_app()
    app.add_middleware(AuditMiddleware, config=config, sink=sink, metrics=metrics)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://audit.test") as client:
        for index in range(25):
            assert (await client.post("/ingest", json={"n": index})).status_code == 200

    assert not sink.path.exists() or sink.path.stat().st_size == 0, (
        "the premise failed: something already flushed"
    )
    started = time.monotonic()
    await sink.close()
    assert time.monotonic() - started < config.shutdown_flush_timeout

    lines = [x for x in (l.strip() for l in sink.path.read_text().splitlines()) if x]
    assert len(lines) == 25, "FR-27: close() drains the queue"
    for line in lines:
        es.index_line(line)
    await sink.close()  # idempotent


# ===========================================================================
# The double itself — a test suite is only as good as its oracle
# ===========================================================================


def test_the_double_rejects_a_field_the_template_does_not_declare(
    es: InProcessElasticsearch,
) -> None:
    """Proof that AC-10's `dynamic: false` bound is really being enforced."""
    doc = {"@timestamp": "2026-09-05T11:22:33.123456Z", "not_in_the_template": 1}
    with pytest.raises(UnmappedFieldError, match="not_in_the_template"):
        es.index(doc)

    nested = {"audit": {"request": {"invented_field": "x"}}}
    with pytest.raises(UnmappedFieldError, match="audit.request.invented_field"):
        es.index(nested)


def test_the_double_pins_constant_keyword_values(es: InProcessElasticsearch) -> None:
    """A `constant_keyword` given anything but its pinned value is a rejection.

    Not `malformed`: `index.mapping.ignore_malformed` does not cover the
    keyword family, so Elasticsearch answers the bulk item with an error and
    the whole document is lost.
    """
    with pytest.raises(DocumentRejectedError) as raised:
        es.index({"data_stream": {"type": "metrics"}, "event": {"kind": "alert"}})

    assert "data_stream.type" in str(raised.value)
    assert "event.kind" in str(raised.value)
    assert es.count() == 0, "a rejected document is not indexed"


# ---------------------------------------------------------------------------
# M-5 and N-9 — the two defects the review addendum said this double would
# green-light (S-15, S-16). It no longer does.
# ---------------------------------------------------------------------------


def test_the_double_rejects_an_object_in_a_keyword_field(
    es: InProcessElasticsearch,
) -> None:
    """Review M-5 / S-15: `ignore_malformed` does **not** cover `keyword`.

    This is the shape a `user_resolver` returning `{"roles": {"a": "b"}}`
    produces. The first version of this double recorded it in `malformed` and
    indexed the document anyway, so M-5 reproduced as a *passing* test while
    production silently lost the audit record.
    """
    with pytest.raises(DocumentRejectedError, match="user.roles"):
        es.index({"user": {"id": "u-1", "roles": {"a": "b"}}})
    assert es.count() == 0

    # And the types it *does* cover still behave the old way: unindexed, kept.
    result = es.index({"client": {"ip": "not-an-ip"}, "http": {"response": {"bytes": "12"}}})
    assert result.rejected == []
    assert len(result.malformed) == 2, "ignore_malformed covers ip and long"
    assert es.count() == 1, "a malformed value costs a field, not the document"


def test_the_double_enforces_lucenes_term_length_on_a_flattened_key(
    es: InProcessElasticsearch,
) -> None:
    """Review N-9 / S-16: `key + NUL + value` over 32,766 bytes is fatal.

    `FlattenedFieldParser.addField` throws before it looks at `index` or
    `doc_values`, so no template setting avoids it. `ignore_above` bounds the
    *value* only — the key is unbounded unless `redact.sanitize_key` bounds it,
    which is why this must be caught here and not deferred to a cluster.
    """
    over = "k" * 40_000
    with pytest.raises(DocumentRejectedError, match="MAX_TERM_LENGTH"):
        es.index({"audit": {"request": {"body": {over: "v"}}}})
    assert es.count() == 0

    # A key just inside the bound, with a value `ignore_above: 1024` admits.
    under = "k" * 31_000
    result = es.index({"audit": {"request": {"body": {under: "v"}}}})
    assert result.rejected == []

    # `ignore_above` really is applied to the value first: a value past it
    # produces no term at all, so it cannot blow the limit however long it is.
    result = es.index({"audit": {"request": {"body": {"short": "v" * 50_000}}}})
    assert result.rejected == [], "a value over ignore_above is skipped, not rejected"


def test_the_double_rejects_a_nul_in_a_flattened_key(es: InProcessElasticsearch) -> None:
    """The 15-byte attack: NUL is the flattened parser's key/value separator."""
    with pytest.raises(DocumentRejectedError, match="NUL"):
        es.index({"audit": {"request": {"body": {"a\x00b": 1}}}})
    assert es.count() == 0


def test_body_raw_produces_no_term_however_long_it_is(
    es: InProcessElasticsearch,
) -> None:
    """Why `audit.request.body_raw` may leave `ignore_above` unset (review §"what I expected").

    `index: false` **and** `doc_values: false` together mean Lucene is never
    asked to make a term, so `MAX_TERM_LENGTH` cannot apply. Every *other*
    keyword in the template has an `ignore_above` well under the limit; this
    asserts the double is checking them, so a future template edit that drops
    one fails here.
    """
    result = es.index({"audit": {"request": {"body_raw": "x" * 200_000}}})
    assert result.rejected == [] and result.malformed == []

    indexed_keywords = {
        path: mapping
        for path, mapping in _declared_keyword_mappings(es.template.mappings).items()
        if mapping.get("index") is not False
    }
    assert indexed_keywords, "the template declares no indexed keyword at all?"
    for path, mapping in indexed_keywords.items():
        ignore_above = mapping.get("ignore_above")
        assert ignore_above is not None, (
            f"{path} is an indexed keyword with no ignore_above: a value over "
            "32,766 bytes would reject the whole document (review N-9)"
        )
        assert int(ignore_above) * 4 <= 32766, (
            f"{path}: ignore_above {ignore_above} characters can be "
            f"{int(ignore_above) * 4} UTF-8 bytes, over Lucene's term limit"
        )


def _declared_keyword_mappings(node: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Every `keyword`/`text` leaf the template declares, by dotted path."""
    found: dict[str, Any] = {}
    for name, child in (node.get("properties") or {}).items():
        path = f"{prefix}.{name}" if prefix else name
        if "properties" in child:
            found.update(_declared_keyword_mappings(child, path))
        elif child.get("type") == "keyword":
            found[path] = child
    return found


def test_the_double_counts_a_flattened_subtree_as_one_field(
    es: InProcessElasticsearch,
) -> None:
    result = es.index({"audit": {"request": {"body": {f"k{i}": i for i in range(500)}}}})
    assert result.fields == {"audit.request.body"}
    assert es.mapping_field_count() == 3  # audit, audit.request, audit.request.body


def test_the_template_on_disk_still_says_what_the_tests_assume(
    es: InProcessElasticsearch,
) -> None:
    """A5 owns the template; if it changes shape, these tests must know."""
    template = es.template
    assert template.total_fields_limit == 200
    assert template.mappings["dynamic"] is False
    assert template.index_patterns == ["logs-apiaudit.*-*"]
    assert "audit.request.body" in template.flattened_paths()
    assert "audit.request.headers" in template.flattened_paths()
    assert len(template.declared_field_paths()) < 200
