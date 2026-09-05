"""Unit tests for ``AuditMiddleware`` (A2).

Driven through ``httpx.ASGITransport`` against a real FastAPI app wherever the
behaviour is observable from outside, and by driving the ASGI callable directly
where it is not (chunk boundaries, client disconnect, scope pass-through).

``redact.py`` is still an A3 stub in Phase 1, so ``document.redact`` and
``document.filter_headers`` are monkeypatched with identity implementations
(AGENTS.md, Phase 0 addendum).
"""

from __future__ import annotations

import asyncio
import json
import time
import tracemalloc
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Iterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response, StreamingResponse

from audit_logging import document as document_module
from audit_logging.config import AuditConfig
from audit_logging.middleware import AuditMiddleware
from audit_logging.sinks.null_sink import NullSink

Scope = dict[str, Any]
Message = dict[str, Any]

# ---------------------------------------------------------------------------
# Stubs for the modules A2 does not own
# ---------------------------------------------------------------------------


class StubMetrics:
    """Records counters. Never raises (contract §6.7)."""

    def __init__(self) -> None:
        self.counters: dict[str, float] = {}

    def inc(self, name: str, value: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + value

    def set(self, name: str, value: float) -> None:
        self.counters[name] = value

    def __getitem__(self, name: str) -> float:
        return self.counters.get(name, 0)


def _identity_redact(
    obj: Any,
    keys: frozenset[str],
    *,
    depth_limit: int = 20,
    max_distinct_keys: int | None = None,
) -> Any:
    return obj


def _identity_filter_headers(
    headers: Iterable[tuple[bytes, bytes]], allowlist: frozenset[str]
) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in headers}


def _normalize_key(key: str) -> str:
    return key.lower().replace("_", "").replace("-", "").replace(".", "")


@pytest.fixture(autouse=True)
def _identity_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    """A3 owns redact.py; in Phase 1 it raises NotImplementedError."""
    monkeypatch.setattr(document_module, "redact", _identity_redact)
    monkeypatch.setattr(document_module, "filter_headers", _identity_filter_headers)
    monkeypatch.setattr(document_module, "normalize_key", _normalize_key)


@pytest.fixture
def metrics() -> StubMetrics:
    return StubMetrics()


@pytest.fixture(autouse=True)
def _reset_warn_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_WARNED`` is a per-process, per-error-kind latch; clear it between tests."""
    import audit_logging.middleware as middleware_module

    monkeypatch.setattr(middleware_module, "_WARNED", set())


# ---------------------------------------------------------------------------
# The application under audit
# ---------------------------------------------------------------------------


async def _read_twice(scope: Scope, receive: Any, send: Any) -> None:
    """Raw ASGI: reads the request stream twice, as an unwrapped app would."""
    first = await receive()
    second = await receive()
    payload = json.dumps({"first": first["type"], "second": second["type"]}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def make_app() -> FastAPI:
    app = FastAPI()

    @app.get("/items/{item_id}")
    async def get_item(item_id: int) -> dict[str, Any]:
        return {"item_id": item_id}

    @app.post("/echo")
    async def echo(request: Request) -> Response:
        body = await request.body()
        return Response(content=body, media_type="application/octet-stream")

    @app.post("/noread")
    async def noread() -> dict[str, str]:
        return {"read": "no"}

    @app.get("/stream")
    async def stream() -> StreamingResponse:
        async def chunks() -> AsyncIterator[bytes]:
            for index in range(5):
                await asyncio.sleep(0.02)
                yield f"chunk-{index};".encode()

        return StreamingResponse(chunks(), media_type="text/plain")

    @app.get("/boom")
    async def boom() -> None:
        raise ValueError("kaboom")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.delete("/gone")
    async def gone() -> Response:
        return Response(status_code=204)

    @app.api_route("/both", methods=["GET", "HEAD"])
    async def both() -> Response:
        return Response(status_code=200)

    @app.get("/preset")
    async def preset() -> Response:
        return JSONResponse({"ok": True}, headers={"X-Request-ID": "app-owned-id"})

    app.mount("/raw", _read_twice)
    return app


def build_config(**overrides: Any) -> AuditConfig:
    values: dict[str, Any] = {
        "service_name": "test-service",
        "service_version": "0.0.1",
        "environment": "test",
        "exclude_paths": ["/health"],
    }
    values.update(overrides)
    return AuditConfig(**values)


def wrap(
    config: AuditConfig, sink: NullSink, metrics: StubMetrics | None = None
) -> tuple[FastAPI, NullSink]:
    app = make_app()
    app.add_middleware(AuditMiddleware, config=config, sink=sink, metrics=metrics)
    return app, sink


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://audit.test"
    )


@pytest.fixture
def audited(metrics: StubMetrics) -> tuple[FastAPI, NullSink, StubMetrics]:
    sink = NullSink()
    app, _ = wrap(build_config(), sink, metrics)
    return app, sink, metrics


# ---------------------------------------------------------------------------
# Helpers for driving ASGI directly
# ---------------------------------------------------------------------------


def http_scope(**overrides: Any) -> Scope:
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/echo",
        "raw_path": b"/echo",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"audit.test"), (b"content-type", b"application/json")],
        "client": ("10.0.0.1", 51234),
        "server": ("audit.test", 80),
    }
    scope.update(overrides)
    return scope


def replay(messages: list[Message]) -> Callable[[], Awaitable[Message]]:
    stream: Iterator[Message] = iter(messages)

    async def receive() -> Message:
        try:
            return next(stream)
        except StopIteration:
            return {"type": "http.disconnect"}

    return receive


def collector() -> tuple[Callable[[Message], Awaitable[None]], list[Message]]:
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    return send, sent


# ===========================================================================
# FR-01 — exactly one document per non-excluded request
# ===========================================================================


async def test_FR_01_one_document_per_request(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, metrics = audited
    async with client_for(app) as client:
        response = await client.get("/items/42")
    assert response.status_code == 200
    doc = sink.only
    assert doc["http"]["request"]["method"] == "GET"
    assert doc["audit"]["route"] == "/items/{item_id}"
    assert doc["http"]["response"]["status_code"] == 200
    assert doc["event"]["outcome"] == "success"
    assert doc["url"]["path"] == "/items/42"
    assert metrics["audit_middleware_errors_total"] == 0


async def test_FR_01_three_requests_three_documents(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        for _ in range(3):
            await client.get("/items/1")
    assert len(sink.submitted) == 3


async def test_FR_01_websocket_scope_passes_through_untouched() -> None:
    sink = NullSink()
    seen: dict[str, Any] = {}

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        seen["receive"] = receive
        seen["send"] = send

    middleware = AuditMiddleware(app, build_config(), sink, StubMetrics())
    receive, (send, _sent) = replay([]), collector()
    await middleware({"type": "websocket", "path": "/ws"}, receive, send)

    assert seen["receive"] is receive
    assert seen["send"] is send
    assert sink.submitted == []


async def test_FR_01_lifespan_is_passed_through_byte_identical() -> None:
    sink = NullSink()
    forwarded: list[Message] = []
    emitted: list[Message] = []

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        startup = await receive()
        forwarded.append(startup)
        complete: Message = {"type": "lifespan.startup.complete"}
        emitted.append(complete)
        await send(complete)
        shutdown = await receive()
        forwarded.append(shutdown)
        done: Message = {"type": "lifespan.shutdown.complete"}
        emitted.append(done)
        await send(done)

    middleware = AuditMiddleware(app, build_config(), sink, StubMetrics())
    incoming = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
    send, sent = collector()
    await middleware({"type": "lifespan"}, replay(incoming), send)

    # Byte-identical in both directions: the very same objects.
    assert [id(m) for m in forwarded] == [id(m) for m in incoming]
    assert [id(m) for m in sent] == [id(m) for m in emitted]
    # ...but observed (AGENTS.md addendum).
    assert sink.started is True
    assert sink.closed is True


async def test_FR_01_sink_started_lazily_without_lifespan(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.get("/items/1")
    await asyncio.sleep(0)
    assert sink.started is True


# ===========================================================================
# FR-02 — exclusions, decided on the raw path before any wrapping
# ===========================================================================


async def test_FR_02_excluded_path_produces_no_document(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        for _ in range(10):
            response = await client.get("/health")
            assert response.status_code == 200
    assert sink.submitted == []


async def test_FR_02_excluded_path_is_not_wrapped() -> None:
    sink = NullSink()
    seen: dict[str, Any] = {}

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        seen["receive"] = receive
        seen["send"] = send
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = AuditMiddleware(app, build_config(), sink, StubMetrics())
    receive, (send, _sent) = replay([]), collector()
    await middleware(http_scope(method="GET", path="/health/live"), receive, send)

    assert seen["receive"] is receive, "receive must not be wrapped for an excluded path"
    assert seen["send"] is send, "send must not be wrapped for an excluded path"
    assert sink.submitted == []


# ===========================================================================
# FR-03 — route template, read after the app returns
# ===========================================================================


async def test_FR_03_route_template_and_path_params(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.get("/items/7")
    doc = sink.only
    assert doc["audit"]["route"] == "/items/{item_id}"
    assert doc["audit"]["path_params"] == {"item_id": "7"}


async def test_FR_03_unmatched_route_is_labelled(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.get("/nothing/here")
    assert response.status_code == 404
    doc = sink.only
    assert doc["audit"]["route"] == "unmatched"
    assert doc["http"]["response"]["status_code"] == 404
    # A 404 is a successful outcome with a 4xx status (schema §2.2).
    assert doc["event"]["outcome"] == "success"


def test_FR_03_route_path_format_is_honoured() -> None:
    """Some Starlette routers expose ``path_format`` instead of ``path``."""

    class LegacyRoute:
        path_format = "/legacy/{id}"

    assert document_module._route_of({"route": LegacyRoute()}) == "/legacy/{id}"
    assert document_module._route_of({}) == "unmatched"


# ===========================================================================
# FR-04 — body captured by wrapping receive, replayed byte-identically
# ===========================================================================


async def test_FR_04_body_is_replayed_byte_identically(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    payload = json.dumps({"pad": "x" * 3000, "qty": 3}).encode()
    async with client_for(app) as client:
        response = await client.post(
            "/echo", content=payload, headers={"content-type": "application/json"}
        )
    assert response.content == payload
    doc = sink.only
    assert doc["audit"]["request"]["body"]["qty"] == 3
    assert doc["audit"]["request"]["body_bytes"] == len(payload)
    assert doc["audit"]["request"]["body_truncated"] is False


async def test_FR_04_chunk_boundaries_are_preserved() -> None:
    """Edge case: a body sent in many chunks, reassembled in order."""
    sink = NullSink()
    received: list[Message] = []

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            received.append(message)
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    incoming: list[Message] = [
        {"type": "http.request", "body": b'{"a":', "more_body": True},
        {"type": "http.request", "body": b'1,"b":', "more_body": True},
        {"type": "http.request", "body": b"2}", "more_body": False},
    ]
    middleware = AuditMiddleware(app, build_config(), sink, StubMetrics())
    send, _sent = collector()
    await middleware(http_scope(), replay(incoming), send)

    assert [id(m) for m in received] == [id(m) for m in incoming]
    assert sink.only["audit"]["request"]["body"] == {"a": 1, "b": 2}


async def test_FR_04_disconnect_message_is_passed_through() -> None:
    sink = NullSink()
    received: list[Message] = []

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        received.append(await receive())
        received.append(await receive())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    incoming: list[Message] = [
        {"type": "http.request", "body": b"{}", "more_body": False},
        {"type": "http.disconnect"},
    ]
    middleware = AuditMiddleware(app, build_config(), sink, StubMetrics())
    send, _sent = collector()
    await middleware(http_scope(), replay(incoming), send)
    assert [m["type"] for m in received] == ["http.request", "http.disconnect"]


# ===========================================================================
# FR-05 — response status, headers and total byte count (no body)
# ===========================================================================


async def test_FR_05_response_status_headers_and_bytes(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.get("/items/9")
    doc = sink.only
    assert doc["http"]["response"]["status_code"] == 200
    assert doc["http"]["response"]["bytes"] == len(response.content)
    assert doc["audit"]["response"]["headers"]["content-type"] == "application/json"
    # D-3: response bodies are never stored.
    assert "body" not in doc["audit"]["response"]
    assert b'{"item_id":9}'.decode() not in json.dumps(doc)


async def test_FR_05_response_without_a_body_counts_zero(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    """Edge case: 204."""
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.delete("/gone")
    assert response.status_code == 204
    doc = sink.only
    assert doc["http"]["response"]["bytes"] == 0
    assert doc["http"]["response"]["status_code"] == 204


async def test_FR_05_head_request_is_logged(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    """Edge case: HEAD."""
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.head("/both")
    assert response.status_code == 200
    doc = sink.only
    assert doc["http"]["request"]["method"] == "HEAD"
    assert doc["http"]["response"]["bytes"] == 0


# ===========================================================================
# FR-06 — duration to the LAST chunk
# ===========================================================================


async def test_FR_06_streaming_response_is_timed_to_the_last_chunk(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.get("/stream")
    expected = b"".join(f"chunk-{i};".encode() for i in range(5))
    assert response.content == expected
    doc = sink.only
    # 5 chunks, 20 ms apart: at least four sleeps must be inside the duration.
    assert doc["event"]["duration"] >= 80_000_000, doc["event"]["duration"]
    assert doc["http"]["response"]["bytes"] == len(expected)


async def test_FR_06_duration_is_nanoseconds_and_positive(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.get("/items/1")
    duration = sink.only["event"]["duration"]
    assert isinstance(duration, int)
    assert 0 < duration < 5_000_000_000


# ===========================================================================
# FR-07 — multipart: metadata only
# ===========================================================================


async def test_FR_07_multipart_records_metadata_only(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.post(
            "/echo",
            files={"upload": ("secret.txt", b"TOP-SECRET-BYTES", "text/plain")},
            data={"note": "hello"},
        )
    doc = sink.only
    request = doc["audit"]["request"]
    assert request["body_skipped"] == "content_type"
    assert "body" not in request
    assert "body_raw" not in request
    assert "TOP-SECRET-BYTES" not in json.dumps(doc)
    names = {part.get("name") for part in request["multipart"]["parts"]}
    assert {"upload", "note"} <= names
    upload = next(p for p in request["multipart"]["parts"] if p.get("name") == "upload")
    assert upload["filename"] == "secret.txt"
    assert upload["content_type"] == "text/plain"
    assert upload["size"] == len(b"TOP-SECRET-BYTES")


async def test_FR_07_binary_content_type_is_skipped(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.post(
            "/echo",
            content=b"\x89PNG\r\n\x1a\nbinary",
            headers={"content-type": "image/png"},
        )
    request = sink.only["audit"]["request"]
    assert request["body_skipped"] == "content_type"
    assert "body_raw" not in request
    assert sink.only["http"]["request"]["mime_type"] == "image/png"


# ===========================================================================
# FR-08 — truncation at max_body_bytes; the app still gets everything
# ===========================================================================


async def test_FR_08_oversized_body_is_truncated_but_replayed_in_full(
    metrics: StubMetrics,
) -> None:
    sink = NullSink()
    app, _ = wrap(build_config(max_body_bytes=128), sink, metrics)
    payload = json.dumps({"pad": "y" * 4000}).encode()
    async with client_for(app) as client:
        response = await client.post(
            "/echo", content=payload, headers={"content-type": "application/json"}
        )
    assert response.content == payload, "the app must receive the full body"
    request = sink.only["audit"]["request"]
    assert request["body_truncated"] is True
    assert request["body_bytes"] == 128
    assert len(request["body_raw"]) <= 128
    assert request["body_parse_failed"] is True  # a truncated body is not JSON
    assert sink.only["http"]["request"]["bytes"] == len(payload)


async def test_FR_08_body_exactly_at_the_cap_is_not_truncated(
    metrics: StubMetrics,
) -> None:
    sink = NullSink()
    payload = json.dumps({"a": "b" * 100}).encode()
    app, _ = wrap(build_config(max_body_bytes=len(payload)), sink, metrics)
    async with client_for(app) as client:
        await client.post(
            "/echo", content=payload, headers={"content-type": "application/json"}
        )
    request = sink.only["audit"]["request"]
    assert request["body_truncated"] is False
    assert request["body_bytes"] == len(payload)


# ===========================================================================
# FR-09 — JSON parsing, parse failure, non-object top level
# ===========================================================================


async def test_FR_09_json_body_is_parsed(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.post("/echo", json={"sku": "A-11", "qty": 3})
    request = sink.only["audit"]["request"]
    assert request["body"] == {"sku": "A-11", "qty": 3}
    assert request["body_parse_failed"] is False
    assert "body_raw" not in request  # FR-30 / schema §2.9


async def test_FR_09_broken_json_keeps_the_raw_text(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.post(
            "/echo", content=b"{not json", headers={"content-type": "application/json"}
        )
    assert response.content == b"{not json"
    request = sink.only["audit"]["request"]
    assert request["body_parse_failed"] is True
    assert request["body_raw"] == "{not json"
    assert "body" not in request


@pytest.mark.parametrize("payload", ["[1,2]", '"x"', "null", "3"])
async def test_FR_09_non_object_json_is_wrapped(
    payload: str, audited: tuple[FastAPI, NullSink, StubMetrics]
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.post(
            "/echo",
            content=payload.encode(),
            headers={"content-type": "application/json"},
        )
    request = sink.only["audit"]["request"]
    assert request["body"] == {"_value": json.loads(payload)}
    assert "body_raw" not in request  # FR-30


async def test_FR_09_duplicate_keys_are_last_wins(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.post(
            "/echo",
            content=b'{"a": 1, "a": 2}',
            headers={"content-type": "application/json"},
        )
    assert sink.only["audit"]["request"]["body"] == {"a": 2}


async def test_FR_28_non_json_text_body_is_not_stored_by_default(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.post(
            "/echo", content=b"plain words", headers={"content-type": "text/plain"}
        )
    request = sink.only["audit"]["request"]
    assert request["body_skipped"] == "content_type"
    assert "body" not in request
    assert "body_raw" not in request
    assert "body_parse_failed" not in request


async def test_FR_28_capture_text_bodies_stores_a_scrubbed_body(
    metrics: StubMetrics,
) -> None:
    sink = NullSink()
    app, _ = wrap(build_config(capture_text_bodies=True), sink, metrics)
    async with client_for(app) as client:
        await client.post(
            "/echo", content=b"plain words", headers={"content-type": "text/plain"}
        )
    request = sink.only["audit"]["request"]
    assert request["body_raw"] == "plain words"
    assert "body" not in request
    assert "body_skipped" not in request


async def test_FR_09_json_suffix_content_type_is_parsed(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.post(
            "/echo",
            content=b'{"a":1}',
            headers={"content-type": "application/vnd.api+json"},
        )
    assert sink.only["audit"]["request"]["body"] == {"a": 1}


# ===========================================================================
# FR-15 — kill switch
# ===========================================================================


async def test_FR_15_kill_switch_is_a_pure_pass_through() -> None:
    sink = NullSink()
    seen: dict[str, Any] = {}

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        seen["receive"] = receive
        seen["send"] = send
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = AuditMiddleware(app, build_config(enabled=False), sink, StubMetrics())
    receive, (send, sent) = replay([]), collector()
    await middleware(http_scope(method="GET", path="/items/1"), receive, send)

    assert seen["receive"] is receive
    assert seen["send"] is send
    assert sink.submitted == []
    # FR-24 is not applied either: the response is untouched.
    assert sent[0]["headers"] == []


def test_FR_15_kill_switch_allocates_no_sink() -> None:
    async def app(scope: Scope, receive: Any, send: Any) -> None:
        return None

    middleware = AuditMiddleware(app, build_config(enabled=False), None, StubMetrics())
    assert middleware._sink is None  # no queue, no file, no FileSink construction


# ===========================================================================
# FR-23 / FR-24 — trace id in, X-Request-ID out
# ===========================================================================


async def test_FR_23_incoming_request_id_is_reused(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.get("/items/1", headers={"X-Request-ID": "abc-123"})
    assert sink.only["trace"]["id"] == "abc-123"
    assert response.headers["x-request-id"] == "abc-123"


async def test_FR_23_generated_trace_id_is_uuid4_hex(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.get("/items/1")
    trace_id = sink.only["trace"]["id"]
    assert len(trace_id) == 32
    int(trace_id, 16)


@pytest.mark.parametrize(
    "bad", ["x" * 201, "has space", "tab\there", ""]
)
async def test_FR_23_malformed_request_id_is_replaced(
    bad: str, audited: tuple[FastAPI, NullSink, StubMetrics]
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.get("/items/1", headers={"X-Request-ID": bad})
    assert sink.only["trace"]["id"] != bad
    assert len(sink.only["trace"]["id"]) == 32


async def test_FR_24_response_carries_the_request_id(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.get("/items/1")
    assert response.headers["x-request-id"] == sink.only["trace"]["id"]


async def test_FR_24_existing_request_id_header_is_not_duplicated(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.get("/preset")
    assert response.headers.get_list("x-request-id") == ["app-owned-id"]


async def test_FR_24_is_the_only_mutation() -> None:
    """Everything the app sends is forwarded unchanged apart from that header."""
    sink = NullSink()
    original: list[Message] = [
        {
            "type": "http.response.start",
            "status": 201,
            "headers": [(b"content-type", b"application/json")],
        },
        {"type": "http.response.body", "body": b'{"ok":true}', "more_body": False},
    ]

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        for message in original:
            await send(message)

    middleware = AuditMiddleware(app, build_config(), sink, StubMetrics())
    send, sent = collector()
    await middleware(http_scope(method="GET", path="/items/1"), replay([]), send)

    assert sent[1] is original[1]  # body messages are forwarded untouched
    start = sent[0]
    assert start["status"] == 201
    assert start["headers"][0] == (b"content-type", b"application/json")
    assert start["headers"][1][0] == b"x-request-id"
    assert len(start["headers"]) == 2
    # The app's own message object was not mutated.
    assert original[0]["headers"] == [(b"content-type", b"application/json")]


# ===========================================================================
# FR-25 — user_resolver
# ===========================================================================


async def test_FR_25_user_resolver_populates_user(metrics: StubMetrics) -> None:
    sink = NullSink()
    config = build_config(
        user_resolver=lambda scope: {"id": "u-1", "name": "a.k", "roles": ["op"], "x": 1}
    )
    app, _ = wrap(config, sink, metrics)
    async with client_for(app) as client:
        await client.get("/items/1")
    assert sink.only["user"] == {"id": "u-1", "name": "a.k", "roles": ["op"]}
    assert metrics["audit_middleware_errors_total"] == 0


async def test_FR_25_raising_resolver_is_counted_and_dropped(
    metrics: StubMetrics,
) -> None:
    def boom(scope: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("no user for you")

    sink = NullSink()
    app, _ = wrap(build_config(user_resolver=boom), sink, metrics)
    async with client_for(app) as client:
        response = await client.get("/items/1")
    assert response.status_code == 200
    assert "user" not in sink.only
    assert metrics["audit_middleware_errors_total"] == 1


async def test_FR_25_non_dict_resolver_is_counted_and_dropped(
    metrics: StubMetrics,
) -> None:
    sink = NullSink()
    app, _ = wrap(build_config(user_resolver=lambda scope: "nope"), sink, metrics)
    async with client_for(app) as client:
        await client.get("/items/1")
    assert "user" not in sink.only
    assert metrics["audit_middleware_errors_total"] == 1


async def test_FR_25_resolver_returning_none_is_not_an_error(
    metrics: StubMetrics,
) -> None:
    sink = NullSink()
    app, _ = wrap(build_config(user_resolver=lambda scope: None), sink, metrics)
    async with client_for(app) as client:
        await client.get("/items/1")
    assert "user" not in sink.only
    assert metrics["audit_middleware_errors_total"] == 0


# ===========================================================================
# Outcomes: exceptions, disconnects
# ===========================================================================


async def test_app_exception_is_reraised_unchanged(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, metrics = audited
    async with client_for(app) as client:
        with pytest.raises(ValueError, match="kaboom"):
            await client.get("/boom")
    doc = sink.only
    assert doc["http"]["response"]["status_code"] == 500
    assert doc["event"]["outcome"] == "failure"
    assert doc["error"]["type"] == "ValueError"
    assert doc["error"]["message"] == "kaboom"
    # NFR-3: our own error counter is untouched — the failure was the app's.
    assert metrics["audit_middleware_errors_total"] == 0


async def test_server_error_status_is_a_failure_outcome() -> None:
    sink = NullSink()

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 503, "headers": []})
        await send({"type": "http.response.body", "body": b"nope"})

    middleware = AuditMiddleware(app, build_config(), sink, StubMetrics())
    send, _sent = collector()
    await middleware(http_scope(method="GET", path="/items/1"), replay([]), send)
    assert sink.only["event"]["outcome"] == "failure"
    assert "error" not in sink.only


async def test_client_disconnect_mid_request() -> None:
    """Edge case: the client vanishes before the response finishes."""
    sink = NullSink()

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        await receive()  # first chunk
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"partial", "more_body": True})
        message = await receive()
        assert message["type"] == "http.disconnect"

    incoming: list[Message] = [
        {"type": "http.request", "body": b'{"a":', "more_body": True},
        {"type": "http.disconnect"},
    ]
    middleware = AuditMiddleware(app, build_config(), sink, StubMetrics())
    send, _sent = collector()
    await middleware(http_scope(), replay(incoming), send)

    doc = sink.only
    assert doc["event"]["outcome"] == "disconnected"
    assert doc["http"]["response"]["status_code"] == 200
    assert doc["http"]["response"]["bytes"] == len(b"partial")


async def test_client_disconnect_before_any_response() -> None:
    sink = NullSink()

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        await receive()
        await receive()

    incoming: list[Message] = [
        {"type": "http.request", "body": b"{}", "more_body": True},
        {"type": "http.disconnect"},
    ]
    middleware = AuditMiddleware(app, build_config(), sink, StubMetrics())
    send, _sent = collector()
    await middleware(http_scope(), replay(incoming), send)

    doc = sink.only
    assert doc["event"]["outcome"] == "disconnected"
    assert "status_code" not in doc["http"]["response"]


# ===========================================================================
# Body edge cases (REQUIREMENTS §3)
# ===========================================================================


async def test_empty_body_is_skipped_as_empty(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.post("/echo", content=b"", headers={"content-length": "0"})
    request = sink.only["audit"]["request"]
    assert request["body_skipped"] == "empty"
    assert "body" not in request
    assert "body_raw" not in request
    assert "body_parse_failed" not in request


async def test_get_without_a_body_is_skipped_as_empty(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        await client.get("/items/1")
    assert sink.only["audit"]["request"]["body_skipped"] == "empty"


async def test_app_that_never_reads_the_body_still_produces_a_document(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.post("/noread", json={"never": "read"})
    assert response.status_code == 200
    request = sink.only["audit"]["request"]
    assert request["body_skipped"] == "unread"
    assert request["body_bytes"] == 0
    assert "body" not in request


async def test_app_reading_the_body_twice_behaves_like_unwrapped_asgi(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.post("/raw/", content=b'{"a":1}')
    async with client_for(make_app()) as bare_client:
        expected = await bare_client.post("/raw/", content=b'{"a":1}')
    # The second read must return exactly what unwrapped ASGI returns: the
    # middleware never resurrects a consumed message.
    assert response.json() == expected.json()
    assert response.json()["first"] == "http.request"
    doc = sink.only
    # A post-body disconnect on a completed response is not a disconnection.
    assert doc["event"]["outcome"] == "success"
    assert doc["audit"]["request"]["body_bytes"] == len(b'{"a":1}')


async def test_chunked_body_without_content_length(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    """Edge case: chunked transfer — no Content-Length to fall back on."""

    async def chunks() -> AsyncIterator[bytes]:
        yield b'{"a":'
        yield b"1}"

    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.post(
            "/echo", content=chunks(), headers={"content-type": "application/json"}
        )
    assert response.content == b'{"a":1}'
    request = sink.only["audit"]["request"]
    assert request["body"] == {"a": 1}
    assert sink.only["http"]["request"]["bytes"] == len(b'{"a":1}')


async def test_expect_100_continue_is_passed_through(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        response = await client.post(
            "/echo",
            content=b'{"a":1}',
            headers={"content-type": "application/json", "expect": "100-continue"},
        )
    assert response.content == b'{"a":1}'
    assert sink.only["audit"]["request"]["body"] == {"a": 1}


# ===========================================================================
# NFR-3 — nothing of ours reaches the application
# ===========================================================================


async def test_NFR_3_document_builder_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch, metrics: StubMetrics
) -> None:
    import audit_logging.middleware as middleware_module

    def explode(ctx: Any, config: Any, **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("builder is broken")

    monkeypatch.setattr(middleware_module, "build_document", explode)
    sink = NullSink()
    app, _ = wrap(build_config(), sink, metrics)
    async with client_for(app) as client:
        response = await client.get("/items/1")
    assert response.status_code == 200
    assert response.json() == {"item_id": 1}
    assert metrics["audit_middleware_errors_total"] == 1
    # FR-01 still holds: a degraded document, not nothing (review S-5).
    assert len(sink.submitted) == 1
    assert sink.only["error"]["message"].startswith("audit_logging: ")


async def test_NFR_3_sink_failure_is_swallowed(metrics: StubMetrics) -> None:
    class BrokenSink(NullSink):
        def submit(self, doc: dict[str, Any]) -> bool:
            raise RuntimeError("queue is on fire")

    app, _ = wrap(build_config(), BrokenSink(), metrics)
    async with client_for(app) as client:
        response = await client.get("/items/1")
    assert response.status_code == 200
    assert metrics["audit_middleware_errors_total"] == 1


async def test_NFR_3_warning_is_logged_once_per_process(
    caplog: pytest.LogCaptureFixture, metrics: StubMetrics
) -> None:
    class BrokenSink(NullSink):
        def submit(self, doc: dict[str, Any]) -> bool:
            raise RuntimeError("queue is on fire")

    app, _ = wrap(build_config(), BrokenSink(), metrics)
    with caplog.at_level("WARNING", logger="audit_logging"):
        async with client_for(app) as client:
            for _ in range(5):
                await client.get("/items/1")
    assert len(caplog.records) == 1
    assert metrics["audit_middleware_errors_total"] == 5


# ===========================================================================
# Regressions for the adversarial review (REVIEW.md) and AC-18…AC-24
# ===========================================================================


async def test_M_4_the_receive_buffer_is_a_bytearray_not_a_list_of_chunks() -> None:
    """REVIEW M-4: 50 slow-loris bodies at 2-byte chunks cost 1.4 GB of RSS.

    The bytes were always capped; the memory was not, because a ``list`` of
    ``bytes`` pays ~33 B of object header plus an 8 B list slot per chunk, and
    the client picks the chunk size over chunked transfer-encoding.

    Measured as bytes traced by ``tracemalloc`` rather than RSS so it is
    deterministic in CI, and measured while the body is still buffered so the
    emit-time copy is not counted. The chunk objects are allocated **before**
    tracing starts, so what is left is what the middleware itself retains: one
    ``bytearray`` of ``max_body_bytes``, or 32 768 list slots.
    """
    cap = 64 * 1024
    chunk = 2
    pool = [bytes(bytearray([index % 251, 7])) for index in range(cap // chunk)]
    gate = asyncio.Event()
    sink = NullSink()

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await gate.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = AuditMiddleware(
        app, build_config(max_body_bytes=cap), sink, StubMetrics()
    )
    index = 0

    async def receive() -> Message:
        nonlocal index
        if index >= len(pool):
            return {"type": "http.request", "body": b"", "more_body": False}
        body = pool[index]
        index += 1
        return {"type": "http.request", "body": body, "more_body": index < len(pool)}

    send, _sent = collector()
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]
    task = asyncio.create_task(middleware(http_scope(), receive, send))
    while index < len(pool):
        await asyncio.sleep(0)
    held = tracemalloc.get_traced_memory()[0] - before
    tracemalloc.stop()
    gate.set()
    await task
    # FR-08 / AC-22: the bound is max_body_bytes, not chunk_count x overhead.
    assert held < 2 * cap, f"{held} bytes retained for a {cap}-byte cap"
    assert sink.only["audit"]["request"]["body_bytes"] == cap


async def test_AC_22_concurrent_two_byte_dribbles_stay_within_two_x_the_cap() -> None:
    cap = 32 * 1024
    concurrency = 20
    gate = asyncio.Event()
    sink = NullSink(max_documents=concurrency)

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await gate.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = AuditMiddleware(
        app, build_config(max_body_bytes=cap), sink, StubMetrics()
    )

    def make_receive() -> Callable[[], Awaitable[Message]]:
        sent = 0

        async def receive() -> Message:
            nonlocal sent
            if sent >= cap:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent += 2
            return {"type": "http.request", "body": bytes(bytearray(2)), "more_body": sent < cap}

        return receive

    send, _sent = collector()
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]
    tasks = [
        asyncio.create_task(middleware(http_scope(), make_receive(), send))
        for _ in range(concurrency)
    ]
    for _ in range(200):
        await asyncio.sleep(0)
    peak = tracemalloc.get_traced_memory()[1] - before
    tracemalloc.stop()
    gate.set()
    await asyncio.gather(*tasks)
    assert peak < 2 * cap * concurrency, f"{peak} bytes for {concurrency} x {cap}"


async def test_S_1_request_bytes_counts_a_truncated_chunked_body_in_full() -> None:
    """REVIEW S-1: with no Content-Length the field silently equalled the cap."""
    sink = NullSink()
    middleware = AuditMiddleware(
        make_app(), build_config(max_body_bytes=32), sink, StubMetrics()
    )
    incoming: list[Message] = [
        {"type": "http.request", "body": b"A" * 20, "more_body": True},
        {"type": "http.request", "body": b"B" * 20, "more_body": True},
        {"type": "http.request", "body": b"C" * 20, "more_body": False},
    ]
    send, _sent = collector()
    await middleware(http_scope(path="/echo"), replay(incoming), send)
    doc = sink.only
    assert doc["audit"]["request"]["body_bytes"] == 32
    assert doc["audit"]["request"]["body_truncated"] is True
    assert doc["http"]["request"]["bytes"] == 60


async def test_S_1_the_replay_is_still_byte_identical_while_we_count() -> None:
    seen: list[tuple[str, int, bool]] = []
    sent_messages: list[Message] = [
        {"type": "http.request", "body": b"A" * 20, "more_body": True},
        {"type": "http.request", "body": b"B" * 20, "more_body": True},
        {"type": "http.request", "body": b"C" * 20, "more_body": False},
    ]
    received: list[Message] = []

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            received.append(message)
            seen.append(
                (message["type"], len(message.get("body", b"")), message.get("more_body", False))
            )
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = AuditMiddleware(
        app, build_config(max_body_bytes=32), NullSink(), StubMetrics()
    )
    send, _sent = collector()
    await middleware(http_scope(), replay(sent_messages), send)
    assert seen == [("http.request", 20, True), ("http.request", 20, True), ("http.request", 20, False)]
    assert all(a is b for a, b in zip(received, sent_messages, strict=True))


async def test_S_5_a_builder_failure_after_the_response_started_still_emits(
    monkeypatch: pytest.MonkeyPatch, metrics: StubMetrics
) -> None:
    """REVIEW S-5: FR-01 lost the document and only a shared counter noticed."""
    import audit_logging.middleware as middleware_module

    def explode(ctx: Any, config: Any, **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("builder is broken")

    monkeypatch.setattr(middleware_module, "build_document", explode)
    sink = NullSink()
    app, _ = wrap(build_config(), sink, metrics)
    async with client_for(app) as client:
        response = await client.get("/stream")
    assert response.status_code == 200
    assert response.text == "chunk-0;chunk-1;chunk-2;chunk-3;chunk-4;"
    doc = sink.only
    assert doc["trace"]["id"]
    assert doc["url"]["path"] == "/stream"
    assert doc["http"]["response"]["status_code"] == 200
    assert doc["error"]["type"] == "RuntimeError"
    assert doc["error"]["message"].startswith("audit_logging: ")
    assert metrics["audit_middleware_errors_total"] == 1


async def test_S_5_a_hostile_client_port_no_longer_costs_the_document(
    metrics: StubMetrics,
) -> None:
    sink = NullSink()
    middleware = AuditMiddleware(make_app(), build_config(), sink, metrics)
    send, _sent = collector()
    await middleware(
        http_scope(method="GET", path="/items/1", client=("1.2.3.4", "notaport")),
        replay([]),
        send,
    )
    assert len(sink.submitted) == 1
    assert sink.only["client"] == {"ip": "1.2.3.4", "port": 0}
    assert metrics["audit_middleware_errors_total"] == 0


async def test_S_6_one_warn_per_error_kind_not_one_per_process(
    caplog: pytest.LogCaptureFixture, metrics: StubMetrics
) -> None:
    """REVIEW S-6: the first benign error silenced every later one, forever."""

    class BrokenSink(NullSink):
        def submit(self, doc: dict[str, Any]) -> bool:
            raise RuntimeError("queue is on fire")

    def boom(scope: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("no user for you")

    app, _ = wrap(build_config(user_resolver=boom), BrokenSink(), metrics)
    with caplog.at_level("WARNING", logger="audit_logging"):
        async with client_for(app) as client:
            for _ in range(3):
                await client.get("/items/1")
    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 2, messages
    assert any("user_resolver raised" in m for m in messages)
    assert any("sink.submit() failed" in m for m in messages)


async def test_S_6_the_latch_is_bounded() -> None:
    import audit_logging.middleware as middleware_module

    for index in range(200):
        middleware_module._warn_once(f"synthetic-{index}")
    assert len(middleware_module._WARNED) <= middleware_module._WARNED_MAX


@pytest.mark.parametrize(
    ("path", "excluded"),
    [
        ("/health", True),
        ("/health/", True),
        ("/health/live", True),
        ("/healthcheck-admin", False),
        ("/health-secret/transfer", False),
        ("/healthz", False),
    ],
)
async def test_N_13_exclude_prefixes_are_anchored_on_a_segment_boundary(
    path: str, excluded: bool
) -> None:
    """REVIEW N-13: ``/health`` used to swallow ``/healthcheck-admin`` silently."""
    sink = NullSink()
    seen: list[str] = []

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        seen.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = AuditMiddleware(app, build_config(exclude_paths=["/health"]), sink, StubMetrics())
    send, _sent = collector()
    await middleware(http_scope(method="GET", path=path), replay([]), send)
    assert seen == [path]
    assert (len(sink.submitted) == 0) is excluded


async def test_N_13_the_shipped_defaults_still_exclude_what_they_should() -> None:
    sink = NullSink()

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    config = AuditConfig(service_name="t", service_version="0", environment="test")
    middleware = AuditMiddleware(app, config, sink, StubMetrics())
    send, _sent = collector()
    for path in ("/health", "/healthz", "/metrics", "/favicon.ico", "/docs", "/docs/oauth2"):
        await middleware(http_scope(method="GET", path=path), replay([]), send)
    assert sink.submitted == []


async def test_N_14_the_kill_switch_removes_the_request_id_header_too() -> None:
    """REVIEW N-14: documented, deliberate — FR-15 leaves no room to keep it.

    Pinned so the behaviour cannot drift without someone noticing, and so the
    runbook (A7) has something to point at.
    """
    sink = NullSink()
    app, _ = wrap(build_config(enabled=False), sink)
    async with client_for(app) as client:
        response = await client.get("/items/1")
    assert response.status_code == 200
    assert "x-request-id" not in response.headers
    assert sink.submitted == []


async def test_AC_23_a_204_and_a_head_response_are_logged_with_zero_bytes(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, _ = audited
    async with client_for(app) as client:
        no_content = await client.delete("/gone")
        head = await client.head("/both")
    assert no_content.status_code == 204
    assert head.status_code == 200
    assert len(sink.submitted) == 2
    for response, doc in zip((no_content, head), sink.submitted, strict=True):
        assert doc["http"]["response"]["bytes"] == 0
        assert response.headers.get_list("x-request-id") == [doc["trace"]["id"]]


async def test_M_2_a_one_mib_adversarial_body_does_not_stall_the_loop() -> None:
    """REVIEW M-2: one 1 MiB body froze the whole worker for 56–176 ms."""
    config = build_config()
    cap = config.max_body_bytes
    payload = (b"[" + b"[]," * (cap // 3))[: cap - 1].rstrip(b",") + b"]"
    sink = NullSink()

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = AuditMiddleware(app, config, sink, StubMetrics())
    send, _sent = collector()
    messages: list[Message] = [{"type": "http.request", "body": payload, "more_body": False}]
    started = time.perf_counter()
    await middleware(http_scope(), replay(messages), send)
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert sink.only["audit"]["request"]["body_skipped"] == "too_complex"
    assert elapsed_ms < 5.0, f"NFR-1 budget is 5 ms, took {elapsed_ms:.1f} ms"


async def test_AC_18_a_json_payload_mislabelled_as_text_leaks_nothing(
    metrics: StubMetrics,
) -> None:
    """The M-1 regression test, end to end through the middleware."""
    sink = NullSink(max_documents=3)
    app, _ = wrap(build_config(), sink, metrics)
    async with client_for(app) as client:
        for content_type in ("text/plain", "application/xml", None):
            headers = {"content-type": content_type} if content_type else {}
            await client.post("/echo", content=b'{"password":"p"}', headers=headers)
    assert len(sink.submitted) == 3
    for doc in sink.submitted:
        request = doc["audit"]["request"]
        assert request["body_skipped"] == "content_type"
        assert "body" not in request and "body_raw" not in request
        assert '"p"' not in json.dumps(doc)


# ===========================================================================
# Overhead (NFR-1/NFR-2) — reported, not asserted, in the default run
# ===========================================================================


async def _drive(app: Any, iterations: int, body: bytes) -> float:
    scope = http_scope(headers=[(b"content-type", b"application/json")])
    send, _sent = collector()
    started = time.perf_counter()
    for _ in range(iterations):
        messages: list[Message] = [
            {"type": "http.request", "body": body, "more_body": False}
        ]
        await app(dict(scope), replay(messages), send)
    return (time.perf_counter() - started) / iterations * 1e6


async def measure_overhead_us(iterations: int = 5000) -> tuple[float, float]:
    body = json.dumps({"pad": "z" * 8000, "qty": 3}).encode()

    async def bare(scope: Scope, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b'{"ok":true}'})

    wrapped = AuditMiddleware(bare, build_config(), NullSink(max_documents=1), StubMetrics())
    await _drive(bare, 200, body)
    await _drive(wrapped, 200, body)
    baseline = await _drive(bare, iterations, body)
    audited = await _drive(wrapped, iterations, body)
    return baseline, audited


@pytest.mark.load
async def test_overhead_per_request_microseconds() -> None:
    baseline, audited = await measure_overhead_us()
    print(
        f"\nbaseline {baseline:.1f} us/req, audited {audited:.1f} us/req, "
        f"overhead {audited - baseline:.1f} us/req"
    )
    assert audited - baseline < 5000  # NFR-1: well under the 5 ms budget


# ===========================================================================
# REVIEW-2 N2-3 / N2-6 — the query string is bounded, and skips are counted
# ===========================================================================


@pytest.mark.parametrize(
    ("name", "query"),
    [("8 KB", b"a&" * 4096), ("64 KB", b"a&" * 32768)],
)
async def test_N2_3_a_large_query_string_on_a_get_does_not_stall_the_loop(
    name: str, query: bytes, metrics: StubMetrics
) -> None:
    """REVIEW-2 N2-3: 8.3 ms at 8 KB, 24.0 ms at 64 KB, with **no body at all**.

    Same blast radius as M-2 — every concurrent request in the worker waits —
    reached by a ``GET`` that needs no body and no authentication.
    """
    sink = NullSink()

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = AuditMiddleware(app, build_config(), sink, metrics)
    send, _sent = collector()
    scope = http_scope(method="GET", path="/items/1", query_string=query, headers=[])
    started = time.perf_counter()
    await middleware(scope, replay([]), send)
    elapsed_ms = (time.perf_counter() - started) * 1000
    request = sink.only["audit"]["request"]
    assert request["query_skipped"] == "too_complex"
    assert request["query"] == {}
    assert sink.only["url"]["query"] == "[SKIPPED]"
    assert metrics["audit_queries_skipped_total"] == 1
    assert elapsed_ms < 5.0, f"NFR-1 budget is 5 ms, {name} took {elapsed_ms:.2f} ms"


async def test_N2_3_an_ordinary_query_string_still_reaches_the_document(
    audited: tuple[FastAPI, NullSink, StubMetrics],
) -> None:
    app, sink, metrics = audited
    async with client_for(app) as client:
        await client.get("/items/1?expand=lines&page=3")
    request = sink.only["audit"]["request"]
    assert "query_skipped" not in request
    assert request["query"] == {"expand": "lines", "page": "3"}
    assert metrics["audit_queries_skipped_total"] == 0


async def test_N2_6_the_middleware_gives_the_builder_its_counters(
    metrics: StubMetrics,
) -> None:
    """REVIEW-2 N2-6: a body that is not stored was counted nowhere at all."""
    sink = NullSink(max_documents=2)
    app, _ = wrap(build_config(), sink, metrics)
    async with client_for(app) as client:
        await client.post(
            "/echo", content=b"plain text body", headers={"content-type": "text/plain"}
        )
        await client.post("/echo", json={"sku": "A-11"})
    assert [d["audit"]["request"].get("body_skipped") for d in sink.submitted] == [
        "content_type",
        None,
    ]
    assert metrics["audit_bodies_skipped_total"] == 1


# ---------------------------------------------------------------------------
# Documented limitations, pinned.
#
# These assert the package's behaviour **as it stands**, not as we would like
# it. `docs/redaction.md` §4 tells operators these gaps exist; without a test
# a gap can silently close (making the doc a lie) or silently widen (making it
# an understatement) and nobody notices. Each docstring says what a fix would
# look like, so whoever fixes it updates the test instead of deleting it.
# ---------------------------------------------------------------------------


@pytest.fixture
def real_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo this module's autouse identity stubs.

    The stubs exist so middleware behaviour can be tested independently of
    redaction (a Phase 1 contract-isolation choice). A limitation test about
    *redaction* must use the real thing or it asserts nothing.
    """
    from audit_logging import redact as redact_module

    monkeypatch.setattr(document_module, "redact", redact_module.redact)
    monkeypatch.setattr(document_module, "filter_headers", redact_module.filter_headers)
    monkeypatch.setattr(document_module, "normalize_key", redact_module.normalize_key)


def _limitation_app() -> FastAPI:
    """Routes that carry a secret in the path, one named and one positional."""
    app = FastAPI()

    @app.get("/keys/{api_key}")
    async def named(api_key: str) -> dict[str, str]:
        return {"ok": api_key}

    @app.get("/tokens/{segment}")
    async def positional(segment: str) -> dict[str, str]:
        return {"ok": segment}

    return app


async def test_LIMITATION_secret_in_a_named_path_param_is_redacted_but_url_path_still_leaks(
    real_redaction: None,
) -> None:
    """`docs/redaction.md` §4.5, both halves, in one document.

    A route that *names* a denylisted parameter (`/keys/{api_key}`) gets that
    value redacted in `audit.path_params` — but `url.path` keeps the raw path,
    and `url.path` is an **indexed** keyword, so the secret stays searchable in
    Elasticsearch. Redacting one copy leaves the queryable one.

    A fix would have to rewrite `url.path` using the matched route's parameter
    spans, which is only possible for *named* parameters — see the companion
    test for the positional case. If that lands, this test should assert the
    rewritten path rather than being deleted.
    """
    sink = NullSink()
    app = _limitation_app()
    app.add_middleware(AuditMiddleware, config=build_config(), sink=sink)

    async with client_for(app) as client:
        await client.get("/keys/SUPERSECRET")

    doc = sink.only
    assert doc["audit"]["path_params"] == {"api_key": "[REDACTED]"}, "the named copy"
    assert doc["url"]["path"] == "/keys/SUPERSECRET", "the raw path is kept as-is"
    assert "SUPERSECRET" in json.dumps(doc), "the secret survives in the document"


async def test_LIMITATION_secret_in_a_positional_path_segment_is_never_redacted(
    real_redaction: None,
) -> None:
    """`docs/redaction.md` §4.5(a).

    Nothing key-based can redact a path segment the route does not name — there
    is no key to match against. The value reaches both `url.path` and
    `audit.path_params` under whatever the route did call it.

    The only real mitigation is not putting secrets in URLs. If a value-based
    detector is ever added, this test should flip to asserting redaction.
    """
    sink = NullSink()
    app = _limitation_app()
    app.add_middleware(AuditMiddleware, config=build_config(), sink=sink)

    async with client_for(app) as client:
        await client.get("/tokens/AKIA-POSITIONAL")

    doc = sink.only
    assert doc["url"]["path"] == "/tokens/AKIA-POSITIONAL"
    assert doc["audit"]["path_params"] == {"segment": "AKIA-POSITIONAL"}


async def test_LIMITATION_client_ip_is_the_transport_peer_not_x_forwarded_for(
    real_redaction: None,
) -> None:
    """`docs/redaction.md` §4.12.

    `client.ip` is `scope["client"]`, the socket peer — behind an ingress that
    is the proxy, not the end user. `X-Forwarded-For` is captured verbatim in
    the headers (it is on the default allowlist) but is deliberately **not**
    used to populate `client.ip`, because the header is client-controlled and
    deciding the true client IP is the ingress's job (schema §4).

    A fix would mean a trusted-proxy configuration. If one is added, this test
    should assert the resolved address rather than being deleted.
    """
    sink = NullSink()
    app, _ = wrap(build_config(), sink)

    async with client_for(app) as client:
        await client.get("/items/7", headers={"X-Forwarded-For": "203.0.113.9"})

    doc = sink.only
    assert doc["client"]["ip"] != "203.0.113.9", "the header must not win"
    assert doc["audit"]["request"]["headers"]["x-forwarded-for"] == "203.0.113.9"
