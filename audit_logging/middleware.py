"""``AuditMiddleware`` — pure ASGI request capture.

Owned by **Agent A2**. See ``docs/REQUIREMENTS.md`` FR-01…FR-09, FR-15,
FR-23…FR-25 and plan §4.1.

Never ``BaseHTTPMiddleware`` (D-1): body replay only works at the raw ASGI
layer. Nothing here awaits I/O, allocates unboundedly, or raises into the
application (NFR-2, NFR-3).

The kill switch takes ``X-Request-ID`` with it (review N-14)
------------------------------------------------------------

With ``enabled = false`` the middleware is a pure pass-through, so FR-24's
``X-Request-ID`` response header disappears along with the logging. That is
deliberate and it is what FR-15 asks for: "no document is built, no queue
allocated, no file opened, and **no measurable overhead**" leaves no room for
still wrapping ``send`` on every request just to stamp a header. The
consequence is that flipping the switch changes API behaviour, not only
logging — anything downstream correlating on the echoed header stops seeing
it. Operators need that in the runbook (A7), not discovered during an
incident. A service that needs the header unconditionally should set it at the
ingress, which is where request identity belongs anyway.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, cast

from ._contracts import (
    BODY_SKIPPED_CONTENT_TYPE,
    BODY_SKIPPED_EMPTY,
    BODY_SKIPPED_UNREAD,
    OUTCOME_DISCONNECTED,
    OUTCOME_FAILURE,
    OUTCOME_SUCCESS,
    Metrics,
    RequestContext,
    Sink,
)
from .config import AuditConfig
from .document import (
    BODY_KIND_BINARY,
    RECEIVED_BYTES_KEY,
    body_kind_for,
    build_document,
    build_minimal_document,
)

__all__ = ["AuditMiddleware"]

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_LOGGER = logging.getLogger("audit_logging")

#: NFR-3 — the package logs each *kind* of internal error once per process at
#: WARN. A single ``bool`` latch meant the first error of the process, however
#: benign (a ``user_resolver`` raising once), silenced every later error of
#: every other kind in every middleware instance forever (review S-6).
#: Keyed on the ``what`` string, all of which are module literals; the cap only
#: guards against a future caller passing something dynamic.
_WARNED: set[str] = set()
_WARNED_MAX = 64

_TRACE_HEADER = b"x-request-id"
_MAX_TRACE_ID_LEN = 200


def _warn_once(what: str, exc: BaseException | None = None) -> None:
    """Log each kind of package-internal error once per process, then stay quiet."""
    if what in _WARNED:
        return
    if len(_WARNED) < _WARNED_MAX:
        _WARNED.add(what)
    _LOGGER.warning(
        "audit_logging: %s — audit capture degraded; further errors of this kind "
        "are counted in audit_middleware_errors_total but not logged",
        what,
        exc_info=exc,
    )


class _NoopMetrics:
    """Fallback used only when :class:`InMemoryMetrics` is unavailable."""

    def inc(self, name: str, value: int = 1) -> None:  # noqa: D102
        return None

    def set(self, name: str, value: float) -> None:  # noqa: D102
        return None


def _default_metrics() -> Metrics:
    try:
        from .metrics import InMemoryMetrics

        return cast(Metrics, InMemoryMetrics())
    except Exception:  # pragma: no cover - A4 not implemented yet
        return _NoopMetrics()


def _header(headers: list[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    for key, value in headers:
        if key.lower() == name:
            return value
    return None


def _is_well_formed_trace_id(raw: bytes) -> bool:
    """FR-23 — ≤ 200 chars, printable ASCII, no whitespace."""
    if not raw or len(raw) > _MAX_TRACE_ID_LEN:
        return False
    return all(0x21 <= byte <= 0x7E for byte in raw)


class AuditMiddleware:
    """Wraps an ASGI app and emits exactly one audit document per request."""

    __slots__ = (
        "app",
        "config",
        "metrics",
        "_sink",
        "_enabled",
        "_exclude",
        "_sink_started",
        "_sink_closed",
        "_max_body",
        "_background",
    )

    def __init__(
        self,
        app: ASGIApp,
        config: AuditConfig,
        sink: Sink | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        self.app = app
        self.config = config
        self.metrics: Metrics = metrics if metrics is not None else _default_metrics()
        self._enabled = bool(config.enabled)
        # FR-02 is prefix matching, but a bare-word prefix silently swallows a
        # route added later that merely shares it — ``/health`` excluding
        # ``/healthcheck-admin`` (review N-13). Anchoring on a path-segment
        # boundary keeps FR-02's intent and removes the trap. A trailing slash
        # is normalised away so ``/health/`` and ``/health`` behave alike; a
        # configured ``"/"`` normalises to ``""`` and excludes everything,
        # which is the only sensible reading of it.
        self._exclude: tuple[str, ...] = tuple(
            prefix.rstrip("/") for prefix in config.exclude_paths
        )
        self._max_body = int(config.max_body_bytes)
        self._sink_started = False
        self._sink_closed = False
        self._background: set[asyncio.Task[None]] = set()
        # FR-15: with the kill switch off nothing is allocated and no file is
        # opened — the sink is never constructed.
        self._sink: Sink | None = None
        if self._enabled:
            self._sink = sink if sink is not None else self._build_sink()

    # -- construction helpers ------------------------------------------------

    def _build_sink(self) -> Sink | None:
        try:
            from .sinks.file_sink import FileSink

            return FileSink(self.config, self.metrics)
        except Exception as exc:  # pragma: no cover - A4 not implemented yet
            self._oops("could not construct the default FileSink", exc)
            return None

    # -- error plumbing (NFR-3) ---------------------------------------------

    def _oops(self, what: str, exc: BaseException | None = None) -> None:
        """Count, log once, swallow. Must never raise."""
        try:
            self.metrics.inc("audit_middleware_errors_total")
        except Exception:  # pragma: no cover - a Metrics impl must not raise
            pass
        try:
            _warn_once(what, exc)
        except Exception:  # pragma: no cover - logging must not break a request
            pass

    # -- ASGI ----------------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type != "http" or not self._enabled:
            if scope_type == "lifespan" and self._enabled:
                await self._lifespan(scope, receive, send)
                return
            # FR-01/FR-15: websocket, anything unknown, and the whole app when
            # the kill switch is off — pure pass-through, no wrapping at all.
            await self.app(scope, receive, send)
            return

        raw_path = str(scope.get("path", ""))
        # FR-02: exclusion is decided on the raw path, before any wrapping.
        if self._is_excluded(raw_path):
            await self.app(scope, receive, send)
            return

        await self._handle_http(scope, receive, send, raw_path)

    def _is_excluded(self, raw_path: str) -> bool:
        """FR-02 — prefix match, anchored on a path-segment boundary (N-13)."""
        for prefix in self._exclude:
            if not prefix:
                return True
            if raw_path == prefix or raw_path.startswith(prefix + "/"):
                return True
        return False

    # -- lifespan (observed, never altered) ----------------------------------

    async def _lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def receive_w() -> Message:
            message = await receive()
            if message.get("type") == "lifespan.shutdown":
                # FR-27: drain before the app tears its own state down.
                await self._close_sink()
            return message

        async def send_w(message: Message) -> None:
            await send(message)
            if message.get("type") == "lifespan.startup.complete":
                await self._start_sink()

        await self.app(scope, receive_w, send_w)

    async def _start_sink(self) -> None:
        if self._sink is None or self._sink_started:
            return
        self._sink_started = True
        try:
            await self._sink.start()
        except Exception as exc:
            self._oops("sink.start() failed", exc)

    async def _close_sink(self) -> None:
        if self._sink is None or self._sink_closed:
            return
        self._sink_closed = True
        try:
            await asyncio.wait_for(
                self._sink.close(), timeout=self.config.shutdown_flush_timeout
            )
        except Exception as exc:
            self._oops("sink.close() failed or timed out", exc)

    def _ensure_started(self) -> None:
        """Lazily start the sink from the request path without awaiting."""
        if self._sink is None or self._sink_started:
            return
        self._sink_started = True
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:  # pragma: no cover - submit outside a loop
            return
        try:
            task = loop.create_task(self._sink.start())
        except Exception as exc:  # pragma: no cover
            self._oops("could not schedule sink.start()", exc)
            return
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    # -- the hot path --------------------------------------------------------

    async def _handle_http(
        self, scope: Scope, receive: Receive, send: Send, raw_path: str
    ) -> None:
        try:
            headers = cast("list[tuple[bytes, bytes]]", scope.get("headers") or [])
            raw_ct = _header(headers, b"content-type")
            ctx = RequestContext(
                trace_id=self._trace_id(headers),
                started_ns=time.monotonic_ns(),
                scope=cast("dict[str, Any]", scope),
                method=str(scope.get("method", "")).upper(),
                raw_path=raw_path,
                query_string=cast(bytes, scope.get("query_string", b"") or b""),
                content_type=raw_ct.decode("latin-1") if raw_ct is not None else None,
            )
        except Exception as exc:
            # We could not even set up: run the app completely unwrapped.
            self._oops("could not start capture", exc)
            await self.app(scope, receive, send)
            return

        trace_id_bytes = ctx.trace_id.encode("latin-1", "replace")
        cap = self._max_body
        # FR-08 / review M-4: a ``bytearray``, not a list of chunks. The bytes
        # were always capped; the *memory* was not, because it was dominated by
        # ~33 B of object header per chunk plus a list slot — and the client
        # picks the chunk size over chunked transfer-encoding. 50 concurrent
        # 1 MiB bodies dribbled two bytes at a time cost 1.4 GB of RSS.
        buffered = bytearray()
        received_total = 0
        saw_disconnect = False
        saw_request_message = False

        async def receive_w() -> Message:
            # FR-04: every message is returned to the app byte-identical.
            nonlocal received_total, saw_disconnect, saw_request_message
            message = await receive()
            try:
                message_type = message.get("type")
                if message_type == "http.request":
                    saw_request_message = True
                    body = message.get("body", b"")
                    if body:
                        # Counted whether or not it is buffered, so
                        # ``http.request.bytes`` is right for a chunked upload
                        # past the cap (review S-1). Counting is free; it is
                        # the buffering that is bounded.
                        received_total += len(body)
                        room = cap - len(buffered)
                        if room > 0:
                            buffered.extend(body[:room] if len(body) > room else body)
                        # FR-08: stop at the cap, flag it, allocate no more.
                        if len(body) > room:
                            ctx.body_truncated = True
                elif message_type == "http.disconnect":
                    saw_disconnect = True
            except Exception as exc:
                self._oops("request capture failed", exc)
            return message

        async def send_w(message: Message) -> None:
            outgoing = message
            try:
                message_type = message.get("type")
                if message_type == "http.response.start":
                    ctx.status_code = int(message.get("status", 0))
                    raw_headers = cast(
                        "list[tuple[bytes, bytes]]", message.get("headers") or []
                    )
                    response_headers = list(raw_headers)
                    # FR-24: the only mutation this middleware makes.
                    if _header(response_headers, _TRACE_HEADER) is None:
                        response_headers.append((_TRACE_HEADER, trace_id_bytes))
                        outgoing = dict(message)
                        outgoing["headers"] = response_headers
                    ctx.response_headers = response_headers
                elif message_type == "http.response.body":
                    ctx.response_bytes += len(message.get("body", b"") or b"")
                    if not message.get("more_body", False):
                        # FR-06: the LAST chunk stops the clock.
                        ctx.ended_ns = time.monotonic_ns()
            except Exception as exc:
                self._oops("response capture failed", exc)
                outgoing = message
            await send(outgoing)

        try:
            await self.app(scope, receive_w, send_w)
        except BaseException as exc:
            try:
                ctx.exc = exc
                if ctx.status_code is None:
                    ctx.status_code = 500
            except Exception:  # pragma: no cover
                pass
            self._emit(ctx, buffered, received_total, saw_disconnect, saw_request_message)
            raise  # NFR-3: application exceptions propagate unchanged.

        self._emit(ctx, buffered, received_total, saw_disconnect, saw_request_message)

    # -- document emission ---------------------------------------------------

    def _trace_id(self, headers: list[tuple[bytes, bytes]]) -> str:
        incoming = _header(headers, _TRACE_HEADER)
        if incoming is not None and _is_well_formed_trace_id(incoming):
            return incoming.decode("ascii")
        return uuid.uuid4().hex

    def _resolve_user(self, scope: Scope) -> dict[str, Any] | None:
        """FR-25 — a bad resolver costs a counter, never the document."""
        resolver = self.config.user_resolver
        if resolver is None:
            return None
        resolved: Any
        try:
            resolved = resolver(cast("dict[str, Any]", scope))
        except Exception as exc:
            self._oops("user_resolver raised", exc)
            return None
        if resolved is None:
            return None
        if not isinstance(resolved, dict):
            # A resolver is application code: it may return anything at all.
            self._oops("user_resolver returned a non-dict")
            return None
        return cast("dict[str, Any]", resolved)

    def _body_skipped(
        self, ctx: RequestContext, buffered_len: int, saw_request_message: bool
    ) -> str | None:
        if body_kind_for(ctx.content_type) == BODY_KIND_BINARY:
            return BODY_SKIPPED_CONTENT_TYPE  # FR-07
        if buffered_len:
            return None
        if saw_request_message:
            return BODY_SKIPPED_EMPTY
        declared = _header(
            cast("list[tuple[bytes, bytes]]", ctx.scope.get("headers") or []),
            b"content-length",
        )
        if declared is None or declared.strip() in (b"", b"0"):
            return BODY_SKIPPED_EMPTY
        return BODY_SKIPPED_UNREAD  # the app never read a body that was announced

    def _emit(
        self,
        ctx: RequestContext,
        buffered: bytearray,
        received_total: int,
        saw_disconnect: bool,
        saw_request_message: bool,
    ) -> None:
        """Finish the context, build the document, hand it to the sink."""
        doc: dict[str, Any] | None = None
        try:
            # Outcome is decided while ``ended_ns is None`` still means "the
            # response never finished"; only then is the clock stopped.
            ctx.outcome = _outcome(ctx, saw_disconnect)
            if ctx.ended_ns is None:
                ctx.ended_ns = time.monotonic_ns()
            ctx.body = bytes(buffered)
            ctx.body_skipped = self._body_skipped(
                ctx, len(buffered), saw_request_message
            )
            ctx.user = self._resolve_user(ctx.scope)
            # Review S-1: the true received count has no home on the frozen
            # ``RequestContext``, so it travels on the scope under a namespaced
            # key. The application has already returned by now, so this is
            # invisible to it.
            try:
                ctx.scope[RECEIVED_BYTES_KEY] = received_total
            except Exception:  # pragma: no cover - a scope must be a mapping
                pass
            # ``metrics`` is keyword-only and optional: the document builder
            # counts the bodies and query strings it refuses to store
            # (``audit_bodies_skipped_total``, review N2-6/N2-3), which needs
            # the same counters the middleware already holds.
            doc = build_document(ctx, self.config, metrics=self.metrics)
        except Exception as exc:
            self._oops("could not build the audit document", exc)
            # FR-01 says exactly one document per request; NFR-3 forbids
            # failing the request to get it. Emit a hole *marker* rather than
            # a hole (review S-5) — but never let the fallback raise either.
            try:
                doc = build_minimal_document(ctx, self.config, exc)
            except Exception as fallback_exc:  # pragma: no cover - defensive
                self._oops("could not build the degraded audit document", fallback_exc)
                return
        sink = self._sink
        if sink is None or doc is None:
            return
        try:
            self._ensure_started()
            sink.submit(doc)  # NFR-2: synchronous, enqueue only.
        except Exception as exc:
            self._oops("sink.submit() failed", exc)


def _outcome(ctx: RequestContext, saw_disconnect: bool) -> str:
    # ``ended_ns`` is still None here unless the final response chunk was seen.
    if saw_disconnect and ctx.ended_ns is None:
        return OUTCOME_DISCONNECTED
    if ctx.exc is not None:
        return OUTCOME_FAILURE
    if ctx.status_code is not None and ctx.status_code >= 500:
        return OUTCOME_FAILURE
    return OUTCOME_SUCCESS
