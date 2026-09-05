"""Frozen contracts for the audit_logging package.

Everything in this module is a contract between independently built modules.
It is frozen at the end of Phase 0 (plan §6). Do not change it without going
back through the orchestrator: middleware, redaction, sinks, infra and the
integration tests are all built against these signatures in isolation.

See ``docs/schema.md`` for the document each of these ultimately produces.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "Sink",
    "RequestContext",
    "Metrics",
    "METRIC_NAMES",
    "OUTCOME_SUCCESS",
    "OUTCOME_FAILURE",
    "OUTCOME_DISCONNECTED",
    "BODY_SKIPPED_CONTENT_TYPE",
    "BODY_SKIPPED_EMPTY",
    "BODY_SKIPPED_UNREAD",
    "BODY_SKIPPED_TOO_COMPLEX",
]

# ---------------------------------------------------------------------------
# Vocabularies
# ---------------------------------------------------------------------------

#: ``event.outcome`` values. Nothing else is legal.
OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_DISCONNECTED = "disconnected"

#: ``RequestContext.body_skipped`` values (``None`` means the body was captured).
BODY_SKIPPED_CONTENT_TYPE = "content_type"
BODY_SKIPPED_EMPTY = "empty"
BODY_SKIPPED_UNREAD = "unread"
#: The parsed body exceeded ``max_body_nodes`` — bounding the request-path cost
#: of an attacker-chosen payload (review M-2).
BODY_SKIPPED_TOO_COMPLEX = "too_complex"


# ---------------------------------------------------------------------------
# Sink
# ---------------------------------------------------------------------------


class Sink(ABC):
    """Where finished audit documents go.

    ``submit`` is deliberately **synchronous**: it is called from the request
    path and must never await. Anything slower than a serialisation plus a
    ``deque.append`` is a bug (plan §6.3, NFR-2).
    """

    @abstractmethod
    async def start(self) -> None:
        """Begin background work. Idempotent — calling twice is a no-op."""

    @abstractmethod
    def submit(self, doc: dict[str, Any]) -> bool:
        """Enqueue one document. Non-blocking. ``False`` if it was dropped."""

    @abstractmethod
    async def flush(self) -> None:
        """Write everything currently queued before returning."""

    @abstractmethod
    async def close(self) -> None:
        """Drain and release resources.

        Must return within ``shutdown_flush_timeout`` whether or not the drain
        succeeded (FR-27). Idempotent.
        """


# ---------------------------------------------------------------------------
# Request context
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class RequestContext:
    """Everything the middleware observed about one request.

    Built by ``middleware.py``, consumed by ``document.build_document``. All
    timings are ``time.monotonic_ns()``; wall-clock ``@timestamp`` is stamped
    by the document builder.
    """

    trace_id: str
    started_ns: int
    scope: dict[str, Any]
    method: str
    raw_path: str
    query_string: bytes
    ended_ns: int | None = None
    content_type: str | None = None
    body: bytes = b""
    body_truncated: bool = False
    body_skipped: str | None = None
    status_code: int | None = None
    response_headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    response_bytes: int = 0
    outcome: str = OUTCOME_SUCCESS
    exc: BaseException | None = None
    user: dict[str, Any] | None = None

    @property
    def duration_ns(self) -> int:
        """Nanoseconds from before the app was invoked to the final chunk."""
        if self.ended_ns is None:
            return 0
        return max(0, self.ended_ns - self.started_ns)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

#: The complete set of metric names the package emits (plan §6.7).
METRIC_NAMES: frozenset[str] = frozenset(
    {
        "audit_documents_submitted_total",
        "audit_documents_dropped_total",
        "audit_documents_failed_total",
        "audit_middleware_errors_total",
        "audit_queue_bytes",
        "audit_flush_seconds",
        "audit_file_rotations_total",
        # Added after the adversarial review (N-8): documents submitted by
        # requests still in flight when the sink is closing. Counted
        # separately from ordinary drops because it means "shutdown was too
        # short", not "disk is not keeping up".
        "audit_documents_dropped_after_close_total",
        # A document whose *body* was not stored: over ``max_body_nodes``,
        # an unparseable content type, or a skipped multipart. The audit
        # record still exists — only the body is missing — but without
        # this counter an operator cannot see it happening at all (A8 N2).
        "audit_bodies_skipped_total",
        # Kept separate from the body counter on purpose: an operator
        # alerting on "we are losing request bodies" must not be paged
        # by a chatty query route.
        "audit_queries_skipped_total",
    }
)


@runtime_checkable
class Metrics(Protocol):
    """Counters and gauges. Implementations must never raise."""

    def inc(self, name: str, value: int = 1) -> None:
        """Increment a counter."""
        ...

    def set(self, name: str, value: float) -> None:
        """Set a gauge."""
        ...
