"""Test helper: capture what ``audit.emit()`` writes (plan §8).

    from audit_logging.testing import capture

    with capture() as rec:
        audit.emit("billing.invoice.sent", uz="{actor} hisob yubordi")
    assert rec.last["audit"]["result"] == "success"
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from .metrics import InMemoryMetrics
from .semantic import runtime
from .sinks.null_sink import NullSink

__all__ = ["Captured", "capture"]


class Captured:
    """Every document submitted while the capture was active."""

    def __init__(self, sink: NullSink, metrics: Any) -> None:
        self.records: list[dict[str, Any]] = sink.submitted
        self.metrics = metrics

    @property
    def last(self) -> dict[str, Any] | None:
        return self.records[-1] if self.records else None


@contextmanager
def capture(config: Any = None) -> Iterator[Captured]:
    """Install a collecting sink as the active one; restore the previous on exit.

    ``config`` defaults to the active one's (service name etc.), else ``None``.
    """
    previous = runtime.get_active()
    sink = NullSink()
    metrics = InMemoryMetrics()
    if config is None and previous is not None:
        config = previous.config
    runtime.set_active(sink, config, metrics)
    try:
        yield Captured(sink, metrics)
    finally:
        if previous is None:
            runtime.clear_active()
        else:
            runtime.set_active(previous.sink, previous.config, previous.metrics)
