"""The frozen contracts themselves. Owned by A1.

These tests exist so that a downstream agent quietly widening a contract
breaks the build rather than the integration tests three days later.
"""

from __future__ import annotations

import inspect
from typing import Any

from audit_logging._contracts import (
    METRIC_NAMES,
    Metrics,
    RequestContext,
    Sink,
)
from audit_logging.sinks.null_sink import NullSink


def test_sink_abc_surface_is_exactly_four_methods() -> None:
    assert Sink.__abstractmethods__ == frozenset({"start", "submit", "flush", "close"})


def test_submit_is_synchronous() -> None:
    """NFR-2: submit() is called from the request path and must never await."""
    assert not inspect.iscoroutinefunction(Sink.submit)
    assert not inspect.iscoroutinefunction(NullSink.submit)


def test_start_flush_close_are_async() -> None:
    for name in ("start", "flush", "close"):
        assert inspect.iscoroutinefunction(getattr(Sink, name)), name


def test_request_context_uses_slots() -> None:
    ctx = RequestContext(
        trace_id="t", started_ns=0, scope={}, method="GET", raw_path="/", query_string=b""
    )
    assert not hasattr(ctx, "__dict__")


def test_request_context_defaults() -> None:
    ctx = RequestContext(
        trace_id="t", started_ns=0, scope={}, method="GET", raw_path="/", query_string=b""
    )
    assert ctx.body == b"" and ctx.body_truncated is False
    assert ctx.body_skipped is None and ctx.status_code is None
    assert ctx.response_bytes == 0 and ctx.outcome == "success"
    assert ctx.exc is None and ctx.user is None
    assert ctx.response_headers == []


def test_duration_is_zero_until_ended() -> None:
    ctx = RequestContext(
        trace_id="t", started_ns=1000, scope={}, method="GET", raw_path="/", query_string=b""
    )
    assert ctx.duration_ns == 0
    ctx.ended_ns = 5000
    assert ctx.duration_ns == 4000


def test_duration_never_negative_across_a_clock_glitch() -> None:
    ctx = RequestContext(
        trace_id="t", started_ns=5000, scope={}, method="GET", raw_path="/", query_string=b""
    )
    ctx.ended_ns = 1000
    assert ctx.duration_ns == 0


def test_metric_names_are_the_plans_seven_plus_the_review_addition() -> None:
    assert METRIC_NAMES == {
        "audit_documents_dropped_after_close_total",
        "audit_bodies_skipped_total",
        "audit_queries_skipped_total",
        "audit_documents_submitted_total",
        "audit_documents_dropped_total",
        "audit_documents_failed_total",
        "audit_middleware_errors_total",
        "audit_queue_bytes",
        "audit_flush_seconds",
        "audit_file_rotations_total",
    }


def test_metrics_protocol_is_structural() -> None:
    class Counter:
        def inc(self, name: str, value: int = 1) -> None: ...
        def set(self, name: str, value: float) -> None: ...

    assert isinstance(Counter(), Metrics)
    assert not isinstance(object(), Metrics)


class TestNullSink:
    async def test_lifecycle(self) -> None:
        s = NullSink()
        await s.start()
        assert s.started
        assert s.submit({"a": 1}) is True
        await s.flush()
        await s.close()
        assert s.closed and s.flush_count == 1
        assert s.submitted == [{"a": 1}]

    def test_only_requires_exactly_one(self) -> None:
        s = NullSink()
        for bad in ([], [{"a": 1}, {"b": 2}]):
            s.submitted = list(bad)
            try:
                s.only
            except AssertionError:
                pass
            else:
                raise AssertionError("expected AssertionError")

    def test_bounded_mode_drops_oldest(self) -> None:
        s = NullSink(max_documents=2)
        for i in range(5):
            s.submit({"i": i})
        assert [d["i"] for d in s.submitted] == [3, 4]

    def test_is_a_sink(self) -> None:
        assert isinstance(NullSink(), Sink)


def test_no_network_client_is_importable_from_the_package() -> None:
    """NFR-4 / AGENTS.md rule 3, enforced as a test rather than a grep."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "audit_logging"
    banned = ("elasticsearch", "kafka", "httpx", "requests", "aiohttp", "urllib3")
    offenders: list[str] = []
    for py in root.rglob("*.py"):
        text = py.read_text()
        for name in banned:
            if f"import {name}" in text or f"from {name}" in text:
                offenders.append(f"{py.name}: {name}")
    assert offenders == [], offenders


def test_no_awaits_hide_behind_submit_in_the_package() -> None:
    """NFR-2, structural: submit() implementations must not be coroutines."""
    import pathlib
    import ast

    root = pathlib.Path(__file__).resolve().parents[2] / "audit_logging"
    for py in root.rglob("*.py"):
        tree = ast.parse(py.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "submit":
                raise AssertionError(f"{py.name}: submit() must not be async")


def _unused(x: Any) -> Any:
    return x
