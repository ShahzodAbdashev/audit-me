"""NFR-1 under *hostile* traffic — the arm the benign load test cannot see.

Why this file exists
--------------------

``test_nfr1_latency.py`` drives 100 rps of well-formed 8 KB JSON and reports a
p99 delta around +0.8 ms against a 5 ms budget. It reported a comfortable PASS
throughout the entire period in which **M-2 was live** — one 1 MiB JSON body
stalling the whole event loop for 56-141 ms — because a benign arm never sends
the payload that triggers it. The adversarial review said so in as many words:

    "A6's new load test only exercises 8 KB bodies, where it measures 0.2 ms —
     so NFR-1 currently reports PASS."

A latency budget that only holds for traffic you control is not a budget. Each
case below is a *shape a client chooses*, taken from a defect that was really
found, really measured, and really fixed:

===========  =====================================  ==========================
Case         Was                                    Defect
===========  =====================================  ==========================
big body     140.6 ms build_document                 M-2
big query    17.9 ms on a GET with **no body**       N2-3
hostile keys 20 ms for a 73 KB body                  N2-4
slow-loris   28x RSS amplification                   M-4 (memory, not latency)
===========  =====================================  ==========================

These run at a low rate for a short duration: the point is not throughput, it
is that a *single* request of each shape cannot blow the budget. If one can,
one client can take a worker down, and the rate is irrelevant.

Marked ``load`` so they stay out of the default run, like the benign arm.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from audit_logging.config import AuditConfig
from audit_logging.document import build_document
from audit_logging._contracts import RequestContext

from .driver import build_app, run_arm

pytestmark = pytest.mark.load

#: NFR-1's budget. An adversarial request may use more of it than a benign one,
#: but it must not exceed it — that is the whole claim.
BUDGET_MS = 5.0


def _config(**overrides: Any) -> AuditConfig:
    values: dict[str, Any] = {"service_name": "adversarial", "log_dir": "/tmp/audit-adv"}
    values.update(overrides)
    return AuditConfig(**values)


def _ctx(body: bytes, query: bytes = b"", content_type: str | None = "application/json") -> RequestContext:
    headers = [(b"content-type", content_type.encode())] if content_type else []
    return RequestContext(
        trace_id="adv",
        started_ns=0,
        scope={"type": "http", "headers": headers, "method": "POST", "query_string": query},
        method="POST",
        raw_path="/adv",
        query_string=query,
        content_type=content_type,
        body=body,
        ended_ns=1,
        status_code=200,
    )


def _time_build(ctx: RequestContext, config: AuditConfig, rounds: int = 5) -> float:
    """Median milliseconds for one ``build_document``. Median, not mean: one
    GC pause must not decide whether NFR-1 passes."""
    import gc
    import time

    gc.collect()
    gc.disable()
    try:
        timings = []
        for _ in range(rounds):
            start = time.perf_counter()
            build_document(ctx, config)
            timings.append((time.perf_counter() - start) * 1000)
    finally:
        gc.enable()
    return sorted(timings)[len(timings) // 2]


# ---------------------------------------------------------------------------
# The four shapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "unit"),
    [
        ("empty objects", b'{},'),
        ("one-key objects", b'{"a":1},'),
        ("scalars", b"0,"),
        ("empty lists", b"[],"),
    ],
)
def test_NFR_1_adversarial_a_one_megabyte_body_cannot_blow_the_budget(
    name: str, unit: bytes
) -> None:
    """M-2's exact payload table, as a standing regression net.

    These four shapes measured 56.0 / 88.2 / 93.4 / 140.6 ms before FR-29's
    node cap. Each is legal, under ``max_body_bytes``, and chosen by the
    client. If this test ever fails again, the node cap has regressed and one
    unauthenticated client can saturate a worker at roughly 9 req/s.
    """
    config = _config()
    cap = config.max_body_bytes
    body = (b"[" + unit * (cap // len(unit)))[: cap - 1].rstrip(b",") + b"]"
    assert len(body) <= cap

    elapsed = _time_build(_ctx(body), config)
    assert elapsed < BUDGET_MS, f"{name}: {elapsed:.2f} ms exceeds the {BUDGET_MS} ms budget"


@pytest.mark.parametrize("size_kb", [8, 64, 164])
def test_NFR_1_adversarial_a_large_query_string_cannot_blow_the_budget(size_kb: int) -> None:
    """N2-3: a GET with **no body at all** used to cost 8.3-24.0 ms.

    The query string is parsed, redacted and re-encoded on the request path
    exactly like a form body, and nothing bounded it until ``max_query_bytes``.
    A body-shaped defence does not cover this route.
    """
    config = _config()
    query = b"a&" * (size_kb * 1024 // 2)
    elapsed = _time_build(_ctx(b"", query=query, content_type=None), config)
    assert elapsed < BUDGET_MS, f"{size_kb} KB query: {elapsed:.2f} ms exceeds the budget"


def test_NFR_1_adversarial_hostile_keys_cannot_blow_the_budget() -> None:
    """N2-4: 73 KB of control-character keys cost 20 ms — inside every cap.

    Key sanitisation is far more expensive per key on the cold path than the
    fast path, and the client chooses what fraction of keys take it. Bounding
    the body's *size* and *node count* does not bound this; only the per-call
    cold-key budget does.
    """
    config = _config()
    body = json.dumps({f"k\x01{i}": i for i in range(3000)}).encode()
    elapsed = _time_build(_ctx(body), config)
    assert elapsed < BUDGET_MS, f"hostile keys: {elapsed:.2f} ms exceeds the budget"


def test_NFR_1_adversarial_a_body_the_cap_accepts_is_still_inside_the_budget() -> None:
    """The boundary case, which is the one that actually ships.

    A body just under ``max_body_nodes`` is *accepted* and fully parsed,
    redacted and serialised. If the cap and the budget ever disagree, this is
    where it shows — and it is the number that decides whether the default is
    honest.
    """
    config = _config()
    order = {
        "order_id": "A-1123",
        "customer": {"id": "u-99", "email": "a@b.c", "password": "hunter2"},
        "lines": [{"sku": f"S-{i}", "qty": i} for i in range(6)],
    }
    body = json.dumps({"orders": [order] * 90}).encode()
    request = build_document(_ctx(body), config)["audit"]["request"]
    assert "body" in request, "this body must be accepted, or the test proves nothing"

    elapsed = _time_build(_ctx(body), config)
    assert elapsed < BUDGET_MS, f"accepted body: {elapsed:.2f} ms exceeds the budget"


# ---------------------------------------------------------------------------
# End to end, through the real middleware and a real sink
# ---------------------------------------------------------------------------


async def test_NFR_1_adversarial_end_to_end_p99_stays_inside_the_budget(
    tmp_path: Any,
) -> None:
    """The same claim through the whole stack, not just ``build_document``.

    A modest rate on purpose: the question is whether a single hostile request
    can stall the loop for everyone, which is what M-2 actually did. The
    baseline arm sends the same bytes to the same app without the middleware,
    so the delta isolates the package.
    """
    from audit_logging import AuditMiddleware
    from audit_logging.metrics import InMemoryMetrics
    from audit_logging.sinks.file_sink import FileSink

    config = _config(log_dir=tmp_path, flush_interval_seconds=1.0)
    body = (b"[" + b"[]," * 300_000)[: config.max_body_bytes - 1].rstrip(b",") + b"]"

    baseline = await run_arm("baseline", build_app(), body, rate=20, duration=3.0)

    metrics = InMemoryMetrics()
    sink = FileSink(config, metrics)
    app = build_app()
    app.add_middleware(AuditMiddleware, config=config, sink=sink, metrics=metrics)
    audited = await run_arm("audited", app, body, rate=20, duration=3.0)
    await sink.close()

    delta = audited.stats()["p99"] - baseline.stats()["p99"]
    assert delta < BUDGET_MS, (
        f"adversarial p99 delta {delta:.2f} ms exceeds the budget "
        f"(baseline {baseline.stats()['p99']:.2f} ms, audited {audited.stats()['p99']:.2f} ms)"
    )
    # The body must have been refused — otherwise the budget was met by luck.
    assert metrics.snapshot().get("audit_bodies_skipped_total", 0) > 0
