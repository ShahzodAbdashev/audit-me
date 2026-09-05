"""NFR-1 as an assertion: added p99 ≤ 5 ms at 100 rps with 8 KB bodies.

Marked ``load``, so it is out of the default run::

    ./.venv/bin/python -m pytest tests/load -q -m load

The default duration here is short enough to sit in a CI job; the honest,
unhurried measurement is ``python -m tests.load.driver --duration 300``, and
the numbers from that run are recorded in ``tests/AC-matrix.md``. Override with
``AUDIT_LOAD_DURATION`` (seconds per arm).
"""

from __future__ import annotations

import os

import pytest

from .driver import DEFAULT_RATE, TARGET_BODY_BYTES, build_body, run_comparison

pytestmark = pytest.mark.load

DURATION = float(os.environ.get("AUDIT_LOAD_DURATION", "30"))

#: NFR-1. The budget is for the *added* p99, not the absolute one.
P99_BUDGET_MS = 5.0


def test_body_is_really_eight_kilobytes() -> None:
    """A load test with the wrong payload measures the wrong thing."""
    body = build_body()
    assert TARGET_BODY_BYTES <= len(body) < TARGET_BODY_BYTES + 512
    assert b"password" in body and b"api_key" in body and b"token" in body


async def test_NFR_1_added_p99_latency_under_five_milliseconds() -> None:
    """100 rps, 8 KB bodies, real FileSink, real redaction, both arms."""
    comparison = await run_comparison(rate=DEFAULT_RATE, duration=DURATION)

    print("\n" + comparison.report())

    baseline, audited = comparison.baseline, comparison.audited
    assert baseline.non_2xx() == 0, "the baseline arm did not serve cleanly"
    assert audited.non_2xx() == 0, "the audited arm did not serve cleanly"

    # The run has to have been a 100 rps run for its numbers to mean anything.
    assert audited.achieved_rps >= DEFAULT_RATE * 0.9, (
        f"the driver only achieved {audited.achieved_rps:.1f} rps; "
        "this is not a measurement of the middleware"
    )

    # NFR-3 / FR-19: overhead is not allowed to be bought with dropped documents.
    assert audited.metrics["audit_documents_dropped_total"] == 0.0
    assert audited.metrics["audit_documents_failed_total"] == 0.0
    assert audited.metrics["audit_middleware_errors_total"] == 0.0
    assert audited.metrics["audit_documents_submitted_total"] >= len(audited.samples)
    assert audited.bytes_written > 0, "the sink must actually have written the JSONL"

    delta = comparison.delta_ms()
    assert delta["p99"] <= P99_BUDGET_MS, (
        f"NFR-1: added p99 is {delta['p99']:.3f} ms, over the {P99_BUDGET_MS} ms budget "
        f"(baseline p99 {baseline.stats()['p99']:.3f} ms, "
        f"audited p99 {audited.stats()['p99']:.3f} ms)"
    )
