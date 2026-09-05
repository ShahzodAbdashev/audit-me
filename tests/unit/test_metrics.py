"""Unit tests for ``audit_logging.metrics`` (Agent A4).

Covers the ``Metrics`` protocol contract from ``_contracts`` §6.7: the frozen
names, the "never raise" rule, and the two implementations' differing policies
for names that are not in ``METRIC_NAMES``.
"""

from __future__ import annotations

import math
from typing import Any

import pytest

from audit_logging._contracts import METRIC_NAMES, Metrics
from audit_logging.metrics import InMemoryMetrics, PrometheusMetrics

# ---------------------------------------------------------------------------
# InMemoryMetrics
# ---------------------------------------------------------------------------


def test_in_memory_satisfies_the_metrics_protocol() -> None:
    assert isinstance(InMemoryMetrics(), Metrics)


def test_in_memory_pre_seeds_every_frozen_name_at_zero() -> None:
    snap = InMemoryMetrics().snapshot()
    assert set(snap) == set(METRIC_NAMES)
    assert set(snap.values()) == {0.0}


def test_in_memory_inc_defaults_to_one_and_accumulates() -> None:
    m = InMemoryMetrics()
    m.inc("audit_documents_submitted_total")
    m.inc("audit_documents_submitted_total")
    m.inc("audit_documents_submitted_total", 5)
    assert m.get("audit_documents_submitted_total") == 7.0


def test_in_memory_set_replaces_rather_than_accumulates() -> None:
    m = InMemoryMetrics()
    m.set("audit_queue_bytes", 100)
    m.set("audit_queue_bytes", 42)
    assert m.get("audit_queue_bytes") == 42.0


def test_in_memory_snapshot_is_a_copy() -> None:
    m = InMemoryMetrics()
    snap = m.snapshot()
    snap["audit_queue_bytes"] = 999.0
    assert m.get("audit_queue_bytes") == 0.0


def test_in_memory_reset_returns_to_the_seeded_state() -> None:
    m = InMemoryMetrics()
    m.inc("audit_documents_dropped_total", 3)
    m.set("something_unknown", 1)
    m.reset()
    assert m.snapshot() == dict.fromkeys(METRIC_NAMES, 0.0)


def test_in_memory_auto_creates_unknown_names() -> None:
    """Policy: InMemoryMetrics is permissive — unknown names are created."""
    m = InMemoryMetrics()
    m.inc("not_a_frozen_name_total", 2)
    m.set("also_not_frozen", 1.5)
    assert m.get("not_a_frozen_name_total") == 2.0
    assert m.get("also_not_frozen") == 1.5


def test_in_memory_get_of_an_untouched_name_is_zero() -> None:
    assert InMemoryMetrics().get("never_seen_before") == 0.0


@pytest.mark.parametrize(
    "name, value",
    [
        (None, 1),
        (object(), 1),
        (["unhashable"], 1),
        ("audit_queue_bytes", "not-a-number"),
        ("audit_queue_bytes", None),
        ("audit_documents_dropped_total", object()),
    ],
)
def test_in_memory_never_raises_on_junk_input(name: Any, value: Any) -> None:
    """NFR-3 / §6.7: 'Implementations must never raise'."""
    m = InMemoryMetrics()
    m.inc(name, value)
    m.set(name, value)


def test_in_memory_accepts_non_finite_gauge_values() -> None:
    m = InMemoryMetrics()
    m.set("audit_flush_seconds", float("nan"))
    assert math.isnan(m.get("audit_flush_seconds"))


def test_in_memory_repr_shows_only_live_metrics() -> None:
    m = InMemoryMetrics()
    m.inc("audit_documents_submitted_total")
    text = repr(m)
    assert "audit_documents_submitted_total" in text
    assert "audit_file_rotations_total" not in text


# ---------------------------------------------------------------------------
# PrometheusMetrics
# ---------------------------------------------------------------------------

prometheus_client = pytest.importorskip("prometheus_client")


@pytest.fixture
def registry() -> Any:
    """A private registry, so instances do not collide on the default one."""
    return prometheus_client.CollectorRegistry()


def test_prometheus_satisfies_the_metrics_protocol(registry: Any) -> None:
    assert isinstance(PrometheusMetrics(registry), Metrics)


def test_prometheus_exposes_exactly_the_frozen_names(registry: Any) -> None:
    PrometheusMetrics(registry)
    exposed = {
        sample.name
        for metric in registry.collect()
        for sample in metric.samples
        if not sample.name.endswith("_created")
    }
    assert exposed == set(METRIC_NAMES)


def test_prometheus_uses_counters_for_total_and_gauges_for_the_rest(
    registry: Any,
) -> None:
    PrometheusMetrics(registry)
    kinds = {}
    for metric in registry.collect():
        for sample in metric.samples:
            if not sample.name.endswith("_created"):
                kinds[sample.name] = metric.type
    for name in METRIC_NAMES:
        expected = "counter" if name.endswith("_total") else "gauge"
        assert kinds[name] == expected, name


def test_prometheus_inc_and_set_reach_the_registry(registry: Any) -> None:
    m = PrometheusMetrics(registry)
    m.inc("audit_documents_dropped_total", 3)
    m.set("audit_queue_bytes", 2048)
    assert registry.get_sample_value("audit_documents_dropped_total") == 3.0
    assert registry.get_sample_value("audit_queue_bytes") == 2048.0


def test_prometheus_snapshot_matches_the_in_memory_shape(registry: Any) -> None:
    m = PrometheusMetrics(registry)
    m.inc("audit_file_rotations_total")
    snap = m.snapshot()
    assert set(snap) == set(METRIC_NAMES)
    assert snap["audit_file_rotations_total"] == 1.0


def test_prometheus_ignores_unknown_names_without_raising(registry: Any) -> None:
    """Policy: a Prometheus registry cannot grow series at runtime, so unknown
    names are silently ignored rather than auto-created."""
    m = PrometheusMetrics(registry)
    m.inc("not_a_frozen_name_total")
    m.set("also_not_frozen", 1.0)
    assert registry.get_sample_value("not_a_frozen_name_total") is None
    assert registry.get_sample_value("also_not_frozen") is None


@pytest.mark.parametrize(
    "name, value",
    [
        (None, 1),
        (object(), 1),
        (["unhashable"], 1),
        ("audit_queue_bytes", "not-a-number"),
        ("audit_documents_dropped_total", None),
    ],
)
def test_prometheus_never_raises_on_junk_input(
    registry: Any, name: Any, value: Any
) -> None:
    m = PrometheusMetrics(registry)
    m.inc(name, value)
    m.set(name, value)


def test_prometheus_counters_reject_nothing_into_the_caller(registry: Any) -> None:
    """A negative increment is illegal in Prometheus; it must be swallowed."""
    m = PrometheusMetrics(registry)
    m.inc("audit_documents_dropped_total", -1)
    assert registry.get_sample_value("audit_documents_dropped_total") == 0.0


def test_prometheus_import_is_lazy() -> None:
    """Importing metrics.py must not require the optional extra (NFR-6)."""
    import audit_logging.metrics as metrics_module

    source = metrics_module.__file__
    assert source is not None
    with open(source, encoding="utf-8") as handle:
        head = handle.read().split("class PrometheusMetrics", 1)[0]
    assert "import prometheus_client" not in head


# ---------------------------------------------------------------------------
# N-8 — the post-close drop counter, now a first-class metric name
# ---------------------------------------------------------------------------

POST_CLOSE = "audit_documents_dropped_after_close_total"


def test_N_8_the_post_close_counter_is_a_frozen_name() -> None:
    """The orchestrator added this name to the frozen `METRIC_NAMES` after the
    review, so shutdown-window drops no longer ride on an implementation's
    unknown-name policy. They are distinct from ordinary drops: this counter
    means "shutdown was too short", not "disk is not keeping up"."""
    assert POST_CLOSE in METRIC_NAMES


def test_N_8_in_memory_records_the_post_close_counter() -> None:
    m = InMemoryMetrics()
    m.inc(POST_CLOSE, 5)
    assert m.get(POST_CLOSE) == 5.0
    assert m.snapshot()[POST_CLOSE] == 5.0


def test_N_8_prometheus_now_exposes_the_post_close_counter(registry: Any) -> None:
    """Now that the name is frozen, the Prometheus path builds a series for it,
    so an operator can see shutdown-window loss on the dashboard rather than
    only in `InMemoryMetrics`."""
    m = PrometheusMetrics(registry)
    m.inc(POST_CLOSE)
    assert registry.get_sample_value(POST_CLOSE) == 1.0
