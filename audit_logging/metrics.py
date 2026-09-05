"""Metrics implementations.

Owned by **Agent A4**. Names are frozen in ``_contracts.METRIC_NAMES``.

Two implementations ship with the package:

``InMemoryMetrics``
    The default. A plain dict of ``name -> float``. Every name in
    :data:`~audit_logging._contracts.METRIC_NAMES` is pre-seeded to ``0.0`` so
    a caller can read a counter that has not fired yet, and any *unknown* name
    is auto-created on first use. Nothing here takes a lock: ``inc`` is on the
    request path and NFR-2 forbids locks there. Under CPython the worst case is
    a lost increment on a metric, never an exception.

``PrometheusMetrics``
    Behind the optional ``prometheus`` extra. ``prometheus_client`` is imported
    lazily inside ``__init__`` so importing this module never requires it.
    Only the frozen names are declared — ``*_total`` as counters, the rest as
    gauges — and an unknown name is **ignored**, because a Prometheus registry
    cannot grow a new time series safely at runtime.

Both obey the contract's one hard rule: ``inc``/``set`` never raise.
"""

from __future__ import annotations

from typing import Any

from ._contracts import METRIC_NAMES

__all__ = ["InMemoryMetrics", "PrometheusMetrics"]


class InMemoryMetrics:
    """Dict-backed default implementation of the ``Metrics`` protocol."""

    __slots__ = ("_values",)

    def __init__(self) -> None:
        self._values: dict[str, float] = dict.fromkeys(METRIC_NAMES, 0.0)

    def inc(self, name: str, value: int = 1) -> None:
        """Increment a counter. Unknown names are auto-created at ``0``."""
        try:
            self._values[name] = self._values.get(name, 0.0) + value
        except Exception:  # pragma: no cover - defensive, must never raise
            pass

    def set(self, name: str, value: float) -> None:
        """Set a gauge. Unknown names are auto-created."""
        try:
            self._values[name] = float(value)
        except Exception:  # pragma: no cover - defensive, must never raise
            pass

    def snapshot(self) -> dict[str, float]:
        """A copy of every metric, for tests and the runbook."""
        return dict(self._values)

    def get(self, name: str) -> float:
        """One metric's current value (``0.0`` if it was never touched)."""
        return self._values.get(name, 0.0)

    def reset(self) -> None:
        """Zero every known metric and forget unknown ones."""
        self._values = dict.fromkeys(METRIC_NAMES, 0.0)

    def __repr__(self) -> str:
        live = {k: v for k, v in self._values.items() if v}
        return f"InMemoryMetrics({live!r})"


class PrometheusMetrics:
    """``prometheus_client`` implementation using the frozen metric names.

    ``registry`` defaults to ``prometheus_client.REGISTRY``. Pass a fresh
    ``CollectorRegistry()`` when building more than one instance in a process
    (tests do), otherwise the default registry rejects the duplicate series.

    Raises ``ImportError`` from ``__init__`` when the extra is not installed;
    ``inc``/``set`` themselves never raise.
    """

    __slots__ = ("_counters", "_gauges", "registry")

    def __init__(self, registry: Any | None = None) -> None:
        try:
            import prometheus_client
        except ImportError as exc:  # pragma: no cover - depends on the env
            raise ImportError(
                "PrometheusMetrics needs the optional 'prometheus' extra: "
                "pip install audit-logging[prometheus]"
            ) from exc

        self.registry: Any = registry if registry is not None else prometheus_client.REGISTRY
        self._counters: dict[str, Any] = {}
        self._gauges: dict[str, Any] = {}

        for name in sorted(METRIC_NAMES):
            doc = f"audit_logging: {name}"
            if name.endswith("_total"):
                # prometheus_client appends the _total suffix itself.
                self._counters[name] = prometheus_client.Counter(
                    name.removesuffix("_total"), doc, registry=self.registry
                )
            else:
                self._gauges[name] = prometheus_client.Gauge(
                    name, doc, registry=self.registry
                )

    def inc(self, name: str, value: int = 1) -> None:
        """Increment a counter. Unknown names are ignored."""
        try:
            metric = self._counters.get(name)
            if metric is not None:
                metric.inc(value)
        except Exception:  # pragma: no cover - defensive, must never raise
            pass

    def set(self, name: str, value: float) -> None:
        """Set a gauge. Unknown names are ignored."""
        try:
            metric = self._gauges.get(name)
            if metric is not None:
                metric.set(value)
        except Exception:  # pragma: no cover - defensive, must never raise
            pass

    def snapshot(self) -> dict[str, float]:
        """Current values, in the same shape as ``InMemoryMetrics.snapshot``."""
        out: dict[str, float] = {}
        for name, metric in self._counters.items():
            out[name] = float(metric._value.get())  # noqa: SLF001
        for name, metric in self._gauges.items():
            out[name] = float(metric._value.get())  # noqa: SLF001
        return out
