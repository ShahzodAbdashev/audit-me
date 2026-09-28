"""Where ``audit.emit()`` finds the sink — FROZEN for the build phase.

The middleware registers its sink, config and metrics on startup
(``set_active``); non-HTTP records written through :func:`audit.emit` go to
the same sink, so they land in the same file and the same index. Before any
middleware started, ``get_active()`` is ``None`` and emit counts a drop.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Active:
    sink: Any      # audit_logging.Sink
    config: Any    # audit_logging.AuditConfig
    metrics: Any   # audit_logging.Metrics


_active: Active | None = None


def set_active(sink: Any, config: Any, metrics: Any) -> None:
    global _active
    _active = Active(sink=sink, config=config, metrics=metrics)


def get_active() -> Active | None:
    return _active


def clear_active() -> None:
    global _active
    _active = None
