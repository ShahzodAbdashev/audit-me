"""audit_logging — one JSONL audit document per API request.

The package captures requests at the raw ASGI layer, redacts them, and writes
them to a rotating file. It never talks to Elasticsearch; Filebeat ships the
files (D-13).

    from audit_logging import AuditConfig, AuditMiddleware, FileSink

    config = AuditConfig(service_name="orders-api")
    app.add_middleware(AuditMiddleware, config=config)
"""

from __future__ import annotations

from ._contracts import Metrics, RequestContext, Sink
from .config import AuditConfig
from .middleware import AuditMiddleware
from .sinks.file_sink import FileSink
from .semantic import EventDef, Target, TargetSpec, audit, audited
from .semantic.model import QueryClause
from .sinks.null_sink import NullSink

__version__ = "0.2.0.dev0"

__all__ = [
    "AuditConfig",
    "AuditMiddleware",
    "EventDef",
    "FileSink",
    "Metrics",
    "NullSink",
    "QueryClause",
    "RequestContext",
    "Sink",
    "Target",
    "TargetSpec",
    "__version__",
    "audit",
    "audited",
]
