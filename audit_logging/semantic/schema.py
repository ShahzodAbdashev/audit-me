"""Schema v2 additions — FROZEN for the build phase (FR-48).

The single source for the new fields: ``templates.py`` merges
:data:`MAPPING_ADDITIONS` into the index template, and ``enrich.py`` must only
produce fields declared here. A test walks an enriched document against the
merged mapping, so the two cannot drift.

Naming follows ECS where ECS has the field (``message``, ``event.action``,
``event.id``, ``event.ingested``, ``user.full_name``); everything audit-specific
lives under ``audit.``.
"""

from __future__ import annotations

from typing import Any

_KW: dict[str, Any] = {"type": "keyword", "ignore_above": 256}
_TEXT_KW: dict[str, Any] = {
    "type": "text",
    "fields": {"keyword": {"type": "keyword", "ignore_above": 512}},
}
_STORED: dict[str, Any] = {"type": "object", "dynamic": False, "enabled": False}

#: Merged into ``INDEX_TEMPLATE["template"]["mappings"]["properties"]``.
#: Keys that already exist (``event``, ``user``, ``audit``) are merged field by
#: field, never replaced.
MAPPING_ADDITIONS: dict[str, Any] = {
    # The finished sentence (ECS `message`) — what a person reads.
    "message": _TEXT_KW,
    "event": {
        "properties": {
            "id": _KW,               # UUID4, also the ES _id (FR-36)
            "ingested": {"type": "date"},  # set by the shipper (FR-41)
            # `event.action` already exists (keyword); 0.2 writes the code there.
        }
    },
    "user": {
        "properties": {
            "full_name": _TEXT_KW,
            "department": _KW,
            "verified": {"type": "boolean"},   # FR-40
            "source": _KW,                     # jwt | header | service | none
        }
    },
    "audit": {
        "properties": {
            "schema_version": _KW,
            "category": _KW,
            "risk": _KW,
            "sensitivity": _KW,
            "derived": {"type": "boolean"},
            "level": _KW,                      # decorator | catalog | derived | emit
            "result": _KW,                     # success | failure | denied | disconnected
            "description": {"type": "text"},
            "count": {"type": "long"},
            "target": {
                "dynamic": False,
                "properties": {"type": _KW, "id": _KW, "label": _TEXT_KW},
            },
            "changes": {
                "dynamic": False,
                "properties": {
                    "diff": {
                        "type": "nested",
                        "dynamic": False,
                        "properties": {
                            "field": _KW,
                            "label": _KW,
                            "old": _KW,
                            "new": _KW,
                        },
                    },
                    "before": _STORED,
                    "after": _STORED,
                },
            },
            "detail": _STORED,
            "i18n": {
                "dynamic": False,
                "properties": {"key": _KW, "params": _STORED},
            },
            # --- round 2 (PLAN §17) ----------------------------------------
            "session": {"dynamic": False, "properties": {"id": _KW}},
            "client": {
                "dynamic": False,
                "properties": {"ip_source": _KW, "forwarded_chain": _KW},
            },
            "query": {
                "dynamic": False,
                "properties": {
                    "normalized": {
                        "type": "nested",
                        "dynamic": False,
                        "properties": {
                            "field": _KW, "label": _KW, "operator": _KW,
                            "value": _KW, "logic": _KW, "group": {"type": "integer"},
                        },
                    },
                    "text": {"type": "text"},
                    "datasource": _KW,
                    "tables": _KW,
                    "clause_count": {"type": "integer"},
                },
            },
            "clock_skew_ms": {"type": "long"},
            # FR-59: the folder a request touched, for investigation-scoped reads
            "context": {
                "dynamic": False,
                "properties": {"investigation_id": _KW, "profile_id": _KW},
            },
            "integrity": {
                "dynamic": False,
                "properties": {
                    "chain": _KW,          # "<service>-<pid>-<start>" one chain per process
                    "seq": {"type": "long"},
                    "prev_hash": _KW,
                    "hash": _KW,
                },
            },
        }
    },
    # ECS `tags` (keyword array): clock_skew, enrich_timeout, ...
    "tags": _KW,
}

# Typed identifiers under audit.target (parity with audit v2).
MAPPING_ADDITIONS["audit"]["properties"]["target"]["properties"].update(
    {"pinpp": _KW, "msisdn": _KW, "passport": _KW, "imei": _KW}
)
# Client IP chosen through trusted proxies replaces 0.1 client.ip (ECS ip type
# already mapped); nothing new needed under ECS `client`.

#: Every leaf path an enriched document may set (dotted). Used by the drift test.
ENRICHED_PATHS: frozenset[str] = frozenset({
    "message",
    "event.id", "event.action", "event.ingested",
    "user.id", "user.name", "user.roles", "user.full_name", "user.department",
    "user.verified", "user.source",
    "audit.schema_version", "audit.category", "audit.risk", "audit.sensitivity",
    "audit.derived", "audit.level", "audit.result", "audit.description", "audit.count",
    "audit.target.type", "audit.target.id", "audit.target.label",
    "audit.changes.diff", "audit.changes.before", "audit.changes.after",
    "audit.detail",
    "audit.i18n.key", "audit.i18n.params",
    # round 2
    "audit.target.pinpp", "audit.target.msisdn", "audit.target.passport", "audit.target.imei",
    "audit.session.id",
    "audit.client.ip_source", "audit.client.forwarded_chain", "client.ip",
    "audit.query.normalized", "audit.query.text", "audit.query.datasource",
    "audit.query.tables", "audit.query.clause_count",
    "audit.clock_skew_ms",
    "audit.integrity.chain", "audit.integrity.seq", "audit.integrity.prev_hash",
    "audit.integrity.hash",
    "trace.id", "tags",
    "audit.context.investigation_id", "audit.context.profile_id",
})
