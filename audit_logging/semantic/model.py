"""Semantic layer contracts (0.2) — FROZEN for the build phase.

Every other ``semantic`` module builds against the names in this file. Change
them only through the orchestrator (PLAN-semantic-audit.md §12).

One event definition (:class:`EventDef`) answers "what did this request mean":
its code, its sentence templates, and how risky / sensitive it is. It comes from
one of three levels, first match wins (FR-50):

``decorator``  ``@audited(...)`` on the handler (``fn.__audit__``)
``catalog``    the service's catalog file, keyed by (METHOD, route template)
``derived``    built from the route itself; never "unknown"
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from typing import Any, Mapping

# ---------------------------------------------------------------------------
# Vocabularies. Nothing else is legal.
# ---------------------------------------------------------------------------

CATEGORIES: tuple[str, ...] = (
    "auth", "read", "search", "write", "export",
    "analysis", "navigation", "admin", "system",
)
RISKS: tuple[str, ...] = ("low", "normal", "high", "critical")
SENSITIVITIES: tuple[str, ...] = ("public", "internal", "confidential", "secret")

#: ``audit.result`` — the user-facing outcome. ``event.outcome`` (ECS, 0.1)
#: is left exactly as it was; this field adds the ``denied`` distinction.
RESULT_SUCCESS = "success"
RESULT_FAILURE = "failure"
RESULT_DENIED = "denied"
RESULT_DISCONNECTED = "disconnected"
RESULTS: tuple[str, ...] = (RESULT_SUCCESS, RESULT_FAILURE, RESULT_DENIED, RESULT_DISCONNECTED)

LEVEL_DECORATOR = "decorator"
LEVEL_CATALOG = "catalog"
LEVEL_DERIVED = "derived"
LEVEL_EMIT = "emit"  # non-HTTP records written through audit.emit()
LEVELS: tuple[str, ...] = (LEVEL_DECORATOR, LEVEL_CATALOG, LEVEL_DERIVED, LEVEL_EMIT)

#: ``audit.schema_version`` written on every 0.2 document (FR-48).
SCHEMA_VERSION = "2"

#: ``<domain>.<object>.<verb>``, snake_case, past-tense verb by convention.
CODE_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$")

#: Placeholders a template may use. ``{detail.<key>}`` is also allowed.
PLACEHOLDERS: frozenset[str] = frozenset({"actor", "target", "count", "service", "object"})

#: Where a target id may be read from (``TargetSpec.id``).
TARGET_SOURCES: tuple[str, ...] = ("path", "query", "detail")

#: Typed identifiers promoted to ``audit.target.<type>`` (PLAN §17, parity with
#: audit v2 target.pinpp / msisdn / passport / imei).
IDENTIFIER_TYPES: tuple[str, ...] = ("pinpp", "msisdn", "passport", "imei")

#: ``audit.query.normalized[].operator`` vocabulary.
QUERY_OPERATORS: tuple[str, ...] = (
    "eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in",
    "contains", "starts_with", "ends_with", "between", "exists", "match",
)

#: ``audit.client.ip_source``.
IP_SOURCES: tuple[str, ...] = ("x_forwarded_for", "x_real_ip", "peer")

#: ECS ``tags`` values this package may add.
TAG_CLOCK_SKEW = "clock_skew"
TAG_ENRICH_TIMEOUT = "enrich_timeout"

#: The only default language; others are optional overlays (X-4).
DEFAULT_LANG = "uz"


def placeholders_of(template: str) -> set[str]:
    """Field names used by a ``str.format`` template (``"{a} {b.c}"`` -> {a, b.c})."""
    names: set[str] = set()
    for _, name, _, _ in string.Formatter().parse(template):
        if name is not None and name != "":
            names.add(name)
    return names


def _check_template(template: str) -> None:
    for name in placeholders_of(template):
        if name in PLACEHOLDERS:
            continue
        if name.startswith("detail.") and len(name) > len("detail."):
            continue
        raise ValueError(f"unknown placeholder {{{name}}} in template {template!r}")


# ---------------------------------------------------------------------------
# Definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetSpec:
    """What the action was performed on.

    ``type`` is a short noun (``user``, ``profile``, ``phone``).
    ``id`` says where the id comes from: ``"path.<name>"``, ``"query.<name>"``
    or ``"detail.<key>"`` — or ``None`` when only the handler knows it
    (``audit.target(id=...)``).
    """

    type: str
    id: str | None = None

    def validate(self) -> None:
        if not self.type or not re.fullmatch(r"[a-z][a-z0-9_]*", self.type):
            raise ValueError(f"target type must be snake_case: {self.type!r}")
        if self.id is not None:
            source, _, name = self.id.partition(".")
            if source not in TARGET_SOURCES or not name:
                raise ValueError(
                    f"target id must be 'path.<name>', 'query.<name>' or 'detail.<key>': {self.id!r}"
                )


@dataclass(frozen=True)
class EventDef:
    """The meaning of one endpoint (or one non-HTTP action)."""

    code: str
    templates: Mapping[str, str]          # lang -> template; DEFAULT_LANG required
    category: str
    risk: str
    sensitivity: str = "internal"
    target: TargetSpec | None = None
    diff: bool = False                    # handler is expected to call audit.diff()
    description: str | None = None        # route summary / docstring, for the viewer
    level: str = LEVEL_DECORATOR

    def validate(self) -> None:
        """Raise ``ValueError`` on anything a stored record could not carry."""
        if not CODE_RE.fullmatch(self.code):
            raise ValueError(f"code must be <domain>.<object>.<verb>: {self.code!r}")
        if DEFAULT_LANG not in self.templates or not self.templates[DEFAULT_LANG].strip():
            raise ValueError(f"{self.code}: a '{DEFAULT_LANG}' template is required")
        for template in self.templates.values():
            _check_template(template)
        if self.category not in CATEGORIES:
            raise ValueError(f"{self.code}: unknown category {self.category!r}")
        if self.risk not in RISKS:
            raise ValueError(f"{self.code}: unknown risk {self.risk!r}")
        if self.sensitivity not in SENSITIVITIES:
            raise ValueError(f"{self.code}: unknown sensitivity {self.sensitivity!r}")
        if self.level not in LEVELS:
            raise ValueError(f"{self.code}: unknown level {self.level!r}")
        if self.target is not None:
            self.target.validate()


@dataclass(frozen=True)
class DiffEntry:
    """One changed field, as stored in ``audit.changes.diff``."""

    field: str
    label: str
    old: Any
    new: Any


@dataclass
class AuditBag:
    """What a handler added during the request (``audit.target()``, ...).

    One fresh bag per request, held in a ``ContextVar`` (see ``context.py``).
    Mutable on purpose: a sync handler runs in a threadpool with a *copied*
    context, and mutating the same object is what makes its writes visible.
    """

    target_type: str | None = None
    target_id: str | None = None
    target_label: str | None = None
    code: str | None = None               # handler override; must be a known EventDef? no: any valid code
    count: int | None = None              # {count}, e.g. rows returned or exported
    diff: list[DiffEntry] = field(default_factory=list)
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    # 0.2 round 2 (PLAN §17) ------------------------------------------------
    #: typed identifiers of the target, already normalised by identifiers.py
    #: (keys are IDENTIFIER_TYPES; values are canonical strings)
    identifiers: dict[str, str] = field(default_factory=dict)
    #: normalised query clauses (audit.query(...)); see QueryClause
    query: list["QueryClause"] = field(default_factory=list)
    query_text: str | None = None
    query_datasource: str | None = None
    query_tables: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class QueryClause:
    """One search condition, stored in ``audit.query.normalized`` (nested)."""

    field: str
    operator: str               # one of QUERY_OPERATORS
    value: Any
    label: str | None = None    # human label of the field
    logic: str = "and"          # "and" | "or"
    group: int = 0              # clauses with the same group were combined together


@dataclass(frozen=True)
class Described:
    """Result of describing one request: the definition and where it came from."""

    event: EventDef
    level: str
