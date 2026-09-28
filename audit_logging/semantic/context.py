"""Per-request bag + the public ``audit`` facade (FR-54). OWNER: agent C.

    from audit_logging import audit
    audit.target(label=db_user.full_name, id=str(user_id), type="user")
    audit.diff(before, after, labels={"role_id": "Rol"})
    audit.detail(permissions_added=[...])
    audit.count(len(rows))
    audit.code("admin.user.password_reset")   # override the described code
    audit.identify(pinpp="3210 1801 2345 67", msisdn="90 123 45 67")
    audit.query([("region", "=", "Toshkent"), ("age", "between", [18, 30])],
                datasource="pg", tables=["persons"], labels={"region": "Viloyat"})

Every facade method is total: outside a request (no bag) it does nothing and
returns None; it never raises into the handler.
"""

from __future__ import annotations

import itertools
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from .identifiers import normalize_all
from .model import CODE_RE, AuditBag, DiffEntry
from .query import normalize_clauses, render_text

if TYPE_CHECKING:  # the real objects are attached at import by emit.py / ui.py
    from .emit import audited_task as _audited_task
    from .emit import emit as _emit
    from .ui import ui_router as _ui_router

_MAX_TEXT = 4096     # audit.query.text
_MAX_TABLES = 32
_MAX_NAME = 256

_BAG: ContextVar[AuditBag | None] = ContextVar("audit_logging_bag", default=None)


def open_bag() -> Token[AuditBag | None]:
    """Middleware: set a fresh AuditBag for this request; returns the reset token."""
    return _BAG.set(AuditBag())


def current_bag() -> AuditBag | None:
    return _BAG.get()


def close_bag(token: Token[AuditBag | None]) -> None:
    """Middleware: restore the previous value. Never raises."""
    try:
        _BAG.reset(token)
    except Exception:  # token from another context or already used
        try:
            _BAG.set(None)
        except Exception:
            pass


def _differs(old: Any, new: Any) -> bool:
    try:
        return bool(old != new)
    except Exception:  # e.g. objects whose __eq__ raises or is ambiguous
        return old is not new


def compute_diff(
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any] | None,
    labels: Mapping[str, str] | None = None,
) -> list[DiffEntry]:
    """Changed keys only (added/removed/changed), sorted by field; label falls back
    to the field name. Values kept as-is (redaction happens in enrich)."""
    b = before or {}
    a = after or {}
    names = labels or {}
    out: list[DiffEntry] = []
    for key in sorted({*b, *a}, key=str):
        old, new = b.get(key), a.get(key)
        if _differs(old, new):
            out.append(DiffEntry(field=key, label=names.get(key) or key, old=old, new=new))
    return out


class _Audit:
    """The ``audit`` facade. Every method is total: no bag -> no-op; never raises.

    No ``__slots__``: emit.py / ui.py attach ``emit``, ``task``, ``ui_router``.
    They are declared here for type checkers only, so ``audit.emit(...)`` passes
    ``mypy --strict`` in user code.
    """

    if TYPE_CHECKING:
        emit = staticmethod(_emit)
        task = staticmethod(_audited_task)
        ui_router = staticmethod(_ui_router)

    def target(self, *, label: str | None = None, id: str | None = None, type: str | None = None) -> None:
        try:
            bag = _BAG.get()
            if bag is None:
                return
            if label is not None:
                bag.target_label = str(label)
            if id is not None:
                bag.target_id = str(id)
            if type is not None:
                bag.target_type = str(type)
        except Exception:
            pass

    def diff(self, before: Mapping[str, Any] | None, after: Mapping[str, Any] | None,
             labels: Mapping[str, str] | None = None) -> None:
        try:
            bag = _BAG.get()
            if bag is None:
                return
            bag.diff = compute_diff(before, after, labels)
            bag.before = dict(before) if before is not None else None
            bag.after = dict(after) if after is not None else None
        except Exception:
            pass

    def detail(self, **values: Any) -> None:
        try:
            bag = _BAG.get()
            if bag is not None:
                bag.detail.update(values)
        except Exception:
            pass

    def count(self, n: int) -> None:
        try:
            bag = _BAG.get()
            if bag is not None and isinstance(n, int) and not isinstance(n, bool):
                bag.count = n
        except Exception:
            pass

    def code(self, code: str) -> None:
        try:
            bag = _BAG.get()
            if bag is not None and isinstance(code, str) and CODE_RE.fullmatch(code):
                bag.code = code
        except Exception:
            pass
    def identify(self, **kinds: Any) -> None:
        """Typed identifiers of the target (``pinpp``, ``msisdn``, ``passport``, ``imei``)
        -> ``audit.target.<kind>``. Invalid ones are listed in
        ``audit.detail.rejected_identifiers`` instead."""
        try:
            bag = _BAG.get()
            if bag is None:
                return
            accepted, rejected = normalize_all(kinds)
            bag.identifiers.update(accepted)
            if rejected:
                seen = bag.detail.setdefault("rejected_identifiers", [])
                if isinstance(seen, list):
                    seen.extend(k for k in rejected if k not in seen)
        except Exception:
            pass

    def query(self, clauses: Iterable[Any], *, text: str | None = None,
              datasource: str | None = None, tables: Iterable[str] | None = None,
              labels: Mapping[str, str] | None = None) -> None:
        """The search the handler ran -> ``audit.query.*``. ``text`` defaults to the
        rendered clauses (``"Viloyat = Toshkent VA ..."``). Replaces an earlier call."""
        try:
            bag = _BAG.get()
            if bag is None:
                return
            kept, _dropped = normalize_clauses(clauses, labels)
            bag.query = kept
            bag.query_text = (str(text) if text is not None else render_text(kept))[:_MAX_TEXT] or None
            bag.query_datasource = str(datasource)[:_MAX_NAME] if datasource is not None else None
            if isinstance(tables, str):
                tables = [tables]
            bag.query_tables = (
                [str(t)[:_MAX_NAME] for t in itertools.islice(tables, _MAX_TABLES)] if tables else []
            )
        except Exception:
            pass
    # emit / task / ui_router are attached by emit.py and ui.py (agent F)


audit = _Audit()
