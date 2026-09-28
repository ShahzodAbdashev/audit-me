"""Turn a 0.1 document into a 0.2 document (FR-36, FR-53, FR-54). OWNER: agent D.

Adds exactly the paths in schema.ENRICHED_PATHS. Runs on the request path:
no I/O, bounded work. The caller (middleware) catches every exception and
keeps the 0.1 document (counted in audit_semantic_errors_total).
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from typing import Any, Sequence

from ..redact import REDACTED, normalize_key, redact
from .identifiers import normalize as normalize_identifier
from .model import (
    IDENTIFIER_TYPES,
    LEVEL_DERIVED,
    RESULT_DENIED,
    RESULT_DISCONNECTED,
    RESULT_FAILURE,
    RESULT_SUCCESS,
    SCHEMA_VERSION,
    AuditBag,
    Described,
    DiffEntry,
    placeholders_of,
)
from .proxies import Network, header_ids, resolve_client_ip
from .context import _MAX_TEXT
from .query import render_text
from .render import MAX_VALUE_LEN, outcome_suffix, render, template_for

_MAX_KEYWORD = 1024   # same bound document.py puts on user.* keywords
_MAX_DIFF = 100       # diff entries stored and rendered
_MAX_BAG_BYTES = 16 * 1024  # JSON size of detail / before / after as stored
_MAX_BAG_KEYS = 256         # distinct keys redact() may meet in one of them


def bounded(value: Any, keys: frozenset[str]) -> Any:
    """redact(value), or ``{"_truncated": True}`` when it has too many distinct keys
    or its JSON is over _MAX_BAG_BYTES. Never raises. Shared with emit()."""
    # ponytail: still one O(n) redact walk + dumps of what the app handed us; a
    # streaming size cutoff is the upgrade if apps put six-figure lists here.
    try:
        out = redact(value, keys, max_distinct_keys=_MAX_BAG_KEYS)
        if len(json.dumps(out, ensure_ascii=False, default=str)) <= _MAX_BAG_BYTES:
            return out
    except Exception:  # noqa: BLE001 - RedactionBudgetExceeded, or an unserialisable value
        pass
    return {"_truncated": True}


def result_of(status_code: int | None, outcome: str) -> str:
    """401/403 -> denied; outcome 'disconnected' -> disconnected; >=400 or failure -> failure; else success."""
    if status_code in (401, 403):
        return RESULT_DENIED
    if outcome == RESULT_DISCONNECTED:
        return RESULT_DISCONNECTED
    if outcome == RESULT_FAILURE or (status_code is not None and status_code >= 400):
        return RESULT_FAILURE
    return RESULT_SUCCESS


def _kw(value: Any) -> str | None:
    """A value fit for a ``keyword`` field, or None (FR-31 style)."""
    if value is None:
        return None
    if isinstance(value, str):
        return value[:_MAX_KEYWORD]
    if isinstance(value, (bool, int, float)):
        return str(value)
    try:
        text = json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    except Exception:
        text = str(value)
    return text[:_MAX_KEYWORD]


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _target_id(source: str | None, doc: dict[str, Any], bag: AuditBag | None,
               keys: frozenset[str] = frozenset()) -> str | None:
    if not source:
        return None
    where, _, name = source.partition(".")
    audit = _mapping(doc.get("audit"))
    if where == "path":
        value = _mapping(audit.get("path_params")).get(name)
    elif where == "query":
        value = _mapping(_mapping(audit.get("request")).get("query")).get(name)
        if isinstance(value, list):
            value = value[0] if value else None
    elif where == "detail" and bag is not None:
        # bag.detail is raw (path/query params were redacted by 0.1 already)
        value = REDACTED if normalize_key(name) in keys else redact(bag.detail.get(name), keys)
    else:
        return None
    return _kw(value)


def _redacted_diff(bag: AuditBag, keys: frozenset[str]) -> list[DiffEntry]:
    out: list[DiffEntry] = []
    for entry in bag.diff[:_MAX_DIFF]:
        field = str(entry.field)
        if normalize_key(field) in keys:
            old: Any = REDACTED if entry.old is not None else None
            new: Any = REDACTED if entry.new is not None else None
        else:
            old, new = _kw(redact(entry.old, keys)), _kw(redact(entry.new, keys))
        out.append(DiffEntry(field=field[:_MAX_KEYWORD], label=str(entry.label)[:_MAX_KEYWORD], old=old, new=new))
    return out


def _actor(doc: dict[str, Any]) -> str | None:
    user = _mapping(doc.get("user"))
    for key in ("full_name", "name", "id"):
        value = user.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _identifiers(target: dict[str, Any], spec_id: str | None, bag: AuditBag | None) -> dict[str, str]:
    """bag.identifiers, plus the target id itself when the target is an identifier
    (``type="pinpp"``, or ``TargetSpec(id="path.pinpp")``) and it normalises."""
    out = dict(bag.identifiers) if bag is not None else {}
    kind = target.get("type")
    if kind not in IDENTIFIER_TYPES:
        kind = (spec_id or "").partition(".")[2]
    if kind in IDENTIFIER_TYPES and kind not in out and target.get("id"):
        value = normalize_identifier(kind, target["id"])
        if value is not None:
            out[kind] = value
    return {k: v for k, v in out.items() if k in IDENTIFIER_TYPES}


def _query(bag: AuditBag, keys: frozenset[str]) -> dict[str, Any]:
    normalized: list[dict[str, Any]] = []
    text = bag.query_text
    secret = [normalize_key(str(c.field)) in keys for c in bag.query]
    if text and any(secret) and text == render_text(bag.query)[:_MAX_TEXT]:
        # The default rendering (audit.query() without text=) holds the raw values:
        # render it again from the redacted clauses. A caller's own text= is kept
        # as given (it cannot be redacted by field).
        text = render_text(
            dataclasses.replace(c, value=REDACTED) if s else c for c, s in zip(bag.query, secret)
        )[:_MAX_TEXT] or None
    for c in bag.query:
        entry: dict[str, Any] = {
            "field": c.field, "operator": c.operator,
            "value": REDACTED if normalize_key(str(c.field)) in keys else c.value,
            "logic": c.logic, "group": c.group,
        }
        if c.label:
            entry["label"] = c.label
        normalized.append(entry)
    out: dict[str, Any] = {
        "normalized": normalized,
        "text": text,
        "datasource": bag.query_datasource,
        "tables": list(bag.query_tables),
        "clause_count": len(normalized),
    }
    return {k: v for k, v in out.items() if v not in (None, [])} if normalized or text else {}


#: Route/query parameter names lifted into ``audit.context`` (FR-59).
_CONTEXT_KEYS: tuple[str, ...] = ("investigation_id", "profile_id")


def _context(audit: dict[str, Any]) -> dict[str, str]:
    """``audit.context`` from the path params, else the query string. Only a
    scalar value becomes the id: a list (``?investigation_id=a&investigation_id=b``)
    names no single folder, so it is not stored as one."""
    path = _mapping(audit.get("path_params"))
    query = _mapping(_mapping(audit.get("request")).get("query"))
    out: dict[str, str] = {}
    for key in _CONTEXT_KEYS:
        for source in (path, query):
            value = source.get(key)
            if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value):
                out[key] = str(value)[:_MAX_KEYWORD]
                break
    return out


def _transport(doc: dict[str, Any], audit: dict[str, Any],
               headers: Sequence[tuple[bytes, bytes]], trusted: tuple[Network, ...]) -> None:
    """audit.session.id, trace.id (only for X-Trace-Id), client.ip through trusted
    proxies + audit.client.*. Replaces, never mutates, the 0.1 ``trace``/``client``
    blocks: the middleware's copy of the 0.1 document shares them."""
    session, _ = header_ids(headers)
    if session:
        audit["session"] = {"id": session}
    _, trace = header_ids([(k, v) for k, v in headers if k == b"x-trace-id"])
    if trace:
        doc["trace"] = {**_mapping(doc.get("trace")), "id": trace}
    client = _mapping(doc.get("client"))
    peer = client.get("ip")
    if not isinstance(peer, str) or not peer:
        return
    resolved = resolve_client_ip(peer, headers, trusted)
    if resolved.ip and resolved.ip != peer:
        # The port belongs to the peer, not to the forwarded client.
        doc["client"] = {"ip": resolved.ip}
    block: dict[str, Any] = {"ip_source": resolved.source}
    if resolved.forwarded_chain:
        block["forwarded_chain"] = resolved.forwarded_chain[:_MAX_KEYWORD]
    audit["client"] = block


def enrich(
    doc: dict[str, Any],
    described: Described,
    bag: AuditBag | None,
    *,
    lang: str,
    service: str,
    redact_keys: frozenset[str],
    headers: Sequence[tuple[bytes, bytes]] = (),
    trusted: tuple[Network, ...] = (),
) -> dict[str, Any]:
    """Mutates and returns doc:
    event.id (uuid4 hex if absent), event.action = code (bag.code wins), message,
    audit.{schema_version, category, risk, sensitivity, derived, level, result,
    description, count, target, changes, detail, i18n}. Target id from
    TargetSpec.id ("path.x" -> doc audit.path_params, "query.x" -> audit.request.query,
    "detail.x" -> bag.detail) unless the bag set one. before/after/detail/diff values
    are passed through redact() with redact_keys. Actor for the sentence:
    user.full_name > user.name > user.id > MISSING word.
    Round 2: audit.target.<identifier>, audit.query.*, and from the raw ASGI
    ``headers``: audit.session.id, trace.id (X-Trace-Id only; 0.1 keeps
    X-Request-ID), client.ip via ``trusted`` proxies + audit.client.*."""
    event_def = described.event
    event = doc.setdefault("event", {})
    audit = doc.setdefault("audit", {})
    code = (bag.code if bag is not None else None) or event_def.code

    spec = event_def.target
    target = {
        "type": _kw(bag.target_type if bag is not None and bag.target_type else (spec.type if spec else None)),
        "id": _kw(bag.target_id) if bag is not None and bag.target_id else _target_id(spec.id if spec else None, doc, bag, redact_keys),
        "label": _kw(bag.target_label) if bag is not None else None,
    }
    target = {k: v for k, v in target.items() if v is not None}

    detail = bounded(bag.detail, redact_keys) if bag is not None and bag.detail else {}
    diff = _redacted_diff(bag, redact_keys) if bag is not None else []
    count = bag.count if bag is not None else None

    params: dict[str, Any] = {
        "actor": _actor(doc),
        "target": target.get("label") or target.get("id"),
        "count": count,
        "service": service,
        "object": target.get("type"),
        "detail": detail,
    }
    used: dict[str, str] = {}
    for name in sorted(placeholders_of(template_for(event_def, lang))):
        value = _mapping(detail).get(name[len("detail."):]) if name.startswith("detail.") else params.get(name)
        text = _kw(value)
        if text:
            used[name] = text[:MAX_VALUE_LEN]

    status = _mapping(_mapping(doc.get("http")).get("response")).get("status_code")
    event["id"] = event.get("id") or uuid.uuid4().hex
    event["action"] = code
    result = result_of(status if isinstance(status, int) else None, str(event.get("outcome", "")))
    doc["message"] = render(event_def, params, lang=lang, diff=diff) + outcome_suffix(result, lang)

    audit["schema_version"] = SCHEMA_VERSION
    audit["category"] = event_def.category
    audit["risk"] = event_def.risk
    audit["sensitivity"] = event_def.sensitivity
    audit["level"] = described.level
    audit["derived"] = described.level == LEVEL_DERIVED
    audit["result"] = result
    if event_def.description:
        audit["description"] = event_def.description
    if count is not None:
        audit["count"] = count
    identifiers = _identifiers(target, spec.id if spec else None, bag)
    if target or identifiers:
        audit["target"] = {**target, **identifiers}
    query = _query(bag, redact_keys) if bag is not None else {}
    if query:
        audit["query"] = query
    _transport(doc, audit, headers, trusted)
    context = _context(audit)
    if context:
        audit["context"] = context
    changes: dict[str, Any] = {}
    if diff:
        changes["diff"] = [
            {"field": d.field, "label": d.label, "old": d.old, "new": d.new} for d in diff
        ]
    if bag is not None and bag.before is not None:
        changes["before"] = bounded(bag.before, redact_keys)
    if bag is not None and bag.after is not None:
        changes["after"] = bounded(bag.after, redact_keys)
    if changes:
        audit["changes"] = changes
    if detail:
        audit["detail"] = detail
    audit["i18n"] = {"key": code, "params": used}
    return doc
