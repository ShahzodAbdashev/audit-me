"""Non-HTTP records: ``audit.emit()`` and ``@audited_task`` (FR-56). OWNER: agent F.

Records go to runtime.get_active().sink with the same schema as HTTP ones:
event.action = code, audit.level = "emit", no http/url blocks, service/host/process
as build_document does. No active middleware -> counted drop, never raises.
Typed identifiers (``identifiers=`` / ``audit.identify`` inside a task) land in
audit.target.<kind> as on HTTP records; session / trace / client ip are HTTP-only.
"""

from __future__ import annotations

import functools
import inspect
import logging
import os
import re
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, TypeVar, cast

from ..redact import DEFAULT_REDACT_KEYS, normalize_key
from . import context, render, runtime
from .context import audit as _audit
from .enrich import bounded
from .identifiers import normalize_all
from .model import (
    CODE_RE,
    DEFAULT_LANG,
    LEVEL_EMIT,
    RESULT_FAILURE,
    RESULT_SUCCESS,
    RESULTS,
    SCHEMA_VERSION,
    EventDef,
)

F = TypeVar("F", bound=Callable[..., Any])

METRIC_EMIT_DROPPED = "audit_emit_dropped_total"

_LOG = logging.getLogger("audit_logging")
#: Drops while no middleware is active (no Metrics to count them in yet).
dropped_without_sink = 0
_warned_without_sink = False

_HOSTNAME = socket.gethostname()
_MAX_FIELD = 1024
_MAX_ROLES = 64
_MAX_ERROR_MESSAGE = 1024
_MISSING = "noma'lum"
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")


def _kw(value: Any) -> str | None:
    """A value fit for a keyword field (same rule as document._coerce_keyword)."""
    if isinstance(value, str):
        return value[:_MAX_FIELD]
    if isinstance(value, (bool, int, float)):
        return str(value)[:_MAX_FIELD]
    return None


def _user_block(actor: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not actor:
        return None
    block: dict[str, Any] = {}
    for key in ("id", "name", "full_name", "department", "source"):
        value = _kw(actor.get(key))
        if value is not None:
            block[key] = value
    roles = actor.get("roles")
    if isinstance(roles, str):
        roles = [roles]
    if isinstance(roles, (list, tuple)):
        clean = [r for r in (_kw(x) for x in roles[:_MAX_ROLES]) if r is not None]
        if clean:
            block["roles"] = clean
    if isinstance(actor.get("verified"), bool):
        block["verified"] = actor["verified"]
    return block or None


def _target_block(target: Mapping[str, Any] | None) -> dict[str, str] | None:
    if not target:
        return None
    block = {k: v for k in ("type", "id", "label") if (v := _kw(target.get(k))) is not None}
    return block or None


def _fallback_render(template: str, params: Mapping[str, Any]) -> str:
    """Used only when render.render fails (e.g. not built yet): never leaves a brace."""
    detail = params.get("detail") or {}

    def one(m: re.Match[str]) -> str:
        name = m.group(1)
        value = detail.get(name[7:]) if name.startswith("detail.") else params.get(name)
        return _MISSING if value is None or value == "" else str(value)

    return _PLACEHOLDER.sub(one, template).replace("{", "").replace("}", "")


def _count_drop(active: runtime.Active | None, lost: bool = False) -> None:
    global dropped_without_sink, _warned_without_sink
    if active is None:
        dropped_without_sink += 1
        if not _warned_without_sink:
            _warned_without_sink = True
            _LOG.warning(
                "audit_logging: audit.emit() called with no active middleware (before startup "
                "or after shutdown); the record was dropped. Further drops are counted in "
                "audit_logging.semantic.emit.dropped_without_sink but not logged"
            )
        return
    try:
        active.metrics.inc(METRIC_EMIT_DROPPED)
        if lost:  # FR-39: never reached a sink, so nothing else counted it
            active.metrics.inc("audit_documents_lost_total")
    except Exception:  # noqa: BLE001 - metrics must never cost the caller
        pass


def _redact_keys(config: Any) -> frozenset[str]:
    extra = getattr(config, "extra_redact_keys", None) or ()
    return DEFAULT_REDACT_KEYS | frozenset(normalize_key(k) for k in extra)


def _emit(
    code: str,
    *,
    uz: str,
    category: str,
    risk: str,
    sensitivity: str,
    target: Mapping[str, Any] | None,
    detail: Mapping[str, Any] | None,
    actor: Mapping[str, Any] | None,
    result: str,
    count: int | None,
    error: BaseException | None = None,
    identifiers: Mapping[str, Any] | None = None,
) -> bool:
    active = runtime.get_active()
    try:
        if active is None:
            _count_drop(None)
            return False
        event = EventDef(
            code=code,
            templates={DEFAULT_LANG: uz},
            category=category,
            risk=risk,
            sensitivity=sensitivity,
            level=LEVEL_EMIT,
        )
        event.validate()
        if result not in RESULTS:
            raise ValueError(f"unknown result {result!r}")
        if count is not None and (isinstance(count, bool) or not isinstance(count, int)):
            raise ValueError("count must be an int")

        config = active.config
        service = str(getattr(config, "service_name", "") or "")
        user = _user_block(actor) or {}
        target_block: dict[str, str] = _target_block(target) or {}
        detail_in = dict(detail) if detail else {}
        if identifiers:
            accepted, rejected = normalize_all(identifiers)
            target_block.update(accepted)
            if rejected:
                detail_in["rejected_identifiers"] = rejected
        detail_block: dict[str, Any] = bounded(detail_in, _redact_keys(config)) if detail_in else {}

        params: dict[str, Any] = {
            "actor": user.get("full_name") or user.get("name") or user.get("id"),
            "target": target_block.get("label") or target_block.get("id"),
            "count": count,
            "service": service,
            "object": target_block.get("type"),
            "detail": detail_block,
        }
        try:
            message = render.render(event, params, lang=DEFAULT_LANG)
        except Exception:  # noqa: BLE001 - render unavailable or a bad value
            message = _fallback_render(uz, params)
        message += render.outcome_suffix(result, DEFAULT_LANG)

        audit_block: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "level": LEVEL_EMIT,
            "derived": False,
            "category": category,
            "risk": risk,
            "sensitivity": sensitivity,
            "result": result,
            "i18n": {
                "key": code,
                "params": {k: v for k, v in params.items() if k != "detail" and v is not None},
            },
        }
        if target_block:
            audit_block["target"] = target_block
        if detail_block:
            audit_block["detail"] = detail_block
        if count is not None:
            audit_block["count"] = count

        doc: dict[str, Any] = {
            "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
            "message": message,
            "event": {
                "kind": "event",
                "category": ["process"],
                "type": ["info"],
                "id": uuid.uuid4().hex,
                "action": code,
                "outcome": {RESULT_SUCCESS: "success", RESULT_FAILURE: "failure"}.get(result, "unknown"),
            },
            "service": {
                "name": service,
                "version": getattr(config, "service_version", None),
                "environment": getattr(config, "environment", None),
            },
            "host": {"hostname": _HOSTNAME},
            "process": {"pid": os.getpid()},
            "audit": audit_block,
        }
        dataset = getattr(config, "data_stream_dataset", None)
        if dataset:
            doc["data_stream"] = {
                "type": "logs",
                "dataset": dataset,
                "namespace": getattr(config, "data_stream_namespace", None),
            }
        if user:
            doc["user"] = user
        if error is not None:
            doc["error"] = {"type": type(error).__name__, "message": str(error)[:_MAX_ERROR_MESSAGE]}

        if active.sink.submit(doc):
            return True
        _count_drop(active)  # the sink counted the refusal as lost itself
        return False
    except Exception:  # noqa: BLE001 - emit never raises into the caller
        pass
    _count_drop(active, lost=True)
    return False


def emit(
    code: str,
    *,
    uz: str,
    category: str = "system",
    risk: str = "normal",
    sensitivity: str = "internal",
    target: Mapping[str, str] | None = None,     # {"type":..,"id":..,"label":..}
    detail: Mapping[str, Any] | None = None,
    actor: Mapping[str, Any] | None = None,      # user.* fields
    result: str = "success",
    count: int | None = None,
    identifiers: Mapping[str, Any] | None = None,  # {"pinpp": ..., "msisdn": ...}
) -> bool:
    """True when handed to the sink. Validates like EventDef; invalid -> False + counted."""
    return _emit(
        code, uz=uz, category=category, risk=risk, sensitivity=sensitivity,
        target=target, detail=detail, actor=actor, result=result, count=count,
        identifiers=identifiers,
    )


def _open() -> Any:
    try:
        return context.open_bag()
    except Exception:  # noqa: BLE001 - no bag is fine; the record still goes out
        return None


def _discard(token: Any) -> None:
    if token is not None:
        try:
            context.close_bag(token)
        except Exception:  # noqa: BLE001
            pass


def _finish(
    token: Any, code: str, uz: str, category: str, risk: str, error: BaseException | None
) -> None:
    """Read the bag the task filled, close it, emit. Never raises."""
    bag = None
    if token is not None:
        try:
            bag = context.current_bag()
        except Exception:  # noqa: BLE001
            bag = None
        try:
            context.close_bag(token)
        except Exception:  # noqa: BLE001
            pass
    target: dict[str, Any] | None = None
    detail: dict[str, Any] | None = None
    count: int | None = None
    identifiers: dict[str, str] | None = None
    if bag is not None:
        if bag.code and CODE_RE.fullmatch(bag.code):
            code = bag.code
        target = {"type": bag.target_type, "id": bag.target_id, "label": bag.target_label}
        detail = dict(bag.detail) or None
        count = bag.count
        identifiers = dict(bag.identifiers) or None
    _emit(
        code, uz=uz, category=category, risk=risk, sensitivity="internal",
        target=target, detail=detail, actor=None,
        result=RESULT_SUCCESS if error is None else RESULT_FAILURE,
        count=count, error=error, identifiers=identifiers,
    )


def audited_task(code: str, *, uz: str, category: str = "system", risk: str = "normal") -> Callable[[F], F]:
    """Wrap a sync or async function; emit one record when it finishes:
    result success, or failure with error.type/message on exception (re-raised).
    Handlers inside may use audit.target/detail/count (a bag is opened per call)."""
    # A bad declaration fails at import, like @audited.
    EventDef(code=code, templates={DEFAULT_LANG: uz}, category=category, risk=risk, level=LEVEL_EMIT).validate()

    async def finish_awaited(awaitable: Any) -> Any:
        token = _open()
        try:
            value = await awaitable
        except BaseException as exc:
            _finish(token, code, uz, category, risk, exc)
            raise
        _finish(token, code, uz, category, risk, None)
        return value

    def decorate(fn: F) -> F:
        if inspect.isasyncgenfunction(fn):
            raise TypeError("@audited_task cannot wrap an async generator: it would finish before any work ran")
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                token = _open()
                try:
                    value = await fn(*args, **kwargs)
                except BaseException as exc:
                    _finish(token, code, uz, category, risk, exc)
                    raise
                _finish(token, code, uz, category, risk, None)
                return value

            return cast(F, async_wrapper)

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            token = _open()
            try:
                value = fn(*args, **kwargs)
            except BaseException as exc:
                _finish(token, code, uz, category, risk, exc)
                raise
            if inspect.isawaitable(value):
                # A wrapper hid a coroutine function: the work has not run yet.
                _discard(token)
                return finish_awaited(value)
            _finish(token, code, uz, category, risk, None)
            return value

        return cast(F, sync_wrapper)

    return decorate


setattr(_audit, "emit", emit)
setattr(_audit, "task", audited_task)
