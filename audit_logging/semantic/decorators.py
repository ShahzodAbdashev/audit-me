"""``@audited`` — Level 1 description (FR-50, FR-51). OWNER: agent A."""

from __future__ import annotations

from typing import Any, Callable, TypeVar

from .model import LEVEL_DECORATOR, EventDef, TargetSpec

F = TypeVar("F", bound=Callable[..., Any])

#: Attribute set on the handler. Read by ``describe.describe`` via scope["route"].endpoint.
ATTRIBUTE = "__audit__"


def audited(
    code: str,
    *,
    uz: str,
    ru: str | None = None,
    en: str | None = None,
    category: str,
    risk: str,
    sensitivity: str = "internal",
    target: TargetSpec | None = None,
    diff: bool = False,
    description: str | None = None,
) -> Callable[[F], F]:
    """Attach an :class:`EventDef` (level ``decorator``) to a handler.

    Must NOT wrap: set ``fn.__audit__`` and return ``fn`` itself, so FastAPI's
    signature inspection, dependencies and OpenAPI are untouched (FR-51).
    Validates eagerly (``EventDef.validate``): a bad declaration raises
    ``ValueError`` at import time.
    """
    templates = {lang: text for lang, text in (("uz", uz), ("ru", ru), ("en", en)) if text is not None}
    event = EventDef(
        code=code, templates=templates, category=category, risk=risk,
        sensitivity=sensitivity, target=target, diff=diff,
        description=description, level=LEVEL_DECORATOR,
    )
    event.validate()

    def attach(fn: F) -> F:
        setattr(fn, ATTRIBUTE, event)
        return fn

    return attach


def event_def_of(endpoint: Any) -> EventDef | None:
    """The EventDef attached by :func:`audited`, or None. Never raises."""
    try:
        event = getattr(endpoint, ATTRIBUTE, None)
    except Exception:
        return None
    return event if isinstance(event, EventDef) else None
