"""Browser events route for a service's OWN backend (FR-57). OWNER: agent F.

    app.include_router(ui_router(actor_resolver=my_resolver))

POST <prefix> body {"events": [{"code": "ui.page.viewed", "uz": "...", "detail": {...}}]}
(max 100). Only codes starting with "ui." are accepted (others -> 422). The actor is
taken ONLY from actor_resolver(request) — never from the body. Each event -> emit().
FastAPI is imported lazily; without it ui_router() raises ImportError with a hint.
"""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.requests import Request

from .context import audit as _audit
from .decorators import ATTRIBUTE
from .emit import emit
from .model import CODE_RE, LEVEL_DECORATOR, EventDef

MAX_EVENTS = 100
#: What a browser may claim; risk is never the browser's to set.
UI_CATEGORIES = ("navigation", "read", "search", "export")

#: The POST itself is described, so ``check coverage`` never lists it as derived.
_RECEIVED = EventDef(
    code="audit.ui_events.received",
    templates={"uz": "{actor} brauzer hodisalarini yubordi"},
    category="system",
    risk="low",
    level=LEVEL_DECORATOR,
)


class UIEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(max_length=128)
    uz: str = Field(min_length=1, max_length=512)
    category: str = "navigation"
    target: dict[str, str] | None = None
    detail: dict[str, Any] = Field(default_factory=dict, max_length=32)
    count: int | None = None

    @field_validator("code")
    @classmethod
    def _ui_code(cls, v: str) -> str:
        if not v.startswith("ui.") or not CODE_RE.fullmatch(v):
            raise ValueError("code must be ui.<object>.<verb>")
        return v

    @field_validator("category")
    @classmethod
    def _ui_category(cls, v: str) -> str:
        if v not in UI_CATEGORIES:
            raise ValueError(f"category must be one of {UI_CATEGORIES}")
        return v


class UIBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[UIEvent] = Field(max_length=MAX_EVENTS)


def ui_router(
    *,
    actor_resolver: Callable[[Any], dict[str, Any] | None],
    prefix: str = "/audit/ui-events",
) -> Any:
    try:
        from fastapi import APIRouter
    except ImportError as exc:
        raise ImportError("ui_router() needs FastAPI: pip install fastapi") from exc

    router = APIRouter()

    @router.post(prefix, status_code=202)
    def receive_ui_events(body: UIBatch, request: Request) -> dict[str, int]:
        try:
            actor = actor_resolver(request)
        except Exception:  # noqa: BLE001 - an unknown actor, never a body-supplied one
            actor = None
        accepted = sum(
            emit(
                e.code, uz=e.uz, category=e.category, risk="low",
                target=e.target, detail=e.detail, actor=actor, count=e.count,
            )
            for e in body.events
        )
        return {"received": len(body.events), "accepted": accepted}

    setattr(receive_ui_events, ATTRIBUTE, _RECEIVED)
    return router


setattr(_audit, "ui_router", ui_router)
