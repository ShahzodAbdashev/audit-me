"""``@audited`` and ``event_def_of`` (FR-50, FR-51). Owned by agent A."""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from audit_logging.semantic.decorators import ATTRIBUTE, audited, event_def_of
from audit_logging.semantic.model import LEVEL_DECORATOR, EventDef, TargetSpec


def _handler(user_id: int, q: str | None = None, *, limit: int = 10) -> dict[str, int]:
    return {"id": user_id}


def test_FR_51_decorator_returns_same_function_object() -> None:
    before = inspect.signature(_handler)
    decorated = audited(
        "admin.user.updated",
        uz="{actor} «{target}» foydalanuvchisini tahrirladi",
        ru="{actor} изменил {target}",
        category="admin",
        risk="high",
        target=TargetSpec("user", id="path.user_id"),
        diff=True,
    )(_handler)
    assert decorated is _handler
    assert inspect.signature(decorated) == before
    assert not hasattr(decorated, "__wrapped__")


async def test_FR_51_async_handler_stays_coroutine() -> None:
    async def handler(user_id: int) -> int:
        return user_id

    decorated = audited("admin.user.viewed", uz="{actor} ko'rdi", category="read", risk="low")(handler)
    assert decorated is handler
    assert inspect.iscoroutinefunction(decorated)
    assert await decorated(3) == 3


def test_FR_50_event_def_attached_with_decorator_level() -> None:
    @audited("admin.user.deleted", uz="{actor} o'chirdi", en="{actor} deleted", category="admin", risk="critical")
    def handler() -> None: ...

    event = event_def_of(handler)
    assert event is getattr(handler, ATTRIBUTE)
    assert event == EventDef(
        code="admin.user.deleted",
        templates={"uz": "{actor} o'chirdi", "en": "{actor} deleted"},
        category="admin",
        risk="critical",
        level=LEVEL_DECORATOR,
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"code": "Admin.User.Deleted"},
        {"code": "admin.user"},
        {"uz": "{actor} {password} o'chirdi"},
        {"uz": "   "},
        {"category": "delete"},
        {"risk": "extreme"},
        {"sensitivity": "top"},
        {"target": TargetSpec("user", id="body.user_id")},
        {"target": TargetSpec("User")},
    ],
)
def test_FR_51_bad_declaration_raises_at_decoration(kwargs: dict[str, Any]) -> None:
    args: dict[str, Any] = {
        "code": "admin.user.deleted", "uz": "{actor} o'chirdi", "category": "admin", "risk": "high",
    }
    args.update(kwargs)
    code = args.pop("code")
    with pytest.raises(ValueError):
        audited(code, **args)


def test_FR_50_event_def_of_never_raises() -> None:
    class Hostile:
        def __getattr__(self, name: str) -> Any:
            raise RuntimeError("boom")

    def plain() -> None: ...

    setattr(plain, ATTRIBUTE, "not an EventDef")
    assert event_def_of(Hostile()) is None
    assert event_def_of(None) is None
    assert event_def_of(plain) is None
    assert event_def_of(lambda: None) is None
