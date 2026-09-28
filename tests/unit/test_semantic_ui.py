"""ui_router() (FR-57). Agent F."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from audit_logging.semantic import audit, render, runtime
from audit_logging.semantic.decorators import ATTRIBUTE
from audit_logging.semantic.ui import ui_router
from audit_logging.testing import capture


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    def boom(*a: Any, **k: Any) -> str:
        raise NotImplementedError

    monkeypatch.setattr(render, "render", boom)
    runtime.clear_active()

    def resolver(request: Any) -> dict[str, Any] | None:
        return {"id": "u1", "name": "sardor", "verified": True} if request.headers.get("x-token") else None

    app = FastAPI()
    app.include_router(ui_router(actor_resolver=resolver))
    yield TestClient(app)
    runtime.clear_active()


def test_FR_57_accepts_ui_events_with_resolved_actor(client: TestClient) -> None:
    with capture() as rec:
        r = client.post(
            "/audit/ui-events",
            headers={"x-token": "t"},
            json={"events": [{"code": "ui.page.viewed", "uz": "{actor} sahifani ko'rdi",
                              "detail": {"page": "/users"}}]},
        )
    assert r.status_code == 202 and r.json() == {"received": 1, "accepted": 1}
    doc = rec.last
    assert doc is not None
    assert doc["event"]["action"] == "ui.page.viewed"
    assert doc["user"]["id"] == "u1"
    assert doc["message"] == "sardor sahifani ko'rdi"
    assert doc["audit"]["risk"] == "low"


def test_FR_57_actor_never_taken_from_body(client: TestClient) -> None:
    with capture() as rec:
        r = client.post("/audit/ui-events", json={"events": [
            {"code": "ui.page.viewed", "uz": "x", "actor": {"id": "admin"}}]})
    assert r.status_code == 422
    with capture() as rec:
        r = client.post("/audit/ui-events", json={"events": [{"code": "ui.page.viewed", "uz": "x"}]})
    assert r.status_code == 202
    assert rec.last is not None and "user" not in rec.last


@pytest.mark.parametrize(
    "event",
    [
        {"code": "admin.user.deleted", "uz": "x"},
        {"code": "ui.bad", "uz": "x"},
        {"code": "ui.page.viewed", "uz": "x", "category": "admin"},
        {"code": "ui.page.viewed", "uz": ""},
    ],
)
def test_FR_57_rejects_non_ui_or_invalid(client: TestClient, event: dict[str, Any]) -> None:
    assert client.post("/audit/ui-events", json={"events": [event]}).status_code == 422


def test_FR_57_max_100_events(client: TestClient) -> None:
    ev = {"code": "ui.page.viewed", "uz": "x"}
    with capture():
        assert client.post("/audit/ui-events", json={"events": [ev] * 100}).status_code == 202
    assert client.post("/audit/ui-events", json={"events": [ev] * 101}).status_code == 422


def test_FR_57_resolver_error_means_no_actor(monkeypatch: pytest.MonkeyPatch) -> None:
    def bad(request: Any) -> dict[str, Any] | None:
        raise RuntimeError

    app = FastAPI()
    app.include_router(ui_router(actor_resolver=bad, prefix="/ui"))
    with capture() as rec:
        r = TestClient(app).post("/ui", json={"events": [{"code": "ui.page.viewed", "uz": "x"}]})
    assert r.status_code == 202 and rec.last is not None and "user" not in rec.last


def test_FR_57_route_is_described_and_attached() -> None:
    router = ui_router(actor_resolver=lambda r: None)
    assert getattr(router.routes[0].endpoint, ATTRIBUTE).code == "audit.ui_events.received"
    assert getattr(audit, "ui_router") is ui_router


def test_FR_57_without_fastapi_raises_importerror(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real = builtins.__import__

    def fake(name: str, *a: Any, **k: Any) -> Any:
        if name == "fastapi":
            raise ImportError(name)
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(ImportError, match="pip install fastapi"):
        ui_router(actor_resolver=lambda r: None)
