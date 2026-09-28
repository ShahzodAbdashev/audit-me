"""End-to-end: a real FastAPI app behind ``AuditMiddleware`` with the 0.2 layer (agent D)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from audit_logging import AuditConfig, AuditMiddleware, NullSink, Target, audit, audited
from audit_logging import middleware as middleware_module
from audit_logging.metrics import InMemoryMetrics
from audit_logging.semantic import runtime
from audit_logging.semantic.schema import ENRICHED_PATHS

ACTOR = {"id": "u7", "name": "sardor", "full_name": "Sardor Karimov", "roles": ["Admin"],
         "department": "Markaziy apparat", "verified": True, "source": "jwt"}


def build_app() -> FastAPI:
    app = FastAPI()

    @app.post("/users/{user_id}")
    @audited(
        "admin.user.updated",
        uz="{actor} «{target}» foydalanuvchisini tahrirladi",
        target=Target("user", id="path.user_id"),
        category="admin", risk="high", diff=True,
    )
    async def update_user(user_id: int, body: dict[str, Any]) -> dict[str, bool]:
        audit.target(label="Aliyev Vali")
        audit.diff({"role_id": "Operator", "password": "a"}, {"role_id": "Admin", "password": "b"},
                   labels={"role_id": "Rol"})
        return {"ok": True}

    @app.delete("/users/{user_id}")
    async def delete_user(user_id: int) -> dict[str, bool]:
        audit.target(label="Aliyev Vali")
        return {"ok": True}

    @app.get("/departments")
    async def list_departments() -> list[str]:
        """API call to list departments."""
        return []

    @app.get("/phones/{phone_id}")
    def phone(phone_id: int) -> dict[str, bool]:  # sync: runs in the threadpool
        audit.target(label="+998 90 123 45 67", type="phone")
        audit.detail(source="card")
        return {"ok": True}

    @app.get("/secret")
    @audited("admin.secret.viewed", uz="{actor} maxfiy sahifani ko'rdi", category="read", risk="high")
    async def secret() -> None:
        raise HTTPException(status_code=403)

    return app


def build_config(**overrides: Any) -> AuditConfig:
    values: dict[str, Any] = {
        "service_name": "users-adminka",
        "dataset": "users_adminka",
        "elasticsearch_url": None,
        "environment": "test",
        "user_resolver": lambda scope: dict(ACTOR),
    }
    values.update(overrides)
    return AuditConfig(**values)


async def call(config: AuditConfig, method: str, path: str, **kwargs: Any) -> tuple[dict[str, Any], InMemoryMetrics, httpx.Response]:
    sink, metrics = NullSink(), InMemoryMetrics()
    app = AuditMiddleware(build_app(), config=config, sink=sink, metrics=metrics)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        response = await client.request(method, path, **kwargs)
    return sink.only, metrics, response


@pytest.fixture(autouse=True)
def _no_active_sink_leaks() -> Any:
    yield
    runtime.clear_active()


def paths_of(obj: Any, prefix: str = "", stop: frozenset[str] = frozenset()) -> set[str]:
    if prefix in stop or not isinstance(obj, dict) or not obj:
        return {prefix} if prefix else set()
    out: set[str] = set()
    for key, value in obj.items():
        out |= paths_of(value, f"{prefix}.{key}" if prefix else key, stop)
    return out


# ---------------------------------------------------------------------------


async def test_FR_50_decorated_route_sentence_actor_target_diff() -> None:
    doc, metrics, _ = await call(build_config(), "POST", "/users/2", json={"role_id": 2})
    assert doc["message"] == (
        "Sardor Karimov «Aliyev Vali» foydalanuvchisini tahrirladi"
        " — password: [REDACTED] → [REDACTED]; Rol: Operator → Admin"
    )
    assert doc["event"]["action"] == "admin.user.updated"
    assert doc["audit"]["level"] == "decorator" and doc["audit"]["derived"] is False
    assert doc["audit"]["target"] == {"type": "user", "id": "2", "label": "Aliyev Vali"}
    assert doc["audit"]["result"] == "success"
    assert doc["user"] == ACTOR | {"roles": ["Admin"]}  # FR-31: 0.2 user fields kept
    assert metrics.get("audit_derived_total") == 0
    assert metrics.get("audit_semantic_errors_total") == 0


async def test_FR_50_catalog_route(tmp_path: Path) -> None:
    catalog = tmp_path / "audit_catalog.json"
    catalog.write_text(json.dumps([{
        "route": "DELETE /users/{user_id}", "code": "admin.user.deleted",
        "uz": "{actor} «{target}» foydalanuvchisini o'chirdi",
        "category": "admin", "risk": "critical", "target": {"type": "user", "id": "path.user_id"},
    }]))
    doc, _, _ = await call(build_config(catalog_file=str(catalog)), "DELETE", "/users/5")
    assert doc["message"] == "Sardor Karimov «Aliyev Vali» foydalanuvchisini o'chirdi"
    assert doc["audit"]["level"] == "catalog"
    assert doc["audit"]["risk"] == "critical"
    assert doc["audit"]["target"]["id"] == "5"


async def test_FR_52_derived_route_is_counted_and_readable() -> None:
    doc, metrics, _ = await call(build_config(), "GET", "/departments")
    assert doc["audit"]["level"] == "derived" and doc["audit"]["derived"] is True
    assert doc["audit"]["description"] == "API call to list departments."
    assert doc["message"].startswith("Sardor Karimov ")
    assert "{" not in doc["message"] and "/" not in doc["message"]
    assert doc["event"]["action"].startswith("users_adminka.")
    assert metrics.get("audit_derived_total") == 1


async def test_FR_54_sync_handler_writes_to_the_bag() -> None:
    doc, _, _ = await call(build_config(), "GET", "/phones/9")
    assert doc["audit"]["target"]["label"] == "+998 90 123 45 67"
    assert doc["audit"]["target"]["type"] == "phone"
    assert doc["audit"]["detail"] == {"source": "card"}


async def test_FR_38_forbidden_is_denied_while_outcome_keeps_0_1_value() -> None:
    doc, _, response = await call(build_config(), "GET", "/secret")
    assert response.status_code == 403
    assert doc["audit"]["result"] == "denied"
    assert doc["event"]["outcome"] == "success"
    assert doc["message"] == "Sardor Karimov maxfiy sahifani ko'rdi — rad etildi"


async def test_NFR_3_enrich_failure_keeps_the_0_1_document(monkeypatch: pytest.MonkeyPatch) -> None:
    baseline, _, _ = await call(build_config(semantic_enabled=False), "POST", "/users/2", json={})

    def boom(*args: Any, **kwargs: Any) -> Any:
        doc = args[0]
        doc["message"] = "half-done"
        doc["audit"]["schema_version"] = "2"
        raise RuntimeError("boom")

    monkeypatch.setattr(middleware_module, "enrich", boom)
    doc, metrics, response = await call(build_config(), "POST", "/users/2", json={})
    assert response.status_code == 200
    # build_document's 0.2 user keys follow semantic_enabled, not enrich().
    user_v2 = {"user.full_name", "user.department", "user.source", "user.verified"}
    assert paths_of(doc) - user_v2 == paths_of(baseline)
    assert "message" not in doc and "schema_version" not in doc["audit"]
    assert doc["event"]["action"] == "http-request"
    assert metrics.get("audit_semantic_errors_total") == 1
    assert metrics.get("audit_middleware_errors_total") == 1


async def test_FR_15_semantic_disabled_is_exactly_the_0_1_shape() -> None:
    doc, metrics, _ = await call(build_config(semantic_enabled=False), "POST", "/users/2", json={})
    assert "message" not in doc
    assert set(doc["event"]) == {"kind", "category", "type", "action", "duration", "outcome"}
    assert set(doc["audit"]) == {"route", "path_params", "request", "response"}
    assert doc["event"]["action"] == "http-request"
    assert metrics.get("audit_derived_total") == 0


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [("POST", "/users/2", {"json": {"a": 1}}), ("GET", "/departments", {}),
     ("GET", "/phones/1", {}), ("GET", "/secret", {}), ("GET", "/nope?x=1", {})],
)
async def test_FR_48_every_new_path_is_declared(method: str, path: str, kwargs: dict[str, Any]) -> None:
    old, _, _ = await call(build_config(semantic_enabled=False), method, path, **kwargs)
    new, _, _ = await call(build_config(), method, path, **kwargs)
    added = paths_of(new, stop=ENRICHED_PATHS) - paths_of(old)
    assert added <= ENRICHED_PATHS, added - ENRICHED_PATHS
    assert "{" not in new["message"]


async def test_FR_31_user_fields_that_will_not_coerce_are_dropped() -> None:
    weird = {"id": 7, "full_name": {"x": 1}, "department": 12, "verified": "yes", "source": ["jwt"]}
    doc, _, _ = await call(build_config(user_resolver=lambda scope: weird), "GET", "/departments")
    assert doc["user"] == {"id": "7", "department": "12"}
    assert doc["message"].startswith("7 ")


def test_bad_catalog_fails_at_construction(tmp_path: Path) -> None:
    bad = tmp_path / "c.json"
    bad.write_text('[{"route": "GET /x", "code": "Not A Code", "uz": "x", "category": "read", "risk": "low"}]')
    with pytest.raises(ValueError):
        AuditMiddleware(build_app(), config=build_config(catalog_file=str(bad)), sink=NullSink())


def test_bad_risk_floor_is_rejected() -> None:
    with pytest.raises(ValueError):
        build_config(derived_risk_floor="extreme")


async def test_FR_56_lifespan_registers_and_clears_the_active_sink() -> None:
    sink = NullSink()
    seen: list[Any] = []

    async def app(scope: Any, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            else:
                await send({"type": "lifespan.shutdown.complete"})
                return

    middleware = AuditMiddleware(app, config=build_config(), sink=sink)
    inbox = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]

    async def receive() -> dict[str, Any]:
        return inbox.pop(0)

    async def send(message: Any) -> None:
        active = runtime.get_active()
        seen.append((message["type"], active.sink if active else None))

    await middleware({"type": "lifespan"}, receive, send)
    assert seen[0] == ("lifespan.startup.complete", None)  # registered after it is forwarded
    assert seen[1] == ("lifespan.shutdown.complete", None)  # cleared before shutdown completes
    assert sink.started and sink.closed


async def test_FR_56_lazy_start_registers_the_active_sink() -> None:
    sink = NullSink()
    app = AuditMiddleware(build_app(), config=build_config(), sink=sink)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        await client.get("/departments")
    active = runtime.get_active()
    assert active is not None and active.sink is sink
