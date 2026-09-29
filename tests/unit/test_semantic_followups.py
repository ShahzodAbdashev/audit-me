"""Two gaps found by the live runs across five services (2026-09-28).

FR-62: a request turned away BEFORE routing (an ownership/auth middleware
answering 401/403, a client that disconnected early) never gets
``scope["route"]``. It was recorded as a vague derived "noma'lum manzilga
so'rov yubordi" — on exactly the denied requests an auditor looks for. The
middleware now matches the request against the app's own routes, as routing
would have, and describes it from the route's @audited.

FR-63: the sentence named an identifier as the client typed it ("901234567")
while ``audit.target.msisdn`` held "+998901234567"; it now uses the canonical
form, so every record reads the same whatever the input format.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse

from audit_logging import AuditConfig, AuditMiddleware, Target, audited, audit
from audit_logging.semantic.enrich import enrich
from audit_logging.semantic.model import Described, EventDef, LEVEL_DECORATOR, TargetSpec

PHONE_EVENT = EventDef("svc.phone.viewed", {"uz": "{actor} {target} raqamini ko'rdi"}, "read", "high",
                       target=TargetSpec("msisdn", "path.p"), level=LEVEL_DECORATOR)


def _doc(p: str) -> dict[str, Any]:
    return {"event": {}, "user": {"full_name": "Sardor Karimov"},
            "audit": {"route": "/phones/{p}", "path_params": {"p": p}, "request": {"query": {}}},
            "http": {"response": {"status_code": 200}}}


def test_FR_63_the_sentence_uses_the_canonical_identifier() -> None:
    for typed in ("901234567", "0901234567", "+998 (90) 123-45-67"):
        out = enrich(_doc(typed), Described(PHONE_EVENT, LEVEL_DECORATOR), None, lang="uz",
                     service="svc", redact_keys=frozenset())
        assert out["message"] == "Sardor Karimov +998901234567 raqamini ko'rdi", out["message"]


def test_FR_63_a_value_that_is_not_a_valid_identifier_is_shown_as_typed() -> None:
    out = enrich(_doc("23423434"), Described(PHONE_EVENT, LEVEL_DECORATOR), None, lang="uz",
                 service="svc", redact_keys=frozenset())
    assert out["message"] == "Sardor Karimov 23423434 raqamini ko'rdi"


# --- FR-62 -----------------------------------------------------------------------

def _app(log_dir: Path) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/investigation/{investigation_id}/phones/{p}")
    @audited("svc.phone.viewed", uz="{actor} {target} raqamini ko'rdi", category="read",
             risk="high", target=Target("msisdn", id="path.p"))
    async def phone(investigation_id: str, p: str) -> dict[str, str]:
        audit.detail(reached=True)
        return {"p": p}

    @app.middleware("http")
    async def ownership(request, call_next):  # answers before routing, like profile's
        if not request.headers.get("authorization"):
            return JSONResponse({"detail": "not your folder"}, status_code=403)
        return await call_next(request)

    app.add_middleware(AuditMiddleware, config=AuditConfig(
        service_name="svc", dataset="svc", log_dir=log_dir, elasticsearch_url="none",
        user_resolver=lambda scope: {"id": "u1", "full_name": "Sardor Karimov"}))
    return app


def _records(log_dir: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for f in log_dir.rglob("*.jsonl")
            for line in f.read_text().splitlines() if line.strip()]


def test_FR_62_a_request_denied_before_routing_is_described_by_its_route(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        assert client.get("/investigation/inv-7/phones/901234567").status_code == 403
    (doc,) = _records(tmp_path)
    assert doc["audit"]["route"] == "/investigation/{investigation_id}/phones/{p}"
    assert doc["audit"]["level"] == "decorator"
    assert doc["event"]["action"] == "svc.phone.viewed"
    assert doc["audit"]["result"] == "denied"
    assert doc["audit"]["target"]["msisdn"] == "+998901234567"
    assert doc["audit"]["context"]["investigation_id"] == "inv-7"
    assert doc["message"] == "Sardor Karimov +998901234567 raqamini ko'rdi — rad etildi"


def test_FR_62_a_routed_request_is_unchanged(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        assert client.get("/investigation/inv-7/phones/901234567",
                          headers={"authorization": "x"}).status_code == 200
    (doc,) = _records(tmp_path)
    assert doc["audit"]["level"] == "decorator" and doc["audit"]["result"] == "success"
    assert doc["audit"]["detail"] == {"reached": True}


def test_FR_62_a_path_no_route_matches_stays_unmatched(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path)) as client:
        client.get("/nowhere/at/all", headers={"authorization": "x"})
    (doc,) = _records(tmp_path)
    assert doc["audit"]["route"] == "unmatched"
    assert doc["audit"]["level"] == "derived"


# --- FR-64: exact-path excludes -------------------------------------------------

def test_FR_64_exact_excludes_skip_only_that_path(tmp_path: Path) -> None:
    """users-adminka must skip its ingest POST /api/v2/audit/events but keep the
    read GET /api/v2/audit/events/{id}; relations must skip its "/" liveness
    probe without a prefix "/" excluding everything. A prefix cannot say either."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/")
    async def root() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/api/v2/audit/events")
    async def ingest() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api/v2/audit/events/{event_id}")
    async def read(event_id: str) -> dict[str, str]:
        return {"id": event_id}

    app.add_middleware(AuditMiddleware, config=AuditConfig(
        service_name="svc", dataset="svc", log_dir=tmp_path, elasticsearch_url="none",
        exclude_exact_paths=["/", "/api/v2/audit/events"]))
    with TestClient(app) as client:
        client.get("/")
        client.post("/api/v2/audit/events")
        client.get("/api/v2/audit/events/e1")
    assert [d["url"]["path"] for d in _records(tmp_path)] == ["/api/v2/audit/events/e1"]


def test_FR_64_exact_excludes_come_from_the_environment_as_csv(monkeypatch: Any) -> None:
    monkeypatch.setenv("AUDIT_EXCLUDE_EXACT_PATHS", "/,/ping")
    config = AuditConfig(service_name="svc", dataset="svc", elasticsearch_url="none")
    assert config.exclude_exact_paths == ["/", "/ping"]
