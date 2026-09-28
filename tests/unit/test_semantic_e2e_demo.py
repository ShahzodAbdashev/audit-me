"""Package exit gate (PLAN §16.3 items 2-3): a demo FastAPI app end to end.

Routes: one ``@audited`` (target label + diff), one catalog-described (fixture
file), one undeclared (derived), one denied (403), one sync handler; plus an
``audit.emit()`` outside any request. Every document must carry its expected
``ENRICHED_PATHS``, fit the merged index mapping, and read as Uzbek text.

Item 3 (a refused document is counted lost and skipped, X-8; a replay answered
409 is not a second document) is already proven with the shipper fakes in
``test_shipper.py``: ``test_X_8_a_refused_document_is_counted_lost_and_skipped``,
``test_FR_36_a_409_counts_as_delivered_not_rejected`` and
``test_FR_36_a_replay_of_the_same_lines_creates_no_second_document``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from audit_logging import AuditConfig, AuditMiddleware, NullSink, Target, audit, audited
from audit_logging.metrics import InMemoryMetrics
from audit_logging.semantic import runtime
from audit_logging.semantic.schema import ENRICHED_PATHS
from audit_logging.templates import index_template_for
from audit_logging.testing import capture

CATALOG = Path(__file__).resolve().parent.parent / "fixtures" / "semantic_catalog.json"
ACTOR: dict[str, Any] = {
    "id": "u7", "name": "sardor", "full_name": "Sardor Karimov", "roles": ["Admin"],
    "verified": True, "source": "jwt",
}
ACTOR_PATHS = {f"user.{k}" for k in ACTOR}
COMMON = ACTOR_PATHS | {
    "message", "event.id", "event.action",
    "audit.schema_version", "audit.category", "audit.risk", "audit.sensitivity",
    "audit.derived", "audit.level", "audit.result", "audit.i18n.key", "audit.i18n.params",
}


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
        audit.diff({"role_id": "Operator"}, {"role_id": "Admin"}, labels={"role_id": "Rol"})
        return {"ok": True}

    @app.delete("/users/{user_id}")  # described by the catalog fixture
    async def delete_user(user_id: int) -> dict[str, bool]:
        audit.target(label="Aliyev Vali")
        return {"ok": True}

    @app.get("/departments")  # undeclared -> derived
    async def list_departments() -> list[str]:
        """API call to list departments."""
        return []

    @app.get("/reports")  # undeclared, always refused
    async def reports() -> None:
        raise HTTPException(status_code=403)

    @app.get("/phones/{phone_id}")
    def phone(phone_id: int) -> dict[str, bool]:  # sync: Starlette threadpool
        audit.target(label="+998 90 123 45 67", type="phone")
        audit.detail(source="card")
        return {"ok": True}

    return app


def build_config() -> AuditConfig:
    return AuditConfig(
        service_name="demo", dataset="demo", elasticsearch_url=None, environment="test",
        catalog_file=str(CATALOG), user_resolver=lambda scope: dict(ACTOR),
    )


REQUESTS: list[tuple[str, str, dict[str, Any]]] = [
    ("POST", "/users/2", {"json": {"role_id": 2}}),
    ("DELETE", "/users/2", {}),
    ("GET", "/departments", {}),
    ("GET", "/reports", {}),
    ("GET", "/phones/5", {}),
]


@pytest.fixture(autouse=True)
def _no_active_sink_leaks() -> Any:
    yield
    runtime.clear_active()


async def run_demo() -> tuple[list[dict[str, Any]], InMemoryMetrics]:
    """Every request's document, then one emit() record, in that order."""
    sink, metrics = NullSink(), InMemoryMetrics()
    app = AuditMiddleware(build_app(), config=build_config(), sink=sink, metrics=metrics)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        for method, path, kwargs in REQUESTS:
            await client.request(method, path, **kwargs)
    docs = list(sink.submitted)
    with capture(build_config()) as rec:
        assert audit.emit(  # type: ignore[attr-defined]
            "demo.report.sent", uz="{actor} «{target}» hisobotini yubordi",
            target={"type": "report", "id": "r1", "label": "Oylik hisobot"},
            actor=ACTOR, detail={"pages": 3},
        )
    assert rec.last is not None
    docs.append(rec.last)
    return docs, metrics


def leaf_paths(obj: Any, mapping: dict[str, Any] | None = None, prefix: str = "") -> set[str]:
    """Dotted leaves of a document; with a mapping node, stops where the mapping does."""
    if isinstance(obj, list):
        return set().union(*(leaf_paths(x, mapping, prefix) for x in obj)) if obj else {prefix}
    if not isinstance(obj, dict) or not obj or (mapping is not None and is_leaf(mapping)):
        return {prefix}
    props = (mapping or {}).get("properties", {})
    out: set[str] = set()
    for key, value in obj.items():
        path = f"{prefix}.{key}" if prefix else key
        out |= leaf_paths(value, props.get(key, {}), path) if mapping is not None else leaf_paths(value, None, path)
    return out


def is_leaf(node: dict[str, Any]) -> bool:
    return (
        node.get("enabled") is False
        or node.get("type", "object") not in ("object", "nested")
        or "properties" not in node
    )


def mapped(path: str, root: dict[str, Any]) -> bool:
    node: dict[str, Any] = root
    for part in path.split("."):
        if is_leaf(node) and node is not root:
            return True
        child = node.get("properties", {}).get(part)
        if child is None:
            return False
        node = child
    return True


# ---------------------------------------------------------------------------


async def test_FR_50_demo_levels_and_results() -> None:
    docs, metrics = await run_demo()
    assert len(docs) == 6
    summary = [(d["event"]["action"], d["audit"]["level"], d["audit"]["result"]) for d in docs]
    assert summary[0] == ("admin.user.updated", "decorator", "success")
    assert summary[1] == ("admin.user.deleted", "catalog", "success")
    assert summary[2][1:] == ("derived", "success") and docs[2]["audit"]["derived"] is True
    assert summary[3][1:] == ("derived", "denied") and docs[3]["event"]["outcome"] == "success"
    assert summary[4][1:] == ("derived", "success")
    assert summary[5] == ("demo.report.sent", "emit", "success")
    assert docs[4]["audit"]["target"] == {"type": "phone", "id": "5", "label": "+998 90 123 45 67"}  # sync bag
    assert docs[0]["audit"]["changes"]["diff"] == [
        {"field": "role_id", "label": "Rol", "old": "Operator", "new": "Admin"}
    ]
    assert metrics.get("audit_derived_total") == 3
    assert metrics.get("audit_semantic_errors_total") == 0


async def test_FR_48_each_doc_carries_its_enriched_paths() -> None:
    docs, _ = await run_demo()
    target = {"audit.target.type", "audit.target.id", "audit.target.label"}
    # Round 2 (PLAN §17): trace.id and client.ip are 0.1 fields now listed in
    # ENRICHED_PATHS, and every HTTP record says where its client.ip came from.
    http = COMMON | {"trace.id", "client.ip", "audit.client.ip_source"}
    expected = [
        http | target | {"audit.changes.diff", "audit.changes.before", "audit.changes.after"},
        http | target | {"audit.description"},
        http | {"audit.description"},
        http,
        http | target | {"audit.detail"},
        COMMON | target | {"audit.detail"},  # emit(): no HTTP transport fields
    ]
    for doc, want in zip(docs, expected):
        leaves = leaf_paths(doc)
        got = {p for p in ENRICHED_PATHS if any(x == p or x.startswith(p + ".") for x in leaves)}
        assert got == want, (doc["event"]["action"], sorted(got ^ want))


async def test_FR_48_every_path_exists_in_the_merged_mapping() -> None:
    docs, _ = await run_demo()
    root = index_template_for("demo")["template"]["mappings"]
    for doc in docs:
        missing = sorted(p for p in leaf_paths(doc, root) if not mapped(p, root))
        assert not missing, (doc["event"]["action"], missing)


_UZ = re.compile(r"\w+(di|ldi|ndi|ydi)\b")  # Uzbek past-tense verb ends every sentence


async def test_FR_52_messages_are_brace_free_uzbek() -> None:
    docs, _ = await run_demo()
    for doc in docs:
        message = doc["message"]
        assert isinstance(message, str) and message.strip(), doc
        assert not set(message) & set("{}/"), message
        assert _UZ.search(message), message
        assert "noma'lum" not in message, message  # every placeholder had a value
