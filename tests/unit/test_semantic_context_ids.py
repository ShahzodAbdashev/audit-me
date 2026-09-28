"""audit.context.investigation_id / profile_id — the folder a request touched.

A reader that scopes by investigation (users-adminka's folder-scoped role, and
its access resolver's forced `investigation_id` filter) needs the id as a real
field. Every service names it `investigation_id` / `profile_id` in its routes,
in the path or the query string, so the package lifts it from there.
"""

from __future__ import annotations

from typing import Any

from audit_logging.semantic.enrich import enrich
from audit_logging.semantic.model import Described, EventDef, LEVEL_CATALOG
from audit_logging.semantic.schema import ENRICHED_PATHS, MAPPING_ADDITIONS

EVENT = EventDef("svc.profile.viewed", {"uz": "{actor} profilni ko'rdi"}, "read", "normal",
                 level=LEVEL_CATALOG)


def _doc(path_params: dict[str, Any] | None = None, query: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"event": {}, "audit": {"route": "/x", "path_params": path_params or {},
                                   "request": {"query": query or {}}},
            "http": {"response": {"status_code": 200}}}


def _run(doc: dict[str, Any]) -> dict[str, Any]:
    return enrich(doc, Described(EVENT, LEVEL_CATALOG), None, lang="uz", service="svc",
                  redact_keys=frozenset())


def test_FR_59_ids_from_the_path_are_lifted() -> None:
    out = _run(_doc({"investigation_id": "665f", "profile_id": "p9", "other": "x"}))
    assert out["audit"]["context"] == {"investigation_id": "665f", "profile_id": "p9"}


def test_FR_59_ids_from_the_query_are_lifted_when_the_path_has_none() -> None:
    out = _run(_doc(query={"investigation_id": "665f"}))
    assert out["audit"]["context"] == {"investigation_id": "665f"}


def test_FR_59_the_path_wins_over_the_query() -> None:
    out = _run(_doc({"investigation_id": "from-path"}, {"investigation_id": "from-query"}))
    assert out["audit"]["context"]["investigation_id"] == "from-path"


def test_FR_59_no_ids_means_no_context_block() -> None:
    assert "context" not in _run(_doc({"user_id": "2"}))["audit"]


def test_FR_59_a_list_or_oversized_value_is_not_stored_as_the_id() -> None:
    out = _run(_doc(query={"investigation_id": ["a", "b"], "profile_id": "p" * 5000}))
    ctx = out["audit"].get("context", {})
    assert "investigation_id" not in ctx
    assert len(ctx.get("profile_id", "")) <= 1024


def test_FR_59_the_fields_are_mapped_and_declared() -> None:
    props = MAPPING_ADDITIONS["audit"]["properties"]["context"]["properties"]
    assert set(props) == {"investigation_id", "profile_id"}
    assert {"audit.context.investigation_id", "audit.context.profile_id"} <= ENRICHED_PATHS
