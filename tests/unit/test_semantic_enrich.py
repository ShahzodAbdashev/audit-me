"""Unit tests for ``semantic.describe`` and ``semantic.enrich`` (agent D)."""

from __future__ import annotations

from typing import Any

import pytest

from audit_logging.redact import DEFAULT_REDACT_KEYS, REDACTED
from audit_logging.semantic import describe as describe_module
from audit_logging.semantic.context import compute_diff
from audit_logging.semantic.derive import default_labels
from audit_logging.semantic.describe import describe
from audit_logging.semantic.enrich import enrich, result_of
from audit_logging.semantic.model import (
    LEVEL_CATALOG,
    LEVEL_DECORATOR,
    LEVEL_DERIVED,
    AuditBag,
    Described,
    EventDef,
    TargetSpec,
)
from audit_logging.semantic.schema import ENRICHED_PATHS

KEYS = DEFAULT_REDACT_KEYS


def base_doc(**overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "event": {"kind": "event", "action": "http-request", "outcome": "success"},
        "http": {"response": {"status_code": 200}},
        "audit": {
            "route": "/users/{user_id}",
            "path_params": {"user_id": "2"},
            "request": {"query": {"ref": ["a1", "a2"]}},
        },
        "user": {"id": "u1", "name": "sardor", "full_name": "Sardor Karimov"},
    }
    doc.update(overrides)
    return doc


def update_def(**overrides: Any) -> EventDef:
    values: dict[str, Any] = {
        "code": "admin.user.updated",
        "templates": {"uz": "{actor} «{target}» foydalanuvchisini tahrirladi"},
        "category": "admin",
        "risk": "high",
        "target": TargetSpec("user", id="path.user_id"),
    }
    values.update(overrides)
    event = EventDef(**values)
    event.validate()
    return event


def leaf_paths(obj: Any, prefix: str = "", stop: frozenset[str] = ENRICHED_PATHS) -> set[str]:
    if prefix in stop or not isinstance(obj, dict) or not obj:
        return {prefix} if prefix else set()
    out: set[str] = set()
    for key, value in obj.items():
        out |= leaf_paths(value, f"{prefix}.{key}" if prefix else key, stop)
    return out


# ---------------------------------------------------------------------------
# result_of (FR-38)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "outcome", "expected"),
    [
        (200, "success", "success"),
        (201, "success", "success"),
        (401, "success", "denied"),
        (403, "success", "denied"),
        (403, "disconnected", "denied"),
        (200, "disconnected", "disconnected"),
        (404, "success", "failure"),
        (500, "failure", "failure"),
        (None, "failure", "failure"),
        (None, "success", "success"),
    ],
)
def test_FR_38_result_of(status: int | None, outcome: str, expected: str) -> None:
    assert result_of(status, outcome) == expected


# ---------------------------------------------------------------------------
# enrich (FR-36, FR-53, FR-54)
# ---------------------------------------------------------------------------


def test_FR_53_decorated_sentence_actor_target_and_i18n() -> None:
    bag = AuditBag(target_label="Aliyev Vali")
    doc = enrich(base_doc(), Described(update_def(), LEVEL_DECORATOR), bag,
                 lang="uz", service="svc", redact_keys=KEYS)
    assert doc["message"] == "Sardor Karimov «Aliyev Vali» foydalanuvchisini tahrirladi"
    assert doc["event"]["action"] == "admin.user.updated"
    assert doc["event"]["outcome"] == "success"  # 0.1 value untouched
    audit = doc["audit"]
    assert audit["target"] == {"type": "user", "id": "2", "label": "Aliyev Vali"}
    assert audit["i18n"] == {
        "key": "admin.user.updated",
        "params": {"actor": "Sardor Karimov", "target": "Aliyev Vali"},
    }
    assert audit["schema_version"] == "2"
    assert (audit["level"], audit["derived"], audit["result"]) == ("decorator", False, "success")
    assert (audit["category"], audit["risk"], audit["sensitivity"]) == ("admin", "high", "internal")
    assert audit["route"] == "/users/{user_id}"  # 0.1 fields kept


def test_FR_36_event_id_is_uuid_hex_and_kept_when_present() -> None:
    doc = enrich(base_doc(), Described(update_def(), LEVEL_DECORATOR), None,
                 lang="uz", service="svc", redact_keys=KEYS)
    assert len(doc["event"]["id"]) == 32 and int(doc["event"]["id"], 16) >= 0
    kept = base_doc(event={"id": "fixed", "outcome": "success"})
    assert enrich(kept, Described(update_def(), LEVEL_DECORATOR), None,
                  lang="uz", service="svc", redact_keys=KEYS)["event"]["id"] == "fixed"


@pytest.mark.parametrize(
    ("user", "actor"),
    [
        ({"id": "u1", "name": "sardor", "full_name": "Sardor K"}, "Sardor K"),
        ({"id": "u1", "name": "sardor"}, "sardor"),
        ({"id": "u1"}, "u1"),
        (None, "noma'lum"),
    ],
)
def test_FR_53_actor_precedence(user: dict[str, Any] | None, actor: str) -> None:
    doc = base_doc()
    if user is None:
        del doc["user"]
    else:
        doc["user"] = user
    event = update_def(templates={"uz": "{actor} ko'rdi"}, target=None)
    out = enrich(doc, Described(event, LEVEL_DECORATOR), None, lang="uz", service="s", redact_keys=KEYS)
    assert out["message"] == f"{actor} ko'rdi"
    assert "{" not in out["message"]


def test_FR_54_target_id_sources_and_bag_override() -> None:
    by_query = update_def(target=TargetSpec("ref", id="query.ref"))
    doc = enrich(base_doc(), Described(by_query, LEVEL_CATALOG), None, lang="uz", service="s", redact_keys=KEYS)
    assert doc["audit"]["target"] == {"type": "ref", "id": "a1"}

    by_detail = update_def(target=TargetSpec("phone", id="detail.phone_id"))
    bag = AuditBag(detail={"phone_id": 77})
    doc = enrich(base_doc(), Described(by_detail, LEVEL_CATALOG), bag, lang="uz", service="s", redact_keys=KEYS)
    assert doc["audit"]["target"]["id"] == "77"
    assert "label" not in doc["audit"]["target"]
    # no label -> the id is what the sentence shows
    assert "«77»" in doc["message"]

    bag = AuditBag(target_id="99", target_type="account", code="admin.account.reset")
    doc = enrich(base_doc(), Described(update_def(), LEVEL_DECORATOR), bag, lang="uz", service="s", redact_keys=KEYS)
    assert doc["audit"]["target"] == {"type": "account", "id": "99"}
    assert doc["event"]["action"] == doc["audit"]["i18n"]["key"] == "admin.account.reset"


def test_FR_54_diff_before_after_detail_are_redacted() -> None:
    before = {"role_id": "Operator", "password": "old-secret", "profile": {"token": "t1"}}
    after = {"role_id": "Admin", "password": "new-secret", "profile": {"token": "t2"}}
    bag = AuditBag(
        diff=compute_diff(before, after, {"role_id": "Rol"}),
        before=before, after=after,
        detail={"api_key": "k", "added": [12]},
    )
    doc = enrich(base_doc(), Described(update_def(diff=True), LEVEL_DECORATOR), bag,
                 lang="uz", service="s", redact_keys=KEYS)
    text = repr(doc)
    for secret in ("old-secret", "new-secret", "t1", "t2", "'k'"):
        assert secret not in text
    changes = doc["audit"]["changes"]
    by_field = {d["field"]: d for d in changes["diff"]}
    assert by_field["role_id"] == {"field": "role_id", "label": "Rol", "old": "Operator", "new": "Admin"}
    assert by_field["password"]["old"] == by_field["password"]["new"] == REDACTED
    assert isinstance(by_field["profile"]["old"], str)  # keyword-safe
    assert changes["before"]["password"] == REDACTED
    assert doc["audit"]["detail"] == {"api_key": REDACTED, "added": [12]}
    assert "Rol: Operator → Admin" in doc["message"]
    assert "password: [REDACTED] → [REDACTED]" in doc["message"]
    assert "old-secret" not in doc["message"]


def test_FR_53_extra_redact_keys_apply() -> None:
    bag = AuditBag(detail={"pinfl": "12345678901234"})
    doc = enrich(base_doc(), Described(update_def(), LEVEL_DECORATOR), bag,
                 lang="uz", service="s", redact_keys=KEYS | {"pinfl"})
    assert doc["audit"]["detail"] == {"pinfl": REDACTED}


def test_FR_53_detail_placeholder_and_count() -> None:
    event = update_def(templates={"uz": "{actor} {count} ta yozuvni {detail.format} ga eksport qildi"},
                       target=None, category="export")
    bag = AuditBag(count=5, detail={"format": "xlsx"})
    doc = enrich(base_doc(), Described(event, LEVEL_DECORATOR), bag, lang="uz", service="s", redact_keys=KEYS)
    assert doc["message"] == "Sardor Karimov 5 ta yozuvni xlsx ga eksport qildi"
    assert doc["audit"]["count"] == 5
    assert doc["audit"]["i18n"]["params"] == {"actor": "Sardor Karimov", "count": "5", "detail.format": "xlsx"}


def test_FR_53_denied_result_keeps_ecs_outcome() -> None:
    doc = base_doc(http={"response": {"status_code": 403}})
    out = enrich(doc, Described(update_def(), LEVEL_DECORATOR), None, lang="uz", service="s", redact_keys=KEYS)
    assert out["audit"]["result"] == "denied"
    assert out["event"]["outcome"] == "success"


def test_FR_48_enrich_only_adds_declared_paths() -> None:
    bag = AuditBag(target_label="x", count=1, detail={"a": {"b": 1}},
                   diff=compute_diff({"a": 1}, {"a": 2}), before={"a": 1}, after={"a": 2})
    before = leaf_paths(base_doc(), stop=frozenset())
    doc = enrich(base_doc(), Described(update_def(description="d"), LEVEL_DECORATOR), bag,
                 lang="uz", service="s", redact_keys=KEYS)
    added = leaf_paths(doc) - before
    assert added <= ENRICHED_PATHS
    assert {"message", "event.id", "audit.changes.diff", "audit.detail", "audit.i18n.params",
            "audit.description", "audit.count", "audit.target.label"} <= added


# ---------------------------------------------------------------------------
# describe (FR-50)
# ---------------------------------------------------------------------------


class FakeRoute:
    def __init__(self, path: str, endpoint: Any = None, summary: str | None = None) -> None:
        self.path = path
        self.endpoint = endpoint
        self.summary = summary


def _handler() -> None:
    """Update a user.

    Long developer notes that must not reach the record.
    """


def _decorated() -> None: ...


_decorated.__audit__ = update_def()  # type: ignore[attr-defined]


def _describe(scope: dict[str, Any], method: str = "POST", catalog: Any = None) -> Described:
    return describe(scope, method, catalog=catalog or {}, service="svc", labels=default_labels())


def test_FR_50_precedence_decorator_catalog_derived() -> None:
    catalog_def = update_def(code="svc.user.changed", level=LEVEL_CATALOG)
    catalog = {("POST", "/users/{user_id}"): catalog_def}

    got = _describe({"route": FakeRoute("/users/{user_id}", _decorated)}, catalog=catalog)
    assert got.level == LEVEL_DECORATOR and got.event.code == "admin.user.updated"

    got = _describe({"route": FakeRoute("/users/{user_id}", _handler)}, "post", catalog=catalog)
    assert got.level == LEVEL_CATALOG and got.event.code == "svc.user.changed"
    assert got.event.description == "Update a user."  # filled from the docstring

    got = _describe({"route": FakeRoute("/users/{user_id}", _handler)}, "DELETE", catalog=catalog)
    assert got.level == LEVEL_DERIVED and got.event.level == LEVEL_DERIVED
    assert got.event.description == "Update a user."
    assert "{" not in got.event.templates["uz"].replace("{actor}", "")


def test_FR_50_summary_wins_over_docstring_and_derived_is_cached() -> None:
    route = FakeRoute("/cars/{car_id}", _handler, summary="Car card")
    first = _describe({"route": route}, "GET")
    assert first.event.description == "Car card"
    assert _describe({"route": route}, "GET").event is first.event


def test_FR_50_cache_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(describe_module, "_CACHE", {})
    monkeypatch.setattr(describe_module, "_CACHE_MAX", 3)
    for i in range(10):
        _describe({"route": FakeRoute(f"/r{i}")}, "GET")
    assert len(describe_module._CACHE) <= 3


def test_FR_50_unmatched_and_hostile_route_never_raise() -> None:
    got = _describe({}, "GET")
    assert got.level == LEVEL_DERIVED and got.event.code

    class Hostile:
        @property
        def path(self) -> str:
            raise RuntimeError("boom")

    got = _describe({"route": Hostile()}, "GET")
    assert got.level == LEVEL_DERIVED


def test_FR_50_head_falls_back_to_the_get_catalog_entry() -> None:
    catalog_def = update_def(code="svc.user.viewed", level=LEVEL_CATALOG)
    catalog = {("GET", "/users/{user_id}"): catalog_def}
    got = _describe({"route": FakeRoute("/users/{user_id}", _handler)}, "HEAD", catalog=catalog)
    assert got.level == LEVEL_CATALOG and got.event.code == "svc.user.viewed"


def test_FR_53_a_denied_or_failed_request_says_so_in_the_message() -> None:
    denied = base_doc(http={"response": {"status_code": 403}})
    enrich(denied, Described(update_def(), LEVEL_DECORATOR), None, lang="uz", service="svc", redact_keys=KEYS)
    assert denied["message"].endswith(" — rad etildi")
    failed = base_doc(http={"response": {"status_code": 500}})
    enrich(failed, Described(update_def(), LEVEL_DECORATOR), None, lang="uz", service="svc", redact_keys=KEYS)
    assert failed["message"].endswith(" — xato")
    ok = base_doc()
    enrich(ok, Described(update_def(), LEVEL_DECORATOR), None, lang="uz", service="svc", redact_keys=KEYS)
    assert " — " not in ok["message"]


def test_FR_54_oversized_detail_and_before_after_are_truncated() -> None:
    import json as _json

    bag = AuditBag()
    bag.detail["ids"] = list(range(200_000))
    bag.before = {"bio": "a"}
    bag.after = {"bio": "x" * 5_000_000}
    bag.diff = compute_diff({"bio": "a"}, {"bio": "x" * 5_000_000})
    doc = enrich(base_doc(), Described(update_def(), LEVEL_DECORATOR), bag, lang="uz", service="svc", redact_keys=KEYS)
    assert len(_json.dumps(doc)) < 100_000
    assert doc["audit"]["detail"] == {"_truncated": True}
    assert doc["audit"]["changes"]["after"] == {"_truncated": True}
    assert doc["audit"]["changes"]["before"] == {"bio": "a"}


def test_FR_54_detail_with_too_many_distinct_keys_is_truncated_not_raised() -> None:
    bag = AuditBag()
    bag.detail.update({f"k{i}": i for i in range(300)})
    doc = enrich(base_doc(), Described(update_def(), LEVEL_DECORATOR), bag, lang="uz", service="svc", redact_keys=KEYS)
    assert doc["audit"]["detail"] == {"_truncated": True}


def test_round2_query_text_does_not_leak_redacted_values() -> None:
    """audit.query.text was rendered from the raw clauses in audit.query()
    (review: text leaks what normalized[].value redacts)."""
    from audit_logging.semantic.context import audit, close_bag, current_bag, open_bag

    token = open_bag()
    try:
        audit.query([("password", "=", "hunter2"), ("token", "=", "abc.def"), ("region", "=", "Toshkent")])
        bag = current_bag()
    finally:
        close_bag(token)
    doc = enrich(base_doc(), Described(update_def(), LEVEL_CATALOG), bag, lang="uz", service="s", redact_keys=KEYS)
    query = doc["audit"]["query"]
    assert [c["value"] for c in query["normalized"]] == [REDACTED, REDACTED, "Toshkent"]
    assert "hunter2" not in query["text"] and "abc.def" not in query["text"]
    assert "Toshkent" in query["text"] and REDACTED in query["text"]


def test_round2_caller_supplied_query_text_is_kept() -> None:
    bag = AuditBag(query_text="custom sql")
    doc = enrich(base_doc(), Described(update_def(), LEVEL_CATALOG), bag, lang="uz", service="s", redact_keys=KEYS)
    assert doc["audit"]["query"]["text"] == "custom sql"


def test_round2_detail_target_id_honours_redact_keys() -> None:
    event = update_def(target=TargetSpec("key", id="detail.api_key"))
    bag = AuditBag(detail={"api_key": "sk-live-123"})
    doc = enrich(base_doc(), Described(event, LEVEL_CATALOG), bag, lang="uz", service="s", redact_keys=KEYS)
    assert doc["audit"]["target"]["id"] == REDACTED
    assert "sk-live-123" not in doc["message"]
