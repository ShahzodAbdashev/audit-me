"""Level 3 derivation (FR-50, FR-52): readable, brace-free Uzbek from the route alone."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from audit_logging.semantic.derive import Labels, default_labels, derive, load_labels
from audit_logging.semantic.model import LEVEL_DERIVED, placeholders_of

L = default_labels()

ROUTES = [
    ("GET", "/api/v1/fortress-console/departments"),
    ("GET", "/api/v1/users/{user_id}"),
    ("POST", "/users"),
    ("PUT", "/users/{user_id:int}"),
    ("PATCH", "/settings"),
    ("DELETE", "/users/{id}"),
    ("POST", "/users/{id}/block"),
    ("POST", "/users/{id}/unblock"),
    ("GET", "/reports/export"),
    ("GET", "/files/{id}/download"),
    ("POST", "/files/upload"),
    ("POST", "/users/search"),
    ("POST", "/auth/login"),
    ("POST", "/logout"),
    ("GET", "/dashboard"),
    ("GET", "/"),
    ("GET", ""),
    ("GET", "unmatched"),
    ("OPTIONS", "/weird-thing"),
    ("get", "/v2/cars/{car_id}/history"),
    ("GET", "/{a}/{b}"),
    ("GET", "/api/{x}{y}/a{b"),
    ("BREW", "/" + "x/" * 5000),
]


def _sentence(method: str, route: str) -> str:
    return derive("users-adminka", method, route, labels=L).templates["uz"]


@pytest.mark.parametrize(("method", "route"), ROUTES)
def test_FR_52_every_derived_template_validates_and_is_brace_free(method: str, route: str) -> None:
    event = derive("users-adminka", method, route, labels=L, description="API call.")
    event.validate()
    assert event.level == LEVEL_DERIVED
    assert event.description == "API call."
    sentence = event.templates["uz"]
    assert placeholders_of(sentence) <= {"actor", "object"}
    stripped = sentence.replace("{actor}", "").replace("{object}", "")
    assert "{" not in stripped and "}" not in stripped and "/" not in stripped
    assert "API call" not in sentence  # description never becomes the sentence


def test_FR_52_derive_is_deterministic() -> None:
    for method, route in ROUTES:
        a = derive("svc", method, route, labels=L)
        b = derive("svc", method, route, labels=L)
        assert a == b


def test_FR_50_list_vs_single_get() -> None:
    lst = derive("users-adminka", "GET", "/api/v1/fortress-console/departments", labels=L)
    one = derive("users-adminka", "GET", "/api/v1/users/{user_id}", labels=L)
    assert lst.code == "users_adminka.department.listed"
    assert lst.templates["uz"] == "{actor} bo'limlar ro'yxatini ko'rdi"
    assert one.code == "users_adminka.user.viewed"
    assert one.templates["uz"] == "{actor} foydalanuvchini ko'rdi"
    assert one.target is not None and one.target.id == "path.user_id"


def test_FR_50_singleton_get_is_viewed_not_listed() -> None:
    assert _sentence("GET", "/dashboard") == "{actor} boshqaruv panelini ko'rdi"
    assert derive("s", "GET", "/api/v1/stats", labels=L).code == "s.statistics.viewed"


def test_FR_50_method_verbs() -> None:
    assert _sentence("POST", "/users") == "{actor} foydalanuvchi yaratdi"
    assert _sentence("PUT", "/users/{user_id:int}") == "{actor} foydalanuvchini tahrirladi"
    assert _sentence("DELETE", "/users/{id}") == "{actor} foydalanuvchini o'chirdi"
    assert derive("s", "OPTIONS", "/users", labels=L).code == "s.user.requested"


def test_FR_50_trailing_action_segment_wins() -> None:
    blocked = derive("s", "POST", "/users/{id}/block", labels=L)
    assert blocked.code == "s.user.blocked"
    assert blocked.templates["uz"] == "{actor} foydalanuvchini blokladi"
    assert derive("s", "GET", "/reports/export", labels=L).templates["uz"] == (
        "{actor} hisobotlarni eksport qildi"
    )
    assert derive("s", "GET", "/files/{id}/download", labels=L).code == "s.file.downloaded"


def test_FR_50_version_and_prefix_segments_are_skipped() -> None:
    assert derive("s", "GET", "/api/v3/roles", labels=L).code == "s.role.listed"
    assert derive("s", "GET", "/v2/cars/{car_id}/history", labels=L).code == "s.car.viewed"


def test_FR_52_unknown_segment_in_guillemets_never_the_uri() -> None:
    sentence = _sentence("GET", "/api/v1/weird-thing/{x}")
    assert sentence == "{actor} «weird-thing»ni ko'rdi"
    assert "/api" not in sentence


def test_FR_52_unmatched_route_still_yields_a_sentence() -> None:
    event = derive("s", "GET", "unmatched", labels=L)
    event.validate()
    assert event.code == "s.unmatched.requested"
    assert event.templates["uz"] == "{actor} noma'lum manzilga so'rov yubordi"


def test_FR_50_category_rules() -> None:
    def cat(method: str, route: str) -> str:
        return derive("s", method, route, labels=L).category

    assert cat("GET", "/users") == "read"
    assert cat("POST", "/users") == "write"
    assert cat("GET", "/reports/export") == "export"
    assert cat("GET", "/export/{id}/users") == "export"
    assert cat("POST", "/users/search") == "search"
    assert cat("POST", "/auth/login") == "auth"
    assert cat("POST", "/logout") == "auth"
    assert cat("POST", "/tokens/refresh") == "auth"


def test_FR_50_risk_rules_and_floor() -> None:
    def risk(method: str, route: str, floor: str = "low") -> str:
        return derive("s", method, route, labels=L, risk_floor=floor).risk

    assert risk("GET", "/users") == "low"
    assert risk("POST", "/users") == "normal"
    assert risk("DELETE", "/users/{id}") == "high"
    assert risk("GET", "/reports/export") == "high"
    assert risk("GET", "/users", "normal") == "normal"
    assert risk("GET", "/users", "critical") == "critical"
    assert risk("DELETE", "/users/{id}", "normal") == "high"
    assert risk("GET", "/users", "bogus") == "normal"  # bad floor never raises
    assert derive("s", "GET", "/users", labels=L).risk == "normal"  # default floor


def test_FR_50_service_name_sanitised_to_domain() -> None:
    assert derive("Users-Adminka", "GET", "/users", labels=L).code == "users_adminka.user.listed"
    assert derive("", "GET", "/users", labels=L).code.startswith("service.")


def test_builtin_labels_cover_common_segments_and_verbs() -> None:
    for seg in ["users", "roles", "departments", "permissions", "profiles", "phones", "reports",
                "files", "documents", "logs", "search", "settings", "notifications", "devices",
                "orders", "tokens", "sessions", "statistics", "dashboard", "cars", "border",
                "history", "map", "graph", "timeline"]:
        assert L.objects[seg]["uz"], seg
    for verb in ["viewed", "listed", "created", "updated", "deleted", "exported", "downloaded",
                 "searched", "blocked", "unblocked", "logged_in", "logged_out", "uploaded"]:
        assert L.verbs[verb]["uz"], verb
    assert L.fields["role_id"] == "Rol"
    for entry in (*L.objects.values(), *L.verbs.values()):
        assert not re.search(r"[{}/]", "".join(entry.values()))


def test_load_labels_overlay_adds_and_overrides(tmp_path: Path) -> None:
    path = tmp_path / "labels.json"
    path.write_text(json.dumps({
        "objects": {"users": {"uz": "xodim"}, "numbers": {"singular": "number", "uz": "raqam"},
                    "ownerchecks": {"singular": "ownercheck", "uz": "egalik tekshiruvi"}},
        "verbs": {"scored": {"uz": "baholadi", "form": "acc", "segments": "score"}},
        "fields": {"role_id": "Lavozim"},
    }), encoding="utf-8")
    labels = load_labels(str(path))
    users = {k: v for k, v in labels.objects["users"].items() if not k.startswith(("ru", "en"))}
    assert users == {"singular": "user", "uz": "xodim"}  # merged, not replaced (ru/en keys kept)
    assert labels.fields["role_id"] == "Lavozim"
    assert "departments" in labels.objects  # built-ins kept
    assert derive("s", "GET", "/users", labels=labels).templates["uz"] == "{actor} xodimlar ro'yxatini ko'rdi"
    assert derive("s", "POST", "/ownerchecks/{id}/score", labels=labels).code == "s.ownercheck.scored"
    assert L.objects["users"]["uz"] == "foydalanuvchi"  # default table untouched


def test_load_labels_none_is_builtin_and_bad_file_fails_at_startup(tmp_path: Path) -> None:
    assert load_labels(None) is default_labels()
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"objects": {"users": "xodim"}}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_labels(str(bad))


def test_derive_with_empty_labels_still_valid() -> None:
    event = derive("s", "GET", "/users/{id}", labels=Labels())
    event.validate()
    assert event.templates["uz"] == "{actor} «users»ni so'rov yubordi"


def test_FR_52_camel_case_path_param_keeps_its_exact_name() -> None:
    # document.py stores path_params under the name as written; lowercasing broke the lookup.
    event = derive("svc", "GET", "/users/{userId:int}", labels=L)
    assert event.target is not None and event.target.id == "path.userId"
