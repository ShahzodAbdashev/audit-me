"""Round-2 #11: derived EventDefs carry ru / en templates from labels_ru/en.json."""

from __future__ import annotations

import json
import re
from importlib import resources

import pytest

from audit_logging.semantic.derive import Labels, default_labels, derive
from audit_logging.semantic.model import placeholders_of
from audit_logging.semantic.render import render

L = default_labels()


def _t(method: str, route: str) -> dict[str, str]:
    return dict(derive("s", method, route, labels=L).templates)


@pytest.mark.parametrize(("method", "route", "ru", "en"), [
    ("GET", "/api/v1/departments", "{actor} просмотрел список отделов", "{actor} viewed the list of departments"),
    ("GET", "/users/{id}", "{actor} просмотрел пользователя", "{actor} viewed user"),
    ("POST", "/users", "{actor} создал пользователя", "{actor} created user"),
    ("DELETE", "/users/{id}", "{actor} удалил пользователя", "{actor} deleted user"),
    ("POST", "/users/{id}/block", "{actor} заблокировал пользователя", "{actor} blocked user"),
    ("GET", "/reports/export", "{actor} экспортировал отчёты", "{actor} exported reports"),
    ("POST", "/auth/login", "{actor} вошёл в систему", "{actor} logged in"),
    ("GET", "/dashboard", "{actor} просмотрел панель управления", "{actor} viewed dashboard"),
    ("GET", "unmatched", "{actor} отправил запрос на неизвестный адрес",
     "{actor} sent a request to an unknown address"),
    ("GET", "/weird/{x}", "{actor} просмотрел «weird»", "{actor} viewed «weird»"),
])
def test_ru_en_sentences(method: str, route: str, ru: str, en: str) -> None:
    t = _t(method, route)
    assert (t["ru"], t["en"]) == (ru, en)
    derive("s", method, route, labels=L).validate()


def test_uz_unchanged_and_only_placeholders_are_actor() -> None:
    t = _t("GET", "/api/v1/departments")
    assert t["uz"] == "{actor} bo'limlar ro'yxatini ko'rdi"
    for text in t.values():
        assert placeholders_of(text) == {"actor"}


def test_lang_absent_from_labels_means_no_template_and_render_falls_back_to_uz() -> None:
    uz_only = Labels(objects={"users": {"singular": "user", "uz": "foydalanuvchi"}},
                     verbs={"deleted": {"uz": "o'chirdi"}})
    event = derive("s", "DELETE", "/users/{id}", labels=uz_only)
    assert set(event.templates) == {"uz"}
    assert render(event, {"actor": "A"}, lang="ru") == "A foydalanuvchini o'chirdi"


def test_render_picks_the_language() -> None:
    event = derive("s", "DELETE", "/users/{id}", labels=L)
    assert render(event, {"actor": "Sardor"}, lang="ru") == "Sardor удалил пользователя"
    assert render(event, {"actor": "Sardor"}, lang="en") == "Sardor deleted user"


def test_tables_cover_every_uz_entry_and_carry_no_braces() -> None:
    uz = json.loads(resources.files("audit_logging.semantic").joinpath("labels_uz.json").read_text("utf-8"))
    for lang in ("ru", "en"):
        table = json.loads(resources.files("audit_logging.semantic")
                           .joinpath(f"labels_{lang}.json").read_text("utf-8"))
        assert set(table["objects"]) == set(uz["objects"]), lang
        assert set(table["verbs"]) == set(uz["verbs"]), lang
        for entry in (*table["objects"].values(), *table["verbs"].values()):
            assert all(k.startswith(lang) for k in entry), entry
            assert not re.search(r"[{}/]", "".join(entry.values()))


def test_new_common_uz_words() -> None:
    assert _t("GET", "/jobs")["uz"] == "{actor} vazifalar ro'yxatini ko'rdi"
    assert _t("POST", "/tokens/{id}/revoke")["uz"] == "{actor} tokenni bekor qildi"
    assert _t("GET", "/activity")["uz"] == "{actor} faollikni ko'rdi"
