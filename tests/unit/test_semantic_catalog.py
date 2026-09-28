"""Catalog file — Level 2 description (FR-50). Owned by agent A."""

from __future__ import annotations

import builtins
import json
from pathlib import Path
from typing import Any

import pytest

from audit_logging.semantic.catalog import load_catalog, parse_catalog
from audit_logging.semantic.model import LEVEL_CATALOG, TargetSpec

ENTRY: dict[str, Any] = {
    "route": "delete /users/{user_id}",
    "code": "admin.user.deleted",
    "uz": "{actor} «{target}» foydalanuvchisini o'chirdi",
    "ru": "{actor} удалил пользователя «{target}»",
    "category": "admin",
    "risk": "critical",
    "target": {"type": "user", "id": "path.user_id"},
    "diff": True,
    "description": "Delete a user",
}


def _entry(**changes: Any) -> dict[str, object]:
    entry = dict(ENTRY)
    for key, value in changes.items():
        if value is None:
            entry.pop(key, None)
        else:
            entry[key] = value
    return entry


def test_FR_50_catalog_happy_path() -> None:
    catalog = parse_catalog([_entry(), _entry(route="GET /users", code="admin.user.listed", target=None)])
    event = catalog[("DELETE", "/users/{user_id}")]
    assert event.level == LEVEL_CATALOG
    assert event.code == "admin.user.deleted"
    assert event.templates == {"uz": ENTRY["uz"], "ru": ENTRY["ru"]}
    assert event.target == TargetSpec("user", id="path.user_id")
    assert event.diff is True
    assert event.sensitivity == "internal"
    assert event.description == "Delete a user"
    assert catalog[("GET", "/users")].target is None


@pytest.mark.parametrize(
    "changes",
    [
        {"route": None},
        {"route": "/users"},
        {"route": "DELETE users"},
        {"route": 5},
        {"code": "deleted"},
        {"code": None},
        {"uz": None},
        {"uz": "{actor} {secret}"},
        {"category": "nope"},
        {"risk": "extreme"},
        {"sensitivity": "top"},
        {"target": {"type": "user", "id": "body.x"}},
        {"target": "user"},
        {"target": {"id": "path.user_id"}},
        {"diff": "yes"},
        {"colour": "red"},
    ],
)
def test_FR_50_bad_entry_names_index_and_source(changes: dict[str, Any]) -> None:
    good = _entry(route="GET /ok")
    with pytest.raises(ValueError, match=r"^cat\.json: entry 1: "):
        parse_catalog([good, _entry(**changes)], source="cat.json")


def test_FR_50_non_mapping_entry_and_non_list() -> None:
    with pytest.raises(ValueError, match="entry 0"):
        parse_catalog(["GET /x"])  # type: ignore[list-item]
    with pytest.raises(ValueError, match="list"):
        parse_catalog({"route": "GET /x"})  # type: ignore[arg-type]


def test_FR_50_duplicate_key_is_error() -> None:
    with pytest.raises(ValueError, match=r"<memory>: entry 1: duplicate route DELETE /users/\{user_id\}"):
        parse_catalog([_entry(), _entry(route="DELETE  /users/{user_id}", code="admin.user.removed")])


def test_FR_50_load_empty_path() -> None:
    assert load_catalog(None) == {}
    assert load_catalog("") == {}


def test_FR_50_load_json(tmp_path: Path) -> None:
    path = tmp_path / "audit_catalog.json"
    path.write_text(json.dumps([ENTRY], ensure_ascii=False), encoding="utf-8")
    assert list(load_catalog(str(path))) == [("DELETE", "/users/{user_id}")]


def test_FR_50_load_errors(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot read"):
        load_catalog(str(tmp_path / "missing.json"))
    bad = tmp_path / "bad.json"
    bad.write_text("[{", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_catalog(str(bad))
    txt = tmp_path / "cat.txt"
    txt.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="json, .yaml or .yml"):
        load_catalog(str(txt))
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps([_entry(risk="extreme")]), encoding="utf-8")
    with pytest.raises(ValueError, match=f"{wrong}: entry 0"):
        load_catalog(str(wrong))


def test_FR_50_load_yaml(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    path = tmp_path / "audit_catalog.yml"
    path.write_text(
        '- route: "DELETE /users/{user_id}"\n'
        "  code: admin.user.deleted\n"
        "  uz: \"{actor} «{target}» foydalanuvchisini o'chirdi\"\n"
        "  category: admin\n"
        "  risk: critical\n"
        "  target: {type: user, id: path.user_id}\n",
        encoding="utf-8",
    )
    assert load_catalog(str(path))[("DELETE", "/users/{user_id}")].target == TargetSpec("user", "path.user_id")
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    assert load_catalog(str(empty)) == {}


def test_FR_50_yaml_without_pyyaml_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "audit_catalog.yaml"
    path.write_text("[]", encoding="utf-8")
    real_import = builtins.__import__

    def no_yaml(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "yaml":
            raise ImportError("no yaml")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_yaml)
    with pytest.raises(ValueError, match="needs PyYAML"):
        load_catalog(str(path))
