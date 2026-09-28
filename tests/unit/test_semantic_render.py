"""Sentence rendering — FR-53. Owned by agent C."""

from __future__ import annotations

from typing import Any

import pytest

from audit_logging.semantic.model import DiffEntry, EventDef
from audit_logging.semantic.render import MAX_VALUE_LEN, MISSING, render, template_for


def ev(**templates: str) -> EventDef:
    return EventDef(code="admin.user.updated", templates=templates, category="admin", risk="high")


UPDATED = ev(
    uz="{actor} «{target}» foydalanuvchisini tahrirladi",
    ru="{actor} изменил пользователя «{target}»",
)


def test_FR_53_basic_sentence() -> None:
    out = render(UPDATED, {"actor": "Sardor Karimov", "target": "Aliyev Vali"})
    assert out == "Sardor Karimov «Aliyev Vali» foydalanuvchisini tahrirladi"


def test_FR_53_diff_suffix_none_as_dash() -> None:
    diff = [DiffEntry("role_id", "Rol", "Operator", "Admin"), DiffEntry("dept", "Bo'lim", None, "Moliya")]
    out = render(UPDATED, {"actor": "S", "target": "V"}, diff=diff)
    assert out.endswith(" — Rol: Operator → Admin; Bo'lim: — → Moliya")


@pytest.mark.parametrize("params", [{}, {"actor": None, "target": ""}])
def test_FR_53_missing_values_use_neutral_word(params: dict[str, Any]) -> None:
    out = render(UPDATED, params)
    assert out == "noma'lum «noma'lum» foydalanuvchisini tahrirladi"


def test_FR_53_lang_and_unknown_lang_fallback() -> None:
    assert render(UPDATED, {"actor": "A"}, lang="ru") == f"A изменил пользователя «{MISSING['ru']}»"
    assert render(UPDATED, {"actor": "A", "target": "B"}, lang="de") == "A «B» foydalanuvchisini tahrirladi"
    assert template_for(UPDATED, "en") == UPDATED.templates["uz"]


def test_FR_53_detail_placeholders() -> None:
    e = ev(uz="{actor} {detail.n} ta ruxsat qo'shdi: {detail.perms}; {detail.absent}")
    out = render(e, {"actor": "A", "detail": {"n": 2, "perms": [12, 13]}})
    assert out == "A 2 ta ruxsat qo'shdi: 12, 13; noma'lum"
    assert render(e, {"actor": "A", "detail": "not a mapping"}).count("noma'lum") == 3


def test_FR_53_result_words() -> None:
    e = ev(uz="{actor}: {result}", en="{actor}: {result}")
    assert render(e, {"actor": "A", "result": "denied"}) == "A: rad etildi"
    assert render(e, {"actor": "A", "result": "failure"}, lang="en") == "A: failed"
    assert render(e, {"actor": "A", "result": "success"}, lang="xx") == "A: muvaffaqiyatli"


def test_FR_53_braces_in_values_are_inert_and_output_brace_free() -> None:
    out = render(UPDATED, {"actor": "{target}", "target": "{0.__class__}"})
    assert "{" not in out and "}" not in out
    assert out.startswith("(target) «(0.__class__)»")


@pytest.mark.parametrize(
    "template", ["{actor", "actor}", "{{literal}}", "{actor.name} {target[0]} {count:>9d}", "{}"]
)
def test_FR_53_odd_templates_never_raise_or_leak_braces(template: str) -> None:
    out = render(ev(uz=template), {"actor": "A", "target": "T", "count": "x"})
    assert "{" not in out and "}" not in out


def test_FR_53_long_values_are_capped() -> None:
    out = render(UPDATED, {"actor": "x" * 10_000, "target": "t"})
    assert len(out) < MAX_VALUE_LEN + 60
    assert "…" in out


def test_FR_53_unprintable_value_never_raises() -> None:
    class Bad:
        def __str__(self) -> str:
            raise RuntimeError

    out = render(UPDATED, {"actor": Bad()})
    assert "{" not in out and out
