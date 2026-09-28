"""Query breakdown — PLAN §17.1 #2. Owned by agent H."""

from __future__ import annotations

from typing import Any, Iterator

import pytest

from audit_logging.semantic.model import QUERY_OPERATORS, QueryClause
from audit_logging.semantic.query import (
    ALIASES, MAX_CLAUSES, MAX_VALUE_LEN, normalize_clauses, render_text,
)


def test_docstring_example() -> None:
    kept, dropped = normalize_clauses(
        [("region", "eq", "Toshkent"), ("age", "between", [18, 30])],
        labels={"region": "Viloyat", "age": "Yosh"},
    )
    assert dropped == 0
    assert kept == [
        QueryClause("region", "eq", "Toshkent", label="Viloyat"),
        QueryClause("age", "between", "18, 30", label="Yosh"),
    ]
    assert render_text(kept) == "Viloyat = Toshkent VA Yosh 18..30"


@pytest.mark.parametrize("op, want", [
    ("=", "eq"), ("==", "eq"), ("!=", "ne"), ("<>", "ne"), (">", "gt"), (">=", "gte"),
    ("<", "lt"), ("<=", "lte"), ("like", "contains"), ("ILIKE", "contains"), ("IN", "in"),
    ("NOT IN", "not_in"), ("not  in", "not_in"), ("Between", "between"), ("eq", "eq"),
])
def test_aliases(op: str, want: str) -> None:
    kept, dropped = normalize_clauses([("f", op, 1)])
    assert (kept[0].operator, dropped) == (want, 0)


def test_every_alias_targets_the_vocabulary() -> None:
    assert set(ALIASES.values()) <= set(QUERY_OPERATORS)
    for op in QUERY_OPERATORS:
        assert normalize_clauses([("f", op, 1)])[0][0].operator == op


def test_shapes_tuple_dict_clause_and_logic_group() -> None:
    kept, dropped = normalize_clauses([
        ("a", "eq", 1, "OR", 2),
        {"field": "b", "operator": ">", "value": 5, "logic": "or", "label": "Bee"},
        QueryClause("c", "=", "x", group=1),
        {"field": "d", "operator": "eq"},  # value missing -> ""
    ], labels={"a": "Ey", "b": "ignored"})
    assert dropped == 0
    assert kept[0] == QueryClause("a", "eq", "1", label="Ey", logic="or", group=2)
    assert kept[1] == QueryClause("b", "gt", "5", label="Bee", logic="or")
    assert kept[2] == QueryClause("c", "eq", "x", group=1)
    assert kept[3].value == ""


@pytest.mark.parametrize("bad", [
    ("f", "bogus", 1), ("", "eq", 1), (None, "eq", 1), (1, "eq", 1), ("f", None, 1),
    ("f", "eq"), ("f", "eq", 1, "and", 0, "extra"), ["f", "eq", 1], "f = 1", None, 5,
    {"operator": "eq", "value": 1}, ("f", "eq", 10**5000),
])
def test_invalid_clauses_are_dropped_and_counted(bad: Any) -> None:
    kept, dropped = normalize_clauses([bad, ("ok", "eq", 1)])
    assert [c.field for c in kept] == ["ok"] and dropped == 1


def test_values_stringified_and_capped() -> None:
    kept, _ = normalize_clauses([
        ("a", "in", ["x", 2, None]), ("b", "eq", "z" * 10_000), ("c", "in", list(range(100_000))),
        ("d", "eq", b"\xffabc"), ("e", "eq", {"k": 1}), ("f" * 1000, "eq", 1),
    ])
    assert kept[0].value == "x, 2, "
    assert all(isinstance(c.value, str) and len(c.value) <= MAX_VALUE_LEN for c in kept)
    assert len(kept[5].field) == MAX_VALUE_LEN


def test_caps_at_100_clauses() -> None:
    kept, dropped = normalize_clauses([("f", "eq", i) for i in range(150)])
    assert len(kept) == MAX_CLAUSES and dropped == 50


def test_bounded_on_endless_iterator() -> None:
    def endless() -> Iterator[tuple[str, str, int]]:
        while True:
            yield ("f", "eq", 1)
    kept, dropped = normalize_clauses(endless())
    assert len(kept) == MAX_CLAUSES and dropped < 10_000


def _raising() -> Iterator[Any]:
    yield ("a", "eq", 1)
    raise RuntimeError("boom")


class _BadStr:
    def __str__(self) -> str:
        raise RuntimeError("nope")


@pytest.mark.parametrize("clauses", [
    None, 5, object(), "a=1", b"a=1", {"field": "x", "operator": "eq", "value": 1},
    _raising(), [("a", "eq", _BadStr())], [("a", "in", [_BadStr()])],
])
def test_never_raises(clauses: Any) -> None:
    kept, dropped = normalize_clauses(clauses, labels="not a mapping")  # type: ignore[arg-type]
    assert isinstance(kept, list) and isinstance(dropped, int)


def test_single_mapping_is_one_clause() -> None:
    kept, _ = normalize_clauses({"field": "x", "operator": "eq", "value": 1})
    assert kept == [QueryClause("x", "eq", "1")]


def test_render_joiners_operators_and_groups() -> None:
    cs = [
        QueryClause("pinpp", "eq", "32101801234567", label="JSHSHIR"),
        QueryClause("passport", "eq", "AA1234512", label="Passport", logic="or"),
        QueryClause("born", "gt", "1985-01-01", label="Tug'ilgan sana", group=1),
        QueryClause("r", "in", "a, b", group=1, logic="or"),
    ]
    assert render_text(cs) == (
        "(JSHSHIR = 32101801234567 YOKI Passport = AA1234512) "
        "VA (Tug'ilgan sana > 1985-01-01 YOKI r in (a, b))"
    )
    assert render_text([QueryClause("x", "exists", ""), QueryClause("y", "contains", "ab")]) \
        == "x exists VA y like ab"
    assert render_text([]) == ""


@pytest.mark.parametrize("junk", [None, 5, [None, "x", 1], _raising()])
def test_render_never_raises(junk: Any) -> None:
    assert isinstance(render_text(junk), str)
