"""Query normalisation helpers (PLAN §17.2). OWNER: agent H.

    audit.query([("region", "eq", "Toshkent"), ("age", "between", [18, 30])],
                text="region = Toshkent AND age 18..30", datasource="clickhouse",
                tables=["persons"], labels={"region": "Viloyat"})

Clauses may be tuples (field, operator, value[, logic[, group]]), dicts with those
keys, or QueryClause. Operators outside QUERY_OPERATORS are mapped by ALIASES
("=", "==" -> eq; "!=" -> ne; ">" -> gt; ">=" -> gte; "<" -> lt; "<=" -> lte;
"like"/"ilike" -> contains; "IN" -> in ...) or dropped (counted in the result).
Values are stringified for storage (lists joined with ", "), each capped at 256 chars.
At most 100 clauses are kept.
"""

from __future__ import annotations

import itertools
from typing import Any, Iterable, Mapping

from .model import QUERY_OPERATORS, QueryClause

MAX_CLAUSES = 100
MAX_VALUE_LEN = 256
#: Items looked at in total (kept + dropped); the rest is ignored unseen.
MAX_SCAN = 1000

ALIASES: dict[str, str] = {
    "=": "eq", "==": "eq", "equals": "eq",
    "!=": "ne", "<>": "ne",
    ">": "gt", ">=": "gte", "<": "lt", "<=": "lte",
    "like": "contains", "ilike": "contains", "icontains": "contains",
    "not in": "not_in", "nin": "not_in",
    "startswith": "starts_with", "endswith": "ends_with",
    "range": "between",
}

_SYMBOLS = {
    "eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<=",
    "in": "in", "not_in": "not in", "contains": "like",
}
_JOINERS = {"and": "VA", "or": "YOKI"}


def _cap(text: str) -> str:
    return text[:MAX_VALUE_LEN]


def _scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value[:MAX_VALUE_LEN * 4]).decode("utf-8", "replace")
    if isinstance(value, str):
        return value[:MAX_VALUE_LEN]
    return str(value)  # huge ints raise ValueError -> the clause is dropped


def _value(value: Any) -> str:
    if isinstance(value, (list, tuple, set, frozenset)):
        return _cap(", ".join(_scalar(v) for v in itertools.islice(value, MAX_VALUE_LEN)))
    return _cap(_scalar(value))


def _operator(op: Any) -> str | None:
    if not isinstance(op, str):
        return None
    key = " ".join(op.lower().split())
    return key if key in QUERY_OPERATORS else ALIASES.get(key)


def _logic(logic: Any) -> str:
    return "or" if isinstance(logic, str) and logic.strip().lower() in ("or", "yoki", "||") else "and"


def _group(group: Any) -> int:
    return group if isinstance(group, int) and not isinstance(group, bool) and group >= 0 else 0


def _one(item: Any, labels: Mapping[str, str]) -> QueryClause | None:
    field: Any
    op: Any
    value: Any
    logic: Any
    group: Any
    label: Any = None
    if isinstance(item, QueryClause):
        field, op, value, logic, group, label = (
            item.field, item.operator, item.value, item.logic, item.group, item.label)
    elif isinstance(item, Mapping):
        field, op, value = item.get("field"), item.get("operator"), item.get("value")
        logic, group, label = item.get("logic"), item.get("group"), item.get("label")
    elif isinstance(item, tuple) and 3 <= len(item) <= 5:
        field, op, value = item[0], item[1], item[2]
        logic = item[3] if len(item) > 3 else None
        group = item[4] if len(item) > 4 else 0
    else:
        return None
    operator = _operator(op)
    if not isinstance(field, str) or not field or operator is None:
        return None
    field = _cap(field)
    if not isinstance(label, str) or not label:
        label = labels.get(field)
    return QueryClause(
        field=field,
        operator=operator,
        value=_value(value),
        label=_cap(label) if isinstance(label, str) and label else None,
        logic=_logic(logic),
        group=_group(group),
    )


def normalize_clauses(
    clauses: Iterable[Any], labels: Mapping[str, str] | None = None
) -> tuple[list[QueryClause], int]:
    """(kept clauses with labels applied, number dropped). Never raises."""
    kept: list[QueryClause] = []
    dropped = 0
    try:
        if not isinstance(labels, Mapping):
            labels = {}
        if isinstance(clauses, (QueryClause, Mapping)):
            clauses = [clauses]
        elif isinstance(clauses, (str, bytes, bytearray)):
            return kept, 1
        for item in itertools.islice(iter(clauses), MAX_SCAN):
            if len(kept) >= MAX_CLAUSES:
                dropped += 1
                continue
            try:
                clause = _one(item, labels)
            except Exception:  # noqa: BLE001 - request path never raises
                clause = None
            if clause is None:
                dropped += 1
            else:
                kept.append(clause)
    except Exception:  # noqa: BLE001 - not iterable, or the iterator raised
        pass
    return kept, dropped


def _clause_text(c: QueryClause) -> str:
    name = c.label or c.field
    value = str(c.value)
    if c.operator == "between":
        low, sep, high = value.partition(", ")
        return f"{name} {low}..{high}" if sep else f"{name} {value}"
    if c.operator == "exists":
        return f"{name} exists"
    if c.operator in ("in", "not_in"):
        return f"{name} {_SYMBOLS[c.operator]} ({value})"
    return f"{name} {_SYMBOLS.get(c.operator, c.operator)} {value}"


def render_text(clauses: Iterable[QueryClause]) -> str:
    """One-line human rendering, e.g. "Viloyat = Toshkent VA Yosh 18..30" (Uzbek joiners VA / YOKI)."""
    try:
        items = [c for c in itertools.islice(clauses, MAX_SCAN) if isinstance(c, QueryClause)]
        runs = [list(g) for _, g in itertools.groupby(items[:MAX_CLAUSES], key=lambda c: c.group)]
        parts: list[str] = []
        for run in runs:
            text = " ".join(
                (f"{_JOINERS.get(c.logic, 'VA')} " if i else "") + _clause_text(c)
                for i, c in enumerate(run)
            )
            if len(runs) > 1 and len(run) > 1:
                text = f"({text})"
            if parts:
                text = f"{_JOINERS.get(run[0].logic, 'VA')} {text}"
            parts.append(text)
        return " ".join(parts)
    except Exception:  # noqa: BLE001 - request path never raises
        return ""
