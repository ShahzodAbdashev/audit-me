"""Sentence rendering (FR-53). OWNER: agent C.

render() never raises and never leaves a '{' in its output: a missing value
renders as a neutral word (uz: "noma'lum"). Diff entries append
" — Rol: Operator → Admin; Bo'lim: — → Moliya" (None renders as "—").
"""

from __future__ import annotations

import string
from typing import Any, Mapping, Sequence

from .model import DEFAULT_LANG, DiffEntry, EventDef

#: result -> {lang: word}
RESULT_WORDS: dict[str, dict[str, str]] = {
    "success": {"uz": "muvaffaqiyatli", "ru": "успешно", "en": "success"},
    "failure": {"uz": "xato", "ru": "ошибка", "en": "failed"},
    "denied": {"uz": "rad etildi", "ru": "отказано", "en": "denied"},
    "disconnected": {"uz": "uzildi", "ru": "прервано", "en": "disconnected"},
}
MISSING: dict[str, str] = {"uz": "noma'lum", "ru": "неизвестно", "en": "unknown"}


#: Longest rendered value; ``message`` is keyword(512) in the mapping.
MAX_VALUE_LEN = 200

_FORMATTER = string.Formatter()


def outcome_suffix(result: str, lang: str = DEFAULT_LANG) -> str:
    """" — rad etildi" / " — xato" / " — uzildi" for a non-success result, else "" (PLAN §6)."""
    words = RESULT_WORDS.get(result)
    if result == "success" or words is None:
        return ""
    return " — " + (words.get(lang) or words[DEFAULT_LANG])


def template_for(event: EventDef, lang: str) -> str:
    """event.templates[lang], falling back to the DEFAULT_LANG template."""
    t = event.templates
    return t.get(lang) or t.get(DEFAULT_LANG) or next(iter(t.values()), "")


def _text(value: Any, missing: str) -> str:
    if value is None or value == "":
        return missing
    if isinstance(value, (list, tuple, set, frozenset)):
        s = ", ".join(str(v) for v in value) or missing
    else:
        s = str(value)
    return s if len(s) <= MAX_VALUE_LEN else s[: MAX_VALUE_LEN - 1] + "…"


def _lookup(name: str, params: Mapping[str, Any], lang: str, missing: str) -> str:
    if name.startswith("detail."):
        detail = params.get("detail")
        value = detail.get(name[len("detail."):]) if isinstance(detail, Mapping) else None
    else:
        value = params.get(name)
        if name == "result" and isinstance(value, str) and value in RESULT_WORDS:
            words = RESULT_WORDS[value]
            value = words.get(lang) or words[DEFAULT_LANG]
    return _text(value, missing)


def _debrace(s: str) -> str:
    # ponytail: braces become parentheses so a value like "{x}" stays readable and inert.
    return s.replace("{", "(").replace("}", ")")


def render(
    event: EventDef,
    params: Mapping[str, Any],
    *,
    lang: str = "uz",
    diff: Sequence[DiffEntry] = (),
) -> str:
    """params keys: actor, target, count, service, object, and 'detail' -> mapping for {detail.x}."""
    try:
        missing = MISSING.get(lang) or MISSING[DEFAULT_LANG]
        template = template_for(event, lang)
        parts: list[str] = []
        try:
            for literal, name, _spec, _conv in _FORMATTER.parse(template):
                parts.append(literal)
                if name is not None:
                    parts.append(_lookup(name, params, lang, missing))
        except ValueError:  # malformed template ("{x", "}"): show it as text
            parts = [template]
        out = "".join(parts)
        if diff:
            dash = "—"
            items = (
                f"{_text(d.label or d.field, dash)}: {_text(d.old, dash)} → {_text(d.new, dash)}"
                for d in diff
            )
            out += " — " + "; ".join(items)
        return _debrace(out)
    except Exception:
        try:
            return _debrace(str(event.code))
        except Exception:
            return MISSING[DEFAULT_LANG]
