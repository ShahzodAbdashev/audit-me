"""Level 3 — derive a readable EventDef from the route itself (FR-50, FR-52). OWNER: agent B.

Rules (PLAN-semantic-audit.md §4.3):
  domain   = service name (sanitised to snake_case)
  object   = first non-parameter path segment after skipping version/prefix
             segments (api, v1, v2, ...), singularised via the labels table
  verb     = GET -> "viewed" (list form when the route ends without a param),
             POST -> "created", PUT/PATCH -> "updated", DELETE -> "deleted";
             a trailing action segment wins (block->blocked, export->exported,
             download->downloaded, search->searched, login->logged_in, ...)
  category = GET -> read, others -> write; export/download in path -> export;
             search -> search; login/logout/token -> auth
  risk     = max(risk_floor, category default) ; sensitivity "internal"
  template = Uzbek sentence from the labels table: "{actor} <object phrase> <verb phrase>"
  level    = "derived"; the route summary/docstring goes to description, NEVER the sentence.
  ru / en  = labels_ru.json / labels_en.json overlay ``ru*`` / ``en*`` keys on the same
             entries; a language gets a template only when the verb has a word in it
             ("{actor} <verb> <object>", object keys ``<lang>`` / ``_acc`` / ``_plural`` /
             ``_plural_gen``; verb key ``<lang>_form`` pins the form, else the uz form).
A derived template contains no URI and no '{' other than known placeholders.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any

from .model import LEVEL_DERIVED, RISKS, EventDef, TargetSpec

_MAX_ROUTE = 1024
_MAX_SEGMENTS = 32
_PREFIX_RE = re.compile(r"^(api|rest|v\d+)$")
_AUTH_SEGMENTS = frozenset({"auth", "login", "logout", "token", "tokens"})
_EXTRA_LANGS = ("ru", "en")
_UNMATCHED = {
    "uz": "{actor} noma'lum manzilga so'rov yubordi",
    "ru": "{actor} отправил запрос на неизвестный адрес",
    "en": "{actor} sent a request to an unknown address",
}
_FALLBACK = {"plural_acc": "plural", "plural_gen": "plural"}
_CATEGORY_RISK = {"read": "low", "search": "low", "write": "normal", "auth": "normal", "export": "high"}


@dataclass(frozen=True)
class Labels:
    """Uzbek (and optional ru/en) words. ``objects``: segment -> {"singular": ..., "uz": ...};
    ``verbs``: verb -> {"uz": ...}; ``fields``: field -> label (for diffs).

    Optional object keys ``uz_acc`` / ``uz_plural`` / ``uz_plural_acc`` override the
    regular suffixes (-ni, -lar); ``singleton: "yes"`` marks a one-of object (dashboard)
    whose GET is "viewed", never a list. Verb keys: ``form`` (acc | plural | nom | none) picks
    the object phrase; ``segments`` (space separated) are path words that trigger it."""

    objects: dict[str, dict[str, str]] = field(default_factory=dict)
    verbs: dict[str, dict[str, str]] = field(default_factory=dict)
    fields: dict[str, str] = field(default_factory=dict)


def _section(data: Any, name: str, source: str) -> dict[str, Any]:
    value = data.get(name, {}) if isinstance(data, dict) else None
    if not isinstance(value, dict):
        raise ValueError(f"{source}: '{name}' must be a mapping")
    return value


def _merge(base: Labels, data: Any, source: str) -> Labels:
    objects = {k: dict(v) for k, v in base.objects.items()}
    verbs = {k: dict(v) for k, v in base.verbs.items()}
    for target, name in ((objects, "objects"), (verbs, "verbs")):
        for key, entry in _section(data, name, source).items():
            if not isinstance(entry, dict) or not all(isinstance(x, str) for x in entry.values()):
                raise ValueError(f"{source}: {name}.{key} must map strings to strings")
            target.setdefault(str(key), {}).update(entry)
    fields = dict(base.fields)
    for key, label in _section(data, "fields", source).items():
        if not isinstance(label, str):
            raise ValueError(f"{source}: fields.{key} must be a string")
        fields[str(key)] = label
    return Labels(objects=objects, verbs=verbs, fields=fields)


@lru_cache(maxsize=1)
def default_labels() -> Labels:
    """The built-in table shipped as ``audit_logging/semantic/labels_uz.json``."""
    labels = Labels()
    for name in ("labels_uz.json", *(f"labels_{lang}.json" for lang in _EXTRA_LANGS)):
        res = resources.files(__package__).joinpath(name)
        if name == "labels_uz.json" or res.is_file():
            labels = _merge(labels, json.loads(res.read_text(encoding="utf-8")), name)
    return labels


def load_labels(path: str | None) -> Labels:
    """Built-in table overlaid with the service's file (entries add or override)."""
    if not path:
        return default_labels()
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise ValueError(f"{path}: PyYAML is not installed; use a .json labels file") from exc
        data: Any = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    return _merge(default_labels(), data, path)


def _snake(text: str, fallback: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    if not out:
        return fallback
    return out if out[0].isalpha() else f"x_{out}"


def _object_entry(segment: str, labels: Labels) -> dict[str, str] | None:
    return labels.objects.get(segment) or labels.objects.get(segment + "s")


def _phrase(segment: str, entry: dict[str, str] | None, form: str) -> str:
    """Object words in the grammatical form a verb needs; unknown -> «segment»."""
    if entry is None or not entry.get("uz"):
        raw = "«" + re.sub(r"[{}«»]", "", segment)[:64] + "»"
        return raw + "ni" if form in ("acc", "plural_acc") else raw
    uz = entry["uz"]
    plural = entry.get("uz_plural") or uz + "lar"
    return {
        "acc": entry.get("uz_acc") or uz + "ni",
        "plural": plural,
        "plural_acc": entry.get("uz_plural_acc") or plural + "ni",
    }.get(form, uz)


def _lang_phrase(segment: str, entry: dict[str, str] | None, lang: str, form: str) -> str:
    """ru/en object words; missing forms fall back plural_* -> plural -> base; unknown -> «segment»."""
    base = (entry or {}).get(lang)
    if not base:
        return "«" + re.sub(r"[{}«»]", "", segment)[:64] + "»"
    for key in (form, _FALLBACK.get(form)):
        if key and (word := (entry or {}).get(f"{lang}_{key}")):
            return word
    return base


def _clean(text: str) -> str:
    return text.replace("{", "").replace("}", "")


def _derive(
    service: str, method: str, route: str, labels: Labels, risk_floor: str, description: str | None
) -> EventDef:
    method = method.upper()
    domain = _snake(service, "service")
    unmatched = not route.startswith("/")
    parts = [p for p in route[:_MAX_ROUTE].split("/") if p][:_MAX_SEGMENTS]
    is_param = [p.startswith("{") for p in parts]
    word_idx = [i for i, flag in enumerate(is_param) if not flag]

    actions: dict[str, str] = {}
    for verb_key, spec in labels.verbs.items():
        for seg in spec.get("segments", "").split():
            actions.setdefault(seg, verb_key)

    action_idx = word_idx[-1] if word_idx and parts[word_idx[-1]].lower() in actions else None
    if action_idx is not None:
        verb = actions[parts[action_idx].lower()]
    elif method in ("GET", "HEAD"):
        verb = "viewed"  # becomes "listed" below when the object is a collection
    else:
        verb = {"POST": "created", "PUT": "updated", "PATCH": "updated", "DELETE": "deleted"}.get(
            method, "requested"
        )
    # object: first labelled non-prefix, non-action segment, else the first such segment
    candidates = [i for i in word_idx if i != action_idx and not _PREFIX_RE.match(parts[i].lower())]
    if unmatched:
        obj_seg, obj_index = "unmatched", -1
    elif candidates:
        known = [i for i in candidates if _object_entry(parts[i].lower(), labels)]
        obj_index = (known or candidates)[0]
        obj_seg = parts[obj_index].lower()
    elif action_idx is not None:
        obj_seg, obj_index = parts[action_idx].lower(), -1
    else:
        obj_seg, obj_index = "root", -1
    entry = _object_entry(obj_seg, labels)
    singleton = entry is not None and entry.get("singleton") == "yes"
    obj_code = _snake((entry or {}).get("singular", "") or obj_seg, "item")

    following = parts[obj_index + 1:] if obj_index >= 0 else []
    param = next((p for p in following if p.startswith("{")), None)
    collection = param is None and not singleton
    if unmatched:
        verb = "requested"
    elif verb == "viewed" and action_idx is None and collection:
        verb = "listed"
    verb_entry = labels.verbs.get(verb, {})
    form = verb_entry.get("form", "acc")
    if form == "acc" and collection and obj_index >= 0:
        form = "plural_acc"
    verb_uz = re.sub(r"[{}]", "", verb_entry.get("uz", "")) or "so'rov yubordi"
    if unmatched:
        sentence = _UNMATCHED["uz"]
    elif form == "none":
        sentence = "{actor} " + verb_uz
    else:
        sentence = "{actor} " + _clean(_phrase(obj_seg, entry, form)) + " " + verb_uz
    templates = {"uz": sentence}
    for lang in _EXTRA_LANGS:
        verb_word = _clean(verb_entry.get(lang, "")).strip()
        if unmatched:
            templates[lang] = _UNMATCHED[lang]
        elif verb_word:
            lang_form = verb_entry.get(f"{lang}_form") or form  # uz form is already collection-aware
            if lang_form == "none":
                templates[lang] = "{actor} " + verb_word
            else:
                templates[lang] = "{actor} " + verb_word + " " + _clean(_lang_phrase(obj_seg, entry, lang, lang_form))

    lowered = {parts[i].lower() for i in word_idx}
    if verb in ("logged_in", "logged_out") or lowered & _AUTH_SEGMENTS:
        category = "auth"
    elif verb in ("exported", "downloaded") or lowered & {"export", "download"}:
        category = "export"
    elif verb == "searched" or "search" in lowered:
        category = "search"
    else:
        category = "read" if method in ("GET", "HEAD") else "write"
    risk = _CATEGORY_RISK[category]
    if verb == "deleted":
        risk = "high"
    floor = risk_floor if risk_floor in RISKS else "normal"
    risk = max(risk, floor, key=RISKS.index)

    target = None
    if param is not None:
        # As written: document.py keys audit.path_params by the exact name (userId, not userid).
        raw = param.strip("{}").split(":", 1)[0].strip()
        name = raw if raw.isidentifier() else _snake(raw, "id")
        target = TargetSpec(type=obj_code, id=f"path.{name}")
    return EventDef(
        code=f"{domain}.{obj_code}.{_snake(verb, 'requested')}",
        templates=templates,
        category=category,
        risk=risk,
        sensitivity="internal",
        target=target,
        description=description,
        level=LEVEL_DERIVED,
    )


def derive(
    service: str,
    method: str,
    route: str,
    *,
    labels: Labels,
    risk_floor: str = "normal",
    description: str | None = None,
) -> EventDef:
    """Pure and deterministic; the caller caches by (method, route). Never raises for
    any method/route string (an unmatched route "unmatched" still yields a sentence)."""
    try:
        return _derive(str(service), str(method), str(route), labels, risk_floor, description)
    except Exception:  # never raise into the application; a bare but valid definition
        return EventDef(
            code=f"{_snake(str(service), 'service')}.request.requested",
            templates={"uz": "{actor} so'rov yubordi"},
            category="system",
            risk=risk_floor if risk_floor in RISKS else "normal",
            description=description,
            level=LEVEL_DERIVED,
        )
