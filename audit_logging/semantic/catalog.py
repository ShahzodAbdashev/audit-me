"""Catalog file — Level 2 description (FR-50). OWNER: agent A.

Format (JSON always; YAML only if PyYAML is importable — no new hard dependency):

    [{"route": "DELETE /users/{user_id}", "code": "admin.user.deleted",
      "uz": "{actor} «{target}» foydalanuvchisini o'chirdi", "ru": "...", "en": "...",
      "category": "admin", "risk": "critical", "sensitivity": "internal",
      "target": {"type": "user", "id": "path.user_id"}, "diff": false,
      "description": "..."}]

``route`` is ``"<METHOD> <route template>"`` exactly as ``scope["route"].path``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import LEVEL_CATALOG, EventDef, TargetSpec

Catalog = dict[tuple[str, str], EventDef]   # (METHOD upper, route template) -> def (level "catalog")


def parse_catalog(entries: list[dict[str, object]], *, source: str = "<memory>") -> Catalog:
    """Validate every entry; raise ValueError naming the entry index and ``source``
    on the first bad one. Duplicate (method, route) keys are an error."""
    if not isinstance(entries, list):
        raise ValueError(f"{source}: catalog must be a list of entries")
    catalog: Catalog = {}
    for index, entry in enumerate(entries):
        try:
            key, event = _parse_entry(entry)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{source}: entry {index}: {exc}") from None
        if key in catalog:
            raise ValueError(f"{source}: entry {index}: duplicate route {key[0]} {key[1]}")
        catalog[key] = event
    return catalog


_KEYS = frozenset({
    "route", "code", "uz", "ru", "en", "category", "risk",
    "sensitivity", "target", "diff", "description",
})


def _str(entry: dict[str, Any], key: str, *, required: bool = False) -> str | None:
    value = entry.get(key)
    if value is None:
        if required:
            raise ValueError(f"'{key}' is required")
        return None
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    return value


def _parse_entry(entry: object) -> tuple[tuple[str, str], EventDef]:
    if not isinstance(entry, dict):
        raise ValueError("entry must be a mapping")
    unknown = set(entry) - _KEYS
    if unknown:
        raise ValueError(f"unknown keys {sorted(map(str, unknown))}")
    route = _str(entry, "route", required=True) or ""
    method, _, path = route.strip().partition(" ")
    path = path.strip()
    if not method.isalpha() or not path.startswith("/"):
        raise ValueError(f"route must be 'METHOD /path': {route!r}")

    target: TargetSpec | None = None
    raw_target = entry.get("target")
    if raw_target is not None:
        if not isinstance(raw_target, dict) or set(raw_target) - {"type", "id"}:
            raise ValueError("'target' must be a mapping with 'type' and optional 'id'")
        target = TargetSpec(type=_str(raw_target, "type", required=True) or "", id=_str(raw_target, "id"))

    diff = entry.get("diff", False)
    if not isinstance(diff, bool):
        raise ValueError("'diff' must be a boolean")

    templates = {lang: text for lang in ("uz", "ru", "en") if (text := _str(entry, lang)) is not None}
    event = EventDef(
        code=_str(entry, "code", required=True) or "",
        templates=templates,
        category=_str(entry, "category", required=True) or "",
        risk=_str(entry, "risk", required=True) or "",
        sensitivity=_str(entry, "sensitivity") or "internal",
        target=target,
        diff=diff,
        description=_str(entry, "description"),
        level=LEVEL_CATALOG,
    )
    event.validate()
    return (method.upper(), path), event


def load_catalog(path: str | None) -> Catalog:
    """``None`` or ``""`` -> empty catalog. ``.json`` / ``.yaml`` / ``.yml`` by suffix.
    A missing file or a YAML file without PyYAML raises ValueError (fail at startup)."""
    if not path:
        return {}
    file = Path(path)
    suffix = file.suffix.lower()
    if suffix not in (".json", ".yaml", ".yml"):
        raise ValueError(f"{path}: catalog must be .json, .yaml or .yml")
    try:
        text = file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"{path}: cannot read catalog: {exc}") from None
    data: Any
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: invalid JSON: {exc}") from None
    else:
        try:
            import yaml  # type: ignore[import-untyped,unused-ignore]
        except ImportError:
            raise ValueError(f"{path}: YAML catalog needs PyYAML; install it or use .json") from None
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"{path}: invalid YAML: {exc}") from None
    return parse_catalog([] if data is None else data, source=path)
