"""Pick the EventDef for a request: decorator > catalog > derived (FR-50). OWNER: agent D."""

from __future__ import annotations

import dataclasses
import inspect
from typing import Any

from .catalog import Catalog
from .decorators import event_def_of
from .derive import Labels, derive
from .model import LEVEL_DERIVED, Described, EventDef

_UNMATCHED = "unmatched"  # the word document.ROUTE_UNMATCHED writes
_MAX_DESCRIPTION = 1024

#: Derived definitions, keyed by everything derive() depends on. The Labels
#: object is kept in the value and compared by identity, so a key can never be
#: answered from another middleware's (collected, then re-allocated) table.
# ponytail: cleared when full, not LRU; routes are server-defined, so only a pathological app fills it.
_CACHE_MAX = 4096
_CACHE: dict[tuple[str, str, str, str, int], tuple[Labels, EventDef]] = {}


def _route_path(route: Any) -> str:
    if route is None:
        return _UNMATCHED
    for attribute in ("path", "path_format"):
        value = getattr(route, attribute, None)
        if isinstance(value, str) and value:
            return value
    return _UNMATCHED


def _description(route: Any) -> str | None:
    """The route's ``summary``, else the first paragraph of the handler's docstring."""
    text = getattr(route, "summary", None)
    if not isinstance(text, str) or not text.strip():
        doc = getattr(getattr(route, "endpoint", None), "__doc__", None)
        text = inspect.cleandoc(doc).split("\n\n", 1)[0] if isinstance(doc, str) else None
    if not text or not text.strip():
        return None
    return text.strip()[:_MAX_DESCRIPTION]


def _with_description(event: EventDef, route: Any) -> EventDef:
    if event.description is not None:
        return event
    description = _description(route)
    return event if description is None else dataclasses.replace(event, description=description)


def _derived(method: str, path: str, route: Any, service: str, labels: Labels, risk_floor: str) -> EventDef:
    key = (service, method, path, risk_floor, id(labels))
    hit = _CACHE.get(key)
    if hit is not None and hit[0] is labels:
        return hit[1]
    event = derive(
        service, method, path, labels=labels, risk_floor=risk_floor, description=_description(route)
    )
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.clear()
    _CACHE[key] = (labels, event)
    return event


def resolve_route(scope: dict[str, Any]) -> bool:
    """FR-62: give a request that never reached the router its route.

    A middleware that answers before routing (an ownership or auth check
    returning 401/403) or a client that disconnected early leaves no
    ``scope["route"]``, and the record would fall back to a derived, vague
    sentence — on exactly the denied requests an auditor reads first. Match the
    request against the app's own routes, as routing would have, and set
    ``route`` and ``path_params``. CPU only, one pass over the route list,
    only for requests that were not routed. Returns whether a route was found;
    never raises.
    """
    if scope.get("route") is not None:
        return False
    try:
        from starlette.routing import Match

        app = scope.get("app")
        routes = getattr(getattr(app, "router", None), "routes", None) or getattr(app, "routes", None)
        for route in routes or ():
            matches = getattr(route, "matches", None)
            if matches is None:
                continue
            match, child = matches(scope)
            if match == Match.FULL:
                scope["route"] = route
                scope["path_params"] = {**(scope.get("path_params") or {}),
                                        **(child.get("path_params") or {})}
                return True
    except Exception:  # noqa: BLE001 - a hostile route object must not cost the record
        return False
    return False


def describe(
    scope: dict[str, Any],
    method: str,
    *,
    catalog: Catalog,
    service: str,
    labels: Labels,
    risk_floor: str = "normal",
) -> Described:
    """Reads scope["route"] (after the app returned): endpoint.__audit__, then
    catalog[(METHOD, route.path)], then derive(...) with the route's summary or
    docstring as description (cached per (method, route)). Never raises."""
    method = str(method).upper()
    try:
        route = scope.get("route")
        path = _route_path(route)
        event = event_def_of(getattr(route, "endpoint", None)) if route is not None else None
        if event is None and route is not None:
            event = catalog.get((method, path))
            if event is None and method == "HEAD":  # Starlette serves HEAD for every GET route
                event = catalog.get(("GET", path))
        if event is not None:
            event = _with_description(event, route)
        else:
            event = _derived(method, path, route, service, labels, risk_floor)
        return Described(event=event, level=event.level)
    except Exception:
        # derive() never raises; this guards the attribute reads on a hostile route.
        event = derive(service, method, _UNMATCHED, labels=labels, risk_floor=risk_floor)
        return Described(event=event, level=LEVEL_DERIVED)
