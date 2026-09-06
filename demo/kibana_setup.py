"""Create the Kibana data view for the audit index, so the UI opens on data.

Without a data view Kibana shows an empty "create your first data view"
screen, which looks exactly like "nothing was indexed". This creates one
pointing at `logs-apiaudit.*-*` with `@timestamp` as the time field, and marks
it the default so Discover opens on it.

Idempotent: re-running it reports the existing view rather than duplicating.

    ./.venv/bin/python demo/kibana_setup.py
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

KIBANA = "http://127.0.0.1:5601"
PATTERN = "logs-apiaudit.*-*"


def call(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{KIBANA}{path}", data=data, method=method)
    req.add_header("content-type", "application/json")
    req.add_header("kbn-xsrf", "true")  # Kibana rejects writes without it
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")
    except urllib.error.URLError as exc:
        print(f"cannot reach Kibana at {KIBANA}: {exc.reason}")
        print("start it:  sg docker -c 'docker compose -f demo/docker-compose.kibana.yml up -d'")
        raise SystemExit(2)


def main() -> int:
    status, body = call("GET", "/api/status")
    level = body.get("status", {}).get("overall", {}).get("level")
    if level != "available":
        print(f"Kibana is not ready yet (status={level!r}). Wait and re-run.")
        return 1

    status, existing = call("GET", "/api/data_views")
    for view in existing.get("data_view", []):
        if view.get("title") == PATTERN:
            print(f"data view already exists: {view['title']}  (id={view['id']})")
            print(f"open: {KIBANA}/app/discover")
            return 0

    status, created = call("POST", "/api/data_views/data_view", {
        "data_view": {"title": PATTERN, "name": "API audit", "timeFieldName": "@timestamp"},
        "override": False,
    })
    if status >= 400:
        print(f"could not create the data view (HTTP {status}): {json.dumps(created)[:300]}")
        return 1

    view_id = created["data_view"]["id"]
    print(f"created data view {PATTERN!r} (id={view_id})")
    call("POST", "/api/data_views/default", {"data_view_id": view_id, "force": True})
    print(f"\nopen:  {KIBANA}/app/discover")
    print("       Discover shows every audited request, newest first.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
