"""A real FastAPI service wired to audit_logging, for the end-to-end demo.

Run it the way a service actually runs — a real uvicorn server on a real
socket, not an in-process ASGI transport::

    ./.venv/bin/python -m uvicorn demo.app:app --port 8080

Everything here is deliberately ordinary. The only audit-specific lines are the
``AuditConfig`` and the ``add_middleware`` call; that is the whole integration
surface, and if it needed more than that the package would be wrong.

``AUDIT_LOG_DIR`` picks the directory Filebeat watches, so the same file this
writes is the file the shipper reads.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from audit_logging import AuditConfig, AuditMiddleware

LOG_DIR = Path(os.environ.get("AUDIT_LOG_DIR", "/tmp/audit-demo"))
LOG_DIR.mkdir(parents=True, exist_ok=True)


def resolve_user(scope: dict[str, Any]) -> dict[str, Any] | None:
    """A user_resolver of the kind a real service writes (FR-25).

    Reads whatever the auth layer has already put on the scope. It must never
    raise — but if it does, the package swallows it, counts it, and still emits
    the document (AC-17), which is exactly why this is allowed to be naive.
    """
    for key, value in scope.get("headers") or []:
        if key.lower() == b"x-demo-user":
            return {"id": value.decode("latin-1"), "roles": ["operator"]}
    return None


app = FastAPI(title="orders-api (audit demo)")

config = AuditConfig(
    service_name="orders-api",
    service_version="1.4.2",
    environment=os.environ.get("AUDIT_ENVIRONMENT", "demo"),
    log_dir=LOG_DIR,
    user_resolver=resolve_user,
    # Short interval so the demo does not wait a second per request to see a
    # line appear. Production leaves this at 1.0.
    flush_interval_seconds=float(os.environ.get("AUDIT_FLUSH_INTERVAL_SECONDS", "0.25")),
)
app.add_middleware(AuditMiddleware, config=config)


# --- ordinary routes -------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    """On `exclude_paths`, so it must produce no audit document at all."""
    return {"status": "ok"}


@app.post("/orders/{order_id}/items")
async def create_item(order_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {"order_id": order_id, "accepted": len(payload)}


@app.get("/orders/{order_id}")
async def get_order(order_id: str) -> dict[str, Any]:
    if order_id == "missing":
        raise HTTPException(status_code=404, detail="no such order")
    return {"order_id": order_id, "total": 1999}


@app.delete("/orders/{order_id}")
async def delete_order(order_id: str) -> Response:
    return Response(status_code=204)


@app.get("/keys/{api_key}")
async def by_key(api_key: str) -> dict[str, str]:
    """A route that *names* a denylisted parameter — see docs/redaction.md §4.5.

    `audit.path_params` redacts it; `url.path` keeps the raw path and is an
    indexed keyword. Both are true at once, and the demo proves it.
    """
    return {"looked_up": api_key[:2] + "..."}


@app.post("/upload")
async def upload(request: Request) -> dict[str, int]:
    body = await request.body()
    return {"bytes": len(body)}


@app.get("/report")
async def report() -> StreamingResponse:
    async def chunks():
        for index in range(5):
            yield f"row-{index}\n".encode()

    return StreamingResponse(chunks(), media_type="text/csv")


@app.get("/boom")
async def boom() -> None:
    """Raises. The exception must reach the client unchanged (NFR-3) while the
    document records outcome=failure and error.type (AC-08)."""
    raise ValueError("kaboom")
