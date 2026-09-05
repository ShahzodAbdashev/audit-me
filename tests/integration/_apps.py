"""The application under audit — one app, shared by both tiers.

Tier 1 and Tier 2 assert the same acceptance criteria against the same routes,
so the routes live here rather than in either test module. Nothing in this file
knows about Elasticsearch or about files; it is just a FastAPI app with the
handlers the ACs describe.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response, StreamingResponse

__all__ = ["Received", "make_app", "make_wide_app", "STREAM_CHUNKS", "STREAM_GAP_SECONDS"]

#: AC-13: five chunks, 100 ms apart, so `event.duration` must clear 400 ms.
STREAM_CHUNKS = 5
STREAM_GAP_SECONDS = 0.1


class Received:
    """What the handlers actually got, so a test can prove FR-04 byte fidelity."""

    def __init__(self) -> None:
        self.bodies: list[bytes] = []
        self.total_bytes = 0

    def record(self, body: bytes) -> None:
        self.bodies.append(body)
        self.total_bytes += len(body)

    @property
    def last(self) -> bytes:
        if not self.bodies:
            raise AssertionError("no handler ever read a request body")
        return self.bodies[-1]

    def clear(self) -> None:
        self.bodies.clear()
        self.total_bytes = 0


def make_app() -> tuple[FastAPI, Received]:
    """The app every acceptance criterion is exercised against."""
    app = FastAPI()
    received = Received()

    @app.get("/items/{item_id}")
    async def get_item(item_id: int) -> dict[str, Any]:
        """AC-01 — the plain, happy path."""
        return {"item_id": item_id}

    @app.post("/echo")
    async def echo(request: Request) -> Response:
        """AC-03 / AC-04 / AC-14 — reads the body and hands it straight back."""
        body = await request.body()
        received.record(body)
        return Response(content=body, media_type="application/octet-stream")

    @app.post("/ingest")
    async def ingest(request: Request) -> dict[str, str]:
        """AC-05 / AC-09 / AC-12 / AC-16 — reads the body, answers small."""
        received.record(await request.body())
        return {"status": "accepted"}

    @app.get("/health")
    async def health() -> dict[str, str]:
        """AC-02 — on `exclude_paths`, so it must never be audited."""
        return {"status": "ok"}

    @app.get("/boom")
    async def boom() -> None:
        """AC-08 — the application raises; the exception must survive intact."""
        raise ValueError("kaboom")

    @app.get("/stream")
    async def stream() -> StreamingResponse:
        """AC-13 — five chunks, 100 ms apart."""

        async def chunks() -> AsyncIterator[bytes]:
            for index in range(STREAM_CHUNKS):
                await asyncio.sleep(STREAM_GAP_SECONDS)
                yield f"chunk-{index};".encode()

        return StreamingResponse(chunks(), media_type="text/plain")

    @app.delete("/gone", status_code=204)
    async def gone() -> Response:
        """§3 edge case — a response with no body at all."""
        return Response(status_code=204)

    @app.head("/ping")
    async def ping() -> Response:
        """AC-23 — a HEAD the *application* answers with no body at all.

        A HEAD against a body-returning GET route is stripped by the HTTP
        server (uvicorn/h11), not by the application, and there is no uvicorn
        in this venv — so that variant cannot show `http.response.bytes == 0`
        in either tier. This route makes the AC reachable honestly: the app
        emits nothing, so the count really is zero.
        """
        return Response(status_code=200)

    @app.get("/whoami")
    async def whoami() -> Response:
        """AC-17 — a route the `user_resolver` is asked about."""
        return JSONResponse({"ok": True})

    return app, received


def wide_body(endpoint: int, request_index: int) -> dict[str, Any]:
    """A body shape unique to (endpoint, request) — the AC-10 fan-out.

    Every request contributes leaf paths no other request has, so a
    ``dynamic: true`` mapping would grow a field per key. ``flattened`` must
    absorb the lot into ``audit.request.body``.
    """
    return {
        f"e{endpoint}_kind": f"shape-{endpoint}",
        f"e{endpoint}_seq": request_index,
        f"e{endpoint}_r{request_index}_value": f"v-{endpoint}-{request_index}",
        f"e{endpoint}_nested": {
            f"inner_{endpoint}_{request_index}": request_index,
            f"tag_{endpoint}": ["a", "b"],
        },
        "shared_marker": True,
    }


def make_wide_app(endpoints: int) -> FastAPI:
    """AC-10 — *endpoints* distinct routes, each with its own body shape."""
    app = FastAPI()

    def register(index: int) -> None:
        @app.post(f"/e{index}/{{resource_id}}", name=f"endpoint_{index}")
        async def handler(resource_id: str, request: Request) -> dict[str, Any]:
            await request.body()
            return {"endpoint": index, "resource_id": resource_id}

    for index in range(endpoints):
        register(index)
    return app
