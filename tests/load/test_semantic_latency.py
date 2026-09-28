"""NFR-8: added p99 of the 0.2 semantic layer over the 0.1 shape, in process.

Same FastAPI app, same real FileSink, same decorated route calling
``audit.target`` / ``audit.diff``; the only difference is ``semantic_enabled``.
Closed loop over ``httpx.ASGITransport``, arms interleaved in chunks so machine
drift hits both. Marked ``load``::

    ./.venv/bin/python -m pytest tests/load/test_semantic_latency.py -q -m load -s

``AUDIT_SEMANTIC_N`` overrides the per-arm request count (default 5000).
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from audit_logging import AuditConfig, AuditMiddleware, Target, audit, audited
from audit_logging.metrics import InMemoryMetrics
from audit_logging.semantic import runtime
from audit_logging.sinks.file_sink import FileSink

from .driver import _percentile

pytestmark = pytest.mark.load

N = max(5000, int(os.environ.get("AUDIT_SEMANTIC_N", "5000")))
CHUNK = 500
WARMUP = 200
P99_BUDGET_MS = 5.0   # NFR-8 hard budget; the +0.3 ms target is reported, not asserted
ACTOR = {"id": "u7", "name": "sardor", "full_name": "Sardor Karimov", "roles": ["Admin"]}
BODY = {"full_name": "Aliyev Vali", "role_id": 2, "password": "secret"}


def build_app() -> FastAPI:
    app = FastAPI()

    @app.post("/users/{user_id}")
    @audited("admin.user.updated", uz="{actor} «{target}» foydalanuvchisini tahrirladi",
             target=Target("user", id="path.user_id"), category="admin", risk="high", diff=True)
    async def update_user(user_id: int, body: dict[str, Any]) -> dict[str, bool]:
        audit.target(label="Aliyev Vali")
        audit.diff({"role_id": "Operator", "full_name": "Aliyev V."},
                   {"role_id": "Admin", "full_name": "Aliyev Vali"}, labels={"role_id": "Rol"})
        return {"ok": True}

    return app


class Arm:
    def __init__(self, name: str, log_dir: Path, semantic: bool) -> None:
        self.name = name
        self.metrics = InMemoryMetrics()
        self.config = AuditConfig(
            service_name="users-adminka", dataset="users_adminka", elasticsearch_url=None,
            environment="load", log_dir=log_dir, semantic_enabled=semantic,
            user_resolver=lambda scope: dict(ACTOR),
            flush_interval_seconds=1.0, flush_max_bytes=4 * 1024 * 1024,
            queue_max_bytes=64 * 1024 * 1024, file_max_bytes=4 * 1024 * 1024 * 1024,
        )
        self.sink = FileSink(self.config, self.metrics)
        app = AuditMiddleware(build_app(), config=self.config, sink=self.sink, metrics=self.metrics)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
        self.ms: list[float] = []

    async def run(self, count: int, record: bool = True) -> None:
        for _ in range(count):
            start = time.perf_counter()
            response = await self.client.post("/users/2", json=BODY)
            elapsed = (time.perf_counter() - start) * 1e3
            assert response.status_code == 200
            if record:
                self.ms.append(elapsed)

    def stats(self) -> dict[str, float]:
        return {"p50": _percentile(self.ms, 50), "p99": _percentile(self.ms, 99)}


async def test_NFR_8_semantic_layer_added_p99(tmp_path: Path) -> None:
    v01 = Arm("0.1 (semantic off)", tmp_path / "v01", semantic=False)
    v02 = Arm("0.2 (decorated+target+diff)", tmp_path / "v02", semantic=True)
    try:
        for arm in (v01, v02):
            await arm.run(WARMUP, record=False)
        for _ in range(N // CHUNK):
            for arm in (v01, v02):
                await arm.run(CHUNK)
    finally:
        for arm in (v01, v02):
            await arm.client.aclose()
            await arm.sink.close()
        runtime.clear_active()

    a, b = v01.stats(), v02.stats()
    print(f"\nNFR-8 N={len(v01.ms)}/arm  0.1 p50 {a['p50']:.3f} p99 {a['p99']:.3f} ms | "
          f"0.2 p50 {b['p50']:.3f} p99 {b['p99']:.3f} ms | added p50 {b['p50'] - a['p50']:+.3f} "
          f"p99 {b['p99'] - a['p99']:+.3f} ms (target +0.3, budget +{P99_BUDGET_MS})")

    assert len(v01.ms) == len(v02.ms) >= 5000
    for arm in (v01, v02):
        assert arm.metrics.get("audit_middleware_errors_total") == 0
        assert arm.metrics.get("audit_documents_dropped_total") == 0
    assert v02.metrics.get("audit_semantic_errors_total") == 0
    # the arms really differ: only 0.2 wrote the semantic record
    assert b"admin.user.updated" in v02.sink.path.read_bytes()[-4096:]
    assert b"admin.user.updated" not in v01.sink.path.read_bytes()[-4096:]
    assert b["p99"] - a["p99"] <= P99_BUDGET_MS
