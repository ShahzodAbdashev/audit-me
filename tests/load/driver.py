"""NFR-1 load driver — 100 rps, 8 KB bodies, with and without the middleware.

Why a hand-written asyncio/httpx driver and not Locust or k6
------------------------------------------------------------

Neither is available, and neither can be made available: `locust` is not in
``.venv`` and is not on the permitted dependency list (AGENTS.md §7), there is
no ``k6`` binary, there is no Docker to run one in, and there is no ``uvicorn``
either — so there is no way to put a real socket server in front of the app.
A self-contained driver over ``httpx.ASGITransport`` is what is left, and it is
also the *right* tool for the question NFR-1 actually asks:

    "Added p99 latency ≤ 5 ms at 100 rps with 8 KB bodies."

The number that matters is a **delta between two arms**, and every source of
noise this driver removes — TCP, the kernel, uvicorn's own protocol parsing,
another process's scheduler — is noise that appears identically in both arms
and only widens the confidence interval on the difference. What it costs is
realism: see "What this does not measure" at the bottom of this docstring.

How it measures
---------------

Open loop. Request *i* is *scheduled* for ``t0 + i / rate`` whether or not
request *i-1* has finished, so a slow arm shows up as queueing instead of
quietly lowering its own offered rate (coordinated omission). Two latencies are
recorded per request:

``service``
    ``finished - started`` — how long the call itself took. This is the
    quantity NFR-1's delta is computed from: it isolates the middleware.
``scheduled``
    ``finished - scheduled`` — including any time spent waiting to be issued.
    Reported as a sanity check: if it diverges from ``service``, the driver
    itself failed to keep up and the run is not a 100 rps run.

Both arms run the same app, the same bodies, the same schedule. The audited arm
adds ``AuditMiddleware`` with a **real** ``FileSink`` writing real JSONL to a
real directory and the **real** ``redact.py`` — not a ``NullSink``, and not an
identity redaction. A2's reported 38 µs/request was measured with both of those
stubbed out; the honest figure is what this produces.

Run it directly for a long, unhurried measurement::

    ./.venv/bin/python -m tests.load.driver --duration 300 --rate 100

What this does not measure
--------------------------

* No sockets, so no TCP, TLS, keep-alive, or accept-queue behaviour.
* No uvicorn/hypercorn, so no h11 parsing and no worker model.
* One process, one event loop: the audited arm's background flush task competes
  with the request path on the *same* loop, which is realistic for a single
  uvicorn worker but says nothing about several workers on one node.
* Filebeat is not running, so nothing is reading the files back.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from audit_logging.config import AuditConfig
from audit_logging.metrics import InMemoryMetrics
from audit_logging.middleware import AuditMiddleware
from audit_logging.sinks.file_sink import FileSink

__all__ = ["Sample", "ArmResult", "Comparison", "build_body", "run_comparison", "main"]

#: NFR-1's two numbers.
DEFAULT_RATE = 100.0
TARGET_BODY_BYTES = 8 * 1024

#: Discarded from the front of every arm: the first requests pay for FastAPI's
#: route-resolution caches, orjson's warm-up and the sink's first file open.
WARMUP_SECONDS = 2.0


# ---------------------------------------------------------------------------
# The payload
# ---------------------------------------------------------------------------


def build_body(target_bytes: int = TARGET_BODY_BYTES) -> bytes:
    """An 8 KB JSON body shaped like something a real API would receive.

    Deliberately *not* a flat blob of filler: it nests, it carries a list of
    objects, and it plants denylisted keys at three different depths, so the
    audited arm pays the real recursive cost of ``redact()`` rather than the
    cost of walking one string.
    """
    document: dict[str, Any] = {
        "order_id": "ord_9f2c1a7d4e8b4f0a",
        "customer": {
            "id": "cus_8813",
            "name": "a.karimov",
            "password": "hunter2",  # denylisted at depth 2
            "contact": {
                "email": "a.karimov@example.invalid",
                "api_key": "sk_live_not_a_real_key",  # denylisted at depth 3
            },
        },
        "payment": {"card": {"pan": "4111111111111111", "cvv": "123"}},
        "session": "abcdef0123456789",
        "lines": [],
    }
    lines: list[dict[str, Any]] = document["lines"]
    index = 0
    while len(json.dumps(document, separators=(",", ":")).encode()) < target_bytes:
        lines.append(
            {
                "sku": f"SKU-{index:05d}",
                "qty": index % 7 + 1,
                "unit_price": 1999 + index,
                "note": "warehouse pick, aisle %d" % (index % 40),
                "token": f"line-token-{index}",  # denylisted inside a list
            }
        )
        index += 1
    return json.dumps(document, separators=(",", ":")).encode()


def build_app() -> FastAPI:
    """The application under load: parses the body, answers small."""
    app = FastAPI()

    @app.post("/orders/{order_id}/items")
    async def create(order_id: str, request: Request) -> JSONResponse:
        body = await request.body()
        return JSONResponse({"order_id": order_id, "received": len(body)}, status_code=201)

    return app


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass
class Sample:
    scheduled: float
    service: float
    status: int


def _percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile; no interpolation, no surprises."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(round(q / 100.0 * len(ordered) + 0.5))))
    return ordered[rank - 1]


@dataclass
class ArmResult:
    name: str
    samples: list[Sample] = field(default_factory=list)
    wall_seconds: float = 0.0
    metrics: dict[str, float] = field(default_factory=dict)
    bytes_written: int = 0

    @property
    def service_ms(self) -> list[float]:
        return [s.service * 1e3 for s in self.samples]

    @property
    def scheduled_ms(self) -> list[float]:
        return [s.scheduled * 1e3 for s in self.samples]

    @property
    def achieved_rps(self) -> float:
        return len(self.samples) / self.wall_seconds if self.wall_seconds else 0.0

    def stats(self) -> dict[str, float]:
        service = self.service_ms
        return {
            "count": float(len(service)),
            "rps": self.achieved_rps,
            "mean": statistics.fmean(service) if service else float("nan"),
            "p50": _percentile(service, 50),
            "p95": _percentile(service, 95),
            "p99": _percentile(service, 99),
            "max": max(service) if service else float("nan"),
            "sched_p99": _percentile(self.scheduled_ms, 99),
        }

    def non_2xx(self) -> int:
        return sum(1 for s in self.samples if not 200 <= s.status < 300)


@dataclass
class Comparison:
    baseline: ArmResult
    audited: ArmResult
    body_bytes: int
    rate: float
    duration: float

    def delta_ms(self) -> dict[str, float]:
        left, right = self.baseline.stats(), self.audited.stats()
        return {key: right[key] - left[key] for key in ("mean", "p50", "p95", "p99")}

    def report(self) -> str:
        base, aud, delta = self.baseline.stats(), self.audited.stats(), self.delta_ms()
        rows = [
            f"NFR-1 — {self.rate:.0f} rps, {self.body_bytes} B bodies, "
            f"{self.duration:.0f} s per arm (after a {WARMUP_SECONDS:.0f} s warm-up)",
            "",
            f"{'':<22}{'baseline':>12}{'audited':>12}{'delta':>12}",
            f"{'-' * 58}",
        ]
        for label, key in (
            ("mean (ms)", "mean"),
            ("p50 (ms)", "p50"),
            ("p95 (ms)", "p95"),
            ("p99 (ms)", "p99"),
        ):
            rows.append(
                f"{label:<22}{base[key]:>12.3f}{aud[key]:>12.3f}{delta[key]:>+12.3f}"
            )
        rows += [
            f"{'max (ms)':<22}{base['max']:>12.3f}{aud['max']:>12.3f}"
            f"{aud['max'] - base['max']:>+12.3f}",
            f"{'-' * 58}",
            f"{'requests':<22}{base['count']:>12.0f}{aud['count']:>12.0f}",
            f"{'achieved rps':<22}{base['rps']:>12.2f}{aud['rps']:>12.2f}",
            f"{'open-loop p99 (ms)':<22}{base['sched_p99']:>12.3f}{aud['sched_p99']:>12.3f}",
            f"{'non-2xx':<22}{self.baseline.non_2xx():>12d}{self.audited.non_2xx():>12d}",
            "",
            f"audit documents submitted: "
            f"{self.audited.metrics.get('audit_documents_submitted_total', 0):.0f}",
            f"audit documents dropped:   "
            f"{self.audited.metrics.get('audit_documents_dropped_total', 0):.0f}",
            f"audit documents failed:    "
            f"{self.audited.metrics.get('audit_documents_failed_total', 0):.0f}",
            f"middleware errors:         "
            f"{self.audited.metrics.get('audit_middleware_errors_total', 0):.0f}",
            f"JSONL written:             {self.audited.bytes_written / 1024 / 1024:.1f} MiB",
            "",
            f"NFR-1 target: added p99 ≤ 5.000 ms — measured {delta['p99']:+.3f} ms "
            f"({'PASS' if delta['p99'] <= 5.0 else 'FAIL'})",
        ]
        return "\n".join(rows)


# ---------------------------------------------------------------------------
# The driver
# ---------------------------------------------------------------------------


async def _one(
    client: httpx.AsyncClient,
    path: str,
    body: bytes,
    scheduled_at: float,
    out: list[Sample],
) -> None:
    started = time.perf_counter()
    try:
        response = await client.post(
            path, content=body, headers={"content-type": "application/json"}
        )
        status = response.status_code
    except Exception:  # noqa: BLE001 - a failed request is a data point, not a crash
        status = 0
    finished = time.perf_counter()
    out.append(
        Sample(
            scheduled=finished - scheduled_at,
            service=finished - started,
            status=status,
        )
    )


async def run_arm(
    name: str,
    app: FastAPI,
    body: bytes,
    *,
    rate: float,
    duration: float,
    warmup: float = WARMUP_SECONDS,
    path: str = "/orders/ord-1/items",
) -> ArmResult:
    """Drive one arm open-loop at *rate* for *duration* seconds.

    *path* may carry a query string, so an arm can exercise the query bound
    (review N2-3) as well as the body path.
    """
    result = ArmResult(name=name)
    samples: list[Sample] = []

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://load.test") as client:
        # Warm up outside the measurement: caches, JIT-ish paths, first open.
        for _ in range(20):
            await client.post(path, content=body, headers={"content-type": "application/json"})

        total = int(rate * (duration + warmup))
        inflight: set[asyncio.Task[None]] = set()
        origin = time.perf_counter()
        for index in range(total):
            scheduled_at = origin + index / rate
            delay = scheduled_at - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)
            task = asyncio.create_task(_one(client, path, body, scheduled_at, samples))
            inflight.add(task)
            task.add_done_callback(inflight.discard)
        if inflight:
            await asyncio.gather(*list(inflight))
        wall = time.perf_counter() - origin

    keep = int(rate * warmup)
    result.samples = samples[keep:]
    result.wall_seconds = max(wall - warmup, 1e-9)
    return result


async def run_comparison(
    *,
    rate: float = DEFAULT_RATE,
    duration: float = 30.0,
    body_bytes: int = TARGET_BODY_BYTES,
    log_dir: Path | None = None,
) -> Comparison:
    """Run both arms and return the comparison. Baseline first, audited second."""
    body = build_body(body_bytes)

    baseline = await run_arm("baseline", build_app(), body, rate=rate, duration=duration)

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if log_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="audit-load-")
        log_dir = Path(temporary.name)
    try:
        config = AuditConfig(
            service_name="load-api",
            service_version="1.0.0",
            environment="load",
            log_dir=log_dir,
            # Production defaults everywhere it matters. Only file_max_bytes is
            # raised, so a five-minute run does not spend its time rotating —
            # rotation is AC-12's subject, not NFR-1's.
            flush_interval_seconds=1.0,
            flush_max_bytes=4 * 1024 * 1024,
            queue_max_bytes=64 * 1024 * 1024,
            file_max_bytes=4 * 1024 * 1024 * 1024,
        )
        metrics = InMemoryMetrics()
        sink = FileSink(config, metrics)
        app = build_app()
        app.add_middleware(AuditMiddleware, config=config, sink=sink, metrics=metrics)

        audited = await run_arm("audited", app, body, rate=rate, duration=duration)
        await sink.close()
        audited.metrics = metrics.snapshot()
        audited.bytes_written = sink.path.stat().st_size if sink.path.exists() else 0
    finally:
        if temporary is not None:
            temporary.cleanup()

    return Comparison(
        baseline=baseline,
        audited=audited,
        body_bytes=len(body),
        rate=rate,
        duration=duration,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--rate", type=float, default=DEFAULT_RATE, help="requests per second")
    parser.add_argument("--duration", type=float, default=60.0, help="seconds per arm")
    parser.add_argument("--body-bytes", type=int, default=TARGET_BODY_BYTES)
    parser.add_argument("--log-dir", type=Path, default=None)
    parser.add_argument("--json", action="store_true", help="emit machine-readable output too")
    args = parser.parse_args()

    comparison = asyncio.run(
        run_comparison(
            rate=args.rate,
            duration=args.duration,
            body_bytes=args.body_bytes,
            log_dir=args.log_dir,
        )
    )
    print(comparison.report())
    if args.json:
        print(
            json.dumps(
                {
                    "baseline": comparison.baseline.stats(),
                    "audited": comparison.audited.stats(),
                    "delta_ms": comparison.delta_ms(),
                },
                indent=2,
            )
        )
    return 0 if comparison.delta_ms()["p99"] <= 5.0 else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
