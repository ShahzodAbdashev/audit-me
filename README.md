# `audit_logging`

One JSONL audit document per API request, captured at the raw ASGI layer.

The middleware wraps your ASGI app, records what the request was (method, path,
route template, query, allowlisted headers, request body) and what happened to
it (status, response byte count, duration, outcome), redacts it, and appends one
JSON line to a rotating file. It never talks to Elasticsearch — Filebeat ships
the files (`infra/`). Response bodies are never stored; neither are uploaded
file bytes.

It is a file writer, not a pipeline. Everything past the file is `infra/`'s job.

---

## Install and wire it up

```bash
pip install -e .            # pydantic>=2, pydantic-settings; starlette is a peer
```

```python
from fastapi import FastAPI
from audit_logging import AuditConfig, AuditMiddleware

app = FastAPI()
app.add_middleware(
    AuditMiddleware,
    config=AuditConfig(service_name="orders-api", log_dir="/var/log/audit"),
)
```

That is the whole integration. The middleware builds a `FileSink` from the
config, starts it on `lifespan.startup.complete` and drains it on
`lifespan.shutdown`; if there is no lifespan it starts the sink lazily on the
first request. Every field of `AuditConfig` also reads from the environment with
an `AUDIT_` prefix, so a deployed service is tuned without a code change.

Full walkthrough — including the volume mount, which is the part that is easy to
get wrong and silently produces nothing: **[`docs/integration.md`](docs/integration.md)**.

## What it exports

`AuditConfig`, `AuditMiddleware`, `FileSink`, `NullSink`, `Sink`,
`RequestContext`, `Metrics`, `__version__`. That is all of it — there is no CLI.

## Configuration

Every field is `AUDIT_<FIELD_NAME>` in the environment. `AuditConfig` is
`extra="forbid"`: a typo'd field raises at construction rather than being
ignored.

| Field | Default | What it does |
|---|---|---|
| `service_name` | **required** | Names the file, `service.name`, and the `apiaudit.<name>` dataset |
| `service_version` | `"unknown"` | `service.version` |
| `environment` | `"dev"` | `service.environment` and the data-stream namespace |
| `enabled` | `True` | Kill switch (FR-15). `false` makes the middleware a pure pass-through — see the note below |
| `log_dir` | `/var/log/audit` | Directory for `{service_name}-{pid}.jsonl` |
| `file_max_bytes` | `268435456` (256 MiB) | Rotation threshold |
| `file_backup_count` | `8` | Rotated generations kept (`.1` … `.8`); older ones are deleted |
| `fsync` | `False` | `fsync` after each batch. Off by default |
| `max_body_bytes` | `1048576` (1 MiB) | Request-body capture cap. Hard ceiling 16 MiB |
| `max_body_nodes` | `10000` | Shape bound on a parsed body; past it the body is skipped as `too_complex` and `audit_bodies_skipped_total` counts it. **A genuine trade — [`docs/integration.md`](docs/integration.md) §3.1** |
| `max_multipart_parts` | `256` | Cap on part-metadata records |
| `max_query_bytes` | `8192` | Bound on the query string, which is parsed, redacted and re-encoded exactly like a form body. The pair bound is derived as `max_query_bytes // 16` (512 pairs at the default). Past either, `url.query` becomes the literal `"[SKIPPED]"`, `audit.request.query` is `{}` and `audit.request.query_skipped` is set |
| `capture_text_bodies` | `False` | Opt in to storing non-JSON text bodies after a weaker, best-effort scrub. **Read [`docs/redaction.md`](docs/redaction.md) first** |
| `max_scrub_bytes` | `32768` | Length bound on that scrub; longer bodies are skipped as `too_complex` |
| `exclude_paths` | `/health`, `/healthz`, `/ready`, `/metrics`, `/favicon.ico`, `/docs`, `/openapi.json` | Prefix match on the raw path, anchored at a path-segment boundary |
| `extra_redact_keys` | `[]` | Additional denylisted body/query keys. Additive only |
| `extra_header_allowlist` | `[]` | Additional storable header names. Additive only |
| `queue_max_bytes` | `67108864` (64 MiB) | In-memory queue bound, in bytes. Must be ≥ `flush_max_bytes` |
| `flush_max_bytes` | `4194304` (4 MiB) | Flush early when the queue passes this |
| `flush_interval_seconds` | `1.0` | Otherwise flush on this interval |
| `shutdown_flush_timeout` | `10.0` | `close()` returns after this whether or not the drain finished |
| `user_resolver` | `None` | `(scope) -> dict \| None` populating `user.id` / `user.name` / `user.roles` |

List fields accept either CSV or JSON from the environment:
`AUDIT_EXCLUDE_PATHS=/health,/internal` and `AUDIT_EXTRA_REDACT_KEYS=["ssn_alt"]`
both work.

> **`AUDIT_ENABLED=false` also removes the `X-Request-ID` response header.**
> The kill switch is a genuine pass-through with no `send` wrapper, so the
> header FR-24 adds disappears with it. That is a change in API behaviour, not
> only in logging (`tests/unit/test_middleware.py::test_N_14_the_kill_switch_removes_the_request_id_header_too`).

## What it costs

Measured, not estimated. Every row says what was measured, because two of these
numbers were previously quoted for a workload the shipped defaults do not
actually run.

| | |
|---|---|
| Added p99 latency | **+0.819 ms** against NFR-1's 5 ms budget — 300 s per arm, 100 rps, 8 KB JSON bodies, real `FileSink` and real redaction (`tests/load/`). **This is the benign arm only** — see the caveat below |
| Middleware overhead per request | ~30 µs with the sink and redaction stubbed out (`test_overhead_per_request_microseconds`) |
| `submit()` | **~1.2 µs** on a ~2 KB document (measured 2026-09-05; 1.0–1.6 µs across trials). A serialisation plus a `deque.append`; the test bounds it at 200 µs |
| `redact()` at the shipped node cap | **~1.7 ms** for a 156 KB / 9,962-node nested body — the largest realistic shape `max_body_nodes=10000` admits (measured 2026-09-05) |
| `redact()` on the 1 MiB benchmark fixture | 12.6 ms (`test_benchmark_one_megabyte_under_20ms`, budget 20 ms). **That fixture is 69,122 nodes and the shipped default refuses it** as `too_complex`, so this number describes a path production does not reach unless you raise `max_body_nodes` |
| Elasticsearch field count | **51** created by real traffic — 50 endpoints × 200 requests with distinct body shapes (AC-10). The mapping itself is **63** entries (45 leaves + 18 object containers) against the 200 limit; a dynamic mapping would have created 20,194. `docs/schema.md` §3 has the resolution of the four numbers |

> **The p99 above is the benign arm** — treat it as "what ordinary traffic
> costs", not as a worst case. There is now also an **adversarial arm**,
> `tests/load/test_nfr1_adversarial.py`, which drives the shapes that actually
> broke this package and asserts each stays inside the same 5 ms budget:
>
| shape a client chooses | before the fix | now |
> |---|---|---|
> | 1 MiB `[[],[],…]` body | 140.6 ms | **0.09 ms** |
> | 1 MiB `[0,0,…]` body | 93.4 ms | **0.10 ms** |
> | 64 KB query, **no body** | 24.0 ms | **0.01 ms** |
> | 73 KB of control-character keys | 20.0 ms | **3.28 ms** |
>
> Each case is a defect that was found, measured and fixed (`REVIEW.md` M-2,
> `REVIEW-2.md` N2-3, N2-4). The arm is verified to be a real net: with the
> caps disabled, **7 of its 10 tests fail**. The tightest margin is the hostile
> keys case at 3.28 ms — 66 % of the budget — so that is the one to watch.

## Documentation

| | |
|---|---|
| [`docs/integration.md`](docs/integration.md) | Adding this to a service, end to end, including the volume mount and how to prove it works |
| [`docs/redaction.md`](docs/redaction.md) | What is redacted, how to extend it, and — at length — **what redaction does not protect against** |
| [`docs/runbook.md`](docs/runbook.md) | On-call: symptom → cause → action, and the kill switch |
| [`docs/schema.md`](docs/schema.md) | Every field of the emitted document. Frozen |
| [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) | FR/AC numbering, known deviations, edge cases. Frozen |
| [`infra/README.md`](infra/README.md) | Deploying Elasticsearch objects, Filebeat and the app-pod volume |
| [`tests/AC-matrix.md`](tests/AC-matrix.md) | What is actually verified, by which test tier, and what is not |
| [`REVIEW.md`](REVIEW.md) | The adversarial review this package was hardened against |
| [`REVIEW-2.md`](REVIEW-2.md) | The verification pass over those fixes — including three new must-fixes the fixes themselves introduced |
| [`CHANGELOG.md`](CHANGELOG.md) | Two supersessions of locked plan decisions, and both review rounds |

**Before trusting anything here in production, read `tests/AC-matrix.md` §5.**
The Elasticsearch + Filebeat test tier has never been executed — there is no
Docker in the environment this was built in — so every claim about what happens
*after* the JSONL line is written is unverified.

## Running the tests

```bash
./.venv/bin/python -m pytest tests -q -m "not integration and not load"
./.venv/bin/python -m mypy --strict audit_logging
```
