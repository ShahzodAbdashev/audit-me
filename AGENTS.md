# AGENTS.md

You are working on the `audit_logging` package. Rules that apply to every task:

1. Read `docs/schema.md`, `docs/REQUIREMENTS.md` and `audit_logging/_contracts.py`
   first. They are frozen. If your task cannot be done without changing them,
   STOP and report why. Do not edit them.
2. Own only the paths listed in your brief. Do not touch other modules; stub
   them against the contract if you need them.
3. Never import from elasticsearch, kafka, or any network client. This package
   writes files. Filebeat ships them.
4. Nothing in the request path may await on I/O, allocate unboundedly, or
   raise. Any exception in package code is caught, counted via Metrics, and
   swallowed. The user's request always completes normally.
5. Type hints everywhere. `mypy --strict` must pass on your files.
6. Tests live beside your module in `tests/unit/`. Each functional requirement
   you implement gets at least one test named `test_FR_XX_*`.
7. Do not add dependencies beyond: `pydantic>=2`, `starlette` (as a peer).
   Optional extras only: `prometheus-client`, `orjson`.
8. Do not write a README, changelog, or CLI. Agent 7 owns docs. There is no CLI.
9. When done, produce a short report: what you built, what you stubbed, which
   FRs/ACs are covered, what you were unsure about. Do not summarise the code.

## Local conventions (added by the orchestrator, Phase 0)

- The interpreter is `./.venv/bin/python`. Run tests with
  `./.venv/bin/python -m pytest tests/unit/<yours> -q` and types with
  `./.venv/bin/python -m mypy --strict audit_logging/<yours>`.
- The companion `SPEC-request-audit-logging.md` named by the plan **does not
  exist**. `docs/REQUIREMENTS.md` is its reconstruction and is authoritative.
  Where it says `[reconstructed]`, say so in your report if you had to guess
  further.
- `pytest-asyncio` is in `auto` mode: `async def test_*` needs no decorator.

## Phase 0 addendum — pinned signatures (orchestrator decision)

The plan freezes the `Sink`, `RequestContext` and `Metrics` contracts but not
the constructors that connect them. These are pinned here so that A2, A4 and A6
compose without a rewrite. **Treat them as frozen too.**

```python
# audit_logging/middleware.py                                            [A2]
class AuditMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        config: AuditConfig,
        sink: Sink | None = None,        # None -> build a FileSink from config
        metrics: Metrics | None = None,  # None -> InMemoryMetrics()
    ) -> None: ...

# audit_logging/document.py                                              [A2]
def build_document(ctx: RequestContext, config: AuditConfig) -> dict[str, Any]: ...

# audit_logging/sinks/file_sink.py                                       [A4]
class FileSink(Sink):
    def __init__(self, config: AuditConfig, metrics: Metrics | None = None) -> None: ...

# audit_logging/metrics.py                                               [A4]
class InMemoryMetrics:
    def __init__(self) -> None: ...
    def snapshot(self) -> dict[str, float]: ...   # for tests and the runbook
```

So `app.add_middleware(AuditMiddleware, config=config)` works with Starlette,
which passes the wrapped app positionally.

### Lifespan is observed, not ignored

Plan §4.1 says non-`http` scopes pass through and §4.2 says the sink drains on
lifespan end. Both hold, resolved this way:

- For `scope["type"] == "lifespan"`, every message is passed through
  **byte-identical in both directions** — the middleware changes nothing.
- It *observes* them: after `lifespan.startup.complete` it awaits
  `sink.start()`; on `lifespan.shutdown` it awaits `sink.close()` **before**
  forwarding the shutdown to the app, bounded by `shutdown_flush_timeout`.
- If the sink was never started (no lifespan — e.g. a bare
  `httpx.ASGITransport` test), the first `submit()` starts it lazily from the
  running loop. Starting must be idempotent and must never raise into the
  request path.
- `websocket` scopes pass through with no wrapping and no observation.

### Redaction across the A2/A3 boundary

`document.py` imports `redact`, `filter_headers`, `DEFAULT_REDACT_KEYS` and
`DEFAULT_HEADER_ALLOWLIST` from `audit_logging.redact` **at module level**.
During Phase 1 those are `NotImplementedError` stubs, so A2's unit tests
monkeypatch `audit_logging.document.redact` / `.filter_headers` with identity
implementations. A2 must not edit `redact.py`; A3 must not edit `document.py`.
They meet in Phase 2.

The effective key sets are `DEFAULT_REDACT_KEYS | {normalize_key(k) for k in
config.extra_redact_keys}` and `DEFAULT_HEADER_ALLOWLIST | {k.lower() for k in
config.extra_header_allowlist}` — additive only (FR-13).
