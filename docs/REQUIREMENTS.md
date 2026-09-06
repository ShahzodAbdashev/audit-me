# Requirements — API Request Audit Logging

| | |
|---|---|
| Status | **Frozen** at Phase 0 exit; **amended at Phase 3** by the orchestrator only |
| Derived from | `PLAN-request-audit-logging.md` |
| Reconstructed | Yes — see the warning below |
| Phase 3 amendments | FR-28…FR-31 and AC-18…AC-26 added from `REVIEW.md`; FR-08/FR-10/FR-26 amended; AC-22 and AC-25 corrected after measurement; §2.2 deviations added. Every change was made by the orchestrator, never by a build agent — the rule that no agent may edit a contract held throughout. |

> ## ⚠ Provenance warning
>
> `PLAN-request-audit-logging.md` cites a companion `SPEC-request-audit-logging.md`
> for FR-01…FR-25, AC-1…AC-12 and §8.1/§8.2/§8.4/§10/§11.  **That file does not
> exist in this repository or anywhere on this machine.**
>
> This document reconstructs those requirements from every constraint the plan
> states about them (§1 decisions, §2 supersessions, §6 contracts, §8 agent
> briefs and definitions-of-done, §10 checklist). Where the plan pins a
> requirement exactly, that wording is used. Where it only names a number, the
> requirement is inferred and marked **[reconstructed]**.
>
> If the real spec surfaces, diff it against this file before trusting either.
> Per plan §2, **the plan wins on conflict** — and this file is the plan's
> requirement numbering made explicit.

---

## 1. Functional requirements

### 1.1 Capture — owned by A2 (`middleware.py`, `document.py`)

| # | Requirement |
|---|---|
| **FR-01** | Every non-excluded HTTP request produces **exactly one** audit document, whatever the outcome. Non-`http` ASGI scopes (`lifespan`, `websocket`) pass through untouched and produce nothing. |
| **FR-02** | A request whose **raw path** matches `exclude_paths` produces no document, and is passed through without wrapping `receive`/`send`. Matching is on the raw path before routing, prefix-based. |
| **FR-03** | Capture request metadata: method, raw path, query string, matched route template, path params, client IP and port, HTTP version, and allowlisted headers. The matched route is read from `scope["route"].path` **after** the app returns; `"unmatched"` when absent. |
| **FR-04** | Capture the request body by wrapping `receive`, and **replay it byte-identically** to the application. Every ASGI message the app receives must be indistinguishable from the unwrapped case, including `more_body` flags and `http.disconnect`. |
| **FR-05** | Capture response status code, allowlisted response headers, and the **total response body byte count**. Response **bodies are never stored** (D-3). |
| **FR-06** | `event.duration` (nanoseconds, ECS) is measured with `time.monotonic_ns()` from before the app is invoked to the final response chunk (`more_body` false / stream end). Streaming responses are measured to the **last** chunk, not the first. |
| **FR-07** | For `multipart/form-data` and other non-text content types, record **metadata only** — content type, declared length, and per-part name/filename/content-type/size when available from what was already buffered. Bytes are never stored (D-5). `audit.request.body_skipped = "content_type"`. |
| **FR-08** | Bodies longer than `max_body_bytes` (default **1 MiB**, D-4) are truncated at the cap and flagged `audit.request.body_truncated = true`. The application still receives the **full** body. Buffering stops at the cap — no unbounded allocation, **measured in RSS and not only in bytes counted**: the buffer must be a `bytearray`, not a list of chunks, since the client chooses the chunk size and a list amplifies 1 MiB into 28 MB (review M-4). |
| **FR-09** | A body with a JSON content type is parsed into `audit.request.body`. If parsing fails, `audit.request.body_parse_failed = true` and the raw text is preserved in `audit.request.body_raw`; the handler receives the bytes unchanged. Non-object JSON (array or scalar at the top level) is wrapped as `{"_value": <parsed>}` so the `flattened` field always sees an object. |
| **FR-28** | A body that is neither JSON nor form-encoded cannot have a key-based denylist applied to it, so by default it is **not stored at all** (`body_skipped = "content_type"`) — only its metadata. `capture_text_bodies = true` opts a service in to storing it after a **best-effort textual scrub**, which is explicitly weaker than the structured path and must be documented as such. Closes review M-1: previously a client could defeat the entire denylist by sending `Content-Type: text/plain`, or no content type at all. |
| **FR-29** | The parsed body is bounded in **shape** as well as length: past `max_body_nodes` (default 10 000) parsing and redaction are abandoned and the body is recorded as `body_skipped = "too_complex"`. Without it a 1 MiB body of `[[],[],…]` costs 140 ms on the event loop, stalling every concurrent request in the worker at ~9 req/s (review M-2). Likewise `max_multipart_parts` (default 256) bounds part records (review S-4). |
| **FR-32** | The number of **distinct** key names in a client-supplied structure is bounded by `max_distinct_keys` (default 2048); past it the body or query is recorded as `too_complex`. Node count is the wrong axis: a repeated key is two dict lookups, a first-seen one costs ~1.4 µs no cache can amortise, and the client chooses which it sends. Measured at the shipped node cap — 9,999 nodes of 4,999 distinct keys was **9.09 ms and stored**, while 10,001 nodes of four repeated keys was 0.16 ms and refused (review N3-1). For a form body the bound is applied **before** parsing, because refusing 9,999 pairs after parsing them costs 6.45 ms — over the whole NFR-1 budget, so the refusal would itself be the attack. |
| **FR-30** | Exactly one of `audit.request.body` and `audit.request.body_raw` is emitted, per `docs/schema.md` §2.9. Supersedes D-10's "both" (review M-3). |
| **FR-31** | Values returned by `user_resolver` are coerced to the types `docs/schema.md` §2.5 declares — `id`/`name` to `str`, `roles` to `list[str]` — and anything that will not coerce is dropped. `ignore_malformed` does not cover `keyword`, so an uncoerced value makes Elasticsearch reject the **entire** document (review M-5). |
| **FR-33** | The destination is declared in configuration. `dataset` and `namespace` override the values otherwise derived from `service_name` and `environment`, and together they name the data stream: `logs-<dataset>-<namespace>`, exposed as `AuditConfig.index_name`. Both are sanitised, because Elasticsearch rejects a data stream name containing uppercase or `\\ / * ? " < > | ,` or a space. **A `dataset` not starting with `apiaudit.` is refused outright**: the shipped template is `index_patterns: ["logs-apiaudit.*-*"]`, so anything else produces an index the template does not match, which Elasticsearch then creates with a *dynamic* mapping — silent at every layer, and fixable only by a reindex (D-11). The package still never contacts Elasticsearch (D-13); it writes these three fields and Filebeat routes on them. |
| **FR-34** | A request ended by a **transport** exception — `CancelledError`, `ConnectionResetError`, `ConnectionAbortedError`, `BrokenPipeError` — is `event.outcome = "disconnected"`, not `"failure"`. Nothing in the application failed; the connection went away. Every in-flight request receives `CancelledError` during a graceful shutdown, so classifying these as failures wrote a burst of failures into the index on **every rolling deploy** and paged whoever alerted on the failure rate (review N-2). `error.type` is still recorded — for a disconnect as well as a failure — because it is the only thing separating "clients are resetting" from "our own deploy is cancelling". `CancelledError` is a `BaseException` and is only classified, never swallowed. |
| **FR-15** | **Kill switch.** With `enabled = false` (env `AUDIT_ENABLED=false`) the middleware is a pure pass-through: no document is built, no queue allocated, no file opened, and no measurable overhead. |
| **FR-23** | `trace.id` is reused from an incoming `X-Request-ID` header when present and well-formed (≤ 200 chars, printable ASCII), otherwise generated as a UUID4 hex string. |
| **FR-24** | The middleware adds `X-Request-ID: <trace.id>` to the response headers inside the `send` wrapper. This is **the only mutation** the middleware makes to the request or response. |
| **FR-25** | An optional `user_resolver(scope) -> dict \| None` populates `user.*`. If it raises or returns a non-dict, the document is still emitted **without** `user.*` and `audit_middleware_errors_total` is incremented. |

**FR-16, FR-17 are deleted** (plan §2 — no sampling).

### 1.2 Redaction — owned by A3 (`redact.py`)

| # | Requirement |
|---|---|
| **FR-10** | Redaction is applied to the captured body, query and headers **before** the document is submitted, and never mutates the object the application holds. `redact()` is pure. **A body the denylist cannot be applied to is not stored** (FR-28) — redaction is never silently skipped. |
| **FR-11** | A default denylist `DEFAULT_REDACT_KEYS` is applied against **normalized** keys at every depth, in dicts and inside lists. Values become `"[REDACTED]"`; the key itself is preserved. |
| **FR-12** | Headers are captured by **allowlist** only (`DEFAULT_HEADER_ALLOWLIST`). A header not on the allowlist does not appear in the document at all — not even as a redacted placeholder. |
| **FR-13** | Services extend both lists via `extra_redact_keys` and `extra_header_allowlist`. Extension is **additive only** — there is no supported way to remove a default (D-12). |
| **FR-14** | Query-string parameters are subject to the same denylist as body keys. |

`DEFAULT_REDACT_KEYS` (normalized forms) covers at minimum: `password`, `passwd`, `pwd`, `secret`, `token`, `accesstoken`, `refreshtoken`, `idtoken`, `apikey`, `apisecret`, `authorization`, `auth`, `cookie`, `setcookie`, `sessionid`, `session`, `csrf`, `xsrf`, `privatekey`, `clientsecret`, `credential`, `credentials`, `pin`, `otp`, `cardnumber`, `cardnum`, `pan`, `cvv`, `cvc`, `ssn`, `taxid`, `iban`, `signature`, `sig`, `salt`, `hash`.

`DEFAULT_HEADER_ALLOWLIST` (lowercase) covers at minimum: `content-type`, `content-length`, `accept`, `accept-encoding`, `accept-language`, `user-agent`, `referer`, `origin`, `host`, `x-request-id`, `x-correlation-id`, `x-forwarded-for`, `x-forwarded-proto`, `x-real-ip`, `traceparent`, `tracestate`.

### 1.3 Sink — owned by A4 (`sinks/file_sink.py`, `metrics.py`)

| # | Requirement |
|---|---|
| **FR-18** | The in-memory queue is bounded **in bytes** by `queue_max_bytes` (default 64 MiB), not in documents (D-9). |
| **FR-19** | When enqueueing a line would push the queue past `queue_max_bytes`, the document is **dropped**, `audit_documents_dropped_total` is incremented, and `submit()` returns `False`. With a file sink this means "disk is not keeping up" — a paging event, not a normal condition (plan §2). |
| **FR-20r** | A single background `asyncio.Task` per process flushes the queue to a JSONL file every `flush_interval_seconds` (default 1.0 s) **or** when queued bytes pass `flush_max_bytes` (default 4 MiB), whichever comes first. Lines are written in submission order with a single `os.write` of the joined bytes. `fsync` is off by default (§4.2). |
| **FR-21r** | A write failure (disk full, permission denied) is counted in `audit_documents_failed_total`, the batch is kept for **one** retry on the next tick and then dropped, and the error is logged **once at ERROR per distinct error type**. It never reaches the request path and never exits the process. |
| **FR-22** | The active file rotates when it passes `file_max_bytes` (default 256 MiB): renamed to `.1` … `.N`, anything beyond `file_backup_count` (default 8) deleted, `audit_file_rotations_total` incremented. |
| **FR-26** | File naming is `{log_dir}/{service_name}-{pid}.jsonl`, so multiple uvicorn workers in one pod write separate files (A-5). A **second live sink** contending for the same path takes a `-{6 hex}` suffix instead: the PID already separates processes, so any live collision is necessarily in-process (a mounted sub-application, `add_middleware` called twice, a test harness). Without it two sinks silently destroyed 35 % of lines (review S-11). Both forms must match Filebeat's `*/*.jsonl` glob and be excluded by its `\.jsonl\.\d+$` rotation pattern. |
| **FR-27** | `close()` drains the queue within `shutdown_flush_timeout` (default 10 s) and **returns regardless** — a slow disk must not hang shutdown. |

### 1.4 Cross-cutting

| # | Requirement |
|---|---|
| **NFR-1** | Added p99 latency ≤ **5 ms** at 100 rps with 8 KB bodies. |
| **NFR-2** | Nothing reachable from the request path awaits I/O, takes a lock, or allocates unboundedly. `submit()` must be no slower than a `deque.append` plus one serialisation. |
| **NFR-3** | **No package exception ever reaches the application.** Package-internal errors are caught, counted via `audit_middleware_errors_total`, logged once at WARN per process, and swallowed. Application exceptions propagate **unchanged**. |
| **NFR-4** | The package imports no network client — no `elasticsearch`, `kafka`, `httpx`, `requests` (D-13). It writes files; Filebeat ships them. |
| **NFR-5** | `mypy --strict` passes on the whole package. |
| **NFR-6** | Dependencies limited to `pydantic>=2` (+ `pydantic-settings`) and `starlette` as a peer. Optional extras only: `prometheus-client`, `orjson`. |

---

## 2. Acceptance criteria

AC-1…AC-12 are **[reconstructed]**; AC-13…AC-17 are quoted from plan §8/A6.
Every AC is asserted against **Elasticsearch**, not against the file, in
`tests/integration/`.

| # | FR | Given / When / Then |
|---|---|---|
| **AC-01** | FR-01 | Given `GET /items/{item_id}` returning 200 · When called once · Then exactly one document exists with `http.request.method=GET`, `audit.route="/items/{item_id}"`, `http.response.status_code=200`, `event.outcome="success"`. |
| **AC-02** | FR-02 | Given `exclude_paths` contains `/health` · When `GET /health` is called 10 times · Then zero documents exist for it. |
| **AC-03** | FR-04 | Given a `POST` with a 3 KB JSON body · When handled · Then the handler received byte-identical bytes **and** the document's `audit.request.body` holds the parsed object. |
| **AC-04** | FR-08 | Given a 2 MB JSON body and `max_body_bytes=1048576` · When logged · Then `audit.request.body_truncated=true`, stored raw body ≤ 1 MiB, and the handler received all 2 MB. |
| **AC-05** | FR-10, FR-11 | Given a body `{"password":"p","nested":{"api_key":"k"},"items":[{"token":"t"}]}` · When logged · Then none of `p`, `k`, `t` appears anywhere in the document, and all three keys are present with `"[REDACTED]"`. |
| **AC-06** | FR-12 | Given a request with `Authorization` and `Cookie` headers · When logged · Then neither key appears in `audit.request.headers`, while `content-type` and `user-agent` do. |
| **AC-07** | FR-03 | Given a request to an unrouted path · When it 404s · Then a document exists with `audit.route="unmatched"` and `http.response.status_code=404`. |
| **AC-08** | FR-01, NFR-3 | Given an endpoint that raises `ValueError` · When called · Then the exception propagates unchanged to the app's own handler **and** a document exists with `event.outcome="failure"`, `http.response.status_code=500`, `error.type="ValueError"`. |
| **AC-09** | FR-19 | Given `queue_max_bytes` set below one batch · When 200 requests are made · Then `audit_documents_dropped_total > 0`, every request still returns 200, and no exception surfaces. |
| **AC-10** | NFR — mapping bound | Given 50 endpoints × 200 requests with distinct body shapes · When all are indexed · Then `GET _mapping` reports a field count **≤ 200**. |
| **AC-11** | FR-15 | Given `AUDIT_ENABLED=false` · When the app is restarted and requests are made · Then zero documents are produced and no log file is created. |
| **AC-12** | FR-22 | Given `file_max_bytes` set to 64 KiB · When enough documents to rotate three times are submitted · Then `.1`/`.2`/`.3` exist, `audit_file_rotations_total=3`, and **every** line reaches Elasticsearch. |
| **AC-13** | FR-06 | Given a `StreamingResponse` yielding 5 chunks 100 ms apart · When it completes · Then `event.duration` is ≥ 400 ms and `http.response.bytes` equals total emitted. |
| **AC-14** | FR-09 | Given a POST with `Content-Type: application/json` and body `{not json` · When logged · Then `audit.request.body_parse_failed` is true, `body_raw` holds the string, and the handler received the bytes unchanged. |
| **AC-15** | FR-20r | Given 1000 documents submitted within 100 ms · When `flush_interval_seconds` is 1.0 · Then all 1000 lines are on disk within 1.5 s, in submission order. |
| **AC-16** | FR-21r | Given the log directory is made unwritable after 50 documents · When 50 more are submitted · Then the API keeps returning 200, `audit_documents_failed_total ≥ 50`, and the process does not exit. |
| **AC-17** | FR-25 | Given a `user_resolver` that raises · When a request is logged · Then the document exists without `user.*`, and `audit_middleware_errors_total = 1`. |

### 2.1 Criteria added after the adversarial review

AC-01…AC-17 left nine FRs and six NFRs without a numbered criterion (A6's
matrix gap), and the review added four requirements of its own. These close
both. AC-18…AC-26 are **[reconstructed]** by the orchestrator.

| # | FR | Given / When / Then |
|---|---|---|
| **AC-18** | FR-28 | Given the body `{"password":"p"}` sent with `Content-Type: text/plain`, with `application/xml`, and with **no content type at all** · When logged · Then no document contains `p`, each has `body_skipped="content_type"`, and neither `body` nor `body_raw` is present. **This is the M-1 regression test.** |
| **AC-19** | FR-29 | Given a 1 MiB body of `[[],[],…]` · When logged · Then `body_skipped="too_complex"`, no body is stored, and `build_document` completes in < 5 ms. |
| **AC-20** | FR-30 | Given any request · When logged · Then `body` and `body_raw` are never both present, and a 1 MiB body produces a JSONL line under Filebeat's `message_max_bytes`. **This is the M-3 regression test.** |
| **AC-21** | FR-31 | Given a `user_resolver` returning `{"id": 7, "roles": {"a": "b"}}` · When logged · Then `user.id == "7"`, `roles` is absent or a list of strings, and every emitted `user.*` value matches the type in schema §2.5. |
| **AC-22** | FR-08, M-4 | Given 20 concurrent requests each dribbling 1 MiB in 2-byte chunks · When they are in flight · Then peak RSS attributable to the **capture buffer** is ~1× `max_body_bytes` per in-flight request, across at least a 1000× change in chunk size. *Corrected after A6 measured it:* the original "< 2× per request" was unachievable on the **parsed** path by any implementation — the parse, the redacted copy and the serialised line each hold roughly one copy (~6× measured). M-4 was about the capture path, which holds one; that is what this AC bounds. |
| **AC-23** | FR-05, FR-24 | Given a 204 and a HEAD response · When logged · Then `http.response.bytes == 0`, the document exists, and `X-Request-ID` is present on the response exactly once. |
| **AC-24** | FR-13, FR-14 | Given `extra_redact_keys=["tenant_ref"]` and a request with `?tenant_ref=X` and `{"tenant_ref": "Y"}` · When logged · Then neither `X` nor `Y` appears, and every default denylist key still redacts (extension is additive, never replacing). |
| **AC-25** | FR-22, FR-26 | Given `file_max_bytes=64 KiB` with the default `flush_max_bytes` (4 MiB — deliberately larger than the file, which is what broke it) · When 2000 documents are written · Then **no file on disk exceeds `file_max_bytes` by more than one line** and rotations are counted. "Every line survives" requires `file_backup_count` ≥ 43 at this size: the real document is ~1385 B, so 2000 need 2.77 MB of retention, and 9 generations × 64 KiB holds 590 KiB. (The original text said ~940 B and ≥ 40 — A6 measured the line and corrected the constants; tests derive them from the measured size rather than hard-coding either.) Retaining less is FR-22 doing its job, not a bound failure — the two clauses must be tested at different backup counts. **This is the S-10 regression test.** |
| **AC-26** | FR-18, FR-27 | Given a sink under sustained load with a failing disk · When `close()` is called · Then it returns within `shutdown_flush_timeout`, `audit_documents_failed_total` equals the number of documents actually lost (not double-counted), and total process memory attributable to the queue stays within `queue_max_bytes` × 2. |

### 2.2 Known deviations from the frozen contracts

Recorded rather than silently carried. Both are orchestrator decisions taken
after the review, when reopening a frozen contract would have cost more than
the deviation.

| # | Deviation | Why it stands |
|---|---|---|
| **DEV-1** | The true received-byte count (FR-03 / S-1) travels from the `receive` wrapper to `build_document` through `scope["audit_logging.received_bytes"]`, not a `RequestContext` field. | `RequestContext` is frozen and every module was built against it. The channel is invisible to the application and set only after the app returns, so FR-24 still holds ("`X-Request-ID` is the only mutation"). **This should become `RequestContext.received_bytes` the next time the contract opens.** Without the counter the field degrades to `Content-Length`, then to the captured length — and that last case is a *visible* lower bound, since `body_truncated` is true and `body_bytes` equals it. |
| **DEV-2** | `audit.request.body_truncated` now also flags the 4096-character clip applied to an unparseable `body_raw`, not only the `max_body_bytes` cap. | Consistent in meaning ("what is stored is not all of it"). **The original justification given here — that a separate flag would cost a mapping entry — was wrong**: at 51 fields used of a 200 limit there is ample room, as A8 pointed out. The honest reason is that one flag meaning "what is stored is not all of it" is simpler to reason about than two, and the distinction is recoverable from `body_skipped` and `body_parse_failed`. `docs/redaction.md` must state the widened meaning. |

---

## 3. Edge cases (plan §10 reconstruction)

Every one of these must have a unit test.

| Case | Required behaviour |
|---|---|
| Empty body (`Content-Length: 0`) | `body_skipped="empty"`, no `body`/`body_raw` keys, no parse attempt. |
| Body sent in many chunks | Reassembled in order; app receives the same chunk boundaries. |
| App never reads the body | Document still emitted; body fields reflect only what was received (`body_skipped="unread"` where nothing arrived). Middleware must not hang waiting. |
| App reads the body twice | Second read behaves exactly as unwrapped ASGI does (returns the disconnect/empty message); the middleware does not resurrect consumed messages. |
| Client disconnects mid-request | `event.outcome="disconnected"`, whatever status was seen, document still emitted. |
| Non-object JSON top level (`[1,2]`, `"x"`, `null`) | Wrapped as `{"_value": …}` for the `flattened` copy; `body_raw` keeps the original text. |
| JSON with duplicate keys | Python's last-wins parse is recorded in `audit.request.body`. **Under FR-30 there is no `body_raw` for a parseable body at all** (schema §2.9), so the original byte sequence is not retained and the duplicate is not recoverable. This row previously described the superseded both-fields behaviour and contradicted §2.9; the loss is real and is the accepted cost of FR-30. |
| Nesting deeper than 20 levels | The subtree at depth 20 is replaced by `"[TRUNCATED]"` — the deep **values** must not survive. |
| Self-referential / cyclic input | Terminated by the depth cap, never infinite recursion (plan A3 DoD). |
| Unicode / homoglyph / whitespace keys | `normalize_key` lowercases and strips `_`, `-`, `.`; anything it does not catch is a documented limitation in `docs/redaction.md`, not a silent one. |
| Secret in the URL path | **Not protected, and worse than it looks.** A route that *names* the parameter (`/keys/{api_key}`) has its `audit.path_params` value redacted. But `url.path` stores the raw path regardless, and `url.path` is an **indexed** `keyword` — so a secret in a path is not merely stored, it is *searchable* in Elasticsearch. A positional segment the route does not name is not redacted anywhere. Nothing key-based can fix this; the mitigation is not to put secrets in URLs. Must be stated in `docs/redaction.md`. |
| Response with no body (204, HEAD) | `http.response.bytes = 0`, document emitted normally. |
| `Expect: 100-continue` | Passed through; body capture still works. |
