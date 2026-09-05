# Changelog

Notable changes to `audit_logging`. This file follows the shape of
[Keep a Changelog](https://keepachangelog.com/); versions are semver.

---

## 0.1.0 — 2026-09-05

First release. The package captures one JSONL audit document per API request at
the ASGI layer, redacts it, and writes it to a rotating file. Filebeat ships the
files; the package imports no network client.

`audit_logging.__version__` and `pyproject.toml` currently read `0.1.0.dev0`;
bump both to `0.1.0` at tag time.

### ⚠ Supersessions of locked plan decisions

`PLAN-request-audit-logging.md` §1 locks a set of decisions. Two of them do not
describe the shipped behaviour. Anyone who read the plan and stopped there will
expect the old behaviour, so they are recorded here as loudly as they deserve.

#### D-10 — `body` and `body_raw` are now **mutually exclusive**

**The plan says:** "Full raw body stored unindexed **plus** a `flattened` copy
for search."

**What ships:** exactly one of `audit.request.body` and `audit.request.body_raw`
is emitted, per `docs/schema.md` §2.9 and FR-30. A parseable JSON or
form-encoded body produces `body` only; a JSON body that failed to parse, or a
text body captured under `capture_text_bodies`, produces `body_raw` only;
several cases produce neither and set `audit.request.body_skipped`. The full
nine-row table is `docs/schema.md` §2.9.

**Why:** storing both doubled every line. A 1 MiB body produced a
**2,097,957-byte** JSONL line — 805 bytes past Filebeat's then-configured
`message_max_bytes` — and 3.0 MiB when the body contained quotes. Those lines
were truncated by filestream, failed ndjson decode, and were silently discarded
by a `drop_event` processor: **the largest and most interesting audit records
never reached Elasticsearch, and no counter on either side recorded the loss**
(review M-3). It also put a second full serialisation of an attacker-sized body
on the request path (review M-2).

**What you lose:** for parseable JSON, only key order and duplicate keys. The
`flattened` `body` *is* the complete content. Where content genuinely cannot be
represented as an object, `body_raw` still carries it verbatim, so D-10's
intent — full fidelity with the mapping bounded — is preserved.

**What to change if you built on the old behaviour:** a query that looks in one
field and finds nothing should look in the other before concluding the body was
not captured; `audit.request.body_skipped` says which case applies. Storage
dropped by half as a result — 30,000 requests wrote **266.2 MiB** of JSONL
against 534.8 MiB before (measured, `tests/AC-matrix.md` §6).

*Tests:* AC-20 (all nine §2.9 rows), `test_document.py::test_FR_30_*`.

#### FR-08 / D-4 — what a truncated body actually stores

**The plan says (D-4):** "Body cap 1 MB, truncation flagged, never unbounded",
and plan §2 already supersedes the old FR-08 default of `65536` with
`1_048_576`. FR-08 then says a body over the cap is "truncated at the cap and
flagged `body_truncated = true`", and AC-04 asks for a "stored raw body
≤ 1 MiB".

**What ships, and the nuance:** the cap and the flag are exactly as described,
and the application still receives the **full** body byte-identically. But a
JSON body cut at 1 MiB is cut mid-JSON, so it **cannot parse** — it takes the
FR-09 parse-failure path, and what is stored is `body_raw` clipped to **4096
characters**, not a ~1 MiB truncated object. A 2 MB JSON body yields
`body_truncated: true`, `body_parse_failed: true`, `body_bytes: 1048576`, and
about 4 KB of text. If you read AC-04 expecting a parsed-but-truncated *object*,
the requirement and the implementation disagree — flagged here rather than
quietly reinterpreted (`tests/AC-matrix.md` §4.3).

**And DEV-2, which widens a flag you may be counting:**
`audit.request.body_truncated` now means "what is stored is not all of it" in
**two** cases — the `max_body_bytes` cap *and* the 4096-character clip on an
unparseable body. It used to mean only the first. Anything alerting on the
truncation rate is now counting both (`docs/REQUIREMENTS.md` §2.2 DEV-2,
`docs/redaction.md` §4.6).

The clip exists because the parse-failure path is the one remaining unredacted
field in the document and a client reaches it by breaking its own JSON
(review S-2). It bounds what that costs: 1 MiB of hostile body becomes a
~5 KB line instead of a ~1 MiB one.

*Tests:* AC-04 in both tiers, which also pin `_MAX_UNPARSED_BODY_RAW == 4096` so
the clip cannot move silently.

### Deleted before implementation

**FR-16 and FR-17 — sampling — were deleted by plan §2 and never built.** There
is no sampling, no sample rate, and no configuration for one. Every non-excluded
request produces exactly one document (D-2, FR-01). `exclude_paths` is the only
way to reduce volume, and it is all-or-nothing per path prefix. They are
correctly absent from the code, the config, the schema and the tests
(`tests/AC-matrix.md` §3).

### Added

**Capture** (`middleware.py`, `document.py`) — one document per non-excluded
HTTP request whatever the outcome; byte-identical request-body replay at the raw
ASGI layer; route template, path params, client, timing to the last response
chunk, response byte count; `trace.id` from `X-Request-ID` or a fresh UUID4,
echoed back on the response; optional `user_resolver`. Non-`http` scopes pass
through untouched. Response bodies and uploaded file bytes are never stored.

**Redaction** (`redact.py`) — a 106-key denylist over normalized body, query,
path-param and multipart keys at every depth, and a 35-name header allowlist
where anything unlisted vanishes without a placeholder. Both extended additively
through `AuditConfig`. `redact()` is pure. It is also where captured keys **and
string values** are made safe for the fields they land in — an over-long key, a
control character, or a lone surrogate in either a key or a value would
otherwise destroy the whole audit document. **Read `docs/redaction.md` §4 for
what it does not protect against** — all of it is disclosed, and §4 now says
plainly which items are pinned by a test and which are not.

**Sink** (`sinks/file_sink.py`, `metrics.py`) — a byte-bounded in-memory queue
draining on an interval or a size threshold to `{service_name}-{pid}.jsonl`,
with size-based rotation, one retry on a write failure, and a `close()` that
returns within `shutdown_flush_timeout` regardless. `InMemoryMetrics` by
default, `PrometheusMetrics` behind an extra.

**Kill switch** — `AUDIT_ENABLED=false` makes the middleware a pure
pass-through: no document, no queue, no file. Note that it takes FR-24's
`X-Request-ID` response header with it (review N-14), which is a change in API
behaviour and is called out in `docs/runbook.md` §0.

**Documentation** — `README.md`, `docs/integration.md`, `docs/redaction.md`,
`docs/runbook.md`, this file.

### Hardened after the adversarial review

`REVIEW.md` found 5 must-fix, 16 should-fix and 15 note-level findings before
pilot. The five must-fixes and the significant should-fixes — all of which the
second review re-ran and confirmed closed:

| # | Was | Now |
|---|---|---|
| **M-1** | Any body with a `text/*`, `application/xml`, `application/graphql` or **absent** content type was stored verbatim, denylist never consulted. `Content-Type: text/plain` on a JSON payload defeated the whole thing | Such bodies are **not stored at all** by default (`body_skipped: "content_type"`, FR-28). `capture_text_bodies` opts back in behind an explicitly weaker scrub (AC-18) |
| **M-2** | One 1 MiB JSON body blocked the event loop for 56–141 ms — ~9 rps saturated a worker | `max_body_nodes` (FR-29) refuses an over-complex body **before** parsing it: the same 1 MiB payload is now refused in ~1.5 ms (AC-19) |
| **M-3** | 1 MiB body → 2.0–3.0 MiB line, silently dropped by Filebeat | FR-30 / schema §2.9 (see above). Largest reachable line is now 1,049,779 B, 12.5 % of `message_max_bytes` (AC-20) |
| **M-4** | Chunked bodies buffered into a list of `bytes`: 28× memory amplification, 1.4 GB RSS from 50 slow-loris connections | A single `bytearray`. Peak is 1.00× across a 32,768× change in chunk size (AC-22) |
| **M-5** | `user.*` written unvalidated into `keyword` fields — a mistyped `user_resolver` return made Elasticsearch reject the **whole** document | Values coerced to the schema's types, uncoercible ones dropped (FR-31, AC-21) |
| **S-1 / DEV-1** | `http.request.bytes` under-reported every chunked body over the cap | The true count travels on `scope["audit_logging.received_bytes"]`; the fallback remains a visible lower bound |
| **S-2** | An unparseable body stored its raw text without limit | Clipped to 4096 characters and flagged (DEV-2) |
| **S-3** | `?a=1;token=SECRET` and `?%20token=SECRET` passed verbatim into the **indexed** `url.query` | Query and form parsing splits on `;` as well as `&` and strips whitespace from keys |
| **S-5** | An internal failure after the response started lost the document entirely | `build_minimal_document` emits a hole marker — trace id, method, path, status, outcome — instead of a hole |
| **S-6 / S-7** | One WARN latch per process silenced every later error of any kind; the sink's ERROR key collapsed `ENOSPC`, `EDQUOT` and `EIO` into one line | Keyed per error kind, and per `phase:type:errno` |
| **S-8** | The real ceiling was 3× `queue_max_bytes` and `audit_queue_bytes` was blind to two thirds of it | `queue_bytes` and the gauge count the in-flight and retry batch too; peak is bounded at 2× |
| **S-9** | `audit_documents_failed_total` double-counted every retried batch | Counted exactly once, on the attempt after which the batch is discarded (AC-26: 122 lost, counter 122) |
| **S-10** | A freshly rotated 0-byte file never rotated, whatever the payload — one file reached 28.6× `file_max_bytes` | Batches are written in segments with a rotation between them; only a single line larger than `file_max_bytes` can exceed the bound (AC-25) |
| **S-11** | Two live sinks on one path destroyed 35 % of each other's lines | The second takes a `-{6 hex}` suffix (FR-26) |
| **N-7** | Multipart part names and filenames were stored unredacted | Clipped, denylisted as keys, and a `filename` under a denylisted part `name` is redacted |
| **N-8** | A document submitted after `close()` was counted as an ordinary drop | Its own counter, `audit_documents_dropped_after_close_total` |
| **N-9** | A 40 KB body key, or a key containing NUL, made Elasticsearch reject the whole document | Keys bounded at 1024 UTF-8 bytes and stripped of control characters and lone surrogates, with a digest suffix so distinct keys cannot collapse |
| **N-13** | `exclude_paths` prefixes were unanchored — `/health` excluded `/health-secret/transfer` | Anchored at a path-segment boundary |

### Hardened again after the verification pass

**The package was reviewed twice.** `REVIEW-2.md` re-ran every finding above
against the fixed tree — all five must-fixes and all sixteen should-fixes held —
and then attacked the fixes themselves. **It found three new must-fixes of the
same severity as the ones they closed, plus one narrow-trigger defect with a
large blast radius.** That is not a criticism of the fix passes; new code
written under time pressure to close a security finding is where the next defect
lives, and it is the reason a verification pass exists. Everything in this
section is a defect *introduced or exposed by the first round of fixes*.

| # | Was | Now |
|---|---|---|
| **N2-1** | **A 14-byte request body deleted its own audit record.** `{"a":"\ud800"}` on any JSON endpoint: `orjson` refuses to parse a lone surrogate, the stdlib fallback accepts it, `redact()` sanitised keys but never values, and `orjson.dumps` then refused to serialise the finished document. The loss was filed under `audit_documents_dropped_total`, whose documented meaning is "the disk is not keeping up" — so the only signal pointed an operator at the wrong subsystem, and a client could fire or mask a disk-pressure alert at will. **Client-selected suppression of the audit trail, unauthenticated, one field** | String **values** are sanitised as well as keys: surrogates become U+FFFD with a BLAKE2b digest of the original appended, so a reader can tell a U+FFFD the package wrote from one the client sent and two distinct values cannot silently merge. `_dumps` also falls back to the stdlib encoder. A serialisation failure is now `audit_documents_failed_total`, never `dropped_total` (`test_N2_1_*` in `test_redact.py` and `test_file_sink.py`) |
| **N2-2** | **The key-sanitisation memo retained attacker-supplied strings across requests**, capped at 4096 *entries* and not at bytes, with the full-length original as the dict key. One 256 KB key per request retained 1000 MiB after 4000 requests; at `max_body_bytes` the reviewer's own repro was OOM-killed by the kernel. M-4's failure mode moved from in-flight memory into a process-global cache, where no amount of backpressure or rate limiting reclaims it | Only keys the fast path can serve are memoised — a key long enough to be excluded is one the memo could never have helped with. Retained text is now bounded by `4096 × 256` characters, ≤ 4 MiB |
| **N2-3** | **The query string was not bounded at all.** `_query` is split → `unquote_plus` per key *and* per value → `redact` → `urlencode`, fully linear with a high constant, on the request path. 64 KB of query on a **bodiless `GET`** cost 17.9 ms of event-loop stall — over 3× the whole NFR-1 budget, from a request needing no body, no `POST` and no authentication. 8 KB is what a default nginx passes | New `max_query_bytes` knob (8192), with a pair bound derived as `max_query_bytes // 16`. Past either, `url.query` becomes the fixed literal `"[SKIPPED]"` — **never client bytes**, so the bound cannot be turned into an FR-14 redaction bypass — `audit.request.query` is `{}`, and a new `audit.request.query_skipped` says `too_complex` |
| **N2-5** | **Audit lines could be written into an unrelated file descriptor during shutdown.** `close()` closed the fd while a write was still parked in `asyncio.to_thread`; the number was then recycled by the next `os.open` or `accept`. Demonstrated: five complete audit documents appended to a plain application file, zero in the audit log. Descriptor numbers are shared with sockets, so the recipient can be a client connection | **The writer owns the close.** A write borrows the descriptor; `close()` takes it out of the sink and, if a writer holds it, leaves the number allocated and hands the close over. **The deliberate cost:** a write that never returns leaves one descriptor unclosed for the remaining life of a process that is already exiting. That trade is documented in `_close_fd` and in `runbook.md` §5 |
| **N2-4** | Per-key sanitisation was a cost amplifier: 4,998 keys each carrying one control character is a **73 KB** body — inside `max_body_bytes` and inside `max_body_nodes` — that cost 20 ms of event-loop stall. `FR-29` bounds node *count*; the cost of a node is attacker-chosen | The *work* is bounded too: past **128** cold-path keys per `redact()` call the rewrite degrades to a constant-cost `<≤24 ASCII chars>[SANITIZED:over-budget-<seq>]`. Safety does not degrade, only informativeness. **Known residual:** `document.py` calls `redact()` up to four times per request, so the per-request ceiling is 4 × 128 |
| **N2-6** | Bodies dropped as `too_complex` were invisible — `audit_documents_submitted_total` counted them as unqualified successes and no counter existed | Two new metrics in `METRIC_NAMES`: `audit_bodies_skipped_total` and `audit_queries_skipped_total`, kept **separate on purpose** so that someone alerting on lost bodies is not paged by a chatty query route. `docs/integration.md` §3.1 documents the `max_body_nodes` trade with the measured latency curve |

**Two new configuration knobs:** `max_query_bytes` (8192) and `max_scrub_bytes`
(32768).

**Two new metric names:** `audit_bodies_skipped_total`,
`audit_queries_skipped_total`. Neither counts a lost document —
`docs/runbook.md` §4.1 says what each one does and does not mean.

**One counter changed meaning:** a document that cannot be serialised is now
`audit_documents_failed_total`, not `audit_documents_dropped_total`. Anything
alerting on `dropped_total` as "disk pressure" is more correct than it was.

#### What the verification pass could *not* break

Recorded so the next reviewer does not re-spend the budget: `sanitize_key`
against marker forgery, shadowing, prefix collision, denylist evasion, the byte
bound and memo poisoning; `_exceeds_node_cap` against 20,000 generated documents
plus hand-picked adversarial shapes (zero under-counts); the `FileSink` rotation
locking; exception safety across six new failure injections; and byte-exact body
replay. `REVIEW-2.md` §6 has the detail.

#### Documentation corrected in the same pass

`docs/redaction.md` §4 claimed a test pinning each of its twelve limitations.
Four of those claims did not hold, and the section now distinguishes **pinned**
from **⚠ unpinned** rather than overstating the set — a limitation that is
documented but untested will silently stop being true, which is exactly what the
audit was for. The unpinned items are listed in a table at the head of §4 so
they can be commissioned. Also corrected: the FR-11 mandated-key count (35 → 36),
the `redact()` benchmark figure (which measured a fixture the shipped defaults
refuse), the field-count arithmetic against `docs/schema.md` §3, and the
prominence of `url.path` — a secret in a URL path is not merely stored, it is
**searchable**, because `url.path` is an indexed `keyword`.

### Known deviations (`docs/REQUIREMENTS.md` §2.2)

* **DEV-1** — the true received-byte count travels through
  `scope["audit_logging.received_bytes"]` rather than a `RequestContext` field,
  because the contract is frozen. It should become
  `RequestContext.received_bytes` the next time the contract opens.
* **DEV-2** — `body_truncated` now also flags the 4096-character clip. See the
  FR-08/D-4 entry above.

### Known open defects

* **D-A6-5** — `FileSink._rotate` races the sink's lazy `start()`. About one run
  in three, a rotating sink ends with a **gap in the `.N` numbering** and one
  file at ~2× `file_max_bytes`. **No lines are lost.** It is an FR-22 bound
  violation, so size node disk with headroom rather than at exactly
  `file_max_bytes` × (`file_backup_count` + 1). Mechanism and repro:
  `tests/AC-matrix.md` §7.
* **N-2** — a TCP reset or a shutdown-cancelled request records
  `event.outcome: "failure"` with `error.type: ConnectionResetError` /
  `CancelledError`, rather than `"disconnected"`. During a rolling deploy every
  in-flight request becomes a `failure` in the index. Exactly one document is
  still emitted.
* **N-12** — `trace.id` is client-chosen when the client sends `X-Request-ID`.
  Deduplicate on `trace.id` + `host.hostname` + `process.pid` + `@timestamp`,
  never on `trace.id` alone (`infra/README.md` §6.4).
* **N2-4 residual** — the cold-key budget is **per `redact()` call**, and
  `document.py` calls `redact()` up to four times per request (query, path
  params, multipart metadata, body). The per-request ceiling is therefore
  4 × 128 cold-path keys, not 128. Flagged by the fix agent; the bound is still
  a large improvement on unbounded, but it is not the number the constant's name
  suggests.
* **N2-5 residual, accepted deliberately** — a write that never returns leaves
  one file descriptor unclosed for the remaining life of an exiting process. The
  alternative was audit records landing in an unrelated file or down a client
  socket via fd recycling, which was demonstrated. `runbook.md` §5.
* **N2-7** — the opt-in text scrub cannot see namespace-prefixed XML elements,
  so `<wsse:Password>` — the literal element name in WS-Security — leaks in the
  clear. Only affects services that set `capture_text_bodies=true`, but those
  are disproportionately the ones with SOAP traffic. `docs/redaction.md` §4.7.
* **N2-8** — the JSON parse-failure path still stores up to 4096 **unredacted**
  characters, and a client reaches it by breaking its own JSON. `AC-14` demands
  the raw text, so the code matches the contract; the reviewer's position is
  that the contract is wrong and a 256-character head plus a byte count plus a
  digest would serve the same diagnostic purpose without the whole credential.
  `docs/redaction.md` §4.6.
* **N2-14** — control characters in a query key defeat the denylist
  (`?pass%00word=SECRET` stores the value in the clear in both `url.query` and
  `audit.request.query`). Documented, **not tested**. `docs/redaction.md` §4.3.

### Not verified — read this before trusting the pipeline

**The Elasticsearch + Filebeat test tier has never been executed.** Docker is
not reachable from the environment this was built in. The 31 tests in
`tests/integration/test_acceptance_es.py` are written and collect cleanly, and
have never run. Everything asserted about behaviour *after* the JSONL line is
written — Filebeat's registry, rotation following, `message_max_bytes`, the
quarantine and dead-letter routes, `dynamic: false` as a cluster fact, the field
count from `_field_caps` — is reasoned from the config files, not observed.

The single most consequential item: **"every line reaches Elasticsearch across a
rotation" is unverified** (AC-12). If the harvester does not follow the rename,
lines are lost silently and nothing else notices.

The complete list, in both directions, is `tests/AC-matrix.md` §4 and §5. Also
unverified: multi-worker behaviour, real sockets (no uvicorn anywhere), ILM
phase transitions, the Kibana dashboards, and the dependency bound NFR-6.

### Measured

All numbers from executed tests on the build machine, not estimates:

| | |
|---|---|
| NFR-1 added p99 | **+0.819 ms** against a 5 ms budget — 300 s per arm, 100 rps, 8 KB bodies, real `FileSink`, real redaction. Benign arm. An **adversarial arm** (`tests/load/test_nfr1_adversarial.py`) covers the hostile shapes separately: 1 MiB pathological bodies 140.6 → 0.09 ms, 64 KB query 24.0 → 0.01 ms, hostile keys 20.0 → 3.28 ms; 7 of its 10 tests fail with the caps disabled |
| AC-10 field count | **51** created by real traffic; **63** mapping entries (45 leaves + 18 objects) against a 200 limit; a dynamic mapping would have created **20,194**. `docs/schema.md` §3 reconciles the four numbers |
| `redact()` at the shipped node cap | **~1.7 ms** for a 156 KB / 9,962-node body — the largest realistic shape `max_body_nodes=10000` admits (2026-09-05) |
| `redact()` on the 1 MiB benchmark fixture | 12.6 ms — but that fixture is 69,122 nodes and the shipped default **refuses** it, so it is not a production path |
| `max_body_nodes` latency curve | 6,802 nodes 2.61 ms · 17,002 nodes 4.95 ms (the budget) · 34,002 nodes 10.14 ms · 68,002 nodes 19.90 ms, on an order-batch shape. A lighter payload put ~20,000 nodes at ~3.2 ms — the crossover is shape-dependent |
| `submit()` | **~1.2 µs** on a ~2 KB document (2026-09-05; 1.0–1.6 µs across trials) |
| Middleware overhead | ~30 µs/request with sink and redaction stubbed |
| AC-15 | 1000 documents submitted in 5.1 ms, on disk 1021 ms later (budget 1.5 s) |
| AC-19 | 1 MiB shape bomb refused in 1.5 ms (was 140 ms of parsing) |
| AC-26 | 122 documents lost, counter 122, `close()` returned in 0 ms |
| Default suite | **584 passed** (`pytest tests -m "not integration and not load"` — unit plus the Tier-2 integration tier); `mypy --strict` clean |
