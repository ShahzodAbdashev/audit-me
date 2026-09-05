# REVIEW.md — adversarial review of `audit_logging` before pilot

| | |
|---|---|
| Reviewer | **A8 — adversarial reviewer** |
| Scope | `audit_logging/**`, `infra/**`, against `docs/REQUIREMENTS.md` + `docs/schema.md` (both frozen) |
| State reviewed | Phase 1 merged: 313 unit tests pass, `mypy --strict` clean on 10 source files (both re-verified here) |
| Method | Every **must-fix** and **should-fix** below has a runnable repro that was executed. Findings I could not execute are marked `unverified` and say what would settle them. |
| Not available | Docker, so no live Elasticsearch or Filebeat. ES/Filebeat findings are derived from the config files plus documents constructed programmatically and measured. |

---

## Verdict

**Not safe to pilot as it stands on any service that accepts requests from clients you do not control.** The package is well built — the ASGI replay layer is genuinely byte-exact, `redact()` is pure, the depth cap really does truncate deep *values*, the sink's write ordering is correctly serialised, and I could not make a single package exception escape into an application across ten injected-failure paths. Those are real results and they are listed in §8.

But three of the seven attack surfaces broke cleanly, and two of the breaks are the exact failure modes an audit log exists to prevent: **a silent PII leak** and **the audit record for the most interesting requests never arriving**. A third is a **remote denial of service on the application itself** at under ten requests per second.

For an internal pilot behind a trusted ingress, with all clients under the same team's control, the risk is manageable *after* M-1 and M-3 are fixed. For anything else, all five must-fixes should land first.

### Top three to fix first

1. **M-1 — redaction is opt-out by the client.** Any body whose `Content-Type` is `text/*`, `application/xml`, `application/graphql`, or **absent entirely** is stored verbatim in `audit.request.body_raw` with no redaction at all. `Content-Type: text/plain` on a JSON payload defeats the entire denylist. (`FR-10`, `AC-05`, contradicts `docs/schema.md` §2.7 "Full **redacted** body text".)
2. **M-3 — the biggest audit records are silently discarded before Elasticsearch.** A request at the documented `max_body_bytes` limit produces a **2,097,957-byte** JSONL line, which is 805 bytes over Filebeat's configured `message_max_bytes: 2097152`. With quoting it reaches 3.0 MiB. The line is truncated, ndjson decode fails, the `drop_event` processor discards it, and **no counter anywhere in the package or the shipper records the loss** — the package counts it as submitted and written. (`AC-04`, `AC-15`, `D-2`.)
3. **M-2 — one 1 MiB request blocks the event loop for 56–141 ms.** `build_document` parses, deep-copies, and re-serialises the body synchronously in the request path. That is 11–28× the entire `NFR-1` p99 budget of 5 ms, and it stalls *every concurrent request in the worker*, not just the attacker's. Roughly 8 req/s saturates one uvicorn worker. (`NFR-1`, `NFR-2`.)

### Findings by severity

| Severity | Count |
|---|---|
| **must-fix** | 5 |
| **should-fix** | 16 |
| **note** | 15 |

Every repro below was run with `/home/shahzod/mywork/audit_logger/.venv/bin/python`. Scratch scripts live in the session scratchpad, not in the project tree; each finding restates the minimal form inline so it can be re-run standalone.

---

## 1. Body replay correctness

The replay layer is the strongest part of the package. `receive_w` returns the **same message object** it received, so byte-fidelity is structural rather than accidental. I attacked all seven cases from the brief; six passed cleanly (see §8). One field is wrong.

### S-1 · should-fix · `http.request.bytes` under-reports a truncated chunked body

**Violates** `docs/schema.md` §2.4 — "`http.request.bytes` · Bytes actually received, **before truncation**".

`_request_bytes` (`document.py:201-216`) reads `Content-Length` and, when there is none — i.e. every chunked upload — falls back to `len(ctx.body)`, which is the *capped* buffer. The middleware never counts total received bytes; `buffered_len` stops incrementing at the cap too (`middleware.py:280-287`).

**Repro** — 60 bytes sent in three chunks, `max_body_bytes=32`, no `Content-Length`:

```python
cfg = AuditConfig(service_name="t", log_dir="/tmp/x", max_body_bytes=32)
# drive AuditMiddleware with:
#   {"type":"http.request","body":b"A"*20,"more_body":True}
#   {"type":"http.request","body":b"B"*20,"more_body":True}
#   {"type":"http.request","body":b"C"*20,"more_body":False}
```

**Observed**

```
app received: [('http.request', 20, True), ('http.request', 20, True), ('http.request', 20, False)]
identical to sent? True                      <- replay is correct
body_bytes=32  truncated=True  http.request.bytes=32
```

**Expected** `http.request.bytes == 60`. The field silently equals `max_body_bytes` for *every* chunked upload over the cap — i.e. it is uninformative for exactly the requests where request size matters. Fix is one `nonlocal` counter in `receive_w` that is not capped.

### N-1 · note · a partial body from a mid-request disconnect is stored raw and unredacted

Disconnecting mid-JSON leaves a truncated body that cannot parse, which routes into the `body_parse_failed` branch and stores the raw prefix verbatim (see S-2 for the general case):

```
disconnect after b'{"a":'  ->  body_parse_failed=True, body_raw='{"a":'
```

A client that cuts the connection just after the first bytes of a secret gets those bytes into the index. Same root cause as S-2; listed here because it needs no control over `Content-Type`.

### N-2 · note · a transport reset mid-stream is `outcome="failure"`, not `"disconnected"`

`_outcome` (`middleware.py:410-418`) infers disconnection only from an `http.disconnect` ASGI message arriving before the last response chunk. A real TCP reset surfaces as an exception out of `send`, never as `http.disconnect`:

```
client resets on chunk 3 of 5:
  documents=1  outcome=failure  status=200  bytes=30  error.type=ConnectionResetError
```

Also: a request cancelled by graceful shutdown records `outcome=failure`, `error.type=CancelledError`. During a rolling deploy every in-flight request becomes a `failure` in the audit index, and `error.type` accumulates transport noise alongside genuine application exceptions. `FR-01` still holds — exactly one document in both cases.

---

## 2. Redaction bypass

Three real bypasses. The first is the single most serious finding in this review.

### M-1 · must-fix · `body_raw` is stored **unredacted** for every non-JSON, non-form content type — including no content type at all

**Violates** `FR-10` ("Redaction is applied to the captured body … before the document is submitted"), `AC-05` ("none of `p`, `k`, `t` appears **anywhere** in the document"), and `docs/schema.md` §2.7, which types `audit.request.body_raw` as "**Full redacted body text**".

`_body_block` (`document.py:219-257`) redacts only two of its four branches. `BODY_KIND_TEXT` falls through to a bare `block["body_raw"] = text`. And `body_kind_for(None)` returns `BODY_KIND_TEXT`, so a request with **no `Content-Type` header** takes the same path.

**Repro**

```python
from audit_logging.document import build_document
from audit_logging._contracts import RequestContext
from audit_logging.config import AuditConfig
cfg = AuditConfig(service_name="t", log_dir="/tmp/x")
for ct in ("text/plain", "text/xml", "application/xml", "application/graphql", "text/csv", ""):
    hs = ([(b"content-type", ct.encode())] if ct else [])
    ctx = RequestContext(trace_id="t", started_ns=0, scope={"headers": hs, "type": "http"},
                         method="POST", raw_path="/p", query_string=b"",
                         content_type=ct or None,
                         body=b'{"password":"hunter2","api_key":"AKIA-SECRET"}',
                         ended_ns=1, status_code=200)
    print(ct or "<none>", build_document(ctx, cfg)["audit"]["request"].get("body_raw"))
```

**Observed** — identical for all six, including the no-content-type case:

```
text/plain           {"password":"hunter2","api_key":"AKIA-SECRET"}
text/xml             {"password":"hunter2","api_key":"AKIA-SECRET"}
application/xml      {"password":"hunter2","api_key":"AKIA-SECRET"}
application/graphql  {"password":"hunter2","api_key":"AKIA-SECRET"}
text/csv             {"password":"hunter2","api_key":"AKIA-SECRET"}
<none>               {"password":"hunter2","api_key":"AKIA-SECRET"}
```

**Expected** `"[REDACTED]"` in place of both values, per `AC-05`.

**Why this is a must-fix and not a limitation.** It is not a gap in *which key names* are caught — it is a whole content-type class where the denylist is never consulted at all, and the class is chosen by the client:

- `navigator.sendBeacon()` sends `text/plain` by default. Any browser telemetry or logout beacon carrying a session token lands verbatim in the index.
- GraphQL over `application/graphql` — login and `changePassword` mutations are plain text in the body.
- SOAP / XML APIs (`text/xml`, `application/xml`) carry credentials in `<Password>` elements.
- `text/csv` uploads are customer exports: names, emails, national IDs, stored in full, up to 1 MiB per request, for 90 days.
- Any client, malicious or merely misconfigured, can move a JSON payload out of the redacted path by changing one header.

The blast radius is a 90-day retention (`ilm-apiaudit.json`) of unredacted credentials in a searchable store, readable by everyone with access to the audit index. Note that `audit.request.body_raw` is `index:false, doc_values:false`, so the values are not *searchable* — but they are in `_source`, returned by every `GET`, and visible in the Kibana document viewer.

### S-2 · should-fix · a client can force the unredacted path on a JSON endpoint by breaking the JSON

**Violates** `AC-05`. Documented in `docs/REQUIREMENTS.md` §3 ("`body_raw` keeps the raw text verbatim and is **unredacted by construction** (AC-14)").

I am re-reporting a disclosed limitation because the disclosure understates it. `_body_block` reaches the unredacted branch on *any* `json.loads` failure, and the client chooses whether parsing succeeds.

**Repro**

```python
# same harness, ct="application/json"
body = b'{"password":"hunter2", oops}'      # one trailing token makes it unparseable
# -> {'body_parse_failed': True, 'body_raw': '{"password":"hunter2", oops}'}
```

**Observed** `body_raw='{"password":"hunter2", oops}'` — full secret stored.

The requirements frame this as "there is nothing to re-dump", which is true, but the consequence is that **every JSON endpoint has an unredacted-storage mode reachable by appending one byte**. `AC-05` says no denylisted value appears anywhere in the document; `AC-14` says the raw text is preserved. The two acceptance criteria conflict and `AC-14` currently wins by default. A safe reconciliation exists and is cheap: on parse failure, run a regex-based scrub of `"<denylisted-key>"\s*:\s*"[^"]*"` over the raw text before storing, or store a hash/prefix rather than the text. Either keeps the diagnostic value of `body_parse_failed` without the leak.

### S-3 · should-fix · query strings using `;` as a separator bypass `FR-14` in both fields

**Violates** `FR-14` and `docs/schema.md` §2.4 (`url.query` · "Raw query string, **with denylisted values already replaced**").

`_query` (`document.py:126-162`) uses `urllib.parse.parse_qsl`, which since Python 3.10 splits on `&` only. When a pair is not recognised, `changed` stays `False` and `url.query` is returned as the client's **original bytes**.

**Repro**

```python
from audit_logging.document import _query
from audit_logging.redact import DEFAULT_REDACT_KEYS as K
print(_query(b"a=1&token=SECRET", K))
print(_query(b"a=1;token=SECRET", K))
print(_query(b"%20token=SECRET",  K))
```

**Observed**

```
('a=1&token=%5BREDACTED%5D', {'a': '1', 'token': '[REDACTED]'})     <- correct
('a=1;token=SECRET',         {'a': '1;token=SECRET'})               <- LEAK, both fields
('%20token=SECRET',          {' token': 'SECRET'})                  <- LEAK, both fields
```

`;` as a query separator is legacy but is still emitted by older Java and PHP stacks and by hand-built links; W3C recommended it for years. The same code path serves `application/x-www-form-urlencoded` bodies, so `user=a;password=hunter2` leaks identically:

```
form body b"user=a;password=hunter2"  ->  body={'user': 'a;password=hunter2'}  body_raw='user=a;password=hunter2'
```

The `%20token` case is the whitespace-key gap (N-4) made remotely triggerable through percent-encoding.

The deeper issue is the design of the `changed` optimisation: **any pair `parse_qsl` does not split the way the application does becomes a verbatim passthrough of attacker bytes into `url.query`**. `url.query` is an indexed `keyword` (`ignore_above: 4096`), so unlike `body_raw` these leaked values *are* searchable.

### N-3 · note · secrets in the URL *path* are never redacted

`url.path` is `ctx.raw_path` verbatim (`document.py:331`). `/reset/token/abc123SECRET` is stored as-is and indexed. This is out of scope for `FR-10`/`FR-14` (which name body, query and headers) and is genuinely hard to fix without a key name to match on. It belongs in the "what is NOT protected" section that plan §8/A7 assigns to `docs/redaction.md`. Recording it so it is not forgotten.

### N-4 · note · homoglyph / fullwidth / whitespace / substring gaps — disclosed, but not yet where operators will see it

I verified each of A3's admitted gaps:

```
{" password": "hunter2"}   -> {" password": "hunter2"}    leading space
{"password ": "hunter2"}   -> {"password ": "hunter2"}    trailing space
{"Ｐａｓｓｗｏｒｄ": ...}    -> unchanged                    fullwidth
{"pаssword": ...}          -> unchanged                    Cyrillic а
"user_password_2" "my_token" "token_v2" "x-api-key-2" "password2"  -> all leak
```

**This is correctly handled as a documented limitation, and I am not re-reporting it as a must-fix.** Every one of these has an explicit `test_LIMITATION_*` in `tests/unit/test_redact.py:593-624` asserting the leak, with a comment tying it to `docs/redaction.md`. That is the right engineering behaviour.

Two caveats worth carrying forward:

- **The disclosure does not exist yet.** `docs/redaction.md` is referenced by `redact.py:49`, by `docs/REQUIREMENTS.md` §3 twice, and by two tests — and is not in the repository. Plan §8 assigns it to A7 in Phase 2. Until it ships, the limitation is documented to *developers reading the test file* and to nobody else. The pilot gate should be "A7's `docs/redaction.md` exists and names these", not "the tests assert them".
- **`normalize_key` and `filter_headers` disagree about whitespace.** `filter_headers` (`redact.py:361`) calls `.strip()` on names; `normalize_key` (`redact.py:236-249`) does not. Adding `.strip()` to `normalize_key` closes the whitespace class outright and is a two-character change with no downside I can find.

### N-5 · note · denylist asymmetry: plurals and trailing punctuation

`DEFAULT_REDACT_KEYS` covers `tokens`, `secrets`, `apikeys`, `cookies`, `credentials` — but not `passwords`. And any trailing character defeats the exact match:

```
"passwords"  -> leaks     ("tokens", "secrets", "apikeys" are all covered)
"Password!"  -> leaks
```

Not a design flaw, just an enumeration gap in a list that clearly *intends* to cover plurals. One-line additions.

### N-6 · note · `body_raw` vs `body` divergence for duplicate keys behaves as documented

```
b'{"a":1,"a":2,"password":"p1","password":"p2"}'
  body     = {'a': 2, 'password': '[REDACTED]'}
  body_raw = {"a":2,"password":"[REDACTED]"}
```

Both carry the last-wins parse, both redacted. This matches `docs/REQUIREMENTS.md` §3 exactly, and it *is* the safe choice — the original text would have carried `p1` under the shadowed key. Byte-fidelity is lost for parseable JSON, as A2 admitted, but the trade is the right way round. **No action.**

### N-7 · note · multipart part names and filenames are stored unredacted

`_multipart` (`document.py:165-198`) never stores part bodies — `FR-07`/`D-5` hold, verified. But `name`, `filename` and `content_type` go into `audit.request.multipart` with no redaction:

```
{"parts": [{"size": 7, "name": "password"},
           {"size": 7, "name": "f", "filename": "ssn-list.csv", "content_type": "text/csv"}], ...}
```

Filenames routinely carry PII (`ssn-list.csv`, `payroll-2026-a.karimov.xlsx`). The part *value* is safe; the filename is not.

---

## 3. Request-path blocking (NFR-2)

I read every path reachable from `submit()` and the `receive`/`send` wrappers rather than trusting the tests. **There is no `await`, no lock, and no I/O on the request path** — that part of `NFR-2` holds and is in §8. What does not hold is "allocates unboundedly", and `NFR-1` is missed by more than an order of magnitude.

### M-2 · must-fix · one 1 MiB JSON body blocks the event loop for 56–141 ms

**Violates** `NFR-1` (added p99 latency ≤ 5 ms) and `NFR-2` ("`submit()` must be no slower than a `deque.append` plus one serialisation").

`_emit` (`middleware.py:378-407`) runs `build_document` **synchronously, inline, before `AuditMiddleware.__call__` returns**. `build_document` does, for a JSON body: `json.loads` → `redact()` (a full deep copy) → `json.dumps` for `body_raw`. Then `FileSink.submit` serialises the whole document *again*. That is one parse, one deep copy and **two** full serialisations of the body per request, all on the loop thread with no yield point.

**Repro** — worst-case payloads, all under `max_body_bytes`, timed without profiler overhead, median of five:

```python
import json, time
from audit_logging.document import build_document
from audit_logging.config import AuditConfig
from audit_logging._contracts import RequestContext
cfg = AuditConfig(service_name="t", log_dir="/tmp/x"); CAP = cfg.max_body_bytes
evil = (b"[" + b'{"a":1},'*131071)[:CAP-1].rstrip(b",") + b"]"
ctx = RequestContext(trace_id="t", started_ns=0,
                     scope={"headers":[(b"content-type",b"application/json")], "type":"http"},
                     method="POST", raw_path="/p", query_string=b"",
                     content_type="application/json", body=evil, ended_ns=1, status_code=200)
t = time.perf_counter(); build_document(ctx, cfg); print((time.perf_counter()-t)*1000, "ms")
```

**Observed**

| 1 MiB payload | `build_document` | peak RSS |
|---|---|---|
| `8 KB` typical JSON (baseline) | **0.2 ms** | 0.0 MB |
| `[{},{},{},…]` | **56.0 ms** | 18.1 MB |
| `[{"a":1},{"a":1},…]` | **88.2 ms** | 15.2 MB |
| `[0,0,0,…]` | **93.4 ms** | — |
| `[[],[],[],…]` | **140.6 ms** | — |
| 1 MiB `text/plain` | 0.4 ms | — |

**Expected** ≤ 5 ms (`NFR-1`).

**And it stalls everything else.** Measured with a 5 ms heartbeat coroutine running alongside a single audited request through the real `AuditMiddleware`:

```
baseline event-loop lag (idle):                                    max  0.33 ms
benign 8 KB request:      middleware 0.66 ms,  loop lag max         0.23 ms
ONE 1 MiB [{"a":1},…]:    middleware 110.4 ms, loop lag max       106.7 ms
  -> sustained rate to fully saturate one uvicorn worker: 9.1 req/s
```

**Blast radius.** This is not "the attacker's own request is slow" — the whole worker is frozen. Roughly 8–9 req/s of 1 MiB `application/json` bodies, from one unauthenticated client, to *any* audited endpoint (the body is parsed before the app is asked whether it wants it), takes a worker to 100% and every other client's p99 with it. The pod's liveness probe is on the same loop. The plan's own §5 sizing assumes 200 rps; this attack needs 9.

Contributing factors, all fixable independently: `document.py` uses stdlib `json` even when `orjson` is installed (`file_sink.py` uses `orjson`, `document.py` does not); `body_raw` is produced by re-serialising the redacted tree rather than reusing the sink's serialiser; and there is no cap on the *number of nodes* in a parsed body, only on its byte length. A node cap (e.g. bail to `body_skipped="too_complex"` past N nodes) would bound all of it.

### M-4 · must-fix · slow-loris: 28 MB of RSS per in-flight 1 MiB body (28× amplification)

**Violates** `FR-08` ("Buffering stops at the cap — **no unbounded allocation**") and `NFR-2`.

`receive_w` (`middleware.py:270-292`) appends each chunk to a Python `list` and never coalesces. The **bytes** are capped at `max_body_bytes`; the **memory** is not, because it is dominated by per-object overhead (~33 B per `bytes` object plus 8 B per list slot), and the attacker chooses the chunk size via HTTP chunked transfer-encoding.

**Repro** — N concurrent requests, each dribbling 1 MiB through `AuditMiddleware` in fixed-size chunks and holding at the cap; RSS via `resource.getrusage`:

```
N=50 concurrent, 1 MiB body each
  chunk size    peak RSS      per in-flight request     amplification
    65536 B      84.1 MB           1.00 MB                  1.0x
       64 B     128.7 MB           1.90 MB                  1.9x
        8 B     385.7 MB           7.04 MB                  7.0x
        2 B    1439.0 MB          28.10 MB                 28.1x
        1 B     434.1 MB           8.01 MB                  8.0x   (CPython interns 1-byte bytes)
```

**Expected** ~1 MB per in-flight request, i.e. the `max_body_bytes` bound `FR-08` promises.

**Blast radius.** 50 concurrent slow-loris connections at 2-byte chunks = **1.4 GB RSS**. Typical API pod memory limits are 512 Mi–1 Gi, so ~20–35 concurrent connections OOM-kill the pod. This costs the attacker almost nothing (no compute, trickle bandwidth, connections held open) and it kills the *application*, not the logger — a logging component taking down the API is precisely the failure mode plan R-10 worries about for the sidecar variant. The fix is one line: buffer into a `bytearray` with `.extend()` instead of a `list` of `bytes`.

### S-4 · should-fix · a 1 MiB multipart body produces 104,857 uncapped part records

Same root cause as M-2 — work proportional to an attacker-controlled 1 MiB body, with no node cap. `_multipart` builds one dict per part and `audit.request.multipart` is a `flattened` field with 1–4 leaves per part.

```
1 MiB of b"--B\r\nz\r\n\r\n"  ->  part_count=104857   build 68.8 ms   line 1.10 MiB   RSS +24.7 MB
```

`FR-07` says "per-part name/filename/content-type/size when available" — it does not authorise 100k of them. Cap `part_count`, set `complete=False` past the cap.

---

## 4. Exception safety (NFR-3)

**I could not break this.** I walked all 51 `except` clauses in the package and ran ten injected-failure paths through the real middleware. Details of what held are in §8. Two consequences of the design are worth recording, and one path loses the document.

### S-5 · should-fix · `build_document` failing after the response has started loses the document with no way to know which one

**Violates** `FR-01` ("Every non-excluded HTTP request produces **exactly one** audit document, whatever the outcome").

**Repro** — patch `middleware.build_document` to raise, drive a 5-chunk streaming response:

```
app response delivered intact: ['http.response.start', 'http.response.body' x4]
client saw status 200; http.response.start sent 1 time     <- NFR-3 fully intact
documents submitted: 0                                     <- FR-01 violated
audit_middleware_errors_total = 1
```

`NFR-3` is honoured perfectly: the response is untouched, `send` is called exactly the right number of times, `http.response.start` is never sent twice, nothing propagates. But the document is gone and the only trace is a counter increment shared with every other internal error. `FR-01` and `NFR-3` are in genuine tension here; the resolution should at least be to emit a **minimal degraded document** (trace id, method, path, status, `event.outcome`) rather than nothing, so the audit trail has a hole marker instead of a hole.

The same applies to a hostile `scope`: `int(client[1])` in `document.py:343` is unguarded, so a client port that is not an integer costs the entire record.

```
client=('1.2.3.4','notaport')  ->  documents=0, audit_middleware_errors_total=1
```

### S-6 · should-fix · `_WARNED` is a module global: one WARN per process covers every error, forever, in every middleware instance

`middleware.py:49,55-66`. The first internal error of the process — including a completely benign one, like a `user_resolver` raising on one request — latches `_WARNED = True`. Every subsequent error in the process, of any kind, in any `AuditMiddleware` instance, is counted but never logged.

**Repro**

```
after the first (harmless) user_resolver error:  MW._WARNED = True
-> a later total redaction or serialisation failure produces no log line at all
```

This satisfies `NFR-3` to the letter ("logged once at WARN per process") and defeats its purpose. A per-*message* latch (a `set` of `what` strings, as `FileSink._log_once` does) costs nothing and keeps the noise bound.

### S-7 · should-fix · `FileSink._log_once` keys on the exception class alone, so `phase` and `errno` collapse

`file_sink.py:484-498`. `key = type(exc).__name__` ignores both the `phase` argument and the errno.

**Repro** — five distinct failures, then count emitted ERROR lines:

```python
s._log_once(OSError(errno.ENOSPC, "No space left on device"), "write")
s._log_once(OSError(errno.EDQUOT, "Disk quota exceeded"),      "write")
s._log_once(OSError(errno.EIO,    "I/O error"),                "write")
s._log_once(PermissionError(errno.EACCES, "Permission denied"),"open")
s._log_once(OSError(errno.ENOSPC, "No space left"),            "open")
```

**Observed** 2 ERROR lines for 5 distinct failures.

- `ENOSPC`, `EDQUOT` and `EIO` are all bare `OSError`: **one line covers all three**, so "disk full" and "disk failing" are indistinguishable in the logs.
- Because `phase` is not in the key, **a transient `OSError` at `open` during boot permanently silences every later `OSError` at `write`** — the exact sequence you get on a pod whose hostPath is not yet mounted.

(A4's report claims `ENOSPC` and `EACCES` share a line. They do not — `EACCES` raises `PermissionError`. The real collapse is the one above, and it is worse.)

### N-8 · note · `submit()` after `close()` silently drops in-flight requests' documents

```
await sink.close(); sink.submit({...})  ->  False, audit_documents_dropped_total += 1
```

`AGENTS.md` has the middleware call `sink.close()` on `lifespan.shutdown` *before* forwarding it to the app. Any request still completing in that window loses its document and is counted as a *drop* (i.e. "disk not keeping up", per `FR-19`), conflating graceful shutdown with a paging event.

---

## 5. Resource exhaustion

M-4 above is the request-path half. This is the sink half.

### S-8 · should-fix · the real in-memory ceiling is **3× `queue_max_bytes`**, and `audit_queue_bytes` cannot see it

**Violates** `FR-18` ("The in-memory queue is bounded **in bytes** by `queue_max_bytes`").

Three copies coexist during a slow or failing write:

1. `self._queue` — refilled by `submit()` up to `queue_max_bytes` the instant `_drain()` empties it;
2. the drained `batch` list, held across `await asyncio.to_thread(...)` and, on failure, parked in `self._retry` (`file_sink.py:379-396`);
3. `payload = b"".join(batch)` inside `_write_batch` (`file_sink.py:417`) — a full third copy, which A4's "worst case is ~2×" admission misses.

**Repro** — `queue_max_bytes = flush_max_bytes = 16 MiB`, `_write_batch` replaced by one that joins the batch and then blocks for 2 s:

```
queue_max_bytes=16 MiB | in flight: batch(4182 docs) + join copy, queue(4182 docs)
audit_queue_bytes gauge reports 16.00 MiB
RSS = 82.5 MB (baseline 34.0)  ->  +48.5 MB for a 16 MiB bound  =  3.0x
```

**Expected** ≤ 16 MiB. At the 64 MiB default this is **~192 MiB of RSS** attributable to the sink during any disk stall — on top of the application's own footprint and on top of M-4's request buffers, in a pod sized from a document that promises 64 MiB.

The observability half is as bad: `audit_queue_bytes` is set from `self._queue_bytes` only, so the gauge reads **0.00 MiB while a full batch is resident in `_retry`**. The one signal an operator has for "am I about to OOM" is blind to two thirds of the memory.

### S-9 · should-fix · `audit_documents_failed_total` double-counts every document

`_flush_once` increments by `len(batch)` on the first failure *and* again on the retry (`file_sink.py:393`).

**Repro** — 10 documents, write always fails:

```
_write_batch calls = 2
audit_documents_failed_total = 20.0     (10 documents submitted)
audit_documents_dropped_total = 0.0
```

`AC-16` asserts `>= 50` for 50 documents so it passes, but any alert threshold or capacity calculation derived from this counter is 2× off. Separately, a batch discarded on `CancelledError` *during a retry* (`file_sink.py:387-391`, `if not is_retry`) is lost with **no counter at all** — the only silent-loss path I found inside the sink.

---

## 6. Rotation races

### S-10 · should-fix · `file_max_bytes` is not a bound: the active file reached **28.6×** its configured maximum

**Violates** `FR-22` and `AC-12`.

Two defects in `_write_batch` (`file_sink.py:415-431`):

- the rotation check is `if self._file_bytes and self._file_bytes + len(payload) > file_max_bytes` — the leading `self._file_bytes` truthiness test means a **freshly opened or freshly rotated (0-byte) file never rotates, whatever the payload size**;
- the check runs once per batch and never splits a batch, so the true bound is `file_max_bytes + max_batch_bytes`.

Nothing in `AuditConfig` relates `flush_max_bytes` (default 4 MiB) to `file_max_bytes`; the model validator only checks `queue_max_bytes >= flush_max_bytes`.

**Repro A** — `AC-12`'s own configuration, `file_max_bytes = 64 KiB`, with default `flush_max_bytes`:

```python
cfg = AuditConfig(service_name="svc", log_dir=D, file_max_bytes=64*1024,
                  file_backup_count=8, flush_max_bytes=4*1024*1024)
s = FileSink(cfg, m); await s.start()
for i in range(2000): s.submit({"@timestamp": "x", "pad": "y"*900, "i": i})
await s.close()
```

**Observed**

```
svc-<pid>.jsonl   1,872,890 bytes      (file_max_bytes = 65,536)
rotations = 0.0                        (expected ~28)
```

**Repro B** — `file_max_bytes=1024`, four flushes of ~2.4 KB each:

```
svc-<pid>.jsonl     2466 bytes   (max=1024)
svc-<pid>.jsonl.1   2466 bytes
svc-<pid>.jsonl.2   2466 bytes
rotations = 3.0
```

Every file is 2.4× its maximum, because the batch that fills a fresh file is never checked.

With the shipped defaults (256 MiB / 4 MiB) the overshoot is ≤ 1.5% and harmless. It matters because the **node disk sizing in `infra/filebeat/daemonset.yaml` is derived from this bound** — "file_max_bytes 256 MB × file_backup_count 8 = 2 GB per pod, size /var/log/audit accordingly". Anyone who tunes `file_max_bytes` down (to rotate more often, or to fit a smaller volume) without also tuning `flush_max_bytes` gets a silently unbounded file on a node volume shared with the kubelet.

### S-11 · should-fix · two `FileSink`s on the same path destroy each other's data — 35% loss measured

`FR-26` names the file `{service}-{pid}.jsonl` with no uniqueness token. Two live sinks on that path each track `self._file_bytes` for *their own* writes only, so rotation fires at the wrong size, and one sink's `os.replace(base, base + ".1")` moves the file the other still holds an `fd` on — after which the second sink's writes land in a backup that will be shifted and eventually unlinked.

**Repro**

```python
cfg = AuditConfig(service_name="s", log_dir=D, file_max_bytes=2000, file_backup_count=3,
                  flush_interval_seconds=0.01, flush_max_bytes=256)
a = FileSink(cfg, m1); b = FileSink(cfg, m2)     # same path
await a.start(); await b.start()
for i in range(60):
    a.submit({"who":"A","i":i,"pad":"a"*60}); b.submit({"who":"B","i":i,"pad":"b"*60})
    await asyncio.sleep(0.002)
await a.close(); await b.close()
```

**Observed**

```
both sinks target: s-<pid>.jsonl  (identical path)
120 documents submitted, 78 lines survive on disk        -> 42 lines (35%) lost
```

**Expected** 120 lines. `FR-01`/`AC-12` ("**every** line reaches Elasticsearch").

In the deployed topology `subPathExpr: $(POD_NAME)` plus per-worker PIDs makes cross-pod and cross-worker collision unlikely, which is why this is should-fix and not must-fix. The realistic triggers are in-process: an app that mounts a sub-application with its own `AuditMiddleware`, an app that calls `add_middleware` twice, a test harness constructing sinks per test, or a supervisor restarting the process onto a recycled PID on a busy node. None of these are guarded, none warn, and the failure is silent data loss. Adding a short random or start-time token to the filename removes the class entirely at the cost of one more glob-matched file.

### §6 result — write ordering and overlap: **not broken**, see §8

A4 asked whether `asyncio.to_thread` can reorder lines or overlap two writes to the same fd. It cannot; `_lock` serialises `_flush_once` correctly. Measured in §8.

---

## 7. Infrastructure

Docker was unavailable, so ES/Filebeat behaviour is reasoned from the config files and demonstrated by constructing documents and checking them against the template's rules programmatically. The template itself is the strongest artefact in the repo — see §8. The problems are at the seams.

### M-3 · must-fix · a `max_body_bytes` request produces a line Filebeat will not ship, and nothing counts the loss

**Violates** `AC-04`, `AC-15`, `D-2` ("nothing is dropped").

`infra/filebeat/filebeat.yml` sets `message_max_bytes: 2097152` with the comment *"the package caps bodies at 1 MiB (D-4) so ~1.2 MiB is a generous per-line ceiling."* That estimate is wrong for two compounding reasons:

1. **The body is stored twice** — once parsed into `audit.request.body` (`flattened`) and once as text in `audit.request.body_raw`. Measured: a 1 MiB body yields a `body` copy of 1,048,576 B **and** a `body_raw` copy of 1,048,575 B.
2. **JSON escaping** inside `body_raw` adds up to another 1× (`"` → `\"`, control characters → `\n`).

**Repro**

```python
from audit_logging.sinks.file_sink import _dumps
from audit_logging.document import build_document
# body = b'{"n":"' + b"x"*(CAP-9) + b'"}'   (exactly max_body_bytes)
line = _dumps(build_document(ctx, cfg))
print(len(line))
```

**Observed** (`message_max_bytes` = 2,097,152):

| 1 MiB body of… | JSONL line | × body | over the limit? |
|---|---:|---:|---|
| plain ASCII | **2,097,957 B** | 2.00× | **yes, by 805 B** |
| `"` characters | **3,146,521 B** | 3.00× | **yes** |
| newlines / control chars | **2,622,238 B** | 2.50× | **yes** |
| CJK text | **2,097,955 B** | 2.00× | **yes** |
| `text/plain`, 1 MiB of `"` | **2,097,909 B** | 2.00× | **yes** |

**Expected** a line Filebeat can carry.

**What happens.** filestream truncates the over-long message; the `ndjson` parser then fails to decode it (`ignore_decoding_error: false`); the document never gets a `data_stream.dataset`; and the `drop_event` processor — which exists precisely to catch undecodable lines — **silently discards it**. The package has already counted it in `audit_documents_submitted_total` and written it to disk successfully. **There is no counter, on either side, that records this loss.** `AC-04`'s own scenario (a 2 MB body truncated to 1 MiB) produces exactly this line.

Two fixes, both needed: raise `message_max_bytes` to at least `4 * max_body_bytes` (and confirm the interaction with `queue.disk.segment_size`), and stop storing the body twice — `body_raw` and the `flattened` `body` are redundant for parseable JSON, and dropping one halves both the line size and the ES storage the plan §5 estimate is built on.

### M-5 · must-fix · `user.*` is written unvalidated into `keyword` fields; a mistyped resolver return makes Elasticsearch reject the whole document

**Violates** `FR-25` ("the document is still emitted"), `FR-01`, and `docs/schema.md` §2.5.

`_user_block` (`document.py:260-267`) copies `id`, `name` and `roles` straight through with no type check. The template maps all three as `keyword`. `index.mapping.ignore_malformed: true` **does not apply to `keyword` or `text`** — Elasticsearch supports `ignore_malformed` only on numeric, boolean, date, `ip` and geo types.

**Repro**

```python
cfg = AuditConfig(service_name="t", log_dir="/tmp/x",
                  user_resolver=lambda s: {"id": "u1", "roles": {"nested": "obj"}})
# ... drive the middleware ...
```

**Observed**

```
documents=1  audit_middleware_errors_total=0
doc["user"] = {"id": "u1", "roles": {"nested": "obj"}}
```

The package considers this a success. Elasticsearch will answer the bulk item with a `mapper_parsing_exception` and reject the **entire audit document** — not just the offending field. Filebeat's `max_retries: -1` then retries the same rejected document indefinitely.

The blast radius is that a *supported application extension point* can silently delete audit records. `FR-25` already anticipates a hostile resolver ("if it raises or returns a non-dict…"); it just does not check the values inside a dict that *is* returned. Coerce to `str` (and to `list[str]` for `roles`), dropping anything that will not coerce, exactly as `_path_params` already does for path params.

I confirmed the rest of the document is safe: **every** top-level key it emits is declared in the mapping, and `client.ip` — the one place a non-conforming string can reach a typed field — is an `ip` field, which *is* covered by `ignore_malformed`:

```
client=('/run/uvicorn.sock', 0)  -> client.ip='/run/uvicorn.sock'   (field ignored by ES, document survives)
client=('not-an-ip', 1)          -> client.ip='not-an-ip'           (same)
```

And a missing `http.response.status_code` when the client vanished pre-response (A2's question) is **fine** — Elasticsearch has no required fields, and the mapping declares no `null_value`. No action needed there.

### S-12 · should-fix · a 200-document bulk can reach ~397 MiB against Elasticsearch's 100 MB default

`bulk_max_size: 200`, `worker: 2`, sized by a comment reading *"~200 × 2 KB ≈ 400 KB per bulk"*. With `D-4`-legal 1 MiB bodies the same 200 documents are **~397 MiB**. `http.max_content_length` defaults to 100 MB, so the bulk is refused with a 413; `max_retries: -1` then retries it forever, wedging the shipper for every service on the node. The Filebeat container's `memory: 500Mi` limit will not hold two workers' buffers at that size either — it OOM-kills first.

Bulk sizing must be by *bytes*, not document count, or `bulk_max_size` must be derived from `max_body_bytes` (e.g. 20 for a 1 MiB cap).

### S-13 · should-fix · a rotation that happens while Filebeat is down loses the rotated file's unshipped tail

The input globs `/var/log/audit/*/*.jsonl` and `prospector.scanner.exclude_files` explicitly excludes `\.jsonl\.\d+$`. The comment justifies this: filestream follows an open file across the rename, so a line written just before rotation is still shipped. That reasoning is correct **while Filebeat is running**.

It fails when Filebeat is not: if the DaemonSet pod is down (node drain, rolling update with `maxUnavailable: 1`, OOM-kill, config reload) when `_rotate()` runs, the unshipped tail of the old file is now at `.1`, which matches neither the glob nor the scanner. On restart Filebeat has registry state for an inode whose path no longer matches an input, and **those lines are never shipped**. `clean_removed: true` then reaps the state.

This is rare at the 256 MiB default and constant at `AC-12`'s 64 KiB. It contradicts `D-2` and `AC-12` ("**every** line reaches Elasticsearch"). Globbing `.1` with `file_identity` set so re-ingest is deduplicated, or simply accepting duplicates (the manifest already says they are "dedupable after the fact on `trace.id`" — though see N-11), is safer than silent loss.

### S-14 · should-fix · a non-root application container cannot write into the `subPathExpr` hostPath directory

`infra/filebeat/daemonset.yaml`, "THE OTHER HALF OF THE CONTRACT" section, instructs every audited app pod to mount the `/var/log/audit` hostPath with `subPathExpr: $(POD_NAME)`, and reassures: *"the app container writes as its own UID; Filebeat reads as root, so it can read anything."*

That addresses the read side and misses the write side. **kubelet creates a `subPath`/`subPathExpr` directory as `root:root` mode 0755, and `fsGroup` is not applied to `hostPath` volumes.** An application container running as a non-root UID — which is what any sane PodSecurity profile requires of an *application* pod, and what the sidecar variant in the same file explicitly assumes (`runAsUser: 1000`) — gets `EACCES` from `FileSink._ensure_open`'s `os.makedirs`/`os.open`.

The failure is quiet by design: `start()` catches `OSError`, calls `_log_once`, and the sink runs happily forever writing to a file it cannot open. Combined with S-7, if anything else raised an `OSError` first, there is not even a log line. The observable result is **an audit deployment that reports healthy and produces zero documents**, which is the worst possible failure for this system.

The manifest needs either an `initContainer` that `chown`s the subdirectory to the app's UID, or a documented requirement that audited app pods run as a UID with write access, stated as loudly as the `runAsUser: 0` decision for Filebeat is.

### N-9 · note · a flattened leaf **key** over 32,766 bytes should be rejected outright by Lucene · *unverified*

`ignore_above: 1024` on the `flattened` fields caps leaf **values**. A `flattened` field indexes `key\0value` as a single term, and the key is not capped anywhere — not by `redact`, not by `document.py`.

**Constructed**

```
body = json.dumps({"k"*40000: "v"}).encode()      # 40,009 B, well under max_body_bytes
-> audit.request.body has one key of 40,000 characters
-> term ≈ 40,002 B > 32,766 (Lucene MAX_TERM_LENGTH)
```

Expected outcome on a live cluster: `IllegalArgumentException: Document contains at least one immense term`, rejecting the **whole document** — so the audit record for a hostile request is the one that disappears. Verify with a single `POST /logs-apiaudit.test-dev/_doc` carrying that body before pilot. If confirmed, cap key length in `redact` (keys over N characters truncated with a marker).

### N-10 · note · empty-string and leading/dot flattened keys · *unverified*

The builder passes JSON keys through untouched:

```
b'{"":"x","a":{"":1}}'      -> audit.request.body = {"": "x", "a": {"": 1}}
b'{".a":1,"b.":2,"c..d":3}' -> audit.request.body = {".a": 1, "b.": 2, "c..d": 3}
```

Elasticsearch's object and flattened parsers reject empty field names and (for objects) fields starting or ending with `.`. Whether the `flattened` parser rejects these in 8.13 needs a cluster to settle. Same test as N-9; same fix (sanitise keys in `redact`).

### N-11 · note · `message` may survive the ndjson parser, doubling every document · *unverified*

`drop_fields` removes `agent`, `ecs`, `input`, `log`, `@metadata.raw_index` — a careful enumeration of what Filebeat adds. It does not remove `message`. With `target: ""`, filestream's ndjson parser may retain the raw line in `message` alongside the decoded fields. If it does, every document carries **a complete second copy of itself** in `_source`: unindexed (the mapping is `dynamic:false` and declares no `message`), but stored, shipped, and counted against both `bulk_max_size` and plan §5's ~0.6 KB/doc storage estimate. Combined with M-3 this would put the line over `message_max_bytes` at half the body size. One `filebeat -e` run against a file settles it; adding `message` to `drop_fields` is free insurance either way.

### N-12 · note · client-pinned `trace.id` defeats the documented deduplication story

`FR-23` reuses a client-supplied `X-Request-ID` when it is ≤ 200 printable-ASCII characters, and `FR-24` echoes it. Header injection is correctly prevented (the `0x21–0x7E` check in `_is_well_formed_trace_id` excludes CR, LF and space — I could not break it). But the value is entirely client-chosen:

```
3 requests, all sending X-Request-ID: aaaaaaaa...
trace.ids: ['aaaa…', 'aaaa…', 'aaaa…']
```

`infra/filebeat/daemonset.yaml` twice relies on duplicates being "dedupable after the fact on `trace.id`" (R-11 registry loss, and the sidecar variant). A client that pins one `X-Request-ID` makes every request it ever sends look like the same event. Deduplication needs `trace.id` **plus** `@timestamp` and `process.pid` at minimum, and the runbook should say so.

### N-13 · note · `FR-02` exclude prefixes are unanchored

```
/health-secret/transfer   excluded by '/health'
/metrics-internal/users   excluded by '/metrics'
/docs-private/keys        excluded by '/docs'
/ready-to-pay             excluded by '/ready'
```

`FR-02` mandates prefix matching, so this is per spec — but the shipped `DEFAULT_EXCLUDE_PATHS` are bare words, and a route added later that happens to share a prefix loses its audit trail **silently, with no log line and no metric**. Matching on a path-segment boundary (`p == prefix or p.startswith(prefix + "/")`) preserves `FR-02`'s intent and removes the trap.

### N-14 · note · the kill switch also removes `FR-24`

With `enabled=false` the middleware is a pure pass-through, so the `X-Request-ID` response header disappears too. That is exactly what `FR-15` asks for ("no measurable overhead"), but it means flipping the kill switch changes *API behaviour*, not just logging — anything downstream correlating on the echoed header breaks. Worth one line in the runbook.

### N-15 · note · field-budget arithmetic disagrees between three places

`docs/schema.md` §3 says 44 fields; the template's `_meta.field_budget` says 45; counting the way `total_fields.limit` counts (leaves **and** object containers, which is what `GET _mapping` reports for `AC-10`) gives **62**. All three are comfortably under 200 and `AC-10` will pass. Cosmetic, but `AC-10` asserts against the number Elasticsearch reports, so the doc should quote that one.

---

## 8. Attacks that failed — where the code is genuinely solid

Listed so the orchestrator knows where **not** to spend fix budget.

**Body replay (`FR-04`) is correct, structurally.** `receive_w` returns the identical message object, so byte-fidelity is not something that can drift. All seven brief cases behave:

| case | result |
|---|---|
| 3-chunk body, `max_body_bytes` exceeded | app received all three chunks with identical bodies and `more_body` flags; only the audit copy was capped |
| zero-length body, `Content-Length: 0` | `body_skipped="empty"`, no `body`/`body_raw` keys, no parse attempted |
| app never reads the body | `body_skipped="unread"`, document emitted, **no hang** |
| app reads the body twice | second read returns exactly what unwrapped ASGI returns; no message is resurrected |
| app reads *past* the end (4 reads) | `['http.request', 'http.disconnect', 'http.disconnect', 'http.disconnect']` — pure passthrough |
| `Expect: 100-continue` | passed through untouched, body captured normally, `expect` header allowlisted |
| `http.disconnect` interleaved | document still emitted; `FR-01` holds |

**`redact()` is pure and the depth cap works as specified.** Input unchanged, no sub-object shared with the output, and — the specific thing the brief asked about — the deep **value** is destroyed, not exposed:

```
25-deep nesting with {"ssn": "111-22-3333", "plain": "DEEPVALUE"} at the bottom
-> "DEEPVALUE" in document: False        "111-22" in document: False
-> {"n":{"n":…{"n":"[TRUNCATED]"}…}}
```

A denylisted key holding a huge subtree is replaced without descending. Cyclic input terminates on the cap with no `id()` bookkeeping. **No action.**

**Sink write ordering and overlap — A4's open question — is correct.** `_lock` genuinely serialises `_flush_once` across the `asyncio.to_thread` boundary. Instrumented with a 2 ms sleep inside `_write_batch` and 400 interleaved submits:

```
400 lines on disk, max concurrent _write_batch = 1, submission order preserved = True
```

**No package exception reached the application in any path I could construct.** Ten injected failures, all swallowed and counted, response always delivered intact, `http.response.start` never sent twice, `send` never left uncalled:

- `build_document` raising mid-stream and after the response completed
- `sink.submit` raising
- the `Metrics` implementation *itself* raising on every `inc`/`set`
- `user_resolver` raising, returning a non-dict, returning a raising `__str__`, returning nested objects
- malformed `scope["client"]` in four shapes
- the log directory unwritable at `start()` and at every `write`

Application exceptions propagate unchanged, including `CancelledError`, and each still produces exactly one document (`AC-08`).

**`body_raw` will not hit the Lucene 32,766-byte term limit.** I expected this to be the highest-risk item, since `docs/schema.md` deliberately leaves `ignore_above` unset. It is fine: with `index: false` **and** `doc_values: false` the field produces no term at all, so the limit never applies. A programmatic sweep of every `keyword` in the template found **no** indexed keyword without an `ignore_above` below the limit. A5's reading is right and `bootstrap.check_body_raw` guards it. **No action.**

**The index template's `dynamic:false` bound holds completely.** Programmatic walk of the mapping:

```
containers WITHOUT dynamic:false: none  — every object container, 'labels' included
composed_of: []
62 declared fields / total_fields.limit 200
top-level keys the builder emits that the mapping lacks: none
```

`composed_of: []` is the right call for ES 8.x: the built-in `logs@settings`/`logs@mappings` component templates are applied only when named in `composed_of`, and the built-in `logs-*-*` index template sits at priority 100 against this one's 500, so nothing can merge `dynamic: true` back in. Filebeat cannot create fields — top-level `dynamic: false` means anything it adds stays out of the mapping entirely. `bootstrap.py`'s guard is a genuinely hard one, not a warning, and it re-runs against `_simulate_index` **after** the PUT to catch anything else in the cluster that composes into the pattern. This is the best artefact in the repo.

**Header redaction is airtight.** `filter_headers` is allowlist-only with no placeholder; `authorization`, `cookie`, `set-cookie` and `proxy-authorization` never appear under any input I tried, including mixed-case, whitespace-padded and `bytes`-typed names. `FR-12`/`AC-06` hold.

**Multipart part *values* are never stored.** `FR-07`/`D-5` hold — only `name`, `filename`, `content_type` and `size`. (The names/filenames being unredacted is N-7; the bytes are genuinely absent.)

**The kill switch is real.** `enabled=false`: sink never constructed, no file created, no queue allocated, pure pass-through with no wrapping. `FR-15`/`AC-11` hold.

**`normalize_key`'s process-global memo cannot be exhausted or poisoned into a leak.** One request with 5,000 distinct keys fills the cache to its 4,096 cap and stops; no growth, no cross-request value leakage (the memo maps key → normalised key, a pure function), and the measured cost to the application's own keys afterwards was *unchanged* (1.84 µs → 1.55 µs per `redact()`, within noise). The `_Decisions` per-call dict is bounded the same way. The design is sound as documented.

**`http.response.status_code` being absent when the client vanished is not an Elasticsearch problem.** A missing field is always legal; no `null_value` is declared. A2's question is answered: no change needed.

**The reported intermittent test did not reproduce.** `test_app_reading_the_body_twice_behaves_like_unwrapped_asgi` passed 8/8 in isolation and the full 313-test suite passed **13 consecutive times** with no failure. Reading the test and `httpx 0.28.1`'s `ASGITransport.receive`, I see no non-determinism: the second `receive()` deterministically returns `{"type": "http.request", "body": b"", "more_body": False}` via `StopAsyncIteration`, never the `response_complete.wait()` branch. If the flake is real it is environmental (event-loop policy, `pytest-randomly` ordering, or a shared `NullSink` across fixtures) rather than in the code under test. **Unverified — recommend running it under `-p randomly` with a fixed failing seed if it recurs, rather than treating it as a code defect on this evidence.**

**`mypy --strict` is clean** (`Success: no issues found in 10 source files`) and **313/313 unit tests pass**, re-verified.

---

## Appendix — recommended pilot gate

| # | Finding | Severity | Blocks pilot? |
|---|---|---|---|
| M-1 | `body_raw` unredacted for `text/*` and no content type | must-fix | **yes** — unconditional |
| M-3 | 1 MiB body → 2.0–3.0 MiB line > `message_max_bytes`, silently dropped | must-fix | **yes** — unconditional |
| M-2 | 56–141 ms event-loop stall per 1 MiB body | must-fix | yes, unless every client is trusted |
| M-4 | 28× memory amplification on chunked bodies | must-fix | yes, unless every client is trusted |
| M-5 | unvalidated `user.*` → Elasticsearch rejects the document | must-fix | yes, if a `user_resolver` is configured |
| S-1…S-14 | see §1–§7 | should-fix | no, but S-14 will make the pilot produce zero documents if the app pod is non-root |
| N-9, N-10, N-11 | unverified ES/Filebeat behaviours | note | run the three verification steps against the pilot cluster before traffic |

A review that finds nothing is a failed review; this one found five things that would have surfaced in production as either a privacy incident or a silent hole in the audit trail. The parts that held — replay fidelity, redaction purity, exception safety, the template's field bound — held convincingly, and they are the parts that were hardest to get right.

---

## Addendum — A6's Phase 2 harness landed mid-review, and it will not catch M-2, M-5 or N-9

`tests/integration/` and `tests/load/` appeared while this review was in progress; they are outside the Phase 1 scope I was given and I have **not** reviewed them. I did check one thing only: whether they already cover the findings above, so the orchestrator does not close any of these on a green integration run. Three of them would pass while the defect stands.

**S-15 · should-fix · `tests/integration/_es_double.py` models `ignore_malformed` as covering `keyword`, which Elasticsearch does not.** `InProcessElasticsearch.index` (`_es_double.py:224-239`) raises only on `unmapped` fields. A value that fails `_accepts` — including a `dict` in a `keyword`-typed field — is appended to `result.malformed` and **the document is indexed anyway** (`_es_double.py:315-317`). Real Elasticsearch answers that bulk item with a `mapper_parsing_exception` and rejects the whole document, because `index.mapping.ignore_malformed` applies to numeric, boolean, date, `ip` and geo types only. So **M-5 reproduces as a passing test**: the double keeps the document, the AC goes green, and production silently loses the audit record. The double should raise for a type mismatch on `keyword`/`text` and record `malformed` only for the types `ignore_malformed` actually covers.

**S-16 · should-fix · the double models no Lucene term-length limit.** There is no `32766` / `MAX_TERM_LENGTH` check anywhere in `_es_double.py`, so **N-9** (a 40 KB `flattened` key) indexes cleanly against the double and is rejected by a real cluster. Since `tests/integration/test_acceptance_es.py` is the artefact that would otherwise settle N-9 and N-10, those two stay `unverified` and still need one `POST` against the pilot cluster.

**M-2 is not covered by `tests/load/test_nfr1_latency.py`.** The load test asserts the `NFR-1` 5 ms added-p99 budget at 100 rps with **8 KB bodies** — and `test_body_is_really_eight_kilobytes` pins that size deliberately. 8 KB is the size at which I measured the middleware at 0.2–0.7 ms, comfortably inside budget. The 56–141 ms stall in M-2 needs a body two orders of magnitude larger, which no load arm exercises. The suite will report `NFR-1: PASS` for a middleware that a 1 MiB body takes to 28× the budget. A second arm at `max_body_bytes` with an adversarial payload shape (`[{"a":1},…]`) belongs in `tests/load/driver.py` before pilot — it is the single cheapest thing that would have caught this.
