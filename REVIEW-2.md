# REVIEW-2.md — verification pass over the five fix passes

| | |
|---|---|
| Reviewer | **A8 — adversarial reviewer**, second pass |
| Scope | Every finding in `REVIEW.md` re-run against the current tree; then the *fixes themselves* attacked; then the new requirements and the new docs judged |
| Method | Every claim in the fix reports was treated as a claim. Nothing below is reported unless I ran it. Findings I could not execute are labelled **unverified** and say what would settle them. |
| State | 511 unit/local tests pass, `mypy --strict` clean on 11 source files (both re-verified here). `orjson 3.12.0` present, so the orjson paths are the ones that run. |
| Not available | Docker. **Tier 1 (Elasticsearch + Filebeat) has still never been executed.** Everything past the JSONL line remains modelled, not measured. |
| Scratch | `/tmp/claude-1000/.../scratchpad/` — nothing was written into the project tree except this file. |

---

## Verdict

**The five fix passes did the work.** All five must-fixes and all sixteen should-fixes from `REVIEW.md` are genuinely closed or genuinely reduced, and I could not talk myself out of a single one of them by re-running the repro. M-1 is gone at the root rather than patched at the edge; M-3's 2.0–3.0× line inflation is now 1.00×; M-4's 28.1× memory amplification is 1.10×; the 110 ms event-loop stall on the payload I named is 1.05 ms. The sink work (S-7…S-11) is the strongest of it: `file_max_bytes` is a real bound now, two sinks on one path lose nothing, and the counters mean what they say.

**But the fixes brought three new defects of the same severity as the ones they closed, and one of them is worse than anything in the first review.** New code written under time pressure to close a security finding is where the next defect lives, and that is exactly what happened:

1. **A 14-byte request body deletes its own audit record, silently, and the loss is filed under the wrong counter.** `{"a":"\ud800"}` on any JSON endpoint. This is FR-01 defeated by a client at will — the single failure mode an audit log exists to prevent. *(I missed this in the first review; it pre-existed. It is here now because I went looking for what the surrogate-aware key sanitiser did **not** cover.)*
2. **The key-sanitisation memo retains attacker-supplied strings across requests, capped in entries and not in bytes.** ~4 GiB of retained RSS before it clears. My first attempt to measure it at `max_body_bytes` was OOM-killed by the kernel. This is M-4 reintroduced one module over, and worse, because the memory is *persistent* rather than in-flight.
3. **M-2 is mitigated, not closed.** The node cap bounds the *body*, and bounds node *count* rather than per-node *cost*. Neither the query string nor per-key sanitisation cost is bounded at all: I measured **24 ms** of event-loop stall from a 64 KB query string on a `GET` with no body, **8.3 ms** from 8 KB (which is what a default nginx lets through), and **20 ms** from a 73 KB JSON body that passes the node cap comfortably. The 5 ms NFR-1 budget is still exceeded 4–7×; the attack is ~5–10× more expensive than before, not impossible.

Plus one narrow-trigger, high-blast-radius defect in the new `FileSink` locking: **during shutdown, audit lines can be written into an unrelated file descriptor**, demonstrated below with the audit records landing in a plain text file the application had opened.

### Where this stands for a pilot

**Not yet safe for an internal pilot** — but it is close, and unlike last time the remaining list is short, specific, and none of it is architectural.

| | Last review | Now |
|---|---|---|
| Untrusted clients | No — unconditional | **No** — N2-1 (audit-record deletion) and N2-2 (OOM) are both remotely triggerable by an unauthenticated client with a tiny request |
| Internal pilot behind a trusted ingress | Manageable after M-1 and M-3 | **After N2-1 and N2-2.** Both are small, contained fixes |

**Gate the pilot on N2-1 and N2-2.** They are each a few lines and they are the two that a client can fire deliberately. N2-3/N2-4 (latency) and N2-5 (fd recycling) are the next tier and should land before the pilot carries production traffic, but they will not by themselves ruin a pilot behind a trusted ingress. Everything else on the list is a should-fix or a documentation correction.

**And gate it separately on Tier 1 having run once.** `tests/AC-matrix.md` §5 is honest that it never has. Three of my original notes (N-9, N-10, N-11) are still settled only by reasoning and by a hand-written double, and the double is now good enough that a green run against it is easy to mistake for a green run against Elasticsearch.

### Findings by severity

| Severity | Count |
|---|---|
| **must-fix** | 3 (+1 must-fix with a narrow, non-remote trigger) |
| **should-fix** | 4 |
| **note** | 9 |

---

## 1. Verification table — every prior finding

Re-run means: the repro from `REVIEW.md` was executed against the current tree and the number below is what it printed.

### 1.1 Must-fixes

| # | Claim after fix | Verdict | Measured now |
|---|---|---|---|
| **M-1** | all six content types store nothing; `body_skipped="content_type"` | ✅ **fixed as claimed** | `text/plain`, `text/xml`, `application/xml`, `application/graphql`, `text/csv` and **no content type** all give `body_skipped='content_type'`, `body=None`, `body_raw=None`. With `capture_text_bodies=True` all six give `{"password":"[REDACTED]","api_key":"[REDACTED]"}`. Fixed at the root (FR-28), not at the edge |
| **M-2** | 140.6 ms → 0.1 ms; end-to-end 110.4 ms → 0.19 ms | ⚠️ **fixed for the payload it named; the class is open** | The four named 1 MiB shapes are all `too_complex` in **0.06–0.07 ms**; end-to-end **1.05 ms** (was 110.4). But see **N2-3** (query string, 24 ms) and **N2-4** (per-key cost, 20 ms) — both inside the node cap, both on the event loop |
| **M-3** | body stored once (schema §2.9); worst line recomputed | ✅ **fixed** | 1 MiB body → **1,049,367 B** line, ×1.00, for ASCII / quote-heavy / newline-heavy / CJK alike (was 2,097,957–3,146,521). `message_max_bytes` 2 MiB → 8 MiB, and an undecodable line is now quarantined to a dead-letter route instead of `drop_event`-ed. See **N2-10** for what §2.9 costs, and note the 6× sizing derivation is unreachable at defaults (safe direction) |
| **M-4** | 28.1× → 1.0× across chunk sizes | ✅ **fixed** | 50 concurrent 1 MiB bodies: **1.08×** at 64 KiB chunks, **1.10×** at 64 B, 8 B, 2 B and 1 B. Flat across a 65,536× change in chunk size |
| **M-5** | coerced to `str` / `list[str]` | ✅ **fixed** | `{"id":"u1","roles":{"nested":"obj"}}` → `{'id': 'u1'}`; `{"id":{"a":1}}` → `None`; `{"id":"u","name":123,"roles":["a",{"b":1},"c"]}` → `{'id':'u','name':'123','roles':['a','c']}`; `{"roles":"admin"}` → `{'roles':['admin']}`; 5000-char id clipped to 1024 |

### 1.2 Should-fixes

| # | Verdict | Measured now |
|---|---|---|
| **S-1** `http.request.bytes` under-reports | ✅ fixed | 60 bytes in 3 chunks at `max_body_bytes=32` → `http.request.bytes=60`, `body_bytes=32`, `truncated=True`. Replay still byte-identical. App-never-reads case falls back to `Content-Length` (12345) with `body_skipped='unread'`. Delivered via **DEV-1** — judged in §4 |
| **S-2** broken JSON forces the unredacted path | ⚠️ **partially fixed — still a live leak** | `{"password":"hunter2", oops}` still stores `body_raw='{"password":"hunter2", oops}'` verbatim. The clip caps the *volume* at 4096 chars, not the *leak*. See **N2-8** |
| **S-3** `;` and `%20` query bypass | ✅ fixed | `a=1;token=SECRET` → `url.query='a=1&token=%5BREDACTED%5D'`; `%20token=`, `+token+=` and mixed `&`/`;` all redact. Form bodies too |
| **S-4** 104,857 multipart parts | ✅ fixed | 1 MiB of `--B\r\nz\r\n\r\n` → `part_count=256`, `complete=False`, **0.8 ms** (was 104,857 in 68.8 ms) |
| **S-5** lost document after response start | ✅ fixed | `build_document` raising mid-stream → **1 document** (`build_minimal_document`), response delivered intact (5 body chunks, one `response.start`), `error.message` prefixed `audit_logging:`. Hostile client port → document survives, `client.port=0` |
| **S-6** `_WARNED` module-global latch | ✅ fixed | A benign `user_resolver` error no longer silences a later, different error: 1 WARN then 2, keys `['could not build the audit document', 'user_resolver raised']` |
| **S-7** `_log_once` collapses errno/phase | ✅ fixed | 5 distinct failures (`ENOSPC`/`EDQUOT`/`EIO` at write, `EACCES`/`ENOSPC` at open) → **5 ERROR lines** (was 2). Key is `phase:type:errno`, bounded at 64 |
| **S-8** 3× memory ceiling, blind gauge | ✅ fixed | 16 MiB `queue_max_bytes` → **1.91×** RSS (was 3.0×). Gauge reads 16.00 MiB with the batch parked in `_retry` and the deque empty — `held_bytes == queued_bytes + inflight_bytes` holds |
| **S-9** `failed_total` double-counts | ✅ fixed | 10 documents, write always fails → `failed_total=10.0` (was 20.0), `dropped_total=0`. The `CancelledError`-during-retry path is counted now too |
| **S-10** `file_max_bytes` not a bound | ✅ fixed | AC-12's own config (64 KiB file / 4 MiB flush): largest file **64,653 B** against a 65,536 limit, **28 rotations** (was 1,872,890 B and 0). At 1 KiB/256 B: largest 937 B |
| **S-11** two sinks, one path | ✅ fixed | 120 submitted, **120 lines on disk** (was 78). Second sink takes `s-<pid>-f1a2cd.jsonl` and logs a WARNING; `flock` backs up the in-process registry |
| **S-12** 200-doc bulk ≈ 397 MiB | ✅ fixed | `bulk_max_size: 12` derived from the line ceiling; Filebeat memory 500Mi → 1Gi; `non_indexable_policy` dead-letters instead of retrying forever |
| **S-13** rotation while Filebeat is down | ✅ fixed | The input now globs rotated files; `exclude_files` is down to `\.gz$`/`\.tmp$` |
| **S-14** non-root app cannot write the `subPathExpr` dir | ✅ fixed | `daemonset.yaml` now carries the `chown` initContainer, names the exact failure (`kubelet creates it root:root 0755, fsGroup does not apply to hostPath`), and lists what does *not* work |
| **S-15** ES double models `ignore_malformed` over `keyword` | ✅ fixed | The double raises `mapper_parsing_exception` for a structural mismatch and confines `malformed` to the types ES actually covers |
| **S-16** ES double models no term-length limit | ✅ fixed | `LUCENE_MAX_TERM_BYTES = 32766` modelled, including the flattened `key\0value` assembly |

### 1.3 Notes

| # | Verdict | Now |
|---|---|---|
| **N-1** partial body from a disconnect stored raw | still present, clipped | `{"password":"hunt` → `body_parse_failed=True, body_raw='{"password":"hunt'`. Same root cause as S-2/N2-8 |
| **N-2** transport reset is `failure`, not `disconnected` | still present — *by inspection, not re-run* | `_outcome` is unchanged. Marked **unverified** this pass |
| **N-3** secrets in `url.path` never redacted | still present, now documented | `/reset/token/abc123SECRET` stored verbatim in an indexed `keyword`. `docs/redaction.md` §4.5 states it — but the two tests it cites do not pin it (§5) |
| **N-4** homoglyph / whitespace / substring gaps | still present, well documented | All still leak, each with a `test_LIMITATION_*`. `normalize_key` still does not `.strip()`; the query/form path *does* strip now, and the asymmetry is documented. Deliberate, and correctly so |
| **N-5** `passwords` / trailing punctuation | still present | `passwords`, `password!` still leak while `tokens`/`secrets`/`apikeys`/`cookies`/`credentials` are covered. One-line additions, still not taken |
| **N-6** `body_raw` vs `body` divergence | superseded by §2.9 | `body_raw` is no longer emitted for parseable JSON at all. But `docs/REQUIREMENTS.md` §3 still describes the old behaviour — see **N2-12** |
| **N-7** multipart names/filenames unredacted | ✅ fixed | `name="password"` → `filename` becomes `[REDACTED]`; part bytes still never stored. A PII filename under a benign name is still a limitation, documented — but with no test (§5) |
| **N-8** `submit()` after `close()` counted as a drop | ✅ fixed | `dropped_after_close_total=1`, `dropped_total=0` — disjoint, with a one-shot WARNING |
| **N-9** immense flattened key | ✅ fixed at capture, still unverified against a cluster | `sanitize_key` bounds every emitted key at exactly 1024 UTF-8 bytes. Attacked hard in §3.1 and it held |
| **N-10** empty / dotted flattened keys | **still unverified**, honestly carried | `{"":"x"}` and `{".a":1}` still emit `''` and `'.a'`. `tests/AC-matrix.md` §4.2/§8 says so plainly and explains why no test was written. Correct handling |
| **N-11** `message` doubling every document | ✅ addressed with reasoning | `filebeat.yml` explains from Filebeat's source why `message` is absent on a clean decode, and preserves it deliberately on the quarantine branch |
| **N-12** client-pinned `trace.id` defeats dedup | ✅ addressed | `docs/runbook.md:423` — "do not deduplicate on `trace.id` alone", with the collapse key |
| **N-13** unanchored exclude prefixes | ✅ fixed | `/health-secret/transfer`, `/metrics-internal/users`, `/docs-private/keys`, `/ready-to-pay` all now audited; `/health`, `/health/`, `/health/x` still excluded |
| **N-14** kill switch removes `X-Request-ID` | ✅ documented | Module docstring, README call-out box, and a named test |
| **N-15** field-budget arithmetic | ✅ resolved | README now quotes the number Elasticsearch reports (51) |

**One prior finding I now believe I got partly wrong:** S-2's fix recommendation. I proposed "run a regex scrub over the raw text on parse failure". The fix pass built exactly that regex machinery for `capture_text_bodies` — and §3.3 below shows it misses namespaced XML, nested elements, YAML block scalars and prose. Applying it to the parse-failure path would have produced a *stronger-looking* leak rather than a smaller one. Clipping was the better call than the one I suggested; the residual leak (N2-8) needs a different answer, and I now think that answer is a hash or a byte-count, not a scrub.

---

## 2. New findings — must-fix

### N2-1 · must-fix · a 14-byte body deletes its own audit record, and the loss is filed under the wrong counter

**Violates** `FR-01` ("exactly one audit document, whatever the outcome") and `FR-19`'s meaning of `audit_documents_dropped_total`.

A lone UTF-16 surrogate in a JSON **value** takes the whole document out. The chain is four modules long and each link is individually reasonable:

1. `document._loads` tries `orjson.loads` → `JSONDecodeError: no low surrogate in string`;
2. the fallback `json.loads(raw.decode("utf-8", "replace"))` — stdlib **accepts** `\ud800` and returns a `str` holding a lone surrogate;
3. `redact()` sanitises **keys** but never touches **values**, so the surrogate rides into the document;
4. `file_sink._dumps` calls `orjson.dumps` with **no stdlib fallback when orjson is present** → `TypeError: str is not valid UTF-8: surrogates not allowed`;
5. `submit()` catches it, increments **`audit_documents_dropped_total`**, and returns `False`.

**Repro**

```python
from audit_logging.document import build_document
from audit_logging.sinks.file_sink import FileSink, _dumps
# ctx: Content-Type: application/json, body = b'{"a":"\\ud800"}'   (14 bytes)
doc = build_document(ctx, cfg)
sink.submit(doc)
```

**Observed**

```
orjson.loads : JSONDecodeError
document body: {'a': '\ud800'}   parse_failed=False     <- looks completely healthy
_dumps(doc)  : RAISES TypeError (surrogates not allowed)
submit()     -> False
2 documents submitted, 1 line on disk
  submitted_total=1.0  dropped_total=1.0  failed_total=0.0  middleware_errors=0.0
```

**Expected** one line on disk per request.

Placement sweep — the value paths all die, the key path survives (because `sanitize_key` handles it):

| where the surrogate is | result |
|---|---|
| `{"a":"\ud800"}` | **document dropped** |
| `{"a":{"b":["\udfff"]}}` | **document dropped** |
| `{"password":"\ud800"}` | stored (value replaced by `[REDACTED]` first) |
| `{"\ud800":1}` | stored (key sanitised) |

**Why this is the worst thing in this review.** It is *client-selected suppression of the audit trail*. Any attacker who wants no record of a request appends one field to it. It costs nothing, needs no authentication, works on every JSON endpoint, and produces a completely healthy-looking `build_document` result — `body_parse_failed` is `False`, `audit_middleware_errors_total` is `0`. The only trace is a tick on `audit_documents_dropped_total`, whose documented meaning is *"disk is not keeping up — a paging event"* (`FR-19`). So the one signal you get points an operator at the disk. An attacker can also use it to *mask* a genuine disk-pressure alert, or to fire one at will.

The near-miss is instructive: `redact.py`'s own docstring says lone surrogates "cannot be encoded as UTF-8 at all: they would break the **JSONL line itself**, not just the term". That reasoning is exactly right and was applied only to keys, because the motivation was Lucene term length. `tests/unit/test_redact.py:833` is `test_NUL_a_lone_surrogate_key_cannot_break_the_jsonl_line`; there is no `..._value_...` counterpart.

**Fix.** Two independent ones, and I would take both: (a) make `_dumps` fall back to the stdlib encoder — or to `orjson` after a `str.encode("utf-8","replace").decode()` pass — when orjson raises, so no document is ever lost to a serialisation refusal; and (b) route a serialisation failure to `audit_middleware_errors_total` plus a dedicated counter, never to `dropped_total`. A degraded document (the `build_minimal_document` shape S-5 introduced) beats no document.

---

### N2-2 · must-fix · the key-sanitisation memo retains attacker-supplied strings across requests — ~4 GiB before it clears

**Violates** `FR-08` / `NFR-2` ("no unbounded allocation" — *measured in RSS*, per the amended FR-08).

`redact._key_cache` is capped at **4096 entries**, not at bytes, and each entry's **dict key is the original, full-length, attacker-supplied string**:

```python
_KEY_CACHE_MAX = 4096
...
info = (_safe_str_key(key), normalize_key(key))
if len(_key_cache) >= _KEY_CACHE_MAX:
    _key_cache.clear()
_key_cache[key] = info          # `key` may be ~max_body_bytes long
```

`_safe_str_key` correctly returns a ≤1024-byte sanitised key — but the memo keeps the 1 MiB original alive as its lookup key, across requests, until 4096 entries have accumulated.

**Repro** — one JSON body per request, a single enormous key, node estimate `2` so the FR-29 cap never fires:

```python
for i in range(4096):
    key  = str(i).zfill(6) + "k" * (max_body_bytes - 20)
    body = ('{"' + key + '":1}').encode()
    build_document(ctx_for(body, "application/json"), cfg)
```

**Observed**

```
key  65,536 B x 4000 requests: _key_cache=4000 entries retaining   250.0 MiB of key strings; RSS +505 MB
key 262,144 B x 4000 requests: _key_cache=4000 entries retaining  1000.0 MiB of key strings; RSS +1501 MB
key 1 MiB    x 4096 requests: *** the process was OOM-killed by the kernel (exit 137) ***
```

Growth is monotonic and the clear only fires at the very end:

```
i=4094  entries=4095  retained=256.0 MiB
i=4095  entries=4096  retained=256.0 MiB
i=4096  entries=1     retained=0.1 MiB     <- clear
```

**Expected** memory attributable to key memoisation bounded by `4096 × MAX_KEY_BYTES` ≈ 4 MiB.

**Blast radius.** A pod with a 512 Mi limit dies after roughly 2000 requests carrying a 256 KB key — about 500 MB of upload, trivially cheap and slow enough to look like ordinary traffic. Crucially this is **not** in-flight memory: it survives the request, so it cannot be reclaimed by backpressure, connection limits, or a slower request rate. It is M-4's failure mode (OOM-kill of the *application*, by the logging component) moved from the capture buffer into a process-global cache.

The design note above the cache reasons carefully about the *count* bound and about why clearing beats freezing — and never asks how large one entry can be. The `_ALWAYS_SHORT_ENOUGH` fast path (≤256 chars) means every entry that reaches the memo's slow path is one that could be arbitrarily long.

**Fix.** Do not memoise a key longer than the fast-path threshold — it is a cache miss by construction and its result is a fixed-size string anyway. `if len(key) <= _ALWAYS_SHORT_ENOUGH: _key_cache[key] = info` is a one-line change that keeps every benefit the memo was built for (real payloads repeat *short* key names) and removes the class outright. A byte counter alongside the entry counter would also work.

---

### N2-3 · must-fix · the query string is not shape-bounded — 24 ms of event-loop stall on a `GET` with no body

**Violates** `NFR-1` (added p99 ≤ 5 ms) and `NFR-2`. `FR-29`'s node cap covers `audit.request.body` only.

`_query` → `_split_pairs` → group → `redact` → `urlencode` is fully linear in the query string, with a high constant, and **nothing caps it**. `max_body_bytes`, `max_body_nodes` and `max_scrub_bytes` all apply to the body.

**Repro** — real `AuditMiddleware`, `NullSink`, a 5 ms heartbeat coroutine measuring event-loop lag alongside:

```python
scope = {..., "query_string": b"a&" * 4096}   # no body at all
```

**Observed**

| query string | middleware | event-loop lag (idle base ≈ 0.3 ms) |
|---|---:|---:|
| baseline 8 KB JSON body | 1.58 ms | 4.55 ms |
| **8 KB** of `a&` | **8.26 ms** | 9.06 ms |
| **16 KB** of `a&` | **13.32 ms** | 15.77 ms |
| **64 KB** of `a&` | **24.25 ms** | 27.76 ms |
| **164 KB**, 20,000 distinct keys | **32.77 ms** | 40.64 ms |

Attribution (`_query` isolated, 3 reps): at 64 KB / 32,768 pairs — total 20.49 ms = `_split_pairs` 9.12 + grouping 1.21 + `redact` 3.71 + the rebuild/`urlencode` remainder. `unquote_plus` is called once per key and once per value.

**Expected** ≤ 5 ms.

**Blast radius.** 8 KB is what a default nginx passes (`large_client_header_buffers 4 8k`); uvicorn's h11 implementation defaults `max_incomplete_event_size` to 16 KiB; httptools imposes no URL length limit of its own. So **8.3–13 ms per request is reachable behind a default ingress, and 24 ms on an unfronted service** — 1.7–5× the entire NFR-1 budget, on the event loop, freezing every concurrent request in the worker. It needs no body, no authentication, and no `POST`: a `GET` to any audited path. Roughly 40–120 req/s saturates one worker. That is better than M-2's 9 req/s and it is not "closed".

**Fix.** Apply the same `_exceeds_node_cap` treatment to `ctx.query_string` — count `&`/`;`/`=` and refuse past `max_body_nodes`, recording it (`url.query` truncated with a marker, `audit.request.query` skipped). And cap the raw length: a query string longer than a few KB is not something an audit reader benefits from in full.

---

### N2-5 · must-fix (narrow, non-remote trigger) · audit lines are written into an unrelated file after `close()`

**Violates** `FR-27`'s intent and, potentially, confidentiality of the audit stream.

The `_open_lock` / `_terminated` work correctly covers the **rotation** that outlives `close()` — I attacked that specifically and could not break it (§6). It does not cover the **write**. `_write_segment` reads the descriptor into a local:

```python
def _write_segment(self, segment):
    fd = self._fd
    if fd is None: raise OSError(...)
    view = memoryview(b"".join(segment))
    while view:
        written = os.write(fd, view)      # <- fd is a local; close() can have closed it by now
```

`close()` runs `_close_fd()` on the event loop after its timeout, and the docstring already knows that "cancelling the task does not stop the thread it parked in `asyncio.to_thread`". The descriptor number is then free, and any subsequent `os.open` in the process gets it.

**Repro** — `shutdown_flush_timeout=0.2`, the worker held inside `_write_segment` by wrapping `os.write`, `close()` called, then the application opens an unrelated file:

**Observed**

```
worker is inside _write_segment with fd 6
close() returned? True   sink._fd = None   _terminated = True
unrelated file opened as fd 6   (same number as the audit fd? True)

--- VICTIM.txt ---
IMPORTANT APPLICATION DATA
{"i":0,"pad":"xxxx..."}
{"i":1,"pad":"xxxx..."}
{"i":2,"pad":"xxxx..."}
{"i":3,"pad":"xxxx..."}
{"i":4,"pad":"xxxx..."}

--- audit file ---
s-<pid>.jsonl   0 bytes
```

Five complete audit documents appended to a file that had nothing to do with the audit log, and zero of them in the audit log.

**Expected** the write fails with `EBADF`, or does not happen.

**Blast radius.** Audit documents carry redacted-but-still-sensitive material — full URL paths, path params, user ids, allowlisted headers, and the entire flattened JSON body. Descriptor numbers are shared between files and **sockets**, so the recipient of a recycled number during shutdown can be a client connection: the failure mode is not only "wrong file" but "audit records emitted to a network peer". The audit trail also loses the lines.

**Honest exploitability.** This is **not remotely triggerable**. It needs a single write to outlast `shutdown_flush_timeout` (default 10 s) — a stalled disk, an NFS hang, a node under IO pressure being drained — concurrent with a graceful shutdown that opens a file or accepts a connection. Rare. I am rating it must-fix on blast radius rather than on likelihood; if you disagree and call it should-fix I would not argue hard, but it should not ship unfixed on the grounds that it is rare, because "the disk stalled during a drain" is the scenario `_terminated` exists for and this is the half of it that was missed.

**Fix.** Either take `_open_lock` around the `os.write` loop (it is already never on the request path, and `close()` already never takes it), or — cheaper and non-blocking — do not `os.close()` in `close()` while a write may be in flight: `os.dup2(os.open(os.devnull, O_WRONLY), fd)` retires the descriptor without freeing the number, so a straggling write goes nowhere instead of somewhere. A per-open generation counter checked inside the write loop would also do it.

---

## 3. New findings — should-fix

### N2-4 · should-fix · key sanitisation is a per-key cost amplifier: 20 ms from a 73 KB body, inside every cap

**Violates** `NFR-1`. Same root as N2-3: `FR-29` bounds node **count**, and the cost of a node is attacker-chosen.

`_safe_str_key`'s fast path (`len ≤ 256 and isprintable() and no marker`) is ~0.06 µs. Everything else falls into `_sanitize_key`, which does an `encode(surrogatepass)`, a regex search, a `str.translate` over a 2,080-entry table, a second `encode`, a BLAKE2b, a slice, a decode and an f-string.

**Repro / measurement** — `_safe_str_key` in isolation, cache cleared, 4,998 keys:

| key shape | µs/key | amplification vs a plain key |
|---|---:|---:|
| 5 printable chars | 0.06 | 1× |
| 99 printable chars | 0.19 | 3× |
| 5 chars, **one C0 control character** | **1.27** | **21×** |
| 1,100 chars (over `MAX_KEY_BYTES`) | **12.84** | **214×** |

End-to-end through the real middleware with an event-loop heartbeat:

| body | size | middleware | loop lag |
|---|---:|---:|---:|
| baseline 8 KB JSON | 8 KB | 1.58 ms | 4.55 ms |
| 4,998 keys each ending in `` | **73 KB** | **20.05 ms** | **28.21 ms** |
| 4,998 keys each with 3 control chars | 136 KB | 18.99 ms | 22.01 ms |
| 4,998 plain 100-byte keys | 507 KB | 13.91 ms | 14.15 ms |

All three pass `_exceeds_node_cap` (4,999 nodes against a 10,000 cap) and are a fraction of `max_body_bytes`.

**Expected** ≤ 5 ms.

**Blast radius.** 20 ms per request from a **73 KB** body, i.e. 4× the NFR-1 budget from a payload 14× under the cap, at ~50 req/s to saturate a worker. Combined with N2-3 (a 64 KB query string on the same request) the attacker-forced stall is ~45 ms, i.e. ~22 req/s per worker. M-2's original figure was 9 req/s. The improvement is real; the property `FR-29` claims — that a client cannot pick the package's CPU cost — is not.

Note the `_KEY_CACHE_MAX` clear-when-full policy makes this cheaper for the attacker than it looks: 4,998 distinct keys in one body overflow the 4096-entry memo mid-body, so a repeated attack never warms it.

**Fix.** Bound the *work*, not only the count: fold the per-key cold-path cost into the FR-29 budget (charge a control-char or over-length key more than one node), or cheapen the cold path — `str.translate` with a `bytes.maketrans`-style table, and skip the `surrogatepass` encode when the fast test already proved there are no surrogates.

### N2-6 · should-fix · `max_body_nodes = 10_000` refuses ordinary bulk traffic, uncounted — the repo's own "realistic" fixture is 6.9× over it

**Trade-off in `FR-29`.** `_exceeds_node_cap` never *under*-counts (§6 — I tried hard). It over-counts by design, and the default is set low enough that real traffic hits it.

**Repro** — default config, `body_skipped` recorded:

| body | size | result |
|---|---:|---|
| bulk POST, 500 records × 15 fields | 74 KB | stored |
| bulk POST, **700 records × 15 fields** | **103 KB** | **`too_complex` — body dropped** |
| bulk POST, 1000 records × 15 fields | 147 KB | `too_complex` |
| a list of **12,000 integer ids** | 73 KB | `too_complex` |
| one field holding a CSV blob with 11,000 commas | 22 KB | `too_complex` |
| one field holding embedded JSON as a string | 60 KB | `too_complex` |

The commas-inside-a-string cases are the over-count the docstring admits. The bulk cases are not — they are genuinely over the cap, at ~97 records.

**The strongest evidence is in the repo.** `tests/unit/test_redact.py::_one_megabyte_of_nested_json`, docstring *"~1 MB of realistic, deeply-nested, denylist-hitting JSON"*, and the fixture behind the README's headline `redact()` benchmark:

```
README's benchmark payload: 1,104,781 B, actual nodes 69,122, cap estimate 69,122, max_body_nodes 10,000
would the node cap refuse it?  True
body_skipped = too_complex
```

The team's own idea of a realistic 1 MB body is **6.9× over the shipped cap**. In production that body has no `audit.request.body` at all.

**And there is no metric.** `too_complex` appears nowhere in `METRIC_NAMES`. `audit_documents_submitted_total` counts these as successes. An operator cannot alert on "we are dropping the bodies of 40 % of our audit records"; they have to notice it in Kibana. For bulk endpoints — mass export, bulk permission change, batch delete — the body *is* the audit value, and those are the endpoints most likely to be over the cap.

**Fix.** Raise the default (100,000 keeps the M-2 shapes refused — the 1 MiB `[[],[],…]` body is ~400,000 nodes — while admitting ordinary bulk traffic), add an `audit_bodies_skipped_total{reason}` counter, and say in the runbook which knob to turn. Also fix the README benchmark to use a body the shipped config admits, or say plainly that it measures a refused shape.

### N2-7 · should-fix · the opt-in text scrub misses the SOAP shape it exists for

**`FR-28`, `docs/redaction.md` §4.7.** The scrub is honestly labelled best-effort, and I am not re-reporting the disclosed gaps (prose, positional CSV). Three of the misses are not the "unusual shape" the disclosure implies — they are the *default* shape of the formats the opt-in is for:

**Repro** — `_scrub_text(text, DEFAULT_REDACT_KEYS)`:

| input | output | |
|---|---|---|
| `<Password>hunter2</Password>` | `<Password>[REDACTED]</Password>` | ok |
| `<ns:Password>hunter2</ns:Password>` | **unchanged** | **LEAK** |
| `<wsse:Password Type="x">hunter2</wsse:Password>` | **unchanged** | **LEAK** |
| `<credentials><a>hunter2</a></credentials>` | **unchanged** | **LEAK** |
| `password: \|\n  hunter2` | `password: [REDACTED]\n  hunter2` | **LEAK** |
| `password:\n  hunter2` | **unchanged** | **LEAK** |
| `{" password":"hunter2"}` | **unchanged** | LEAK (known N-4 class) |
| `{"ns:password":"hunter2"}` | **unchanged** | LEAK |
| `Content-Disposition: ... name="password"\n\nhunter2` | **unchanged** | **LEAK** |
| `INSERT INTO u(password) VALUES('hunter2')` | **unchanged** | LEAK |

`<wsse:Password>` is the literal element name in WS-Security. `_SCRUB_KEY` is `[A-Za-z0-9_.\-]{1,64}` — it excludes `:`, so **every namespace-prefixed XML element is invisible to the scrub**, and namespace prefixes are the norm in SOAP, not the exception. `application/xml` and `text/xml` were two of the six content types M-1 was filed about; a service that turns `capture_text_bodies` on to capture its SOAP traffic gets the passwords in the clear.

**Fix.** Add `:` to `_SCRUB_KEY` and normalise on the local part after the last `:`, and match a close tag as `</\s*(?:[^\s<>]*:)?(?P=key)\s*>`. Recurse the XML pattern once so a denylisted *parent* redacts its subtree. Then say explicitly in `docs/redaction.md` §4.7 which of the remaining shapes are untested (four of five currently are — §5).

### N2-8 · should-fix · the parse-failure path still stores up to 4096 unredacted characters, client-selectable

**Residual S-2.** The 4096-char clip caps the volume, not the leak. `{"password":"hunter2", oops}` still stores the secret in full; a secret is short and an attacker controls where it sits in the body.

```
{"password":"hunter2", oops}  ->  body_parse_failed=True, body_raw='{"password":"hunter2", oops}'
long broken JSON              ->  len(body_raw)=4096, body_truncated=True, secret present: True
```

This is now correctly identified in three places as *the* one unredacted field, is pinned by a well-written regression test (`test_AC_14_a_parse_failure_is_the_only_unredacted_body_raw`, with a comment telling a future fixer to update the doc), and `AC-14` demands it. So the code is doing what the contract says. My position is that the **contract** is wrong: `AC-14`'s diagnostic value ("what did the broken JSON look like?") is fully served by the first ~256 characters plus a byte count plus a SHA-256 of the raw bytes, and none of those leak a whole credential. 4096 characters is a whole request body for most APIs.

Do not apply the §3.3 scrub here — see the correction in §1.3.

---

## 4. Judgement on the new requirements

### Schema §2.9 / FR-30 — `body` and `body_raw` mutually exclusive. **Right call.**

M-3 was real and this removes it at the root rather than by raising a ceiling; it also removes the second serialisation from the request path, which was a third of M-2. Measured: 1 MiB body → 1.00× line, every flavour. Supersede D-10.

**But §2.9 understates what is lost.** It says the raw text "adds only key order and duplicate keys, at 100 % of the storage". Three more things go with it, and I can demonstrate all three:

| body | what the document now records | what `body_raw` used to preserve |
|---|---|---|
| `{"a":123456789012345678901234567890}` | `{'a': 1.2345678901234568e+29}` | the exact integer |
| `{"a":1e400}` | `null` (orjson emits `null` for non-finite) | `1e400` |
| `{"a":"\ud800"}` | **nothing — the document is dropped** (N2-1) | the raw bytes |

The first is the one I would not accept quietly. For a payments, ledger or entitlement API, "the client sent 123456789012345678901234567890" and "the client sent 1.2345678901234568e+29" are different facts, and the audit log is now the only place that difference would have been recoverable. This is not an argument for restoring D-10 — it is an argument for the cheap third option the §2.9 table does not consider: **a `audit.request.body_hash` (SHA-256 of the raw captured bytes, 64 characters, one `keyword`, `ignore_above` 64)**. That restores non-repudiation — "these are the bytes we received, here is their digest" — at 0.006 % of the storage D-10 wanted, and it is the property an audit log actually needs from raw fidelity. The field budget is 51 of 200; there is room.

**Verdict: keep §2.9. Add `body_hash`. Correct the §2.9 sentence about what is lost.**

### FR-28 (`capture_text_bodies`) — **right call, correctly defaulted off.** See N2-7 for the scrub's gaps and §5 for the untested half of its disclosure.

### FR-29 (`max_body_nodes`) — **right mechanism, wrong default, and it bounds the wrong quantity.** See N2-6 (default) and N2-3/N2-4 (it bounds count, not cost, and not the query string). The pre-parse `bytes.count` design is genuinely good and I could not make it under-count (§6).

### FR-31 (`user.*` coercion) — **right call, no reservations.** Verified in §1.1.

### DEV-1 — `scope["audit_logging.received_bytes"]`. **Sound. Accept it.**

I went looking for the ways a scope channel goes wrong and did not find one that matters. The key is namespaced; it is written only after the application has returned, so `FR-24`'s "the only mutation" claim survives; nested `AuditMiddleware` instances (a mounted sub-application) both count the same body, so the outer's overwrite is a no-op; and the degradation path when the key is absent is a *visible* lower bound rather than a silent one (`body_truncated` true, `body_bytes` equal to it). The deviation note says all of this and says it should become a `RequestContext` field next time the contract opens. That is the right disposition. My only reservation is presentational: `RECEIVED_BYTES_KEY` is a public module constant, so an application *could* set it and steer `http.request.bytes` — harmless, but it should be documented as read-only or made private.

### DEV-2 — `body_truncated` also flags the 4096-char clip. **Accept, but the stated justification is wrong.**

The meaning ("what is stored is not all of it") really is consistent, and an operator can still separate the two cases (`body_parse_failed` true and `body_bytes > 4096` means the clip). What I do not accept is the reason given: *"it avoids adding a field to a `dynamic: false` mapping, which would cost a mapping entry for a flag"*. The mapping is at **51 fields of a 200 limit** — by the repo's own README. There is no scarcity to trade against. The honest version is "one field is not worth the schema churn at this point in the project", which is a fine reason; the stated one implies a constraint that does not exist and will be cited later as precedent when the budget actually matters.

### AC-18…AC-26 — **well constructed**, and the two that were corrected after measurement (AC-22's "~1× on the capture path" and AC-25's constants) were corrected in the right direction, with the reasoning recorded. AC-19's "< 5 ms" holds (0.07 ms); AC-20's "under `message_max_bytes`" holds (1,049,367 of 8,388,608); AC-22 holds (1.10×); AC-26's "within `queue_max_bytes` × 2" holds (1.91×). No objection to any of them.

### `docs/REQUIREMENTS.md` §3 was not updated with the rest — see N2-12.

---

## 5. Judgement on the docs

The documentation set is a genuine improvement and mostly tells the truth. `README.md` volunteers, in bold, that Tier 1 has never run. `tests/AC-matrix.md` §5 quotes the actual `docker ps` failure. `infra/filebeat/filebeat.yml` shows its sizing arithmetic and names which review finding each number closes. That is the right instinct throughout.

I sampled `docs/redaction.md` §4's twelve limitations against the tests each cites. **Nine of twelve are properly pinned** — several excellently, including `test_LIMITATION_matching_is_exact_not_substring` (asserts both the leak *and* the covered variants) and `test_AC_14_a_parse_failure_is_the_only_unredacted_body_raw` (asserts the sentinel survives, with a comment telling whoever fixes it to update the doc in the same commit). That is the behaviour I asked for in N-4 and it was delivered.

The exceptions:

| # | Doc claim | Problem |
|---|---|---|
| **N2-12** | `docs/REQUIREMENTS.md` §3, "JSON with duplicate keys": *"recorded in **both** `body` and `body_raw`. `body_raw` is the redacted re-dump"* | **Contradicts FR-30 and schema §2.9**, added in the same pass. `body_raw` is not emitted at all for parseable JSON now. §3 was not swept when §1/§2 were amended. Fix the row, or the next reader builds against it |
| **N2-13** | `README.md` "What it costs": *"Added p99 latency **+0.819 ms**"*; *"`redact()` 11.6 ms for a 1 MiB nested body"* | The p99 is the **8 KB benign arm only** — honestly labelled, but it is the headline number and the worst case is 20–33 ms (N2-3, N2-4). The `redact()` figure measures a fixture the **shipped default refuses** (`too_complex`, §N2-6), so it describes a path production cannot reach. Also: `tests/load/` still has only the 8 KB arm — the adversarial arm my first review recommended was not added, so nothing in CI would catch N2-3 or N2-4 |
| — | `docs/redaction.md` §4.5, secrets in `url.path`: *"asserted by `test_AC_07_...` and `test_S_5_...`"* | **Neither test puts a secret in a path.** AC-07 asserts `url.path == "/no/such/endpoint"`; the S-5 test asserts the path on the *degraded* `build_minimal_document` route. The limitation is read-and-verified, not pinned. (The doc applies exactly the right caveat to the `path_params` half — it should apply it here too) |
| — | `docs/redaction.md` §4 preamble: *"Each of these is a real, reproduced limitation **with a test that pins it**"* | **§4.8 (PII filename under a benign part name) cites no test and none exists** — only the inverse is tested. **§4.12 cites nothing.** Four of the five §4.7 scrub gaps (prose, nested XML, multi-line values, the `max_scrub_bytes` refusal) are uncited and untested; only the CSV one is pinned. The preamble overstates the set |
| — | `docs/redaction.md` §4.11, truncation loses benign data | Pinned by a bare `assert redact(...) != original`. It fails if the limitation is *fixed* and passes unchanged if truncation is silently made **worse** (cap lowered, marker renamed, more aggressive dropping). Weakest pin in the file; should assert `[TRUNCATED]` at the expected depth |
| — | `docs/redaction.md` §4.9 names six over-redacted keys (`hash, salt, sig, pan, session, auth`) | The test asserts two |
| — | `docs/redaction.md` §2.2: *"FR-11 mandates 35 of them"* | **36.** Both `redact.py:66-102` and `REQUIREMENTS.md`'s FR-11 list have 36. (The "106 entries" and "35 header allowlist" totals are correct) |
| — | `document.py` comment on `_SCAN_WINDOW`: *"32 KiB keeps the measured worst case (dense `key: value` lines) at ~3.5 ms, inside NFR-1's 5 ms"* | **Measured 6.19 ms** for exactly that input at exactly 32 KiB — over the budget the comment invokes. Other shapes: `key=value` 3.68, `"k":"v"` 3.37, `<k>v</k>` 2.66, prose 1.81. See **N2-9** below |
| — | `infra/filebeat/filebeat.yml` sizing header: worst line `= 6 × max_body_bytes = 6,292,571 B` | Not reachable at defaults. `body_raw` is now the *only* 6×-expanding field and it is capped at 4096 chars (parse failure) or `max_scrub_bytes` = 32 KiB (scrub), so the real ceiling is the flattened `body` at ~1.05 MB. **Over-provisioned, which is the safe direction** — but the derivation should name the knob it depends on (`max_scrub_bytes`), since it *is* correct if that is raised to `max_body_bytes` |

Minor, and correct to record: §2.3 describes key sanitisation as applying to "a body key" (it applies to every key `redact()` emits — body, query, `path_params`, multipart) and omits the third trigger (a key already containing the literal `[SANITIZED:`); §6's multipart row reads "✅ part names/filenames" when part *names* are matched against the denylist but never redacted themselves; §4.5 omits that `url.path` is `ignore_above: 2048`.

Everything else I checked against the code was accurate, including every constant: `MAX_KEY_BYTES = 1024`, the 16-hex BLAKE2b suffix, `_MAX_UNPARSED_BODY_RAW = 4096` with `body_truncated` on clip, `max_scrub_bytes` 32 KiB, depth cap 20 → `[TRUNCATED]`, part metadata clipped at 256, `error.message` at 1024, `url.path` indexed while `body_raw` is `index:false, doc_values:false`, ILM `min_age: 90d`.

### Two smaller ones from the scrub

**N2-9 · note · the scrub's own worst case is over the NFR-1 budget.** 6.19 ms at exactly `max_scrub_bytes`, against the 5 ms the code comment invokes and the 3.5 ms it claims. Not remotely dangerous — the path is off by default — but the bound was chosen from a number that is 1.8× optimistic, so it should be re-derived (or `max_scrub_bytes` lowered to ~16 KiB) rather than left as a comment that disagrees with the machine.

**N2-11 · note · the scrub corrupts its own output, and a client can forge its marker.** Pattern 5 re-matches pattern 4's replacement:

```
in : 'Authorization: Bearer abc123\nCookie: s=zzz'
out: 'Authorization: [REDACTED]\nCookie: [REDACTED]]'     <- note the doubled ]
```

Harmless (it is stable under re-application, and can only ever over-redact), but it is a visible defect in stored evidence. Separately, a client can put the literal string `[REDACTED]` in a text body and it survives verbatim, so a reader cannot distinguish "the package redacted this" from "the client wrote this" — worth one line in `docs/redaction.md`.

**N2-14 · note · control characters inside query keys defeat the denylist.** `?pass%00word=SECRET` → key `pass\x00word`, not normalised to `password`, value stored in the clear in both `url.query` and `audit.request.query`. This is the §4.3 whitespace class extended to C0, and unlike whitespace it is not documented — the query/form path strips whitespace now but not control characters. One `.strip()`-adjacent change; at minimum, document it alongside §4.3.

**N2-15 · note · `_open_lock` can block the event loop, once.** `start()` calls `_ensure_open()` synchronously on the event loop; if the worker thread is inside `_rotate_locked` on a stalled disk, the loop waits on a `threading.Lock`. The window is narrow (only while `_task is None`, i.e. first open) and I could not construct a realistic trigger, so this is a note, not a finding. Worth one comment next to `_ensure_open`'s "callable from any thread" docstring, which currently reads as though thread-safety were the only concern.

---

## 6. What I tried against the fixes and could not break

Listed so the next pass does not re-spend the budget here. All of these were attacked deliberately, not merely observed.

**`redact.sanitize_key` held against everything I threw at it.** This is a well-built piece of code.

| attack | result |
|---|---|
| **Marker forgery** — send a key that is already `<prefix>[SANITIZED:<16 hex>]` | Detected as unsafe, gets its *own* marker appended with a different digest. Cannot collide with a real rewrite |
| **Shadowing** — send the exact sanitised form of a victim key alongside the victim | Both survive as distinct entries; `redact` emitted 2 keys, not 1 |
| **Prefix collision** — two keys sharing a 996-byte prefix (`x*1100`, `x*1101`) | Prefixes identical, digests differ, both entries emitted. The digest is over the **original**, which is what makes this work |
| **Denylist evasion via sanitisation** | Impossible by construction: `_Decisions` takes the verdict from the original key before sanitising. `PASS_WORD`, `pass.word` still redact; the leaks (`password\x00`, `" password"`, ZWJ, homoglyph) are all the pre-existing N-4 class, unchanged by sanitisation |
| **Byte-bound escape** — 1,000 / 1,024 / 1,025 / 2,000 / 100,000 chars; 300 and 400 four-byte emoji | Output is **exactly ≤ 1024 UTF-8 bytes** in every case, cut on a character boundary. No mid-sequence truncation |
| **Lone surrogates in keys** | `\ud800` → U+FFFD + digest; result is always UTF-8-encodable. Serialises cleanly. (The *value* path is N2-1 — that is a different function's problem) |
| **NUL in a key** | `{"a b":1}` → `'a�b[SANITIZED:ffc151...]'`, no NUL, 31 chars |
| **Memo poisoning** | Not possible: the memo maps key → (safe key, normalized key), both pure functions of the key, with no dependence on the keyset. The clear-when-full policy cannot produce a wrong answer, only a slower one. *(Its **memory** is N2-2 — a different property)* |

**`_exceeds_node_cap` never under-counted.** I could not find a bypass, and I looked for one specifically.

- The bound `nodes ≤ 1 + count(",") + count("{") + count("[")` is *provable* for well-formed JSON: every container with *k* children contributes *k−1* commas plus its own bracket, so the sum telescopes to exactly the child count. It is tight for whitespace-free JSON and only ever over-counts.
- **20,000 randomly generated JSON documents** (mixed dicts/lists/scalars to depth 4, including string values deliberately containing `,`, `{` and `[`): **zero** under-counts.
- Hand-picked adversarial cases — `,`/`{`/`[` escapes, empty containers, bare scalars, deep nesting — all over-count or match.
- UTF-16/UTF-32-encoded JSON does not evade it either: the structural characters are still single `0x2C`/`0x7B`/`0x5B` bytes, and such a body fails both parsers anyway and lands on the clipped parse-failure path.
- The early-exit windowing is correct: `bytes.count(ch, start, end)` copies nothing, and the running total is checked per 64 KiB window, so a hostile body is refused in ~0.07 ms rather than after a full pass.

The design is right. The problem is what it is a proxy for (N2-4, N2-6), not whether it computes what it claims.

**`FileSink` locking: no deadlock, no cross-thread rotation window.** `_open_lock` is non-reentrant and every locked region is spelled `*_locked` and calls only other `*_locked` helpers — `_ensure_open`→`_open_locked` and `_rotate`→`_rotate_locked`→`_open_locked` never nest, and `_write_batch` acquires and releases each separately. `close()` genuinely never takes it, so FR-27's bound is preserved. The `_terminated` double-check is correct under interleaving in both directions: if `close()` runs *before* the fd is installed the worker's re-check undoes it; if *after*, `close()`'s own `_close_fd` sees the fd. `_release_path` is idempotent so the claim is released exactly once either way. **`submit()` touches none of it** — I re-read the whole request path: no lock, no `await`, no I/O. The one gap is the write itself (N2-5) — not the rotation.

**Write ordering and the `file_max_bytes` bound survive segmentation.** The new segmenting `_write_batch` never split a line across two files, never spun (the progress guard is sound: each pass either writes a line or rotates), and reported the bound correctly at two configurations 64× apart. `_whole_lines_within` correctly retries only the line a short write stopped inside.

**`_query`'s `changed` optimisation is no longer a passthrough for attacker bytes.** I specifically probed whether a *sanitised* key could make `reduced.get(key, value)` miss and fall back to the raw value — it can (for a >1024-byte key), but only for keys that are not denylisted, because any denylisted key normalises to a short printable name and is returned unchanged by `sanitize_key`. No secret escapes this way. `%20password%20`, `+password+`, `pass%00word` (see N2-14), 2000-char keys and mixed separators all behave.

**NFR-3 still holds across every new code path.** I injected a raising `_scrub_text`, `_safe_str_key`, `_exceeds_node_cap`, `filter_headers`, `redact` and `_query` into a live request with `capture_text_bodies` on, path params, a query string and a text body. In all six: **no exception escaped**, the response was delivered intact (`http.response.start` once, body once), and the document was replaced by the degraded marker. `mypy --strict` clean, 511 tests green.

**Body replay is still byte-exact.** Three chunks of 20 bytes at `max_body_bytes=32`: the app received `[(http.request, 20, True), (http.request, 20, True), (http.request, 20, False)]` — identical objects, identical `more_body` flags — while only the audit copy was capped.

**The `_key_cache` clear-when-full policy does not cost the service's own keys.** The design note's claim is right: after a flood, the service's real key names simply re-warm on the next request at 0.06 µs each. There is no permanent eviction and no measurable steady-state penalty. (The policy is fine; the *retention* is N2-2.)

**Infrastructure fixes check out on paper.** `message_max_bytes` 8 MiB clears the real ceiling with 8× headroom; `bulk_max_size: 12` clears `http.max_content_length` with room; rotated files are globbed; the undecodable-line path is a dead-letter route rather than `drop_event`; the `subPathExpr` `chown` initContainer exists with the PSA fallbacks spelled out. **All of this remains unexecuted** — see the verdict.

---

## Appendix — recommended pilot gate

| # | Finding | Severity | Blocks pilot? |
|---|---|---|---|
| **N2-1** | `{"a":"\ud800"}` deletes its own audit record, counted as disk pressure | must-fix | **yes — unconditional.** Client-selected audit suppression |
| **N2-2** | `_key_cache` retains ~4 GiB of attacker key strings; OOM-kills the pod | must-fix | **yes — unconditional.** Remote, cheap, kills the application |
| **N2-3** | 8–24 ms event-loop stall from an unbounded query string, on a `GET` | must-fix | yes, unless every client is trusted |
| **N2-5** | audit lines written into a recycled fd after `close()` | must-fix (narrow trigger) | yes if the pilot runs on shared/stalling storage; otherwise fix in the first follow-up |
| **N2-4** | 20 ms from a 73 KB body via per-key sanitisation cost | should-fix | no — but it is the other half of N2-3 and the fix is adjacent |
| **N2-6** | `max_body_nodes=10_000` silently drops ordinary bulk bodies, uncounted | should-fix | no — but raise the default *before* pilot traffic, or the pilot will under-report its own coverage |
| **N2-7** | scrub misses `<wsse:Password>` and every namespaced XML element | should-fix | only if the pilot service enables `capture_text_bodies` — in which case **yes** |
| **N2-8** | 4096 unredacted characters on the parse-failure path | should-fix | no |
| **N2-9…N2-15**, doc items | see §3, §5 | note | no — but fix N2-12 (contradictory requirement) and the §4 preamble before anyone builds against them |
| — | **Tier 1 has never been executed** | — | **yes.** One green Docker run before production traffic. N-9, N-10 and N-11 are still settled only against a (now good) hand-written double, and a green run against the double is easy to mistake for a green run against Elasticsearch |

The first review found five things that would have surfaced in production as a privacy incident or a hole in the audit trail. All five are closed. This one found three of the same weight, all three introduced by the code that closed them — which is not a criticism of the fix passes so much as the reason a verification pass exists. The parts that held this time — key sanitisation against forgery and collision, the node-cap bound, the rotation locking, exception safety across six new failure injections, replay fidelity — held under deliberate attack, and they are the parts that were hardest to get right.
