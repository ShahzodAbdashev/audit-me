# Runbook — `audit_logging`

For on-call. Symptom → cause → action. Nothing here needs you to read the
package source.

**Two things to know before anything else.**

1. **This package cannot break your API.** No exception it raises reaches the
   application, the sink never blocks the request path, and a full queue or an
   unwritable disk costs you audit records, not availability (NFR-3, AC-08,
   AC-09, AC-16). If your service is down, it is almost certainly not this. The
   one honest exception is memory: the sink holds up to `queue_max_bytes`
   (64 MiB default) plus at most one batch, and that is real RSS in your pod.
2. **The metrics are in-process and, by default, not exposed anywhere.** The
   middleware builds an `InMemoryMetrics` unless a service passes something
   else. If a service did not wire `PrometheusMetrics`
   ([`integration.md`](integration.md) §3), none of the counters below are
   scrapeable and your only signals are the log lines and the files on disk.
   Check that first, before you conclude a counter is at zero.

---

## 0. "I need to disable this right now"

```
AUDIT_ENABLED=false
```

and restart the service. It is an `AuditConfig` field, so it is settable purely
in the environment — no code change, no image build. With it off the middleware
is a genuine pass-through: no document built, no queue allocated, no file
opened, no `receive`/`send` wrapping, nothing to measure
(`test_FR_15_kill_switch_is_a_pure_pass_through`,
`test_FR_15_kill_switch_allocates_no_sink`, AC-11).

> ### ⚠ The kill switch also removes the `X-Request-ID` response header
>
> FR-15 asks for no measurable overhead, which leaves no room to keep wrapping
> `send` just to stamp a header — so FR-24's `X-Request-ID` disappears along
> with the logging (review N-14,
> `test_N_14_the_kill_switch_removes_the_request_id_header_too`).
>
> **This changes API behaviour, not just logging.** Anything downstream that
> correlates on that header — a client SDK, a support tool, another service's
> logs, a synthetic check — stops seeing it. Before you flip the switch on a
> service whose consumers you do not control, check whether the ingress can set
> the header instead. That is where request identity belongs anyway.

Softer levers, in rough order of how much they cost you:

| Lever | Effect |
|---|---|
| `AUDIT_EXCLUDE_PATHS=...,/the/noisy/endpoint` | Stops auditing one route. Prefix match, anchored at a path-segment boundary |
| `AUDIT_MAX_BODY_BYTES=8192` | Keeps every record; stops storing large bodies. Cuts line size and CPU |
| `AUDIT_MAX_BODY_NODES=2000` | Keeps every record; stops storing *complex* bodies. Cuts CPU harder than the byte cap does, and shows up in `audit_bodies_skipped_total` (§4.1) |
| `AUDIT_MAX_QUERY_BYTES=2048` | Same idea for the query string. Shows up in `audit_queries_skipped_total` |
| `AUDIT_CAPTURE_TEXT_BODIES=false` | Undoes an opt-in to text-body storage (this is the default) |
| `AUDIT_FLUSH_INTERVAL_SECONDS=5` | Fewer, larger writes. Trades freshness for I/O |
| `AUDIT_ENABLED=false` | Everything off, including `X-Request-ID` |

---

## 1. The metrics

The complete set, frozen in `audit_logging._contracts.METRIC_NAMES`:

| Metric | Type | Means |
|---|---|---|
| `audit_documents_submitted_total` | counter | Documents handed to the sink. Should track your request rate minus excluded paths |
| `audit_documents_dropped_total` | counter | Refused at `submit()` because the queue was full **or** because the sink was already closed. **See §2 and §5** |
| `audit_documents_failed_total` | counter | Documents the sink could not get onto disk and gave up on, counted once each — a failed write, **or** a document that could not be serialised. **See §4** |
| `audit_documents_dropped_after_close_total` | counter | The subset of drops that were requests still in flight at shutdown. **"Shutdown was too short", not "disk is not keeping up"** |
| `audit_middleware_errors_total` | counter | Package-internal errors, all swallowed. A `user_resolver` raising lands here |
| `audit_bodies_skipped_total` | counter | The audit **record exists**; its *body* was not stored — over `max_body_nodes`, a content type the denylist cannot be applied to, or a skipped multipart. **Not a lost document.** See §4.1 |
| `audit_queries_skipped_total` | counter | The same for the **query string**, over `max_query_bytes` or its derived pair bound. Deliberately a separate counter — see §4.1 |
| `audit_queue_bytes` | gauge | Every audit byte the sink holds: queued lines **plus** the batch in flight or parked for a retry |
| `audit_flush_seconds` | gauge | Duration of the last flush |
| `audit_file_rotations_total` | counter | Files rotated |

**The four "something was lost" counters are disjoint in meaning and it is worth
learning the difference once, at three in the morning it is too late:**

| Counter | Was a document lost? | Page? |
|---|---|---|
| `audit_documents_dropped_total` | **yes** | yes — disk is not keeping up (§2) |
| `audit_documents_failed_total` | **yes** | yes — the write or the serialisation failed (§4) |
| `audit_documents_dropped_after_close_total` | **yes** | only if large or growing — shutdown ordering (§5) |
| `audit_bodies_skipped_total` / `audit_queries_skipped_total` | **no** — the record is there, part of its content is not | no, but dashboard it (§4.1) |

Log lines come from two loggers: `audit_logging` (middleware, WARN, once per
kind of error per process) and `audit_logging.sinks.file_sink` (ERROR, once per
distinct `phase:ExceptionType:errno` per process). Both are deliberately
one-shot to bound noise — **a single ERROR line can represent an ongoing
failure**, so check the counter, not the line count.

---

## 2. `audit_documents_dropped_total` is rising

**Means:** `submit()` refused a document. Two very different causes share this
counter.

**First, split them:**

```
drops from a full queue = audit_documents_dropped_total
                        − audit_documents_dropped_after_close_total
```

If the whole rise is the second term, go to [§5](#5-audit_documents_dropped_after_close_total--0).

**Cause (full queue).** Enqueueing the line would push the sink past
`queue_max_bytes` (64 MiB default). With a file sink this means one thing:
**the disk is not keeping up with the request rate.** It is a paging event, not
a normal condition (FR-19, plan §2). Requests keep succeeding; the audit trail
has holes.

**Check:**

```bash
# Is the volume full or slow?
kubectl -n <app-ns> exec <pod> -- df -h /var/log/audit
kubectl -n <app-ns> exec <pod> -- ls -la /var/log/audit
# Did the sink log a write failure? (once per distinct errno)
kubectl -n <app-ns> logs <pod> | grep 'audit file sink'
```

**Action, in order:**

1. If the disk is **full** → [§8](#8-disk-full-on-a-node).
2. If the disk is **slow** (an overloaded node volume, a network-backed
   `hostPath`, another tenant saturating it) → the sink cannot fix this. Reduce
   what it writes: `AUDIT_MAX_BODY_BYTES` down (8 KiB is plenty for most audit
   value), or `AUDIT_EXCLUDE_PATHS` for the highest-volume endpoint.
3. If the disk is healthy and the rate is simply higher than planned → raise
   `AUDIT_QUEUE_MAX_BYTES`, remembering that it is **real memory in the
   application pod** and that peak is up to 2× it. Raise the pod memory limit at
   the same time.
4. Record the gap. The records are gone; nothing recovers them.

**Do not** assume a rise here is Elasticsearch's fault. This counter is
upstream of Filebeat entirely.

**And it no longer includes serialisation failures.** A document that could not
be encoded used to tick this counter, which meant a client could point you at
the disk — or mask a genuine disk-pressure alert — with a 14-byte request body
(`REVIEW-2.md` N2-1). Those now go to `audit_documents_failed_total` (§4), so a
rise here really is about capacity.

---

## 3. `audit_queue_bytes` is climbing

**Means:** the flush task is falling behind, or is not running.

The gauge counts queued lines **plus** the in-flight/retry batch, so it is the
number to size a pod against (review S-8 — it used to read `0.00 MiB` while a
full batch sat in the retry slot).

**Causes, most likely first:**

| Cause | Tell |
|---|---|
| Disk slow or failing | `audit_documents_failed_total` also rising; ERROR lines from the sink |
| Write failing outright (permissions, full) | ERROR line with an errno; §7 or §8 |
| Sustained request rate above the flush rate | Everything else healthy, gauge sawtooths upward |
| The flush task never started | Gauge climbs from process start, `audit_documents_submitted_total` rises, nothing on disk. Rare — the sink starts on lifespan startup and lazily on the first `submit()` otherwise |

**Action:** if it is approaching `queue_max_bytes` you are about to start
dropping (§2), and the pod is holding that many bytes plus a batch right now.
Treat a gauge above ~50 % of `queue_max_bytes` for more than a few minutes as
the warning and the drop counter as the page.

---

## 4. `audit_documents_failed_total` is rising

**Means:** a document did not reach the disk and the sink gave up on it. Each
lost document is counted exactly once — not twice, which it used to be
(review S-9 / D-A6-1, `test_AC_26_close_returns_in_time_and_counts_each_lost_document_once`,
measured 122 lost / counter 122). So this number is the number of audit records
actually lost, and you can put it in an incident report as-is.

**Two causes now share it**, and the log line tells you which:

1. **A write failed** — the sink wrote, the write failed, it retried the batch
   **once**, then dropped it. This is the common case and the rest of this
   section is about it.
2. **A document could not be serialised at all** (`phase: serialise`). This is
   counted here rather than under `audit_documents_dropped_total`, and the
   change matters: `dropped_total`'s documented meaning is "the disk is not
   keeping up", a paging event about *capacity*, and a document nobody could
   encode says nothing whatsoever about the disk. Filing it there meant the one
   signal you got pointed an operator at the wrong subsystem — and let a client
   fire or mask a disk-pressure alert at will (`REVIEW-2.md` N2-1).
   **This should now be very hard to reach**: `_dumps` falls back to the stdlib
   encoder when the fast one refuses, and lone surrogates are neutralised in
   `redact()` before the document ever gets here. So a non-zero `serialise`
   count is *new information* — capture the document shape before it ages out.

**Cause (a failed write):** something about the file. Get the errno from the log:

```bash
kubectl -n <app-ns> logs <pod> | grep 'audit file sink .* failed on'
```

The line names the phase (`open` / `write`), the exception type and the errno,
and each distinct combination logs once per process.

| errno | Cause | Action |
|---|---|---|
| `ENOSPC` / `EDQUOT` | Node volume full | [§8](#8-disk-full-on-a-node) |
| `EACCES` / `EPERM` | The app cannot write the directory | [§7](#7-a-service-is-producing-no-documents-at-all) — almost always the missing initContainer |
| `EIO` | Failing disk | Drain the node |

The request path is never affected and the process never exits (AC-16).

---

## 4.1 `audit_bodies_skipped_total` / `audit_queries_skipped_total` are rising

**Means:** the audit **record exists** and is on disk; part of its *content* was
not captured. **Nothing is lost from the audit trail as a count of requests** —
do not treat these like §2 or §4. They exist because before them an operator
could not see this happening at all: `audit_documents_submitted_total` counted
these as unqualified successes and the only evidence was noticing a missing
`body` in Kibana.

**`audit_bodies_skipped_total` — three causes**, and the document tells you
which in `audit.request.body_skipped`:

| `body_skipped` | Cause | Lever |
|---|---|---|
| `too_complex` | The body was over `max_body_nodes` (10,000 by default), counted before parsing | `AUDIT_MAX_BODY_NODES` up — **and accept the latency**; see `integration.md` §3.1 for the measured trade |
| `content_type` | The body is not JSON or form-encoded, so a key denylist cannot be applied to it, so by default it is not stored (review M-1) | `AUDIT_CAPTURE_TEXT_BODIES=true`, only after reading `redaction.md` §4.7 |
| `content_type` on a multipart request | Uploaded bytes are never stored by design (D-5). Part metadata still is | none — this is not a defect |

`empty` (there was no body) and `unread` (the application never read a body it
was sent) are **not** counted, so an ordinary `GET` does not move this number.

**The most likely real answer is bulk endpoints.** The default node cap starts
refusing at roughly 97 records in a batch. If this counter tracks your bulk
routes, you are storing bodiless records for exactly the requests where the body
*is* the audit value. That is a decision to make, not an incident: `integration.md`
§3.1.

**`audit_queries_skipped_total`** means a query string was over
`max_query_bytes` (8192) or over the derived pair bound (`max_query_bytes // 16`,
512 pairs at the default). `url.query` then holds the fixed literal
`"[SKIPPED]"` — never client bytes, so the bound cannot be used as a redaction
bypass — and `audit.request.query` is `{}`.

**It is a separate counter on purpose.** A route with long query strings is
chatty, not broken, and whoever is alerting on "we are losing request bodies"
must not be woken by it. Do not merge the two into one alert.

If a service genuinely needs longer queries audited, `AUDIT_MAX_QUERY_BYTES` up
is the lever — the cost is pair-dominated (~1.1 µs per pair against ~2.8 µs per
KB) and it is paid on the event loop, on the request path, so raise it in
proportion to your NFR-1 headroom and not further.

---

## 5. `audit_documents_dropped_after_close_total` > 0

**Means:** requests were still in flight when the sink closed at
`lifespan.shutdown`. Their documents were dropped.

**It does NOT mean the disk is not keeping up.** It has its own counter for
exactly that reason — the FR-19 drop counter is a paging event and this is not
(review N-8). Note that these documents increment **both** counters, so subtract
before you interpret §2.

**Cause:** shutdown reached the sink before the last requests finished. Normal
in small numbers during a rolling deploy; a problem if it is large or growing.

**Action:**

1. A handful per pod termination: expected. Ignore.
2. Hundreds per termination: your app is being terminated while still serving.
   Fix the shutdown ordering — the middleware closes the sink on
   `lifespan.shutdown`, so anything the server admits after that is unlogged.
   Lengthen `terminationGracePeriodSeconds` and make sure the pod is out of the
   load-balancer's rotation before the shutdown signal.
3. It is also worth checking `shutdown_flush_timeout` (10 s default): `close()`
   returns after that whether or not the drain finished, by design — a slow disk
   must not hang shutdown (FR-27, AC-26). If the queue was deep and the disk
   slow, the drain may also have timed out. That loss shows in
   `audit_documents_failed_total`, not here.

> ### One file descriptor may survive `close()`, deliberately
>
> If a write is still in flight when the sink closes — a stalled disk, an NFS
> hang, a node under IO pressure being drained — `close()` does **not** close
> the descriptor. It hands ownership of the close to the writer thread, which
> closes it when the write returns. If that write never returns, **one
> descriptor stays open for the remaining life of the process**.
>
> That is the intended behaviour, not a leak to chase. The alternative was
> measured and is far worse: closing the fd out from under a live `os.write`
> frees the *number*, the kernel hands the same integer to the next `os.open`
> or `accept`, and the straggling write lands in whatever now owns it. That was
> demonstrated — five complete audit documents appended to an unrelated
> application file, and none in the audit log (`REVIEW-2.md` N2-5). Descriptor
> numbers are shared with **sockets**, so the recipient can be a client
> connection: audit content — full URL paths, path params, user ids, the whole
> flattened body — written down a network peer.
>
> **What this means for you:** one stranded fd in a process that is already
> exiting, lasting seconds. If you see an fd-count alert fire during a drain on
> a service with a sick disk, this is why, and it is not worth an incident.
> `close()` itself is unaffected and still returns inside
> `shutdown_flush_timeout` — it takes only a lock that is never held across a
> syscall.

---

## 6. File rotations spiking

**Means:** `audit_file_rotations_total` is climbing far faster than usual.

**Cause:** you are writing far more bytes than expected. Either request volume
jumped, or bodies got much bigger, or someone lowered `file_max_bytes`.

**Why it matters:** rotation is where lines are most at risk. `filestream`
follows an open file across the rename **only while Filebeat is running**; if
the DaemonSet pod is down at that moment — node drain, rolling update,
OOM-kill, config reload — the unshipped tail lands at `.1`. The shipped
`filebeat.yml` deliberately globs rotated files to cover this (review S-13), but
faster rotation shrinks the window in which any given file is still on disk to
be read at all: retention is `file_max_bytes` × (`file_backup_count` + 1) per
process, 2.25 GB at the defaults.

**Action:**

1. Confirm the cause: `du -sh /var/log/audit/<pod>` over time, and check whether
   `AUDIT_MAX_BODY_BYTES` or `AUDIT_FILE_MAX_BYTES` was changed recently.
2. Confirm Filebeat is keeping up (§9) — if it is, fast rotation is only a disk
   cost.
3. If bodies are the cause, `AUDIT_MAX_BODY_BYTES` down is the lever.

> **Known open defect, D-A6-5.** About one process in three, a rotation that
> races the sink's lazy `start()` leaves a **gap in the `.N` numbering** and one
> file at roughly 2× `file_max_bytes`. **No lines are lost** — the oversized file
> holds both generations — but `file_max_bytes` is not a hard bound while this
> stands, so size a node with headroom rather than at exactly
> `file_max_bytes` × (`file_backup_count` + 1). Details and the mechanism are in
> `tests/AC-matrix.md` §7.

---

## 7. A service is producing no documents at all

The worst failure this system has, because everything looks healthy: the pod is
green, requests succeed, and the index is empty. The sink cannot raise into the
request path, so a directory it cannot write to is silent by design.

**Work down this list; each step rules out one layer.**

1. **Is it switched off?** `AUDIT_ENABLED` in the pod's env. Also: does the
   response carry an `X-Request-ID` header? If not, and the app does not set one
   itself, the middleware is disabled or not installed.
2. **Is the path excluded?** `AUDIT_EXCLUDE_PATHS` is prefix matching anchored at
   a path-segment boundary. `/metrics` excludes `/metrics` and `/metrics/foo`,
   but not `/metrics-internal` — check the actual value, not the default.
3. **Is anything on disk?**
   ```bash
   kubectl -n <app-ns> exec <pod> -- ls -l /var/log/audit
   kubectl -n <app-ns> exec <pod> -- tail -1 /var/log/audit/<svc>-*.jsonl
   ```
   Empty directory → the write side. Go to 4. Lines present → the shipping
   side. Go to §9.
4. **The write side, and this is the usual answer:** the `audit-log-dir`
   initContainer is missing from the app pod. The kubelet creates a
   `subPathExpr` directory as `root:root` 0755 and `fsGroup` does not apply to
   `hostPath` volumes, so a `runAsNonRoot` app container gets `EACCES` when the
   sink opens its file (review S-14). Check:
   ```bash
   kubectl -n <app-ns> logs <pod> -c audit-log-dir     # does it even exist?
   kubectl -n <app-ns> logs <pod> | grep 'audit file sink'
   ```
   The fix is the manifest fragment in `infra/filebeat/daemonset.yaml`
   ("THE OTHER HALF OF THE CONTRACT"); the procedure is `infra/README.md` §2
   step 3 and the check is §7.
5. **Is the volume mounted at all?** Without the mount the app writes into the
   container filesystem, Filebeat sees nothing, and the pipeline is silently
   empty. `kubectl describe pod` and look for the `hostPath` volume and the
   `subPathExpr` mount.

---

## 8. Disk full on a node

**Symptom:** `audit_documents_failed_total` climbing with `ENOSPC` in the log;
possibly `audit_documents_dropped_total` too, once the queue backs up.

**Nothing breaks.** The write fails, the batch gets one retry, then it is
dropped and counted. The API keeps serving (AC-16).

**Immediate:**

1. Find what filled it. Audit files are `du -sh /var/log/audit/*`; the Filebeat
   disk queue is separate and is another ~2.2 GB.
2. Do **not** delete the active `.jsonl` file out from under a running process —
   the sink holds an open fd and you will free nothing. Delete the oldest
   rotated `.jsonl.N` files, or lower `AUDIT_FILE_BACKUP_COUNT` and restart.
3. If a quarantine or dead-letter investigation is open (§10, §11), **copy the
   relevant file off the node before you delete anything** — it is the only
   place the full line still exists.

**Then size it properly.** Per audited **process**: `file_max_bytes` ×
(`file_backup_count` + 1) = 2.25 GB at the defaults, multiplied by uvicorn
workers, multiplied by audited pods per node, plus Filebeat's own disk queue.
`infra/README.md` §2 step 3.

---

## 9. Filebeat: lines on disk, nothing in Elasticsearch

Everything from here down is `infra/`'s territory; this section is a triage
index into `infra/README.md`, which has the copy-pasteable queries.

**Check, in order:**

```bash
# 1. Is the shipper wedged? `failed` climbing with `acked` flat for more than a
#    few minutes is a page.
kubectl -n audit-logging exec ds/filebeat-audit -- curl -s localhost:5066/stats |
  jq '{acked: .libbeat.output.events.acked,
       failed: .libbeat.output.events.failed,
       dropped: .libbeat.output.events.dropped,
       queue: .libbeat.pipeline.queue}'

# 2. Can it see the files at all, and did the registry survive the restart?
#    (infra/README.md §4 has both commands.)
```

| Tell | Cause | Where |
|---|---|---|
| `failed` climbing, `acked` flat, `413` in the log | Bulk too large for the cluster; retried forever by design | `infra/README.md` §6.3 |
| `Rejecting event with size ... segment buffer limit` | Disk queue `segment_size` below `message_max_bytes` | `infra/README.md` §6.3 |
| Documents in `logs-apiaudit.undecodable-*` | A line Filebeat could not decode | §10 below |
| Documents in `apiaudit-dead-letter` | Elasticsearch refused the document | §11 below |
| Duplicates everywhere after a restart | Registry loss — `path.data` was lost | §12 below |
| Nothing wrong anywhere and still no documents | The data stream may have been created before the template. `infra/README.md` §4 and §8 — this one needs a reindex |

### 9.1 A caveat you should know while triaging

The Elasticsearch + Filebeat test tier has **never been executed** — no Docker
in the environment this was built in (`tests/AC-matrix.md` §5). Everything from
the JSONL line onward is reasoned from the config files, not observed. In
particular "Filebeat follows the file across rotation and every line reaches
Elasticsearch" is unverified and is the single most consequential unverified
claim in this system (`tests/AC-matrix.md` §4.3, AC-12). If you are triaging
missing lines around a rotation, treat that as a live hypothesis rather than a
ruled-out one.

---

## 10. Documents quarantined in `logs-apiaudit.undecodable-*`

**Means:** Filebeat read a line, could not decode it as ndjson, and routed it to
a quarantine data stream instead of discarding it. In practice: **the line was
longer than `message_max_bytes` and filestream truncated it**, so the JSON no
longer parsed.

This is the M-3 class of loss — the one where the largest and most interesting
audit records were the ones that vanished, with no counter anywhere. The
quarantine data stream **is** the counter; Filebeat has no metric for this at
all.

**Queries:** `infra/README.md` §6.1 (a count over 24 h, and a sample with the
first 400 characters of the raw line).

**What quarantine preserves:** that the record existed, its timestamp, and the
first chunk of it. **What it does not:** the bytes past `message_max_bytes`,
which filestream discarded before any processor ran.

**Action:**

1. Look at the head of `message`. A huge `audit.request.body_raw` is the usual
   answer.
2. **Go and copy the source file off the node now, not later.** The full line is
   still in `/var/log/audit/<pod>/<service>-<pid>.jsonl*` until rotation reaches
   it.
3. The package-side lever is `AUDIT_MAX_BODY_BYTES` down. The shipper-side lever
   is `message_max_bytes` up — read the SIZING INVARIANTS block at the top of
   `infra/filebeat/filebeat.yml` first, because `queue.disk.segment_size` and
   `bulk_max_size` are derived from it and moving one alone reintroduces the
   loss one layer down.
4. Anything above zero is worth investigating. Expect zero.

> Context: the largest line a 1 MiB `max_body_bytes` can now produce is
> **1,049,779 B** — 12.5 % of the configured 8 MiB `message_max_bytes`
> (`tests/AC-matrix.md` §2.4). If you are seeing quarantined lines with the
> shipped defaults, something is different from what was measured; find out
> what before you raise a limit.

## 11. Documents in `apiaudit-dead-letter`

**Means:** Elasticsearch refused the document. A mapping error rejects the
**whole document**, not the offending field — `ignore_malformed` covers numeric,
boolean, date, `ip` and geo types only, never `keyword` or `flattened`.

**Queries:** `infra/README.md` §6.2, including a cluster-side corroboration
(`index_failed` per node) that counts rejections whether or not the dead-letter
write itself succeeded.

**Three known causes**, all listed in `infra/README.md` §6.2 with the cost to an
attacker. The package now defends against all three — `user.*` values are
coerced to the schema's types (FR-31, AC-21), and body keys are bounded at
1024 UTF-8 bytes and stripped of control characters and lone surrogates before
they are emitted. **So a hit here in current code is new information**: either a
service is on an older build, or there is a rejection cause nobody has found
yet. Capture the `error.message` and the document before it ages out.

Note the nasty property of this failure class: a key over the Lucene term limit
whose *value* also exceeds `ignore_above` is dropped before the term is built
and indexes cleanly, so the same request shape works intermittently. Do not
conclude from one successful retry that it is fixed.

## 12. Filebeat registry loss → duplicates

**Means:** `path.data` was lost, so Filebeat re-read every file it can still see
from byte 0.

**Action:** `infra/README.md` §6.4 has the deduplication aggregation.

**The one thing to get right:** **do not deduplicate on `trace.id` alone.**
FR-23 reuses a client-supplied `X-Request-ID` when it is well formed, so
`trace.id` is client-chosen — one client pinning one value makes every request
it ever sends collapse into a single "event" (review N-12). The collapse key is
`trace.id` **+** `host.hostname` **+** `process.pid` **+** `@timestamp`.

---

## 13. Elasticsearch field count approaching 200

**Means:** the index template's `total_fields.limit` is 200 and something is
consuming the headroom.

**Check:** `infra/README.md` §4 has the query. Measured: **51 fields created by
real traffic** after 50 endpoints × 200 requests with deliberately distinct body
shapes — a dynamic mapping would have created **20,194** (AC-10, executed).

Elasticsearch compares `total_fields.limit` against the **63** entries in the
installed mapping (45 documented leaves + 18 object containers), not against the
51. Both numbers are correct and they count different things; `docs/schema.md`
§3 is the resolution. The 51 is the one to watch, because it is the one that
moves.

**This should not move on its own.** The mapping is `dynamic: false` and every
variable-shaped part of the document (`audit.request.body`, `.headers`,
`.query`, `.multipart`, `audit.path_params`, `audit.response.headers`) is
`flattened`, which costs **one** field regardless of what a client sends. No
request body can add a field.

**So a rise means someone changed the template**, which is a change-management
question, not an incident. The headroom exists to absorb ECS additions, not new
`audit.*` fields (`docs/schema.md` §3: anything new goes through the
orchestrator).

Related trap, from `infra/README.md` §8: **`dynamic: false` is silent.** A field
the template does not declare is accepted, stored in `_source`, and simply never
indexed. If a field is missing from Discover, check the template before you
check the application.

---

## 14. "Requests got slower after we deployed this"

**Measured, not estimated:** added p99 latency is **+0.819 ms** against NFR-1's
5 ms budget — 300 s per arm, 100 rps, 8 KB bodies, real `FileSink` writing real
JSONL, real redaction (`tests/AC-matrix.md` §6). The overhead is flat across the
distribution (+0.70 ms mean, +0.73 p50, +0.81 p95, +0.82 p99), which is what you
expect from something that does no I/O on the request path.

> **That figure is the benign arm.** It says what *ordinary* traffic costs.
> What a hostile client can cost is measured separately, by
> `tests/load/test_nfr1_adversarial.py`:
>
| shape a client chooses | before the fix | now |
> |---|---|---|
> | 1 MiB `[[],[],…]` body | 140.6 ms | **0.09 ms** |
> | 1 MiB `[0,0,…]` body | 93.4 ms | **0.10 ms** |
> | 64 KB query, **no body** | 24.0 ms | **0.01 ms** |
> | 73 KB of control-character keys | 20.0 ms | **3.28 ms** |
>
> If you are triaging a latency change, **check the shape of the traffic, not
> just its volume** — every row above is a shape the client picks, and volume
> is irrelevant to all of them. Run that file (`-m load`) against the deployed
> version before concluding the bounds still hold.

If you are seeing materially more than that, in order of likelihood:

1. **Large or awkwardly-shaped bodies.** Cost scales with body *shape*, not
   only size: `redact()` is ~1.7 ms on the largest realistic body the shipped
   `max_body_nodes` admits (156 KB, 9,962 nodes) and 12.6 ms on a 1.05 MB /
   69,122-node body — which the shipped default **refuses** as `too_complex`
   before parsing, by counting `,`, `{` and `[` in the raw bytes. So the
   pathological case is bounded at defaults. **If someone raised
   `AUDIT_MAX_BODY_NODES`, that bound moved and this is your first suspect** —
   the measured curve is in `integration.md` §3.1. `AUDIT_MAX_BODY_BYTES` down
   is the other lever.
2. **A chatty query route.** The query string is parsed, redacted and re-encoded
   on the request path exactly like a form body, and the cost is
   pair-dominated. It is bounded by `max_query_bytes` (8192) and a 512-pair
   derived bound; before those existed, 64 KB of query on a **bodiless `GET`**
   cost 17.9 ms of event-loop stall. Check `audit_queries_skipped_total` (§4.1)
   and whether anyone raised `AUDIT_MAX_QUERY_BYTES`.
3. **Hostile key shapes.** Keys carrying control characters or over 1024 bytes
   take a sanitisation path 20–70× the cost of an ordinary key. It is bounded at
   128 such keys per `redact()` call — but `redact()` runs up to four times per
   request, so the real per-request ceiling is 512. A body engineered for this
   was measured at 20 ms before the bound existed.
4. **The flush task competing on the same event loop.** One process, one loop:
   the background flush shares it with your handlers. A slow disk shows up here.
5. **It is not this.** The p99 delta above was measured with the real sink; a
   middleware doing I/O on the request path would show a fat tail (a p99 delta
   several times its p50 delta) and this one does not.

Caveat on all of these numbers: measured in-process with `httpx.ASGITransport`.
No sockets, no uvicorn, no TLS, one worker.

---

## 15. What is not in this runbook, because nothing measures it

Stated so you do not go looking for a signal that does not exist:

* **Whether every line reached Elasticsearch.** Nothing reconciles
  `audit_documents_submitted_total` against the index. The three known loss
  paths each have a query (§10, §11, and `infra/README.md` §6.3); the reconcile
  does not exist.
* **Multi-worker behaviour.** `{pid}` in the filename is tested; "several
  uvicorn workers write separate files and Filebeat picks up all of them" is
  not (`tests/AC-matrix.md` §4.2).
* **ILM actually rolling over or deleting.** The policy is installed and its
  presence asserted; no test observes a phase transition. It is an operational
  check — `infra/README.md` §4, the `_ilm/explain` line.
* **A `dropped_after_close` document's identity.** You know how many were lost,
  never which.
* **What hostile traffic costs.** `tests/load/` has one arm — 8 KB JSON bodies,
  100 rps — and nothing adversarial. The bounds on query size, body shape and
  per-key sanitisation cost all hold today (they were each measured once, by
  hand, during the verification review), but **nothing in CI would notice if one
  of them regressed.** §14 lists them so you know what to suspect; there is no
  signal that would tell you first.
