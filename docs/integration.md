# Adding `audit_logging` to a service

Everything below is either code you write once or a check you run once. The
order matters in exactly one place — the Elasticsearch objects must exist before
the first document arrives, and that is `infra/README.md`'s problem, not yours.

Budget half an hour. Most of it is step 0.

---

## Step 0 — decide what you are allowed to store

Do this before you write any code, because one of the answers is
**additive-only and cannot be undone later** (FR-13/D-12).

Three questions:

1. **Does this service handle PII you are not allowed to keep for 90 days?**
   Emails, phone numbers, names, addresses, dates of birth, national IDs under
   your own field names — **none of these are redacted by default.** That was
   deliberate, and it is the single most likely thing to bite you. If you have
   a compliance requirement, you opt in with `extra_redact_keys`. Read
   [`redaction.md`](redaction.md) §4.10 before you decide, and §5 for how to
   pick the list.
2. **Do any of your endpoints accept non-JSON bodies you need in the audit
   trail?** By default they are stored as metadata only — content type,
   declared length, and for multipart the per-part names and sizes. Turning
   `capture_text_bodies` on gets you the body text back after a scrub that is
   materially weaker than the JSON path. [`redaction.md`](redaction.md) §4.7.
   **If those bodies are SOAP, read the namespace bullet there first** — the
   scrub cannot see `<wsse:Password>` or any other namespace-prefixed element,
   which is the default shape of the traffic the flag exists for.
3. **Do you have fields named `hash`, `salt`, `sig`, `pan`, `session` or `auth`
   that carry something you actually want to read later?** Those are on the
   default denylist and their values will be `"[REDACTED]"` in every document,
   with no supported way to opt out. Rename them now or accept the loss —
   [`redaction.md`](redaction.md) §4.9.

## Step 1 — the dependency

```bash
pip install -e /path/to/audit_logger
```

Runtime dependencies are `pydantic>=2` and `pydantic-settings`. `starlette` is a
peer — your app already has it. Two optional extras are worth taking:

```bash
pip install -e '.[fast]'         # orjson: faster serialisation on both paths
pip install -e '.[prometheus]'   # prometheus_client, for PrometheusMetrics
```

## Step 2 — the middleware

```python
from fastapi import FastAPI
from audit_logging import AuditConfig, AuditMiddleware

app = FastAPI()

app.add_middleware(
    AuditMiddleware,
    config=AuditConfig(service_name="orders-api"),
)
```

Starlette passes the wrapped app positionally, which is why `config=` is a
keyword. Plain Starlette and any other ASGI framework work the same way; there
is nothing FastAPI-specific in the package.

Three things happen for you:

* the middleware constructs a `FileSink` from the config (unless you pass one);
* it starts the sink after `lifespan.startup.complete` and drains it on
  `lifespan.shutdown`, bounded by `shutdown_flush_timeout`;
* if your app has no lifespan — a bare `httpx.ASGITransport` in a test, say —
  the first `submit()` starts the sink lazily from the running loop.

Lifespan messages are passed through byte-identical in both directions. The
middleware **observes** the lifespan; it never alters it.

### Middleware order

`AuditMiddleware` should sit close to the outside of the stack, so that it sees
the real client, the real status code, and any exception a downstream middleware
converts into a 500. It is a pure ASGI middleware, not a
`BaseHTTPMiddleware` — body replay only works at the raw layer (D-1) — so it
composes with either kind.

### What it changes about your API

Exactly one thing: an `X-Request-ID` response header carrying `trace.id`
(FR-24). If the request already had a well-formed `X-Request-ID` (≤ 200
characters, printable ASCII), that value is reused; otherwise it is a fresh
UUID4 hex string. If your application sets the header itself, yours wins and the
middleware does not add a second one
(`test_middleware.py::test_FR_24_*`).

Nothing else about the request or the response is touched. The application
receives the request body byte-identically, chunk boundaries and `more_body`
flags included, whether or not the audit copy was truncated
(`test_middleware.py::test_FR_04_*`, AC-03, AC-04).

## Step 3 — configuration

Everything is settable in code or from the environment with an `AUDIT_` prefix.
Deployed services should use the environment, so that the kill switch is a
config change and not a release.

```yaml
env:
  - name: AUDIT_SERVICE_NAME
    value: orders-api
  - name: AUDIT_SERVICE_VERSION
    valueFrom: { fieldRef: { fieldPath: metadata.labels['app.kubernetes.io/version'] } }
  - name: AUDIT_ENVIRONMENT
    value: prod
  - name: AUDIT_LOG_DIR
    value: /var/log/audit
  - name: AUDIT_EXCLUDE_PATHS
    value: "/health,/healthz,/ready,/metrics,/internal/probe"
  - name: AUDIT_EXTRA_REDACT_KEYS
    value: "email,phone,date_of_birth"      # see step 0
```

List fields accept CSV or a JSON list. `AuditConfig` is `extra="forbid"`, so a
misspelled setting fails loudly at construction rather than being silently
ignored — but note that an **unknown `AUDIT_*` environment variable** is not a
field and is simply not read.

The full table is in the [README](../README.md#configuration); the source of
truth is `audit_logging/config.py`.

### 3.1 `max_body_nodes` — the one knob that is a genuine trade

Most of the config is a preference. This one is a decision, and if your service
has bulk endpoints you have to make it deliberately.

`max_body_nodes` (default **10,000**) bounds the *shape* of a parsed body, not
its length. A 1 MiB body of `[[],[],[],…]` costs far more to parse and redact
than a 1 MiB string, so without a shape bound a client picks your CPU cost — one
1 MiB payload used to block the event loop for 56–141 ms, at which point about
9 requests per second saturated a worker (review M-2). The count is estimated
before parsing, by counting `,`, `{` and `[` in the raw bytes, so an over-cap
body is refused in microseconds rather than after you have paid for the parse.

**Past the cap the audit record still exists** — only its body is missing:

```
audit.request.body_skipped = "too_complex"
audit_bodies_skipped_total += 1
```

**The trade, measured.** From `config.py`'s own docstring, on a realistic
order-batch payload:

| Nodes | Size | `redact()` |
|---:|---:|---:|
| 6,802 | 76 KiB | 2.61 ms |
| 17,002 | 191 KiB | **4.95 ms** — the whole NFR-1 budget |
| 34,002 | 382 KiB | 10.14 ms |
| 68,002 | 764 KiB | 19.90 ms |

Roughly linear, at about **0.29 µs per node** on that shape. (This document
previously said 3.4 µs — a factor of ~12 out, and contradicted by its own
table: 2.61 ms over 6,802 nodes is 0.38 µs. Corrected after `REVIEW-3.md`
caught it.) **A second measurement on a lighter payload put ~20,000 nodes at
~3.2 ms**, so the exact crossover depends on payload shape — how many keys take
the cold sanitisation path, how deep the nesting goes, how much of the body is
one long string. Treat 17,002 as "the order of magnitude at which you have
spent the budget on this shape", not as a universal number, and measure your
own worst body before you pick a value.

> **Node count is only one of the two bounds.** The other is
> `max_distinct_keys` (default 2048), and it is the one an attacker aims at.
> A *repeated* key is two dict lookups; a *first-seen* key costs ~1.4 µs that
> no cache can amortise. The table above uses an order-batch payload whose keys
> repeat, which is why 17,002 nodes only costs 4.95 ms — a body of 4,999
> **distinct** keys is 9.09 ms at a third of the node count. Bulk payloads
> repeat their keys, so this bound rarely touches real traffic; bodies built to
> be expensive do not. See `REVIEW-3.md` N3-1.

**What this means for a service with genuine bulk endpoints.** The cap bites
earlier than people expect: a bulk `POST` of ~700 records × 15 fields is about
103 KB and already over it, so the crossover is around **97 records**. The
repo's own "realistic 1 MB body" benchmark fixture is 69,122 nodes — **6.9×**
the shipped default. So if you have mass-export, batch-delete or bulk
permission-change routes, those are precisely the routes whose bodies will not
be stored, and they are precisely the routes where the body *is* the audit
value.

You have two options and there is no third:

* **Raise `max_body_nodes` and accept the latency**, on every request, not just
  the bulk ones — the bound is global, not per route. Size it from the table
  above against your own p99 headroom.
* **Accept bodiless records for those routes.** You still get one audit document
  per request with the route, the user, the status, the timing and
  `body_skipped: "too_complex"`; you do not get what was in the batch.

There is no setting that gives you both. Whichever you choose, **wire
`audit_bodies_skipped_total` to a dashboard before you send real traffic** — it
is the only way to find out you are dropping 40 % of your bodies, and without it
the loss is visible only by noticing it in Kibana.

The query string has its own, much tighter bound (`max_query_bytes`, 8192, with
a 512-pair bound derived from it) and its own counter,
`audit_queries_skipped_total`. It is deliberately a separate counter: a route
with chatty query strings must not page whoever is alerting on lost bodies.

### `user_resolver`

The one hook. It is called with the raw ASGI `scope` and returns a dict, or
`None`:

```python
def resolve_user(scope: dict) -> dict | None:
    principal = scope.get("state", {}).get("principal")
    if principal is None:
        return None
    return {"id": principal.id, "name": principal.username, "roles": principal.roles}

config = AuditConfig(service_name="orders-api", user_resolver=resolve_user)
```

Only `id`, `name` and `roles` are kept; anything else is dropped. Values are
coerced to the types `schema.md` §2.5 declares — `id`/`name` to `str`, `roles`
to `list[str]` — and anything that will not coerce is dropped rather than
emitted (FR-31). This matters more than it looks: an object in a `keyword` field
makes Elasticsearch reject **the whole document**, so an unvalidated resolver
could delete audit records (review M-5, `test_document.py::test_FR_31_*`,
AC-21).

If the resolver raises or returns a non-dict, the document is still emitted
without any `user.*` block and `audit_middleware_errors_total` is incremented
(AC-17). Your request is never affected.

### Metrics

By default the middleware builds an `InMemoryMetrics`, which is a dict you can
read with `.snapshot()`. To get the counters into Prometheus, pass one in:

```python
from audit_logging.metrics import PrometheusMetrics

app.add_middleware(AuditMiddleware, config=config, metrics=PrometheusMetrics())
```

The metric names are frozen in `audit_logging._contracts.METRIC_NAMES`. What
each one means, and which ones to alert on, is in
[`runbook.md`](runbook.md) §1.

## Step 4 — the volume mount

**This is the step that fails silently.** The sink cannot raise into the request
path (NFR-3), so a directory it cannot write to produces a pod that reports
healthy, serves traffic normally, and writes nothing at all.

The manifest fragment lives in `infra/filebeat/daemonset.yaml`, in the block
marked "THE OTHER HALF OF THE CONTRACT". Copy it; do not retype it. The
procedure is `infra/README.md` §2 step 3. Three parts:

* a `hostPath` volume at `/var/log/audit`, mounted with
  `subPathExpr: $(POD_NAME)` so each pod gets its own subdirectory (and a
  `POD_NAME` downward-API env var to make that expand);
* the `audit-log-dir` **initContainer**, which `chown`s that subdirectory to
  your application's UID. It is **not optional for a non-root app container**:
  the kubelet creates a `subPathExpr` directory as `root:root` mode 0755, and
  `fsGroup` is not applied to `hostPath` volumes, so a `runAsNonRoot` app gets
  `EACCES` when the sink opens its file (review S-14);
* node disk budget: `file_max_bytes` × (`file_backup_count` + 1) per **process**
  — 2.25 GB at the defaults — multiplied by uvicorn workers, multiplied by
  audited pods per node.

Each process writes its own file, `{service_name}-{pid}.jsonl`, so several
uvicorn workers in one pod do not contend
(`test_file_sink.py::test_FR_26_*`). If two live sinks in **one process** end up
on the same path — a mounted sub-application with its own middleware,
`add_middleware` called twice, a test harness — the second takes a `-{6 hex}`
suffix instead of quietly destroying the first one's lines (review S-11).

> Caveat, stated because the AC matrix states it: "several uvicorn workers write
> separate files and Filebeat picks up all of them" is **not tested**. There is
> no uvicorn in this environment. The `{pid}` in the name and the in-process
> collision suffix are both tested; the multi-worker deployment is reasoned, not
> verified (`tests/AC-matrix.md` §4.2).

## Step 5 — prove it works

Run these in order. Each one fails in a different, informative way.

### 5.1 Locally, before you deploy

```python
import json, tempfile
from audit_logging import AuditConfig, AuditMiddleware
# ... build your app with log_dir=tempfile.mkdtemp(), send one request ...
```

Then read the file. You are looking for one line per request, with `audit.route`
holding your **route template** (not the concrete path), and no secret anywhere
in it:

```bash
tail -1 "$TMPDIR"/orders-api-*.jsonl | jq '{
  route: .audit.route, method: .http.request.method,
  status: .http.response.status_code, outcome: .event.outcome,
  skipped: .audit.request.body_skipped, body: .audit.request.body }'
```

If you would rather assert in a test than eyeball a file, use `NullSink`, which
keeps documents in memory:

```python
from audit_logging import AuditMiddleware, AuditConfig, NullSink

sink = NullSink()
app.add_middleware(AuditMiddleware, config=AuditConfig(service_name="t"), sink=sink)
# ... exercise the app ...
assert sink.only["audit"]["request"]["body"]["password"] == "[REDACTED]"
```

`tests/integration/test_acceptance_local.py` is a working, readable example of
this shape at scale.

### 5.2 On the node, after the first rollout

`infra/README.md` §7 is a copy-pasteable four-step check. The short version:

```bash
POD=$(kubectl -n <app-ns> get pod -l app=<svc> -o jsonpath='{.items[0].metadata.name}')
kubectl -n <app-ns> exec "$POD" -- ls -l /var/log/audit
kubectl -n <app-ns> exec "$POD" -- tail -1 /var/log/audit/<svc>-*.jsonl
kubectl -n <app-ns> logs "$POD" -c audit-log-dir
```

An empty directory here means the mount or the initContainer is wrong. Run this
**once per service, on its first rollout** — it is the only evidence the write
side works, and the failure mode is a green pod with an empty index.

### 5.3 In Elasticsearch

`infra/README.md` §4. The one that matters most:

```bash
curl -sS "$ES_URL/logs-apiaudit.<svc>-<env>/_count?pretty"
```

Zero, with 5.2 passing, means the shipping half is broken — go to
[`runbook.md`](runbook.md).

## What a document looks like

`docs/schema.md` §1 has a full worked example and §2 the complete field
reference. Two things trip people up:

* **`body` and `body_raw` are mutually exclusive** (schema §2.9, which
  supersedes plan decision D-10). A parseable JSON body appears in
  `audit.request.body` and there is no `body_raw` at all. `body_raw` appears
  only when the content genuinely cannot be represented as an object: a JSON
  parse failure, or an opted-in text body. `audit.request.body_skipped` names
  the case when neither is present.
* **`audit.request.body` is `flattened`**, so its sub-keys are `keyword`-only:
  exact-match queries work, range queries and full-text on body values do not.
  That is the trade that keeps 50 endpoints' worth of distinct body shapes at
  **51 fields created by traffic** instead of 20,194 (AC-10, measured). The
  installed mapping itself is **63** entries — 45 documented leaves plus 18
  object containers — against a `total_fields.limit` of 200. `schema.md` §3
  reconciles the four numbers; the one that moves is the 51.

## Before you send real traffic

- [ ] Step 0 answered, and `extra_redact_keys` set if the answer to question 1
      was yes.
- [ ] [`redaction.md`](redaction.md) §4 read by whoever owns the compliance
      answer for this service — not skimmed.
- [ ] §3.1 answered if this service has bulk endpoints, and
      `audit_bodies_skipped_total` on a dashboard either way — otherwise you
      will not know your bulk routes are producing bodiless records.
- [ ] Step 5.2 run and passing, on this service specifically.
- [ ] `infra/README.md` §6.1 and §6.3 wired to an alert. Those are the two ways
      a document disappears after the package has done its job correctly.
- [ ] Someone on call has read [`runbook.md`](runbook.md) and knows that
      `AUDIT_ENABLED=false` also removes the `X-Request-ID` response header.
