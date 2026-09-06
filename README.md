# audit_logging

One audit record per API request — who called what, with which body, and what
came back — captured inside your FastAPI app and shipped to Elasticsearch.

```python
from audit_logging import AuditConfig, AuditMiddleware

app.add_middleware(AuditMiddleware, config=AuditConfig(service_name="orders-api"))
```

That is the whole integration. Secrets are stripped before anything is written.

---

## Why you would want this

Application logs tell you *that* a request happened. An audit log tells you
**what was in it** — which is what you need when someone asks "who changed this
order, and to what?", six weeks later, and the answer has to hold up.

Doing it with a logging decorator or a `BaseHTTPMiddleware` runs into four
problems that this package exists to solve:

| problem | what happens without it |
|---|---|
| **Reading the body consumes it** | An ASGI request body can be read once. Naive capture makes the request body empty by the time your handler sees it. This package replays it byte-for-byte. |
| **Secrets end up in the index** | `password`, `api_key`, `Authorization`, card numbers. Once they are in a searchable store with 90-day retention, they are a breach waiting to be noticed. Redaction here happens *before* the record leaves the process. |
| **The logger becomes the outage** | Anything that awaits I/O on the request path — an HTTP call to Elasticsearch, a blocking write — puts your API's latency at the mercy of your log store. This package writes to a local file from a background task; the request path only appends to a queue (~1 µs). |
| **The index mapping explodes** | Every distinct JSON body shape becomes new Elasticsearch fields, and a mapping that grows without bound eventually refuses writes. Measured here: 10,000 documents across 50 endpoints produce **51 fields**; the same traffic under a dynamic mapping produces **20,194**. |

**It never talks to Elasticsearch.** It writes JSONL to a file. Filebeat ships
the file. That means an Elasticsearch outage cannot slow down or break your API
— the records queue on disk and catch up later.

```
FastAPI ──▶ AuditMiddleware ──▶ queue ──▶ JSONL file ──▶ Filebeat ──▶ Elasticsearch
            (~30 µs, no I/O)            (background task)   (separate process)
```

### What it costs

Measured, not estimated — reproduce with `pytest tests/load -m load`.

| | |
|---|---|
| Added p99 latency | **+0.82 ms** against a 5 ms budget (100 rps, 8 KB JSON bodies, real sink, 300 s per arm) |
| Middleware overhead | ~30 µs per request |
| `submit()` on the request path | ~1.2 µs — a serialisation and a `deque.append` |
| Redaction | ~1.7 ms per 156 KB body |
| Storage | ~1.2 KB per typical record |
| Elasticsearch fields | 51 created by real traffic, against a 200 limit |

---

## Install

Requires Python 3.11+. The only hard dependencies are `pydantic` and
`pydantic-settings`; `starlette` is a peer you already have.

```bash
pip install git+https://github.com/ShahzodAbdashev/audit-me.git
```

Optional extras: `orjson` (faster serialisation), `prometheus-client` (metrics).

---

## Setup

### 1. Add the middleware

```python
from fastapi import FastAPI
from audit_logging import AuditConfig, AuditMiddleware

app = FastAPI()

config = AuditConfig(
    service_name="orders-api",       # -> index logs-apiaudit.orders_api-<env>
    service_version="1.4.2",
    environment="prod",
    log_dir="/var/log/audit",        # must be writable by the app container
)
app.add_middleware(AuditMiddleware, config=config)
```

Every field can come from the environment with an `AUDIT_` prefix
(`AUDIT_SERVICE_NAME`, `AUDIT_LOG_DIR`, `AUDIT_ENABLED`, …), so a deployment can
be tuned or switched off without a code change.

### 2. Attach the user (optional)

```python
def resolve_user(scope: dict) -> dict | None:
    """Whatever your auth layer already put on the scope."""
    user = scope.get("state", {}).get("user")
    return {"id": user.id, "name": user.email, "roles": user.roles} if user else None

config = AuditConfig(service_name="orders-api", user_resolver=resolve_user)
```

If it raises, the record is still written — without `user.*` — and the error is
counted. Your audit trail does not depend on your auth layer behaving.

### 3. Install the Elasticsearch template — **before the first record**

```bash
ES_URL=https://your-cluster:9200 ES_USERNAME=elastic ES_PASSWORD=... \
  python infra/elasticsearch/bootstrap.py
```

**Order matters and is not recoverable.** A data stream created before its
template gets a *dynamic* mapping. It keeps working, and keeps indexing, until
the field count explodes — and the only fix is a reindex. The script installs
the ILM policy and index template, verifies `dynamic: false` actually holds, and
refuses to run if it does not. It never deletes or reindexes anything.

### 4. Ship the files

Mount a volume at `log_dir`, and run Filebeat over it. `infra/filebeat/` ships
a working `filebeat.yml` and a Kubernetes DaemonSet with a commented sidecar
variant for clusters where `hostPath` is blocked.

Two things there are easy to get wrong and expensive to discover late:

* The application container must be able to **write** into the mounted
  directory. The kubelet creates `subPathExpr` directories owned by root, so a
  `runAsNonRoot` app needs the `initContainer` included in the manifest.
* The Elasticsearch role Filebeat uses must **not** hold `manage_index_templates`
  or `manage_ilm`. `setup.template.enabled: false` is a request, not an
  enforcement — a Filebeat with template rights can replace the mapping and
  undo `dynamic: false`.

```yaml
# the application pod writes here
volumeMounts:
  - name: audit-logs
    mountPath: /var/log/audit
    subPathExpr: $(POD_NAME)
```

Filebeat routes on three fields the package writes (`data_stream.type`,
`.dataset`, `.namespace`), so adding a service needs no Filebeat change.

### 5. Choose the destination (optional)

```python
AuditConfig(service_name="billing-api", dataset="apiaudit.billing", namespace="tenant-a")
# -> logs-apiaudit.billing-tenant_a
```

`dataset` **must** start with `apiaudit.` — the shipped template matches
`logs-apiaudit.*-*`, and anything else silently gets a dynamic mapping. The
config refuses it rather than letting that happen.

---

## Configuration

| Setting | Default | What it does |
|---|---|---|
| `service_name` | *required* | Names the service and derives the index |
| `service_version` | `"unknown"` | Recorded on every document |
| `environment` | `"dev"` | Becomes the data stream namespace |
| `enabled` | `True` | **Kill switch.** `AUDIT_ENABLED=false` makes the middleware a pass-through |
| `log_dir` | `/var/log/audit` | Where JSONL is written; one file per process |
| `dataset` / `namespace` | derived | Override the destination index |
| `max_body_bytes` | 1 MiB | Bodies larger than this are truncated and flagged |
| `max_body_nodes` | 10 000 | Bodies with more nodes are recorded without their body — see below |
| `max_distinct_keys` | 2 048 | Same, for distinct key names |
| `max_query_bytes` | 8 KiB | Same, for the query string |
| `capture_text_bodies` | `False` | Store non-JSON bodies — **read the warning below first** |
| `extra_redact_keys` | `[]` | Additional keys to redact (additive; defaults cannot be removed) |
| `extra_header_allowlist` | `[]` | Additional headers to keep |
| `exclude_paths` | health/metrics/docs | Paths that produce no record at all |
| `file_max_bytes` / `file_backup_count` | 256 MiB / 8 | Rotation — ~2 GB per pod ceiling |
| `flush_interval_seconds` | 1.0 | How often the background task writes |
| `queue_max_bytes` | 64 MiB | In-memory bound; past it records are dropped and counted |
| `user_resolver` | `None` | Callable returning `{"id", "name", "roles"}` |

### Bodies that are not stored

Three caps refuse a body rather than pay for it on the request path. The
**record is still written** — only the body is missing, and
`audit.request.body_skipped` says why. `audit_bodies_skipped_total` counts it.

This is a real trade: a bulk endpoint posting thousands of records will exceed
`max_body_nodes`, and those are exactly the routes where the body is the audit
value. Raise the cap **and accept the latency**, or accept bodiless records.
Measured on an order-batch payload: 6,802 nodes = 2.6 ms, 17,002 = 5.0 ms (the
whole latency budget), 68,002 = 19.9 ms. There is no setting that gives both.

---

## What redaction does **not** protect

Redaction is **key-based**: it matches key names, never values. Please read this
section before pointing it at production traffic — every item is a tested,
deliberate limitation, not a bug.

**PII is not redacted by default.** `email`, `phone`, `name`, `address`,
`date_of_birth` are stored in full. This is deliberate — the denylist is
additive-only, so a wrong default could never be undone by a service that
needed the field — but **if you have a compliance requirement, you must opt in**:

```python
AuditConfig(service_name="...", extra_redact_keys=["email", "phone", "national_id"])
```

This is the single most likely thing to surprise you.

| Not protected | Detail |
|---|---|
| **Secrets in the URL path** | `url.path` stores the raw path *and is indexed*, so a secret in a URL is searchable. A route that *names* the parameter (`/keys/{api_key}`) has that value redacted, but the path itself is not. Don't put secrets in URLs. |
| **Matching is exact, not substring** | `password` is caught; `user_password_2` is not. The ~75-key default list is a mitigation, not a fix. |
| **Homoglyphs and lookalikes** | `раssword` with a Cyrillic `а` passes through with its value intact. |
| **Values are never inspected** | A token pasted into a `note` field is stored verbatim. |
| **Broken JSON** | A body that fails to parse keeps up to 4096 characters of **unredacted** raw text, so the parse failure can be diagnosed — and a client can choose that path by sending malformed JSON. |
| **`capture_text_bodies=True`** | Non-JSON bodies can only get a best-effort textual scrub. It misses prose, nested and namespaced XML (`<wsse:Password>`), CSV columns and multi-line values. Off by default for this reason. |
| **Multipart filenames** | A PII filename under a non-denylisted field name is not detectable by a key denylist. |

What it *does* do reliably: keys matching the denylist at any depth, inside
lists and nested objects, in bodies, query strings and form data; and headers by
**allowlist**, so `Authorization` and `Cookie` never appear at all.

---

## Verifying it works

Documents arriving is necessary but **not sufficient** — a broken index template
still indexes documents happily. Three checks distinguish them:

```bash
python demo/query.py mapping   # must print dynamic: 'false'
python demo/query.py leaks hunter2   # a real secret must return 0 documents
python demo/query.py routes    # must show /orders/{order_id}, not /orders/42
```

| check | a bad answer means |
|---|---|
| `dynamic` is not `'false'` | The template did not apply. The index has a dynamic mapping and only a reindex fixes it. |
| A secret returns hits | A live leak — unless it is in `url.path` or a parse-failure `body_raw`, which are documented above. |
| Routes show ids, not templates | Route resolution is failing; every id becomes its own bucket. |

Useful counters (`audit_documents_dropped_total` rising means the disk is not
keeping up; `audit_bodies_skipped_total` means bodies are hitting the caps):

```bash
curl -s localhost:5066/stats   # Filebeat: acked should track what was written
```

### Try it end to end

Needs Docker. Starts Elasticsearch and Filebeat, runs a real FastAPI service
under uvicorn, sends 13 request shapes, and asserts on what reaches the index.

```bash
./demo/run_e2e.sh          # tears down afterwards
./demo/run_e2e.sh --keep   # leaves the stack up to explore
python demo/query.py recent 10
```

Add Kibana for a browser UI at <http://localhost:5601>:

```bash
docker compose -f demo/docker-compose.kibana.yml up -d
python demo/kibana_setup.py
```

---

## Operating it

| Symptom | Cause | Action |
|---|---|---|
| `audit_documents_dropped_total` rising | The queue filled — disk not keeping up | Check disk I/O and free space on the volume |
| `audit_bodies_skipped_total` rising | Bodies hitting `max_body_nodes` / `max_distinct_keys` | Expected on bulk routes; raise the cap only if you accept the latency |
| `audit_documents_failed_total` rising | Writes are failing | Check permissions and free space on `log_dir` |
| Files growing, nothing in Elasticsearch | Filebeat is down or misconfigured | `docker logs` / pod logs for Filebeat; check `curl :5066/stats` |
| Documents in `logs-apiaudit.undecodable-*` | A line Filebeat could not decode | The full line is still on the node until rotation — go copy it |
| **"Turn it off now"** | | `AUDIT_ENABLED=false` and restart. Note this also removes the `X-Request-ID` response header. |

Records are **not** deduplicated by `trace.id` alone — a client can send its own
`X-Request-ID`. Use `trace.id` + `host.hostname` + `process.pid` + `@timestamp`.

---

## Testing

```bash
pytest tests -m "not load and not integration"   # 611 offline tests
pytest tests/load -m load                        # latency, incl. adversarial bodies
pytest tests/integration -m integration          # 31 tests against real Elasticsearch
mypy --strict audit_logging
```

The load suite has an **adversarial arm** as well as a benign one. A latency
budget that only holds for traffic you control is not a budget — so it drives
the payload shapes that previously broke this package (1 MiB pathological
bodies, 64 KB query strings, hostile keys) and asserts each stays inside 5 ms.

---

## Documentation

This repository ships the code, the infrastructure and this README. The
detailed design and review documents — the requirements, the field-by-field
schema, the full redaction analysis, the on-call runbook, the adversarial
review reports and the build plan — are kept **out of the repository** to keep
it small and readable. They live alongside the working copy and are listed in
`.gitignore`.

If you need them, ask whoever set this up.

---

## Licence

MIT — see [LICENSE](LICENSE).
