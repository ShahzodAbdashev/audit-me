# audit_logging

One searchable record per API request — who called it, what body they sent,
what came back — with secrets stripped before anything is written.

Your app writes JSONL to a file. Filebeat ships it to Elasticsearch. The
package never talks to Elasticsearch, so a log-store outage cannot slow down
or break your API.

```
FastAPI ─▶ middleware ─▶ file ─▶ Filebeat ─▶ Elasticsearch
           ~30 µs, no I/O
```

---

## Quick start

```bash
pip install "audit-me[elasticsearch]"
```

> Installed as **`audit-me`**, imported as **`audit_logging`**. The import name
> was fixed before `audit-logging` turned out to be taken on PyPI.

```python
from audit_logging import AuditConfig, AuditMiddleware

app.add_middleware(AuditMiddleware, config=AuditConfig())
```

```bash
export AUDIT_SERVICE_NAME=orders-api
export AUDIT_ENVIRONMENT=prod
export AUDIT_LOG_DIR=/var/log/audit

export AUDIT_ELASTICSEARCH_URL=https://your-cluster:9200
export AUDIT_ELASTICSEARCH_USERNAME=elastic
export AUDIT_ELASTICSEARCH_PASSWORD=...
```

Start your app. That is the whole setup — no Filebeat, no manual template
install, nothing to run first. On startup the package installs its own index
template and ILM policy, then ships. Records appear in
`logs-apiaudit.orders_api-prod`.

Use `AUDIT_ELASTICSEARCH_API_KEY` instead of user/password if you prefer, and
`AUDIT_ELASTICSEARCH_VERIFY_CERTS=false` for a self-signed cluster.

### It still writes to disk first

Setting a URL does **not** make your API depend on Elasticsearch. Records go to
a local JSONL file, and a background task tails that file and bulk-posts it:

```
FastAPI ─▶ middleware ─▶ file ─▶ shipper ─▶ Elasticsearch
           ~30 µs, no I/O        background
```

If the cluster is down, the files accumulate and the shipper retries. Tested:
stop Elasticsearch, serve 25 requests, restart it — all 25 records arrive, and
not one request was slowed or failed.

The shipper also refuses to send anything until the index template is installed.
A data stream created without it gets a dynamic mapping, which keeps working
until the field count explodes and is fixable only by a reindex.

### Using Filebeat instead

If you already run Filebeat, leave `AUDIT_ELASTICSEARCH_URL` unset and no HTTP
client is even imported. Point Filebeat at `AUDIT_LOG_DIR`.

The Filebeat config, the Kubernetes DaemonSet and the template installer live
in the [repository](https://github.com/ShahzodAbdashev/audit-me) under
`infra/` — they are deployment files, not Python, so they are not in the wheel:

```bash
git clone https://github.com/ShahzodAbdashev/audit-me
ES_URL=https://your-cluster:9200 ES_USERNAME=elastic ES_PASSWORD=... \
  python audit-me/infra/elasticsearch/bootstrap.py
```

The exact same template is bundled in the package as
`audit_logging.templates.INDEX_TEMPLATE`, and a test asserts the two never
drift — so you can also install it from Python if that is easier.

On Kubernetes, mount the log directory into your app pod:

```yaml
volumeMounts:
  - name: audit-logs
    mountPath: /var/log/audit
    subPathExpr: $(POD_NAME)
```

Two things there are easy to get wrong: a `runAsNonRoot` app needs the
`initContainer` in the manifest to be able to write into the mounted directory,
and Filebeat's Elasticsearch role must **not** hold `manage_index_templates` —
`setup.template.enabled: false` is a request, not an enforcement.

---

## Environment variables

**The ones you will actually set:**

| Variable | Default | |
|---|---|---|
| `AUDIT_SERVICE_NAME` | **required** | Names the service and the index |
| `AUDIT_ENVIRONMENT` | `dev` | `prod`, `staging`, … |
| `AUDIT_LOG_DIR` | `/var/log/audit` | Where JSONL is written |
| `AUDIT_ENABLED` | `true` | **`false` turns everything off.** Your kill switch |
| `AUDIT_EXTRA_REDACT_KEYS` | — | Extra keys to redact: `email,phone,national_id` |
| `AUDIT_SERVICE_VERSION` | `unknown` | Recorded on every record |

**Shipping straight to Elasticsearch** (omit all of these to use Filebeat):

| Variable | Default | |
|---|---|---|
| `AUDIT_ELASTICSEARCH_URL` | — | Set it and the package ships its own records |
| `AUDIT_ELASTICSEARCH_USERNAME` / `_PASSWORD` | — | Basic auth |
| `AUDIT_ELASTICSEARCH_API_KEY` | — | Base64 `id:api_key`, instead of the above |
| `AUDIT_ELASTICSEARCH_VERIFY_CERTS` | `true` | `false` for a self-signed cluster |
| `AUDIT_ELASTICSEARCH_SETUP` | `true` | Install the template and ILM policy on start |
| `AUDIT_RETENTION_DAYS` | `90` | When ILM deletes the index |
| `AUDIT_SHIP_INTERVAL_SECONDS` | `2.0` | How often the shipper checks for new records |
| `AUDIT_SHIP_BATCH_SIZE` | `500` | Documents per bulk request |

**Tuning, if you need it:**

| Variable | Default | |
|---|---|---|
| `AUDIT_EXCLUDE_PATHS` | `/health,/metrics,/docs,…` | Paths that produce no record |
| `AUDIT_MAX_BODY_BYTES` | `1048576` | Bigger bodies are truncated |
| `AUDIT_MAX_BODY_NODES` | `10000` | Bigger bodies stored **without** their body |
| `AUDIT_MAX_DISTINCT_KEYS` | `2048` | Same, for distinct key names |
| `AUDIT_MAX_QUERY_BYTES` | `8192` | Same, for the query string |
| `AUDIT_FLUSH_INTERVAL_SECONDS` | `1.0` | How often records reach the disk |
| `AUDIT_QUEUE_MAX_BYTES` | `67108864` | Memory bound; past it records drop and are counted |
| `AUDIT_FILE_MAX_BYTES` | `268435456` | Rotation size |
| `AUDIT_FILE_BACKUP_COUNT` | `8` | Files kept — with the above, ~2 GB per pod |
| `AUDIT_DATASET` / `AUDIT_NAMESPACE` | derived | Override the index. Dataset must start with `apiaudit.` |
| `AUDIT_CAPTURE_TEXT_BODIES` | `false` | Store non-JSON bodies — see the warning below |
| `AUDIT_EXTRA_HEADER_ALLOWLIST` | — | Extra headers to keep |

Lists are comma-separated: `AUDIT_EXTRA_REDACT_KEYS=email,phone`.

Anything set in code wins over the environment.

---

## Two things to know before production

**1. PII is not redacted by default.**

`password`, `api_key`, `token`, card numbers and `Authorization` headers are
handled automatically. **`email`, `phone`, `name`, `address` and
`date_of_birth` are stored in full.** If you have a compliance requirement,
turn them on yourself:

```bash
export AUDIT_EXTRA_REDACT_KEYS=email,phone,address,national_id
```

**2. Redaction matches key *names*, not values.**

So it cannot catch: a secret pasted into a `note` field, a secret in the URL
path (`url.path` is stored *and indexed*), `user_password_2` (matching is
exact, not substring), or a body that isn't JSON. Don't put secrets in URLs.

---

## Attaching the user

```python
def resolve_user(scope):
    user = scope.get("state", {}).get("user")
    return {"id": user.id, "name": user.email, "roles": user.roles} if user else None

AuditConfig(user_resolver=resolve_user)
```

If it raises, the record is still written without `user.*`. Your audit trail
doesn't depend on your auth layer behaving.

---

## Check it's working

```bash
python -m audit_logging.check
python -m audit_logging.check --leak "a-real-secret"
```

It reads the same `AUDIT_*` environment your app uses, so it checks what you
actually deployed:

```
  ok    1 file(s) on disk, 4 record(s) written
  ok    elasticsearch reachable, cluster is yellow
  ok    4 document(s) indexed
  ok    mapping is dynamic:false — the template is in force (46 fields)
  ok    'topsecret' appears in no document
```

**The mapping line is the one that matters.** Documents arriving proves very
little: an index created without the template accepts them happily, and the
field count looks fine right up until it doesn't. If it says anything other
than `dynamic:false`, fix that before the index grows — only a reindex will
afterwards.

Exit code is non-zero on failure, so this works as a deployment smoke test.

**Try the whole thing locally** — clone the repository (these scripts are not
in the wheel) and run, with Docker available:

```bash
git clone https://github.com/ShahzodAbdashev/audit-me && cd audit-me
./demo/run_e2e.sh --keep     # Elasticsearch + Filebeat + a real API, end to end
python demo/query.py recent 10
docker compose -f demo/docker-compose.kibana.yml up -d   # browser UI on :5601
python demo/kibana_setup.py
```

---

## When something looks wrong

| Symptom | Meaning |
|---|---|
| No records at all | Check `AUDIT_ENABLED`, and that `AUDIT_LOG_DIR` is writable |
| Files growing, nothing in Elasticsearch | Filebeat is down — check its logs and `curl :5066/stats` |
| `audit_documents_dropped_total` rising | Disk isn't keeping up |
| `audit_bodies_skipped_total` rising | Bodies hitting the size caps — normal on bulk routes |
| Need it off right now | `AUDIT_ENABLED=false` and restart |

---

## What it costs

Measured, not estimated (`pytest tests/load -m load`):

* **+0.82 ms** added p99, against a 5 ms budget
* ~30 µs per request in the middleware
* ~1.2 KB per record
* 51 Elasticsearch fields — a dynamic mapping would create 20,194

## Licence

MIT — see [LICENSE](LICENSE).
