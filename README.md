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

## 1. Install

```bash
pip install git+https://github.com/ShahzodAbdashev/audit-me.git
```

Python 3.11+. Only needs `pydantic` and `pydantic-settings`.

## 2. Add two lines to your app

```python
from audit_logging import AuditConfig, AuditMiddleware

app.add_middleware(AuditMiddleware, config=AuditConfig())
```

That's it. Everything else is environment variables.

## 3. Set the environment

```bash
export AUDIT_SERVICE_NAME=orders-api      # required — also names the ES index
export AUDIT_ENVIRONMENT=prod
export AUDIT_LOG_DIR=/var/log/audit       # must be writable by your app
```

Those three are the minimum. Records land in
`logs-apiaudit.orders_api-prod`.

## 4. Install the Elasticsearch template — **before your first request**

```bash
export ES_URL=https://your-cluster:9200
export ES_USERNAME=elastic
export ES_PASSWORD=...

python infra/elasticsearch/bootstrap.py
```

> **Do this first.** If records arrive before the template exists,
> Elasticsearch invents its own mapping. Everything keeps working until the
> field count explodes, and the only fix is a reindex.

## 5. Run Filebeat over the log directory

Config is in `infra/filebeat/`. Point it at the same directory:

```bash
export ES_HOSTS=https://your-cluster:9200
export ES_USERNAME=filebeat_writer
export ES_PASSWORD=...
```

On Kubernetes use `infra/filebeat/daemonset.yaml`, and mount the log dir into
your app pod:

```yaml
volumeMounts:
  - name: audit-logs
    mountPath: /var/log/audit
    subPathExpr: $(POD_NAME)
```

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
python demo/query.py             # counts per service
python demo/query.py recent 10   # last 10 requests
python demo/query.py mapping     # must say dynamic: 'false'
python demo/query.py leaks hunter2   # a real secret must return 0
```

`mapping` is the important one. If it doesn't say `dynamic: 'false'`, the
template didn't install and you need to fix that before the index grows.

**Try the whole thing locally** (needs Docker) — starts Elasticsearch and
Filebeat, runs a real API, and checks what arrives:

```bash
./demo/run_e2e.sh --keep
python demo/query.py recent 10
```

Browser UI at <http://localhost:5601>:

```bash
docker compose -f demo/docker-compose.kibana.yml up -d
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
