# audit_logging

One searchable record per API request — who called it, what body they sent,
what came back — with secrets stripped before anything is written. Since 0.2
each record also says what the request **meant**, as a sentence a
non-developer can read:

> Sardor Karimov «Aliyev Vali» foydalanuvchisini tahrirladi — Rol: Operator → Admin

Your app writes JSONL to a local file. A background shipper in the same
process (or Filebeat, if you prefer) sends it to Elasticsearch. Nothing on the
request path talks to the network, so a log-store outage cannot slow down or
break your API.

```
FastAPI ─▶ middleware ─▶ file ─▶ shipper (or Filebeat) ─▶ Elasticsearch
           no I/O               background
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

`AuditConfig()` reads the environment. Anything passed in code wins over it.

Three variables are **required** and have no defaults — the process will not
start without them:

```bash
export AUDIT_SERVICE_NAME=orders-api                      # who wrote the record
export AUDIT_DATASET=orders_api                           # which index it lands in
export AUDIT_ELASTICSEARCH_URL=https://your-cluster:9200  # where it ships, or `none`
```

Each one silently defaulting is a different silent failure: an unnamed
service, an index nobody chose, or a service that writes perfect JSONL to disk
and ships none of it. Naming them is a deployment decision, so it is made
explicitly or the service refuses to start.

The rest have sensible defaults:

```bash
export AUDIT_ENVIRONMENT=prod
export AUDIT_LOG_DIR=/var/log/fortress
export AUDIT_ELASTICSEARCH_USERNAME=elastic
export AUDIT_ELASTICSEARCH_PASSWORD=...
```

Start your app. That is the whole setup — no Filebeat, no manual template
install, nothing to run first. On startup the package installs its own index
template and ILM policy, then ships. Records appear in
`logs-orders_api-prod`.

The index is `logs-<dataset>-<namespace>`, where the dataset defaults to the
sanitised `AUDIT_SERVICE_NAME` and the namespace to `AUDIT_ENVIRONMENT`. The
template and the ILM policy are installed **per dataset** — `logs-orders_api`
matching `logs-orders_api-*`, and `orders_api-ilm` — so two services never
share them and neither can redefine the other's mapping or retention.

Use `AUDIT_ELASTICSEARCH_API_KEY` instead of user/password if you prefer, and
`AUDIT_ELASTICSEARCH_VERIFY_CERTS=false` for a self-signed cluster.

### Several services, one index

Set the same `AUDIT_DATASET` everywhere and give each service its own
`AUDIT_SERVICE_NAME`:

```bash
# shared by every service
AUDIT_DATASET=platform
AUDIT_NAMESPACE=prod

# per service
AUDIT_SERVICE_NAME=orders-api     # and payments-api, search-api, …
```

Everything lands in `logs-platform-prod`, and each record carries
`service.name`, `service.version`, `host.hostname` and `process.pid`, so
`service.name: "orders-api"` is the whole filter. One dataset means one ILM
policy, so retention and rollover are shared — split the dataset when two
services need different retention.

A dataset cannot contain `-` or `*`. The template is installed as
`logs-<dataset>` matching `logs-<dataset>-*` at `priority: 500`, which
outranks Elasticsearch's built-in `logs` template, so either character would
widen that pattern onto data streams this package does not own and impose its
`dynamic: false` mapping on them — their documents would index with none of
their fields. `AuditConfig` refuses it rather than letting that happen.

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

If you already run Filebeat, set `AUDIT_ELASTICSEARCH_URL=none` and no HTTP
client is even imported. It has to be said rather than omitted — a forgotten
variable and a deliberate Filebeat deployment used to look identical. Point Filebeat at `AUDIT_LOG_DIR`.

The Filebeat config, the Kubernetes DaemonSet and the template installer live
in the [repository](https://github.com/ShahzodAbdashev/audit-me) under
`infra/` — they are deployment files, not Python, so they are not in the wheel:

```bash
git clone https://github.com/ShahzodAbdashev/audit-me
AUDIT_DATASET=orders_api \
ES_URL=https://your-cluster:9200 ES_USERNAME=elastic ES_PASSWORD=... \
  python audit-me/infra/elasticsearch/bootstrap.py
```

`AUDIT_DATASET` is required and has no default: the template is scoped to one
dataset, so guessing it would install a template pointed at the wrong indices.
Run it once per dataset, plus once with `AUDIT_DATASET=undecodable` for the
stream Filebeat quarantines undecodable lines into.

The package bundles the template as `audit_logging.templates.INDEX_TEMPLATE`.
**In 0.2 the two differ:** the package's copy is the `infra/` file plus the v2
fields (`audit_logging.semantic.schema.MAPPING_ADDITIONS`), and a test asserts
exactly that. `infra/` has not been regenerated yet, so a Filebeat deployment
that wants the v2 fields indexed should install the template from Python. Both copies
carry `{dataset}` where the dataset goes;
`audit_logging.templates.index_template_for("orders_api")` binds it. The
Kibana objects in `infra/kibana/dashboards.ndjson` carry the same placeholder,
so substitute it before importing them:

```bash
sed 's/{dataset}/orders_api/g' infra/kibana/dashboards.ndjson > /tmp/dash.ndjson
```

On Kubernetes, mount the log directory into your app pod:

```yaml
volumeMounts:
  - name: audit-logs
    mountPath: /var/log/fortress
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
| `AUDIT_SERVICE_NAME` | **required** | Goes on every record as `service.name` |
| `AUDIT_DATASET` | **required** | The index: `logs-<dataset>-<namespace>`. Share it to collect services |
| `AUDIT_ELASTICSEARCH_URL` | **required** | Where the shipper posts, or `none` to ship with Filebeat |
| `AUDIT_ENVIRONMENT` | `dev` | `prod`, `staging`, … |
| `AUDIT_LOG_DIR` | `/var/log/fortress` | Where JSONL is written |
| `AUDIT_ENABLED` | `true` | **`false` turns everything off.** Your kill switch |
| `AUDIT_EXTRA_REDACT_KEYS` | — | Extra keys to redact: `email,phone,national_id` |
| `AUDIT_SERVICE_VERSION` | `unknown` | Recorded on every record |

**Shipping straight to Elasticsearch** (`AUDIT_ELASTICSEARCH_URL=none` to use
Filebeat instead, which makes the rest of these irrelevant):

| Variable | Default | |
|---|---|---|
| `AUDIT_ELASTICSEARCH_USERNAME` / `_PASSWORD` | — | Basic auth |
| `AUDIT_ELASTICSEARCH_API_KEY` | — | Base64 `id:api_key`, instead of the above |
| `AUDIT_ELASTICSEARCH_VERIFY_CERTS` | `true` | `false` for a self-signed cluster |
| `AUDIT_ELASTICSEARCH_SETUP` | `true` | Install the template and ILM policy on start |
| `AUDIT_RETENTION_DAYS` | **`never`** | Nothing is ever deleted. Set a number of days to opt in |
| `AUDIT_ROLLOVER_MAX_AGE` | `7d` | New index every `1d` / `7d` / `30d`, or `never` for size-only |
| `AUDIT_ROLLOVER_MAX_SIZE` | `50gb` | ...or sooner, at this size |

Partitioning, the four shapes people actually want:

```bash
# daily indices, never deleted  — the usual choice for a compliance audit trail
AUDIT_ROLLOVER_MAX_AGE=1d
# AUDIT_RETENTION_DAYS is already never; shown here only to be explicit
AUDIT_RETENTION_DAYS=never

# weekly indices, kept 7 years
AUDIT_ROLLOVER_MAX_AGE=7d
AUDIT_RETENTION_DAYS=2555

# roll by size only, never deleted — for wildly uneven traffic
AUDIT_ROLLOVER_MAX_AGE=never
AUDIT_ROLLOVER_MAX_SIZE=20gb
AUDIT_RETENTION_DAYS=never
```

**Nothing is deleted by default.** The shipped ILM policy has no delete phase
at all — `hot`, `warm`, `cold`, and there it stops. An audit trail that erases
its own evidence on a timer is the one failure here you cannot undo, and a
disk bill is the recoverable problem, so the default errs towards keeping.

Set `AUDIT_RETENTION_DAYS` to a number and the shipper adds a delete phase
back. `never` (or `0`, or empty) is the explicit spelling of the default. Both rollover triggers cannot be off at once &mdash; a single backing
index would grow until Lucene's 2.1&nbsp;billion document limit stops writes,
long past the point where reindexing is comfortable.
| `AUDIT_SHIP_INTERVAL_SECONDS` | `2.0` | How often the shipper checks for new records |
| `AUDIT_SHIP_BATCH_SIZE` | `500` | Documents per bulk request |

**The semantic layer (0.2):**

| Variable | Default | |
|---|---|---|
| `AUDIT_SEMANTIC_ENABLED` | `true` | `false` writes exactly the 0.1 document: no `message`, no `event.id` |
| `AUDIT_CATALOG_FILE` | — | Level 2 descriptions, `.json` (`.yaml` needs PyYAML installed) |
| `AUDIT_LABELS_FILE` | built-in Uzbek table | Overlay for derived sentences and field labels |
| `AUDIT_LANG` | `uz` | Language of `message`; a missing template falls back to `uz` |
| `AUDIT_DERIVED_RISK_FLOOR` | `normal` | Lowest `audit.risk` an undescribed route gets: `low` / `normal` / `high` / `critical` |
| `AUDIT_TRUSTED_PROXIES` | — | CIDRs / IPs of your ingress, comma-separated. Only for these peers is `X-Forwarded-For` / `X-Real-IP` believed. A bad entry stops startup |
| `AUDIT_INTEGRITY_ENABLED` | `false` | Per-process sha256 hash chain in `audit.integrity.*`; check with `check verify-chain` |
| `AUDIT_ENRICH_TIMEOUT_MS` | `200` | Per-lookup timeout of the background enricher (the function itself is set in code: `enricher=`) |
| `AUDIT_ENRICH_CACHE_SECONDS` | `60` | Enricher result cache; `0` turns it off |
| `AUDIT_MAX_CLOCK_SKEW_S` | `300` | Past this, the shipper tags a record `clock_skew` and writes `audit.clock_skew_ms` |
| `AUDIT_SCHEMA_UPGRADE` | `false` | Let the shipper replace an index template of a different schema version (FR-48). Set it once, on one service |

A bad catalog or labels file stops the app at startup, not at the first request.

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
| `AUDIT_NAMESPACE` | `AUDIT_ENVIRONMENT` | Third part of the index name |
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

## 0.2 — describing endpoints

With the semantic layer on (the default), every record gets an event code,
a category, a risk level, a target and a finished Uzbek sentence in
`message`. The full field list is `docs/schema.md` §5.

Each endpoint is described at one of three levels. The first match wins, so
no record is ever "unknown":

| Level | How | `audit.level` |
|---|---|---|
| 1. Decorator | `@audited(...)` on the handler — **the recommended way** | `decorator` |
| 2. Catalog | an entry in `AUDIT_CATALOG_FILE`, keyed by method + route | `catalog` |
| 3. Derived | built from the route when nothing else describes it | `derived` |

### 1. The decorator

```python
from audit_logging import audited, Target

@router.post("/{user_id}")
@audited(
    "admin.user.updated",
    uz="{actor} «{target}» foydalanuvchisini tahrirladi",
    target=Target("user", id="path.user_id"),
    category="admin", risk="high", sensitivity="internal",
)
async def update_user(user_id: int, ...): ...
```

- Put `@audited` **under** the router decorator. It does not wrap the
  function; it attaches the definition and returns the same function, so
  FastAPI's dependencies and OpenAPI are unchanged.
- It is checked when the module is imported. A bad code, category or
  placeholder raises `ValueError` then, not at request time.
- Code: `<domain>.<object>.<verb>`, snake_case (`admin.user.updated`).
- `category`: `auth read search write export analysis navigation admin system`.
  `risk`: `low normal high critical`. `sensitivity`: `public internal
  confidential secret` (default `internal`).
- Placeholders: `{actor}`, `{target}`, `{count}`, `{service}`, `{object}`,
  `{detail.<key>}`. A missing value renders as «noma'lum»; the stored
  sentence never contains a brace.
- `ru=` / `en=` templates are optional. `uz=` is required.
- `Target("user", id="path.user_id")` reads the id from the path. `query.<name>`
  and `detail.<key>` also work, or leave `id` out and set it in the handler.

### 2. The catalog

Describe routes without editing handlers — useful for a first pass over a big
service:

```json
[
  {"route": "DELETE /users/{user_id}", "code": "admin.user.deleted",
   "uz": "{actor} «{target}» foydalanuvchisini o'chirdi",
   "category": "admin", "risk": "critical",
   "target": {"type": "user", "id": "path.user_id"}}
]
```

`route` is `"<METHOD> <route template>"`, with the template written exactly as
the route declares it. Optional keys: `ru`, `en`, `sensitivity`, `diff`,
`description`. Any other key, or a duplicate route, is an error. Set
`AUDIT_CATALOG_FILE=/app/audit_catalog.json`. For YAML, install PyYAML
yourself; the package does not depend on it.

### 3. Derived

A route nobody described still gets a readable record, flagged
`audit.derived: true`:

| Route | Code | Sentence |
|---|---|---|
| `GET /api/v1/departments` | `users_adminka.department.listed` | `{actor} bo'limlar ro'yxatini ko'rdi` |
| `DELETE /users/{user_id}` | `users_adminka.user.deleted` | `{actor} foydalanuvchini o'chirdi` |
| `POST /users/{user_id}/block` | `users_adminka.user.blocked` | `{actor} foydalanuvchini blokladi` |
| `GET /stats/export` | `users_adminka.statistics.exported` | `{actor} statistikani eksport qildi` |

The domain is `AUDIT_SERVICE_NAME`. The words come from a built-in Uzbek table
of 61 objects and 23 verbs, with Russian and English tables covering the same
words (`AUDIT_LANG=ru` / `en`; a decorator's `ru=` / `en=` template wins). Add your own nouns, verbs and field labels with
`AUDIT_LABELS_FILE` (a JSON object with `objects`, `verbs` and `fields`). The
route's `summary=` or docstring goes into `audit.description`. It is never used
as the sentence, because docstrings are developer notes.

Derived is a safety net, not a goal. `check coverage` (below) tells you which
routes are still derived, and `audit_derived_total` counts them at runtime.

### Adding what only the handler knows — the `audit` facade

```python
from audit_logging import audit

async def update_user(user_id: int, body: UserUpdate, session: SessionDep):
    db_user = crud.get_user(session, user_id)
    audit.target(label=db_user.full_name)            # the name for «{target}»
    before = {"role_id": db_user.role.name}
    ...update...
    audit.diff(before, {"role_id": db_user.role.name}, labels={"role_id": "Rol"})
    audit.detail(permissions_added=[12])
    audit.count(len(rows))                          # for {count}
    audit.code("admin.user.password_reset")         # override the described code
```

- Works in `async def` and plain `def` handlers.
- Outside a request, every call does nothing. No call ever raises into your
  handler.
- The package does **no** database lookup of its own. If you want a name in the
  sentence, the handler passes it — or you register an optional background
  enricher (below).
- `diff` stores changed keys only, and appends `— Rol: Operator → Admin` to the
  sentence. `detail`, `before` and `after` are redacted with the same denylist
  as request bodies. Past 16 KiB or 256 keys they are stored as
  `{"_truncated": true}`.
- Only writes made while the request is being handled are guaranteed to be in
  the record.

**Who or what was looked up — `audit.identify` and `audit.query`:**

```python
audit.identify(pinpp="3210 1801 2345 67", msisdn="90 123 45 67")
# -> audit.target.pinpp "32101801234567", audit.target.msisdn "+998901234567"

audit.query([("region", "=", "Toshkent"), ("age", "between", [18, 30])],
            labels={"region": "Viloyat", "age": "Yosh"},
            datasource="clickhouse", tables=["persons"])
# -> audit.query.normalized (nested, one entry per clause),
#    audit.query.text "Viloyat = Toshkent VA Yosh 18..30", .datasource, .tables, .clause_count
```

- Identifiers are stored in canonical form only: `pinpp` (14 digits),
  `msisdn` (E.164; Uzbek forms become `+998…`), `passport` (`AA1234567`),
  `imei` (15 digits, Luhn-checked). A value that does not normalise is dropped
  and its kind listed in `audit.detail.rejected_identifiers`. They are **not
  redacted** (`docs/redaction.md` §4.13).
- A target whose type is an identifier kind (`TargetSpec(type="pinpp", ...)`,
  or an id written `path.pinpp`) is promoted to `audit.target.<kind>` as well.
- `query` accepts tuples `(field, op, value[, logic[, group]])`, dicts or
  `QueryClause`; operators like `=`, `>=`, `like`, `in`, `not in` are mapped to
  one vocabulary. At most 100 clauses, values ≤ 256 characters. A clause on a
  redact-key field stores `[REDACTED]`. A `text=` you pass is stored as given.

**Optional: a background enricher.** For labels only a database knows, register
a sync function; it runs in the file writer thread, never on the request path:

```python
def lookup(doc: dict) -> dict | None:
    t = doc.get("audit", {}).get("target", {})
    return {"audit.target.label": names.get(t.get("id"))} if t.get("type") == "user" else None

AuditConfig(service_name="users-adminka", enricher=lookup)
```

It may patch only `audit.target.label`, `audit.detail`, `user.full_name` and
`user.department`. A lookup slower than `AUDIT_ENRICH_TIMEOUT_MS` leaves the
record unchanged and tagged `enrich_timeout`. It works only when the middleware
builds its own `FileSink` (no `sink=` passed).

### Who did it

The actor in the sentence comes from your `user_resolver` (see *Attaching the
user*). In 0.2 it may also return `full_name` (preferred in the sentence),
`department`, `verified` (bool) and `source`:

```python
return {"id": u.id, "name": u.login, "full_name": u.full_name, "roles": [u.role],
        "verified": True, "source": "jwt"}
```

Return `verified: True` only for claims your auth layer actually checked. Leave
it out and the record has no `user.verified` at all.

### Denied and failed requests

`audit.result` is `denied` for 401/403, `failure` for other 4xx/5xx or an
exception, `disconnected` when the client left, otherwise `success`. The
sentence gets ` — rad etildi`, ` — xato` or ` — uzildi` on the end.
`event.outcome` keeps its 0.1 meaning, so old dashboards still work.

### Actions that are not HTTP requests — `emit`

```python
from audit_logging import audit
from audit_logging.semantic import audited_task

audit.emit("billing.invoice.sent", uz="{actor} «{target}» hisobini yubordi",
           category="write", target={"type": "invoice", "id": "42", "label": "INV-42"},
           actor={"id": "system", "name": "scheduler"}, detail={"amount": 100})

@audited_task("ownercheck.number.scored", uz="{service} raqamni baholadi")
async def score(number: str) -> None:
    audit.target(id=number, type="number")          # works inside the task too
    ...
```

- These records go to the same file and index, with the same schema, and
  `audit.level: "emit"`. They have no `http.*` or `url.*`.
- `@audited_task` writes one record when the function finishes: `success`, or
  `failure` with `error.type` if it raised. The exception is still re-raised.
- They need a running `AuditMiddleware` in the same process. Before startup or
  after shutdown, `emit` returns `False` and counts the drop
  (`audit_emit_dropped_total`, or `semantic.emit.dropped_without_sink` before
  any middleware started). A worker process with no HTTP app has nowhere to
  write yet.

### Browser actions — `ui_router`

```python
from audit_logging.semantic import ui_router

app.include_router(ui_router(actor_resolver=lambda request: request.state.user_claims))
```

The browser POSTs `{"events": [{"code": "ui.page.viewed", "uz": "{actor} hisobotlar sahifasini ochdi"}]}`
to `/audit/ui-events` (change it with `prefix=`) and gets `202` with
`{"received": n, "accepted": m}`.

- Only `ui.*` codes are accepted. The limit is 100 events per call.
- `category` must be `navigation`, `read`, `search` or `export`. Risk is always
  `low`.
- The actor comes **only** from your `actor_resolver(request)`. Anything the
  body says about the user is ignored.
- Mount it on your service's own backend, behind your normal auth. It needs
  FastAPI.

### Is every endpoint described? — `check coverage` / `check docs`

```bash
python -m audit_logging.check coverage main:app --max-derived 0
#  42 routes · 30 decorator · 10 catalog · 2 derived (4.8 %)
#    DERIVED  GET /stats/export  -> add @audited(...) or a catalog entry
#    ORPHAN   catalog: POST /old  -> no such route
#  FAIL  derived 4.8 % > --max-derived 0 %

python -m audit_logging.check docs main:app > AUDIT_EVENTS.md   # method | route | level | code | … | uz
```

- `coverage` exits non-zero when derived routes are over `--max-derived`
  (default 0 %). Put it in CI.
- It reads `AUDIT_CATALOG_FILE`, or `--catalog FILE`.
- Routes hidden from OpenAPI (`include_in_schema=False`) are listed as
  `HIDDEN` and not counted: they are still recorded.
- `docs` prints a Markdown table of every endpoint for security review. It is
  also a good first draft of a catalog.

### Testing your descriptions

```python
from audit_logging.testing import capture

def test_invoice_is_audited():
    with capture() as rec:
        send_invoice(42)
    assert rec.last["event"]["action"] == "billing.invoice.sent"
    assert "{" not in rec.last["message"]
```

`capture()` only collects what goes through `audit.emit()` and
`@audited_task`. It replaces the active sink for the duration. `rec.records` is
every document; `rec.last` is the last one, as a `dict`. To test HTTP records,
pass `NullSink()` as the middleware's `sink=` and read `sink.submitted`.

### Delivery guarantees added in 0.2

- **No duplicates.** Every document has `event.id`, which the shipper sends as
  the Elasticsearch `_id`. A replay, such as an adopted orphan file or a lost
  offset file, is answered `409` and counted as delivered.
- **No silent loss.** A document Elasticsearch refuses, for example because of
  a mapping conflict, is logged once per error kind (WARN, with the ES error),
  counted in `audit_ship_rejected_total` and `audit_documents_lost_total`, and
  skipped (X-8: there is no dead-letter file). The line stays in the JSONL
  file on disk, so `check reconcile` reports that process as missing it.
- **One loss counter.** `audit_documents_lost_total` sums every drop path:
  ES refusals, sink queue overflow (`audit_documents_dropped_total`), write
  failures (`audit_documents_failed_total`), drops after close
  (`audit_documents_dropped_after_close_total`), and `audit.emit()` records
  that never reached a sink. Alert on this one.
- **`event.ingested`** is set when the shipper sends a record. When it is more
  than `AUDIT_MAX_CLOCK_SKEW_S` (300 s) away from `@timestamp`, the record gets
  `tags: ["clock_skew"]` and the signed difference in `audit.clock_skew_ms`.
  `@timestamp` is never rewritten.
- **One schema per dataset (FR-48).** The template carries
  `_meta.schema_version`. The shipper will not overwrite a template of another
  version: it logs one ERROR and ships nothing until you set
  `AUDIT_SCHEMA_UPGRADE=true`. `check version` shows both versions.
- **Session and trace.** `X-Session-Id` → `audit.session.id`; a valid
  `X-Trace-Id` → `trace.id` (the `X-Request-ID` header is unchanged).
- **Client IP through trusted proxies.** Set `AUDIT_TRUSTED_PROXIES`; the
  record says where `client.ip` came from in `audit.client.ip_source`
  (`x_forwarded_for`, `x_real_ip` or `peer`).
- **Tamper evidence (optional).** `AUDIT_INTEGRITY_ENABLED=true` chains every
  record of a process by sha256 (`docs/schema.md` §5.6).
- **Shutdown warning.** If a native import (aspose, a JVM bridge) replaced the
  `SIGTERM` handler, a WARNING at startup says so: the last batch would be lost
  on `docker stop` (`docs/runbook.md` §16.4).
- **Trusted proxies and uvicorn.** uvicorn rewrites the peer address from
  `X-Forwarded-For` itself by default (`--proxy-headers`, trusting
  `--forwarded-allow-ips`, 127.0.0.1 by default) before the middleware runs.
  The record then says `audit.client.ip_source: peer` with no
  `forwarded_chain`, and `AUDIT_TRUSTED_PROXIES` is bypassed. To let this
  package decide, run uvicorn with `--no-proxy-headers` (gunicorn's uvicorn
  worker: `forwarded_allow_ips=""`).
- **`check verify-chain`** anchors each chain at its oldest surviving record,
  so rotated or ILM-deleted history is reported as `TRUNCATED`, not as a
  break. `--require-genesis` makes a missing seq 1 a failure.

### Not built yet

- Detecting deletion of the **newest** records of a hash chain (nothing points
  back at them); `check reconcile` is the other signal.
- A viewer. Records are read from Elasticsearch directly (PLAN §11).
- The optional shared vocabulary package (PLAN §4.5).

Status per requirement: `docs/REQUIREMENTS.md` §1.5.

---

## Check it's working

```bash
python -m audit_logging.check
python -m audit_logging.check --leak "a-real-secret"
```

It reads the same `AUDIT_*` environment your app uses, so it checks what you
actually deployed (`coverage` and `docs` are separate sub-commands, above).
With the built-in shipper, three more:

```bash
python -m audit_logging.check reconcile      # lines on disk vs indexed, per process; exit 1 if any are missing
python -m audit_logging.check version        # installed template schema_version vs this package
python -m audit_logging.check verify-chain   # the integrity hash chains (--from-files reads the JSONL)
```

The default run prints:

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
| Files growing, nothing in Elasticsearch | The shipper cannot reach the cluster (look for its WARN line), or, with `AUDIT_ELASTICSEARCH_URL=none`, Filebeat is down — check its logs and `curl :5066/stats` |
| `audit_documents_dropped_total` rising | Disk isn't keeping up |
| `audit_bodies_skipped_total` rising | Bodies hitting the size caps — normal on bulk routes |
| `audit_derived_total` rising | Routes nobody described — run `check coverage` |
| `audit_semantic_errors_total` rising | Enrichment failed; the 0.1 document was written instead |
| `audit_ship_rejected_total` rising | Elasticsearch is refusing documents (mapping conflict, say) — the shipper's WARN line has the ES error; those records are skipped, not retried |
| `audit_documents_lost_total` rising | Records gone for good, from any drop path — see the counters above to find which |
| Shipper log: `schema_version ... NOT shipping` | The dataset's template is another schema version — `check version`, then `AUDIT_SCHEMA_UPGRADE` (runbook §16.2) |
| Startup log: `SIGTERM is not handled by Python` | A native import took the signal; the last batch is lost on shutdown (runbook §16.4) |
| Records tagged `clock_skew` / `enrich_timeout` | A shipping backlog or a wrong clock / a slow enricher lookup (runbook §16.3, §16.6) |
| Need it off right now | `AUDIT_ENABLED=false` and restart |

---

## What it costs

Measured, not estimated (`pytest tests/load -m load`):

* **+0.82 ms** added p99, against a 5 ms budget
* ~30 µs per request in the middleware
* ~1.2 KB per record
* 51 Elasticsearch fields — a dynamic mapping would create 20,194

Those are 0.1 numbers. The 0.2 semantic layer (NFR-8,
`tests/load/test_semantic_latency.py`, 5 000 requests per arm) adds **p50
+0.09 ms, p99 +0.19 ms** on a decorated route with `audit.target()` and
`audit.diff()` (a second run: p99 +0.25 ms), under the +0.3 ms target. The v2
template has 126 mapping entries of the 200 limit.

## Licence

MIT — see [LICENSE](LICENSE).
