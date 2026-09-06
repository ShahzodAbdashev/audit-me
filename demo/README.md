# End-to-end demo

A real FastAPI service, a real uvicorn socket, a real Elasticsearch, and
assertions against what actually lands in the index.

```bash
./demo/run_e2e.sh          # full run, tears the stack down afterwards
./demo/run_e2e.sh --keep   # leave Elasticsearch up to poke at
```

## What it does

1. **Preflight** — checks the Docker daemon is reachable and says exactly how
   to fix it if not.
2. **Starts Elasticsearch 8.13.4 + Filebeat** from
   `tests/integration/docker-compose.test.yml` (512 MB heap, single node).
3. **Installs the ILM policy and index template *before* any document is
   written.** This ordering is not cosmetic: a data stream created before its
   template gets a dynamic mapping and cannot be fixed without a reindex
   (D-11, plan §10).
4. **Runs `demo/app.py` under uvicorn** on a real port.
5. **Sends 13 request shapes** — secrets in body/query/headers, a 404, a 204,
   an unrouted path, a raising handler, a streaming response, a secret in a
   named path parameter, a `text/plain` body, broken JSON, 4,000 distinct keys,
   and a 1 MiB pathological body.
6. **Verifies the JSONL on disk first**, then waits for it to reach ES and
   **verifies again against Elasticsearch**. Splitting the two means a failure
   tells you *which half* broke: the package, or the shipper.
7. **Runs the Tier 1 acceptance suite** (AC-01…AC-26) against the live cluster.

## Why the disk check comes first

The package writing correct JSONL is already covered by 597 offline tests. What
is unproven is everything *after* the file — Filebeat's ndjson decode,
`data_stream` routing, and Elasticsearch actually enforcing `dynamic: false`.
If the disk check passes and the ES check fails, the package is fine and the
pipeline is not. That distinction is the entire reason this script exists.

## Running the halves separately

```bash
# just the service
AUDIT_LOG_DIR=/tmp/audit-demo ./.venv/bin/python -m uvicorn demo.app:app --port 8080

# traffic, then check the file — no Elasticsearch needed
./.venv/bin/python demo/traffic.py send
./.venv/bin/python demo/traffic.py verify --from-file /tmp/audit-demo

# check Elasticsearch instead
./.venv/bin/python demo/traffic.py verify
```

## Two checks that assert a *limitation*

`verify` asserts that secrets are absent from every redacted field, and then
asserts that two documented leaks **are still present**:

| check | why |
|---|---|
| `url.path` still carries a path secret | `docs/redaction.md` §4.5 — it is an indexed keyword, so a secret in a URL is searchable |
| a parse-failure `body_raw` is unredacted | AC-14 / review S-2 — the raw text must be kept, and a client selects this path by sending broken JSON |

They are asserted positively so that if either limitation is ever fixed, the
check fails and tells you to update the documentation. A limitation that
silently stops being true makes the docs a lie in the other direction.

---

## Seeing the results

Bring the stack up and leave it running:

```bash
sg docker -c "./demo/run_e2e.sh --keep"      # or just ./demo/run_e2e.sh after re-login
```

Then look at what landed. `demo/query.py` wraps the queries you actually want:

```bash
./.venv/bin/python demo/query.py             # cluster health + documents per service
./.venv/bin/python demo/query.py recent 10   # last 10 requests, one line each
./.venv/bin/python demo/query.py doc         # the full JSON of the most recent record
./.venv/bin/python demo/query.py errors      # only failures, with error.type
./.venv/bin/python demo/query.py slow 100    # anything over 100 ms
./.venv/bin/python demo/query.py routes      # count + p95 latency, by route template
./.venv/bin/python demo/query.py trace <id>  # one request by its X-Request-ID
./.venv/bin/python demo/query.py leaks hunter2   # search every field for a string
./.venv/bin/python demo/query.py mapping     # prove dynamic:false is in force
```

`ES_URL` points it at a different cluster.

### The three checks that tell you it is really working

Documents arriving is necessary but not sufficient. These three are the ones
that distinguish a working pipeline from one that only looks like it:

| check | what a bad answer means |
|---|---|
| `query.py mapping` says `dynamic : 'false'` | If it says `None`, the index template did not apply and the data stream was auto-created with a dynamic mapping. It will keep working and keep indexing until the field count explodes, and it is only fixable by a reindex (D-11). |
| `query.py leaks <a real secret>` returns 0 | Redaction is per-field. A hit in `url.path` or in a parse-failure `body_raw` is *documented* (docs/redaction.md §4.5, AC-14); a hit anywhere else is a live leak. |
| `query.py routes` shows route **templates** | If you see `/orders/42` instead of `/orders/{order_id}`, route resolution is failing and every distinct id is its own bucket. |

### Raw curl, if you prefer

```bash
curl -s localhost:9200/_cluster/health?pretty
curl -s 'localhost:9200/_cat/indices/logs-apiaudit*?v&h=index,docs.count,store.size'
curl -s 'localhost:9200/logs-apiaudit.*-*/_search?pretty&size=1&sort=@timestamp:desc'
```

### Is Filebeat keeping up?

```bash
curl -s localhost:5066/stats | ./.venv/bin/python -m json.tool | grep -A6 '"output"'
```

`events.acked` should track what the package wrote; `dropped` and `failed`
should be `0`. If `acked` stalls while the JSONL file keeps growing, the
shipper is the problem, not the package — check
`docker compose -f tests/integration/docker-compose.test.yml logs filebeat`.
