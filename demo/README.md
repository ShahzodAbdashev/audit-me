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
