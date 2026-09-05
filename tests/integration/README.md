# `tests/integration/` — the two acceptance tiers

AC-01 … AC-26 are defined in `docs/REQUIREMENTS.md` §2 (AC-18 … AC-26 were
added by §2.1 after the adversarial review). They are implemented
**twice**, with the same numbering and the same Given/When/Then, so that the
question "is AC-07 satisfied?" has an answer whether or not you have Docker.

| | Tier 2 — `test_acceptance_local.py` | Tier 1 — `test_acceptance_es.py` |
|---|---|---|
| Needs | nothing | Docker + `docker-compose.test.yml` |
| Asserts against | the real JSONL on disk, validated by the real index template | real Elasticsearch |
| Covers | middleware, redaction, FileSink, rotation, the mapping bound | all of that **plus** Filebeat, data-stream routing, ILM, and Elasticsearch's own field counting |
| Marker | none — runs by default | `@pytest.mark.integration` |
| Status | **passing** | **never executed** — see below |

> ### Tier 1 has not been run
>
> The Docker daemon was unreachable from the environment these tests were
> written in (`docker ps` → `permission denied … /var/run/docker.sock`; the
> user is not in the `docker` group and `sudo` requires a password). Every
> Tier 1 test is written to run and none of them has. The first green run is
> new information — budget time for it. `tests/AC-matrix.md` marks every
> affected AC.

---

## Tier 2 — run it now

```bash
./.venv/bin/python -m pytest tests/integration -q -m "not integration"
```

No stack, no network, no Docker. It exercises a FastAPI app through the real
`AuditMiddleware`, the real `redact.py` and a real `FileSink` writing real
files, then pushes every line through `_es_double.InProcessElasticsearch` —
which parses `infra/elasticsearch/template-apiaudit.json` and applies its
rules:

* `dynamic: false`, at the root **and** in every nested object. A field the
  template does not declare raises `UnmappedFieldError`. Real Elasticsearch
  accepts such a field silently and simply never indexes it, so the double is
  deliberately *stricter* than the thing it stands in for: a document that
  indexes cleanly here is a document that is wholly searchable in production.
* `flattened` collapsing an arbitrary object into one mapping field. This is
  what makes AC-10's bound decidable here rather than deferred.
* `total_fields.limit: 200` and `depth_limit`, read from the template's own
  settings.
* `constant_keyword` pins (`data_stream.type: "logs"`, `event.kind: "event"`).

`ignore_malformed: true` means a wrong-typed value is not a rejection in
Elasticsearch, just a silently unindexed field — the double collects those in
`malformed` and the tests assert it is empty, which is the only way to notice.

---

## Tier 1 — the real stack

### 1. Bring it up

```bash
cd /home/shahzod/mywork/audit_logger

export AUDIT_TEST_LOG_DIR="$PWD/tests/integration/.stack/logs"
mkdir -p "$AUDIT_TEST_LOG_DIR"

docker compose -f tests/integration/docker-compose.test.yml up -d
docker compose -f tests/integration/docker-compose.test.yml ps
```

Wait for both services to report healthy — Elasticsearch takes 30–60 s on a
cold start:

```bash
curl -sS 'http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=60s' | jq .
curl -sS localhost:5066/stats | jq '.libbeat.output.events'
```

**Yellow is correct and permanent.** The index template asks for one replica
and this is a one-node cluster, so every index is yellow forever. Nothing waits
for green.

### 2. Run the tier

```bash
./.venv/bin/python -m pytest tests/integration -q -m integration
```

The test session installs A5's ILM policy and index template itself, from
`infra/elasticsearch/*.json`, **before** any test writes a line — plan §10 /
D-11 / R-1: a data stream created before its template exists gets a dynamic
mapping and the only fix is a reindex. It then runs A5's own
`_simulate_index` check to confirm what a new index would actually get.

If you would rather exercise `bootstrap.py` (which does this properly, with a
diff and a `dynamic:false` guard), its `ES_URL` is a literal in the CONFIG
block with no environment override, so point it at the test stack by hand:

```python
# infra/elasticsearch/bootstrap.py — CONFIG block
ES_URL = "http://localhost:9200"
ES_PASSWORD = ""            # security is disabled in the test stack
ES_CA_BUNDLE: str | bool = False
```

```bash
./.venv/bin/python infra/elasticsearch/bootstrap.py     # run it twice: the
./.venv/bin/python infra/elasticsearch/bootstrap.py     # second says "unchanged"
```

Then revert those three lines. **Do not commit them.**

### 3. Tear it down

```bash
docker compose -f tests/integration/docker-compose.test.yml down -v
rm -rf tests/integration/.stack
```

`down -v` also drops the Filebeat registry volume. Leaving the registry but
deleting `.stack/logs` (or the other way round) is the one combination that
produces confusing results on the next run — do both or neither.

---

## Environment variables

| Variable | Default | What it is |
|---|---|---|
| `AUDIT_TEST_ES_URL` | `http://127.0.0.1:9200` | Where Elasticsearch is. Anything else skips the tier with a message saying so. |
| `AUDIT_TEST_LOG_DIR` | `tests/integration/.stack/logs` | The directory the tests write JSONL into, bind-mounted to `/var/log/audit/testpod`. Must match what compose mounts. |
| `AUDIT_TEST_SHIP_TIMEOUT` | `120` | Seconds to wait for a document to reach Elasticsearch. Raise it on a slow machine. |

Every wait in the tier **polls for the document it wants** (by `trace.id`,
which FR-23 lets the test set through `X-Request-ID`). Nothing sleeps for a
guessed interval. That is the single thing keeping this tier off plan R-9's
flakiness list — if you add a test here, poll; do not sleep.

---

## What the compose file changes, and why

`infra/filebeat/filebeat.yml` is mounted **verbatim**: it is the artefact under
test and rewriting it would defeat the purpose. Four settings are overridden
with `-E` flags on the command line instead, and each is a property of the test
stack rather than of the shipper:

| Override | Why |
|---|---|
| `output.elasticsearch.ssl.enabled=false`, `ssl.verification_mode=none` | The stack speaks plain HTTP, so there is nothing to verify. `ssl.certificate_authorities` is *not* overridden: Filebeat validates that path when it loads the config, before it notices TLS is disabled, so `tests/integration/stack/ca.crt` — a throwaway self-signed certificate with no private key anywhere — is mounted at the path `filebeat.yml` names. It verifies nothing. |
| `output.elasticsearch.username=`, `password=` | `xpack.security.enabled=false`, so sending basic auth is a 401. |
| `queue.disk.max_size=200MB`, `segment_size=64MB` | 2200 MB is sized for a six-hour production outage at 50 rps (plan §5); a test run cannot be asked to reserve that. `segment_size` was 10MB and had to move: A5 raised `message_max_bytes` to 8 MiB, and Filebeat's disk queue silently drops any event over `segment_size - header` with only a `Warnf`. The invariants are `segment_size >= 2 x message_max_bytes` and `max_size >= 2 x segment_size`; `test_AC_20_the_acceptance_stacks_disk_queue_can_hold_that_line` re-derives both from these two files. |

Elasticsearch runs with `ES_JAVA_OPTS=-Xms512m -Xmx512m` and `mem_limit: 1500m`
because the machine this was written on had ~3 GB free; an 8.x default heap is
half of host RAM and would have been OOM-killed. It also runs with
`cluster.routing.allocation.disk.threshold_enabled=false`, because a laptop
`/var` over the 85 % watermark turns into a read-only index block, which is a
baffling way to fail an acceptance test.

---

## When a document does not arrive

In this order.

```bash
# 1. Did the app write it at all?
ls -la "$AUDIT_TEST_LOG_DIR"
tail -1 "$AUDIT_TEST_LOG_DIR"/*.jsonl | jq '{trace: .trace.id, ds: .data_stream}'

# 2. Can Filebeat see the file? (glob is /var/log/audit/*/*.jsonl — one
#    directory level is mandatory, files directly in /var/log/audit are missed)
docker compose -f tests/integration/docker-compose.test.yml exec filebeat \
    ls -la /var/log/audit/testpod/

# 3. Is Filebeat harvesting and publishing?
curl -sS localhost:5066/stats |
  jq '{harvesters: .filebeat.harvester, published: .libbeat.output.events}'
docker compose -f tests/integration/docker-compose.test.yml logs --tail=50 filebeat

# 4. Did Elasticsearch reject the write?
curl -sS 'localhost:9200/_nodes/stats/indices/indexing' |
  jq '.nodes[].indices.indexing.index_failed'

# 5. Is the data stream on the right template? Anything other than
#    "logs-apiaudit" means it was created before step 1 and its backing
#    indices carry a dynamic mapping. The fix is a reindex.
curl -sS 'localhost:9200/_data_stream/logs-apiaudit.*-*' |
  jq '.data_streams[] | {name, template, generation}'

# 6. The field bound (AC-10):
curl -sS 'localhost:9200/logs-apiaudit.*-*/_field_caps?fields=*' | jq '.fields | length'
```

Known shapes of failure:

* **`libbeat.output.events.failed` climbing.** Elasticsearch is rejecting the
  bulk. Almost always a mapping problem; check `index_failed` above.
* **`harvester.open_files: 0`.** Filebeat is not seeing the files. Either
  `AUDIT_TEST_LOG_DIR` does not match the compose bind mount, or the files
  landed directly in `/var/log/audit` instead of one level down.
* **Documents arrive with an `@timestamp` of "now".** `overwrite_keys: true`
  is not in effect, so Filebeat's own timestamp won. Every latency query is
  then wrong; `test_AC_01_one_document_per_request` is the tripwire.
* **Nothing at all, no errors.** Check `queue.disk` is not full and that the
  registry volume is not remembering a previous run's offsets —
  `down -v` and start again.

---

## Layout

| File | What it is |
|---|---|
| `test_acceptance_local.py` | Tier 2, 60 tests. AC-01 … AC-26 plus tests of the double itself, including the M-5 and N-9 rejection models. |
| `test_acceptance_es.py` | Tier 1, 31 tests, never executed. AC-01 … AC-17 plus AC-18, AC-20 and AC-21 against Elasticsearch — the three whose point is a cluster/shipper behaviour. |
| `_es_double.py` | The template-enforcing in-process Elasticsearch. |
| `_apps.py` | The application under audit, shared by both tiers. |
| `conftest.py` | The `Audited` harness: middleware + real FileSink + temp log dir. |
| `docker-compose.test.yml` | Elasticsearch 8.13.4 + Filebeat 8.13.4. |
| `stack/ca.crt` | A throwaway self-signed certificate, mounted only so Filebeat's config loads. No private key exists; it verifies nothing; it is not a credential. |
| `.stack/logs/` | Created at run time. The bind-mounted directory Filebeat watches. Not committed. |
