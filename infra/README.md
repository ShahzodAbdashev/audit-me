# `infra/` — shipping and storage for `audit_logging`

The package writes JSONL files and nothing else (NFR-4, D-13). Everything that
gets those lines into Elasticsearch and in front of a human lives here.

```
app pod  ──writes──▶  /var/log/audit/<pod>/<service>-<pid>.jsonl   (hostPath)
                                │
                          Filebeat DaemonSet  (filestream + ndjson, disk queue)
                                │  index: %{[data_stream.type]}-%{[data_stream.dataset]}-%{[data_stream.namespace]}
                                ▼
                      logs-apiaudit.<service>-<env>   data stream
                          mapped by  logs-apiaudit    index template  (dynamic:false, 200-field cap)
                          aged   by  apiaudit-ilm     ILM policy      (hot → warm → cold → delete)
                                ▼
                          Kibana: 3 dashboards
```

| File | What it is |
|---|---|
| `elasticsearch/template-apiaudit.json` | Data-stream index template for `logs-apiaudit.*-*`. The field bound (AC-10). |
| `elasticsearch/ilm-apiaudit.json` | ILM policy. **`_meta.RETENTION_DAYS` at the top is the only retention knob.** |
| `elasticsearch/bootstrap.py` | Installs and verifies both, idempotently. Config block at the top, no CLI args. |
| `filebeat/filebeat.yml` | The shipper. One file, used by both the DaemonSet and the sidecar variant. |
| `filebeat/daemonset.yaml` | DaemonSet + RBAC + Secret, **plus** the snippet application pods need, **plus** the commented sidecar variant. |
| `kibana/dashboards.ndjson` | Data view + 8 visualizations + 3 dashboards. |

Everything below works with **no internet access at apply time**.

---

## 0. Assumptions you must confirm before applying

Three of plan §12's open inputs are still unanswered. Each one is a default in
these files, chosen so it fails loudly rather than quietly:

| Open input | Default here | Where to change it |
|---|---|---|
| **I-2** ES / Filebeat / Kibana versions | Elasticsearch **8.x**, Filebeat **8.13.4** | `daemonset.yaml` image tag. 7.x needs template-syntax changes; < 7.3 has no `flattened` and this design does not work at all. |
| **I-3** is `hostPath` permitted in RKE2? | **Assumed yes** — DaemonSet is the default | `daemonset.yaml`; the sidecar variant at the bottom of that file is a drop-in if the answer is no. |
| **I-4** retention | **90 days**, discretionary | `elasticsearch/ilm-apiaudit.json` → `_meta.RETENTION_DAYS`. See §6 below. |

Also unanswered: **I-1**, real peak rps. The Filebeat disk queue is sized for
the **50 rps row** of plan §5 (2.2 GB for a 6-hour Elasticsearch outage). If
your real number is 200 rps, change it before you go live — see
`filebeat/filebeat.yml`, the table above `queue.disk`.

---

## 1. Air-gapped image import

Do this once per cluster, from a workstation that has both the images and a
route to the internal registry.

```bash
# On a connected machine
docker pull docker.elastic.co/beats/filebeat:8.13.4
docker save docker.elastic.co/beats/filebeat:8.13.4 -o filebeat-8.13.4.tar
sha256sum filebeat-8.13.4.tar > filebeat-8.13.4.tar.sha256

# Carry the tar across. On the air-gapped side:
sha256sum -c filebeat-8.13.4.tar.sha256
docker load -i filebeat-8.13.4.tar
docker tag docker.elastic.co/beats/filebeat:8.13.4 registry.internal/beats/filebeat:8.13.4
docker push registry.internal/beats/filebeat:8.13.4

# Record the digest and pin it in daemonset.yaml for production:
docker inspect --format='{{index .RepoDigests 0}}' registry.internal/beats/filebeat:8.13.4
```

RKE2 uses containerd, so if you are importing directly onto nodes instead of
through a registry:

```bash
sudo /var/lib/rancher/rke2/bin/ctr -a /run/k3s/containerd/containerd.sock \
     -n k8s.io images import filebeat-8.13.4.tar
```

`bootstrap.py` needs only `requests`, which is already in `./.venv`. Nothing
else in this directory downloads anything.

---

## 2. Apply order — this order, not another one

> **A data stream created before its index template exists gets a dynamic
> mapping, and there is no way to fix it without a reindex** (plan §10,
> D-11, R-1). Step 1 comes first. Always.

### Step 1 — Elasticsearch objects (ILM policy, then index template)

```bash
# Edit the CONFIG block at the top of bootstrap.py first: ES_URL, credentials,
# ES_CA_BUNDLE, COLD_TIER_EXISTS, DATA_STREAMS.
$EDITOR infra/elasticsearch/bootstrap.py

# Validate without touching the cluster (set DRY_RUN = True), then:
./.venv/bin/python infra/elasticsearch/bootstrap.py
```

It refuses to send anything unless the mapping is `dynamic: false` at the top
level *and* in every nested object, `total_fields.limit` is 200, `codec` is
`best_compression`, and `audit.request.body_raw` is `index:false` +
`doc_values:false` with no `ignore_above`. Then it PUTs, GETs everything back,
and prints a diff. Run it twice: the second run must print `unchanged`.

It never deletes and never reindexes. It is safe against a cluster that
already holds live audit data.

<details>
<summary>Without the script (curl only)</summary>

```bash
# The ILM API takes only the "policy" key; strip the _meta envelope.
jq '{policy}' infra/elasticsearch/ilm-apiaudit.json |
  curl -u "$ES_USER:$ES_PASS" --cacert ca.crt -sS -XPUT \
       "$ES_URL/_ilm/policy/apiaudit-ilm" -H 'Content-Type: application/json' -d @-

curl -u "$ES_USER:$ES_PASS" --cacert ca.crt -sS -XPUT \
     "$ES_URL/_index_template/logs-apiaudit" -H 'Content-Type: application/json' \
     -d @infra/elasticsearch/template-apiaudit.json
```

If you do this by hand you lose the `dynamic:false` guard and the retention
normalisation. Keep `policy.phases.delete.min_age` in sync with
`_meta.RETENTION_DAYS` yourself, and delete the `cold` phase if the cluster has
no `data_cold` nodes.
</details>

### Step 2 — Filebeat

```bash
kubectl apply -f infra/filebeat/daemonset.yaml

# The ConfigMap is generated from filebeat.yml, not inlined, so the two
# cannot drift. Re-run this whenever you edit filebeat.yml.
kubectl -n audit-logging create configmap filebeat-audit-config \
    --from-file=filebeat.yml=infra/filebeat/filebeat.yml \
    --dry-run=client -o yaml | kubectl apply -f -

# Real credentials (daemonset.yaml ships a REPLACE_ME placeholder):
kubectl -n audit-logging create secret generic filebeat-audit-es \
    --from-literal=ES_HOSTS=https://elasticsearch.internal:9200 \
    --from-literal=ES_USERNAME=filebeat_writer \
    --from-literal=ES_PASSWORD='...' \
    --dry-run=client -o yaml | kubectl apply -f -

# Cluster CA, if your ES uses TLS with a private CA (it should):
kubectl -n audit-logging create secret generic elasticsearch-ca --from-file=ca.crt

kubectl -n audit-logging rollout status ds/filebeat-audit
```

Create `filebeat_writer` before this step, exactly as §3 specifies. It is the
one credential in this system whose over-provisioning silently defeats the
design.

### Step 3 — Application pods

Add the volume, the `POD_NAME` downward-API env var, the `subPathExpr` mount
**and the `audit-log-dir` initContainer** from the commented block in
`filebeat/daemonset.yaml` ("THE OTHER HALF OF THE CONTRACT"). Without the
mount the app writes into the container filesystem, Filebeat sees nothing, and
the whole pipeline is silently empty.

> **The initContainer is not optional for a non-root application container.**
> The kubelet creates the `subPathExpr` directory as `root:root` mode 0755 and
> `fsGroup` is not applied to `hostPath` volumes, so a `runAsNonRoot` app gets
> `EACCES` when the sink opens its file — and the sink swallows that, logs it
> once and keeps running. You get a deployment that reports healthy and
> produces zero documents. Run §7's check after every first rollout of a
> service; it is the only evidence the write side works.

Budget the node disk: `file_max_bytes` 256 MB × `file_backup_count` 8 = **2 GB
per pod** (plan §5), multiplied by uvicorn workers, multiplied by audited pods
per node — and that is separate from the 2.2 GB Filebeat disk queue.

### Step 4 — Kibana

```bash
curl -u "$KB_USER:$KB_PASS" --cacert ca.crt -sS \
     -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
     -H "kbn-xsrf: true" \
     --form file=@infra/kibana/dashboards.ndjson
```

Expect `{"success":true,"successCount":12,...}`. Then open the data view once
and refresh its field list — the export ships `fields: "[]"` on purpose so it
does not carry a stale field list from whatever cluster it was made on.

Import this **after** step 1: the data view resolves against the mapping.

---

## 3. The `filebeat_writer` role — least privilege, and why

This is a hard requirement, not a hardening suggestion. `setup.template.enabled:
false` in `filebeat.yml` is a *request* Filebeat makes of itself; the only thing
that **enforces** it is this role. A Filebeat that holds
`manage_index_templates` can replace the `logs-apiaudit` template with its own
`dynamic: true` one on any restart, at which point the 200-field bound (AC-10)
is gone, every distinct request-body shape becomes a mapping entry, and the
first symptom is a cluster that will not index.

Create it before step 2:

```bash
ES() { curl -u "$ES_USER:$ES_PASS" --cacert ca.crt -sS "$@"; }

ES -XPUT "$ES_URL/_security/role/filebeat_writer" \
   -H 'Content-Type: application/json' -d '{
  "cluster": ["monitor"],
  "indices": [
    { "names": ["logs-apiaudit.*-*"],   "privileges": ["auto_configure", "create_doc"] },
    { "names": ["apiaudit-dead-letter*"], "privileges": ["auto_configure", "create_doc", "create_index"] }
  ]
}'

ES -XPUT "$ES_URL/_security/user/filebeat_writer" \
   -H 'Content-Type: application/json' -d '{"password":"...","roles":["filebeat_writer"]}'
```

| Privilege | Why it is there |
|---|---|
| `cluster: monitor` | Filebeat's connection/version probe. Read-only. |
| `auto_configure`, `create_doc` on `logs-apiaudit.*-*` | Write audit documents into the data streams. `create_doc` cannot overwrite an existing document — an audit record, once written, cannot be edited by the shipper. |
| `auto_configure`, `create_doc`, `create_index` on `apiaudit-dead-letter*` | `output.elasticsearch.non_indexable_policy.dead_letter_index`. Without `create_index` the first dead-letter write fails and a permanently rejected audit document is lost silently — the exact failure this policy exists to prevent. |

**Never** grant `manage_index_templates`, `manage_ilm`, `manage`, `all`,
`delete`, `delete_index`, or `write` (which includes delete-by-query). Verify
after creating it:

```bash
ES "$ES_URL/_security/role/filebeat_writer?pretty"
# The output must contain no "manage" of any kind.
```

---

## 4. Verification

```bash
ES() { curl -u "$ES_USER:$ES_PASS" --cacert ca.crt -sS "$@"; }

# --- the objects exist -------------------------------------------------
ES "$ES_URL/_ilm/policy/apiaudit-ilm?pretty"
ES "$ES_URL/_index_template/logs-apiaudit?pretty"

# --- THE check: what would a new index actually get? -------------------
# dynamic must be false, here and in every nested object.
ES -XPOST "$ES_URL/_index_template/_simulate_index/logs-apiaudit.probe-prod" |
  jq '.template.mappings | {dynamic, nested_dynamic: [paths(type=="object" and has("properties")) as $p | {($p|join(".")): getpath($p).dynamic}]}'

ES -XPOST "$ES_URL/_index_template/_simulate_index/logs-apiaudit.probe-prod" |
  jq '.template.settings.index | {codec, total_fields: .mapping.total_fields.limit, ilm: .lifecycle.name}'
# expect: best_compression / "200" / apiaudit-ilm

# --- the data stream ---------------------------------------------------
ES "$ES_URL/_data_stream/logs-apiaudit.*-*?pretty" | jq '.data_streams[] | {name, generation, template, status}'
# `template` MUST be "logs-apiaudit". Anything else means the data stream was
# created before step 1 and its backing indices have a dynamic mapping.

# --- the field bound (AC-10) -------------------------------------------
ES "$ES_URL/logs-apiaudit.*-*/_field_caps?fields=*" | jq '.fields | length'
# must stay <= 200, whatever the endpoints do to their request bodies

# --- documents are actually arriving -----------------------------------
ES "$ES_URL/logs-apiaudit.*-*/_count?pretty"
ES "$ES_URL/logs-apiaudit.*-*/_search?size=1&sort=@timestamp:desc&pretty"

# --- ILM is progressing, not stuck -------------------------------------
ES "$ES_URL/logs-apiaudit.*-*/_ilm/explain?pretty" | jq '.indices[] | {index, phase, action, step, failed_step, age}'
# `"step": "check-migration"` that never advances == the cold phase is enabled
# on a cluster with no data_cold nodes. Set COLD_TIER_EXISTS = False and re-run
# bootstrap.py.

# --- rejected writes: the mapping refusing something ---------------------
ES "$ES_URL/_nodes/stats/indices/indexing?pretty" | jq '.nodes[].indices.indexing.index_failed'
```

Filebeat side:

```bash
kubectl -n audit-logging logs -l app.kubernetes.io/name=filebeat-audit --tail=50
kubectl -n audit-logging exec ds/filebeat-audit -- curl -s localhost:5066/stats |
  jq '{harvesters: .filebeat.harvester, published: .libbeat.output.events, queue: .libbeat.pipeline.queue}'

# The registry survived the last restart (R-11)? It should be non-empty:
kubectl -n audit-logging exec ds/filebeat-audit -- \
  ls -la /usr/share/filebeat/data/registry/filebeat/

# Filebeat can see the files at all:
kubectl -n audit-logging exec ds/filebeat-audit -- ls -la /var/log/audit/
```

**Health signals worth an alert**, all visible on the "Pipeline health"
dashboard: documents/min per service going flat while the app still serves
traffic (shipping is broken, not the app); `libbeat.output.events.failed`
climbing (ES rejecting writes — check the mapping); the disk queue at
`max_size` (ES has been unreachable long enough to matter).

---

## 5. Changing retention

**One number, one file.**

```bash
$EDITOR infra/elasticsearch/ilm-apiaudit.json   # _meta.RETENTION_DAYS: 90 -> 180
./.venv/bin/python infra/elasticsearch/bootstrap.py
```

`bootstrap.py` reads `_meta.RETENTION_DAYS` and writes it into
`policy.phases.delete.min_age` before the PUT, so the two cannot drift, and it
refuses a value that would delete an index before it reaches its warm or cold
phase. The change applies to existing indices at their next ILM poll (10
minutes by default) — no reindex, no restart, nothing to redeploy.

For a single environment that must differ from the file, set `RETENTION_DAYS`
in `bootstrap.py`'s CONFIG block instead; it overrides the file.

At 200 rps, 90 days with a replica is ~1.86 TB (plan §5). The levers, in
order: shorter hot/warm windows, `number_of_replicas: 0` in cold, 60-day
retention, then `max_body_bytes` down to 256 KB per service.

---

## 6. Detecting a silently lost line

An audit trail whose holes are invisible is worse than one with none, so the
three ways a document can disappear between `submit()` and Elasticsearch each
have a query. Run all of them from the "Pipeline health" dashboard or from
cron; each returns 0 on a healthy pipeline.

### 6.1 Lines Filebeat could not decode — the M-3 class

A line longer than `message_max_bytes` is **truncated** by filestream, so the
ndjson parser then fails on it. It used to be discarded by a `drop_event`
processor with no counter anywhere; it is now routed to
`logs-apiaudit.undecodable-<namespace>` with the (truncated) raw line in
`message` and Filebeat's decode error in `error.message`.

```bash
# How many, over the last 24 h? Expect 0.
ES "$ES_URL/logs-apiaudit.undecodable-*/_count?pretty" \
   -H 'Content-Type: application/json' -d '{
  "query": { "range": { "@timestamp": { "gte": "now-24h" } } } }'

# What did they look like? `message` is stored but not indexed (dynamic:false),
# so fetch it from _source rather than searching it.
ES "$ES_URL/logs-apiaudit.undecodable-*/_search?size=5&sort=@timestamp:desc&pretty" |
  jq '.hits.hits[]._source | {ts: .["@timestamp"], err: .error.message, head: .message[0:400]}'
```

Anything above zero means either an over-long line (check the head of
`message` for a huge `audit.request.body_raw`) or corruption on the node's
disk. The lever for the first is `AuditConfig.max_body_bytes`; see the SIZING
INVARIANTS block at the top of `filebeat/filebeat.yml` before changing
`message_max_bytes` instead.

**Filebeat has no counter of its own for this** — there is no
"line exceeded `message_max_bytes`" metric anywhere in `/stats`, and
`filebeat.harvester.*` and `libbeat.output.events.*` all count a truncated
line as a normal success. That is exactly why the quarantine data stream
exists: it is the counter.

Be honest about what quarantine does and does not recover. The *existence* of
the lost record, its timestamp, and the first 8 KiB of it are preserved and
countable. The bytes past `message_max_bytes` are not — filestream discarded
them before any processor ran. The full line is still on the node, in
`/var/log/audit/<pod>/<service>-<pid>.jsonl*`, until rotation reaches it
(`file_max_bytes` × `file_backup_count` = 2 GB per pod by default), so a
quarantine hit is a reason to go and copy that file **now**, not later.

### 6.2 Documents Elasticsearch refused — the M-5 / N-9 class

A mapping error rejects the **whole document**, not the offending field:
`index.mapping.ignore_malformed` covers numeric, boolean, date, `ip` and geo
types only, never `keyword` or `flattened`. These now land in
`apiaudit-dead-letter` instead of being dropped.

```bash
ES "$ES_URL/apiaudit-dead-letter/_count?pretty"
ES "$ES_URL/apiaudit-dead-letter/_search?size=5&sort=@timestamp:desc&pretty" |
  jq '.hits.hits[]._source | {status: .error.type, reason: .error.message, doc: .message[0:400]}'

# Corroborate from the cluster side — this counts rejections whether or not
# the dead-letter write itself succeeded:
ES "$ES_URL/_nodes/stats/indices/indexing?pretty" | jq '.nodes[].indices.indexing.index_failed'
```

Three known causes, all package-side, all open at the time of writing, all
verified against the `elasticsearch` v8.13.4 `FlattenedFieldParser.addField`
source rather than against a cluster:

| Cause | Cost to an attacker |
|---|---|
| a `user_resolver` returning a non-string for `user.id`/`name`/`roles` (review M-5, FR-31) | needs a misconfigured service, not a client |
| a JSON body **key** longer than ~29.7 KB — the `flattened` `key`+NUL+`value` term then exceeds Lucene's 32 766-byte `MAX_TERM_LENGTH` (review N-9) | one 40 KB request body |
| a JSON body **key containing a NUL character** — `addField` rejects `\0` in a key outright (not in the review; found while verifying N-9) | a 15-byte request body |

None of the three can be fixed in the index template. `addField` throws before
it reaches the `isIndexed()` / `hasDocValues()` branches, so even
`index: false, doc_values: false` would not avoid it, and `ignore_above`
bounds the leaf **value**, never the key. The fix is to bound and sanitise
body keys in `redact.py`; until then, watch `apiaudit-dead-letter`.

Two things that are *not* problems, checked at the same time: empty-string
keys (`{"": 1}`) and leading/trailing/doubled-dot keys (`{".a":1,"b.":2,"c..d":3}`)
are accepted by the flattened parser — the object-mapper rules that reject
them never run inside a `flattened` field (review N-10, disproved). And a key
over the limit whose *value* also exceeds `ignore_above` is dropped by the
`ignore_above` check before the term is ever built, so it indexes cleanly —
which is why this failure is intermittent rather than deterministic and needs
the dead-letter index to be visible at all.

### 6.3 The shipper is wedged

A bulk that Elasticsearch refuses at the request level (413, for a bulk over
`http.max_content_length`) is retried **forever** — Filebeat's Elasticsearch
output ignores `max_retries` by design. The symptom is `acked` flat while
`failed` climbs.

```bash
kubectl -n audit-logging exec ds/filebeat-audit -- curl -s localhost:5066/stats |
  jq '{acked: .libbeat.output.events.acked,
       failed: .libbeat.output.events.failed,
       dropped: .libbeat.output.events.dropped,
       queue: .libbeat.pipeline.queue}'
```

`failed` rising with `acked` flat for more than a few minutes is a page.
Check the Filebeat log for `413`; if that is it, `bulk_max_size` in
`filebeat.yml` is too large for the bodies this cluster is actually seeing —
it is sized at 12 for a 1 MiB `max_body_bytes`.

Also watch for `Rejecting event with size ... because the segment buffer
limit is ...` in the Filebeat log. That is the disk queue dropping a single
oversized event with nothing but a warn line; it means
`queue.disk.segment_size` is smaller than `message_max_bytes`.

### 6.4 Deduplicating after a registry loss

If `path.data` is lost (plan R-11) Filebeat re-reads from byte 0 and
duplicates lines. **Do not deduplicate on `trace.id` alone.** FR-23 reuses a
client-supplied `X-Request-ID`, so `trace.id` is client-chosen: one client
pinning one value makes every request it ever sends collapse into a single
"event" (review N-12). The collapse key is the composite:

```bash
ES "$ES_URL/logs-apiaudit.*-*/_search?size=0&pretty" \
   -H 'Content-Type: application/json' -d '{
  "query": { "range": { "@timestamp": { "gte": "now-1h" } } },
  "aggs": { "dupes": {
    "multi_terms": {
      "terms": [ { "field": "trace.id" }, { "field": "host.hostname" },
                 { "field": "process.pid" }, { "field": "@timestamp" } ],
      "size": 20, "min_doc_count": 2 } } } }'
```

A hit here is a genuine duplicate of one request. The same aggregation on
`trace.id` alone will report thousands of "duplicates" that are simply one
client reusing a header, which is why the earlier wording in
`daemonset.yaml` was wrong and has been corrected.

---

## 7. Post-deployment write check (run once per audited service)

The sink cannot raise into the request path (NFR-3), so a directory it cannot
write to produces a healthy-looking pod and an empty index. Prove the write
side works the first time each service rolls out:

```bash
POD=$(kubectl -n <app-ns> get pod -l app=<svc> -o jsonpath='{.items[0].metadata.name}')

# 1. The directory exists on the node and is owned by the app UID, not root.
#    (This is what the audit-log-dir initContainer is for — review S-14.)
kubectl -n <app-ns> exec "$POD" -c api -- sh -c 'ls -ld /var/log/audit && id'

# 2. The app can actually create a file there, as itself.
kubectl -n <app-ns> exec "$POD" -c api -- sh -c 'touch /var/log/audit/.wtest && rm /var/log/audit/.wtest && echo WRITABLE'

# 3. Real lines are being written.
kubectl -n <app-ns> exec "$POD" -c api -- sh -c 'ls -l /var/log/audit/*.jsonl && wc -l /var/log/audit/*.jsonl'

# 4. And the initContainer said so at startup:
kubectl -n <app-ns> logs "$POD" -c audit-log-dir
```

`Permission denied` at step 2 means the initContainer is missing, ran as a
non-root user, or chowned to a UID that does not match the app container's
`runAsUser`. Fix that before believing anything downstream.

---

## 8. Things that will bite you

- **Data stream created before the template.** Its backing indices keep the
  dynamic mapping until the next rollover, and the documents already in them
  keep it forever. `_data_stream/...` reporting a `template` other than
  `logs-apiaudit` is how you find out. The fix is a reindex; the prevention is
  step 1 first.
- **`dynamic: false` is silent.** A field the template does not declare is
  accepted, stored in `_source`, and simply not indexed or searchable. Nothing
  errors. If a field is missing from Discover, check the template before you
  check the app.
- **`body` and `body_raw` are mutually exclusive** (docs/schema.md §2.9, which
  supersedes D-10). A parseable JSON body appears only in
  `audit.request.body`; only a body that could not be represented as an object
  — a JSON parse failure, or an opted-in text body — appears in
  `audit.request.body_raw`. A query that looks in one and finds nothing should
  look in the other before concluding the body was not captured;
  `audit.request.body_skipped` says which case applies.
- **`audit.request.body_raw` is not searchable, by design.** It is
  `index: false, doc_values: false` — retrievable per document, invisible to
  queries and aggregations. Search `audit.request.body` instead, which is
  `flattened` and therefore `keyword`-only: no range queries, no full text
  (docs/schema.md §2.8).
- **`event.duration` is nanoseconds.** The Kibana data view formats it as
  milliseconds; a raw `_search` does not. Divide by 1e6 by hand.
- **Rotated files (`.jsonl.1` … `.8`) ARE globbed**, and that is deliberate
  (review S-13). `filestream` follows an open file across the rename only
  while it is *running*; if the DaemonSet pod is down when the sink rotates —
  node drain, rolling update, OOM-kill, config reload — the unshipped tail of
  the old file sits at `.1` and, under the old exclusion, was never read.
  Globbing them does **not** duplicate anything because `file_identity` is
  `native` (inode + device) and a rename does not change the inode. Do not
  switch `file_identity` to `path` or `fingerprint` without re-reading that
  input's comments; either would re-ingest every rotated file in full.
- **Filebeat runs as root** so it can read files written by application
  containers running as arbitrary UIDs. That is the *read* side and it was
  never the problem. The *write* side needs the `audit-log-dir` initContainer
  in every audited app pod (§3 step 3, §7, review S-14): the kubelet creates
  the `subPathExpr` directory `root:root` 0755 and `fsGroup` does not apply to
  `hostPath`, so `fsGroup` alone does **not** work no matter how many services
  agree on a GID. If your PodSecurity profile forbids a root initContainer,
  use the sidecar variant — its `emptyDir` *does* honour `fsGroup`.
- **A silently missing audit record is the failure this system exists to
  prevent.** Three ways it can still happen, and the query for each, are in
  §6. Wire at least §6.1 and §6.3 to an alert before pilot traffic.
