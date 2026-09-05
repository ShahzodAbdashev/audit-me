# Audit document schema

| | |
|---|---|
| Status | **Frozen** (Phase 0 exit) |
| Basis | ECS 8.x where a field exists; a custom `audit.*` namespace where it does not |
| Produced by | `audit_logging.document.build_document` [A2] |
| Bounded by | `infra/elasticsearch/template-apiaudit.json` [A5], `dynamic: false`, `total_fields.limit: 200` |

One JSON object per line in `{log_dir}/{service_name}-{pid}.jsonl`.

---

## 1. Worked example

```json
{
  "@timestamp": "2026-09-05T11:22:33.123456Z",
  "data_stream": { "type": "logs", "dataset": "apiaudit.orders_api", "namespace": "prod" },
  "event": {
    "kind": "event",
    "category": ["web"],
    "type": ["access"],
    "action": "http-request",
    "duration": 4211000,
    "outcome": "success"
  },
  "trace": { "id": "9f2c1a7d4e8b4f0aa1c3d5e7f9b0c2d4" },
  "service": { "name": "orders-api", "version": "1.4.2", "environment": "prod" },
  "host": { "hostname": "orders-api-7d9f8c-h2k4m" },
  "process": { "pid": 7 },
  "url": { "path": "/orders/42/items", "query": "expand=lines&token=%5BREDACTED%5D" },
  "http": {
    "version": "1.1",
    "request": { "method": "POST", "bytes": 812, "mime_type": "application/json" },
    "response": { "status_code": 201, "bytes": 128 }
  },
  "client": { "ip": "10.42.0.31", "port": 51234 },
  "user_agent": { "original": "python-httpx/0.28.1" },
  "user": { "id": "u-8813", "name": "a.karimov", "roles": ["operator"] },
  "audit": {
    "route": "/orders/{order_id}/items",
    "path_params": { "order_id": "42" },
    "request": {
      "headers": { "content-type": "application/json", "user-agent": "python-httpx/0.28.1" },
      "query": { "expand": "lines", "token": "[REDACTED]" },
      "body": { "sku": "A-11", "qty": 3, "card": { "cvv": "[REDACTED]" } },
      "body_bytes": 812,
      "body_truncated": false,
      "body_parse_failed": false
    },
    "response": { "headers": { "content-type": "application/json" } }
  }
}
```

There is **no `body_raw` here.** This body parsed, so `body` carries it and
`body_raw` is absent — the two are mutually exclusive (§2.9). A document with
`body_raw` and no `body` is the parse-failure or text case; see the table
there. Earlier drafts of this example showed both, which §2.9 made impossible.

---

## 2. Field reference

`C` = custom, `E` = ECS. "Agent" is who writes the value.

### 2.1 Envelope

| Field | Type | E/C | Agent | Notes |
|---|---|---|---|---|
| `@timestamp` | `date` | E | A2 | UTC, wall-clock at document build, ISO-8601 with microseconds |
| `data_stream.type` | `constant_keyword` | E | A2 | Always `"logs"` |
| `data_stream.dataset` | `constant_keyword` | E | A2 | `apiaudit.` + service name, `[^a-z0-9_.]` → `_` (§6.2) |
| `data_stream.namespace` | `constant_keyword` | E | A2 | `config.environment` |

Filebeat routes on these three (plan §4.3). They are `constant_keyword` per index, so they cost 3 fields, not 3 × cardinality.

### 2.2 Event

| Field | Type | E/C | Agent | Notes |
|---|---|---|---|---|
| `event.kind` | `constant_keyword` | E | A2 | Always `"event"` |
| `event.category` | `keyword` | E | A2 | Always `["web"]` |
| `event.type` | `keyword` | E | A2 | Always `["access"]` |
| `event.action` | `keyword` | E | A2 | Always `"http-request"` |
| `event.duration` | `long` | E | A2 | **Nanoseconds** (ECS). FR-06 |
| `event.outcome` | `keyword` | E | A2 | `success` \| `failure` \| `disconnected` |

`event.outcome` is `failure` when the app raised **or** status ≥ 500; `disconnected` when the client vanished before the response finished; `success` otherwise — a 404 or 422 is a `success` outcome with a 4xx status.

### 2.3 Identity and origin

| Field | Type | E/C | Agent | Notes |
|---|---|---|---|---|
| `trace.id` | `keyword` | E | A2 | FR-23; echoed as `X-Request-ID` (FR-24) |
| `service.name` | `keyword` | E | A2 | `config.service_name` |
| `service.version` | `keyword` | E | A2 | |
| `service.environment` | `keyword` | E | A2 | |
| `host.hostname` | `keyword` | E | A2 | `socket.gethostname()`, resolved once at import |
| `process.pid` | `long` | E | A2 | Distinguishes uvicorn workers (A-5, FR-26) |
| `client.ip` | `ip` | E | A2 | From `scope["client"]`. **Not** from `X-Forwarded-For` — see §4 |
| `client.port` | `long` | E | A2 | |
| `user_agent.original` | `keyword` | E | A2 | Only if `user-agent` is allowlisted |

### 2.4 HTTP

| Field | Type | E/C | Agent | Notes |
|---|---|---|---|---|
| `url.path` | `keyword` | E | A2 | Raw path, before routing |
| `url.query` | `keyword` | E | A2 | Raw query string, **with denylisted values already replaced** (FR-14). Over `max_query_bytes` (or its derived pair bound) this is the fixed literal `"[SKIPPED]"` — **no client bytes**, so the bound cannot become an FR-14 bypass |
| `http.version` | `keyword` | E | A2 | `scope["http_version"]` |
| `http.request.method` | `keyword` | E | A2 | Uppercase |
| `http.request.bytes` | `long` | E | A2 | Bytes actually received, before truncation |
| `http.request.mime_type` | `keyword` | E | A2 | Content type without parameters |
| `http.response.status_code` | `long` | E | A2 | `500` when the app raised before responding |
| `http.response.bytes` | `long` | E | A2 | Total body bytes emitted (FR-05, AC-13) |

### 2.5 User (optional, FR-25)

| Field | Type | E/C | Agent | Notes |
|---|---|---|---|---|
| `user.id` | `keyword` | E | A2 | From `user_resolver` |
| `user.name` | `keyword` | E | A2 | |
| `user.roles` | `keyword` | E | A2 | |

The block is absent entirely when there is no resolver, it returns `None`, or it raises. Keys the resolver returns that are not `id`/`name`/`roles` are dropped — `user.*` is not `dynamic`.

### 2.6 Error (present only on failure)

| Field | Type | E/C | Agent | Notes |
|---|---|---|---|---|
| `error.type` | `keyword` | E | A2 | Exception class name |
| `error.message` | `text` | E | A2 | `str(exc)`, truncated to 1024 chars |

**No stack trace.** It is the application's job to log its own tracebacks; a trace here would blow the field budget and duplicate the app log.

### 2.7 The `audit.*` namespace

| Field | Type | E/C | Agent | Notes |
|---|---|---|---|---|
| `audit.route` | `keyword` | C | A2 | Route template, e.g. `/orders/{order_id}`; `"unmatched"` if absent (FR-03) |
| `audit.path_params` | `flattened` | C | A2 | `scope["path_params"]`, values stringified |
| `audit.request.headers` | `flattened` | C | A2/A3 | Allowlist only (FR-12) |
| `audit.request.query` | `flattened` | C | A2/A3 | Parsed and redacted (FR-14). `{}` when the query was not captured |
| `audit.request.query_skipped` | `keyword` | C | A2 | `too_complex`; absent when the query was captured. The exact analogue of `body_skipped`: a 64 KB query on a bodiless `GET` cost 17.9 ms of event-loop stall before this bound existed (N2-3). Counted by `audit_queries_skipped_total` |
| `audit.request.body` | `flattened` | C | A2/A3 | Parsed and redacted JSON. Non-object top level wrapped as `{"_value": …}` (FR-09) |
| `audit.request.body_raw` | `keyword` (`index: false`, `doc_values: false`, `ignore_above` unset) | C | A2 | Body text for the cases `body` cannot represent. **Mutually exclusive with `body`** — see §2.9. Stored, never indexed |
| `audit.request.body_bytes` | `long` | C | A2 | Bytes captured, ≤ `max_body_bytes` |
| `audit.request.body_truncated` | `boolean` | C | A2 | FR-08 |
| `audit.request.body_parse_failed` | `boolean` | C | A2 | FR-09; absent when there was no body to parse |
| `audit.request.body_skipped` | `keyword` | C | A2 | `content_type` \| `empty` \| `unread` \| `too_complex`; absent when the body was captured |
| `audit.request.multipart` | `flattened` | C | A2 | Part metadata only, never bytes (FR-07) |
| `audit.response.headers` | `flattened` | C | A2 | Allowlist only |

### 2.8 Why `flattened`

`flattened` maps an arbitrary object to **one** field in the mapping (D-10, plan §8.3). Without it, 50 endpoints with distinct body shapes would each add fields and blow past `total_fields.limit` — exactly what AC-10 tests. The cost is that sub-keys are `keyword`-only: no range queries on `audit.request.body.qty`, no full-text on body values. That is the deliberate trade.

`body_raw` carries the full fidelity D-10 requires, with `index: false` so it costs storage but not a mapping entry or an inverted index.


### 2.9 `body` and `body_raw` are mutually exclusive — supersedes D-10

Plan D-10 specifies "full raw body stored unindexed **plus** a `flattened`
copy for search". Storing both was measured to double every line: a 1 MiB body
produced a **2,097,957-byte** JSONL line, 805 bytes past Filebeat's
`message_max_bytes`, and 3.0 MiB when the body contained quotes. Those lines
were truncated, failed ndjson decode, and were silently discarded by
`drop_event` — the largest and most interesting audit records never reached
Elasticsearch, and no counter recorded the loss (review M-3). It also put a
second full serialisation of an attacker-sized body on the request path (M-2).

Exactly one of the two is emitted:

| Body | Emitted | `body_parse_failed` | `body_skipped` |
|---|---|---|---|
| Parseable JSON | `body` (flattened, redacted) | `false` | absent |
| Form-encoded | `body` (flattened, redacted) | `false` | absent |
| JSON that failed to parse | `body_raw` (raw text, **unredacted by construction**) | `true` | absent |
| Text, `capture_text_bodies` on | `body_raw` (best-effort scrub) | absent | absent |
| Text, default | neither | absent | `content_type` |
| Multipart / binary | neither (`multipart` metadata only) | absent | `content_type` |
| Over `max_body_nodes` | neither | absent | `too_complex` |
| Empty / unread | neither | absent | `empty` / `unread` |

D-10's intent — full fidelity, with the mapping bounded — is preserved. For
parseable JSON the `flattened` `body` **is** the complete content; the raw text
adds only key order and duplicate keys, at 100 % of the storage. Where the
content genuinely cannot be represented as an object, `body_raw` still carries
it verbatim. The plan §5 sizing estimate (~2 KB/document) assumes single
storage and was always inconsistent with double storage.

---

## 3. Field budget

Four different numbers for "how many fields" circulate in this repo and they
are **not** in conflict — they count different things. Review N-15 flagged the
disagreement; this table is the resolution.

| Number | What it counts | Where it comes from |
|---|---|---|
| **45** | Leaf fields documented in §2 | This document, and the template's leaves — the two agree exactly, checked by A5's cross-check script |
| **18** | Object containers (`event`, `http.request`, `audit.request`, …) | Structure, not data. Each is one `dynamic: false` boundary |
| **63** | Total mapping entries = 45 + 18 | What `GET _mapping` returns for the template as installed |
| **51** | Fields actually created by real traffic | Measured by AC-10: 50 endpoints × 200 requests, 10 000 documents |

`total_fields.limit: 200` is compared by Elasticsearch against the **63**.

The number that matters is the **51**, because it is the one that moves. Under
a `dynamic: true` mapping the same 10 000 documents create **20 194** fields —
AC-10 asserts both directions, so it cannot pass by accident. That ~400×
difference is `flattened` doing its job (§2.8), and it is the whole reason
D-11 installs the template before the first write: a data stream created first
gets dynamic mapping and cannot be fixed without a reindex.

The headroom between 63 and 200 exists because `flattened` absorbs body shape.
It is **not** an invitation to add fields — anything new goes through the
orchestrator.

## 4. What is deliberately absent

| Not stored | Why |
|---|---|
| Response bodies | D-3 — ~3× storage and the main PII leak vector |
| Uploaded file bytes | D-5 — blobs belong in object storage |
| Stack traces | §2.6 |
| Non-allowlisted headers | FR-12 — `Authorization` and `Cookie` must never be recoverable |
| `X-Forwarded-For` as `client.ip` | The header is client-controlled. It is captured verbatim in `audit.request.headers` when allowlisted; deciding the *true* client IP is the ingress's job, not this package's |
