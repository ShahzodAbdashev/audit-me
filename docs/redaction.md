# Redaction — what it does, and what it does not

> **If you read one section, read [§4](#4-what-redaction-does-not-protect-against).**
> Everything in it is real, reproduced and disclosed; each item says whether a
> test pins it. In particular: **PII is not
> redacted by default.** `email`, `phone`, `name`, `address` and
> `date_of_birth` are stored in full. If your service has a compliance
> requirement about any of those, you must opt in with `extra_redact_keys`
> ([§4.10](#410-pii-is-not-redacted-by-default-the-one-most-likely-to-bite-you)),
> and you must do it before the first request, because the retention is 90 days
> and there is no un-storing.
>
> And the one people underestimate: **a secret in a URL path is not merely
> stored, it is *searchable*.** `url.path` is an indexed `keyword` and is never
> redacted, and `audit.path_params` redaction does not help — it removes the
> second copy, not the indexed one
> ([§4.5](#45-secrets-in-the-url-path-are-never-redacted-and-they-are-searchable)).

Redaction here is **key-driven**. It looks at the *names* of things and never at
their contents. That single sentence explains most of §4.

---

## 1. The two mechanisms

They are deliberately asymmetric (plan D-12).

| | Bodies, query strings, path params, multipart metadata | Headers |
|---|---|---|
| Mechanism | **Denylist** of key names | **Allowlist** of header names |
| Why | The shape is user data; the keys cannot be enumerated in advance | The header set is small and known |
| A match | value becomes `"[REDACTED]"`, **key is kept** | — |
| A non-match | value is stored as-is | header **vanishes entirely**, not even as a name |

Keeping the key is the point on the body side: knowing that a request carried a
`password` field is useful in an audit trail; knowing the password is not.
Dropping the name entirely is the point on the header side: `Authorization` must
not be recoverable, and must not be visible as a name either (FR-12, AC-06).

`redact()` is **pure** — it returns a new structure and never mutates the object
your application parsed (FR-10, `test_redact.py::test_FR_10_redact_is_pure_and_does_not_mutate_the_input`,
plus a Hypothesis property test).

## 2. What is redacted by default

### 2.1 The body/query denylist

`audit_logging.redact.DEFAULT_REDACT_KEYS` — **106 entries** at the time of
writing. FR-11 mandates 36 of them; the rest are the same secrets under the
spellings real APIs use (`oldPassword`, `x-api-key`, `awsSecretAccessKey`,
`totpCode`, `routingNumber`, and so on). Read the list in
`audit_logging/redact.py`; it is one flat, commented `frozenset` and it is worth
the two minutes.

Matching is on the **normalized** key: lowercased, with `_`, `-` and `.`
removed. So `api_key`, `API-KEY`, `Api.Key` and `apikey` are one key
(`test_normalize_key_variants`).

Applied at **every depth**, inside dicts and inside lists, to:

| Field | Notes |
|---|---|
| `audit.request.body` | Parsed JSON and form-encoded bodies |
| `audit.request.query` | Parsed query string |
| `url.query` | The raw query string is **rebuilt** with the redacted values |
| `audit.path_params` | So a route declaring `/keys/{api_key}` does not leak the value there — but see [§4.5](#45-secrets-in-the-url-path-are-never-redacted-and-they-are-searchable) |
| `audit.request.multipart` | Part `name`, `filename`, `content_type`; a `filename` under a denylisted part `name` is redacted (`test_N_7_a_filename_under_a_denylisted_part_name_is_redacted`) |

A denylisted key holding a whole object is replaced wholesale, without
descending into it — `{"credentials": {...anything...}}` becomes
`{"credentials": "[REDACTED]"}`.

Query strings and form bodies split on **`;` as well as `&`**, and their keys are
whitespace-stripped, so `?a=1;token=SECRET` and `?%20token=SECRET` are both
caught (review S-3, `test_document.py::test_S_3_*`). Those two used to pass
through verbatim into the indexed `url.query`. (Control characters in a key are
*not* stripped and do defeat the denylist — see §4.3.)

**The query string is now bounded, and the bound is not a redaction bypass.**
`url.query` is where FR-14 rewrites denylisted values in the *raw* string, so
storing an unparsed — and therefore unredacted — query there would turn a cost
bound into a leak. Past `max_query_bytes` (8192) or the derived pair bound
(`max_query_bytes // 16`, so 512 pairs at the default), the package stores a
fixed literal and nothing else:

```
url.query                    = "[SKIPPED]"      <- a constant, never client bytes
audit.request.query          = {}
audit.request.query_skipped  = "too_complex"
audit_queries_skipped_total  += 1
```

The bound exists for cost, not for secrecy: `_query` is
split → `unquote_plus` per key *and* per value → `redact` → `urlencode`, all on
the request path, and nothing capped it. A 64 KB query string on a **bodiless
`GET`** cost 17.9 ms of event-loop stall — over three times the whole NFR-1
budget, from a request with no body, no authentication and no `POST`
(`REVIEW-2.md` N2-3). *Tests:* `test_document.py::test_N2_3_*`, including
`test_N2_3_a_refused_query_is_not_a_redaction_bypass`, which plants a secret in
an over-bound query and asserts it appears nowhere in the document.

### 2.2 The header allowlist

`DEFAULT_HEADER_ALLOWLIST` — **35 entries**, lowercase: content negotiation,
`user-agent`, `host`, `referer`, `origin`, the `x-forwarded-*` family, and the
tracing headers (`traceparent`, `tracestate`, `b3`, `baggage`, …). Applied to
both request and response headers.

`authorization`, `cookie`, `set-cookie` and `proxy-authorization` are not on it
and never appear, under any casing, whitespace padding or byte encoding the
reviewer could construct (REVIEW §8, "Header redaction is airtight").

### 2.3 Three other bounds that are not redaction but limit exposure

None of these three is about secrecy. All three exist because a single hostile
key or value can destroy the **whole** audit document — the record of the very
request that carried it — which is a strictly worse outcome than storing it.

* **Depth cap.** Anything at nesting depth 20 or deeper is replaced by
  `"[TRUNCATED]"` — values included, so a deep value cannot escape unchecked,
  and cyclic input terminates without any `id()` bookkeeping.
* **Key sanitisation.** Applies to **every key `redact()` emits** — body, query
  string, path params and multipart metadata alike, not just body keys. Three
  triggers: a key longer than 1024 UTF-8 bytes; a key carrying a C0 control
  character, DEL or a lone surrogate; or a key that already contains the literal
  `[SANITIZED:`, so that a client cannot forge a rewrite that collides with a
  real one. Such a key is rewritten as `<prefix>[SANITIZED:<16 hex>]`, the hex
  being a BLAKE2b digest of the *original*, so two distinct keys never collapse
  into one. Without this, an over-long or control-carrying key makes
  Elasticsearch reject the entire document (review N-9, and a NUL case found
  afterwards).
* **Value sanitisation.** A string **value** that cannot be encoded as UTF-8 —
  in practice, one holding a lone UTF-16 surrogate — has its surrogates replaced
  with U+FFFD and the same 16-hex digest appended. Nothing else about values is
  touched: no length rule, no control-character rule, so an ordinary body comes
  back byte-identical.

  This one is new, and it closed the worst finding in either review. `orjson`
  refuses to parse a lone surrogate, the stdlib fallback accepts it, and
  `orjson.dumps` then refuses to serialise the finished document — so
  **`{"a":"\ud800"}`, a 14-byte body on any JSON endpoint, used to delete its
  own audit record**, silently, with the loss filed under
  `audit_documents_dropped_total` ("the disk is not keeping up"). That is
  client-selected suppression of the audit trail, and it cost an attacker one
  field (review N2-1). The digest suffix is what makes the fix honest: a reader
  can tell a U+FFFD *we* wrote from one the client actually sent, and two
  distinct values cannot silently merge into one.

> **Key sanitisation degrades under load, on purpose.** The rewrite above is
> 20–70× the cost of passing a key through untouched, and *which* keys pay it is
> the client's choice — 4,998 keys each carrying one control character is a
> 73 KB body, inside every other cap, that cost 10 ms of event-loop time in
> `redact()` alone (review N2-4). So the *work* is bounded: past **128**
> cold-path keys in one `redact()` call, the rewrite is replaced by a
> constant-cost stand-in, `<≤24 ASCII chars>[SANITIZED:over-budget-<seq>]`.
> Safety does not degrade — the result is still ASCII, printable, far under the
> byte bound, and distinct per key — only informativeness does: you get a
> recognisable head or nothing, and no digest to correlate on.
>
> **The residual, flagged by the fix agent and repeated here so it is not
> lost:** `document.py` calls `redact()` up to four times per request (query,
> path params, multipart metadata, body), and the budget is per call, so the
> real per-request ceiling is **4 × 128 = 512** cold-path keys, not 128.

## 3. Extending it

Both lists are extended through `AuditConfig`, and extension is **additive
only** — there is no supported way to remove a default (FR-13, D-12):

```python
AuditConfig(
    service_name="orders-api",
    extra_redact_keys=["tenant_ref", "email", "phone", "date_of_birth"],
    extra_header_allowlist=["x-tenant-id"],
)
```

or from the environment:

```
AUDIT_EXTRA_REDACT_KEYS=tenant_ref,email,phone,date_of_birth
AUDIT_EXTRA_HEADER_ALLOWLIST=x-tenant-id
```

Your keys are normalized the same way the defaults are, so `date_of_birth`,
`dateOfBirth` and `date-of-birth` are all covered by the one entry. The
effective sets are

```
DEFAULT_REDACT_KEYS      | {normalize_key(k) for k in config.extra_redact_keys}
DEFAULT_HEADER_ALLOWLIST | {k.lower()        for k in config.extra_header_allowlist}
```

and AC-24 asserts both halves: your extra key redacts in the query *and* the
body, and every default still redacts alongside it.

**Adding to the header allowlist is the more dangerous of the two.** A denylist
addition can only remove data from the index; an allowlist addition adds a
header you have decided is safe. Check that it is not a bearer credential under
a vendor-specific name before you add it.

---

## 4. What redaction does NOT protect against

Each of these is a real, reproduced limitation. **Most, but not all, have a test
that pins them.** Where a test exists it is named, so that changing the
behaviour fails a test and sends someone back here; where none exists the item
was marked **⚠ unpinned**, which meant exactly one thing: *this limitation could
silently stop being true — or silently get worse — and nothing would notice.*

That distinction was itself a review finding. The first version of this section
claimed a test for all twelve; a verification pass checked them one by one and
found four claims that did not hold (`REVIEW-2.md` §5). Three of the four are
repaired below with citations that do hold. The remainder are labelled rather
than quietly dropped, because a limitation you have stopped testing is worse
than one you never tested — you still believe you are covered.

These have since been **commissioned and pinned**. The tests are named
`test_LIMITATION_*` so they read as a category, and each states in its
docstring what a fix would look like — so whoever fixes one updates the test
rather than deleting it.

| Item | Now pinned by |
|---|---|
| [§4.5](#45-secrets-in-the-url-path-are-never-redacted-and-they-are-searchable) | `test_middleware.py::test_LIMITATION_secret_in_a_named_path_param_is_redacted_but_url_path_still_leaks` (both halves in one document) and `..._secret_in_a_positional_path_segment_is_never_redacted` |
| **§4.7** | `test_document.py::test_LIMITATION_the_text_scrub_misses_these_shapes` (parametrised), `..._a_client_can_forge_the_redacted_literal`, `..._a_text_body_over_max_scrub_bytes_is_refused_not_scrubbed` |
| [§4.12](#412-what-redaction-is-not-for-at-all) | `test_middleware.py::test_LIMITATION_client_ip_is_the_transport_peer_not_x_forwarded_for` |
| **§4.3** | `test_document.py::test_LIMITATION_control_characters_in_query_keys_are_not_normalised_away` |

Both files stub redaction with identity implementations by default — a Phase 1
contract-isolation choice — so each of these tests takes a `real_redaction`
fixture that undoes the stub. Without it they would assert nothing, which is
how the first draft of the §4.5 pin passed against code that was not redacting
at all.

> **One claim was overstated and has been narrowed.** §4.7 previously listed
> *nested XML* as a gap. It is not: the `<k>v</k>` pattern is a regex over the
> whole body, so nesting does not hide a match. Only **namespacing**
> (`<wsse:Password>`) defeats it. Found while writing the pin.

### 4.1 Homoglyphs and Unicode forms are not folded

`normalize_key` lowercases and strips three separators. It performs no Unicode
confusable mapping and no NFKC normalization.

```python
{"раssword": "hunter2"}      # Cyrillic р and а  -> stored in full
{"ｐａｓｓｗｏｒｄ": "hunter2"}   # fullwidth forms     -> stored in full
```

*Tests:* `test_LIMITATION_unicode_homoglyph_keys_are_not_caught`,
`test_LIMITATION_unicode_normalization_forms_are_not_folded`.

This is remotely triggerable: a client picks its own body key names. If your
threat model includes a client that is trying to get a secret into your audit
index, a key denylist does not stop it.

### 4.2 Matching is exact, not substring

The whole normalized key must be on the list.

```python
{"user_password_2": "hunter2"}   # -> stored in full
{"my_secret_stuff": "hunter2"}   # -> stored in full
{"old_password":    "hunter2"}   # -> "[REDACTED]"  (enumerated explicitly)
{"x-api-key":       "hunter2"}   # -> "[REDACTED]"
```

*Test:* `test_LIMITATION_matching_is_exact_not_substring`.

The 106-key default list is a **mitigation for this, not a fix.** It works by
enumerating spellings, and no enumeration is complete. Substring matching was
not chosen because it over-redacts catastrophically — `hash` as a substring
takes `hashtag`, `sig` takes `signup_date` and `design` — and over-redaction is
irreversible ([§4.9](#49-over-redaction-is-irreversible)).

**What to do about it:** grep your own request models for field names, and add
the ones that carry secrets to `extra_redact_keys`. Nobody else can do this for
you; the package does not know your schema.

### 4.3 Only `_`, `-` and `.` are stripped from keys

Spaces and tabs are not.

```python
{"pass word":  "hunter2"}   # -> stored in full
{" password ": "hunter2"}   # -> stored in full   (in a JSON body)
```

*Test:* `test_LIMITATION_whitespace_inside_keys_is_not_stripped`.

Note the asymmetry, which is easy to misremember: **query strings and form
bodies do strip leading/trailing whitespace from keys** (that was review S-3),
so `?%20password=x` *is* caught. A JSON body is not treated the same way,
because `{" password ": …}` and `{"password": …}` are genuinely different keys
in JSON and rewriting them would change the shape the audit record reports.
Interior whitespace (`"pass word"`) is never caught anywhere.

**Control characters extend the same class, and the query path does not strip
them either.** `?pass%00word=SECRET` decodes to the key `pass\x00word`, which
does not normalise to `password`, so the value is stored in the clear in **both**
`url.query` and `audit.request.query`. (The key itself is then rewritten by the
sanitiser of §2.3 — but that happens *after* the denylist verdict is taken, by
design, so it does not rescue the value.) `REVIEW-2.md` N2-14. Pinned by `test_LIMITATION_control_characters_in_query_keys_are_not_normalised_away`.

### 4.4 Values are never inspected

Redaction is key-driven, end to end. Nothing looks at what a value contains.

```python
{"note": "the password is hunter2"}              # -> stored in full
{"url":  "https://x/callback?token=hunter2"}     # -> stored in full
```

*Test:* `test_LIMITATION_secrets_in_values_are_never_detected`.

So: a token pasted into a free-text `note`, `comment` or `description` field; a
webhook URL carrying its own query string; a base64 blob under a benign key; a
stack trace your API echoes back — all stored verbatim. There is no regex pass
over values, on purpose: value-shaped detection has a false-positive rate that
would destroy the audit trail's usefulness and a false-negative rate that would
not let you stop worrying anyway.

### 4.5 Secrets in the URL path are never redacted, and they are searchable

**This is the most serious item in this section after §4.10 and §4.6, and it is
the one most likely to be underestimated, because `path_params` redaction makes
it look handled.** It is recorded at spec level in
[`REQUIREMENTS.md`](REQUIREMENTS.md) §3.

`url.path` is the raw path, verbatim, and it is an **indexed `keyword`**
(`ignore_above: 2048`). That word *indexed* is the whole point of this section.
Compare it with the other unredacted field in the document:

| Field | Redacted? | Mapping | So a secret in it is… |
|---|---|---|---|
| `audit.request.body_raw` (§4.6) | no | `index: false, doc_values: false` | **stored** — in `_source`, visible to anyone who fetches the document |
| `url.path` | no | **indexed `keyword`** | **stored *and* queryable** — `url.path:"/reset/abc123SECRET"` matches, and so does any aggregation, wildcard or terms query over the field |

```
GET /password-reset/confirm/abc123SECRET
  -> url.path = "/password-reset/confirm/abc123SECRET"     (indexed)
```

Being indexed changes who is exposed. An unindexed field leaks to someone
already reading whole audit documents; an indexed one leaks to anyone who can
run a query — including someone who does not know the secret and is *searching
for* it, and including every Kibana visualisation, saved search and CSV export
built over the field. It is also the field an audit index is most routinely
aggregated on, because "which paths were hit" is the first question anyone asks.

A route that *names* the parameter does get its `audit.path_params` entry
redacted — `/keys/{api_key}` yields `path_params: {"api_key": "[REDACTED]"}` —
but **`url.path` still holds the secret in both cases**, because the raw path is
captured before routing and there is no key name to match on inside it. So
`path_params` redaction is not a mitigation for this; it removes the *second*
copy and leaves the searchable one. A positional segment
(`/reset/{token_value}` under a name nobody denylisted, or a route with no
template at all) is not protected at either field.

*Review:* N-3, and REVIEW-2 §5.

> **Pinned — both halves**, in one document, by
> `test_LIMITATION_secret_in_a_named_path_param_is_redacted_but_url_path_still_leaks`:
> it asserts the named parameter *is* redacted and that the raw secret still
> survives in the indexed `url.path` of the same record.
>
> * **No test anywhere puts a secret in a request path.** The two tests this
>   section used to cite do not: `test_AC_07_unmatched_route_is_logged_with_its_404`
>   asserts `url.path == "/no/such/endpoint"` and
>   `test_S_5_the_degraded_document_is_a_hole_marker_not_a_hole` asserts the
>   path on the *degraded* `build_minimal_document` route. Between them they pin
>   that `url.path` is the raw path passed through unchanged — which is the
>   mechanism — but nothing pins the consequence, and nothing would fail if
>   someone added path redaction and left this page saying they had not.
> * **`audit.path_params` redaction has no test of its own.**
>   `test_FR_03_route_and_stringified_path_params` asserts stringification only,
>   and no route in the suite declares a denylisted parameter name. The code
>   does pass the denylist to it (`document._path_params`); nothing asserts the
>   result.
>
> A test for the first would send one request to a path containing a
> secret-shaped segment and assert it is present in `url.path` — the leak, not
> the absence of one — the way `test_LIMITATION_secrets_in_values_are_never_detected`
> does for §4.4.

**What to do about it:** do not put secrets in URL paths. That is good advice
independent of this package — they end up in proxy logs, browser history and
`Referer` headers too — but this package will not save you from it, and here it
makes them searchable rather than merely stored.

### 4.6 A client can choose the one unredacted path, by breaking its own JSON

This is the most important item in this section after §4.10.

A body sent with a JSON content type that fails to parse takes the FR-09
parse-failure branch: `body_parse_failed: true`, and the **raw text** is kept in
`audit.request.body_raw`. That text is **unredacted by construction** — there is
no parsed object to walk, so there are no keys to match on. AC-14 requires the
raw text to be preserved, and AC-05 requires no denylisted value anywhere in the
document; the two conflict on this one path and AC-14 wins.

```
POST /login   Content-Type: application/json
{"password":"hunter2", oops}          <- one trailing token
  -> body_parse_failed: true
  -> body_raw: '{"password":"hunter2", oops}'
```

Any JSON endpoint therefore has an unredacted-storage mode that a client reaches
by appending one byte (review S-2).

**What bounds it:** the kept text is clipped to **4096 characters**
(`document._MAX_UNPARSED_BODY_RAW`). A 1 MiB hostile body yields ~5 KB on disk,
not 1 MiB. And `body_raw` is mapped `index: false, doc_values: false`, so the
value is not *searchable* — it is in `_source`, returned by a `GET` and visible
in the Kibana document viewer, but you cannot query for it.

**What does not bound it:** nothing else. If your threat model includes a client
deliberately planting data in your audit index, this is the hole, and the answer
is access control on the index rather than anything the package can do.

*Tests:* `test_AC_14_broken_json_keeps_the_raw_text`,
`test_AC_14_a_parse_failure_is_the_only_unredacted_body_raw` — the second one is
deliberately named so that anyone "fixing" this without updating this document
gets a failure with an explanation attached. `test_AC_04_*` pins the 4096
clip.

> **DEV-2 — a widened flag.** `audit.request.body_truncated` now means *"what is
> stored is not all of it"* in **two** cases: the `max_body_bytes` cap, and this
> 4096-character clip. It used to mean only the first. Anything counting
> truncations, or alerting on the ratio, is counting both
> (`docs/REQUIREMENTS.md` §2.2).

### 4.7 Non-JSON bodies are not stored at all — and the opt-in scrub is weak

A body that is neither JSON nor form-encoded cannot have a key-based denylist
applied to it. The default is therefore **not to store it**:
`audit.request.body_skipped = "content_type"`, metadata only, no `body`, no
`body_raw` (FR-28).

This is the fix for review M-1, which was the most serious finding in the
adversarial review: `Content-Type: text/plain` on a JSON payload — or **no
content type at all** — used to store the whole body verbatim with the denylist
never consulted. `navigator.sendBeacon()` sends `text/plain` by default.

*Test:* `test_AC_18_a_body_the_denylist_cannot_reach_is_not_stored`,
parametrized over `text/plain`, `application/xml`, and no content type.

`capture_text_bodies=True` opts a service back in, after a **best-effort textual
scrub**. Be honest with yourself about what that scrub is: six regexes that know
four shapes — `"key": "value"`, `key: value` on its own line, `key=value`, and
`<key>value</key>` — and rewrite the value when the key normalizes onto the
denylist. It catches the obvious cases
(`test_M_1_capture_text_bodies_scrubs_the_four_known_shapes` covers JSON
mislabelled as text, form-ish text, YAML-ish lines, XML/SOAP leaf elements and a
GraphQL argument).

It **misses**, and each of these is a real gap, not a hypothetical one:

* **prose** — "the password is hunter2" has no key shape at all. Pinned;
* **positional CSV columns** — `name,ssn\na.karimov,123-45-6789` is stored in
  full, which the test asserts explicitly
  (`test_FR_28_the_scrub_is_documented_as_weaker_than_the_structured_path`);
* **nested XML** — the pattern matches leaf elements only, so a secret inside a
  wrapper element with its own children survives. Pinned (namespaced form);
* **namespace-prefixed XML** — `_SCRUB_KEY` is `[A-Za-z0-9_.\-]{1,64}` and
  excludes `:`, so **every namespaced element is invisible to the scrub**:
  `<Password>hunter2</Password>` is caught, `<ns:Password>hunter2</ns:Password>`
  and `<wsse:Password>hunter2</wsse:Password>` are not. `<wsse:Password>` is the
  literal element name in WS-Security, and namespace prefixes are the norm in
  SOAP rather than the exception — so a service that enables this flag
  *specifically to capture its SOAP traffic* gets the passwords in the clear.
  This is `REVIEW-2.md` N2-7 and it is the gap most likely to matter in
  practice. Pinned;
* **multi-line values** — the `key: value` pattern stops at the end of the line,
  so a YAML block scalar (`password: |` followed by an indented line) leaks its
  body. Pinned;
* **anything cut by truncation or by the length bound** — past
  `max_scrub_bytes` (32 KiB) the body is refused as `too_complex` rather than
  half-scrubbed, which is the safe direction, but it means large text bodies are
  simply not captured. Pinned.

Two more properties of the scrub's *output*, worth knowing before you read one
as evidence:

* **The literal `[REDACTED]` is forgeable.** A client can put that string in a
  text body and it survives verbatim, so on this path — unlike the structured
  one — you cannot tell "the package redacted this" from "the client wrote
  this". Pinned.
* **The scrub can over-redact its own output.** The last two patterns can match
  a replacement the earlier ones made, producing a stray extra `]`
  (`Cookie: [REDACTED]]`). Harmless and stable under re-application — it can
  only ever redact more — but it is a visible defect in stored evidence.

If a service turns this on, it is choosing "some visibility into text bodies,
with a known leak rate" over "no text bodies". Make that choice explicitly,
write it down, and prefer sending JSON. If your text bodies are SOAP, read the
namespace bullet again before you decide.

### 4.8 A PII filename under an innocuous field name is undetectable

Multipart bytes are never stored (FR-07/D-5, verified). The *metadata* is:
part `name`, `filename`, `content_type` and `size`. A `filename` is redacted
when its part `name` is denylisted (review N-7), but:

```
Content-Disposition: form-data; name="attachment"; filename="ssn-list-2026.csv"
  -> {"name": "attachment", "filename": "ssn-list-2026.csv", ...}
```

`attachment` is not on any denylist and never will be. Filenames routinely carry
names, dates of birth and national IDs. **A key denylist cannot detect this**,
by construction. If your service accepts uploads whose filenames are
user-supplied, that is a thing to know about your audit index.

Part metadata strings are clipped to 256 characters and the number of part
records to `max_multipart_parts` (256), so the exposure is bounded in size but
not in kind.

*Tests:* the behaviour is pinned, though not by a `test_LIMITATION_*` — a
filename under a **non**-denylisted part name is asserted to be stored verbatim
by `test_middleware.py::test_FR_07_multipart_records_metadata_only` (part name
`"upload"`, `filename` `"secret.txt"`, asserted present) and
`test_document.py::test_FR_07_multipart_metadata_only` (part name `"upload"`,
`filename` `"a.bin"`). The inverse — redaction under a denylisted part name — is
`test_N_7_a_filename_under_a_denylisted_part_name_is_redacted`. Be aware that
the two FR-07 tests exist to assert *metadata-only capture*, not to assert this
limitation, so someone adding filename redaction would update them without
necessarily arriving here.

### 4.9 Over-redaction is irreversible

Six default keys are broad by mandate: `hash`, `salt`, `sig`, `pan`, `session`,
`auth`.

```python
{"hash": "git-abc123", "pan": "fried"}   # -> both "[REDACTED]"
```

*Test:* `test_LIMITATION_denylisted_keys_are_over_redacted` — which exercises
**`hash` and `pan` only**. The other four (`salt`, `sig`, `session`, `auth`) are
pinned one step weaker, as membership in the default set, by
`test_FR_11_required_default_keys_are_present`. Membership implies the
behaviour, since `redact` treats every entry identically, but no test
demonstrates it for those four.

If a benign field of yours is named any of those, its value is gone from every
document, and FR-13 makes the denylist additive-only — **there is no opt-out.**
The only remedy is to rename the field in your API. This is a deliberate trade:
a wrong "redact" default costs you a field; a wrong "do not redact" default
costs you a disclosure you cannot undo.

### 4.10 PII is NOT redacted by default (the one most likely to bite you)

```python
{"email": "a@b.c", "phone": "+998901234567", "date_of_birth": "1990-01-01"}
# -> stored, all three, in full
```

*Test:* `test_LIMITATION_pii_is_not_redacted_by_default`.

Also not on the list: `name`, `full_name`, `address`, `city`, `postcode`,
`ip_address`, `user_agent` values, order contents, free text.

**This was a deliberate decision, and the reasoning is worth understanding
before you disagree with it.** Because extension is additive-only, a default the
package gets *wrong in the redacting direction* can never be undone by a
service: if `email` were on the list, every service auditing a signup flow would
permanently lose the field that makes the record useful, and would have no
supported way to get it back. Identity fields are also frequently the whole
point of an audit trail — "who did this" is usually a name or an email.

The consequence is that **the compliance decision is yours, per service, and it
has to be made before the first request.** Retention is 90 days
(`infra/elasticsearch/ilm-apiaudit.json`) and there is no un-storing.

```python
AuditConfig(
    service_name="orders-api",
    extra_redact_keys=[
        "email", "phone", "mobile", "name", "full_name", "first_name",
        "last_name", "address", "street", "postcode", "date_of_birth", "dob",
    ],
)
```

Note that this only redacts those **keys**. It does nothing about an email
appearing inside a free-text value ([§4.4](#44-values-are-never-inspected)) or
in a filename ([§4.8](#48-a-pii-filename-under-an-innocuous-field-name-is-undetectable)).

### 4.11 Truncation loses benign data too

Past the depth-20 cap, everything goes — harmless values included. Same trade as
§4.9: safety over fidelity.

*Tests:* `test_depth_cap_default_is_20` is the one to rely on — it asserts
`redact(_nest(20, MARKER)) == _nest(20, TRUNCATED)` **and**
`redact(_nest(19, MARKER)) == _nest(19, MARKER)`, so it fails if the cap moves
in either direction or if the `[TRUNCATED]` marker is renamed.
`test_depth_cap_replaces_the_deep_subtree` and
`test_depth_cap_deep_values_do_not_survive` pin the same thing at other depths
and for list levels.

`test_LIMITATION_truncation_loses_data_not_just_secrets` is the test this
section used to cite alone, and it is a **weak pin**: its whole body is
`assert redact(_nest(21, {"harmless": 1}), KEYS) != _nest(21, {"harmless": 1})`.
An inequality passes unchanged if truncation is silently made *worse* — the cap
lowered, the marker renamed, more aggressive dropping — and fails only if the
limitation is fixed. It is kept for its name; the assertions above are what
actually hold the behaviour still (`REVIEW-2.md` §5).

### 4.12 What redaction is not for at all

Recorded so nobody assumes otherwise. This list used to cite nothing at all;
four of the five claims turn out to be tested, and the one that is not is marked.

* **Response bodies are never captured** (D-3), so nothing in a response is
  redacted, because nothing in a response is stored. The response byte *count*
  and the allowlisted response headers are.
  *Tests:* `test_FR_05_response_status_headers_and_bytes` (asserts the response
  body's bytes are absent from the whole serialised document) and
  `test_acceptance_local.py::test_FR_05_response_bodies_are_never_stored`
  (asserts `audit.response` has exactly the key `headers`).
* **Uploaded file bytes are never captured** (D-5).
  *Tests:* `test_FR_07_multipart_records_metadata_only` and
  `test_document.py::test_FR_07_multipart_metadata_only`, both asserting a
  planted marker in the part payload is absent from the document.
* **Stack traces are never captured.** `error.type` and a 1024-character
  `error.message` are. If your exception messages carry secrets, those reach
  the index.
  *Tests:* `test_no_stack_trace_is_ever_stored` (asserts `error` has exactly
  `type` and `message`, and that `"Traceback"` appears nowhere) and
  `test_error_message_is_truncated_to_1024_chars`.
* **`client.ip` is the transport peer**, not `X-Forwarded-For`. The header is
  captured verbatim when allowlisted; deciding the true client IP is the
  ingress's job.
  Pinned by `test_LIMITATION_client_ip_is_the_transport_peer_not_x_forwarded_for`,
  which sends the header and asserts it loses. Previously every `client.*` assertion read back the ASGI
  `scope["client"]` tuple; no test sends an `X-Forwarded-For` or `X-Real-IP`
  header and asserts `client.ip` ignores it. If a future change started
  honouring the header, nothing would fail and this line would quietly become
  false — which matters, because a reader making a trust decision about
  `client.ip` is doing so on the strength of this sentence.
* **Redaction is not encryption or access control.** Everything in the index is
  readable by everyone with access to the index, for 90 days. Not a testable
  claim; it is a property of the deployment, not of the code.

---

## 5. Choosing `extra_redact_keys` for your service

A ten-minute exercise that is worth doing properly once:

1. **List your request models.** Every field name that reaches a body, a query
   string or a named path parameter.
2. **Mark the ones carrying a secret or credential** under a spelling not in
   `DEFAULT_REDACT_KEYS`. Remember §4.2: `user_password_2` is not covered by
   `password`.
3. **Mark the ones carrying PII** your compliance answer says you may not retain
   for 90 days (§4.10).
4. **Check §4.9 in reverse** — is anything of yours called `hash`, `salt`,
   `sig`, `pan`, `session` or `auth` that you actually need to read later? If
   so, rename it now; you cannot opt out later.
5. **Set `extra_redact_keys` from steps 2 and 3**, and write down in your own
   service's docs why each entry is there.
6. **Verify.** Send one request per marked field through a `NullSink` and assert
   the value is absent from `json.dumps(document)` — that is exactly what AC-05
   does. See [`integration.md`](integration.md) §5.1.

## 6. Where each protection applies — one table

| Captured thing | Denylist | Allowlist | Not protected |
|---|:--:|:--:|---|
| JSON body (parseable) | ✅ every depth | | interior-whitespace / homoglyph / unenumerated keys; secrets in values |
| JSON body (parse failed) | | | **nothing** — raw text, clipped to 4096 chars (§4.6) |
| Form-encoded body | ✅ (`;` and `&`, keys stripped) | | as above |
| Text/XML body, default | | | not stored at all |
| Text/XML body, `capture_text_bodies` | best effort only | | prose, CSV columns, nested XML, **namespaced XML (`<wsse:Password>`)**, multi-line values (§4.7) |
| Multipart metadata | ✅ part names matched; a `filename` under a denylisted `name` is replaced | | a PII filename under a benign part name (§4.8). Note a part `name` is *matched* against the denylist but never redacted itself |
| Binary body | | | not stored at all |
| Query string (both `url.query` and `audit.request.query`) | ✅ | | secrets in values; control characters in keys (§4.3). Over `max_query_bytes` / 512 pairs the whole query is dropped for `"[SKIPPED]"` (§2.1) |
| Path params (`audit.path_params`) | ✅ (§4.5) | | positional segments |
| `url.path` | | | **nothing** (§4.5) — and it is an **indexed** `keyword`, so a secret there is searchable, not merely stored |
| Request headers | | ✅ 35 names | a credential under an allowlisted name you added |
| Response headers | | ✅ same list | as above |
| Response body | n/a | n/a | never captured |
| `error.message` | | | first 1024 characters, verbatim |

## 7. If you find a new gap

Add a `test_LIMITATION_*` next to the others in `tests/unit/test_redact.py`
asserting the leak, and add a section here. A limitation that is asserted in a
test and written down is a documented trade; the same limitation undocumented is
an incident waiting to happen. That is the standard this file exists to hold.

Three rules learned from the verification pass, because this file failed all
three at least once:

1. **Assert the leak, not a proxy for it.** A test citing a limitation must
   contain the thing that leaks. `test_AC_07_unmatched_route_is_logged_with_its_404`
   was cited for §4.5 and has no secret in it; two multipart tests genuinely do
   pin §4.8 because they contain a filename under a benign part name.
2. **Assert equality, not inequality.** `assert redact(x) != x` (the old §4.11
   pin) still passes if the behaviour gets *worse*. Assert the exact expected
   output, so the test fails in both directions.
3. **If no test exists, say so here — do not delete the section.** A limitation
   you have stopped testing and stopped writing down is one you will rediscover
   in an incident. `⚠ unpinned` is an honest state; a missing section is not.
