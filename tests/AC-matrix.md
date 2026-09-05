# AC / FR traceability matrix

| | |
|---|---|
| Owner | Agent A6 — integration & load tests |
| Sources | `docs/REQUIREMENTS.md` §1 (FR-01…FR-31, NFR-1…NFR-6) and §2 (AC-01…AC-26, §2.1, §2.2) |
| Covers | `tests/unit/**` (A2–A4), `tests/integration/**`, `tests/load/**` |
| Status | Tier 2 and the load test **executed and passing**. Tier 1 **never executed** — see §5. |
| Rewritten | After the adversarial review and the three fix passes — see §7 for what moved |

This file is meant to be the single place to look. It is complete in both
directions: every AC in `docs/REQUIREMENTS.md` §2 appears in §2 here, every FR
and NFR in §1 appears in §3 here, and everything that is *not* covered is named
in §4 rather than left implied.

**Read §4 before trusting §2.** Several criteria are covered in part, and the
part that is missing is named there rather than papered over with a weaker
assertion carrying the AC's number.

---

## 1. The two tiers

| | Tier 2 — `tests/integration/test_acceptance_local.py` | Tier 1 — `tests/integration/test_acceptance_es.py` |
|---|---|---|
| Asserts against | the real `FileSink` JSONL, validated by an in-process double that applies the real `infra/elasticsearch/template-apiaudit.json` | a real Elasticsearch 8.13.4 behind a real Filebeat 8.13.4 |
| Marker | none — part of the default run | `@pytest.mark.integration` |
| Executed? | **yes**, 60 tests passing | **no** — Docker is unreachable here (§5) |
| Size | 60 tests | 31 tests, collect cleanly, all skip |
| Command | `./.venv/bin/python -m pytest tests/integration -q -m "not integration"` | `./.venv/bin/python -m pytest tests/integration -q -m integration` |

The Tier 2 double is **stricter than Elasticsearch in one direction and now a
faithful model in another**, and the difference matters:

* **Stricter.** A field the template does not declare raises
  `UnmappedFieldError`. Real Elasticsearch with `dynamic: false` accepts it,
  stores it in `_source`, and silently never indexes it (`infra/README.md` §5).
  So a document that passes Tier 2 is one that is wholly *searchable* in
  production, not merely one that is accepted.
* **Faithful, since the review.** The double used to model
  `index.mapping.ignore_malformed` as covering every type, so every type
  mismatch was recorded in `malformed` and the document was indexed anyway.
  Review addendum S-15/S-16 pointed out that this green-lights two real
  defects. It now raises `DocumentRejectedError` — and does **not** index the
  document — for everything a cluster answers with an error:

  | Rejected (document lost) | Modelled because |
  |---|---|
  | an object in a `keyword`/`constant_keyword`/`text` field | **M-5**: `ignore_malformed` covers numerics, boolean, date, ip and geo only |
  | a `constant_keyword` value other than the pinned one | same family; ES throws `illegal_argument_exception` |
  | a `flattened` leaf whose `key + NUL + value` exceeds 32,766 bytes | **N-9**: `FlattenedFieldParser.addField` throws before it looks at `index`/`doc_values` |
  | a NUL byte in a `flattened` key | the parser's own key/value separator — 15 bytes of body costs the record |
  | a non-object in a `flattened` field, or past its `depth_limit` | `mapper_parsing_exception` |
  | an object mapper handed a scalar | `mapper_parsing_exception` |

  `malformed` is now reserved for the types `ignore_malformed` really covers.
  Tests assert both lists are empty; silence is the failure mode either way.

What the double still does **not** model is §4.5.

---

## 2. AC → FR → test (both directions start here)

Legend for **Verified**: `T2 ✅` = Tier 2 written **and passing here**;
`T1 ⬜` = Tier 1 written, collects cleanly, and **has never been executed** (§5);
`⚠` = covered in part, with the missing clause named in §4.3.
No AC in this table is currently verified against a real Elasticsearch.

### 2.1 AC-01…AC-17 — the original criteria

| AC | FR | Tier 2 test | Tier 1 test | Verified | Supporting unit tests |
|---|---|---|---|---|---|
| **AC-01** | FR-01 | `test_AC_01_one_document_per_request`, `test_AC_01_the_document_is_fully_mapped` | `test_AC_01_one_document_per_request`, `…_the_data_stream_uses_our_template_not_a_dynamic_one`, `…_filebeat_dropped_its_own_metadata` | T2 ✅ · T1 ⬜ | `test_middleware.py::test_FR_01_*` (5) |
| **AC-02** | FR-02 | `test_AC_02_excluded_path_produces_no_document`, `…_an_audited_path_still_works_alongside` | `test_AC_02_excluded_path_produces_no_document` | T2 ✅ · T1 ⬜ | `test_middleware.py::test_FR_02_*` (2) |
| **AC-03** | FR-04 | `test_AC_03_json_body_is_replayed_and_parsed`, `…_the_body_costs_exactly_one_mapping_field` | `test_AC_03_json_body_is_replayed_and_parsed`, `…_the_flattened_body_is_searchable_by_subkey`, `…_body_raw_is_stored_but_not_searchable`, `…_parseable_json_emits_no_body_raw_at_all` | T2 ✅ · T1 ⬜ | `test_middleware.py::test_FR_04_*` (3) |
| **AC-04** | FR-08 | `test_AC_04_oversized_body_is_truncated_but_replayed_in_full` | `test_AC_04_oversized_body_is_truncated_but_replayed_in_full` | T2 ✅ · T1 ⬜ ⚠ §4.3 | `test_middleware.py::test_FR_08_*` (2), `test_document.py::test_FR_08_*` (1) |
| **AC-05** | FR-10, FR-11 | `test_AC_05_denylisted_values_are_replaced_everywhere`, `…_no_secret_appears_anywhere_in_the_document`, `…_the_application_object_is_not_mutated` | `test_AC_05_denylisted_values_are_replaced_everywhere`, `…_no_secret_is_anywhere_in_the_indexed_document` | T2 ✅ · T1 ⬜ | `test_redact.py::test_FR_10_*` (2), `::test_FR_11_*` (5) + property tests |
| **AC-06** | FR-12 | `test_AC_06_credential_headers_never_appear` | `test_AC_06_credential_headers_never_appear` | T2 ✅ · T1 ⬜ | `test_redact.py::test_FR_12_*` (9), `test_document.py::test_FR_12_*` (1) |
| **AC-07** | FR-03 | `test_AC_07_unmatched_route_is_logged_with_its_404` | `test_AC_07_unmatched_route_is_logged_with_its_404` | T2 ✅ · T1 ⬜ | `test_middleware.py::test_FR_03_*` (3), `test_document.py::test_FR_03_*` (3) |
| **AC-08** | FR-01, NFR-3 | `test_AC_08_application_exception_propagates_and_is_logged` | `test_AC_08_application_exception_propagates_and_is_logged` | T2 ✅ · T1 ⬜ | `test_middleware.py::test_NFR_3_*` (3) |
| **AC-09** | FR-19 | `test_AC_09_full_queue_drops_documents_and_serves_every_request` | `test_AC_09_full_queue_drops_documents_and_serves_every_request` | T2 ✅ · T1 ⬜ ⚠ §4.3 | `test_file_sink.py::test_FR_19_*` (4), `::test_FR_18_*` (4) |
| **AC-10** | mapping bound | `test_AC_10_fifty_endpoints_two_hundred_requests_stay_under_the_bound` | `test_AC_10_fifty_endpoints_two_hundred_requests_stay_under_the_bound` | T2 ✅ · T1 ⬜ ⚠ §4.3 | — (§2.3 has the numbers) |
| **AC-11** | FR-15 | `test_AC_11_kill_switch_produces_no_document_and_no_file` | `test_AC_11_kill_switch_produces_no_document_and_no_file` | T2 ✅ · T1 ⬜ | `test_config.py::test_FR_15_*`, `test_middleware.py::test_FR_15_*` (2) |
| **AC-12** | FR-22 | `test_AC_12_rotation_keeps_every_line` | `test_AC_12_every_line_survives_three_rotations` | T2 ✅ · T1 ⬜ ⚠ §4.3 | `test_file_sink.py::test_FR_22_*` (7) |
| **AC-13** | FR-06 | `test_AC_13_streaming_duration_reaches_the_last_chunk` | `test_AC_13_streaming_duration_reaches_the_last_chunk` | T2 ✅ · T1 ⬜ | `test_middleware.py::test_FR_06_*` (2) |
| **AC-14** | FR-09 | `test_AC_14_broken_json_keeps_the_raw_text`, `…_a_parse_failure_is_the_only_unredacted_body_raw` | `test_AC_14_broken_json_keeps_the_raw_text` | T2 ✅ · T1 ⬜ | `test_middleware.py::test_FR_09_*` (5), `test_document.py::test_FR_09_*` (6) |
| **AC-15** | FR-20r | `test_AC_15_a_thousand_documents_land_within_the_interval` | `test_AC_15_a_thousand_documents_land_within_the_interval` | T2 ✅ · T1 ⬜ ⚠ §4.3 | `test_file_sink.py::test_FR_20r_*` (10) |
| **AC-16** | FR-21r | `test_AC_16_unwritable_log_dir_never_reaches_the_request_path` | `test_AC_16_unwritable_log_dir_never_reaches_the_request_path` | T2 ✅ · T1 ⬜ ⚠ §4.3 | `test_file_sink.py::test_FR_21r_*` (6) |
| **AC-17** | FR-25 | `test_AC_17_raising_user_resolver_still_produces_the_document`, `…_a_working_resolver_populates_only_id_name_roles` | `test_AC_17_raising_user_resolver_still_produces_the_document` | T2 ✅ · T1 ⬜ | `test_middleware.py::test_FR_25_*` (4), `test_document.py::test_FR_25_*` (2) |

### 2.2 AC-18…AC-26 — added after the adversarial review

| AC | FR | Tier 2 test | Tier 1 test | Verified | Supporting unit tests |
|---|---|---|---|---|---|
| **AC-18** *(M-1)* | FR-28 | `test_AC_18_a_body_the_denylist_cannot_reach_is_not_stored` **[3 params: `text/plain`, `application/xml`, no content type]**, `…_capture_text_bodies_is_the_only_way_in_and_it_scrubs` | `test_AC_18_a_body_the_denylist_cannot_reach_never_reaches_the_index` **[same 3]** | T2 ✅ · T1 ⬜ | `test_document.py::test_FR_28_*` (8), `test_middleware.py::test_FR_28_*` (2) |
| **AC-19** | FR-29 | `test_AC_19_a_1MiB_shape_bomb_is_refused_as_too_complex` | — | T2 ✅ ⚠ §4.3 | `test_document.py::test_FR_29_*` (4) |
| **AC-20** *(M-3)* | FR-30 | `test_AC_20_body_and_body_raw_are_never_both_present` (all nine §2.9 rows), `…_a_1MiB_body_produces_a_line_under_message_max_bytes`, `…_the_acceptance_stacks_disk_queue_can_hold_that_line` | `test_AC_20_a_1MiB_body_survives_the_whole_pipeline`, `…_nothing_was_quarantined_as_undecodable` | T2 ✅ · T1 ⬜ | `test_document.py::test_FR_30_*` (2) |
| **AC-21** *(M-5)* | FR-31 | `test_AC_21_user_values_are_coerced_to_the_types_the_schema_declares`, `…_every_user_value_matches_schema_2_5`, `…_the_uncoerced_shape_really_would_have_lost_the_document` | `test_AC_21_a_hostile_user_resolver_does_not_cost_the_document`, `…_the_uncoerced_shape_really_is_rejected_by_elasticsearch`, `…_a_flattened_key_over_the_lucene_term_limit_is_rejected` | T2 ✅ · T1 ⬜ | `test_document.py::test_FR_31_*` (3) |
| **AC-22** *(M-4)* | FR-08 | `test_AC_22_buffering_a_dribbled_body_stays_under_twice_the_cap`, `…_the_client_does_not_choose_our_memory` | — | T2 ✅ ⚠ §4.3 | `test_middleware.py::test_FR_08_*` (2) |
| **AC-23** | FR-05, FR-24 | `test_AC_23_a_204_and_a_HEAD_are_logged_with_zero_response_bytes` | — | T2 ✅ ⚠ §4.3 | `test_middleware.py::test_FR_05_*` (3), `::test_FR_24_*` (3) |
| **AC-24** | FR-13, FR-14 | `test_AC_24_an_extra_key_redacts_in_both_the_query_and_the_body`, `…_every_default_denylist_key_still_redacts_alongside_an_extra` | — | T2 ✅ | `test_redact.py::test_FR_13_*` (2), `::test_FR_14_*` (1), `test_document.py::test_FR_13_*` (2), `::test_FR_14_*` (1) |
| **AC-25** *(S-10)* | FR-22, FR-26 | `test_AC_25_no_file_exceeds_file_max_bytes_by_more_than_one_line` (bound clause, `file_backup_count=8`), `…_every_line_survives_when_the_backup_count_can_hold_them` (survival clause, `file_backup_count=64`) | — | T2 ✅ ⚠ §4.3 | `test_file_sink.py::test_FR_22_*` (7) |
| **AC-26** *(S-9)* | FR-18, FR-27 | `test_AC_26_close_returns_in_time_and_counts_each_lost_document_once` | — | T2 ✅ ⚠ §4.3 | `test_file_sink.py::test_FR_27_*` (7), `::test_FR_18_*` (4), `::test_FR_21r_*` (6) |

AC-19, AC-22, AC-23, AC-24, AC-25 and AC-26 have **no Tier 1 counterpart on
purpose**: every clause of each is about the package's own behaviour (parse
bounds, buffer size, byte counts, denylist extension, rotation on disk, counter
arithmetic). Routing them through Filebeat and Elasticsearch would add latency
and flakiness and settle nothing. The three that *do* have Tier 1 tests —
AC-18, AC-20, AC-21 — each have a clause a cluster is the only oracle for:
"the secret is not in the index", "the 1 MiB line is not truncated by
Filebeat", "the uncoerced document is rejected".

### 2.3 AC-10 — the measured numbers

Tier 2, executed:

```
50 endpoints × 200 requests = 10 000 documents, every request carrying keys
no other request uses.

  mapped fields reached                             51   (limit: 200)
  fields declared by the template                   62   (a constant: dynamic:false)
  fields a dynamic:true mapping would have created  20 194
```

`flattened` absorbs ~20 100 would-be fields into six mapping entries
(`audit.path_params`, `audit.request.{headers,query,body,multipart}`,
`audit.response.headers`). The test asserts **both** directions — that the real
count is under the bound *and* that the fan-out was large enough for the result
to mean something (`> 200` under a dynamic mapping) — so it cannot pass
vacuously.

Tier 1 asks Elasticsearch the same question via `GET _field_caps?fields=*` and
checks `index_failed == 0` on every node. Not executed.

### 2.4 The other measured numbers, from the passing run

```
AC-15  1000 documents submitted in 5.1 ms, on disk 1021 ms later (budget 1.5 s)
AC-19  1 MiB shape bomb refused in 1.5 ms round trip (review M-2 measured 140 ms of parsing)
AC-20  1 MiB body, stored whole   ->  1 049 779 B line = 12.5 % of message_max_bytes
       1 MiB of quotes, stored    ->  1 049 779 B line = 12.5 %
       1 MiB cut mid-JSON         ->      5 296 B line (4096-char clip)
       1 MiB of raw control bytes ->     25 730 B line (4096-char clip; A5's 6x case)
AC-22  4 × 128 KiB dribbled in 2-byte chunks peaked at 0.30 MB
       (budget 1.05 MB; a list of chunks would have been ~9 MB)
       peak with 64 KiB chunks 3.01 MB vs 2 B chunks 3.02 MB = 1.00x
AC-25  bound:    9 files, largest 65 144 B against a 65 536 B cap + one 1 387 B line,
                 42 rotations at file_backup_count=8
       survival: 2000 documents / ~2 770 951 B (1385 B/line) across 42 rotated
                 files at file_backup_count=64, every line present and in order
AC-26  122 documents actually lost, audit_documents_failed_total = 122 (not 244),
       close() returned in 0 ms against a 2 s timeout
```

---

## 3. FR → AC → test (the other direction, complete)

Every functional requirement in `docs/REQUIREMENTS.md` §1, whether or not an AC
names it. "Tier 2" means executed and passing; any mention of "Tier 1" means
written but **not executed** (§5).

| FR | AC | Unit tests | Integration coverage |
|---|---|---|---|
| **FR-01** one document per request; non-`http` scopes pass through | AC-01, AC-08 | `test_middleware.py::test_FR_01_*` (5) | Tier 2 + Tier 1 AC-01, AC-08; AC-23 for a bodiless response |
| **FR-02** `exclude_paths`, raw path, no wrapping | AC-02 | `::test_FR_02_*` (2) | Tier 2 + Tier 1 AC-02 |
| **FR-03** request metadata, route after the app returns | AC-07 | `::test_FR_03_*` (3), `test_document.py::test_FR_03_*` (3) | Tier 2 + Tier 1 AC-07; route asserted in AC-01 too |
| **FR-04** body capture + byte-identical replay | AC-03 | `::test_FR_04_*` (3) | Tier 2 + Tier 1 AC-03, AC-04, AC-14; AC-18 asserts replay survives the FR-28 skip |
| **FR-05** response status/headers/byte count, **no response bodies** | AC-23 | `::test_FR_05_*` (3) | Tier 2 `test_FR_05_response_bodies_are_never_stored`, AC-13, AC-23 |
| **FR-06** `event.duration` ns, to the last chunk | AC-13 | `::test_FR_06_*` (2) | Tier 2 + Tier 1 AC-13 |
| **FR-07** multipart / binary → metadata only | *(none — see §4.1)* | `::test_FR_07_*` (2), `test_document.py::test_FR_07_*` (4) | Tier 2 `test_every_body_kind_indexes_cleanly`, AC-20's §2.9 sweep |
| **FR-08** truncation at `max_body_bytes`; bounded RSS | AC-04, AC-22 | `::test_FR_08_*` (2), `test_document.py::test_FR_08_*` (1) | Tier 2 + Tier 1 AC-04; Tier 2 AC-22 |
| **FR-09** JSON parse, parse failure, non-object wrapping | AC-14 | `::test_FR_09_*` (5), `test_document.py::test_FR_09_*` (6) | Tier 2 + Tier 1 AC-14; `test_every_body_kind_indexes_cleanly` covers `{"_value": …}` |
| **FR-10** redaction is pure, applied before submit; a body it cannot reach is not stored | AC-05, AC-18 | `test_redact.py::test_FR_10_*` (2) + property test | Tier 2 `test_AC_05_the_application_object_is_not_mutated`, AC-18 |
| **FR-11** default denylist, normalized keys, every depth | AC-05 | `test_redact.py::test_FR_11_*` (5) + 5 property tests | Tier 2 + Tier 1 AC-05; Tier 2 AC-24 sweeps the whole default list |
| **FR-12** headers by allowlist; dropped ones vanish | AC-06 | `test_redact.py::test_FR_12_*` (9) | Tier 2 + Tier 1 AC-06 |
| **FR-13** `extra_redact_keys` / `extra_header_allowlist`, additive only | AC-24 | `test_redact.py::test_FR_13_*` (2), `test_document.py::test_FR_13_*` (2) | Tier 2 `test_FR_13_extra_redact_keys_and_headers_are_additive`, AC-24 (both tests) |
| **FR-14** query params use the same denylist | AC-24 | `test_redact.py::test_FR_14_*` (1), `test_document.py::test_FR_14_*` (1) | Tier 2 AC-05, AC-24, `test_every_body_kind_indexes_cleanly` |
| **FR-15** kill switch | AC-11 | `test_config.py::test_FR_15_*`, `test_middleware.py::test_FR_15_*` (2) | Tier 2 + Tier 1 AC-11 |
| ~~FR-16, FR-17~~ | — | — | **Deleted** by plan §2 (no sampling). Correctly absent everywhere. |
| **FR-18** queue bounded in **bytes** | AC-09, AC-26 | `test_file_sink.py::test_FR_18_*` (4) | Tier 2 + Tier 1 AC-09; Tier 2 AC-26 ⚠ §4.3 |
| **FR-19** drop + count when the queue is full | AC-09 | `::test_FR_19_*` (4) | Tier 2 + Tier 1 AC-09 |
| **FR-20r** one background task, interval or size, submission order | AC-15 | `::test_FR_20r_*` (10) | Tier 2 + Tier 1 AC-15; order across rotation in AC-12 and AC-25 |
| **FR-21r** write failure counted, one retry, logged once | AC-16 | `::test_FR_21r_*` (6) | Tier 2 + Tier 1 AC-16; Tier 2 AC-26 asserts the count is not doubled |
| **FR-22** rotation, backup count | AC-12, AC-25 | `::test_FR_22_*` (7) | Tier 2 + Tier 1 AC-12; Tier 2 AC-25 (both clauses) |
| **FR-23** `trace.id` from `X-Request-ID` or UUID4 | *(none — see §4.1)* | `test_middleware.py::test_FR_23_*` (3) | Tier 2 `test_FR_23_and_FR_24_the_trace_id_round_trips`; Tier 1 relies on it for **every** lookup |
| **FR-24** `X-Request-ID` on the response, the only mutation | AC-23 | `::test_FR_24_*` (3) | Tier 2 `test_FR_23_and_FR_24_…`, AC-23 (asserts it appears exactly once); Tier 1 AC-01 |
| **FR-25** `user_resolver` | AC-17 | `::test_FR_25_*` (4), `test_document.py::test_FR_25_*` (2) | Tier 2 + Tier 1 AC-17, AC-21 |
| **FR-26** `{service}-{pid}.jsonl`, `-{6 hex}` on a live collision | AC-25 | `test_file_sink.py::test_FR_26_*` (5) | Tier 2 `test_FR_26_the_file_is_named_for_the_service_and_the_pid`, `…_a_second_live_sink_takes_a_collision_suffix`, `…_both_name_forms_survive_filebeats_glob_and_rotation_exclude` |
| **FR-27** `close()` drains within the timeout, returns regardless | AC-26 | `::test_FR_27_*` (7) | Tier 2 `test_FR_27_close_drains_what_is_queued`, AC-26 |
| **FR-28** non-JSON bodies are metadata-only; `capture_text_bodies` opts in | AC-18 | `test_document.py::test_FR_28_*` (8), `test_middleware.py::test_FR_28_*` (2) | Tier 2 + Tier 1 AC-18; Tier 2 `test_every_body_kind_indexes_cleanly` |
| **FR-29** `max_body_nodes`, `max_multipart_parts` | AC-19 | `test_document.py::test_FR_29_*` (4) | Tier 2 AC-19, AC-20's §2.9 sweep. `max_multipart_parts` is unit-only — §4.2 |
| **FR-30** `body` and `body_raw` are mutually exclusive | AC-20 | `test_document.py::test_FR_30_*` (2) | Tier 2 AC-20 (all nine §2.9 rows), AC-04, AC-14, AC-18; Tier 1 AC-03, AC-20 |
| **FR-31** `user.*` coerced to schema §2.5's types | AC-21 | `test_document.py::test_FR_31_*` (3) | Tier 2 + Tier 1 AC-21 |
| **NFR-1** added p99 ≤ 5 ms @ 100 rps, 8 KB | *(none — see §4.1)* | `test_middleware.py::test_overhead_per_request_microseconds` (in-process, `NullSink`, identity redaction), `test_file_sink.py::test_submit_is_fast_enough_for_the_request_path` | `tests/load/test_nfr1_latency.py` — **measured, §6** |
| **NFR-2** nothing on the request path awaits, locks, or allocates unboundedly | AC-22 (allocation half) | `test_contracts.py::test_no_awaits_hide_behind_submit_in_the_package`, `::test_submit_is_synchronous`, `test_file_sink.py::test_submit_is_fast_enough_for_the_request_path` | Tier 2 AC-22; load test: 0 dropped, 0 failed, 0 middleware errors under load |
| **NFR-3** no package exception ever reaches the app | AC-08 | `test_middleware.py::test_NFR_3_*` (3) | Tier 2 + Tier 1 AC-08, AC-09, AC-16, AC-17 |
| **NFR-4** no network client imported | *(none)* | `test_contracts.py::test_no_network_client_is_importable_from_the_package`, `test_file_sink.py::test_no_network_client_is_imported` | Not re-tested; a source-level property, asserted at unit level |
| **NFR-5** `mypy --strict` | *(none)* | not a test — `./.venv/bin/python -m mypy --strict audit_logging` | Owned by the package agents; A6 does not re-run it as an acceptance gate |
| **NFR-6** dependency limits | *(none)* | not a test — `pyproject.toml` | Not tested. §4.2. |

### 3.1 Known deviations (`docs/REQUIREMENTS.md` §2.2) and where they show up

| Deviation | Where a test pins it |
|---|---|
| **DEV-1** — the true received-byte count travels through `scope["audit_logging.received_bytes"]` rather than a `RequestContext` field | Tier 2 AC-04 and Tier 1 AC-04 assert `http.request.bytes == len(raw)` for a truncated body, which is the *only* externally visible consequence. The degraded chunked case is D-A6-2 in §7. |
| **DEV-2** — `body_truncated` now also flags the 4096-character clip on an unparseable `body_raw` | Tier 2 AC-04 asserts `body_truncated is True` **and** `len(body_raw) <= 4096`, and pins `document._MAX_UNPARSED_BODY_RAW == 4096` so the clip cannot move silently. |

---

## 4. Gaps, stated rather than papered over

### 4.1 Functional requirements with **no** numbered acceptance criterion

AC-18…AC-26 closed most of the original gap. What is left is:

> **FR-07, FR-23, NFR-1, NFR-4, NFR-5, NFR-6.**

FR-07 (multipart/binary → metadata only) and FR-23 (`trace.id`) are each unit
tested and have a named Tier 2 integration test; they simply do not have an AC
number of their own. NFR-1 has the load test (§6). NFR-4 and NFR-5 are
source-level properties. NFR-6 is genuinely untested (§4.2).

A6 does not own `docs/REQUIREMENTS.md` and has not invented AC-27+ to close
this. If the acceptance set is meant to be exhaustive, that is an orchestrator
decision.

### 4.2 Not verified at all

| What | Why not |
|---|---|
| **NFR-6** (dependency limits) | No test asserts the installed dependency set. `pyproject.toml` declares it; nothing enforces that the venv matches. A `pip check`-style test belongs to A1's `test_contracts.py`, not here. |
| **`max_multipart_parts`** (half of FR-29) | Unit tested in `test_document.py`; no integration test sends a multipart body with more than `max_multipart_parts` parts. Building one through `httpx` is possible but adds nothing the unit test does not already decide, since the bound is applied in `_multipart` with no I/O involved. |
| **`ilm-apiaudit.json` behaviour** | Tier 1's bootstrap fixture installs it and asserts its *presence* (`settings.lifecycle.name == "apiaudit-ilm"`), but no test observes a rollover, a phase transition or a delete. Those take days of wall clock; verifying them needs `_ilm/explain` against a long-lived cluster — an operational check (`infra/README.md` §3), not a test. |
| **`infra/kibana/dashboards.ndjson`** | Neither tier imports or exercises the dashboards. No Kibana in the compose stack. |
| **`infra/filebeat/daemonset.yaml`** | Kubernetes-only. The compose stack exercises `filebeat.yml`, which is the file both the DaemonSet and the sidecar variant mount, but not the manifest. |
| **`infra/elasticsearch/bootstrap.py`** | Tier 1 installs the same JSON artefacts over the REST API instead of running the script, because the script's `ES_URL` is a literal in a CONFIG block with no environment override. `tests/integration/README.md` documents the edit to exercise it by hand; its `dynamic: false` guard is re-implemented as an assertion in the bootstrap fixture. |
| **TLS between Filebeat and Elasticsearch** | The test stack runs with security disabled over plain HTTP, so `ssl.verification_mode: full` and the CA bundle — how production is meant to run — are the one part of the shipper config the stack overrides rather than exercises. `tests/integration/stack/ca.crt` exists only so the config parses. |
| **Multi-worker / multi-process behaviour** (A-5, FR-26) | Both tiers run in one process. `{pid}` in the filename is asserted, and `test_FR_26_a_second_live_sink_takes_a_collision_suffix` covers the *in-process* collision FR-26 is actually about — but "several uvicorn workers write separate files and Filebeat picks up all of them" is not tested. No `uvicorn` in the venv. |
| **Real sockets** | No `uvicorn`, so every request in every tier goes through `httpx.ASGITransport` in-process. TCP, TLS, keep-alive, `Expect: 100-continue` at the wire level, chunked transfer encoding as a *transport*, and a server stripping a HEAD response body are therefore untested end to end. |
| **Review N-10** (flattened rejecting empty field names, or keys starting/ending with `.`) | The review left it `unverified` and the ES double does not model it either (§4.5). Tier 1 could settle it with one `POST`, in the same style as `test_AC_21_a_flattened_key_over_the_lucene_term_limit_is_rejected` — it is not written, because unlike N-9 there is no fix in `redact.py` for it to be a regression test *for*. |

### 4.3 Acceptance criteria verified only partially

| AC | What is missing, and where |
|---|---|
| **AC-04** | Both tiers now assert the **4096-character** clip rather than the AC's "≤ 1 MiB", which the clip beats by three orders of magnitude and which would therefore pass on a 1 MiB `body_raw`. The AC's own bound is still asserted alongside. If the AC's author expected a parsed-but-truncated *object*, the requirement and the implementation disagree — flagged, not silently reinterpreted. |
| **AC-09** | Tier 2 asserts drop counting and that every request still returns 200. It cannot assert *which* documents were dropped, because that depends on flush timing. Tier 1 additionally reconciles `audit_documents_submitted_total` against the traces that reached Elasticsearch. |
| **AC-10** | Tier 2 measures the mapped-field count against the template's own rules — a faithful model of `dynamic: false` + `flattened`, but still a model. Only Tier 1 asks Elasticsearch's own `_field_caps` / `_mapping`. |
| **AC-12** | Tier 2 asserts every line survives rotation *on disk*. Only Tier 1 can assert "every line reaches Elasticsearch", which depends on `filestream` following the file across the rename and on the deliberate globbing of `*.jsonl.[0-9]` (review S-13). **Unverified until Tier 1 runs, and still the single most consequential unverified thing in this matrix**: if the harvester does not follow the rename, lines are lost silently and nothing else notices. |
| **AC-15** | "within 1.5 s" is wall-clock on the machine running the test. It passed with margin (§2.4) but is the one AC in Tier 2 whose result is machine-dependent. |
| **AC-16** | Neither tier can assert that the *failed* documents reach Elasticsearch — they were never written anywhere for Filebeat to ship, which is what "failed" means. Tier 1 additionally uses a **private** log directory rather than the shared one, since chmod-ing the shared directory read-only would break every test after it. Both tiers skip on root (`os.geteuid() == 0`), which ignores file-mode bits. |
| **AC-19** | The "`build_document` completes in < 5 ms" clause is a unit-tier measurement (`test_document.py::test_FR_29_*`). Tier 2 asserts the whole round trip is under 250 ms — enough to prove the refusal happened *before* the parse (measured 1.5 ms against review M-2's 140 ms of parsing), not enough to pin 5 ms. |
| **AC-22** | The AC says "peak **RSS** under 2× `max_body_bytes` per request". Tier 2 measures `tracemalloc` peak, not RSS — deterministic where RSS is not — and reaches the 2× bound only on the path the AC is actually about: a body that is **captured and not parsed**, where the buffer is the only allocation (measured 0.30 MB against a 1.05 MB budget). On the *parsed* path the peak is ~6× the body, because the parse, the redacted copy and the serialised line each hold one; **no implementation of FR-09 can meet "2×" there**, and the AC does not account for it. The M-4 regression proper — peak scaling with the *chunk count* rather than the body size — is fully covered: 1.00× across a 32,768× change in chunk size. Concurrency is 4, not the AC's 20, and the body 128 KiB, not 1 MiB, to keep the default suite under a second; the amplification a chunk list would cause is ~9× the budget at that scale, so the margin is not the thing that was reduced. |
| **AC-23** | The 204 half is fully covered. The HEAD half uses a route registered **for HEAD** that emits no body, so the zero is the application's. A HEAD against a body-returning GET route would show a non-zero `http.response.bytes` in either tier and be right to: stripping that body is the HTTP server's job (uvicorn/h11), and there is no uvicorn here (§4.2, "Real sockets"). |
| **AC-25** | Both clauses are covered, at different `file_backup_count`s as the AC requires. The bound clause is **structurally blind to D-A6-5** (§7): the oversized file that defect produces is evicted long before the run ends at `file_backup_count=8`, so the clause passes whether or not the sink violated the bound. Two numbers in the AC do not survive contact: the document produced by the test app is **~1385 B, not ~940 B** (it carries a user-agent, a host header, a 32-hex trace id and a route template), so 2000 documents need **2.77 MB** of retention, not 1.87 MB, and the survival clause needs `file_backup_count ≥ 43`, not `≥ 40`. The test derives both from the measured line rather than from the AC's constants, and asserts the premise in both directions so it cannot pass vacuously. See §7. |
| **AC-26** | "total process memory attributable to the queue" is asserted from the sink's **own byte accounting** (`queued_bytes + inflight_bytes`), not from RSS — the sink is the only thing that knows which bytes are its. The `audit_documents_failed_total` clause is exact and is the D-A6-1/S-9 regression test. No Tier 1 counterpart: nothing in the clause involves Elasticsearch. |

### 4.4 What only Tier 1 can cover

Nothing in Tier 2 touches any of this; all of it is unverified today.

* Filebeat's `filestream` input, its registry, `ignore_older` / `clean_removed`,
  and the deliberate globbing of rotated `*.jsonl.[0-9]` (review S-13).
* The `ndjson` parser with `target: ""` **and `overwrite_keys: true`** — without
  the latter, `@timestamp` becomes the moment Filebeat read the line and every
  latency query in the Kibana dashboards is wrong. Tier 1's
  `test_AC_01_one_document_per_request` and `…_filebeat_dropped_its_own_metadata`
  are the tripwires.
* **`message_max_bytes` and the quarantine route.** Review M-3 was not a
  serialisation bug — the line was written correctly and then truncated by
  Filebeat, failed ndjson decode, and was discarded by a `drop_event` processor
  with no counter on either side. `test_AC_20_a_1MiB_body_survives_the_whole_pipeline`
  and `…_nothing_was_quarantined_as_undecodable` are where M-3 is really
  settled. Tier 2 can only assert the line is small enough.
* The disk queue's `segment_size` floor. `diskqueue.handleProducerWriteRequest`
  drops an oversized event with a `Warnf` and nothing else. Tier 2's
  `test_AC_20_the_acceptance_stacks_disk_queue_can_hold_that_line` checks the
  *arithmetic* of the compose overrides against `filebeat.yml`; only a running
  stack checks the behaviour.
* The `drop_fields` processor removing `agent`/`ecs`/`input`/`log` while leaving
  `host.hostname` (ours) alone.
* `index: "%{[data_stream.type]}-%{[dataset]}-%{[namespace]}"` resolving to a
  real data stream, and that data stream being created **from the
  `logs-apiaudit` template** and not a dynamic one (plan §10, D-11, R-1). A
  one-way door: a data stream created before its template needs a reindex.
* Elasticsearch actually enforcing `dynamic: false`, actually costing one field
  per `flattened`, and actually reporting ≤ 200 in `_field_caps`.
* `audit.request.body_raw` being `index: false` — a query against it being a
  400 rather than a silent miss.
* **N-9 and M-5 as cluster facts.** Tier 2 now models both (§1), but the model
  is A6's reading of `FlattenedFieldParser.addField` and of the
  `ignore_malformed` documentation. `test_AC_21_the_uncoerced_shape_really_is_rejected_by_elasticsearch`
  and `…_a_flattened_key_over_the_lucene_term_limit_is_rejected` are the two
  `POST`s that turn both from "modelled" into "verified".
* `event.duration` being a queryable `long` (a range query on it).
* Filebeat surviving log rotation (AC-12, §4.3).

### 4.5 What the Tier 2 Elasticsearch double still does **not** model

Recorded so nobody reads a green Tier 2 as a green cluster.

| Not modelled | Consequence |
|---|---|
| Everything Filebeat does | §4.4. The double is handed the JSONL line directly; there is no ndjson decode, no `message_max_bytes`, no processors, no routing. |
| Lucene analysis for `text` fields | `error.message` is `text`, so its terms are analyzer tokens, not the whole value. A single token over `MAX_TERM_LENGTH` would fail on a real cluster; the standard analyzer splits at 255 characters, so this is unreachable in practice and is not checked. |
| Review **N-10** — empty flattened field names, and keys starting or ending with `.` | Left `unverified` by the review and unmodelled here. A body with a `""` key would pass Tier 2 and might be rejected by a cluster. One `POST` settles it; see §4.2. |
| Mapping *updates* and how `total_fields.limit` is enforced | With `dynamic: false` no mapping update ever happens, so the limit is a constant the double reads out of the template rather than a runtime bound it enforces. |
| Bulk semantics | Partial bulk failures, the 413 that `bulk_max_size: 12` exists to prevent, `max_retries: -1`, and the `non_indexable_policy.dead_letter_index` route are all invisible here. |
| `date` format validation | `@timestamp` is accepted as any string; the template's `strict_date_optional_time_nanos\|\|…` format is not parsed. |
| `ignore_above` semantics beyond term suppression | Modelled only as "a value past it produces no term". Its effect on `_source` (none) and on doc values is not modelled because nothing asserts on those. |
| Scoring, the query DSL, aggregations | `search`/`one`/`by_trace` are exact-match lookups over a Python list. Tier 1's `_search` calls are the real query surface. |

---

## 5. Tier 1 execution status — **NOT RUN**

`tests/integration/test_acceptance_es.py` and `docker-compose.test.yml` are
written, collect cleanly (**31 tests**, up from 22 — AC-18, AC-20 and AC-21
were added in this pass), and skip with an actionable message. They have
**never been executed**, because the Docker daemon is not reachable from the
environment they were written in. Re-confirmed at the start of this pass:

```
$ docker ps
permission denied while trying to connect to the docker API at unix:///var/run/docker.sock
```

The user is not in the `docker` group and `sudo` requires a password. Nothing in
this matrix marked "Tier 1" should be read as verified. Treat the first green
run as new information and budget for it; plan R-9 already names flakiness in
this tier as the top schedule risk, and every wait in the tier polls for the
document it wants (by `trace.id`, which FR-23 lets the test set via
`X-Request-ID`) rather than sleeping for a guessed interval, specifically to
keep it off that list.

The stack config changed in this pass and is also unexercised: see §7,
D-A6-3 and D-A6-4.

Bring-up, verification and triage: `tests/integration/README.md`.

---

## 6. NFR-1 — the measured load-test numbers

`tests/load/driver.py`. **A plain asyncio/httpx driver, not Locust and not k6**:
`locust` is not installed and is not on the permitted dependency list
(AGENTS.md §7), there is no `k6` binary, there is no Docker to run one in, and
there is no `uvicorn` either — so there is no way to put a real socket server in
front of the app. It is also the right instrument for the question: NFR-1 asks
for a **delta between two arms**, and every source of noise removed by staying
in-process appears identically in both arms and only widens the interval on the
difference.

Both arms: same app, same 8 KB bodies, same open-loop schedule (request *i* is
issued at `t0 + i/rate` whether or not *i-1* finished, so a slow arm shows as
queueing rather than as a quietly lowered rate). The audited arm uses the
**real `FileSink`** writing real JSONL and the **real `redact.py`** — not a
`NullSink`, not identity redaction.

### Result — **PASS**, re-measured 2026-09-05 after the three fix passes

```
NFR-1 — 100 rps, 8262 B bodies, 300 s per arm (after a 2 s warm-up)

                          baseline     audited       delta
----------------------------------------------------------
mean (ms)                    1.417       2.113      +0.696
p50 (ms)                     1.460       2.191      +0.731
p95 (ms)                     1.793       2.602      +0.809
p99 (ms)                     2.078       2.897      +0.819     <-- NFR-1
max (ms)                    23.026      29.817      +6.791
----------------------------------------------------------
requests                     30000       30000
achieved rps                100.00      100.00
open-loop p99 (ms)           4.120       4.274
non-2xx                          0           0

audit documents submitted: 30220
audit documents dropped:   0
audit documents failed:    0
middleware errors:         0
JSONL written:             266.2 MiB
```

A shorter confirming run (`pytest tests/load -m load`, 30 s per arm, 3000
requests) measured **+0.698 ms**. The two agree.

**Added p99 = +0.819 ms against a 5 ms budget — 16 % of it.** The overhead is
flat across the distribution: +0.70 ms at the mean, +0.73 at p50, +0.81 at p95,
+0.82 at p99. That shape is the interesting part. A middleware that did I/O on
the request path would show a fat tail — a p99 delta several times its p50
delta — and this one does not, which is NFR-2 (`submit()` is a serialisation
plus a `deque.append`) visible from the outside.

### What the fix passes changed, measured rather than assumed

| | before (this matrix's previous revision) | after |
|---|---|---|
| added p99 | +1.008 ms | **+0.819 ms** (−19 %) |
| added p50 | +1.049 ms | **+0.731 ms** (−30 %) |
| JSONL written for 30 000 requests | 534.8 MiB | **266.2 MiB** (−50.2 %) |

The halved storage is FR-30 landing: `body` and `body_raw` are no longer both
written, so an 8 KB body is serialised once instead of twice. The latency
improvement is the same change seen from the request path — the second full
serialisation (review M-2) is gone.

### Confirming A2's numbers independently

| A2 reported | A6 measured here | Verdict |
|---|---|---|
| 8 KB overhead 38.0 → 28.4 µs/request | `test_middleware.py::test_overhead_per_request_microseconds`: baseline 1.0 µs, audited 31.2 µs, **overhead 30.2 µs** | Confirmed. 30.2 vs 28.4 µs is within run-to-run noise on a contended machine, and the direction (a large improvement from ~38 µs) is reproduced. Note this benchmark is A2's, uses a `NullSink` and identity redaction, and is *not* the NFR-1 number. |
| NFR-1 p99 at +0.715 ms | **+0.819 ms** over 300 s/arm, **+0.698 ms** over 30 s/arm, with the real sink and real redaction | Confirmed. A2's figure sits between the two runs. |

The ~0.8 ms here and the ~30 µs above measure different things and both are
correct: the microbenchmark isolates `AuditMiddleware` with the sink and
redaction stubbed out; the load number is that plus real recursive `redact()`
over an 8 KB nested body, real `orjson` serialisation of a ~9 KB document, and
a background flush task sharing the event loop. NFR-1 asks about the latter.

### What it does not measure

No sockets, so no TCP/TLS/keep-alive. No uvicorn, so no h11 parsing and no
worker model. One process and one event loop, so the audited arm's background
flush task competes with the request path on the same loop — realistic for a
single uvicorn worker, silent about several on one node. Filebeat is not
running, so nothing reads the files back.

Reproduce:

```bash
./.venv/bin/python -m tests.load.driver --duration 300 --rate 100 --json
./.venv/bin/python -m pytest tests/load -q -m load -s        # 30 s per arm
AUDIT_LOAD_DURATION=300 ./.venv/bin/python -m pytest tests/load -q -m load -s
```

---

## 7. Defects found

A6 owns only `tests/**`. Defects in other agents' files are recorded and
reported, never fixed here; defects in A6's own files are fixed and recorded.

### D-A6-1 — `audit_documents_failed_total` double-counts a retried batch — **FIXED**

| | |
|---|---|
| Owner | **A4** — `audit_logging/sinks/file_sink.py` |
| Severity | Low — metric accuracy, not data loss |
| Requirement | FR-21r, AC-26 |
| Status | **Fixed.** The same defect the review numbered **S-9**; the fix pass landed it as `FileSink._keep_or_lose`. |

**Was.** A batch whose write failed was counted `len(batch)` in
`audit_documents_failed_total`, kept for one retry, and — when the retry also
failed — counted `len(batch)` **again**. 180 lost documents were reported as
360. `is_retry` already distinguished the two paths and was used to decide
whether to re-queue, but not whether to count.

**Now.** `_keep_or_lose` increments the counter exactly once, on the attempt
after which the batch is discarded, and counts only the lines `_write_batch`
could not place — so a partially written batch is not counted whole. The
`CancelledError`-during-a-retry path, which used to discard a batch with no
counter at all, counts there too.

**Regression test.** `test_AC_26_close_returns_in_time_and_counts_each_lost_document_once`
reconstructs the number actually lost from the lines on disk and asserts the
counter equals it: measured **122 lost, counter 122**. Under the old code this
test reads 244.

### D-A6-2 — `http.request.bytes` under-reports a truncated chunked body

| | |
|---|---|
| Owner | **A2** — `audit_logging/document.py::_request_bytes` |
| Severity | Informational — a known consequence, recorded so it is not rediscovered |
| Requirement | FR-08, `docs/schema.md` §2.4, and now `docs/REQUIREMENTS.md` §2.2 **DEV-1** |
| Status | Open, and now an accepted deviation rather than an unrecorded one. |

`http.request.bytes` is meant to be "bytes actually received, **before**
truncation". The count now travels from the `receive` wrapper on
`scope["audit_logging.received_bytes"]` (DEV-1), which fixes the common case.
Where the counter is absent the code still falls back to `Content-Length` and
then to the *captured* length — which for a truncated body is `max_body_bytes`,
not the real size. `body_truncated: true` combined with
`http.request.bytes == max_body_bytes` remains the signature to look for.
DEV-1 records that this should become `RequestContext.received_bytes` the next
time the contract opens.

### D-A6-3 — the acceptance stack's disk queue could silently drop a worst-case line — **FIXED (A6's own file)**

| | |
|---|---|
| Owner | **A6** — `tests/integration/docker-compose.test.yml` |
| Severity | Medium — a test-stack defect that would have looked like a package defect |
| Requirement | AC-20, and `infra/filebeat/filebeat.yml`'s SIZING INVARIANTS |

**Was.** The compose stack overrode `queue.disk.segment_size=10MB`. A5 then
raised `message_max_bytes` to 8 MiB after recomputing the worst-case line — a
1 MiB body of control characters expands 6× to 6,292,571 B, which A8's 2–3×
estimate had missed. `diskqueue.handleProducerWriteRequest` (beats v8.13.4
`core_loop.go`) refuses any event larger than
`segment_size - segmentHeaderSize` with a `Warnf` and **drops it** — the same
class of quiet loss as M-3, one layer down, with no counter on either side.
10MB cleared the 8 MiB floor by only ~1.6 MB and no longer satisfied
`segment_size >= 2 × message_max_bytes`.

**Now.** `segment_size=64MB` — 4× headroom over the floor, and still inside
`max_size >= 2 × segment_size` (200 ≥ 128), which Filebeat validates at
startup. `test_AC_20_the_acceptance_stacks_disk_queue_can_hold_that_line` reads
both overrides out of the compose file and `message_max_bytes` out of
`filebeat.yml` and re-derives both invariants, so the two files cannot drift
apart again silently.

### D-A6-4 — the acceptance stack capped Filebeat below what its own config sizes for — **FIXED (A6's own file)**

| | |
|---|---|
| Owner | **A6** — `tests/integration/docker-compose.test.yml` |
| Severity | Low — the same class of drift as D-A6-3, found by checking for it |
| Requirement | AC-20 |

The compose stack set `mem_limit: 400m` on Filebeat. A5's fix pass moved the
DaemonSet from 500Mi to **1Gi** (review S-12) because `worker: 2` ×
`bulk_max_size: 12` × a 6,292,571 B worst-case document is 151 MB of bulk
buffers, roughly doubled while gzip runs, on top of `queue.disk.read_ahead: 32`
events held in memory. A stack capped at 400m OOM-kills the shipper on exactly
the adversarial body AC-20 exists to send — and an OOM-killed Filebeat looks
like "the document never arrived", which is indistinguishable from the bug
under test. Raised to `1g` to match the DaemonSet. The other four `-E`
overrides (`ssl.enabled`, `ssl.verification_mode`, `username`, `password`) were
checked against A5's revised `filebeat.yml` and are unaffected by anything the
fix passes changed.

### D-A6-5 — `FileSink._rotate` races `start()` and loses a whole generation — **NEW, open**

| | |
|---|---|
| Owner | **A4** — `audit_logging/sinks/file_sink.py::_rotate` / `_ensure_open` |
| Severity | **Medium** — an FR-22 bound violation and one lost rotation slot per process. No documents are lost. |
| Requirement | FR-22, AC-25's bound clause |
| Found | While chasing an intermittent AC-25 failure that turned out to be *two* defects, one of them mine (D-A6-6). |

**Symptom.** About **one run in three**, a rotating sink ends up with a **gap
in the `.N` numbering** and one generation holding **two files' worth of data**:

```
orders-api-<pid>.jsonl        36 037 B
orders-api-<pid>.jsonl.1      65 143 B
…
orders-api-<pid>.jsonl.40     65 090 B
                              <-- .41 does not exist
orders-api-<pid>.jsonl.42    130 090 B   <-- 2x file_max_bytes (65 536)
```

`audit_file_rotations_total` reads 42, but only 41 backup files exist. No line
is lost — the 130 KB file holds both generations — so this is a **bound**
failure, not a durability one. `file_max_bytes` is meant to be a bound (FR-22);
one file is at 198 % of it, and a node sized as
`file_max_bytes × (file_backup_count + 1)` is under-provisioned by one file.

**Mechanism** (confirmed by instrumenting `_rotate` and `_ensure_open` with the
calling thread; the correlation is exact over 8 runs — every run with the gap
has the extra open, every run without it does not):

`_write_batch`, and therefore `_rotate`, runs on an `asyncio.to_thread` worker
(`asyncio_0`). `_rotate` does close-fd → rename → reopen. `FileSink.start()`,
scheduled on the event loop by `_start_lazily`, calls `_ensure_open()` on
`MainThread`. When `start()` lands inside `_rotate`'s window:

1. worker: `_close_fd()` — `self._fd` is now `None`;
2. **main thread**: `_ensure_open()` sees `_fd is None`, opens the *pre-rename*
   base file and stores the fd. The spy catches this as the one open in the
   process that finds a **non-empty** file: `('open', 'MainThread', 65040)`;
3. worker: `os.replace(base, base + ".1")` — the fd from step 2 now points at
   `.1`;
4. worker: `finally: self._ensure_open()` — `_fd` is not `None`, so it is a
   no-op and **no new base file is created**;
5. the next segment is written through that fd, i.e. appended to `.1`, which
   reaches 130 KB;
6. the next `_rotate` finds no `base` to move to `.1`, so `.1` is never
   created — the hole. Every later rotation shifts the hole up by one, which is
   why it always ends at `.{rotations - 1}`.

`self._open_lock` guards the *open* but not `_rotate`'s close → rename →
reopen sequence, and `_close_fd()` leaving `_fd` clear is exactly what makes
step 2 possible. A fix has to hold `_open_lock` across the whole of `_rotate`,
or give `_rotate` a sentinel that makes a concurrent `_ensure_open` wait rather
than open.

**Why no test asserts it.** It reproduces ~1 in 3 runs, so an assertion would be
a flaky failure rather than a regression test. Worse, **AC-25's bound clause
structurally cannot see it**: the oversized file is created within the first two
rotations, and at `file_backup_count=8` it is evicted long before the 42nd
rotation, so `test_AC_25_no_file_exceeds_file_max_bytes_by_more_than_one_line`
is green whether or not the defect fires. It is only visible at a large backup
count, where the AC asks about survival rather than about the bound.
`test_AC_25_every_line_survives_when_the_backup_count_can_hold_them` therefore
**prints** the gap and the oversized file when it fires, and fails only on
actual line loss. Whoever fixes this should add the deterministic assertion.

### D-A6-6 — the A6 harness walked rotated files contiguously — **FIXED (A6's own file)**

| | |
|---|---|
| Owner | **A6** — `tests/integration/conftest.py::Audited.rotated_paths` |
| Severity | Medium — it reported D-A6-5 as a *different, worse* defect |

`rotated_paths()` walked `.1`, `.2`, … and stopped at the first missing index.
With D-A6-5's gap at `.41` it therefore returned 40 of 42 files, and
`lines(include_rotated=True)` silently dropped the other two — so AC-25 failed
with **"2000 documents written, 1906 lines survived rotation"**, i.e. it accused
the sink of losing 94 audit records that were on disk the whole time. A harness
that turns one defect into a louder, wrong one is worse than no harness. It now
globs the directory and sorts by index, and `Audited.rotated_indices()` exposes
the numbering so a test can assert on the gap itself.

### Observations for other agents — not defects

* **`message_max_bytes: 8388608` is now ~8× the reachable worst case, not
  1.33×.** A5 sized it against a 6,292,571 B line: 1 MiB of raw control
  characters kept verbatim in `body_raw` and escaped to `\u0001` six bytes at a
  time. That line is no longer reachable. It came from the FR-09 parse-failure
  path, and DEV-2 now clips that path to 4096 characters, so the same body
  produces a **25,730 B** line. The largest line a 1 MiB `max_body_bytes` can
  now produce is a fully-stored parseable body at **1,049,779 B** — 12.5 % of
  `message_max_bytes`. The 8 MiB value is not wrong, and being generous here is
  cheap; it is simply no longer tight, and `bulk_max_size: 12` (sized from the
  same 6.29 MB figure) is correspondingly conservative. Worth one look before
  anyone treats those two numbers as load-bearing.
* **AC-25's arithmetic is light.** The AC says "2000 × ~940 B needs 1.87 MB"
  and "`file_backup_count` ≥ 40". The document this test app produces is
  **~1385 B**, so 2000 of them need **2.77 MB** and the survival clause needs
  `file_backup_count ≥ 43`. The AC's *argument* — that the two clauses cannot
  be tested at the same backup count — is exactly right, and is why the tests
  derive the numbers from the measured line instead of from the AC.
* **AC-22's "2× `max_body_bytes` per request" is not achievable on the parsed
  path**, by any implementation: the parse, the redacted copy and the
  serialised line each hold roughly one copy of the body. It *is* achievable on
  the path M-4 was about (capture without parse), which is where the test
  asserts it. See §4.3.
* **AC-23's HEAD clause needs an HTTP server**, not an application. See §4.3.

### Not defects — checked and confirmed correct

* Every document shape the middleware can emit — JSON, form-urlencoded,
  multipart, opaque binary, XML/text with and without `capture_text_bodies`,
  empty, unread, non-object JSON top level, unparseable JSON, over
  `max_body_nodes`, 204, 404, 422, 500 — indexes against the real template with
  **zero** unmapped fields, **zero** malformed values and **zero** rejections
  (`test_every_body_kind_indexes_cleanly`, `test_AC_20_body_and_body_raw_are_never_both_present`).
* All nine rows of `docs/schema.md` §2.9 are reachable and mutually exclusive,
  and all three of the "neither" / "body" / "body_raw" outcomes actually occur
  in the sweep, so the assertion cannot pass vacuously.
* A body that failed to parse keeps its text verbatim and is therefore
  unredacted — the documented exception (schema §3, `docs/redaction.md`).
  `test_AC_14_a_parse_failure_is_the_only_unredacted_body_raw` pins it
  deliberately and will fail loudly if it is ever "fixed" without updating the
  docs. The 4096-character clip bounds what that costs.
* A 4xx is `event.outcome: "success"`; only an app exception or a 5xx is
  `"failure"` (AC-07 vs AC-08).
* `user.*` drops keys the resolver returns that are not `id`/`name`/`roles`,
  and coerces the ones it keeps (AC-17, AC-21).
* Two live `FileSink`s on one path no longer destroy each other's lines: 60 in,
  60 out, on each of two files (`test_FR_26_a_second_live_sink_takes_a_collision_suffix`).
  Both name forms match Filebeat's `*/*.jsonl` glob and neither matches
  `\.jsonl\.\d+$` until rotated.

---

## 8. Flakes observed

| Test | Owner | Observed by A6? |
|---|---|---|
| `tests/unit/test_middleware.py::test_app_reading_the_body_twice_behaves_like_unwrapped_asgi` | A4 reported it as intermittent | **No.** Green in every A6 run across this pass. Not fixed (not A6's file), not removed, still listed so it is not forgotten. |
| Tier 2, all 60 | A6 | None. Repeated runs green. |
| Tier 1, all 31 | A6 | **Unknown — never executed.** |
| `tests/unit/test_redact.py` | A3 | A fourth agent was editing `audit_logging/redact.py` and `tests/unit/test_redact.py` concurrently with this pass. Both were green in A6's final run; if either fails, look there first. |

---

## 9. How to run everything

```bash
# The default run: unit (460) + Tier 2 (60) = 518. Must stay green.
./.venv/bin/python -m pytest tests -q -m "not load and not integration"

# Tier 2 alone, with the measured numbers printed
./.venv/bin/python -m pytest tests/integration -q -m "not integration" -s

# Tier 1 — needs the compose stack (tests/integration/README.md)
export AUDIT_TEST_LOG_DIR="$PWD/tests/integration/.stack/logs" && mkdir -p "$AUDIT_TEST_LOG_DIR"
docker compose -f tests/integration/docker-compose.test.yml up -d
./.venv/bin/python -m pytest tests/integration -q -m integration

# Load
./.venv/bin/python -m pytest tests/load -q -m load -s
./.venv/bin/python -m tests.load.driver --duration 300 --rate 100 --json

# Types (owned by the package agents, not an A6 gate)
./.venv/bin/python -m mypy --strict audit_logging
```
