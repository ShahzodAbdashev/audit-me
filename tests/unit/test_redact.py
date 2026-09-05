"""Redaction — FR-10…FR-14. Owned by A3.

The tests are grouped as: normalize_key, redact (purity, recursion, depth cap,
cycles), filter_headers, hypothesis properties, the documented limitations,
and a benchmark.

The limitation tests assert the *current* behaviour of things redaction does
not catch. They are deliberately phrased as "this value is NOT redacted" so
that the gap is a tested, reviewable fact rather than a surprise, and so that
anyone who later widens the matching sees these tests fail and has to make a
decision. They feed ``docs/redaction.md``.
"""

from __future__ import annotations

import copy
import gc
import json
import re
import time
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from audit_logging import redact as R
from audit_logging.redact import (
    DEFAULT_HEADER_ALLOWLIST,
    DEFAULT_REDACT_KEYS,
    MAX_KEY_BYTES,
    REDACTED,
    TRUNCATED,
    filter_headers,
    normalize_key,
    redact,
    sanitize_key,
)

KEYS = DEFAULT_REDACT_KEYS
ALLOW = DEFAULT_HEADER_ALLOWLIST

MARKER = "s3cr3t-marker-6f21a9"


def _dumps(obj: Any) -> str:
    """JSON text of a redacted structure, for 'does this value survive' checks."""
    return json.dumps(obj, default=repr)


# ---------------------------------------------------------------------------
# normalize_key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Pass-Word", "password"),
        ("pass_word", "password"),
        ("PASS.WORD", "password"),
        ("api-key", "apikey"),
        ("API.KEY", "apikey"),
        ("api_key", "apikey"),
        ("__token__", "token"),
        ("X-Api-Key", "xapikey"),
        ("", ""),
        ("---", ""),
        ("already_normal", "alreadynormal"),
    ],
)
def test_normalize_key_variants(raw: str, expected: str) -> None:
    assert normalize_key(raw) == expected


def test_normalize_key_is_idempotent() -> None:
    for raw in ("Pass-Word", "API.KEY", "__token__", "Set-Cookie"):
        once = normalize_key(raw)
        assert normalize_key(once) == once


def test_normalize_key_survives_non_str_input() -> None:
    """An int key from a JSON-ish dict must not blow up the request path."""
    assert normalize_key(7) == "7"  # type: ignore[arg-type]
    assert normalize_key(None) == "none"  # type: ignore[arg-type]
    assert normalize_key(True) == "true"  # type: ignore[arg-type]
    assert normalize_key(3.5) == "35"  # type: ignore[arg-type]
    assert normalize_key(b"Api-Key") == "apikey"  # type: ignore[arg-type]
    assert normalize_key((1, 2)) == "(1, 2)"  # spaces are not stripped


def test_normalize_key_never_raises_on_a_hostile_object() -> None:
    class Hostile:
        def __str__(self) -> str:
            raise RuntimeError("boom")

        def __hash__(self) -> int:
            return 0

    assert normalize_key(Hostile()) == ""  # type: ignore[arg-type]
    # ...and it stays out of the way of redaction rather than crashing it.
    assert redact({Hostile(): "v"}, KEYS) != {}


def test_default_key_sets_are_normalized_and_frozen() -> None:
    assert isinstance(DEFAULT_REDACT_KEYS, frozenset)
    assert isinstance(DEFAULT_HEADER_ALLOWLIST, frozenset)
    # Every denylist entry is already in normalized form, or matching silently
    # fails for it.
    for key in DEFAULT_REDACT_KEYS:
        assert normalize_key(key) == key, key
    # Allowlist entries are matched on lowercased header names, hyphens intact.
    for name in DEFAULT_HEADER_ALLOWLIST:
        assert name == name.lower().strip(), name


def test_FR_11_required_default_keys_are_present() -> None:
    """The minimum denylist from REQUIREMENTS.md §1.2."""
    required = {
        "password", "passwd", "pwd", "secret", "token", "accesstoken",
        "refreshtoken", "idtoken", "apikey", "apisecret", "authorization",
        "auth", "cookie", "setcookie", "sessionid", "session", "csrf", "xsrf",
        "privatekey", "clientsecret", "credential", "credentials", "pin",
        "otp", "cardnumber", "cardnum", "pan", "cvv", "cvc", "ssn", "taxid",
        "iban", "signature", "sig", "salt", "hash",
    }
    assert required <= DEFAULT_REDACT_KEYS


def test_FR_12_required_default_header_allowlist_is_present() -> None:
    """The minimum allowlist from REQUIREMENTS.md §1.2."""
    required = {
        "content-type", "content-length", "accept", "accept-encoding",
        "accept-language", "user-agent", "referer", "origin", "host",
        "x-request-id", "x-correlation-id", "x-forwarded-for",
        "x-forwarded-proto", "x-real-ip", "traceparent", "tracestate",
    }
    assert required <= DEFAULT_HEADER_ALLOWLIST


def test_FR_12_credential_headers_are_not_allowlisted() -> None:
    for name in ("authorization", "cookie", "set-cookie", "proxy-authorization",
                 "x-api-key", "x-auth-token", "x-csrf-token"):
        assert name not in DEFAULT_HEADER_ALLOWLIST


# ---------------------------------------------------------------------------
# redact — the basics
# ---------------------------------------------------------------------------


def test_FR_11_denylisted_key_spellings_are_all_caught() -> None:
    body = {
        "Pass-Word": "p1",
        "api-key": "k1",
        "API.KEY": "k2",
        "__token__": "t1",
        "Set_Cookie": "c1",
        "keep": "visible",
    }
    out = redact(body, KEYS)
    assert out == {
        "Pass-Word": REDACTED,
        "api-key": REDACTED,
        "API.KEY": REDACTED,
        "__token__": REDACTED,
        "Set_Cookie": REDACTED,
        "keep": "visible",
    }


def test_FR_11_keys_are_preserved_exactly_as_written() -> None:
    """The key is evidence; only the value is a secret."""
    out = redact({"Pass-Word": "p"}, KEYS)
    assert list(out) == ["Pass-Word"]


def test_FR_10_redact_is_pure_and_does_not_mutate_the_input() -> None:
    body = {
        "password": "hunter2",
        "nested": {"api_key": "k"},
        "items": [{"token": "t"}, {"ok": 1}],
    }
    before = copy.deepcopy(body)
    out = redact(body, KEYS)

    assert body == before, "redact() mutated the object the application holds"
    assert out is not body
    assert out["nested"] is not body["nested"]
    assert out["items"] is not body["items"]
    assert out["items"][0] is not body["items"][0]
    # ...and the application still sees its own values.
    assert body["password"] == "hunter2"


def test_FR_10_AC_05_no_denylisted_value_appears_anywhere() -> None:
    """AC-05 verbatim, at the unit level."""
    body = {"password": "p", "nested": {"api_key": "k"}, "items": [{"token": "t"}]}
    out = redact(body, KEYS)
    text = _dumps(out)
    assert '"p"' not in text and '"k"' not in text and '"t"' not in text
    assert out["password"] == REDACTED
    assert out["nested"]["api_key"] == REDACTED
    assert out["items"][0]["token"] == REDACTED


def test_FR_11_nested_arrays_of_objects_at_depth() -> None:
    body = {
        "batch": [
            {"user": {"credentials": {"pwd": MARKER}}},
            [[{"cvv": MARKER}]],
            {"safe": [1, 2, {"deeper": [{"secret": MARKER}]}]},
        ]
    }
    out = redact(body, KEYS)
    assert MARKER not in _dumps(out)
    assert out["batch"][0]["user"]["credentials"] == REDACTED
    assert out["batch"][1][0][0]["cvv"] == REDACTED
    assert out["batch"][2]["safe"][2]["deeper"][0]["secret"] == REDACTED
    assert out["batch"][2]["safe"][:2] == [1, 2]


def test_FR_11_denylisted_key_holding_a_large_object_is_replaced_wholesale() -> None:
    """No recursion into a subtree that is already condemned."""
    body = {"credentials": {"user": "u", "pwd": MARKER, "meta": [{"x": MARKER}] * 50}}
    out = redact(body, KEYS)
    assert out == {"credentials": REDACTED}
    assert MARKER not in _dumps(out)


def test_leaf_types_pass_through_unchanged() -> None:
    body = {"a": None, "b": True, "c": False, "d": 1.5, "e": -3, "f": "", "g": "x"}
    assert redact(body, KEYS) == body


def test_empty_containers() -> None:
    assert redact({}, KEYS) == {}
    assert redact([], KEYS) == []
    assert redact({"a": {}, "b": []}, KEYS) == {"a": {}, "b": []}
    assert redact(None, KEYS) is None
    assert redact("scalar", KEYS) == "scalar"


def test_top_level_list_is_redacted() -> None:
    """FR-09 wraps non-object JSON, but redact() must handle a bare list too."""
    assert redact([{"token": MARKER}, {"ok": 1}], KEYS) == [{"token": REDACTED}, {"ok": 1}]


def test_tuples_become_lists() -> None:
    """JSON has no tuple; normalising here keeps the document serialisable."""
    out = redact({"t": ({"token": MARKER}, 2)}, KEYS)
    assert out == {"t": [{"token": REDACTED}, 2]}


def test_non_str_keys_are_preserved_and_checked() -> None:
    body = {1: "one", 2: {"token": MARKER}, True: "yes", "3": "three"}
    out = redact(body, KEYS)
    assert out[2] == {"token": REDACTED}
    assert MARKER not in _dumps(out)
    assert set(out) == set(body)


def test_empty_keyset_still_copies_and_changes_nothing() -> None:
    body = {"password": "p", "n": [{"token": "t"}]}
    out = redact(body, frozenset())
    assert out == body
    assert out is not body
    assert out["n"] is not body["n"]


def test_FR_13_extra_keys_are_additive() -> None:
    """Config-supplied keys extend the defaults; defaults cannot be removed."""
    effective = DEFAULT_REDACT_KEYS | {normalize_key(k) for k in ["Internal-Ref", "x.y"]}
    body = {"internal_ref": MARKER, "XY": MARKER, "password": MARKER, "kept": "v"}
    out = redact(body, effective)
    assert out == {
        "internal_ref": REDACTED,
        "XY": REDACTED,
        "password": REDACTED,
        "kept": "v",
    }
    assert DEFAULT_REDACT_KEYS <= effective


def test_FR_14_query_parameters_use_the_same_denylist() -> None:
    """A parsed query string is just a dict of str -> str | list[str]."""
    query = {"expand": "lines", "token": MARKER, "api_key": [MARKER, MARKER]}
    out = redact(query, KEYS)
    assert out == {"expand": "lines", "token": REDACTED, "api_key": REDACTED}
    assert MARKER not in _dumps(out)


# ---------------------------------------------------------------------------
# redact — the depth cap
# ---------------------------------------------------------------------------


def _nest(depth: int, leaf: Any) -> Any:
    """``{"a": {"a": ... leaf}}`` with ``depth`` dict levels."""
    node: Any = leaf
    for _ in range(depth):
        node = {"a": node}
    return node


def test_depth_cap_replaces_the_deep_subtree() -> None:
    out = redact(_nest(25, {"leaf": MARKER}), KEYS, depth_limit=20)
    node = out
    for _ in range(20):
        assert isinstance(node, dict)
        node = node["a"]
    assert node == TRUNCATED


def test_depth_cap_deep_values_do_not_survive() -> None:
    """The point of the cap: nothing below it reaches the document at all."""
    for limit in (1, 2, 5, 20):
        for planted in (
            _nest(limit + 3, {"leaf": MARKER}),
            _nest(limit + 3, MARKER),
            _nest(limit + 1, [MARKER]),
            _nest(limit, MARKER),
        ):
            out = redact(planted, KEYS, depth_limit=limit)
            assert MARKER not in _dumps(out), (limit, planted)


def test_depth_cap_counts_lists_as_levels_too() -> None:
    node: Any = MARKER
    for _ in range(30):
        node = [node]
    assert MARKER not in _dumps(redact(node, KEYS, depth_limit=20))


def test_depth_cap_default_is_20() -> None:
    assert redact(_nest(20, MARKER), KEYS) == _nest(20, TRUNCATED)
    assert redact(_nest(19, MARKER), KEYS) == _nest(19, MARKER)


def test_depth_limit_zero_truncates_everything() -> None:
    assert redact({"a": 1}, KEYS, depth_limit=0) == TRUNCATED


def test_cycles_terminate_via_the_depth_cap() -> None:
    """Self-referential input must not recurse for ever (plan §8/A3)."""
    d: dict[str, Any] = {"name": "root", "password": MARKER}
    d["self"] = d
    out = redact(d, KEYS, depth_limit=8)
    assert MARKER not in _dumps(out)
    node = out
    for _ in range(8):
        assert isinstance(node, dict)
        node = node["self"]
    assert node == TRUNCATED
    assert d["self"] is d, "input cycle was mutated"


def test_mutual_cycles_and_list_cycles_terminate() -> None:
    a: dict[str, Any] = {}
    b: list[Any] = [a]
    a["b"] = b
    a["token"] = MARKER
    out = redact(a, KEYS, depth_limit=10)
    assert MARKER not in _dumps(out)


# ---------------------------------------------------------------------------
# filter_headers — FR-12
# ---------------------------------------------------------------------------


def test_FR_12_AC_06_allowlist_only_dropped_headers_vanish() -> None:
    headers = [
        (b"host", b"api.example.com"),
        (b"content-type", b"application/json"),
        (b"user-agent", b"python-httpx/0.28.1"),
        (b"authorization", b"Bearer " + MARKER.encode()),
        (b"cookie", b"session=" + MARKER.encode()),
        (b"x-api-key", MARKER.encode()),
    ]
    out = filter_headers(headers, ALLOW)
    assert out == {
        "host": "api.example.com",
        "content-type": "application/json",
        "user-agent": "python-httpx/0.28.1",
    }
    # Not even the name survives — no redacted placeholder (FR-12).
    assert "authorization" not in out
    assert "cookie" not in out
    assert "x-api-key" not in out
    assert MARKER not in _dumps(out)


def test_FR_12_header_names_are_matched_case_insensitively() -> None:
    out = filter_headers([(b"Content-Type", b"text/plain"), (b"HOST", b"h")], ALLOW)
    assert out == {"content-type": "text/plain", "host": "h"}


def test_FR_12_duplicate_header_names_are_joined_like_http_does() -> None:
    out = filter_headers(
        [
            (b"accept", b"text/html"),
            (b"Accept", b"application/json"),
            (b"accept", b"*/*"),
        ],
        ALLOW,
    )
    assert out == {"accept": "text/html, application/json, */*"}


def test_FR_12_duplicate_non_allowlisted_headers_still_vanish() -> None:
    out = filter_headers([(b"cookie", b"a=1"), (b"cookie", b"b=2")], ALLOW)
    assert out == {}


def test_FR_12_undecodable_bytes_do_not_raise() -> None:
    """latin-1 is the ASGI convention: every byte decodes, nothing raises."""
    out = filter_headers([(b"user-agent", b"caf\xe9/\xff\xfe")], ALLOW)
    assert out["user-agent"] == "café/ÿþ"

    # A non-UTF-8 header *name* simply fails to match the allowlist.
    assert filter_headers([(b"x-\xff", b"v")], ALLOW) == {}


def test_FR_12_empty_inputs() -> None:
    assert filter_headers([], ALLOW) == {}
    assert filter_headers([(b"content-type", b"application/json")], frozenset()) == {}
    assert filter_headers([(b"content-type", b"")], ALLOW) == {"content-type": ""}


def test_FR_12_whitespace_around_names_and_values_is_trimmed() -> None:
    out = filter_headers([(b" Accept ", b"  application/json  ")], ALLOW)
    assert out == {"accept": "application/json"}


def test_FR_13_extra_header_allowlist_is_additive() -> None:
    effective = DEFAULT_HEADER_ALLOWLIST | {k.lower() for k in ["X-Tenant-ID"]}
    out = filter_headers(
        [(b"x-tenant-id", b"t-1"), (b"authorization", MARKER.encode())], effective
    )
    assert out == {"x-tenant-id": "t-1"}
    assert DEFAULT_HEADER_ALLOWLIST <= effective


def test_filter_headers_does_not_mutate_its_input() -> None:
    headers = [(b"host", b"h"), (b"cookie", b"c")]
    before = list(headers)
    filter_headers(headers, ALLOW)
    assert headers == before


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------

_KEY_POOL = [
    "password", "Pass-Word", "api_key", "API.KEY", "__token__", "Set-Cookie",
    "cvv", "SSN", "user", "id", "items", "nested", "amount", "0", "a b",
]

_LEAVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=8),
    st.just(MARKER),
)

_JSONISH = st.recursive(
    _LEAVES,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.sampled_from(_KEY_POOL), children, max_size=4),
    ),
    max_leaves=12,
)


def _depth(obj: Any) -> int:
    if isinstance(obj, dict):
        return 1 + max((_depth(v) for v in obj.values()), default=0)
    if isinstance(obj, list):
        return 1 + max((_depth(v) for v in obj), default=0)
    return 0


def _assert_redacted(inp: Any, out: Any, depth: int, limit: int) -> None:
    """Walk input and output together, checking every rule at every node."""
    if depth >= limit:
        assert out == TRUNCATED
        return
    if isinstance(inp, dict):
        assert isinstance(out, dict)
        assert list(out.keys()) == list(inp.keys()), "key structure changed"
        for key, value in inp.items():
            if normalize_key(key) in KEYS:
                assert out[key] == REDACTED
                # Nothing from the condemned subtree leaked through.
                assert MARKER not in _dumps({"x": out[key]}) or value == MARKER
            else:
                _assert_redacted(value, out[key], depth + 1, limit)
        return
    if isinstance(inp, list):
        assert isinstance(out, list)
        assert len(out) == len(inp)
        for a, b in zip(inp, out):
            _assert_redacted(a, b, depth + 1, limit)
        return
    assert out == inp or (out != out and inp != inp)  # NaN excluded by strategy


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(_JSONISH)
def test_property_no_denylisted_value_survives(obj: Any) -> None:
    """(a) No value stored under a denylisted key survives, at any depth."""
    out = redact(obj, KEYS)
    _assert_redacted(obj, out, 0, 20)


@settings(max_examples=200)
@given(_JSONISH, st.integers(min_value=0, max_value=6), st.sampled_from(
    ["password", "Pass-Word", "api_key", "API.KEY", "__token__", "cvv", "SSN"]
))
def test_property_planted_secret_never_survives_at_any_depth(
    payload: Any, extra_depth: int, secret_key: str
) -> None:
    """A subtree under a denylisted key is unreachable however deep it sits."""
    node: Any = {secret_key: {"payload": payload, "raw": MARKER}}
    for i in range(extra_depth):
        node = {"level": [node]} if i % 2 else [{"level": node}]
    assert MARKER not in _dumps(redact(node, KEYS))
    # ...and also when the whole thing is buried past the depth cap.
    assert MARKER not in _dumps(redact(node, KEYS, depth_limit=2))


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(_JSONISH)
def test_property_key_structure_is_preserved(obj: Any) -> None:
    """(b) Nothing added, nothing dropped — below the depth cap."""

    def actual(node: Any) -> Any:
        """Shape of the output: keys kept, every leaf collapsed to None."""
        if isinstance(node, dict):
            return {k: actual(v) for k, v in node.items()}
        if isinstance(node, list):
            return [actual(v) for v in node]
        return None

    def expected(node: Any) -> Any:
        """Shape the input should produce: a denylisted value is a leaf."""
        if isinstance(node, dict):
            return {
                k: (None if normalize_key(k) in KEYS else expected(v))
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [expected(v) for v in node]
        return None

    out = redact(obj, KEYS, depth_limit=_depth(obj) + 1)
    assert actual(out) == expected(obj)


@settings(max_examples=200)
@given(_JSONISH)
def test_property_redact_never_mutates_its_input(obj: Any) -> None:
    before = copy.deepcopy(obj)
    redact(obj, KEYS)
    assert obj == before


@settings(max_examples=200)
@given(
    st.lists(
        st.tuples(
            st.sampled_from(
                [b"host", b"Accept", b"cookie", b"authorization", b"x-request-id",
                 b"content-type", b"x-secret", b"", b"\xff\xfe"]
            ),
            st.binary(max_size=12),
        ),
        max_size=8,
    )
)
def test_property_filter_headers_only_ever_returns_allowlisted_names(
    headers: list[tuple[bytes, bytes]]
) -> None:
    out = filter_headers(headers, ALLOW)
    assert set(out) <= ALLOW
    for name, value in out.items():
        assert name == name.lower()
        assert isinstance(value, str)


# ---------------------------------------------------------------------------
# Known limitations — asserted so they are documented facts, not surprises.
# These belong in docs/redaction.md.
# ---------------------------------------------------------------------------


def test_LIMITATION_unicode_homoglyph_keys_are_not_caught() -> None:
    """``раssword`` with Cyrillic а/с is a different string and is NOT caught.

    normalize_key does casefolding and separator stripping only. It performs no
    Unicode confusable mapping, so a homoglyph key passes straight through.
    """
    homoglyph = "раssword"  # Cyrillic ‘р’ and ‘а’
    assert homoglyph != "password"
    assert normalize_key(homoglyph) not in DEFAULT_REDACT_KEYS
    out = redact({homoglyph: MARKER}, KEYS)
    assert out == {homoglyph: MARKER}, "behaviour changed — update docs/redaction.md"


def test_LIMITATION_unicode_normalization_forms_are_not_folded() -> None:
    """NFKC-equivalent keys (fullwidth, ligatures) are not folded either."""
    fullwidth = "ｐａｓｓｗｏｒｄ"
    assert redact({fullwidth: MARKER}, KEYS) == {fullwidth: MARKER}


def test_LIMITATION_matching_is_exact_not_substring() -> None:
    """A compound key only matches if the whole normalized key is on the list.

    This is why the defaults carry explicit spellings like ``oldpassword``.
    Keys nobody enumerated still leak.
    """
    assert redact({"user_password_2": MARKER}, KEYS) == {"user_password_2": MARKER}
    assert redact({"my_secret_stuff": MARKER}, KEYS) == {"my_secret_stuff": MARKER}
    # The enumerated variants that *are* covered:
    assert redact({"old_password": MARKER}, KEYS) == {"old_password": REDACTED}
    assert redact({"x-api-key": MARKER}, KEYS) == {"x-api-key": REDACTED}


def test_LIMITATION_whitespace_inside_keys_is_not_stripped() -> None:
    """Only ``_``, ``-`` and ``.`` are stripped — spaces and tabs are not."""
    assert redact({"pass word": MARKER}, KEYS) == {"pass word": MARKER}
    assert redact({" password ": MARKER}, KEYS) == {" password ": MARKER}


def test_LIMITATION_secrets_in_values_are_never_detected() -> None:
    """Redaction is key-driven. A secret in a value, or in free text, stays."""
    body = {"note": f"the password is {MARKER}", "url": f"https://x/?token={MARKER}"}
    assert redact(body, KEYS) == body


def test_LIMITATION_denylisted_keys_are_over_redacted() -> None:
    """``hash``, ``salt``, ``sig``, ``pan``, ``session`` are broad by mandate.

    Benign fields with those names lose their values, and FR-13/D-12 give no
    way to opt out. That is the deliberate trade.
    """
    assert redact({"hash": "git-abc123", "pan": "fried"}, KEYS) == {
        "hash": REDACTED,
        "pan": REDACTED,
    }


def test_LIMITATION_pii_is_not_redacted_by_default() -> None:
    """Email, phone, name, address, DOB are not on the denylist.

    They are frequently load-bearing in an audit trail, and because extension
    is additive-only a bad default cannot be undone. Services that must not
    store them add them via ``extra_redact_keys``.
    """
    body = {"email": "a@b.c", "phone": "+998901234567", "date_of_birth": "1990-01-01"}
    assert redact(body, KEYS) == body


def test_LIMITATION_truncation_loses_data_not_just_secrets() -> None:
    """Past the cap everything goes, benign values included. Safety over fidelity."""
    assert redact(_nest(21, {"harmless": 1}), KEYS) != _nest(21, {"harmless": 1})


def test_LIMITATION_recursion_is_bounded_by_the_depth_limit_only() -> None:
    """A caller passing a huge depth_limit can still hit Python's own limit."""
    deep = _nest(2000, 1)
    with pytest.raises(RecursionError):
        redact(deep, KEYS, depth_limit=10_000)
    # The default is nowhere near it.
    assert redact(deep, KEYS) is not None


# ---------------------------------------------------------------------------
# Key sanitisation — review N-9, and the NUL case from the A5 fix pass
#
# `audit.request.body` and friends are `flattened` (docs/schema.md §2.7).
# Lucene indexes each leaf as `key + NUL + value` and rejects the term — and
# therefore the WHOLE document — when it exceeds MAX_TERM_LENGTH or when the
# key carries the separator itself. Body keys are attacker-chosen, so both are
# remotely triggerable, and the document lost is the record of the very request
# that triggered it. These tests assert on the emitted keys because that is the
# only thing this package controls; the term the cluster builds is `key`, `\0`
# and a value already capped by the template's `ignore_above`.
# ---------------------------------------------------------------------------

#: Lucene 8.13.4 `IndexWriter.MAX_TERM_LENGTH`.
LUCENE_MAX_TERM_BYTES = 32_766

#: The largest value the template's `ignore_above: 1024` still admits, in
#: bytes: `ignore_above` counts characters, a character is up to 4 UTF-8 bytes.
WORST_CASE_VALUE_BYTES = 4 * 1024

#: Everything Lucene's flattened parser or the JSONL line itself cannot carry.
_UNSAFE_IN_KEY = re.compile(r"[\x00-\x1f\x7f\ud800-\udfff]")


def _assert_key_is_indexable(key: Any) -> None:
    """The one invariant: this key can never reject the document."""
    if not isinstance(key, str):
        return
    encoded = key.encode("utf-8")  # raises on a lone surrogate: that is the test
    assert len(encoded) <= MAX_KEY_BYTES, f"{len(encoded)} B key"
    assert _UNSAFE_IN_KEY.search(key) is None, f"control character in {key!r}"
    # The real constraint, restated: key + NUL + worst-case value.
    assert len(encoded) + 1 + WORST_CASE_VALUE_BYTES <= LUCENE_MAX_TERM_BYTES


def _walk_keys(obj: Any) -> list[Any]:
    """Every key emitted anywhere in a redacted structure."""
    found: list[Any] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            found.append(key)
            found.extend(_walk_keys(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_walk_keys(item))
    return found


def test_N_9_the_chosen_bound_is_safe_against_the_real_lucene_limit() -> None:
    """The bound is derived from `key + NUL + value <= MAX_TERM_LENGTH`."""
    assert MAX_KEY_BYTES + 1 + WORST_CASE_VALUE_BYTES <= LUCENE_MAX_TERM_BYTES
    # And with a lot of room to spare, because the value cap lives in a
    # template this package does not own.
    assert MAX_KEY_BYTES * 4 < LUCENE_MAX_TERM_BYTES


def test_N_9_a_forty_kilobyte_key_no_longer_destroys_the_document() -> None:
    """The constructed case from REVIEW.md N-9, verbatim."""
    body = json.loads(json.dumps({"k" * 40_000: "v"}))
    out = redact(body, KEYS)

    assert len(out) == 1
    (key,) = out
    _assert_key_is_indexable(key)
    assert out[key] == "v"  # the value is untouched; only the key was cut
    assert key.startswith("kkkk")  # still recognisable as the key it came from


def test_N_9_a_key_one_byte_over_the_bound_is_rewritten() -> None:
    at_bound = "a" * MAX_KEY_BYTES
    over_bound = "a" * (MAX_KEY_BYTES + 1)

    assert sanitize_key(at_bound) is at_bound, "the bound itself must pass"
    assert sanitize_key(over_bound) != over_bound
    _assert_key_is_indexable(sanitize_key(over_bound))


def test_N_9_bound_is_bytes_not_characters() -> None:
    """One character can be four bytes; the cap is on the encoded form."""
    key = "😀" * (MAX_KEY_BYTES // 2)  # half the characters, twice the bytes
    assert len(key) < MAX_KEY_BYTES
    assert len(key.encode("utf-8")) > MAX_KEY_BYTES

    out = redact({key: 1}, KEYS)
    (emitted,) = out
    _assert_key_is_indexable(emitted)


def test_N_9_truncation_never_cuts_a_character_in_half() -> None:
    """A prefix cut mid-sequence would be invalid UTF-8 and unserialisable."""
    for pad in range(8):  # every alignment of a 4-byte character to the cut
        key = "a" * pad + "😀" * MAX_KEY_BYTES
        emitted = sanitize_key(key)
        _assert_key_is_indexable(emitted)
        assert emitted.encode("utf-8").decode("utf-8") == emitted


def test_N_9_over_long_keys_survive_json_serialisation() -> None:
    """The whole point: the document is still shippable."""
    body = {"k" * 40_000: "v", "n": [{"j" * 90_000: {"deep": 1}}]}
    line = _dumps(redact(body, KEYS))
    assert len(line) < 4096, "a hostile key no longer bloats the line either"
    json.loads(line)


def test_N_9_a_denylisted_key_is_still_redacted_after_sanitisation() -> None:
    """Sanitisation reads the key; the denylist verdict is taken before it."""
    long_key = "a" * (MAX_KEY_BYTES + 500)
    keys = KEYS | {normalize_key(long_key)}

    out = redact({long_key: MARKER}, keys)
    (emitted,) = out
    _assert_key_is_indexable(emitted)
    assert out[emitted] == REDACTED
    assert MARKER not in _dumps(out)


# --- the NUL / control-character case (A5 fix pass, not in REVIEW.md) -------


def test_NUL_in_a_body_key_no_longer_destroys_the_document() -> None:
    """A 15-byte body used to cost the entire audit record."""
    body = json.loads(r'{"a\u0000b": 1}')
    assert body == {"a\x00b": 1}

    out = redact(body, KEYS)
    (key,) = out
    _assert_key_is_indexable(key)
    assert out[key] == 1


def test_NUL_every_c0_control_and_del_is_removed() -> None:
    body = {f"a{chr(c)}b": c for c in list(range(0x20)) + [0x7F]}
    out = redact(body, KEYS)

    assert len(out) == len(body), "distinct control characters collapsed"
    for key in out:
        _assert_key_is_indexable(key)


def test_NUL_control_characters_at_depth_and_inside_lists() -> None:
    body = {"ok": [{"a\x00b": {"c\x1fd": [{"e\x7ff": MARKER}]}}]}
    out = redact(body, KEYS)

    keys = _walk_keys(out)
    assert len(keys) == 4
    for key in keys:
        _assert_key_is_indexable(key)
    assert MARKER in _dumps(out), "only the keys are rewritten, not the values"


def test_NUL_a_lone_surrogate_key_cannot_break_the_jsonl_line() -> None:
    """`json` accepts `\\ud800` from an escape; UTF-8 cannot encode it."""
    body = json.loads(r'{"a\ud800b": 1}')
    with pytest.raises(UnicodeEncodeError):
        body_key_bytes = next(iter(body)).encode("utf-8")
        assert body_key_bytes  # pragma: no cover - the encode raises

    out = redact(body, KEYS)
    (key,) = out
    _assert_key_is_indexable(key)
    json.dumps(out, ensure_ascii=False).encode("utf-8")  # would raise before


def test_NUL_a_denylisted_key_carrying_a_control_char_is_still_redacted() -> None:
    keys = KEYS | {normalize_key("pass\x00word")}
    out = redact({"pass\x00word": MARKER}, keys)

    (key,) = out
    _assert_key_is_indexable(key)
    assert out[key] == REDACTED


# --- distinctness: corruption is not an improvement on loss -----------------


def test_N_9_two_long_keys_sharing_a_prefix_stay_distinct() -> None:
    """A plain cut would merge these into one key and lose a field."""
    a = "x" * 5_000 + "-alpha"
    b = "x" * 5_000 + "-beta"
    assert sanitize_key(a) != sanitize_key(b)

    out = redact({a: 1, b: 2}, KEYS)
    assert len(out) == 2, "two distinct fields became one"
    assert sorted(out.values()) == [1, 2]
    for key in out:
        _assert_key_is_indexable(key)


def test_N_9_keys_differing_only_past_the_cut_stay_distinct() -> None:
    """The digest is taken over the whole original, not the surviving prefix."""
    base = "y" * 40_000
    out = redact({base + "1": "a", base + "2": "b"}, KEYS)
    assert len(out) == 2


def test_NUL_distinct_control_characters_do_not_collapse() -> None:
    out = redact({"a\x00b": 1, "a\x01b": 2, "a\x02b": 3}, KEYS)
    assert len(out) == 3
    assert sorted(out.values()) == [1, 2, 3]


def test_N_9_a_forged_sanitised_key_cannot_collide_with_a_real_one() -> None:
    """A client that replays our own output must not shadow the real key."""
    hostile = "a\x00b"
    forged = sanitize_key(hostile)  # the exact key we would emit for it

    out = redact({hostile: "real", forged: "forgery"}, KEYS)
    assert len(out) == 2, "the forged key shadowed the sanitised one"
    assert sorted(out.values()) == ["forgery", "real"]
    for key in out:
        _assert_key_is_indexable(key)


# --- the ordinary case is untouched ----------------------------------------


def test_ordinary_keys_are_returned_unchanged_and_unwrapped() -> None:
    """~100 % of traffic must not even allocate: same object back."""
    for key in ["sku", "order_id", "X-Request-ID", "a b", "0", "", "цена", "😀"]:
        assert sanitize_key(key) is key
    assert sanitize_key(1) == 1
    assert sanitize_key(None) is None


# --- properties over hostile structures ------------------------------------

#: Fragments chosen so that a joined key can be over-long, control-bearing,
#: surrogate-bearing, multi-byte, marker-forging, or perfectly ordinary.
_HOSTILE_FRAGMENTS = [
    "a", "order_id", " ", "0", "ß", "😀", " ",
    "\x00", "\x01", "\x1f", "\x7f", "\ud800", "\udfff",
    "[SANITIZED:", "]", "password", "x" * 700, "y" * 40_000,
]

_HOSTILE_KEYS = st.builds(
    "".join, st.lists(st.sampled_from(_HOSTILE_FRAGMENTS), max_size=6)
)

_HOSTILE_JSONISH = st.recursive(
    _LEAVES,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(_HOSTILE_KEYS, children, max_size=4),
    ),
    max_leaves=8,
)


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(_HOSTILE_JSONISH)
def test_property_every_emitted_key_is_indexable(obj: Any) -> None:
    """No input structure can produce a key that rejects the document."""
    for key in _walk_keys(redact(obj, KEYS)):
        _assert_key_is_indexable(key)


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(_HOSTILE_KEYS, min_size=1, max_size=6, unique=True))
def test_property_distinct_keys_never_collapse(keys: list[str]) -> None:
    """Data corruption is not an improvement on data loss."""
    body = {key: i for i, key in enumerate(keys)}
    # No denylist: this is about keys, and a redacted value would hide a merge.
    out = redact(body, frozenset())

    assert len(out) == len(body)
    assert sorted(out.values()) == sorted(body.values())


@settings(max_examples=200)
@given(_HOSTILE_KEYS)
def test_property_sanitize_key_is_deterministic(key: str) -> None:
    """Same key in, same key out — a term that changes per process is useless."""
    assert sanitize_key(key) == sanitize_key(key)
    # Deliberately *not* idempotent: a key already shaped like our own output
    # is rewritten again, which is what stops a client forging a collision
    # (test_N_9_a_forged_sanitised_key_cannot_collide_with_a_real_one). The
    # result stays inside the bound however many times it is applied.
    _assert_key_is_indexable(sanitize_key(sanitize_key(key)))


def test_sanitisation_leaves_a_realistic_body_byte_identical() -> None:
    body = {
        "sku": "A-11",
        "qty": 3,
        "customer": {"name": "a.karimov", "password": "hunter2"},
        "lines": [{"sku": "L-1", "note": "n"}],
    }
    before = _dumps(redact(body, frozenset()))
    assert before == _dumps(body)


# ---------------------------------------------------------------------------
# Benchmark — plan §8/A3: 1 MB of nested JSON in < 20 ms
# ---------------------------------------------------------------------------


def _one_megabyte_of_nested_json() -> Any:
    """~1 MB of realistic, deeply-nested, denylist-hitting JSON."""
    record = {
        "id": "0123456789abcdef",
        "user": {
            "name": "a.karimov",
            "password": "hunter2",
            "profile": {"email": "a@b.c", "api_key": "k" * 32, "tags": ["x", "y", "z"]},
        },
        "payment": {"card": {"pan": "4111111111111111", "cvv": "123"}, "amount": 42.5},
        "items": [
            {"sku": f"A-{i}", "qty": i, "meta": {"token": "t" * 16, "note": "n" * 24}}
            for i in range(6)
        ],
        "trace": {"id": "9f2c1a7d4e8b4f0a", "parent": None, "flags": [True, False]},
    }
    payload = {"records": []}
    blob: list[Any] = payload["records"]
    while len(json.dumps(payload)) < 1_048_576:
        blob.extend(copy.deepcopy(record) for _ in range(64))
    return payload


@pytest.mark.load
def test_benchmark_one_megabyte_under_20ms() -> None:
    payload = _one_megabyte_of_nested_json()
    size = len(json.dumps(payload))
    assert size >= 1_048_576

    redact(payload, KEYS)  # warm caches / branch predictors
    timings = []
    # Disabled the way ``timeit`` disables it: this measures redact(), not the
    # cost of a generation-2 sweep over whatever the rest of the module (the
    # hypothesis tests, mostly) still has live. Measured 12 ms alone and 26 ms
    # after the property tests, on identical code, before this was added.
    gc.collect()
    gc.disable()
    try:
        for _ in range(5):
            start = time.perf_counter()
            redact(payload, KEYS)
            timings.append((time.perf_counter() - start) * 1000.0)
    finally:
        gc.enable()

    best = min(timings)
    print(f"\nredact(): {size / 1024:.0f} KiB in {best:.2f} ms (best of 5, "
          f"median {sorted(timings)[2]:.2f} ms)")
    assert best < 20.0, f"1 MB took {best:.2f} ms, budget is 20 ms"


# ---------------------------------------------------------------------------
# REVIEW-2 N2-1 — a lone surrogate in a *value* deleted the whole document
#
# `{"a":"\ud800"}` is 14 bytes. orjson refuses to parse it, document.py's
# stdlib fallback accepts it, redact() used to pass it through untouched, and
# the sink's orjson.dumps then refused to serialise the document — so the
# request had no audit record at all and the loss was counted as disk pressure.
# The reasoning that covers keys ("cannot be encoded as UTF-8 at all: they
# would break the JSONL line itself") is the same reasoning; it just was not
# applied on the value side.
#
# The invariant asserted here is exactly the one the sink needs: every string
# the document carries survives `str.encode("utf-8")`.
# ---------------------------------------------------------------------------


def _walk_strings(obj: Any) -> list[str]:
    """Every string emitted anywhere in a redacted structure, keys included."""
    found: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str):
                found.append(key)
            found.extend(_walk_strings(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_walk_strings(item))
    elif isinstance(obj, str):
        found.append(obj)
    return found


def _assert_line_is_writable(out: Any) -> None:
    """No string in `out` can stop the JSONL line from being encoded."""
    for text in _walk_strings(out):
        text.encode("utf-8")  # raises on a lone surrogate: that is the test
    json.dumps(out, ensure_ascii=False).encode("utf-8")


def test_N2_1_a_lone_surrogate_value_cannot_break_the_jsonl_line() -> None:
    """The 14-byte body from REVIEW-2 N2-1, verbatim."""
    body = json.loads('{"a":"\\ud800"}')
    assert body == {"a": "\ud800"}
    out = redact(body, KEYS)
    _assert_line_is_writable(out)
    assert out["a"] != "\ud800"


def test_N2_1_surrogate_values_survive_at_depth_and_inside_lists() -> None:
    """The placement sweep from the finding: every value path, not just the top."""
    for body in (
        {"a": {"b": ["\udfff"]}},
        {"a": ["x", ["y", {"c": "\ud800"}]]},
        ["\ud800", {"k": "\udc00"}],
        {"a": "text with \ud800 in the middle and \udfff at the end"},
        "\ud800",
    ):
        out = redact(body, KEYS)
        _assert_line_is_writable(out)


def test_a_surrogate_value_under_a_denylisted_key_is_still_redacted() -> None:
    """Guard, not a regression: this row of the placement sweep already held."""
    out = redact({"password": "\ud800", "token": {"a": "\udfff"}}, KEYS)
    assert out == {"password": REDACTED, "token": REDACTED}
    _assert_line_is_writable(out)


def test_N2_1_distinct_surrogate_values_do_not_collapse_into_one() -> None:
    """Replacement alone is lossy; the digest is what keeps values distinct."""
    out = redact({"a": "\ud800", "b": "\udfff", "c": "�"}, KEYS)
    _assert_line_is_writable(out)
    assert len({out["a"], out["b"], out["c"]}) == 3
    # And a client cannot pass off a real U+FFFD as one we wrote.
    assert out["c"] == "�"


def test_N2_1_a_surrogate_value_is_marked_not_silently_replaced() -> None:
    out = redact({"a": "before\ud800after"}, KEYS)
    assert out["a"].startswith("before�after")
    assert "[SANITIZED:" in out["a"]


def test_N2_1_surrogate_keys_and_values_together() -> None:
    """Both halves at once — the key path and the value path do not interfere."""
    out = redact({"\ud800": "\udfff"}, KEYS)
    _assert_line_is_writable(out)
    assert len(out) == 1


def test_values_that_are_already_encodable_are_returned_unchanged() -> None:
    """Guard: the fix must not touch ~100 % of traffic. Same object back."""
    values = ["", "hunter2", "a" * 5000, "цена", "😀", "line\nbreak\ttab",
              "\x00\x01\x1f\x7f", "[SANITIZED:deadbeefdeadbeef]", "�"]
    for value in values:
        out = redact({"k": value}, frozenset())
        assert out["k"] is value, repr(value)
    body = {"sku": "A-11", "note": "ok", "n": [1, 2.5, True, None, "x"]}
    assert _dumps(redact(body, frozenset())) == _dumps(body)


#: `st.text()` will not emit a surrogate — not from `st.characters()` and not
#: from an alphabet that merely contains one — so they are joined in from
#: fragments, the way `_HOSTILE_KEYS` above does. Without this the strategy is
#: silently benign and the property below passes against the unfixed code.
_SURROGATE_FRAGMENTS = [
    "", "a", "ok", "é", "😀", "\N{REPLACEMENT CHARACTER}", MARKER,
    "\ud800", "\udbff", "\udc00", "\udfff", "[SANITIZED:", "]",
]

_SURROGATE_TEXT = st.builds(
    "".join, st.lists(st.sampled_from(_SURROGATE_FRAGMENTS), max_size=5)
)

_SURROGATE_JSONISH = st.recursive(
    st.one_of(_LEAVES, _SURROGATE_TEXT),
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.sampled_from(_KEY_POOL), children, max_size=4),
    ),
    max_leaves=10,
)


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(_SURROGATE_JSONISH)
def test_N2_1_property_every_emitted_string_is_utf8_encodable(obj: Any) -> None:
    """No input structure can produce a document that cannot be written."""
    _assert_line_is_writable(redact(obj, KEYS))


# ---------------------------------------------------------------------------
# REVIEW-2 N2-2 — the key memo was capped in entries, not in bytes
#
# Each entry's dict key was the original, attacker-supplied string, held alive
# across requests until 4096 entries had accumulated: 4000 requests carrying
# one 256 KB key retained 1000 MiB, and the reviewer's process was OOM-killed
# at max_body_bytes. Only keys the fast path can serve are memoised now, so the
# retained text is bounded by _KEY_CACHE_MAX x _ALWAYS_SHORT_ENOUGH.
# ---------------------------------------------------------------------------

#: The bound this module can now state on process-lifetime memory attributable
#: to key memoisation, in characters of retained key text.
KEY_CACHE_CHAR_BOUND = R._KEY_CACHE_MAX * R._ALWAYS_SHORT_ENOUGH


def test_N2_2_a_long_key_is_never_memoised() -> None:
    R._key_cache.clear()
    redact({"k" * (R._ALWAYS_SHORT_ENOUGH + 1): 1}, KEYS)
    assert R._key_cache == {}
    # The threshold itself is still cached: this is a bound, not a bypass.
    key = "k" * R._ALWAYS_SHORT_ENOUGH
    redact({key: 1}, KEYS)
    assert key in R._key_cache


def test_N2_2_repeated_requests_with_a_huge_key_retain_nothing() -> None:
    """REVIEW-2's repro, scaled down: one 64 KB key per request, 300 requests.

    Before the fix this retained 300 x 65,536 = 19.6 M characters and kept
    growing to 4096 entries — about 4 GiB at max_body_bytes.
    """
    R._key_cache.clear()
    for i in range(300):
        key = str(i).zfill(6) + "k" * (65_536 - 20)
        redact({key: 1}, KEYS)
    retained = sum(len(k) for k in R._key_cache)
    assert retained == 0, f"{retained} characters retained"


def test_N2_2_the_memo_is_bounded_in_characters_not_only_in_entries() -> None:
    """The stated bound: 4096 x 256 = 1,048,576 characters of key text.

    Filled the way an attacker fills it — one distinct 4 KB key per request —
    and then the way ordinary traffic does. Before the fix the first loop alone
    retained 1.6 M characters and would have gone on to 268 M at 4096 entries.
    """
    assert KEY_CACHE_CHAR_BOUND == 1_048_576
    R._key_cache.clear()
    for i in range(400):
        redact({str(i).zfill(6) + "k" * (16 * R._ALWAYS_SHORT_ENOUGH): 1}, KEYS)
    assert sum(len(k) for k in R._key_cache) <= KEY_CACHE_CHAR_BOUND
    for i in range(R._KEY_CACHE_MAX):
        redact({str(i).zfill(6) + "k" * 250: 1}, KEYS)
    assert len(R._key_cache) <= R._KEY_CACHE_MAX
    assert all(len(k) <= R._ALWAYS_SHORT_ENOUGH for k in R._key_cache)
    assert sum(len(k) for k in R._key_cache) <= KEY_CACHE_CHAR_BOUND
    R._key_cache.clear()


def test_the_module_retains_nothing_else_across_calls() -> None:
    """Guard for N2-2's real question: what else outlives a request?

    `_key_cache` is the only mutable module-level state in this module. The
    per-call `_Decisions` memo also holds full-length keys, but it is created
    inside `redact()` and dies with the call, so it is in-flight memory bounded
    by the body — not retention.
    """
    mutable = {
        name: value
        for name, value in vars(R).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set, bytearray))
        and not isinstance(value, frozenset)
    }
    assert set(mutable) == {
        "_key_cache",
        "_STRIP_TABLE",
        "_CONTROL_TABLE",
        "_SURROGATE_TABLE",
    }, sorted(mutable)


# ---------------------------------------------------------------------------
# REVIEW-2 N2-4 — key sanitisation was a 21-214x per-key cost amplifier
#
# The cold path is far more expensive than the fast path and the client picks
# which keys take it: 4,998 keys each carrying one control character is a 73 KB
# body, inside every cap, that cost 20 ms end to end. The node cap bounds the
# node *count*; the cost of a node is attacker-chosen, so the *work* is bounded
# here instead. Past `_COLD_KEY_BUDGET` cold-path keys in one call the rewrite
# degrades to a constant-cost form that is less informative and never less safe.
# ---------------------------------------------------------------------------


def _hostile_key_body(n: int = 4998, suffix: str = "\x01") -> dict[str, int]:
    return {("k%04d" % i) + suffix: i for i in range(n)}


def test_N2_4_cold_path_sanitisations_are_bounded_per_call() -> None:
    R._key_cache.clear()
    out = redact(_hostile_key_body(), KEYS)
    full = [k for k in out if R._KEY_MARK in k and R._KEY_BUDGET_MARK not in k]
    degraded = [k for k in out if R._KEY_BUDGET_MARK in k]
    assert len(full) == R._COLD_KEY_BUDGET
    assert len(degraded) == 4998 - R._COLD_KEY_BUDGET


def test_N2_4_over_budget_keys_are_still_safe_and_still_distinct() -> None:
    """Degrading informativeness is allowed; degrading safety is not."""
    R._key_cache.clear()
    body = _hostile_key_body()
    out = redact(body, KEYS)
    assert len(out) == len(body), "distinct keys collapsed onto one another"
    for key in out:
        _assert_key_is_indexable(key)
    assert any(R._KEY_BUDGET_MARK in k for k in out), "budget never engaged"


def test_N2_4_the_budget_keeps_what_it_can_of_a_long_printable_key() -> None:
    """The realistic over-budget case: long, ordinary, machine-generated keys."""
    R._key_cache.clear()
    body = {f"user.profile.address.line.{i:04d}." + "x" * 400: 1 for i in range(300)}
    out = redact(body, KEYS)
    degraded = [k for k in out if R._KEY_BUDGET_MARK in k]
    assert degraded, "budget never engaged"
    assert all(k.startswith("user.profile.address.lin") for k in degraded)
    assert len(out) == len(body)


def test_an_over_budget_key_cannot_forge_the_budget_marker() -> None:
    R._key_cache.clear()
    forged = R._KEY_BUDGET_MARK + "0]"
    body = {forged + "\x01" + ("k%04d" % i): i for i in range(300)}
    out = redact(body, KEYS)
    # A client cannot make two of its keys land on the same entry, whether the
    # budget rewrote them (each gets its own sequence number) or the cold path
    # did (each gets its own digest, over the original).
    assert len(out) == len(body)
    for key in out:
        _assert_key_is_indexable(key)
    degraded = [k for k in out if k.startswith(R._KEY_BUDGET_MARK)]
    assert len(set(degraded)) == len(degraded)


def test_N2_4_the_budget_resets_between_calls() -> None:
    """It bounds the work of one document, not the life of the process."""
    for _ in range(2):
        R._key_cache.clear()  # a cold process, not a warm one
        out = redact(_hostile_key_body(n=200), KEYS)
        assert len([k for k in out if R._KEY_BUDGET_MARK in k]) == 200 - min(
            200, R._COLD_KEY_BUDGET
        )


def test_a_repeat_of_the_same_hostile_body_is_served_from_the_memo() -> None:
    """The budget costs a warm process nothing: the first call filled the memo.

    Keys the budget refused are not memoised (their sequence number means
    nothing outside the call that made it), so on the repeat they are back
    inside the budget and get the full rewrite. Both forms are safe and both
    are distinct; only the shape of the marker differs.
    """
    R._key_cache.clear()
    body = _hostile_key_body(n=200)
    redact(body, KEYS)
    out = redact(body, KEYS)
    assert not [k for k in out if R._KEY_BUDGET_MARK in k]
    assert len(out) == len(body)
    for key in out:
        _assert_key_is_indexable(key)


def test_N2_4_a_hostile_keyset_is_no_longer_a_cost_amplifier() -> None:
    """Ratio against an identically shaped benign body, in the same process.

    Measured 5.00x with the fix reverted in place and 1.34-1.38x with it, both
    stable to +/-0.03 across repeats. The threshold is set at 2.0 because a
    ratio is what the finding is about: an attacker choosing what fraction of
    keys take the expensive path.
    """
    benign = _hostile_key_body(suffix="p")
    hostile = _hostile_key_body(suffix="\x01")

    def best(body: dict[str, int]) -> float:
        timings = []
        gc.collect()
        gc.disable()
        try:
            for _ in range(5):
                R._key_cache.clear()
                start = time.perf_counter()
                redact(body, KEYS)
                timings.append(time.perf_counter() - start)
        finally:
            gc.enable()
        return min(timings)

    redact(benign, KEYS)  # warm
    ratio = best(hostile) / best(benign)
    print(f"\nN2-4 cold-path amplification: {ratio:.2f}x")
    assert ratio < 2.0, f"{ratio:.2f}x amplification from one control character"


def test_one_enormous_key_produces_the_same_output_as_before() -> None:
    """The per-key half of the bound: the cold path cuts first, inspects second.

    Before the fix a 4 MiB key was scanned and `translate`d in full even though
    all but the first 1025 characters are discarded. This asserts the outcome is
    unchanged; the cost is asserted by the ratio test above.
    """
    R._key_cache.clear()
    key = "\x01" + "k" * (4 << 20)
    out = redact({key: 1}, KEYS)
    (emitted,) = out
    _assert_key_is_indexable(emitted)
    assert emitted.startswith("�k")
    assert emitted.endswith("]")
