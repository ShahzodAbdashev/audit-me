"""Redaction — denylist for body keys, allowlist for headers.

Owned by **Agent A3**. Contract: plan §6.5; requirements FR-10…FR-14.

Two independent mechanisms, deliberately asymmetric (D-12):

* **Bodies and query strings** are filtered by a *denylist* of key names. The
  shape is user data, so the keys cannot be enumerated in advance; anything
  whose normalized key is on the denylist has its value replaced by
  ``"[REDACTED]"``. The key itself survives — knowing that a request carried a
  password field is useful; knowing the password is not.
* **Headers** are filtered by an *allowlist*. The header set is small and
  known, so anything unrecognised vanishes entirely rather than appearing as a
  placeholder (FR-12): ``Authorization`` must not even be visible as a name.

Both key sets are extended additively by ``AuditConfig`` (FR-13). There is no
supported way to remove a default.

``redact`` is pure: it returns a new structure and never mutates its input, so
the object the application holds is untouched (FR-10).

Redaction is also where captured **keys and string values** are made safe for
the fields they land in (review N-9, the NUL case found in the A5 fix pass, and
review N2-1). Both are attacker-chosen, and a single hostile one destroys the
whole audit document:

* a key that is too long, or carries a control character, is rejected by
  Elasticsearch at index time — see :func:`_sanitize_key`;
* a key *or a value* holding a lone UTF-16 surrogate cannot be encoded as UTF-8
  at all, so the JSONL line itself cannot be written — see
  :func:`_sanitize_value`. ``{"a":"\\ud800"}`` is a 14-byte body that used to
  delete its own audit record (N2-1).

This is the only place every captured structure passes through, and it is
already the function that rebuilds it, so sanitisation lives here rather than
in ``document.py``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import Any

__all__ = [
    "DEFAULT_REDACT_KEYS",
    "RedactionBudgetExceeded",
    "DEFAULT_HEADER_ALLOWLIST",
    "MAX_KEY_BYTES",
    "REDACTED",
    "TRUNCATED",
    "normalize_key",
    "redact",
    "filter_headers",
    "sanitize_key",
]

REDACTED = "[REDACTED]"
TRUNCATED = "[TRUNCATED]"


class RedactionBudgetExceeded(Exception):
    """A structure carried more distinct keys than the caller allowed.

    Cost here is driven by **first-seen** keys, not by node count: a repeated
    key is two dict lookups, while a new one costs ~1.4 us of normalisation
    and safety checking that no cache can amortise, because it has never been
    seen. Which of the two a body contains is the *client's* choice.

    ``max_body_nodes`` bounds the wrong axis for this. Measured at the shipped
    default: 9,999 nodes made of 4,999 **distinct** keys is 9.09 ms and is
    accepted, while 10,001 nodes of four repeated keys is 0.16 ms and is
    refused (review N3-1). The caller catches this and records the body as
    ``too_complex``, exactly as it does for the node cap.
    """

#: Characters dropped by :func:`normalize_key`, so that ``api_key``,
#: ``api-key``, ``API.KEY`` and ``apiKey`` all collapse to ``apikey``.
_STRIP_TABLE = str.maketrans("", "", "_-.")

#: Key names whose values never reach the audit document.
#:
#: Stored in **normalized** form (see :func:`normalize_key`): lowercase with
#: ``_``, ``-`` and ``.`` removed. Matching is exact on the normalized key, not
#: substring — see ``docs/redaction.md`` for what that does and does not catch.
#:
#: The first block is the minimum mandated by FR-11. The rest are additions
#: covering the same secrets under the spellings real APIs actually use.
DEFAULT_REDACT_KEYS: frozenset[str] = frozenset(
    {
        # --- FR-11 required minimum -------------------------------------
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "apikey",
        "apisecret",
        "authorization",
        "auth",
        "cookie",
        "setcookie",
        "sessionid",
        "session",
        "csrf",
        "xsrf",
        "privatekey",
        "clientsecret",
        "credential",
        "credentials",
        "pin",
        "otp",
        "cardnumber",
        "cardnum",
        "pan",
        "cvv",
        "cvc",
        "ssn",
        "taxid",
        "iban",
        "signature",
        "sig",
        "salt",
        "hash",
        # --- A3 additions: password spellings ---------------------------
        # Exact matching means "old_password" does NOT match "password".
        "passphrase",
        "oldpassword",
        "newpassword",
        "currentpassword",
        "confirmpassword",
        "passwordconfirmation",
        "userpassword",
        "dbpassword",
        "passwordhash",
        # --- A3 additions: token spellings ------------------------------
        "authtoken",
        "apitoken",
        "sessiontoken",
        "sessionkey",
        "bearer",
        "bearertoken",
        "jwt",
        "jwttoken",
        "xapikey",
        "xauthtoken",
        "apikeys",
        "tokens",
        "secrets",
        "authcode",
        "authorizationcode",
        "codeverifier",
        "clientassertion",
        # --- A3 additions: CSRF spellings -------------------------------
        "csrftoken",
        "xsrftoken",
        "xcsrftoken",
        "antiforgerytoken",
        # --- A3 additions: keys and shared secrets ----------------------
        "accesskey",
        "secretkey",
        "secretaccesskey",
        "awssecretaccesskey",
        "awssessiontoken",
        "encryptionkey",
        "signingkey",
        "sshkey",
        "gpgkey",
        "consumersecret",
        "appsecret",
        "webhooksecret",
        "signingsecret",
        "sharedsecret",
        "connectionstring",
        # --- A3 additions: OTP / MFA ------------------------------------
        "otpcode",
        "totp",
        "totpcode",
        "mfacode",
        "mfatoken",
        "twofactorcode",
        "verificationcode",
        "securitycode",
        "recoverycode",
        "backupcode",
        "securityanswer",
        "secretanswer",
        # --- A3 additions: payment and identity documents ---------------
        "cvv2",
        "cardcvv",
        "cardpin",
        "accountnumber",
        "bankaccount",
        "routingnumber",
        "sortcode",
        "passportnumber",
        "nationalid",
        "driverlicense",
        "driverslicense",
        # --- A3 additions: header names seen as body/query keys ---------
        "cookies",
        "proxyauthorization",
    }
)

#: Request/response headers that may be stored, lowercase (FR-12).
#:
#: Everything not listed here is dropped without trace. The list is the
#: FR-12 minimum plus a few routing/observability headers that carry no
#: credential material.
DEFAULT_HEADER_ALLOWLIST: frozenset[str] = frozenset(
    {
        # --- FR-12 required minimum -------------------------------------
        "content-type",
        "content-length",
        "accept",
        "accept-encoding",
        "accept-language",
        "user-agent",
        "referer",
        "origin",
        "host",
        "x-request-id",
        "x-correlation-id",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-real-ip",
        "traceparent",
        "tracestate",
        # --- A3 additions: routing / observability, no credentials ------
        "content-encoding",
        "content-language",
        "connection",
        "cache-control",
        "date",
        "expect",
        "from",
        "te",
        "transfer-encoding",
        "via",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-b3-traceid",
        "x-b3-spanid",
        "b3",
        "baggage",
        "x-amzn-trace-id",
        "x-envoy-external-address",
        "x-request-start",
    }
)


def _as_text(value: object) -> str:
    """Best-effort text for something used as a key. Never raises."""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        # latin-1 is the ASGI convention and is total: every byte decodes.
        return bytes(value).decode("latin-1", "replace")
    try:
        return str(value)
    except Exception:  # pragma: no cover - pathological __str__
        # Unknown shape: return something that cannot match the denylist and
        # cannot be mistaken for a real key.
        return ""


def normalize_key(k: str) -> str:
    """Lowercase and strip ``_``, ``-`` and ``.``.

    ``"Pass-Word"``, ``"pass_word"`` and ``"PASS.WORD"`` all become
    ``"password"``. Non-``str`` input (an ``int`` key from a JSON-ish dict, a
    ``bytes`` key) is coerced defensively rather than raising — this runs in
    the request path, where nothing may raise (NFR-3).
    """
    if k.__class__ is str:
        lowered = k.lower()
        if "_" in lowered or "-" in lowered or "." in lowered:
            return lowered.translate(_STRIP_TABLE)
        return lowered
    return _as_text(k).lower().translate(_STRIP_TABLE)


#: Memo over ``str`` keys: raw key → ``(key to emit, normalized key)``. Real
#: payloads repeat the same key names thousands of times — within one body and
#: across every request to the same endpoint — and these two derivations are
#: the hot path's only string work. Hard-capped, because the keys are
#: attacker-supplied (NFR-2): memory can never grow past the cap. When it
#: fills it is **cleared**, not frozen — one flood of unique keys must not
#: permanently evict a service's real key names and leave every later request
#: recomputing. Clearing is O(1) amortised over the 4096 inserts that filled it.
#:
#: The entry count is only half the bound. The *dict key* is the original,
#: attacker-supplied string, and it stays alive for as long as the entry does —
#: **across requests**, so no amount of backpressure or connection limiting
#: reclaims it. Capped at 4096 entries and nothing else, one 256 KB key per
#: request retained 1000 MiB after 4000 requests and OOM-killed the process at
#: ``max_body_bytes`` (review N2-2). So only keys the fast path can serve are
#: memoised — see :meth:`_Decisions.__missing__` and ``_ALWAYS_SHORT_ENOUGH``.
#: That makes the retained text bounded by
#: ``_KEY_CACHE_MAX × _ALWAYS_SHORT_ENOUGH`` = 1,048,576 characters (≤ 4 MiB of
#: string data even in the UCS-4 worst case), and it costs nothing: a key long
#: enough to be excluded is one the memo could never have helped with, because
#: real payloads repeat *short* key names.
_KEY_CACHE_MAX = 4096
_key_cache: dict[str, tuple[str, str]] = {}
_key_cache_get = _key_cache.get


# ---------------------------------------------------------------------------
# Key sanitisation — keeping a hostile key from destroying the whole document
# ---------------------------------------------------------------------------
#
# ``audit.request.body`` and friends are mapped ``flattened`` (docs/schema.md
# §2.7). Lucene's ``FlattenedFieldParser.addField`` indexes each leaf as the
# single term ``key + NUL + value``. It applies ``ignore_above`` to the *value*
# only and then throws ``IllegalArgumentException`` when the assembled term
# exceeds ``IndexWriter.MAX_TERM_LENGTH`` (32,766 bytes) — before the
# ``isIndexed()`` / ``hasDocValues()`` branches, so ``index: false`` does not
# rescue it. Elasticsearch answers the bulk item with a
# ``mapper_parsing_exception`` and **the entire audit document is lost**: the
# record of the very request that triggered it. No index-template setting can
# prevent it, which is why the bound has to be enforced here, at capture.
#
# Why 1024 bytes:
#
# * The provable ceiling under the shipped template is 32,766 − 1 (the NUL
#   separator) − 4,096 (the largest value ``ignore_above: 1024`` still admits;
#   ``ignore_above`` counts *characters*, and a character is up to 4 UTF-8
#   bytes) = **28,669 bytes**. Any key at or under that is safe today.
# * We do not take 28,669. It is derived from a template this package does not
#   own (``infra/`` is A5's) and from a value cap that may be raised later;
#   1024 bytes stays correct for any ``ignore_above`` up to 7,935 characters,
#   28× of headroom against the real limit.
# * 1024 bytes is also ~4× the longest key ever seen in real traffic (a couple
#   of hundred bytes of generated form-field path), so nothing legitimate is
#   touched, and a 28 KB key is worthless as a search term anyway.
#
# The failure this prevents is worse than a deterministic one: a key over the
# limit whose *value* also exceeds ``ignore_above`` is skipped before the
# length check and indexes cleanly, so the same key shape works intermittently.

#: Largest key, in **UTF-8 bytes**, that may be emitted into a ``flattened``
#: field. See the derivation above.
MAX_KEY_BYTES = 1024

#: A truncated or de-controlled key carries a digest of the key it came from,
#: so that two distinct inputs cannot silently become one output — data
#: corruption is not an improvement on data loss. 64 bits of BLAKE2b over the
#: original key; the marker is what makes the rewrite visible to a reader.
_KEY_MARK = "[SANITIZED:"
_KEY_DIGEST_SIZE = 8
_KEY_SUFFIX_BYTES = len(_KEY_MARK) + 2 * _KEY_DIGEST_SIZE + 1  # + closing "]"
_MAX_KEY_PREFIX_BYTES = MAX_KEY_BYTES - _KEY_SUFFIX_BYTES

#: What makes a key unsafe to emit:
#:
#: * ``\x00``-``\x1f`` — the whole C0 range. NUL is the flattened parser's own
#:   key/value separator (a 15-byte body ``{"a\x00b": 1}`` loses the document);
#:   the rest are illegal in JSON text unescaped and worthless as terms.
#: * ``\x7f`` — DEL, a control character by every other definition.
#: * ``\ud800``-``\udfff`` — lone surrogates. ``json`` accepts them from
#:   ``\uXXXX`` escapes, and they cannot be encoded as UTF-8 at all: they would
#:   break the JSONL line itself, not just the term. (Values are exposed to
#:   exactly this — see :func:`_sanitize_value`.)
#:
#: A key that is already shaped like a sanitised one is unsafe too, so that a
#: client cannot collide with a real rewrite (see :func:`_sanitize_key`) — but
#: that is tested with ``in``, not here. Folding the literal into this pattern
#: turns a single character-class scan into an alternation and costs **5×**:
#: 9.5 µs against 1.9 µs on a 1100-character key, and the cold path is exactly
#: what an attacker chooses to hit (review N2-4).
_UNSAFE_KEY_CHAR = re.compile(r"[\x00-\x1f\x7f\ud800-\udfff]")
_unsafe_char_search = _UNSAFE_KEY_CHAR.search

#: Everything ``_UNSAFE_KEY_CHAR`` matches, mapped to U+FFFD REPLACEMENT
#: CHARACTER. Replacement is lossy on its own; the digest suffix is what keeps
#: the result distinguishable. (``str.translate`` with this dict measures
#: 0.79 ns/char, ~2.5× faster than the equivalent ``re.sub``.)
_REPLACEMENT = "�"
_SURROGATE_TABLE: dict[int, str] = {c: _REPLACEMENT for c in range(0xD800, 0xE000)}
_CONTROL_TABLE: dict[int, str] = {c: _REPLACEMENT for c in range(0x20)}
_CONTROL_TABLE[0x7F] = _REPLACEMENT
_CONTROL_TABLE.update(_SURROGATE_TABLE)

#: Below this many *characters* a key cannot reach ``MAX_KEY_BYTES``, whatever
#: it contains (UTF-8 is at most 4 bytes per character), so the hot path never
#: has to encode one to find out.
_ALWAYS_SHORT_ENOUGH = MAX_KEY_BYTES // 4

#: At or above this many characters a key is *certainly* over ``MAX_KEY_BYTES``
#: (UTF-8 is at least 1 byte per character), so it is going to be rewritten
#: whatever it contains. Everything past this point is discarded, so the cold
#: path cuts **first** and inspects second: without it, one 1 MiB key costs a
#: 1 MiB scan plus a 1 MiB ``translate``, and the per-key cold cost is
#: unbounded rather than merely expensive (review N2-4).
_CERTAINLY_TOO_LONG = MAX_KEY_BYTES + 1


def _sanitize_key(key: str) -> str:
    """Cold path of :func:`sanitize_key`: the key is long, or unsafe, or both.

    Returns ``<cleaned prefix>[SANITIZED:<16 hex>]``. The prefix is cut on a
    UTF-8 *character* boundary — never mid-sequence, so the result is always
    valid UTF-8 — and the digest is taken over the **original** key, so two
    keys sharing a 996-byte prefix stay distinct.

    Every step but the digest works on at most ``_CERTAINLY_TOO_LONG``
    characters, so the cost of one call is bounded by a constant plus the
    linear-with-a-small-constant encode the digest needs (0.05 ns/char).
    """
    # ``surrogatepass`` because the original may contain lone surrogates and
    # this encoding is total and injective over ``str``; it feeds the digest
    # only, never the document.
    original = key.encode("utf-8", "surrogatepass")
    if len(key) < _CERTAINLY_TOO_LONG:
        head = key
        over_long = len(original) > MAX_KEY_BYTES
    else:
        # Certainly over the byte bound; only the retained prefix matters, and
        # inspecting the discarded remainder would be work an attacker chose.
        head = key[:_CERTAINLY_TOO_LONG]
        over_long = True

    # ``str.isprintable`` is a cheaper superset test than the pattern (see
    # ``_safe_str_key``): true means no C0, no DEL and no surrogate, so the
    # precise scan only runs on a key that is already unusual.
    unsafe = not head.isprintable() and _unsafe_char_search(head) is not None
    if not unsafe and _KEY_MARK in head:
        unsafe = True
    if not unsafe and not over_long:
        return key  # long in characters, still inside the byte bound.

    cleaned = head.translate(_CONTROL_TABLE) if unsafe else head
    data = cleaned.encode("utf-8")  # no surrogates left: cannot raise.
    if len(data) > _MAX_KEY_PREFIX_BYTES:
        # ``errors="ignore"`` drops exactly the incomplete trailing sequence;
        # everything before it is known-valid UTF-8 we just encoded.
        cleaned = data[:_MAX_KEY_PREFIX_BYTES].decode("utf-8", "ignore")
    digest = hashlib.blake2b(original, digest_size=_KEY_DIGEST_SIZE).hexdigest()
    return f"{cleaned}{_KEY_MARK}{digest}]"


#: How many keys in one :func:`redact` call may take the cold path before it is
#: replaced by :func:`_degraded_key`.
#:
#: The cold path is 20–70× the fast path per key, and *which* keys take it is
#: the client's choice: 4,998 keys each carrying one control character is a
#: 73 KB body — inside ``max_body_bytes`` and inside ``max_body_nodes`` — that
#: cost 10 ms of event-loop time in ``redact`` alone (review N2-4). Bounding
#: the node *count* cannot bound this, because the cost of a node is
#: attacker-chosen; so the *work* is bounded here instead.
#:
#: 128 is ~0.4 ms of cold path per call at the measured worst case, and no
#: legitimate body comes near it: a key reaches the cold path only by exceeding
#: 256 characters or by carrying a control character, a lone surrogate or the
#: marker. ``document.py`` calls :func:`redact` up to four times per request
#: (query, path params, multipart metadata, body), so the per-request ceiling
#: is 4× this.
_COLD_KEY_BUDGET = 128

#: How much of an over-budget key is kept verbatim. Enough to recognise a field
#: name; short enough that inspecting it is a constant, not a length the client
#: picks.
_DEGRADED_HEAD_CHARS = 24

#: Marker for a key the cold-path budget refused. Deliberately not the 16-hex
#: shape :func:`_sanitize_key` emits, so a reader can tell "this key was
#: rewritten" from "this document hit the budget", and so the two forms can
#: never collide.
_KEY_BUDGET_MARK = _KEY_MARK + "over-budget-"


def _degraded_key(key: str, seq: int) -> str:
    """Constant-cost stand-in for :func:`_sanitize_key` once the budget is out.

    Safety does not degrade — only informativeness. The result is ASCII,
    printable, far under ``MAX_KEY_BYTES``, and carries no control character,
    surrogate or forged marker: the head is emitted only if it is already all
    three (and free of ``[``, which is what makes the single trailing marker
    unambiguous), otherwise it is dropped entirely.

    ``seq`` is unique per key within one :func:`redact` call, so distinct keys
    stay distinct entries rather than collapsing onto each other and silently
    dropping one another's values.
    """
    head = key[:_DEGRADED_HEAD_CHARS]
    if not head.isascii() or not head.isprintable() or "[" in head:
        head = ""
    return f"{head}{_KEY_BUDGET_MARK}{seq:x}]"


def _safe_str_key(key: str) -> str:
    """:func:`sanitize_key` for a known ``str``. Hot: keep it branch-cheap.

    ``str.isprintable`` is a C-level scan with no match object to allocate —
    ~4× cheaper than running ``_UNSAFE_KEY``, and ``False`` for every character
    that pattern matches (C0, DEL and surrogates are all non-printable). It is
    a *superset* test: it also rejects NBSP, ZWJ and friends, which are
    harmless here. The cold path re-tests precisely and hands those back
    unchanged, so the cheap test costs an occasional wasted call, never a wrong
    answer.
    """
    if (
        len(key) <= _ALWAYS_SHORT_ENOUGH
        and key.isprintable()
        and _KEY_MARK not in key
    ):
        return key
    return _sanitize_key(key)


def sanitize_key(key: Any) -> Any:
    """Make ``key`` safe to emit into a ``flattened`` field.

    Returns the key unchanged — the same object — for anything a real client
    sends, which is ~100 % of traffic. A key that is too long, or that carries
    a control character, a lone surrogate or the sanitisation marker, is
    rewritten by :func:`_sanitize_key`.

    Non-``str`` keys are returned untouched: they cannot carry either defect,
    and coercing them here would change the structure the document reports.
    """
    if key.__class__ is not str:
        return key
    return _safe_str_key(key)


# ---------------------------------------------------------------------------
# Value sanitisation — keeping a hostile value from destroying the JSONL line
# ---------------------------------------------------------------------------
#
# A lone surrogate in a *value* is the same defect as one in a key, one layer
# out: ``orjson`` refuses to parse it, the stdlib fallback in ``document.py``
# accepts it, and ``orjson.dumps`` then refuses to serialise the document —
# "str is not valid UTF-8: surrogates not allowed". The sink catches that,
# counts it as a *drop*, and the request has no audit record at all. The whole
# attack is ``{"a":"\ud800"}``: 14 bytes, no authentication, any JSON endpoint,
# and the only signal an operator gets points at disk pressure (review N2-1).
#
# So values get the surrogate half of the key treatment and nothing else.
# Control characters are left alone deliberately: they are legal in a JSON
# string, every encoder escapes them, and they are not the flattened parser's
# separator when they are on the value side of it. Length is left alone too —
# ``ignore_above`` handles a long value, and a length rule here would be a
# behaviour change dressed as a fix.


def _sanitize_value(value: str) -> str:
    """Cold path of :func:`_safe_str_value`: the value cannot be UTF-8 encoded.

    Surrogates become U+FFFD and a digest of the original is appended, for the
    same reason keys carry one: two distinct values must not silently become
    one, and a reader must be able to tell a replacement character we wrote
    from one the client sent.
    """
    digest = hashlib.blake2b(
        value.encode("utf-8", "surrogatepass"), digest_size=_KEY_DIGEST_SIZE
    ).hexdigest()
    return f"{value.translate(_SURROGATE_TABLE)}{_KEY_MARK}{digest}]"


def _safe_str_value(value: str) -> str:
    """Return ``value`` unchanged unless it cannot be encoded as UTF-8.

    Two tests, both C-level and both cheap. ``str.isascii`` is a flag read on
    the string object — O(1), true for the overwhelming majority of values, and
    ASCII excludes surrogates by construction. Only a non-ASCII value is
    actually encoded, and the encode is thrown away: it is ~2× cheaper than a
    surrogate-class regex scan on the same string and it is the *exact* test —
    what the sink will do later, done here where the document can still be
    saved instead of dropped.
    """
    if value.isascii():
        return value
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return _sanitize_value(value)
    return value


#: Characters of key text one call's :class:`_Decisions` memo may retain.
#:
#: The entry cap (``_KEY_CACHE_MAX``) is only half the bound here for exactly
#: the reason it was only half the bound for ``_key_cache`` (review N2-2): the
#: *dict key* is the original, attacker-supplied string, so 4096 entries can be
#: 4096 × whatever length the client chose. This memo is per call rather than
#: process-global, so it cannot accumulate across requests the way N2-2 did —
#: it dies with ``redact()`` — but "bounded in entries" still does not bound
#: the memory it holds while it lives, and ``document.py`` calls ``redact()``
#: up to four times per request.
#:
#: Same number as the ``_key_cache`` bound, one scope narrower: 4096 × 256 =
#: 1,048,576 characters, ≤ 4 MiB of string data even in the UCS-4 worst case.
#: The *emitted* key in each entry is separately bounded by ``MAX_KEY_BYTES``,
#: so the whole memo is bounded by this plus 4096 × 1 KiB.
#:
#: Refusing to memoise past the budget costs nothing an attacker can exploit:
#: the fallback is recomputation, which for a key long enough to exhaust the
#: budget is exactly the cold path that ``_COLD_KEY_BUDGET`` already bounds,
#: and real payloads repeat *short* key names.
_DECISION_CACHE_MAX_CHARS = _KEY_CACHE_MAX * _ALWAYS_SHORT_ENOUGH


class _Decisions(dict[Any, "tuple[Any, bool]"]):
    """``decisions[key]`` → ``(key to emit, is this key denylisted?)``.

    A ``dict`` subclass with ``__missing__`` so that the hot path is a C-level
    dict lookup instead of a Python call: request bodies repeat the same key
    names once per element of every list of objects. Both halves of the answer
    live in one entry so the hot path needs one lookup, not two.

    The denylist verdict is taken from the **original** key, so a key that is
    denylisted before sanitisation is still redacted after it.

    It also carries the two budgets that make a hostile keyset survivable: the
    per-call cold-path allowance (``_COLD_KEY_BUDGET``, review N2-4) and the
    sequence number that keeps over-budget keys distinct.

    The memo itself is bounded in **entries and in characters** — see
    :data:`_DECISION_CACHE_MAX_CHARS`. Entries alone do not bound it, because
    the dict key is the original attacker-supplied string.
    """

    __slots__ = ("_keys", "_cold", "_seq", "_chars", "_distinct")

    def __init__(self, keys: frozenset[str], max_distinct: int | None = None) -> None:
        super().__init__()
        self._keys = keys
        self._cold = _COLD_KEY_BUDGET
        self._seq = 0
        self._chars = _DECISION_CACHE_MAX_CHARS
        #: Remaining first-seen keys. ``None`` means unbounded, which is right
        #: for the small server-defined structures (path params, headers) and
        #: wrong for anything a client sends.
        self._distinct = max_distinct

    def _remember(self, key: Any, entry: tuple[Any, bool]) -> None:
        """Memoise ``key`` if both budgets allow it. Never required for
        correctness: the fallback is recomputing the same answer.

        A ``str`` key is charged its own length, so a flood of long keys stops
        memoisation instead of retaining every one of them; a non-``str`` key
        is not charged, since it cannot be an attacker-chosen text blob (it is
        an ``int``/``bool``/``None`` from a JSON-ish structure) and measuring
        it would mean stringifying it.
        """
        if len(self) >= _KEY_CACHE_MAX:
            return
        if key.__class__ is str:
            remaining = self._chars - len(key)
            if remaining < 0:
                return
            self._chars = remaining
        self[key] = entry

    def __missing__(self, key: Any) -> tuple[Any, bool]:
        # Inlined rather than delegated: on a warm module cache this is two
        # dict lookups and a frozenset probe, with no Python-level call at all.
        #
        # Reaching here at all means this key is new *to this call*, so this is
        # the one place that sees the quantity N3-1 is about.
        remaining = self._distinct
        if remaining is not None:
            if remaining <= 0:
                raise RedactionBudgetExceeded(
                    "too many distinct keys in one structure"
                )
            self._distinct = remaining - 1
        info: tuple[Any, str] | None
        if key.__class__ is str:
            info = _key_cache_get(key)
            if info is None:
                short = len(key) <= _ALWAYS_SHORT_ENOUGH
                if short and key.isprintable() and _KEY_MARK not in key:
                    info = (key, normalize_key(key))
                elif self._cold > 0:
                    self._cold -= 1
                    info = (_sanitize_key(key), normalize_key(key))
                else:
                    # Out of cold-path budget: a constant-cost stand-in, and
                    # never memoised — its sequence number is meaningful only
                    # within this call, so caching it could let two distinct
                    # keys in a *later* call collapse onto one entry.
                    seq = self._seq
                    self._seq = seq + 1
                    entry = (
                        _degraded_key(key, seq),
                        normalize_key(key) in self._keys,
                    )
                    self._remember(key, entry)
                    return entry
                if short:
                    # Only keys the fast path can serve are memoised: the memo
                    # holds the original string alive across requests, so an
                    # entry cap alone bounds nothing (review N2-2).
                    if len(_key_cache) >= _KEY_CACHE_MAX:
                        _key_cache.clear()
                    _key_cache[key] = info
        else:
            info = (key, normalize_key(key))
        entry = (info[0], info[1] in self._keys)
        self._remember(key, entry)
        return entry


def _redact(obj: Any, keys: _Decisions, depth: int, limit: int) -> Any:
    """Recursive worker for :func:`redact`. ``depth`` is the level of ``obj``."""
    if depth >= limit:
        # Everything at or below the cap is dropped, containers and scalars
        # alike. Nothing from here down may survive into the document — that
        # is what makes cyclic input safe and what stops a deep value from
        # escaping unchecked.
        return TRUNCATED

    if obj.__class__ is str:
        # First, and by exact type: strings are the commonest leaf by a wide
        # margin, so this saves them the two container ``isinstance`` calls and
        # costs every container one pointer comparison.
        return _safe_str_value(obj)

    if isinstance(obj, dict):
        child_depth = depth + 1
        # Denylisted keys are replaced without descending: a nested object
        # under "credentials" is a secret in its entirety, and recursing into
        # it would be wasted work on a value that is thrown away.
        #
        # ``decision`` is bound in the key expression and used in the value
        # expression: since 3.8 a dict comprehension evaluates the key first,
        # and this package requires 3.11. One memo lookup per key, not two.
        return {
            (decision := keys[key])[0]: (
                REDACTED
                if decision[1]
                else _redact(value, keys, child_depth, limit)
            )
            for key, value in obj.items()
        }

    if isinstance(obj, (list, tuple)):
        child_depth = depth + 1
        return [_redact(item, keys, child_depth, limit) for item in obj]

    if isinstance(obj, str):
        # Only reachable for a ``str`` *subclass*: the exact type is handled
        # above, before the container tests, because it is the commonest leaf.
        return _safe_str_value(obj)

    # Remaining scalars (int, float, bool, None) and anything else opaque are
    # already immutable-enough to share with the caller, and none of them can
    # carry a byte sequence that breaks the line.
    return obj


def redact(
    obj: Any,
    keys: frozenset[str],
    *,
    depth_limit: int = 20,
    max_distinct_keys: int | None = None,
) -> Any:
    """Pure. Returns a new structure with denylisted values replaced.

    Recurses through dicts *and* lists, so a denylisted key inside a list of
    objects at any depth is caught (FR-11). The input is never mutated: the
    application keeps the object it parsed (FR-10).

    Anything at nesting depth ``depth_limit`` or deeper is replaced by
    ``"[TRUNCATED]"`` — values included, so nothing below the cap reaches the
    document unredacted. The cap is also what terminates cyclic or
    self-referential input; there is no ``id()`` bookkeeping.

    Every emitted key is passed through :func:`sanitize_key`, so no key in the
    result exceeds ``MAX_KEY_BYTES`` UTF-8 bytes or carries a C0 control
    character, a DEL or a lone surrogate — any one of which makes Elasticsearch
    reject the **whole** audit document (review N-9). Ordinary keys come back
    as the same object, and the denylist verdict is taken before sanitisation,
    so redaction is unaffected by it. Past ``_COLD_KEY_BUDGET`` such keys in
    one call, the rewrite degrades to a cheaper, less informative — but never
    less safe — form (review N2-4).

    Every emitted **string value** is UTF-8-encodable: a value carrying a lone
    surrogate is rewritten rather than left to make the whole JSONL line
    unwritable and the document undeliverable (review N2-1). Values are
    otherwise untouched — no length rule, no control-character rule — so an
    ordinary body comes back byte-identical.

    ``keys`` must already be normalized (see :func:`normalize_key`);
    ``DEFAULT_REDACT_KEYS`` is.

    ``max_distinct_keys`` bounds the number of **first-seen** keys, raising
    :exc:`RedactionBudgetExceeded` past it. Pass it for anything a client
    controls; leave it ``None`` for server-defined structures (review N3-1).
    """
    return _redact(obj, _Decisions(keys, max_distinct_keys), 0, depth_limit)


def filter_headers(
    headers: Iterable[tuple[bytes, bytes]], allowlist: frozenset[str]
) -> dict[str, str]:
    """Allowlist only — anything else vanishes entirely.

    Takes raw ASGI headers (lowercase ``bytes`` pairs by the ASGI spec, but
    the case is not trusted here) and returns ``{name: value}`` for the
    allowlisted names only. A dropped header leaves no placeholder, so
    ``Authorization`` and ``Cookie`` are not even visible as names (FR-12).

    Repeated header names are joined with ``", "``, the way HTTP itself
    combines them. Bytes are decoded as latin-1, the ASGI convention, which
    cannot fail.
    """
    out: dict[str, str] = {}
    for raw_name, raw_value in headers:
        name = _as_text(raw_name).strip().lower()
        if name not in allowlist:
            continue
        value = _as_text(raw_value).strip()
        existing = out.get(name)
        out[name] = value if existing is None else f"{existing}, {value}"
    return out
