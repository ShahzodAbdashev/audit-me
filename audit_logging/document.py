"""``build_document`` — RequestContext to the ECS-shaped audit document.

Owned by **Agent A2**. ``docs/schema.md`` §2 is the field reference; every key
this module can emit appears there and nothing else does — the index template
is ``dynamic: false``.

Redaction lives across the A2/A3 boundary: ``redact``/``filter_headers`` are
imported at module level so tests can substitute identity implementations
while ``redact.py`` is still a stub (AGENTS.md, Phase 0 addendum).

Post-review shape (``docs/schema.md`` §2.9, FR-28…FR-31)
--------------------------------------------------------

* ``body`` and ``body_raw`` are **mutually exclusive** (FR-30). For parseable
  JSON and for form bodies the ``flattened`` ``body`` *is* the content; nothing
  is re-serialised, which removes both the doubled line size (review M-3) and
  the second full serialisation from the request path (review M-2).
* A body the key denylist cannot be applied to is **not stored** by default
  (FR-28). ``capture_text_bodies`` opts a service in to a *best-effort textual
  scrub* — see :func:`_scrub_text`, which is deliberately weaker than the
  structured path.
* Parsing and redaction are bounded in **shape**, not only in bytes: past
  ``config.max_body_nodes`` the body is abandoned as ``too_complex`` (FR-29),
  and the check runs over the raw bytes so we never pay for the parse we are
  about to refuse.
* The **query string** is bounded the same way (review N2-3). It is parsed,
  redacted and re-encoded on the request path exactly like a form body, and
  nothing capped it: 8 KB of ``a&`` cost 2.5 ms and 64 KB cost 20 ms of
  event-loop time on a ``GET`` with no body at all. See
  :func:`_query_bounds`. This adds one key to §2.7 that
  ``docs/schema.md`` does not list yet — ``audit.request.query_skipped``,
  ``keyword``, the exact analogue of ``body_skipped`` — and it needs a row in
  the index template (A5) or it lands in ``_source`` unindexed.
* A body or query that is *not* stored is counted, not only recorded in the
  document: ``audit_bodies_skipped_total`` and ``audit_queries_skipped_total``
  (review N2-6 — an operator could not see bodies being dropped at all).
* ``user.*`` values are coerced to the types schema §2.5 declares (FR-31);
  ``ignore_malformed`` does not cover ``keyword``, so an uncoerced value would
  make Elasticsearch reject the entire document (review M-5).
"""

from __future__ import annotations

import json
import os
import re
import socket
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote_plus, urlencode

from ._contracts import (
    BODY_SKIPPED_CONTENT_TYPE,
    BODY_SKIPPED_TOO_COMPLEX,
    OUTCOME_FAILURE,
    Metrics,
    RequestContext,
)
from .config import AuditConfig
from .redact import (
    RedactionBudgetExceeded,
    DEFAULT_HEADER_ALLOWLIST,
    DEFAULT_REDACT_KEYS,
    REDACTED,
    filter_headers,
    normalize_key,
    redact,
)

__all__ = [
    "build_document",
    "build_minimal_document",
    "body_kind_for",
    "BODY_KIND_JSON",
    "BODY_KIND_FORM",
    "BODY_KIND_TEXT",
    "BODY_KIND_BINARY",
    "RECEIVED_BYTES_KEY",
    "ROUTE_UNMATCHED",
    "QUERY_SKIPPED_MARKER",
    "METRIC_BODIES_SKIPPED",
    "METRIC_QUERIES_SKIPPED",
]

#: ``audit.route`` when the request never matched a route (FR-03).
ROUTE_UNMATCHED = "unmatched"

#: ``socket.gethostname()`` resolved once at import (schema §2.3).
_HOSTNAME = socket.gethostname()

_MAX_ERROR_MESSAGE = 1024

#: How much raw text the one remaining unredacted path — a body that declared
#: a JSON content type and then failed to parse (AC-14, review S-2/N-1) — may
#: store. The diagnostic value of a parse failure is in its first bytes; the
#: leak scales with whatever we keep past them. Clipping is reported through
#: ``body_truncated``, which already means "what is stored is not all of it".
_MAX_UNPARSED_BODY_RAW = 4096

#: Bounds on ``user.*`` (FR-31) and on multipart part metadata (FR-07/S-4).
#: All four land in ``keyword``/``flattened`` fields, where an unbounded
#: attacker-influenced string is a Lucene term-length risk and a line-size one.
_MAX_USER_FIELD = 1024
_MAX_USER_ROLES = 64
_MAX_PART_FIELD = 256

#: Where :mod:`audit_logging.middleware` parks the true number of request body
#: bytes it saw, uncapped, for ``http.request.bytes`` (review S-1).
#:
#: ``RequestContext`` is frozen and has no field for it, so the count rides on
#: the ASGI scope under a namespaced key, set **after** the application has
#: returned. It is the only channel available without reopening the contract;
#: when the contract next opens this should become ``RequestContext``.
RECEIVED_BYTES_KEY = "audit_logging.received_bytes"

BODY_KIND_JSON = "json"
BODY_KIND_FORM = "form"
BODY_KIND_TEXT = "text"
BODY_KIND_BINARY = "binary"

_FORM_MIME = "application/x-www-form-urlencoded"
_TEXT_MIMES = frozenset({"application/xml", "application/javascript", "application/graphql"})


# ---------------------------------------------------------------------------
# JSON backend (review M-2b — ``file_sink.py`` already prefers orjson)
# ---------------------------------------------------------------------------

_ORJSON: Any | None
try:  # pragma: no cover - depends on whether the 'fast' extra is installed
    import orjson as _orjson_mod

    _ORJSON = _orjson_mod
except ImportError:  # pragma: no cover - depends on the environment
    _ORJSON = None


def _loads(raw: bytes) -> Any:
    """Parse JSON from raw bytes with the fastest backend available.

    Both backends accept ``bytes``, so the common path never decodes the body
    into a ``str`` first — that decode is a full extra copy of an
    attacker-sized payload.
    """
    if _ORJSON is not None:
        return _ORJSON.loads(raw)
    return json.loads(raw)


def _mime_type(content_type: str | None) -> str:
    """The content type without its parameters, lowercased."""
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def body_kind_for(content_type: str | None) -> str:
    """How a body with this content type is captured.

    ``binary`` means metadata only — bytes are never stored (FR-07, D-5).
    ``text`` means the key denylist cannot be applied, so by default nothing is
    stored either (FR-28).
    """
    mime = _mime_type(content_type)
    if not mime:
        return BODY_KIND_TEXT
    if mime == "application/json" or mime.endswith("+json") or mime == "text/json":
        return BODY_KIND_JSON
    if mime == _FORM_MIME:
        return BODY_KIND_FORM
    if mime.startswith("text/") or mime in _TEXT_MIMES:
        return BODY_KIND_TEXT
    return BODY_KIND_BINARY


# ---------------------------------------------------------------------------
# Effective key sets (FR-13 — additive only)
# ---------------------------------------------------------------------------


def _redact_keys(config: AuditConfig) -> frozenset[str]:
    extra = config.extra_redact_keys
    if not extra:
        return DEFAULT_REDACT_KEYS
    return DEFAULT_REDACT_KEYS | frozenset(normalize_key(k) for k in extra)


def _header_allowlist(config: AuditConfig) -> frozenset[str]:
    extra = config.extra_header_allowlist
    if not extra:
        return DEFAULT_HEADER_ALLOWLIST
    return DEFAULT_HEADER_ALLOWLIST | frozenset(k.lower() for k in extra)


# ---------------------------------------------------------------------------
# Shape bounds (FR-29 — review M-2)
# ---------------------------------------------------------------------------


#: Structural characters that bound the node count of a JSON text. Every value
#: other than the root is either preceded by a ``,`` (it is not the first
#: element of its container) or is the first element of a container, and there
#: is one container per ``{`` or ``[``, so
#:
#:     nodes ≤ 1 + count(",") + count("{") + count("[")
#:
#: Characters inside strings inflate that, so it is an upper bound and errs in
#: the safe direction: a body of one enormous comma-heavy string can be refused
#: as ``too_complex`` although it would have parsed cheaply. That is the
#: deliberate trade — we would rather drop a body than let a client choose our
#: CPU cost.
_JSON_STRUCTURE = (b",", b"{", b"[")

#: The same idea for a form body: ``a=1&b=2;c=3`` is at most ``separators + 1``
#: pairs, and ``;`` counts as a separator here too (review S-3).
_FORM_STRUCTURE = (b"&", b";")

#: Sites the textual scrub might have to rewrite (FR-28's opt-in path). The
#: scrub *is* that path's parse, so FR-29 applies to it the same way.
_TEXT_STRUCTURE = (b"=", b":", b"<")

#: ...and a hard length budget on top, because the scrub's regexes scan the
#: whole text linearly even when nothing matches. Measured at ~110 MB/s across
#: the six patterns, so 1 MiB of ordinary prose costs 56 ms — M-2 all over
#: again, just behind a config flag. 32 KiB keeps the measured worst case
#: (dense ``key: value`` lines) at ~3.5 ms, inside NFR-1's 5 ms. Longer text
#: bodies are refused rather than half-scrubbed: storing the part we scanned
#: and dropping the rest would be the same silent leak M-1 was.
#: This wants to be a config knob; ``config.py`` is not A2's to extend.

#: The scan checks its running total every window rather than at the end, so an
#: adversarial body is refused after the first few KB instead of after a full
#: pass. ``bytes.count`` takes a range, so no window is ever copied.
_SCAN_WINDOW = 64 * 1024


def _exceeds_node_cap(raw: bytes, limit: int, structure: tuple[bytes, ...]) -> bool:
    """FR-29 — is this body over ``max_body_nodes``, without parsing it?

    Checking a node cap *after* ``json.loads`` still pays for the parse we are
    trying to refuse, which is most of what M-2 measured. This is C-level
    ``bytes.count`` over the raw bytes with an early exit, so the refusal costs
    microseconds and the accept path costs one pass at memory bandwidth.
    """
    total = 1
    size = len(raw)
    start = 0
    while start < size:
        end = start + _SCAN_WINDOW
        if end > size:
            end = size
        for character in structure:
            total += raw.count(character, start, end)
        if total > limit:
            return True
        start = end
    return False


# ---------------------------------------------------------------------------
# Best-effort textual scrub (FR-28 — review M-1)
# ---------------------------------------------------------------------------

#: What may look like a key in free text. Deliberately narrow.
_SCRUB_KEY = r"[A-Za-z0-9_.\-]{1,64}"

#: ``(pattern, quote)`` — ``quote`` is what wraps the replacement value so the
#: scrubbed text stays syntactically plausible. Applied in order.
_SCRUB_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # "key": "value"  — JSON-ish text, including JSON mislabelled as text/plain
    (
        re.compile(r'(?P<pre>"(?P<key>' + _SCRUB_KEY + r')"\s*:\s*)"(?:[^"\\]|\\.)*"'),
        '"',
    ),
    # "key": 12345 | true | null  — unquoted JSON scalar
    (
        re.compile(
            r'(?P<pre>"(?P<key>' + _SCRUB_KEY + r')"\s*:\s*)(?!["\{\[])[^\s,\}\]]+'
        ),
        "",
    ),
    # <key ...>value</key>  — XML/SOAP leaf elements only
    (
        re.compile(
            r"(?P<pre><\s*(?P<key>" + _SCRUB_KEY + r")[^<>]*>)"
            r"[^<]*"
            r"(?P<post></\s*(?P=key)\s*>)"
        ),
        "",
    ),
    # key: value  — one per line (headers, YAML, GraphQL variables written out)
    (
        re.compile(
            r"(?m)(?P<pre>^[ \t]*(?P<key>" + _SCRUB_KEY + r")[ \t]*:[ \t]*)\S.*$"
        ),
        "",
    ),
    # ...(key: value)  — the same shape mid-line, inside brackets or a list,
    # as GraphQL arguments and JS-ish object literals write it. Bounded to one
    # token or one quoted string, since there is no line end to stop at.
    (
        re.compile(
            r"(?P<pre>[\s,(\[\{](?P<key>" + _SCRUB_KEY + r")[ \t]*:[ \t]*)"
            r"(?:\"[^\"]*\"|'[^']*'|[^\s,)\]\}]+)"
        ),
        "",
    ),
    # key=value  — query-ish, form-ish, log-ish
    (
        re.compile(
            r"(?P<pre>(?<![A-Za-z0-9_.\-])(?P<key>" + _SCRUB_KEY + r")[ \t]*=[ \t]*)"
            r"(?:\"[^\"]*\"|'[^']*'|[^&;\s\"'<>]*)"
        ),
        "",
    ),
)


def _scrub_text(text: str, keys: frozenset[str]) -> str:
    """Replace denylisted values in unstructured text. **Best effort only.**

    This is materially weaker than the structured path and must be documented
    as such (FR-28, ``docs/redaction.md`` — A7). It knows four shapes:
    ``"key": "value"``, ``key: value``, ``key=value`` and
    ``<key>value</key>``. A secret that appears in any other shape — prose, a
    positional CSV column, a binary blob base64'd into the body, a nested XML
    element, a multi-line value — survives. It is off by default for exactly
    that reason: the honest answer for a body the denylist cannot be applied to
    is not to store it.
    """
    if not text:
        return text

    def replacer(quote: str) -> Callable[[re.Match[str]], str]:
        def replace(match: re.Match[str]) -> str:
            if normalize_key(match.group("key")) not in keys:
                return match.group(0)
            post = match.groupdict().get("post") or ""
            return f"{match.group('pre')}{quote}{REDACTED}{quote}{post}"

        return replace

    for pattern, quote in _SCRUB_PATTERNS:
        text = pattern.sub(replacer(quote), text)
    return text


# ---------------------------------------------------------------------------
# Pieces
# ---------------------------------------------------------------------------


def _route_of(scope: dict[str, Any]) -> str:
    """FR-03 — read after the app returned; ``"unmatched"`` when absent."""
    route = scope.get("route")
    if route is None:
        return ROUTE_UNMATCHED
    # Starlette names it ``path``; some versions/routers expose ``path_format``.
    for attribute in ("path", "path_format"):
        value = getattr(route, attribute, None)
        if isinstance(value, str) and value:
            return value
    return ROUTE_UNMATCHED


def _path_params(scope: dict[str, Any], keys: frozenset[str]) -> dict[str, Any]:
    """``audit.path_params``, redacted like every other flattened field.

    Param *names* come from the route template, so they are server-defined and
    cannot be attacker-chosen — but a route may legitimately declare
    ``/keys/{api_key}``, and the value is then a client-supplied secret
    landing in a flattened field. This used to be the one captured structure
    that never passed through ``redact()`` at all.

    Note this does **not** rescue a secret in a *positional* path segment that
    the route does not name (review N-3) — nothing key-based can.
    """
    params = scope.get("path_params")
    if not isinstance(params, dict):
        return {}
    stringified = {
        str(k): v if isinstance(v, str) else str(v) for k, v in params.items()
    }
    reduced = redact(stringified, keys)
    return reduced if isinstance(reduced, dict) else {}


# ---------------------------------------------------------------------------
# Counters for what was captured but not stored (review N2-6)
# ---------------------------------------------------------------------------

#: A document whose *body* was not stored — over ``max_body_nodes``, a content
#: type the denylist cannot be applied to, or a skipped multipart. Frozen in
#: ``_contracts.METRIC_NAMES``.
METRIC_BODIES_SKIPPED = "audit_bodies_skipped_total"

#: The same for the **query string** (review N2-3). Deliberately *not*
#: ``audit_bodies_skipped_total``: a dropped query is not a dropped body, and
#: an operator alerting on "we are losing request bodies" must not be woken by
#: a route with long query strings. This name is in
#: ``_contracts.METRIC_NAMES``, so ``PrometheusMetrics`` exposes it. It is
#: deliberately separate from ``audit_bodies_skipped_total``: an operator
#: alerting on lost request bodies must not be paged by a chatty query route.
METRIC_QUERIES_SKIPPED = "audit_queries_skipped_total"


def _count(metrics: Metrics | None, name: str) -> None:
    """Increment ``name`` if we were given somewhere to put it.

    A ``Metrics`` implementation is contractually forbidden from raising, but
    it is caller-supplied and this runs while a document is half-built: a
    raising counter must cost the counter, never the audit record (NFR-3).
    """
    if metrics is None:
        return
    try:
        metrics.inc(name)
    except Exception:  # pragma: no cover - a Metrics impl must not raise
        pass


# ---------------------------------------------------------------------------
# Query string (FR-14, review S-3 and N2-3)
# ---------------------------------------------------------------------------

#: ``url.query`` when the query string was over the bounds below. A fixed
#: literal, never client bytes: ``url.query`` is where FR-14 replaces
#: denylisted values in the *raw* string, so storing an unparsed — and
#: therefore unredacted — query here, whole or truncated, would turn the bound
#: into a redaction bypass. The parsed ``audit.request.query`` is ``{}`` and
#: ``audit.request.query_skipped`` says ``too_complex``, so the document still
#: exists and says plainly that the query was not captured.
QUERY_SKIPPED_MARKER = "[SKIPPED]"

#: FR-29 for the query string (review N2-3). ``_query`` is
#: ``split`` → ``unquote_plus`` per key *and* per value → ``redact`` →
#: ``urlencode``, and measured on this machine it costs **~1.1 µs per pair**
#: and only ~2.8 µs per KB otherwise::
#:
#:        256 pairs (  3 KB)   0.28 ms        4 pairs ( 4 KB)   0.03 ms
#:      1 024 pairs ( 12 KB)   1.06 ms        4 pairs (16 KB)   0.05 ms
#:      4 096 pairs ( 48 KB)   4.66 ms        4 pairs (64 KB)   0.18 ms
#:      8 192 pairs ( 96 KB)  11.12 ms
#:
#: So the quantity to bound is the **pair count**, exactly as FR-29 bounds a
#: form body's node count — a query string *is* a form body's grammar, and it
#: shares ``_FORM_STRUCTURE``. 512 pairs is ~0.55 ms, ~11 % of NFR-1's 5 ms
#: budget, which leaves room for the per-key sanitisation cost review N2-4
#: measures on top. The byte ceiling then bounds the linear part and the line
#: size; 8 KiB is what a default nginx (``large_client_header_buffers 4 8k``)
#: and Apache (``LimitRequestLine 8190``) will pass in a request line at all.
#:
#: **Derivation.** This bound was first expressed as fixed ceilings over the
#: body knobs, because the agent that wrote it did not own ``config.py``. The
#: orchestrator has since added the real knob, so :func:`_query_bounds` reads
#: ``config.max_query_bytes`` (default 8192) and derives the pair bound as
#: ``max_query_bytes // 16`` (512 at the default — the measurement above).
#: The capture knobs still cap the result: tightening ``max_body_bytes`` or
#: ``max_body_nodes`` tightens the query too, and neither can loosen it.


def _query_bounds(config: AuditConfig) -> tuple[int, int]:
    """``(max bytes, max pairs)`` for a query string.

    Driven by ``config.max_query_bytes``, the dedicated knob the orchestrator
    added after this bound was first derived from the body knobs. The pair
    bound is ``max_query_bytes // 16``, so raising the byte budget raises both
    halves coherently — the cost is pair-dominated (~1.1 us/pair against
    ~2.8 us/KB), and a byte ceiling alone would not bound it.

    The capture knobs still cap the result: tightening ``max_body_bytes`` or
    ``max_body_nodes`` can only ever tighten the query too, never loosen it.
    """
    return (
        min(config.max_body_bytes, config.max_query_bytes),
        min(config.max_body_nodes, max(1, config.max_query_bytes // 16)),
    )


#: ``&`` **and** ``;``. ``urllib.parse.parse_qsl`` has split on ``&`` alone
#: since Python 3.10, and older Java/PHP stacks and hand-built links still
#: emit ``;`` — a pair the parser does not recognise used to pass through
#: verbatim into the indexed ``url.query`` (review S-3).
_QUERY_SEPARATOR = re.compile(r"[&;]")


def _split_pairs(text: str) -> list[tuple[str, str]]:
    """``parse_qsl(keep_blank_values=True)`` that also splits on ``;``.

    Keys are stripped of surrounding whitespace: ``?%20token=SECRET`` decodes
    to the key ``" token"``, which the denylist does not normalise away, and
    the value then reached both ``url.query`` and ``audit.request.query`` in
    the clear (review S-3).
    """
    pairs: list[tuple[str, str]] = []
    for component in _QUERY_SEPARATOR.split(text):
        if not component:
            continue
        name, separator, value = component.partition("=")
        pairs.append(
            (unquote_plus(name).strip(), unquote_plus(value) if separator else "")
        )
    return pairs


def _query(
    query_string: bytes,
    keys: frozenset[str],
    *,
    rebuild: bool = True,
    max_distinct: int | None = None,
) -> tuple[str, dict[str, Any]]:
    """Return ``(url.query, audit.request.query)`` — both redacted (FR-14).

    ``rebuild=False`` returns ``""`` for the first element and skips the
    re-encode that produces it. The form-body path (``_body_block``) wants only
    the parsed mapping and used to pay for a full ``urlencode`` of the body it
    then threw away — free work on the request path, scaling with an
    attacker-sized body.
    """
    text = query_string.decode("latin-1") if query_string else ""
    if not text:
        return "", {}
    pairs = _split_pairs(text)
    if not pairs:
        return text, {}
    grouped: dict[str, Any] = {}
    for key, value in pairs:
        if key in grouped:
            current = grouped[key]
            if isinstance(current, list):
                current.append(value)
            else:
                grouped[key] = [current, value]
        else:
            grouped[key] = value
    reduced = redact(grouped, keys, max_distinct_keys=max_distinct)
    if not isinstance(reduced, dict):  # pragma: no cover - redact is dict-in/dict-out
        return text, {}
    if not rebuild:
        return "", reduced
    # Rebuild the raw string from the redacted values, but only re-encode it
    # when something actually changed — otherwise keep the client's bytes.
    seen: dict[str, int] = {}
    rebuilt: list[tuple[str, str]] = []
    changed = False
    for key, value in pairs:
        replacement = reduced.get(key, value)
        if isinstance(replacement, list):
            index = seen.get(key, 0)
            seen[key] = index + 1
            replacement = replacement[index] if index < len(replacement) else value
        as_text = replacement if isinstance(replacement, str) else str(replacement)
        if as_text != value:
            changed = True
        rebuilt.append((key, as_text))
    return (urlencode(rebuilt) if changed else text), reduced


def _url_query(
    query_string: bytes, keys: frozenset[str], config: AuditConfig
) -> tuple[str, dict[str, Any], str | None]:
    """``(url.query, audit.request.query, query_skipped)`` — bounded (N2-3).

    The two checks are ordered by cost: a length test is O(1) and refuses a
    1 MiB query string without touching it, and only then does the pair count
    run — over at most ``config.max_query_bytes`` bytes, with ``bytes.count`` and
    an early exit, so the refusal costs microseconds.

    Refusal is ``too_complex``, the same word ``body_skipped`` uses, and covers
    all three bounds: they bound one thing (the cost of parsing this query)
    through the three quantities that drive it — length, pair count, and the
    number of **distinct** key names (review N3-1), which no amount of
    node-counting sees.
    """
    if not query_string:
        return "", {}, None
    max_bytes, max_nodes = _query_bounds(config)
    if len(query_string) > max_bytes or _exceeds_node_cap(
        query_string, max_nodes, _FORM_STRUCTURE
    ):
        return QUERY_SKIPPED_MARKER, {}, BODY_SKIPPED_TOO_COMPLEX
    try:
        url_query, parsed = _query(
            query_string, keys, max_distinct=config.max_distinct_keys
        )
    except RedactionBudgetExceeded:
        return QUERY_SKIPPED_MARKER, {}, BODY_SKIPPED_TOO_COMPLEX
    return url_query, parsed, None


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit]


def _multipart(
    body: bytes,
    content_type: str | None,
    truncated: bool,
    keys: frozenset[str],
    limit: int,
) -> dict[str, Any]:
    """FR-07 — part metadata from what was already buffered. Never bytes.

    Bounded two ways the first cut was not:

    * at most ``limit`` (``config.max_multipart_parts``) part records, with
      ``complete: false`` past the cap. 1 MiB of ``--B\\r\\nz\\r\\n\\r\\n``
      previously produced 104 857 records in 573 ms (review S-4);
    * the scan walks the body with ``bytes.find`` and slices only each part's
      header block, so the cost is proportional to the parts it keeps rather
      than to the whole body.

    Part ``name``/``filename``/``content_type`` are attacker-supplied strings,
    so they are clipped, run through the denylist as keys in their own right,
    and a part whose ``name`` is denylisted has its ``filename`` redacted
    (review N-7). A filename that carries PII under an innocuous field name is
    *not* detectable by a key denylist and stays a documented limitation.
    """
    meta: dict[str, Any] = {"parts": [], "part_count": 0, "complete": not truncated}
    boundary = ""
    for parameter in (content_type or "").split(";")[1:]:
        name, _, value = parameter.partition("=")
        if name.strip().lower() == "boundary":
            boundary = value.strip().strip('"')
            break
    if not boundary or not body:
        return meta

    delimiter = b"--" + boundary.encode("latin-1")
    span = len(delimiter)
    parts: list[dict[str, Any]] = []
    hit_limit = False
    position = body.find(delimiter)
    while position != -1:
        start = position + span
        if body[start : start + 2] == b"--":  # closing delimiter
            break
        if len(parts) >= limit:
            hit_limit = True
            break
        following = body.find(delimiter, start)
        end = following if following != -1 else len(body)
        head_end = body.find(b"\r\n\r\n", start, end)
        if head_end == -1:
            position = following
            continue
        # The payload runs to the next delimiter less the CRLF before it.
        part: dict[str, Any] = {"size": max(0, end - (head_end + 4) - 2)}
        for line in body[start:head_end].split(b"\r\n"):
            raw_name, _, raw_value = line.partition(b":")
            header = raw_name.strip().lower()
            if header == b"content-disposition":
                for parameter in raw_value.decode("latin-1", "replace").split(";")[1:]:
                    field, _, literal = parameter.partition("=")
                    field = field.strip().lower()
                    if field in ("name", "filename"):
                        part[field] = _clip(literal.strip().strip('"'), _MAX_PART_FIELD)
            elif header == b"content-type":
                part["content_type"] = _clip(
                    raw_value.decode("latin-1", "replace").strip(), _MAX_PART_FIELD
                )
        parts.append(part)
        position = following

    for part in parts:
        part_name = part.get("name")
        if isinstance(part_name, str) and normalize_key(part_name) in keys:
            if "filename" in part:
                part["filename"] = REDACTED
    meta["parts"] = parts
    meta["part_count"] = len(parts)
    if hit_limit:
        meta["complete"] = False
    reduced = redact(meta, keys)
    return reduced if isinstance(reduced, dict) else meta


def _request_bytes(ctx: RequestContext, captured: int) -> int:
    """``http.request.bytes`` — received before truncation (schema §2.4).

    Preference order:

    1. what the middleware actually counted off the wire, parked on the scope
       under :data:`RECEIVED_BYTES_KEY` — uncapped, so it is right for a
       chunked upload past ``max_body_bytes`` (review S-1);
    2. a declared ``Content-Length``, which covers a body the application never
       read (nothing passed through ``receive`` to count);
    3. what we captured, which for a truncated body is a **lower bound**. That
       case is visible in the document rather than silent: it is exactly the
       one where ``body_truncated`` is true and ``body_bytes`` equals this
       field, i.e. "at least this many". It only arises when ``build_document``
       is called with a context this package's middleware did not build.
    """
    counted = ctx.scope.get(RECEIVED_BYTES_KEY)
    if isinstance(counted, int) and counted > 0:
        return counted
    for key, value in ctx.scope.get("headers") or []:
        if key.lower() == b"content-length":
            try:
                declared = int(value)
            except (TypeError, ValueError):
                break
            if declared >= 0:
                return declared
            break
    return captured


def _body_block(
    ctx: RequestContext,
    kind: str,
    keys: frozenset[str],
    config: AuditConfig,
    block: dict[str, Any],
) -> None:
    """Fill ``audit.request.body*`` in place, per ``docs/schema.md`` §2.9.

    Exactly one of ``body`` and ``body_raw`` is ever written (FR-30).
    """
    skipped = ctx.body_skipped
    if skipped is None and kind == BODY_KIND_BINARY:
        skipped = BODY_SKIPPED_CONTENT_TYPE  # belt and braces: bytes are never stored
    if skipped is not None:
        block["body_skipped"] = skipped
        if kind == BODY_KIND_BINARY and _mime_type(ctx.content_type).startswith(
            "multipart/"
        ):
            block["multipart"] = _multipart(
                ctx.body,
                ctx.content_type,
                ctx.body_truncated,
                keys,
                config.max_multipart_parts,
            )
        return

    raw = ctx.body
    max_nodes = config.max_body_nodes

    if kind == BODY_KIND_JSON:
        # FR-29: refuse before parsing, not after — see _json_node_estimate.
        if _exceeds_node_cap(raw, max_nodes, _JSON_STRUCTURE):
            block["body_skipped"] = BODY_SKIPPED_TOO_COMPLEX
            return
        try:
            parsed = _loads(raw)
        except Exception:
            try:
                # Undecodable bytes become U+FFFD rather than a parse failure;
                # only reached when the raw parse already refused the body.
                parsed = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                # FR-09 / AC-14: keep the raw text, tell the truth about the
                # parse. This is now the *only* unredacted path in the
                # document, and a client reaches it by breaking its own JSON
                # (review S-2), so what it keeps is clipped.
                block["body_parse_failed"] = True
                text = raw.decode("utf-8", "replace")
                if len(text) > _MAX_UNPARSED_BODY_RAW:
                    text = text[:_MAX_UNPARSED_BODY_RAW]
                    block["body_truncated"] = True
                block["body_raw"] = text
                return
        try:
            reduced = redact(
                parsed, keys, max_distinct_keys=config.max_distinct_keys
            )
        except RedactionBudgetExceeded:
            # N3-1: node count is not the axis that costs. A body of many
            # *distinct* keys is cheap to parse and expensive to redact, and
            # the node cap waves it through.
            block["body_skipped"] = BODY_SKIPPED_TOO_COMPLEX
            return
        # FR-09: the ``flattened`` field must always see an object.
        block["body"] = reduced if isinstance(reduced, dict) else {"_value": reduced}
        block["body_parse_failed"] = False
        return

    if kind == BODY_KIND_FORM:
        # Every form pair is a key, so the distinct-key budget is also a pair
        # ceiling — and it has to be applied *here*, before `_split_pairs`
        # walks the body. Catching `RedactionBudgetExceeded` afterwards still
        # refuses the body, but only after paying to parse it: 9,999 pairs
        # cost 6.45 ms to refuse that way, over the NFR-1 budget on its own.
        # Refusing has to be cheap, or the refusal is the attack.
        form_cap = min(max_nodes, config.max_distinct_keys)
        if _exceeds_node_cap(raw, form_cap, _FORM_STRUCTURE):
            block["body_skipped"] = BODY_SKIPPED_TOO_COMPLEX
            return
        try:
            _, parsed_form = _query(
                raw, keys, rebuild=False, max_distinct=config.max_distinct_keys
            )
        except RedactionBudgetExceeded:
            block["body_skipped"] = BODY_SKIPPED_TOO_COMPLEX
            return
        block["body"] = parsed_form
        block["body_parse_failed"] = False
        return

    # BODY_KIND_TEXT — FR-28. A key-based denylist cannot be applied to text,
    # and `Content-Type: text/plain` on a JSON payload used to be enough to
    # defeat the whole denylist (review M-1). Default: metadata only.
    if not config.capture_text_bodies:
        block["body_skipped"] = BODY_SKIPPED_CONTENT_TYPE
        return
    # FR-29 again: the scrub is this path's parse, and its cost is
    # attacker-chosen in both the number of rewrite sites and the sheer length.
    if len(raw) > config.max_scrub_bytes or _exceeds_node_cap(
        raw, max_nodes, _TEXT_STRUCTURE
    ):
        block["body_skipped"] = BODY_SKIPPED_TOO_COMPLEX
        return
    block["body_raw"] = _scrub_text(raw.decode("utf-8", "replace"), keys)


def _coerce_keyword(value: Any) -> str | None:
    """FR-31 — a value fit for a ``keyword`` field, or ``None`` to drop it."""
    if isinstance(value, str):
        return _clip(value, _MAX_USER_FIELD)
    if isinstance(value, (bool, int, float)):
        return _clip(str(value), _MAX_USER_FIELD)
    return None


def _coerce_roles(value: Any) -> list[str] | None:
    """FR-31 — ``user.roles`` is a ``keyword``; a dict there loses the record."""
    if isinstance(value, str):
        single = _coerce_keyword(value)
        return [single] if single is not None else None
    if isinstance(value, (list, tuple)):
        roles = [
            coerced
            for coerced in (_coerce_keyword(item) for item in value[:_MAX_USER_ROLES])
            if coerced is not None
        ]
        return roles or None
    return None


def _user_block(user: dict[str, Any] | None) -> dict[str, Any] | None:
    """Schema §2.5 — ``id``/``name``/``roles`` only, absent when empty.

    ``user_resolver`` is application code and may return anything (FR-25).
    ``index.mapping.ignore_malformed`` does **not** cover ``keyword``, so a
    dict landing in ``user.roles`` makes Elasticsearch reject the whole
    document with a ``mapper_parsing_exception`` (review M-5). Values are
    coerced to the declared types; whatever will not coerce is dropped, the
    same way ``_path_params`` already stringifies.
    """
    if not user:
        return None
    block: dict[str, Any] = {}
    for key in ("id", "name"):
        if key in user:
            coerced = _coerce_keyword(user[key])
            if coerced is not None:
                block[key] = coerced
    if "roles" in user:
        roles = _coerce_roles(user["roles"])
        if roles is not None:
            block["roles"] = roles
    return block or None


def _client_block(scope: dict[str, Any]) -> dict[str, Any] | None:
    """``client.ip``/``client.port``. A hostile scope must not cost the record.

    ``int(client[1])`` was unguarded, so a non-integer port took the whole
    document down the ``build_document`` failure path (review S-5).
    """
    client = scope.get("client")
    if not (isinstance(client, (tuple, list)) and len(client) == 2 and client[0]):
        return None
    try:
        port = int(client[1] or 0)
    except (TypeError, ValueError):
        port = 0
    return {"ip": str(client[0]), "port": port}


# ---------------------------------------------------------------------------
# The document
# ---------------------------------------------------------------------------


#: ``body_skipped`` values that mean "there was a body and we did not store
#: it", which is what ``audit_bodies_skipped_total`` counts. ``empty`` (there
#: was no body) and ``unread`` (the application never read the body it was
#: sent, so there was nothing to capture) are *not* the package dropping
#: anything, and counting them would bury the signal under every ``GET``.
_BODY_SKIPPED_COUNTED = frozenset({BODY_SKIPPED_CONTENT_TYPE, BODY_SKIPPED_TOO_COMPLEX})


def build_document(
    ctx: RequestContext, config: AuditConfig, *, metrics: Metrics | None = None
) -> dict[str, Any]:
    """Produce the document described in ``docs/schema.md`` §2.

    ``metrics`` is optional and keyword-only so the frozen two-argument call in
    AGENTS.md §"contracts" keeps working; without it the document is identical
    and only the counters are lost.
    """
    keys = _redact_keys(config)
    allowlist = _header_allowlist(config)
    scope = ctx.scope
    request_headers = filter_headers(scope.get("headers") or [], allowlist)
    url_query, audit_query, query_skipped = _url_query(ctx.query_string, keys, config)

    audit_request: dict[str, Any] = {
        "headers": request_headers,
        "query": audit_query,
        "body_bytes": len(ctx.body),
        "body_truncated": ctx.body_truncated,
    }
    if query_skipped is not None:
        audit_request["query_skipped"] = query_skipped
        _count(metrics, METRIC_QUERIES_SKIPPED)

    kind = body_kind_for(ctx.content_type)
    _body_block(ctx, kind, keys, config, audit_request)
    # Counted here rather than inside ``_body_block`` so that *every* path that
    # can set ``body_skipped`` — the four in ``_body_block`` plus the value the
    # middleware put on the context — is covered by construction, and a fifth
    # added later cannot forget the counter (review N2-6).
    if audit_request.get("body_skipped") in _BODY_SKIPPED_COUNTED:
        _count(metrics, METRIC_BODIES_SKIPPED)

    http: dict[str, Any] = {
        "request": {
            "method": ctx.method,
            "bytes": _request_bytes(ctx, len(ctx.body)),
        },
        "response": {"bytes": ctx.response_bytes},
    }
    version = scope.get("http_version")
    if version:
        http["version"] = str(version)
    mime = _mime_type(ctx.content_type)
    if mime:
        http["request"]["mime_type"] = mime
    if ctx.status_code is not None:
        http["response"]["status_code"] = ctx.status_code

    doc: dict[str, Any] = {
        "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "data_stream": {
            "type": "logs",
            "dataset": config.data_stream_dataset,
            "namespace": config.data_stream_namespace,
        },
        "event": {
            "kind": "event",
            "category": ["web"],
            "type": ["access"],
            "action": "http-request",
            "duration": ctx.duration_ns,
            "outcome": ctx.outcome,
        },
        "trace": {"id": ctx.trace_id},
        "service": {
            "name": config.service_name,
            "version": config.service_version,
            "environment": config.environment,
        },
        "host": {"hostname": _HOSTNAME},
        "process": {"pid": os.getpid()},
        "url": {"path": ctx.raw_path, "query": url_query},
        "http": http,
        "audit": {
            "route": _route_of(scope),
            "path_params": _path_params(scope, keys),
            "request": audit_request,
            "response": {"headers": filter_headers(ctx.response_headers, allowlist)},
        },
    }

    client = _client_block(scope)
    if client is not None:
        doc["client"] = client

    user_agent = request_headers.get("user-agent")
    if user_agent:
        doc["user_agent"] = {"original": user_agent}

    user = _user_block(ctx.user)
    if user is not None:
        doc["user"] = user

    if ctx.exc is not None and ctx.outcome == OUTCOME_FAILURE:
        doc["error"] = {
            "type": type(ctx.exc).__name__,
            "message": str(ctx.exc)[:_MAX_ERROR_MESSAGE],
        }

    return doc


def build_minimal_document(
    ctx: RequestContext, config: AuditConfig, exc: BaseException
) -> dict[str, Any]:
    """A degraded document for when :func:`build_document` itself failed.

    FR-01 ("exactly one document, whatever the outcome") and NFR-3 ("no package
    exception ever reaches the application") are in genuine tension once the
    response has already started: the request cannot be failed, but dropping
    the document leaves a hole in the audit trail that only a shared error
    counter records (review S-5). This emits a **hole marker** instead of a
    hole: identity, route-less origin, outcome, and an ``error.*`` block whose
    message is prefixed ``audit_logging:`` so a degraded record is greppable
    and never mistaken for an application failure.

    Every field is read defensively — this runs *because* something else
    already raised.
    """

    def safe(value: Any, fallback: str = "") -> str:
        try:
            return value if isinstance(value, str) else str(value)
        except Exception:  # pragma: no cover - pathological __str__
            return fallback

    try:
        dataset = config.data_stream_dataset
    except Exception:  # pragma: no cover - service_name is a validated str
        dataset = "apiaudit.unknown"

    doc: dict[str, Any] = {
        "@timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "data_stream": {
            "type": "logs",
            "dataset": dataset,
            "namespace": safe(config.environment),
        },
        "event": {
            "kind": "event",
            "category": ["web"],
            "type": ["access"],
            "action": "http-request",
            "duration": ctx.duration_ns,
            "outcome": safe(ctx.outcome),
        },
        "trace": {"id": safe(ctx.trace_id)},
        "service": {
            "name": safe(config.service_name),
            "version": safe(config.service_version),
            "environment": safe(config.environment),
        },
        "host": {"hostname": _HOSTNAME},
        "process": {"pid": os.getpid()},
        "url": {"path": safe(ctx.raw_path), "query": ""},
        "http": {
            "request": {"method": safe(ctx.method)},
            "response": {"bytes": ctx.response_bytes},
        },
        "audit": {"route": ROUTE_UNMATCHED},
        "error": {
            "type": type(exc).__name__,
            "message": _clip(
                f"audit_logging: could not build the audit document: {safe(exc)}",
                _MAX_ERROR_MESSAGE,
            ),
        },
    }
    if ctx.status_code is not None:
        doc["http"]["response"]["status_code"] = ctx.status_code
    return doc
