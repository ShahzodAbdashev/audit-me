"""An in-process Elasticsearch double that enforces the real index template.

Tier 2 has no Elasticsearch. What it *does* have is the artefact that decides
what Elasticsearch would do: ``infra/elasticsearch/template-apiaudit.json``
(A5). This module parses that file and applies its rules to a document:

* ``dynamic: false`` at the root and in **every** nested object — a field the
  template does not declare is reported. Real Elasticsearch swallows such a
  field silently (it lands in ``_source`` and is never indexed), which is
  exactly why the double is deliberately *stricter*: it raises. A test that
  passes here is a test whose documents are wholly searchable in production.
* ``flattened`` collapses an arbitrary object into **one** mapping field. This
  is the mechanism AC-10 exists to prove, so the walker models it exactly:
  everything under ``audit.request.body`` costs one field, not one per key.
* ``total_fields.limit: 200`` and ``depth_limit`` are read from the template's
  settings rather than hardcoded here.
* ``constant_keyword`` values are checked against the constant the template
  pins (``data_stream.type: "logs"``, ``event.kind: "event"``).

``ignore_malformed: true`` is set on the index, so a value of the wrong type is
*not* a rejection in Elasticsearch — it is silently unindexed. The double
records those in ``malformed`` instead of raising, and tests assert the list is
empty, which is the only way to notice.

Rejection vs. malformed — the distinction the review said was missing
---------------------------------------------------------------------

The first version of this file modelled ``ignore_malformed`` as covering every
type, so *every* type mismatch was recorded in ``malformed`` and the document
was indexed anyway. Review addendum S-15/S-16 pointed out that this makes the
double green-light two defects that a real cluster rejects:

* **M-5** — ``index.mapping.ignore_malformed`` applies to the numeric family,
  ``boolean``, ``date``, ``ip`` and the geo types **only**. It does not cover
  ``keyword``, ``constant_keyword``, ``text`` or ``flattened``. A ``dict`` in
  ``user.roles`` is a ``mapper_parsing_exception`` and the **whole document**
  is lost — not one field.
* **N-9** — ``FlattenedFieldParser.addField`` (elasticsearch v8.13.4) indexes a
  flattened leaf as the single term ``key + NUL + value`` and throws
  ``IllegalArgumentException`` when that exceeds ``IndexWriter``'s
  ``MAX_TERM_LENGTH`` of 32,766 bytes — *before* it looks at ``index`` or
  ``doc_values``, so no template setting avoids it. The same method throws on a
  NUL byte in a key.

So this double now has **two** failure modes, and they are not the same thing:

``malformed``
    Only the types ``ignore_malformed`` really covers. The value is silently
    not indexed; the document survives. Tests assert the list is empty, because
    silence is the whole problem.
``DocumentRejectedError``
    Everything Elasticsearch answers with a rejection. The document is **not**
    indexed — ``self.documents`` never sees it — and the error is raised
    regardless of ``strict``, because unlike ``UnmappedFieldError`` this is not
    the double being stricter than production. It *is* production.

Nothing here is a general-purpose Elasticsearch: there is no query DSL, no
analysis, no scoring. It answers exactly the questions the acceptance criteria
ask. What it still does **not** model is listed in ``tests/AC-matrix.md`` §4.5.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "TEMPLATE_PATH",
    "ILM_PATH",
    "UnmappedFieldError",
    "DocumentRejectedError",
    "IndexTemplate",
    "InProcessElasticsearch",
    "load_template",
    "dynamic_leaf_paths",
    "flattened_terms",
    "IGNORE_MALFORMED_TYPES",
    "LUCENE_MAX_TERM_BYTES",
]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_PATH = PROJECT_ROOT / "infra" / "elasticsearch" / "template-apiaudit.json"
ILM_PATH = PROJECT_ROOT / "infra" / "elasticsearch" / "ilm-apiaudit.json"

#: ``org.apache.lucene.index.IndexWriter.MAX_TERM_LENGTH`` — 32,766 bytes, i.e.
#: ``IndexWriter.MAX_TERM_LENGTH = BYTE_BLOCK_SIZE - 2`` (review N-9).
LUCENE_MAX_TERM_BYTES = 32766

#: The types ``index.mapping.ignore_malformed`` actually covers in ES 8.x. A
#: mismatch in one of these is silently unindexed; a mismatch in anything else
#: — ``keyword``, ``constant_keyword``, ``text``, ``flattened`` — rejects the
#: entire document (review M-5).
IGNORE_MALFORMED_TYPES = frozenset(
    {
        "long",
        "integer",
        "short",
        "byte",
        "double",
        "float",
        "half_float",
        "scaled_float",
        "boolean",
        "date",
        "date_nanos",
        "ip",
        "geo_point",
        "geo_shape",
    }
)


class UnmappedFieldError(AssertionError):
    """A document carried a field the index template does not declare.

    In production this is silent data loss at query time (``dynamic: false``),
    which is why it is loud here.
    """


class DocumentRejectedError(AssertionError):
    """Elasticsearch would answer this document with an error, not index it.

    Models the bulk-item failures that lose a whole audit record:
    ``mapper_parsing_exception`` for a structural type mismatch in a field
    ``ignore_malformed`` does not cover (review M-5), and
    ``illegal_argument_exception`` for a flattened term over Lucene's
    ``MAX_TERM_LENGTH`` or a NUL in a flattened key (review N-9).

    Unlike :class:`UnmappedFieldError` this is **not** the double being
    stricter than production, so it is raised whatever ``strict`` says.
    """


def load_template(path: Path = TEMPLATE_PATH) -> dict[str, Any]:
    """The real A5 index template, straight off disk."""
    with path.open(encoding="utf-8") as handle:
        loaded: dict[str, Any] = json.load(handle)
    return loaded


# ---------------------------------------------------------------------------
# Type checking, the little that `ignore_malformed: true` leaves meaningful
# ---------------------------------------------------------------------------


def _is_long(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_stringish(value: Any) -> bool:
    return isinstance(value, str)


def _accepts(es_type: str, value: Any) -> bool:
    """Would Elasticsearch index this value into a field of this type?"""
    if value is None:
        return True  # a null is accepted and simply not indexed
    if isinstance(value, list):
        return all(_accepts(es_type, item) for item in value)
    if es_type in ("keyword", "constant_keyword", "text", "wildcard"):
        return _is_stringish(value) or _is_long(value) or isinstance(value, bool)
    if es_type == "long":
        return _is_long(value)
    if es_type == "boolean":
        return isinstance(value, bool)
    if es_type == "ip":
        return _is_ip(value)
    if es_type == "date":
        return _is_stringish(value) or _is_long(value)
    if es_type == "float" or es_type == "double":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return True


def _utf8(value: str) -> bytes:
    """UTF-8 bytes, tolerating the lone surrogates a hostile body can carry."""
    return value.encode("utf-8", "surrogatepass")


def _string_form(value: Any) -> str | None:
    """How a leaf value is rendered before it becomes a term, or ``None``.

    ``None`` means "produces no term at all": Elasticsearch skips nulls, and
    the flattened parser only ever indexes scalars.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return repr(value) if isinstance(value, float) else str(value)
    return None


def _structural_rejection(es_type: str, path: str, value: Any) -> str | None:
    """Why a ``keyword``-family field would reject this value (review M-5).

    ``index.mapping.ignore_malformed`` does not cover the string types, so an
    object here is not "one unindexed field" — it is a
    ``mapper_parsing_exception`` and the whole audit record is gone. This is
    exactly the case the first version of the double indexed happily.
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        for item in value:
            reason = _structural_rejection(es_type, path, item)
            if reason is not None:
                return reason
        return None
    if isinstance(value, dict):
        return (
            f"{path}: mapper_parsing_exception — an object cannot be indexed "
            f"into a [{es_type}] field (ignore_malformed does not cover it)"
        )
    if isinstance(value, (str, int, float, bool)):
        return None
    return (
        f"{path}: mapper_parsing_exception — {type(value).__name__} cannot be "
        f"indexed into a [{es_type}] field"
    )


def flattened_terms(obj: Any, prefix: str = "") -> Any:
    """``(key, value)`` leaves the way ``FlattenedFieldParser`` builds them.

    The key is the dotted path *inside* the flattened field — for
    ``{"a": {"b": "v"}}`` the parser indexes the single term ``a`` + NUL +
    ``v`` under the key ``a.b``. Lists contribute one leaf per element under
    the same key, which is why a list does not extend the key.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from flattened_terms(value, path)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from flattened_terms(item, prefix)
    else:
        yield prefix, obj


def _term_rejection(key: str, value: Any, ignore_above: int | None, field_path: str) -> str | None:
    """Lucene's ``MAX_TERM_LENGTH`` and the NUL separator, for one leaf (N-9).

    ``ignore_above`` is applied to the **value** and counts *characters*, so a
    value past it produces no term and cannot blow the limit. The key is not
    covered by ``ignore_above`` at all — which is the whole defect.
    """
    if "\x00" in key:
        return (
            f"{field_path}: illegal_argument_exception — the flattened key "
            f"{key!r} contains a NUL, which is the parser's own key/value "
            "separator"
        )
    text = _string_form(value)
    if text is None:
        return None
    if ignore_above is not None and len(text) > ignore_above:
        return None  # skipped by ignore_above: no term is produced at all
    # AC-10 pushes ~150 000 leaves through here, so do not encode what cannot
    # possibly be over the bound: UTF-8 is at most 4 bytes per character.
    if (len(key) + len(text)) * 4 + 1 <= LUCENE_MAX_TERM_BYTES:
        return None
    term_bytes = len(_utf8(key)) + 1 + len(_utf8(text))
    if term_bytes > LUCENE_MAX_TERM_BYTES:
        return (
            f"{field_path}: illegal_argument_exception — the flattened term for "
            f"key {key[:40]!r}… is {term_bytes} bytes, over Lucene's "
            f"MAX_TERM_LENGTH of {LUCENE_MAX_TERM_BYTES}"
        )
    return None


def _object_depth(value: Any, depth: int = 1) -> int:
    """Depth of a nested structure, the way `flattened.depth_limit` counts."""
    if isinstance(value, dict):
        if not value:
            return depth
        return max(_object_depth(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        if not value:
            return depth
        return max(_object_depth(v, depth) for v in value)
    return depth


# ---------------------------------------------------------------------------
# The template
# ---------------------------------------------------------------------------


@dataclass
class IndexTemplate:
    """``template-apiaudit.json`` reduced to the rules a document must satisfy."""

    raw: dict[str, Any]

    @classmethod
    def load(cls, path: Path = TEMPLATE_PATH) -> IndexTemplate:
        return cls(load_template(path))

    @property
    def mappings(self) -> dict[str, Any]:
        mappings: dict[str, Any] = self.raw["template"]["mappings"]
        return mappings

    @property
    def index_settings(self) -> dict[str, Any]:
        settings: dict[str, Any] = self.raw["template"]["settings"]["index"]
        return settings

    @property
    def total_fields_limit(self) -> int:
        return int(self.index_settings["mapping"]["total_fields"]["limit"])

    @property
    def index_depth_limit(self) -> int:
        """``index.mapping.depth.limit`` — note the nesting.

        This used to read ``mapping["depth_limit"]``, matching the template,
        and both were wrong in the same way: Elasticsearch spells the *index
        setting* ``index.mapping.depth.limit`` and rejects the flat form with
        ``unknown setting [index.mapping.depth_limit]``. ``depth_limit`` is
        correct only as a ``flattened`` **field** parameter, which is almost
        certainly how the two got confused.

        Because the double agreed with the template, Tier 2 stayed green while
        a real cluster refused the template outright — and the data stream was
        then created with a dynamic mapping, the one-way door D-11 exists to
        prevent. A double that shares the config's assumption cannot test it;
        this reads the real shape and falls back only to keep an older
        template loadable.
        """
        mapping = self.index_settings["mapping"]
        depth = mapping.get("depth")
        if isinstance(depth, dict):
            return int(depth["limit"])
        return int(mapping["depth_limit"])

    @property
    def index_patterns(self) -> list[str]:
        patterns: list[str] = self.raw["index_patterns"]
        return patterns

    def declared_field_paths(self) -> set[str]:
        """Every mapping entry the template declares — leaves *and* containers.

        This is what ``total_fields.limit`` is actually counted against in
        Elasticsearch, and with ``dynamic: false`` it is a constant: no volume
        of traffic and no body shape can make it grow. AC-10 in one sentence.
        """
        found: set[str] = set()

        def walk(node: dict[str, Any], prefix: str) -> None:
            for name, child in (node.get("properties") or {}).items():
                path = f"{prefix}.{name}" if prefix else name
                found.add(path)
                if "properties" in child:
                    walk(child, path)

        walk(self.mappings, "")
        return found

    def flattened_paths(self) -> set[str]:
        """Mapping paths declared as ``flattened`` — the field-budget shields."""
        found: set[str] = set()

        def walk(node: dict[str, Any], prefix: str) -> None:
            for name, child in (node.get("properties") or {}).items():
                path = f"{prefix}.{name}" if prefix else name
                if child.get("type") == "flattened":
                    found.add(path)
                elif "properties" in child:
                    walk(child, path)

        walk(self.mappings, "")
        return found


# ---------------------------------------------------------------------------
# The double
# ---------------------------------------------------------------------------


@dataclass
class IndexResult:
    """What indexing one document produced."""

    index: str
    fields: set[str] = field(default_factory=set)
    unmapped: list[str] = field(default_factory=list)
    #: Values ``ignore_malformed`` silently drops. The document survives.
    malformed: list[str] = field(default_factory=list)
    #: Reasons Elasticsearch would refuse the document outright (M-5, N-9).
    #: Non-empty means the whole audit record is lost, not one field.
    rejected: list[str] = field(default_factory=list)


class InProcessElasticsearch:
    """Applies ``template-apiaudit.json`` to documents and answers queries."""

    def __init__(self, template: IndexTemplate | None = None) -> None:
        self.template = template if template is not None else IndexTemplate.load()
        self.documents: list[dict[str, Any]] = []
        #: Distinct mapping fields any indexed document has actually reached.
        self.mapped_fields: set[str] = set()
        #: Values the mapping would silently refuse to index (ignore_malformed).
        self.malformed: list[str] = []
        #: Documents Elasticsearch would have rejected outright, had any been
        #: indexed with ``raise_on_reject=False``.
        self.rejected: list[str] = []
        self._flattened = self.template.flattened_paths()

    # -- ingest -------------------------------------------------------------

    def index(
        self, doc: dict[str, Any], *, strict: bool = True, raise_on_reject: bool = True
    ) -> IndexResult:
        """Index one document, enforcing the template. Returns what it cost.

        Two different failures, deliberately not conflated:

        ``UnmappedFieldError`` (``strict``)
            The double being stricter than production — ``dynamic: false``
            stores such a field in ``_source`` and never indexes it, silently.
        ``DocumentRejectedError`` (``raise_on_reject``)
            Production itself. The document is not indexed at all, so it is
            not appended to :attr:`documents` either. Only turn this off to
            *inspect* a rejection, never to tolerate one.
        """
        result = IndexResult(index=self.index_name_for(doc))
        self._walk(self.template.mappings, doc, "", result, depth=1)
        if strict and result.unmapped:
            raise UnmappedFieldError(
                "the index template is dynamic:false and does not declare: "
                + ", ".join(sorted(result.unmapped))
            )
        if result.rejected:
            self.rejected.extend(result.rejected)
            if raise_on_reject:
                raise DocumentRejectedError(
                    "Elasticsearch would reject this document and lose the whole "
                    "audit record: " + "; ".join(result.rejected)
                )
            return result
        self.documents.append(doc)
        self.mapped_fields |= result.fields
        self.malformed.extend(result.malformed)
        return result

    def index_line(
        self, line: str, *, strict: bool = True, raise_on_reject: bool = True
    ) -> IndexResult:
        """Index one JSONL line, the way Filebeat's ndjson parser would."""
        return self.index(json.loads(line), strict=strict, raise_on_reject=raise_on_reject)

    def index_file(self, path: Path, *, strict: bool = True) -> list[IndexResult]:
        """Index every line of a JSONL file written by ``FileSink``."""
        results = []
        with path.open(encoding="utf-8") as handle:
            for raw in handle:
                raw = raw.strip()
                if raw:
                    results.append(self.index_line(raw, strict=strict))
        return results

    def index_name_for(self, doc: dict[str, Any]) -> str:
        """Filebeat's ``%{[data_stream.type]}-%{[dataset]}-%{[namespace]}``."""
        stream = doc.get("data_stream") or {}
        return "{}-{}-{}".format(
            stream.get("type", ""), stream.get("dataset", ""), stream.get("namespace", "")
        )

    # -- the walker ---------------------------------------------------------

    def _walk(
        self,
        node: dict[str, Any],
        value: Any,
        prefix: str,
        result: IndexResult,
        depth: int,
    ) -> None:
        properties = node.get("properties") or {}
        dynamic = node.get("dynamic", True)
        if not isinstance(value, dict):
            # An object mapper handed a scalar is a mapper_parsing_exception,
            # not an unindexed field: ignore_malformed covers no object type.
            result.rejected.append(
                f"{prefix or '<root>'}: mapper_parsing_exception — object mapper "
                f"given {type(value).__name__}"
            )
            return
        if depth > self.template.index_depth_limit:
            result.malformed.append(f"{prefix}: past index.mapping.depth_limit")
            return

        for key, child_value in value.items():
            path = f"{prefix}.{key}" if prefix else key
            child = properties.get(key)
            if child is None:
                if dynamic is False:
                    result.unmapped.append(path)
                else:  # pragma: no cover - the template is dynamic:false throughout
                    result.fields.add(path)
                continue

            es_type = child.get("type")
            if es_type == "flattened":
                # The whole subtree costs exactly one mapping field (D-10).
                result.fields.add(path)
                self._flattened_field(child, child_value, path, result)
                continue

            if "properties" in child:
                self._walk(child, child_value, path, result, depth + 1)
                continue

            result.fields.add(path)
            if es_type is None:  # pragma: no cover - template always names a type
                continue

            if es_type in IGNORE_MALFORMED_TYPES:
                # The only types the index setting actually covers: a bad value
                # here is silently unindexed and the document still lands.
                if not _accepts(es_type, child_value):
                    result.malformed.append(
                        f"{path}: {child_value!r} is not a valid {es_type}"
                    )
                continue

            # keyword / constant_keyword / text / wildcard — review M-5. A
            # structural mismatch here loses the entire document.
            structural = _structural_rejection(es_type, path, child_value)
            if structural is not None:
                result.rejected.append(structural)
                continue
            if es_type == "constant_keyword" and "value" in child:
                if child_value is not None and child_value != child["value"]:
                    result.rejected.append(
                        f"{path}: illegal_argument_exception — [constant_keyword] "
                        f"is pinned to {child['value']!r}, got {child_value!r}"
                    )
                    continue
            self._keyword_term_limit(child, child_value, path, result)

    def _keyword_term_limit(
        self, mapping: dict[str, Any], value: Any, path: str, result: IndexResult
    ) -> None:
        """Lucene ``MAX_TERM_LENGTH`` on a plain indexed ``keyword`` (N-9).

        ``index: false`` **and** ``doc_values: false`` together mean no term is
        produced at all, which is why ``audit.request.body_raw`` can carry a
        1 MiB string with ``ignore_above`` unset and still be safe (review,
        "what I expected to find and did not"). Anything still indexed is
        checked, so a future template edit that drops an ``ignore_above``
        fails here rather than in production.
        """
        if mapping.get("index") is False and mapping.get("doc_values") is False:
            return
        ignore_above = mapping.get("ignore_above")
        values = value if isinstance(value, (list, tuple)) else [value]
        for item in values:
            text = _string_form(item)
            if text is None:
                continue
            if ignore_above is not None and len(text) > int(ignore_above):
                continue
            if len(_utf8(text)) > LUCENE_MAX_TERM_BYTES:
                result.rejected.append(
                    f"{path}: illegal_argument_exception — {len(_utf8(text))} bytes "
                    f"is over Lucene's MAX_TERM_LENGTH of {LUCENE_MAX_TERM_BYTES}"
                )
                return

    def _flattened_field(
        self, mapping: dict[str, Any], value: Any, path: str, result: IndexResult
    ) -> None:
        """One ``flattened`` field: depth, shape, and every leaf's term (N-9)."""
        if value is None:
            return
        if not isinstance(value, dict):
            result.rejected.append(
                f"{path}: mapper_parsing_exception — a [flattened] field must be "
                f"an object, got {type(value).__name__}"
            )
            return
        limit = int(mapping.get("depth_limit", 20))
        actual = _object_depth(value)
        if actual > limit:
            result.rejected.append(
                f"{path}: illegal_argument_exception — depth {actual} exceeds the "
                f"[flattened] depth_limit of {limit}"
            )
            return
        ignore_above = mapping.get("ignore_above")
        cap = int(ignore_above) if ignore_above is not None else None
        for key, leaf in flattened_terms(value):
            reason = _term_rejection(key, leaf, cap, path)
            if reason is not None:
                result.rejected.append(reason)
                return

    # -- queries ------------------------------------------------------------

    def count(self) -> int:
        return len(self.documents)

    def search(self, **terms: Any) -> list[dict[str, Any]]:
        """Every document whose dotted paths equal all of ``terms``."""
        return [d for d in self.documents if all(_get(d, k) == v for k, v in terms.items())]

    def by_trace(self, trace_id: str) -> list[dict[str, Any]]:
        return [d for d in self.documents if _get(d, "trace.id") == trace_id]

    def one(self, **terms: Any) -> dict[str, Any]:
        """The single matching document, or an assertion failure."""
        hits = self.search(**terms)
        if len(hits) != 1:
            raise AssertionError(f"expected exactly 1 document for {terms}, got {len(hits)}")
        return hits[0]

    def field_caps(self) -> set[str]:
        """``GET _field_caps?fields=*`` — the fields documents actually reached.

        Mapping *containers* are added too, because Elasticsearch counts an
        object mapper against ``total_fields.limit`` just like a leaf.
        """
        with_parents = set(self.mapped_fields)
        for path in self.mapped_fields:
            parts = path.split(".")
            for index in range(1, len(parts)):
                with_parents.add(".".join(parts[:index]))
        return with_parents

    def mapping_field_count(self) -> int:
        """What ``GET _mapping`` would report as the field count (AC-10)."""
        return len(self.field_caps())


def _get(doc: dict[str, Any], dotted: str) -> Any:
    """Read a dotted path out of a document; ``None`` when any hop is missing."""
    current: Any = doc
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


# ---------------------------------------------------------------------------
# The counterfactual
# ---------------------------------------------------------------------------


def dynamic_leaf_paths(doc: dict[str, Any], prefix: str = "") -> set[str]:
    """Every field a ``dynamic: true`` mapping would have created for *doc*.

    This is the mapping explosion ``flattened`` exists to prevent. AC-10
    compares the two numbers: without ``flattened``, 50 endpoints' worth of
    distinct body shapes blows straight past ``total_fields.limit``.
    """
    found: set[str] = set()
    if isinstance(doc, dict):
        for key, value in doc.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict) and value:
                found |= dynamic_leaf_paths(value, path)
            elif isinstance(value, list):
                found.add(path)
                for item in value:
                    if isinstance(item, dict):
                        found |= dynamic_leaf_paths(item, path)
            else:
                found.add(path)
    return found
