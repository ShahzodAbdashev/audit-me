"""``python -m audit_logging.check`` — is this actually working?

Reads the same ``AUDIT_*`` environment your application uses, so it checks the
configuration you really deployed rather than one retyped into a command line.

    python -m audit_logging.check
    python -m audit_logging.check --leak "a-real-secret"
    python -m audit_logging.check reconcile [--tolerance N]
    python -m audit_logging.check version
    python -m audit_logging.check verify-chain [--from-files] [--require-genesis]

Documents arriving is necessary but not sufficient, which is the reason this
exists as code rather than as a paragraph. An index template that failed to
install still accepts documents happily; the field count still looks fine,
because a dynamic mapping is under the limit until it suddenly is not. So the
check that matters is ``dynamic: false``, and it is easy to never think to run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .config import AuditConfig

OK = "  ok   "
BAD = "  FAIL "
WARN = "  warn "


def _client(config: AuditConfig) -> Any:
    try:
        import httpx
    except ImportError:
        print("httpx is not installed — pip install 'audit-me[elasticsearch]'")
        raise SystemExit(2)
    auth = None
    headers = {}
    if config.elasticsearch_api_key:
        headers["authorization"] = f"ApiKey {config.elasticsearch_api_key}"
    elif config.elasticsearch_username:
        auth = (config.elasticsearch_username, config.elasticsearch_password or "")
    return httpx.Client(
        base_url=str(config.elasticsearch_url).rstrip("/"),
        auth=auth,
        headers=headers,
        verify=config.elasticsearch_verify_certs,
        timeout=30.0,
    )


def _count_fields(props: dict[str, Any]) -> int:
    total = 0
    for spec in props.values():
        if isinstance(spec, dict) and "properties" in spec:
            total += _count_fields(spec["properties"])
        else:
            total += 1
    return total


# ---------------------------------------------------------------------------
# 0.2: `coverage` and `docs` — is every endpoint described? (plan §4.4, §8)
# ---------------------------------------------------------------------------


def _load_app(spec: str) -> Any:
    import importlib

    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        raise SystemExit(f"expected <module:app>, got {spec!r}")
    sys.path.insert(0, str(Path.cwd()))
    obj: Any = importlib.import_module(module_name)
    for part in attr.split("."):
        obj = getattr(obj, part)
    return obj


def _endpoints(app: Any, *, hidden: bool = False) -> list[tuple[str, str, Any]]:
    """(METHOD, route template, route) for every documented method+route, or with
    ``hidden`` for the include_in_schema=False ones (still recorded at runtime)."""
    out: list[tuple[str, str, Any]] = []
    for route in getattr(app, "routes", []):
        methods = getattr(route, "methods", None)
        if not methods or not hasattr(route, "endpoint") or not hasattr(route, "path"):
            continue
        if bool(getattr(route, "include_in_schema", True)) == hidden:
            continue
        for method in sorted(m.upper() for m in methods):
            if method not in ("HEAD", "OPTIONS"):
                out.append((method, route.path, route))
    return out


def _classify(
    endpoints: list[tuple[str, str, Any]], catalog: dict[tuple[str, str], Any]
) -> list[tuple[str, str, str, Any, Any]]:
    """(method, path, level, EventDef|None, route). Raises if decorators is unbuilt."""
    from .semantic.decorators import event_def_of

    rows: list[tuple[str, str, str, Any, Any]] = []
    for method, path, route in endpoints:
        event = event_def_of(route.endpoint)
        if event is not None:
            rows.append((method, path, "decorator", event, route))
        elif (method, path) in catalog:
            rows.append((method, path, "catalog", catalog[(method, path)], route))
        else:
            rows.append((method, path, "derived", None, route))
    return rows


Rows = list[tuple[str, str, str, Any, Any]]


def _semantic_rows(args: argparse.Namespace) -> tuple[Rows, dict[tuple[str, str], Any], Rows]:
    """(documented rows, catalog, hidden rows)."""
    app = _load_app(args.app)
    catalog: dict[tuple[str, str], Any] = {}
    try:
        if getattr(args, "catalog", None):
            from .semantic.catalog import load_catalog

            catalog = dict(load_catalog(args.catalog))
        rows = _classify(_endpoints(app), catalog)
        hidden = _classify(_endpoints(app, hidden=True), catalog)
    except NotImplementedError:
        print(f"{BAD} the semantic layer (decorators/catalog) is not implemented in this build")
        raise SystemExit(2)
    except ValueError as exc:
        print(f"{BAD} catalog is invalid: {exc}")
        raise SystemExit(2)
    return rows, catalog, hidden


def _coverage(args: argparse.Namespace) -> int:
    rows, catalog, hidden = _semantic_rows(args)
    total = len(rows)
    counts = {level: sum(1 for r in rows if r[2] == level) for level in ("decorator", "catalog", "derived")}
    pct = 100.0 * counts["derived"] / total if total else 0.0
    print(
        f"{total} routes · {counts['decorator']} decorator · {counts['catalog']} catalog"
        f" · {counts['derived']} derived ({pct:.1f} %)"
    )
    for method, path, level, _, _ in rows:
        if level == "derived":
            print(f"  DERIVED  {method} {path}  -> add @audited(...) or a catalog entry")
    for method, path, level, _, _ in hidden:
        if level == "derived":
            print(f"  HIDDEN   {method} {path}  -> not in the schema, still recorded as derived")
    seen = {(m, p) for m, p, _, _, _ in rows + hidden}
    for method, path in sorted(set(catalog) - seen):
        print(f"  ORPHAN   catalog: {method} {path}  -> no such route")
    if pct > args.max_derived:
        print(f"{BAD} derived {pct:.1f} % > --max-derived {args.max_derived:g} %")
        return 1
    return 0


def _docs(args: argparse.Namespace) -> int:
    rows, _, _ = _semantic_rows(args)
    service = os.environ.get("AUDIT_SERVICE_NAME", "service")
    derive_fn: Any = None
    labels: Any = None
    try:
        from .semantic.derive import default_labels, derive

        labels, derive_fn = default_labels(), derive
    except NotImplementedError:
        pass

    def cell(value: Any) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ") if value is not None else "—"

    print("| method | route | level | code | category | risk | uz |")
    print("|---|---|---|---|---|---|---|")
    for method, path, level, event, route in rows:
        if event is None and derive_fn is not None:
            try:
                event = derive_fn(service, method, path, labels=labels, description=getattr(route, "summary", None))
            except Exception:  # noqa: BLE001 - the table still lists the route
                event = None
        if event is None:
            print(f"| {method} | {cell(path)} | derived | — | — | — | — |")
        else:
            print(
                f"| {method} | {cell(path)} | {level} | {cell(event.code)} | {cell(event.category)}"
                f" | {cell(event.risk)} | {cell(event.templates.get('uz'))} |"
            )
    return 0


def _semantic_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m audit_logging.check")
    sub = parser.add_subparsers(dest="command", required=True)
    cov = sub.add_parser("coverage", help="count decorator / catalog / derived routes")
    cov.add_argument("app", metavar="module:app")
    cov.add_argument("--max-derived", type=float, default=0.0, metavar="PCT")
    cov.add_argument("--catalog", metavar="FILE", default=os.environ.get("AUDIT_CATALOG_FILE"))
    docs = sub.add_parser("docs", help="Markdown table of every endpoint -> code -> sentence")
    docs.add_argument("app", metavar="module:app")
    docs.add_argument("--catalog", metavar="FILE", default=os.environ.get("AUDIT_CATALOG_FILE"))
    args = parser.parse_args(argv)
    return _coverage(args) if args.command == "coverage" else _docs(args)


# ---------------------------------------------------------------------------
# 0.2 round 2: `reconcile`, `version`, `verify-chain` (NFR-7, FR-48, §17.1)
# ---------------------------------------------------------------------------

_OPS = ("reconcile", "version", "verify-chain")
_PAGE = 1000


def _service_files(config: AuditConfig) -> list[Path]:
    """This service's JSONL files in ``log_dir``, rotations included, oldest name first."""
    from .sinks.file_sink import _safe_service_name

    prefix = f"{_safe_service_name(config.service_name)}-"
    log_dir = Path(config.log_dir)
    if not log_dir.is_dir():
        return []
    return sorted(p for p in log_dir.glob("*.jsonl*") if p.name.startswith(prefix))


def _file_docs(files: list[Path]) -> list[tuple[Path, Any]]:
    """(file, parsed line) for every complete, non-empty line. Unparseable lines
    come back as ``None`` so they still count as written."""
    out: list[tuple[Path, Any]] = []
    for path in files:
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        for line in raw.split(b"\n")[:-1]:  # the last piece is a partial line or b""
            if not line.strip():
                continue
            try:
                out.append((path, json.loads(line)))
            except ValueError:
                out.append((path, None))
    return out


def _pid_of(path: Path, doc: Any) -> int | None:
    process = doc.get("process") if isinstance(doc, dict) else None
    pid = process.get("pid") if isinstance(process, dict) else None
    if isinstance(pid, int) and not isinstance(pid, bool):
        return pid
    from .shipper import _FILENAME

    match = _FILENAME.match(path.name)
    return int(match.group("pid")) if match else None


class _Span:
    """What the files on disk say about one pid: line count, host, @timestamp range."""

    def __init__(self) -> None:
        self.written = 0
        self.host: str | None = None
        self.lo: str | None = None
        self.hi: str | None = None

    def add(self, doc: Any) -> None:
        self.written += 1
        if not isinstance(doc, dict):
            return
        host = doc.get("host")
        name = host.get("hostname") if isinstance(host, dict) else None
        if self.host is None and isinstance(name, str):
            self.host = name
        ts = doc.get("@timestamp")
        if isinstance(ts, str):  # ISO-8601 UTC, same format: string order is time order
            self.lo = ts if self.lo is None or ts < self.lo else self.lo
            self.hi = ts if self.hi is None or ts > self.hi else self.hi


def _es_count(client: Any, index: str, pid: int, service: str, span: _Span) -> int:
    """Documents of this pid, service and host within the time span still on disk:
    pids repeat across pods, containers and restarts, and retention deletes files."""
    from .document import _HOSTNAME

    filters: list[dict[str, Any]] = [
        {"term": {"process.pid": pid}},
        {"term": {"service.name": service}},
        {"term": {"host.hostname": span.host or _HOSTNAME}},
    ]
    if span.lo is not None and span.hi is not None:
        # "…:00.123456Z" -> "…:00.123Z": ES stores milliseconds, and a
        # microsecond gte would exclude the oldest line's own document.
        lo, hi = (t[:23] + "Z" if len(t) > 24 and t.endswith("Z") else t for t in (span.lo, span.hi))
        filters.append({"range": {"@timestamp": {"gte": lo, "lte": hi}}})
    response = client.post(f"/{index}/_count", json={"query": {"bool": {"filter": filters}}})
    if response.status_code == 404:
        return 0  # nothing shipped yet: the data stream does not exist
    if response.status_code >= 300:
        raise RuntimeError(f"HTTP {response.status_code}: {response.text[:200]}")
    return int(response.json()["count"])


def _reconcile(config: AuditConfig, args: argparse.Namespace) -> int:
    written: dict[int | None, _Span] = {}
    for path, doc in _file_docs(_service_files(config)):
        written.setdefault(_pid_of(path, doc), _Span()).add(doc)
    if not written:
        print(f"{WARN} no records on disk in {config.log_dir}")
        return 0
    client = _client(config)
    failures = 0
    try:
        print(f"{'pid':>10} {'written':>10} {'indexed':>10} {'missing':>10}")
        for pid in sorted(written, key=lambda p: -1 if p is None else p):
            span = written[pid]
            indexed = _es_count(client, config.index_name, pid, config.service_name, span) if pid is not None else 0
            missing = max(0, span.written - indexed)
            flag = ""
            if missing > args.tolerance:
                failures += 1
                flag = "  FAIL"
            print(f"{pid if pid is not None else '?':>10} {span.written:>10} {indexed:>10} {missing:>10}{flag}")
    except Exception as exc:  # noqa: BLE001
        print(f"{BAD} cannot count in {config.index_name}: {exc}")
        return 1
    finally:
        client.close()
    if failures:
        print(f"{BAD} {failures} process(es) have more records on disk than indexed (--tolerance {args.tolerance})")
        return 1
    print(f"{OK} every process's records are indexed (--tolerance {args.tolerance})")
    return 0


def _installed_schema_version(client: Any, name: str) -> tuple[bool, str | None]:
    """(template exists, its ``_meta.schema_version``)."""
    response = client.get(f"/_index_template/{name}")
    if response.status_code == 404:
        return False, None
    if response.status_code >= 300:
        raise RuntimeError(f"HTTP {response.status_code}: {response.text[:200]}")
    version = None
    for entry in response.json().get("index_templates", []):
        meta = entry.get("index_template", {}).get("_meta") or {}
        version = meta.get("schema_version", version)
    return True, None if version is None else str(version)


def _version(config: AuditConfig) -> int:
    from .semantic.model import SCHEMA_VERSION

    client = _client(config)
    try:
        exists, installed = _installed_schema_version(client, config.index_template_name)
    except Exception as exc:  # noqa: BLE001
        print(f"{BAD} cannot read template {config.index_template_name}: {exc}")
        return 1
    finally:
        client.close()
    shown = installed if installed is not None else ("none (0.1 template)" if exists else "not installed")
    print(f"template  : {config.index_template_name}")
    print(f"installed : {shown}")
    print(f"package   : {SCHEMA_VERSION}")
    if installed == SCHEMA_VERSION:
        print(f"{OK} schema versions match")
        return 0
    print(f"{BAD} schema versions differ — the shipper will not overwrite a different version without schema_upgrade")
    return 1


def _unship(doc: dict[str, Any]) -> dict[str, Any]:
    """Undo what the shipper adds at ship time (FR-41 skew) so the hash matches
    the document as it was written. ``event.ingested`` is already excluded."""
    audit = doc.get("audit")
    if not isinstance(audit, dict) or "clock_skew_ms" not in audit:
        return doc
    from .semantic.model import TAG_CLOCK_SKEW

    doc = dict(doc)
    doc["audit"] = {k: v for k, v in audit.items() if k != "clock_skew_ms"}
    tags = doc.get("tags")
    if isinstance(tags, list) and TAG_CLOCK_SKEW in tags:
        # ponytail: assumes the shipper's tag is the last "clock_skew" and no writer
        # stores tags == []; true for this package. Exact fix: exclude ship-time
        # fields in integrity.canonical().
        i = len(tags) - 1 - tags[::-1].index(TAG_CLOCK_SKEW)
        kept = tags[:i] + tags[i + 1:]
        if kept:
            doc["tags"] = kept
        else:
            del doc["tags"]
    return doc


def _es_chain_docs(client: Any, index: str) -> list[dict[str, Any]]:
    """Every document carrying ``audit.integrity``, paged with ``search_after``."""
    docs: list[dict[str, Any]] = []
    after: list[Any] | None = None
    while True:
        body: dict[str, Any] = {
            "size": _PAGE,
            "query": {"exists": {"field": "audit.integrity.chain"}},
            "sort": [{"audit.integrity.chain": "asc"}, {"audit.integrity.seq": "asc"}],
        }
        if after is not None:
            body["search_after"] = after
        response = client.post(f"/{index}/_search", json=body)
        if response.status_code == 404:
            return docs
        if response.status_code >= 300:
            raise RuntimeError(f"HTTP {response.status_code}: {response.text[:200]}")
        hits = response.json().get("hits", {}).get("hits", [])
        docs += [h.get("_source", {}) for h in hits]
        if len(hits) < _PAGE:
            return docs
        after = hits[-1].get("sort")
        if not after:
            return docs


def _verify_chain(config: AuditConfig, args: argparse.Namespace) -> int:
    try:
        from .semantic.integrity import verify
    except ImportError:
        print(f"{BAD} semantic.integrity is not available in this build")
        return 2
    if args.from_files:
        docs = [d for _, d in _file_docs(_service_files(config)) if isinstance(d, dict)]
        source = str(config.log_dir)
    else:
        client = _client(config)
        try:
            docs = _es_chain_docs(client, config.index_name)
        except Exception as exc:  # noqa: BLE001
            print(f"{BAD} cannot read {config.index_name}: {exc}")
            return 1
        finally:
            client.close()
        source = config.index_name
    try:
        report = verify((_unship(d) for d in docs), require_genesis=args.require_genesis)
    except NotImplementedError:
        print(f"{BAD} semantic.integrity.verify is not implemented in this build")
        return 2
    print(f"source    : {source}")
    print(f"chains    : {report.chains}")
    print(f"documents : {report.documents}")
    for line in getattr(report, "truncated", [])[:50]:
        print(f"  TRUNCATED {line} (older records rotated or deleted)")
    for line in report.broken[:50]:
        print(f"  BROKEN   {line}")
    if len(report.broken) > 50:
        print(f"  ... and {len(report.broken) - 50} more")
    if report.documents == 0:
        print(f"{WARN} no document carries audit.integrity — is AUDIT_INTEGRITY_ENABLED on?")
        return 0
    if report.ok:
        print(f"{OK} every chain verifies")
        return 0
    print(f"{BAD} {len(report.broken)} break(s) in the hash chain")
    return 1


def _ops_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m audit_logging.check")
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("reconcile", help="records on disk vs indexed, per process (NFR-7)")
    rec.add_argument("--tolerance", type=int, default=0, metavar="N",
                     help="missing records per process allowed (the unshipped tail)")
    sub.add_parser("version", help="installed template schema_version vs this package (FR-48)")
    ver = sub.add_parser("verify-chain", help="verify the per-process hash chains")
    ver.add_argument("--from-files", action="store_true", help="read the JSONL files, not Elasticsearch")
    ver.add_argument("--require-genesis", action="store_true",
                     help="a chain that does not start at seq 1 is broken (default: rotation/retention, info)")
    args = parser.parse_args(argv)
    try:
        config = AuditConfig()  # type: ignore[call-arg]
    except Exception as exc:  # noqa: BLE001
        print(f"{BAD} configuration is invalid: {exc}")
        return 1
    if not (args.command == "verify-chain" and args.from_files) and not config.elasticsearch_url:
        print(f"{BAD} AUDIT_ELASTICSEARCH_URL is not set")
        return 1
    if args.command == "reconcile":
        return _reconcile(config, args)
    if args.command == "version":
        return _version(config)
    return _verify_chain(config, args)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("coverage", "docs"):
        return _semantic_main(argv)
    if argv and argv[0] in _OPS:
        return _ops_main(argv)
    parser = argparse.ArgumentParser(prog="python -m audit_logging.check")
    parser.add_argument(
        "--leak",
        metavar="STRING",
        help="search every field for a value that must not be there",
    )
    args = parser.parse_args(argv)

    try:
        config = AuditConfig()  # type: ignore[call-arg]
    except Exception as exc:  # noqa: BLE001
        print(f"{BAD} configuration is invalid: {exc}")
        return 1

    failures = 0
    print(f"service : {config.service_name}")
    print(f"index   : {config.index_name}")
    print(f"log dir : {config.log_dir}")
    print()

    # --- the local half: is the app actually writing? ---------------------
    log_dir = Path(config.log_dir)
    if not log_dir.is_dir():
        print(f"{BAD} log directory does not exist")
        failures += 1
    else:
        files = sorted(log_dir.glob("*.jsonl"))
        lines = sum(
            sum(1 for line in f.open() if line.strip()) for f in files
        ) if files else 0
        if not files:
            print(f"{WARN} no .jsonl files yet — has the app served a request?")
        else:
            print(f"{OK} {len(files)} file(s) on disk, {lines} record(s) written")

    if not config.elasticsearch_url:
        print()
        print(f"{WARN} AUDIT_ELASTICSEARCH_URL is 'none', so nothing is checked in")
        print("       Elasticsearch. That is correct if you ship with Filebeat.")
        return 1 if failures else 0

    # --- the remote half --------------------------------------------------
    print()
    client = _client(config)
    try:
        health = client.get("/_cluster/health")
        if health.status_code >= 300:
            print(f"{BAD} elasticsearch answered HTTP {health.status_code}")
            return 1
        print(f"{OK} elasticsearch reachable, cluster is {health.json()['status']}")
    except Exception as exc:  # noqa: BLE001
        print(f"{BAD} cannot reach {config.elasticsearch_url}: {exc}")
        return 1

    count = client.get(f"/{config.index_name}/_count")
    if count.status_code >= 300:
        print(f"{BAD} index {config.index_name} does not exist yet")
        print("       nothing has been shipped — check the app's logs for shipper warnings")
        return 1
    print(f"{OK} {count.json()['count']} document(s) indexed")

    # The one that actually matters.
    mapping = client.get(f"/{config.index_name}/_mapping").json()
    for name, body in mapping.items():
        m = body.get("mappings", {})
        dynamic = str(m.get("dynamic", "")).lower()
        fields = _count_fields(m.get("properties", {}))
        if dynamic == "false":
            print(f"{OK} mapping is dynamic:false — the template is in force ({fields} fields)")
        else:
            failures += 1
            print(f"{BAD} mapping is dynamic={m.get('dynamic')!r}, NOT false")
            print(f"       {name} was created without the index template.")
            print("       It will keep working until the field count explodes, and")
            print("       only a reindex fixes it. Delete the data stream and let")
            print("       the shipper recreate it, before this index grows.")
        break

    if args.leak:
        hits = client.post(
            f"/{config.index_name}/_search",
            json={"size": 0, "query": {"query_string": {"query": f'"{args.leak}"'}}},
        ).json()
        n = hits.get("hits", {}).get("total", {}).get("value", 0)
        if n:
            failures += 1
            print(f"{BAD} {n} document(s) contain {args.leak!r}")
            print("       if it is not in url.path or a parse-failure body_raw,")
            print("       add the key to AUDIT_EXTRA_REDACT_KEYS")
        else:
            print(f"{OK} {args.leak!r} appears in no document")

    client.close()
    print()
    print("all checks passed" if not failures else f"{failures} check(s) FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
