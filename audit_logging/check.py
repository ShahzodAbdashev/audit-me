"""``python -m audit_logging.check`` — is this actually working?

Reads the same ``AUDIT_*`` environment your application uses, so it checks the
configuration you really deployed rather than one retyped into a command line.

    python -m audit_logging.check
    python -m audit_logging.check --leak "a-real-secret"

Documents arriving is necessary but not sufficient, which is the reason this
exists as code rather than as a paragraph. An index template that failed to
install still accepts documents happily; the field count still looks fine,
because a dynamic mapping is under the limit until it suddenly is not. So the
check that matters is ``dynamic: false``, and it is easy to never think to run.
"""

from __future__ import annotations

import argparse
import json
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


def main(argv: list[str] | None = None) -> int:
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
        print(f"{WARN} AUDIT_ELASTICSEARCH_URL is not set, so nothing is checked in")
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
