"""Look at what actually landed in Elasticsearch.

    ./.venv/bin/python demo/query.py                  health + document counts
    ./.venv/bin/python demo/query.py recent [n]       n most recent records, one line each
    ./.venv/bin/python demo/query.py doc [n]          full JSON of the n most recent
    ./.venv/bin/python demo/query.py errors           only failed requests
    ./.venv/bin/python demo/query.py slow [ms]        requests slower than N ms
    ./.venv/bin/python demo/query.py routes           count + p95 latency by route
    ./.venv/bin/python demo/query.py trace <id>       one request by X-Request-ID
    ./.venv/bin/python demo/query.py leaks <string>   search every field for a secret
    ./.venv/bin/python demo/query.py mapping          prove dynamic:false is in force

Set ES_URL to point somewhere other than the local test stack.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

ES = os.environ.get("ES_URL", "http://127.0.0.1:9200")
INDEX = "logs-apiaudit.*-*"


def call(path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{ES}/{path}", data=data,
                                 method="POST" if data else "GET")
    req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read() or b"{}")
    except urllib.error.URLError as exc:
        print(f"cannot reach Elasticsearch at {ES}: {exc.reason}")
        print("is the stack up?  sg docker -c 'docker compose -f "
              "tests/integration/docker-compose.test.yml up -d'")
        raise SystemExit(2)


def hits(body: dict[str, Any]) -> list[dict[str, Any]]:
    return [h["_source"] for h in call(f"{INDEX}/_search", body).get("hits", {}).get("hits", [])]


def ms(doc: dict[str, Any]) -> float:
    return doc.get("event", {}).get("duration", 0) / 1e6


def status() -> None:
    health = call("_cluster/health")
    if not health:
        print("no response"); return
    print(f"cluster : {health.get('status')}  ({health.get('number_of_nodes')} node)")
    total = call(f"{INDEX}/_count").get("count", 0)
    print(f"audit documents indexed: {total}\n")
    agg = call(f"{INDEX}/_search", {"size": 0, "aggs": {
        "svc": {"terms": {"field": "service.name", "size": 20}}}})
    print(f"{'documents':>10}  service")
    for b in agg.get("aggregations", {}).get("svc", {}).get("buckets", []):
        print(f"{b['doc_count']:>10}  {b['key']}")


def recent(n: int = 10) -> None:
    print(f"{'time':>12}  {'method':6} {'code':>4} {'latency':>9}  route")
    for d in hits({"size": n, "sort": [{"@timestamp": "desc"}]}):
        http = d.get("http", {})
        print(f"{d['@timestamp'][11:23]:>12}  "
              f"{http.get('request', {}).get('method', '?'):6} "
              f"{http.get('response', {}).get('status_code', 0):>4} "
              f"{ms(d):8.2f}ms  {d.get('audit', {}).get('route', '?')}")


def doc(n: int = 1) -> None:
    for d in hits({"size": n, "sort": [{"@timestamp": "desc"}]}):
        print(json.dumps(d, indent=2))


def errors() -> None:
    found = hits({"size": 20, "sort": [{"@timestamp": "desc"}], "query": {"bool": {"should": [
        {"range": {"http.response.status_code": {"gte": 500}}},
        {"term": {"event.outcome": "failure"}}]}}})
    print(f"{len(found)} failing request(s)")
    for d in found:
        err = d.get("error", {})
        print(f"  {d['@timestamp'][11:23]}  {d.get('audit', {}).get('route')}  "
              f"{err.get('type', '-')}: {err.get('message', '')[:70]}")


def slow(threshold_ms: int = 100) -> None:
    found = hits({"size": 20, "sort": [{"event.duration": "desc"}],
                  "query": {"range": {"event.duration": {"gte": threshold_ms * 1_000_000}}}})
    print(f"{len(found)} request(s) slower than {threshold_ms} ms")
    for d in found:
        print(f"  {ms(d):9.2f}ms  {d.get('audit', {}).get('route')}")


def routes() -> None:
    agg = call(f"{INDEX}/_search", {"size": 0, "aggs": {"r": {
        "terms": {"field": "audit.route", "size": 25},
        "aggs": {"p95": {"percentiles": {"field": "event.duration", "percents": [95]}}}}}})
    print(f"{'count':>8}  {'p95':>9}  route")
    for b in agg.get("aggregations", {}).get("r", {}).get("buckets", []):
        p95 = next(iter(b["p95"]["values"].values())) or 0
        print(f"{b['doc_count']:>8}  {p95 / 1e6:7.2f}ms  {b['key']}")


def trace(trace_id: str) -> None:
    found = hits({"query": {"term": {"trace.id": trace_id}}})
    print(json.dumps(found[0], indent=2) if found else "no document with that trace.id")


def leaks(needle: str) -> None:
    n = call(f"{INDEX}/_search", {"size": 0, "query": {
        "query_string": {"query": f'"{needle}"'}}}).get("hits", {}).get("total", {}).get("value", 0)
    print(f'{n} document(s) contain "{needle}"' + ("   <-- INVESTIGATE" if n else "   (clean)"))
    print("note: url.path and a parse-failure body_raw are documented as unredacted")
    print("      (docs/redaction.md §4.5 and AC-14) — a hit in those two is expected.")


def mapping() -> None:
    def count(props: dict[str, Any]) -> int:
        total = 0
        for value in props.values():
            total += count(value["properties"]) if isinstance(value, dict) and "properties" in value else 1
        return total

    for name, body in call(f"{INDEX}/_mapping").items():
        m = body["mappings"]
        dyn = m.get("dynamic")
        ok = "OK" if str(dyn).lower() == "false" else "WRONG — the template did not apply"
        print(f"{name}\n  dynamic : {dyn!r}   {ok}")
        print(f"  fields  : {count(m.get('properties', {}))} of a 200 limit")
        return


COMMANDS = {"status": status, "recent": recent, "doc": doc, "errors": errors,
            "slow": slow, "routes": routes, "trace": trace, "leaks": leaks,
            "mapping": mapping}


def main() -> int:
    argv = sys.argv[1:] or ["status"]
    name, args = argv[0], argv[1:]
    fn = COMMANDS.get(name)
    if fn is None:
        print(__doc__)
        return 1
    typed = [int(a) if a.isdigit() else a for a in args]
    fn(*typed)  # type: ignore[operator]
    return 0


if __name__ == "__main__":
    sys.exit(main())
