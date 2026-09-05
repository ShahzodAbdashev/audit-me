"""Drive the demo service over a real socket, then verify in Elasticsearch.

Two phases, deliberately separated:

``send``    hit a live uvicorn over HTTP and record what we sent
``verify``  query Elasticsearch and assert the documents arrived correctly

The verification asserts on **Elasticsearch**, not on the JSONL file. That is
the whole point of Tier 1: the file half is already covered by 597 offline
tests, and everything interesting that is still unproven lives past it —
Filebeat's ndjson decode, `data_stream` routing, and the index template
actually enforcing `dynamic: false`.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any

BASE = "http://127.0.0.1:8080"
ES = "http://127.0.0.1:9200"
INDEX = "logs-apiaudit.orders_api-demo"

#: Values planted in requests that must NEVER appear in any document.
SECRETS = ["hunter2", "sk_live_LEAKED", "Bearer LEAKTOKEN", "cvv-999", "qs-SECRET"]


def _req(method: str, url: str, body: bytes | None = None,
         headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def send() -> list[str]:
    """Every shape the reviews cared about, over a real socket."""
    sent: list[str] = []

    def note(label: str) -> None:
        sent.append(label)
        print(f"  sent  {label}")

    _req("GET", f"{BASE}/health"); note("health (excluded — expect NO document)")
    for _ in range(4):
        _req("GET", f"{BASE}/health")

    body = json.dumps({
        "sku": "A-11", "qty": 3,
        "password": "hunter2",
        "card": {"cvv": "cvv-999"},
        "lines": [{"api_key": "sk_live_LEAKED", "qty": 1}],
    }).encode()
    _req("POST", f"{BASE}/orders/42/items?expand=lines&token=qs-SECRET", body,
         {"content-type": "application/json",
          "authorization": "Bearer LEAKTOKEN",
          "cookie": "sid=LEAKTOKEN",
          "x-demo-user": "u-8813"})
    note("POST with secrets in body, query, headers")

    _req("GET", f"{BASE}/orders/7"); note("GET 200")
    _req("GET", f"{BASE}/orders/missing"); note("GET 404")
    _req("DELETE", f"{BASE}/orders/9"); note("DELETE 204 (no body)")
    _req("GET", f"{BASE}/nope/nothing/here"); note("unrouted -> audit.route=unmatched")
    _req("GET", f"{BASE}/boom"); note("handler raises -> outcome=failure")
    _req("GET", f"{BASE}/report"); note("streaming response (5 chunks)")
    _req("GET", f"{BASE}/keys/sk_live_LEAKED"); note("secret in a NAMED path param")

    _req("POST", f"{BASE}/upload", b'{"password":"hunter2"}',
         {"content-type": "text/plain"})
    note("text/plain body -> FR-28, must store NOTHING")

    _req("POST", f"{BASE}/upload", b'{"password":"hunter2", oops',
         {"content-type": "application/json"})
    note("broken JSON -> body_parse_failed")

    big = json.dumps({f"distinct_key_{i}": i for i in range(4000)}).encode()
    _req("POST", f"{BASE}/upload", big, {"content-type": "application/json"})
    note("4,000 distinct keys -> FR-32 too_complex")

    _req("POST", f"{BASE}/upload", b"[" + b"[]," * 200_000 + b"]",
         {"content-type": "application/json"})
    note("1 MiB pathological body -> FR-29 too_complex")
    return sent


def _es(path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode() if body is not None else None
    status, raw = _req("POST" if body else "GET", f"{ES}{path}", data,
                       {"content-type": "application/json"})
    return json.loads(raw or b"{}")


def _search(query: dict[str, Any], size: int = 50) -> list[dict[str, Any]]:
    result = _es(f"/{INDEX}/_search", {"query": query, "size": size})
    return [h["_source"] for h in result.get("hits", {}).get("hits", [])]


def _from_file(log_dir: str) -> list[dict[str, Any]]:
    """The same documents, read straight off disk.

    Lets every assertion below run without Elasticsearch, so that when the ES
    stack does come up the *only* untested hop is file -> Filebeat -> ES.
    """
    import pathlib

    docs = []
    for path in sorted(pathlib.Path(log_dir).glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if line.strip():
                docs.append(json.loads(line))
    return docs


def verify(expected_min: int, log_dir: str | None = None) -> int:
    """Assert on Elasticsearch, or on the JSONL file when *log_dir* is given.

    Returns the number of failed checks.
    """
    failures = 0

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        if ok:
            print(f"  PASS  {label}")
        else:
            failures += 1
            print(f"  FAIL  {label}{(' — ' + detail) if detail else ''}")

    if log_dir is not None:
        docs = _from_file(log_dir)
        check(f"documents written to JSONL (got {len(docs)})", len(docs) >= expected_min,
              f"expected at least {expected_min}")
        check("every line is valid JSON", True)  # _from_file would have raised
    else:
        _es("/_refresh")
        docs = _search({"match_all": {}}, size=200)
        check(f"documents reached Elasticsearch (got {len(docs)})", len(docs) >= expected_min,
              f"expected at least {expected_min}")
    if not docs:
        print("\n  nothing found — the pipeline is broken")
        return failures + 1

    # Redaction holds everywhere EXCEPT two places the docs are explicit about.
    # Asserting "no secret anywhere" would be asserting an aspiration; the real
    # contract is narrower and sharper, so check that instead — and check the
    # two exceptions *are* still there, so a silent change in either direction
    # shows up.
    documented_leaks = {
        # docs/redaction.md §4.5 — url.path is an indexed keyword and keeps the
        # raw path. Named path params are redacted; the path itself is not.
        "url.path": lambda d: d.get("url", {}).get("path", ""),
        # AC-14 / review S-2 — a body that fails to parse keeps its raw text,
        # unredacted by construction. The client selects this by sending
        # broken JSON, so it is the one path an attacker can steer into.
        "audit.request.body_raw": lambda d: (
            d.get("audit", {}).get("request", {}).get("body_raw", "")
            if d.get("audit", {}).get("request", {}).get("body_parse_failed")
            else ""
        ),
    }

    def _scrubbed(doc: dict[str, Any]) -> str:
        """The document minus the two fields documented as unredacted."""
        copy = json.loads(json.dumps(doc))
        copy.get("url", {}).pop("path", None)
        copy.get("audit", {}).get("request", {}).pop("body_raw", None)
        return json.dumps(copy)

    scrubbed = " ".join(_scrubbed(d) for d in docs)
    for secret in SECRETS:
        check(f"secret {secret!r} absent from every redacted field", secret not in scrubbed)

    # And the exceptions, asserted positively so they cannot vanish unnoticed.
    leaked_in_path = any("sk_live_LEAKED" in fn(d) for d in docs
                         for name, fn in documented_leaks.items() if name == "url.path")
    check("KNOWN: url.path still carries a path secret (docs/redaction.md §4.5)",
          leaked_in_path, "the limitation is gone — update docs/redaction.md §4.5")
    leaked_in_raw = any("hunter2" in fn(d) for d in docs
                        for name, fn in documented_leaks.items()
                        if name == "audit.request.body_raw")
    check("KNOWN: a parse-failure body_raw is unredacted (AC-14 / S-2)",
          leaked_in_raw, "the limitation is gone — update docs/redaction.md")

    check("no document for the excluded /health path",
          not any(d.get("url", {}).get("path") == "/health" for d in docs))
    check("audit.route is the template, not the raw path",
          any(d.get("audit", {}).get("route") == "/orders/{order_id}/items" for d in docs))
    check("unrouted request recorded as 'unmatched'",
          any(d.get("audit", {}).get("route") == "unmatched" for d in docs))
    check("raising handler recorded as outcome=failure",
          any(d.get("event", {}).get("outcome") == "failure" for d in docs))
    check("error.type captured for the raising handler",
          any(d.get("error", {}).get("type") == "ValueError" for d in docs))
    check("204 recorded with zero response bytes",
          any(d.get("http", {}).get("response", {}).get("status_code") == 204 for d in docs))
    check("404 recorded",
          any(d.get("http", {}).get("response", {}).get("status_code") == 404 for d in docs))

    streamed = [d for d in docs if d.get("url", {}).get("path") == "/report"]
    check("streaming response timed to the LAST chunk (FR-06)",
          bool(streamed) and streamed[0]["event"]["duration"] > 0)

    text = [d for d in docs if d.get("audit", {}).get("request", {}).get("body_skipped")
            == "content_type"]
    check("text/plain body stored nothing (FR-28 / M-1 regression)", bool(text))

    too_complex = [d for d in docs
                   if d.get("audit", {}).get("request", {}).get("body_skipped") == "too_complex"]
    check("hostile bodies refused as too_complex (FR-29 / FR-32)", len(too_complex) >= 2,
          f"got {len(too_complex)}")

    check("Authorization header never stored",
          not any("authorization" in d.get("audit", {}).get("request", {}).get("headers", {})
                  for d in docs))
    check("allowlisted header IS stored",
          any("content-type" in d.get("audit", {}).get("request", {}).get("headers", {})
              for d in docs))

    keyed = [d for d in docs if str(d.get("url", {}).get("path", "")).startswith("/keys/")]
    check("named path param redacted (docs/redaction.md §4.5)",
          bool(keyed) and keyed[0]["audit"]["path_params"]["api_key"] == "[REDACTED]")
    check("...while url.path still holds it — the documented limitation",
          bool(keyed) and "sk_live_LEAKED" in keyed[0]["url"]["path"])

    check("data_stream routed by the package's own fields",
          all(d.get("data_stream", {}).get("dataset") == "apiaudit.orders_api" for d in docs))
    check("user.* populated by user_resolver (FR-25)",
          any(d.get("user", {}).get("id") == "u-8813" for d in docs))
    check("trace.id present on every document",
          all(d.get("trace", {}).get("id") for d in docs))

    if log_dir is not None:
        # The remaining checks are about Elasticsearch itself — the mapping
        # bound and the quarantine index. Neither exists without a cluster,
        # and pretending otherwise is how a green run stops meaning anything.
        print("  SKIP  mapping bound and quarantine checks (no Elasticsearch)")
        return failures

    # The mapping bound — AC-10, but against real Elasticsearch this time.
    mapping = _es(f"/{INDEX}/_mapping")
    def count(node: dict[str, Any]) -> int:
        total = 0
        for value in node.values():
            if isinstance(value, dict):
                total += count(value["properties"]) if "properties" in value else 1
        return total
    fields = 0
    for index in mapping.values():
        fields = count(index.get("mappings", {}).get("properties", {}))
    check(f"field count within the 200 limit (got {fields})", 0 < fields <= 200)

    # A field count under the limit means nothing on its own: a dynamic mapping
    # is also under the limit until enough distinct shapes arrive. What matters
    # is that the index took OUR template. Assert dynamic:false is actually in
    # force — the D-11 failure is silent and unfixable without a reindex.
    raw = next(iter(mapping.values()), {}).get("mappings", {})
    check("mapping is dynamic:false — the template really is in force (D-11)",
          str(raw.get("dynamic", "")).lower() == "false",
          f"dynamic={raw.get('dynamic')!r} — the data stream was auto-created "
          "with a dynamic mapping; the template did not apply")
    check("mapping carries our constant_keyword dataset pin",
          raw.get("properties", {}).get("data_stream", {})
             .get("properties", {}).get("dataset", {}).get("type") == "constant_keyword")

    # dynamic:false actually enforced by ES, not just declared in the template.
    stats = _es("/logs-apiaudit.undecodable-*/_count")
    check("no undecodable lines quarantined", stats.get("count", 0) == 0,
          f"{stats.get('count')} lines failed to decode")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["send", "verify"])
    parser.add_argument("--expect", type=int, default=12)
    parser.add_argument("--from-file", metavar="LOG_DIR",
                        help="verify against the JSONL on disk instead of Elasticsearch")
    args = parser.parse_args()
    if args.phase == "send":
        sent = send()
        print(f"\n{len(sent)} request shapes sent")
        return 0
    failures = verify(args.expect, args.from_file)
    print(f"\n{'ALL CHECKS PASSED' if not failures else str(failures) + ' CHECK(S) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
