"""Round 2 (PLAN §17) end to end: a FastAPI app behind ``AuditMiddleware`` (agent N).

identify / query / session / trace / trusted proxies with a NullSink, then the
writer-thread features (integrity chain, slow enricher) through a real FileSink
the middleware builds itself, read back from disk.
"""

from __future__ import annotations

import json
import logging
import signal
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from audit_logging import AuditConfig, AuditMiddleware, NullSink, QueryClause, Target, audit, audited
from audit_logging.metrics import InMemoryMetrics
from audit_logging.semantic import integrity, runtime
from audit_logging.semantic.context import close_bag, current_bag, open_bag
from audit_logging.semantic.model import TAG_ENRICH_TIMEOUT
from audit_logging.semantic.schema import ENRICHED_PATHS
from audit_logging.templates import index_template_for

ACTOR = {"id": "u7", "name": "sardor", "full_name": "Sardor Karimov", "roles": ["Admin"]}


def build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/persons/{pinpp}")
    @audited("search.person.viewed", uz="{actor} «{target}» shaxsini ko'rdi",
             target=Target("pinpp", id="path.pinpp"), category="read", risk="high")
    async def person(pinpp: str) -> dict[str, bool]:
        audit.identify(msisdn="90 123 45 67", passport="aa 1234567", imei="bogus")
        return {"ok": True}

    @app.get("/search")
    @audited("search.person.searched", uz="{actor} shaxslarni qidirdi", category="search", risk="high")
    def search() -> dict[str, bool]:  # sync: threadpool, copied context
        audit.query(
            [("region", "=", "Toshkent"), ("age", "between", [18, 30]), ("password", "=", "x"),
             ("junk",)],
            datasource="pg", tables=["persons"], labels={"region": "Viloyat", "age": "Yosh"},
        )
        return {"ok": True}

    @app.get("/users/{user_id}")
    @audited("admin.user.viewed", uz="{actor} «{target}» foydalanuvchini ko'rdi",
             target=Target("user", id="path.user_id"), category="read", risk="normal")
    async def user(user_id: int) -> dict[str, bool]:
        return {"ok": True}

    return app


def build_config(**overrides: Any) -> AuditConfig:
    values: dict[str, Any] = {
        "service_name": "users-adminka", "dataset": "users_adminka",
        "elasticsearch_url": None, "environment": "test",
        "user_resolver": lambda scope: dict(ACTOR),
    }
    values.update(overrides)
    return AuditConfig(**values)


@pytest.fixture(autouse=True)
def _no_active_sink_leaks() -> Any:
    yield
    runtime.clear_active()


async def call(config: AuditConfig, path: str, headers: dict[str, str] | None = None) -> tuple[dict[str, Any], httpx.Response]:
    sink = NullSink()
    app = AuditMiddleware(build_app(), config=config, sink=sink, metrics=InMemoryMetrics())
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        response = await client.get(path, headers=headers or {})
    return sink.only, response


def leaves(obj: Any, prefix: str = "") -> set[str]:
    if isinstance(obj, dict) and obj:
        return set().union(*(leaves(v, f"{prefix}.{k}" if prefix else k) for k, v in obj.items()))
    return {prefix}


# --- identify / TargetSpec promotion ----------------------------------------


async def test_identify_and_targetspec_promotion() -> None:
    doc, _ = await call(build_config(), "/persons/3210-1801-2345-67")
    target = doc["audit"]["target"]
    assert target["type"] == "pinpp" and target["id"] == "3210-1801-2345-67"
    assert target["pinpp"] == "32101801234567"          # promoted from path.pinpp
    assert target["msisdn"] == "+998901234567"
    assert target["passport"] == "AA1234567"
    assert "imei" not in target
    assert doc["audit"]["detail"]["rejected_identifiers"] == ["imei"]


async def test_invalid_promoted_id_is_not_stored() -> None:
    doc, _ = await call(build_config(), "/persons/123")
    assert "pinpp" not in doc["audit"]["target"]


def test_facade_is_a_noop_outside_a_request() -> None:
    audit.identify(pinpp="32101801234567")
    audit.query([("a", "=", 1)])


def test_identify_accumulates_and_query_replaces() -> None:
    token = open_bag()
    try:
        audit.identify(pinpp="32101801234567", imei="x")
        audit.identify(imei="y", msisdn="+998901234567")
        audit.query([("a", "=", 1)], text="custom", tables="t1")
        audit.query([QueryClause("b", "gt", "2")])
        bag = current_bag()
        assert bag is not None
        assert bag.identifiers == {"pinpp": "32101801234567", "msisdn": "+998901234567"}
        assert bag.detail["rejected_identifiers"] == ["imei"]
        assert [c.field for c in bag.query] == ["b"] and bag.query_text == "b > 2"
        assert bag.query_tables == []
    finally:
        close_bag(token)


# --- query --------------------------------------------------------------------


async def test_query_breakdown() -> None:
    doc, _ = await call(build_config(), "/search")
    q = doc["audit"]["query"]
    assert q["clause_count"] == 3 and q["datasource"] == "pg" and q["tables"] == ["persons"]
    first = q["normalized"][0]
    assert first == {"field": "region", "label": "Viloyat", "operator": "eq", "value": "Toshkent",
                     "logic": "and", "group": 0}
    assert q["normalized"][1]["operator"] == "between"
    assert q["normalized"][2]["value"] == "[REDACTED]"   # redact keys apply to query values
    assert q["text"].startswith("Viloyat = Toshkent VA Yosh")


# --- session / trace ------------------------------------------------------------


async def test_session_and_trace_headers() -> None:
    doc, response = await call(build_config(), "/users/2",
                               {"X-Session-Id": "s-1", "X-Trace-Id": "t-1", "X-Request-ID": "r-1"})
    assert doc["audit"]["session"] == {"id": "s-1"}
    assert doc["trace"]["id"] == "t-1"
    assert response.headers["x-request-id"] == "r-1"   # 0.1 echo untouched


async def test_without_x_trace_id_the_0_1_request_id_stays() -> None:
    doc, response = await call(build_config(), "/users/2", {"X-Request-ID": "r-1", "X-Session-Id": "bad id"})
    assert doc["trace"]["id"] == "r-1" == response.headers["x-request-id"]
    assert "session" not in doc["audit"]


# --- trusted proxies ------------------------------------------------------------


async def test_no_trusted_proxies_keeps_the_peer() -> None:
    doc, _ = await call(build_config(), "/users/2", {"X-Forwarded-For": "203.0.113.9"})
    assert doc["client"]["ip"] == "127.0.0.1"
    assert doc["audit"]["client"] == {"ip_source": "peer"}


async def test_trusted_proxy_picks_the_forwarded_client() -> None:
    config = build_config(trusted_proxies="127.0.0.1, 10.0.0.0/8")
    doc, _ = await call(config, "/users/2", {"X-Forwarded-For": "203.0.113.9, 10.0.0.5"})
    assert doc["client"] == {"ip": "203.0.113.9"}
    assert doc["audit"]["client"] == {"ip_source": "x_forwarded_for",
                                      "forwarded_chain": "203.0.113.9, 10.0.0.5"}


def test_bad_trusted_proxy_fails_construction() -> None:
    with pytest.raises(ValueError):
        build_config(trusted_proxies="10.0.0.0/8, nope")


async def test_round2_fields_are_enriched_paths_and_mapped() -> None:
    config = build_config(trusted_proxies="127.0.0.1")
    root = index_template_for("demo")["template"]["mappings"]
    headers = {"X-Session-Id": "s", "X-Trace-Id": "t", "X-Forwarded-For": "203.0.113.9"}
    seen: set[str] = set()
    for path in ("/persons/32101801234567", "/search"):
        doc, _ = await call(config, path, headers)
        for leaf in leaves(doc):
            node: Any = root
            for part in leaf.split("."):
                if "properties" not in node or node.get("type") == "nested":
                    break
                node = node["properties"].get(part)
                assert node is not None, (path, leaf)
        seen |= {p for p in ENRICHED_PATHS if any(x == p or x.startswith(p + ".") for x in leaves(doc))}
    assert {"audit.target.pinpp", "audit.target.msisdn", "audit.target.passport", "audit.session.id",
            "audit.client.ip_source", "audit.client.forwarded_chain", "client.ip", "trace.id",
            "audit.query.normalized", "audit.query.text", "audit.query.datasource",
            "audit.query.tables", "audit.query.clause_count"} <= seen


# --- writer thread: integrity + enricher, through a real FileSink -----------------


async def run_file(config: AuditConfig, paths: list[str]) -> tuple[list[dict[str, Any]], InMemoryMetrics]:
    metrics = InMemoryMetrics()
    app = AuditMiddleware(build_app(), config=config, metrics=metrics)  # builds its own FileSink
    sink: Any = app._sink
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as client:
        for path in paths:
            await client.get(path)
    await app._close_sink()
    lines = sink.path.read_text("utf-8").splitlines()
    return [json.loads(line) for line in lines], metrics


async def test_integrity_chain_written_and_verifiable(tmp_path: Path) -> None:
    config = build_config(log_dir=tmp_path, integrity_enabled=True)
    docs, _ = await run_file(config, ["/users/1", "/users/2", "/search"])
    assert [d["audit"]["integrity"]["seq"] for d in docs] == [1, 2, 3]
    assert integrity.verify(docs).ok
    docs[1]["audit"]["target"]["id"] = "999"
    assert not integrity.verify(docs).ok


async def test_integrity_off_by_default(tmp_path: Path) -> None:
    docs, _ = await run_file(build_config(log_dir=tmp_path), ["/users/1"])
    assert "integrity" not in docs[0]["audit"]


async def test_enricher_patches_label_and_slow_one_times_out(tmp_path: Path) -> None:
    def lookup(doc: dict[str, Any]) -> dict[str, Any] | None:
        if doc["audit"]["target"]["id"] == "2":
            time.sleep(0.5)
        return {"audit.target.label": "Aliyev Vali"}

    config = build_config(log_dir=tmp_path, enricher=lookup, enrich_timeout_ms=50, integrity_enabled=True)
    docs, _ = await run_file(config, ["/users/1", "/users/2"])
    fast, slow = docs
    assert fast["audit"]["target"]["label"] == "Aliyev Vali"
    assert "Aliyev Vali" in fast["message"]
    assert TAG_ENRICH_TIMEOUT in slow["tags"] and "label" not in slow["audit"]["target"]
    assert integrity.verify(docs).ok   # stamped after enrichment


# --- startup ------------------------------------------------------------------------


async def test_sigterm_warning_after_lifespan_startup(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(signal, "getsignal", lambda sig: signal.SIG_DFL)

    async def app(scope: Any, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            else:
                await send({"type": "lifespan.shutdown.complete"})
                return

    inbox = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]

    async def receive() -> dict[str, Any]:
        return inbox.pop(0)

    async def send(message: Any) -> None:
        return None

    middleware = AuditMiddleware(app, config=build_config(log_dir=tmp_path), sink=NullSink())
    with caplog.at_level(logging.WARNING, logger="audit_logging"):
        await middleware({"type": "lifespan"}, receive, send)
    assert sum("SIGTERM is not handled by Python" in r.getMessage() for r in caplog.records) == 1
