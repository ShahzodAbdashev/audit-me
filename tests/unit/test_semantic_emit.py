"""audit.emit() / @audited_task (FR-56) and the capture() helper. Agent F."""

from __future__ import annotations

from collections.abc import Iterator
from contextvars import ContextVar, Token
from typing import Any

import pytest

from audit_logging.config import AuditConfig
from audit_logging.metrics import InMemoryMetrics
from audit_logging.semantic import audit, context, render, runtime
from audit_logging.semantic.emit import audited_task, emit
from audit_logging.semantic.model import AuditBag
from audit_logging.semantic.schema import ENRICHED_PATHS
from audit_logging.sinks.null_sink import NullSink
from audit_logging.testing import capture

_BASE = {
    "@timestamp", "event.kind", "event.category", "event.type", "event.outcome",
    "service.name", "service.version", "service.environment", "host.hostname",
    "process.pid", "data_stream.type", "data_stream.dataset", "data_stream.namespace",
    "error.type", "error.message",
}


def _leaves(doc: dict[str, Any], prefix: str = "") -> set[str]:
    out: set[str] = set()
    for k, v in doc.items():
        path = f"{prefix}{k}"
        if isinstance(v, dict) and path not in ("audit.detail", "audit.i18n.params"):
            out |= _leaves(v, path + ".")
        else:
            out.add(path)
    return out


@pytest.fixture(autouse=True)
def _no_render(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def boom(*a: Any, **k: Any) -> str:
        raise NotImplementedError

    monkeypatch.setattr(render, "render", boom)
    runtime.clear_active()
    yield
    runtime.clear_active()


@pytest.fixture
def active(config: AuditConfig) -> tuple[NullSink, InMemoryMetrics]:
    sink, metrics = NullSink(), InMemoryMetrics()
    runtime.set_active(sink, config, metrics)
    return sink, metrics


def test_FR_56_emit_writes_schema_v2_document(active: tuple[NullSink, InMemoryMetrics]) -> None:
    sink, _ = active
    ok = emit(
        "billing.invoice.sent",
        uz="{actor} «{target}» hisobini yubordi ({detail.channel})",
        category="write",
        risk="high",
        target={"type": "invoice", "id": "42", "label": "INV-42"},
        detail={"channel": "email", "password": "hunter2"},
        actor={"id": "u1", "name": "sardor", "full_name": "Sardor Karimov", "roles": ["Admin"],
               "verified": True, "source": "service"},
        count=3,
    )
    assert ok is True
    doc = sink.submitted[-1]
    assert doc["message"] == "Sardor Karimov «INV-42» hisobini yubordi (email)"
    assert doc["event"]["action"] == "billing.invoice.sent"
    assert doc["event"]["category"] == ["process"] and doc["event"]["outcome"] == "success"
    assert len(doc["event"]["id"]) == 32
    assert doc["service"]["name"] == "test-service"
    a = doc["audit"]
    assert (a["schema_version"], a["level"], a["result"], a["count"]) == ("2", "emit", "success", 3)
    assert a["target"] == {"type": "invoice", "id": "42", "label": "INV-42"}
    assert a["detail"]["password"] != "hunter2"
    assert a["i18n"]["key"] == "billing.invoice.sent"
    assert doc["user"]["full_name"] == "Sardor Karimov" and doc["user"]["verified"] is True
    assert "http" not in doc and "url" not in doc
    assert _leaves(doc) <= ENRICHED_PATHS | _BASE


def test_FR_56_emit_uses_render_when_available(
    active: tuple[NullSink, InMemoryMetrics], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(render, "render", lambda event, params, **k: f"R:{params['actor']}")
    assert emit("sys.job.ran", uz="{actor} ishga tushirdi", actor={"name": "bot"})
    assert active[0].submitted[-1]["message"] == "R:bot"


def test_FR_56_missing_values_render_brace_free(active: tuple[NullSink, InMemoryMetrics]) -> None:
    assert emit("sys.job.ran", uz="{actor} {target} {detail.x} tugatdi")
    assert "{" not in active[0].submitted[-1]["message"]
    assert "noma'lum" in active[0].submitted[-1]["message"]


def test_FR_56_no_active_sink_returns_false() -> None:
    assert emit("sys.job.ran", uz="ishladi") is False


@pytest.mark.parametrize(
    "kwargs",
    [
        {"code": "Bad Code", "uz": "x"},
        {"code": "sys.job.ran", "uz": ""},
        {"code": "sys.job.ran", "uz": "{nope}"},
        {"code": "sys.job.ran", "uz": "x", "category": "weird"},
        {"code": "sys.job.ran", "uz": "x", "result": "maybe"},
        {"code": "sys.job.ran", "uz": "x", "count": "3"},
    ],
)
def test_FR_56_invalid_is_dropped_and_counted(
    active: tuple[NullSink, InMemoryMetrics], kwargs: dict[str, Any]
) -> None:
    assert emit(**kwargs) is False
    assert active[0].submitted == []
    assert active[1].get("audit_emit_dropped_total") == 1
    assert active[1].get("audit_documents_lost_total") == 1  # FR-39


def test_FR_56_sink_refusal_is_counted(config: AuditConfig) -> None:
    class Full(NullSink):
        def submit(self, doc: dict[str, Any]) -> bool:
            return False

    metrics = InMemoryMetrics()
    runtime.set_active(Full(), config, metrics)
    assert emit("sys.job.ran", uz="x") is False
    assert metrics.get("audit_emit_dropped_total") == 1
    # the sink counts its own refusals as lost; emit must not count them twice
    assert metrics.get("audit_documents_lost_total") == 0


def test_FR_56_emit_attached_to_facade() -> None:
    assert getattr(audit, "emit") is emit
    assert getattr(audit, "task") is audited_task


# --- @audited_task ---------------------------------------------------------

_bag: ContextVar[AuditBag | None] = ContextVar("_bag", default=None)


@pytest.fixture
def bags(monkeypatch: pytest.MonkeyPatch) -> None:
    def open_bag() -> Token[AuditBag | None]:
        return _bag.set(AuditBag())

    monkeypatch.setattr(context, "open_bag", open_bag)
    monkeypatch.setattr(context, "current_bag", _bag.get)
    monkeypatch.setattr(context, "close_bag", _bag.reset)


def test_FR_56_task_sync_success_reads_bag(active: tuple[NullSink, InMemoryMetrics], bags: None) -> None:
    @audited_task("ownercheck.number.scored", uz="{target} baholandi", category="analysis")
    def score(n: str) -> int:
        bag = _bag.get()
        assert bag is not None
        bag.target_type, bag.target_id = "number", n
        bag.count = 7
        return 5

    assert score("998901234567") == 5
    doc = active[0].submitted[-1]
    assert doc["audit"]["result"] == "success"
    assert doc["audit"]["target"] == {"type": "number", "id": "998901234567"}
    assert doc["audit"]["count"] == 7
    assert doc["message"] == "998901234567 baholandi"
    assert _bag.get() is None


async def test_FR_56_task_async_failure_reraises(active: tuple[NullSink, InMemoryMetrics], bags: None) -> None:
    @audited_task("sys.sync.ran", uz="sinxronlash")
    async def job() -> None:
        raise RuntimeError("db down")

    with pytest.raises(RuntimeError):
        await job()
    doc = active[0].submitted[-1]
    assert doc["audit"]["result"] == "failure" and doc["event"]["outcome"] == "failure"
    assert doc["error"] == {"type": "RuntimeError", "message": "db down"}


def test_FR_56_task_without_bag_support_still_emits(active: tuple[NullSink, InMemoryMetrics]) -> None:
    # context.open_bag may be an unbuilt stub: the task must still run and emit.
    @audited_task("sys.job.ran", uz="ishladi")
    def job() -> str:
        return "ok"

    assert job() == "ok"
    assert active[0].submitted[-1]["event"]["action"] == "sys.job.ran"


def test_FR_56_task_bad_declaration_fails_at_import() -> None:
    with pytest.raises(ValueError):
        audited_task("nope", uz="x")


# --- capture() -------------------------------------------------------------


def test_FR_56_capture_collects_and_restores(active: tuple[NullSink, InMemoryMetrics]) -> None:
    before = runtime.get_active()
    with capture() as rec:
        assert not rec.records
        emit("sys.job.ran", uz="ishladi")
        assert rec.last is not None and rec.last["event"]["action"] == "sys.job.ran"
        assert len(rec.records) == 1
    assert runtime.get_active() == before
    assert active[0].submitted == []


def test_FR_56_capture_without_previous_clears() -> None:
    with capture() as rec:
        assert emit("sys.job.ran", uz="ishladi")
    assert len(rec.records) == 1
    assert runtime.get_active() is None


# --- fixes -------------------------------------------------------------------


def test_FR_56_wide_detail_is_truncated_not_dropped(active: tuple[NullSink, InMemoryMetrics]) -> None:
    assert emit("a.b.c", uz="x", detail={f"k{i}": i for i in range(300)}) is True
    assert active[0].submitted[-1]["audit"]["detail"] == {"_truncated": True}
    assert active[1].get("audit_emit_dropped_total") == 0


def test_FR_56_drop_without_middleware_is_counted_and_logged(caplog: pytest.LogCaptureFixture) -> None:
    import importlib

    emit_module = importlib.import_module("audit_logging.semantic.emit")

    before = emit_module.dropped_without_sink
    with caplog.at_level("WARNING", logger="audit_logging"):
        assert emit("sys.app.started", uz="ishga tushdi") is False
        assert emit("sys.app.started", uz="ishga tushdi") is False
    assert emit_module.dropped_without_sink == before + 2
    assert sum("no active" in r.getMessage() for r in caplog.records) <= 1


def test_FR_56_failure_message_says_xato(active: tuple[NullSink, InMemoryMetrics]) -> None:
    assert emit("sys.job.ran", uz="ishladi", result="failure")
    assert active[0].submitted[-1]["message"] == "ishladi — xato"


def test_FR_56_task_rejects_async_generators() -> None:
    async def gen() -> Any:
        yield 1

    with pytest.raises(TypeError):
        audited_task("sys.job.ran", uz="x")(gen)


async def test_FR_56_task_sync_wrapper_returning_a_coroutine_emits_after_await(
    active: tuple[NullSink, InMemoryMetrics],
) -> None:
    async def work() -> int:
        raise RuntimeError("late")

    @audited_task("sys.job.ran", uz="ishladi")
    def job() -> Any:
        return work()  # e.g. a retry decorator hiding the coroutine function

    pending = job()
    assert active[0].submitted == []
    with pytest.raises(RuntimeError):
        await pending
    assert active[0].submitted[-1]["audit"]["result"] == "failure"


def test_facade_emit_and_task_type_check_in_user_code(tmp_path: Any) -> None:
    """audit.emit / audit.task are attached at runtime; mypy --strict must still see
    them (gate finding: '"_Audit" has no attribute "emit"')."""
    mypy_api = pytest.importorskip("mypy.api")
    src = tmp_path / "user_app.py"
    src.write_text(
        "from audit_logging import audit\n\n\n"
        "@audit.task('sys.job.ran', uz='x')\n"
        "def job() -> int:\n    return 1\n\n\n"
        "def f() -> bool:\n    return audit.emit('sys.job.ran', uz='x') and job() == 1\n"
    )
    out, err, status = mypy_api.run(["--strict", "--no-incremental", str(src)])
    assert status == 0, out + err
