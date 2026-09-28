"""audit_logging.semantic.enricher (FR-55): patch whitelist, re-render rule,
timeout tag, TTL cache, never raises."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from audit_logging.metrics import InMemoryMetrics
from audit_logging.semantic.enricher import Enricher
from audit_logging.semantic.model import TAG_ENRICH_TIMEOUT


def make_doc(target_id: Any = "2", params_target: Any = None, message: str | None = None) -> dict[str, Any]:
    shown = "noma'lum" if params_target is None else str(params_target)
    return {
        "message": message or f"Sardor «{shown}» foydalanuvchisini tahrirladi",
        "event": {"action": "admin.user.updated"},
        "user": {"id": "7", "name": "sardor"},
        "audit": {
            "target": {"type": "user", "id": target_id},
            "detail": {"a": 1},
            "i18n": {"key": "admin.user.updated",
                     "params": {"actor": "Sardor", "target": params_target}},
        },
    }


@pytest.fixture
def make() -> Any:
    made: list[Enricher] = []

    def factory(fn: Any, **kw: Any) -> Enricher:
        e = Enricher(fn, **kw)
        made.append(e)
        return e

    yield factory
    for e in made:
        e.close()


def test_whitelisted_patch_is_applied_and_the_rest_ignored(make: Any) -> None:
    e = make(lambda d: {
        "audit": {"target": {"label": "Aliyev Vali", "id": "HACK"}, "detail": {"b": 2}, "risk": "low"},
        "user.full_name": "Sardor Karimov", "user.department": "Moliya",
        "user.id": "HACK", "message": "HACK",
    })
    [d] = e.apply([make_doc()])
    assert d["audit"]["target"] == {"type": "user", "id": "2", "label": "Aliyev Vali"}
    assert d["audit"]["detail"] == {"a": 1, "b": 2}
    assert "risk" not in d["audit"]
    assert d["user"] == {"id": "7", "name": "sardor", "full_name": "Sardor Karimov", "department": "Moliya"}
    assert d["message"] == "Sardor «Aliyev Vali» foydalanuvchisini tahrirladi"
    assert d["audit"]["i18n"]["params"]["target"] == "Aliyev Vali"


def test_message_rerendered_when_target_was_the_id(make: Any) -> None:
    e = make(lambda d: {"audit.target.label": "Aliyev Vali"})
    [d] = e.apply([make_doc(params_target="2")])
    assert d["message"] == "Sardor «Aliyev Vali» foydalanuvchisini tahrirladi"


def test_message_left_alone_when_target_was_already_a_label(make: Any) -> None:
    e = make(lambda d: {"audit.target.label": "New Name"})
    [d] = e.apply([make_doc(params_target="Old Name")])
    assert d["message"] == "Sardor «Old Name» foydalanuvchisini tahrirladi"
    assert d["audit"]["i18n"]["params"]["target"] == "Old Name"
    assert d["audit"]["target"]["label"] == "New Name"


def test_no_i18n_means_label_only(make: Any) -> None:
    e = make(lambda d: {"audit.target.label": "X"})
    doc = make_doc()
    del doc["audit"]["i18n"]
    [d] = e.apply([doc])
    assert d["audit"]["target"]["label"] == "X"
    assert "noma'lum" in d["message"]


def test_bad_patch_values_are_ignored(make: Any) -> None:
    e = make(lambda d: {"audit.target.label": 5, "audit.detail": "x", "user.full_name": ""})
    before = make_doc()
    [d] = e.apply([make_doc()])
    assert d == before


def test_timeout_tags_and_leaves_the_doc_unchanged(make: Any) -> None:
    release = threading.Event()

    def slow(_d: dict[str, Any]) -> dict[str, Any]:
        release.wait(5)
        return {"audit.target.label": "late"}

    e = make(slow, timeout_ms=50)
    started = time.monotonic()
    docs = e.apply([make_doc(target_id=str(i)) for i in range(3)])
    assert time.monotonic() - started < 1.0
    release.set()
    for d in docs:
        assert d["tags"] == [TAG_ENRICH_TIMEOUT]
        assert "label" not in d["audit"]["target"]


def test_exception_leaves_doc_unchanged_without_tag_and_counts(make: Any) -> None:
    metrics = InMemoryMetrics()

    def boom(_d: dict[str, Any]) -> None:
        raise RuntimeError("db down")

    e = make(boom, metrics=metrics)
    before = make_doc()
    [d] = e.apply([make_doc()])
    assert d == before
    assert metrics.get("audit_semantic_errors_total") == 1.0


def test_cache_hits_skip_the_lookup_and_expire(make: Any) -> None:
    calls: list[str] = []

    def fn(d: dict[str, Any]) -> dict[str, Any]:
        calls.append(d["audit"]["target"]["id"])
        return {"audit.target.label": "L" + d["audit"]["target"]["id"]}

    e = make(fn, cache_seconds=0.2)
    out = e.apply([make_doc("1"), make_doc("1"), make_doc("2")])
    assert sorted(calls) == ["1", "2"]  # equal keys looked up once per batch
    assert [d["audit"]["target"]["label"] for d in out] == ["L1", "L1", "L2"]
    e.apply([make_doc("1")])
    assert len(calls) == 2
    time.sleep(0.25)
    e.apply([make_doc("1")])
    assert len(calls) == 3


def test_docs_without_target_id_are_never_cached(make: Any) -> None:
    calls: list[int] = []
    e = make(lambda d: calls.append(1))
    e.apply([make_doc(target_id=None)])
    e.apply([make_doc(target_id=None)])
    assert len(calls) == 2


def test_cache_is_bounded(make: Any) -> None:
    e = make(lambda d: None, max_cache=3)
    e.apply([make_doc(str(i)) for i in range(10)])
    assert len(e._cache) == 3
    assert [k[2] for k in e._cache] == ["7", "8", "9"]


def test_fn_gets_a_copy(make: Any) -> None:
    def mutate(d: dict[str, Any]) -> None:
        d["audit"]["target"]["id"] = "mutated"

    e = make(mutate)
    [d] = e.apply([make_doc()])
    assert d["audit"]["target"]["id"] == "2"


def test_never_raises_on_junk_and_after_close(make: Any) -> None:
    e = make(lambda d: {"audit.target.label": "x"})
    junk: list[Any] = [None, 1, {"audit": "str"}, {}]
    assert e.apply(junk) is junk
    e.close()
    e.close()
    doc = make_doc()
    assert e.apply([doc]) == [doc]
    assert "label" not in doc["audit"]["target"]


def test_a_wedged_pool_is_skipped_not_waited_on(make: Any) -> None:
    """Hung lookups occupy every worker: later batches are tagged at once instead of
    blocking the writer thread for timeout x rounds (review: enricher bound)."""
    release = threading.Event()

    def hung(_d: dict[str, Any]) -> dict[str, Any]:
        release.wait(10)
        return {}

    e = make(hung, timeout_ms=50)
    try:
        e.apply([make_doc(target_id=str(i)) for i in range(8)])
        started = time.monotonic()
        docs = e.apply([make_doc(target_id=f"n{i}") for i in range(400)])
        assert time.monotonic() - started < 0.2
        assert all(d["tags"] == [TAG_ENRICH_TIMEOUT] for d in docs)
    finally:
        release.set()


def test_one_batch_wait_is_capped_whatever_its_size(make: Any) -> None:
    def slow(_d: dict[str, Any]) -> dict[str, Any]:
        time.sleep(0.2)
        return {}

    e = make(slow, timeout_ms=200)
    started = time.monotonic()
    docs = e.apply([make_doc(target_id=str(i)) for i in range(200)])  # 50 rounds uncapped = 10 s
    assert time.monotonic() - started < 2.0
    assert any(d.get("tags") == [TAG_ENRICH_TIMEOUT] for d in docs)


def test_a_hung_lookup_does_not_block_interpreter_exit() -> None:
    import subprocess
    import sys

    code = (
        "import threading\n"
        "from audit_logging.semantic.enricher import Enricher\n"
        "hang = threading.Event()\n"
        "e = Enricher(lambda d: hang.wait(), timeout_ms=20)\n"
        "e.apply([{'audit': {'target': {'id': '1'}}}])\n"
        "e.close()\n"
    )
    done = subprocess.run([sys.executable, "-c", code], timeout=10)
    assert done.returncode == 0
