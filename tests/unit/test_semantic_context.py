"""Per-request bag + audit facade — FR-54. Owned by agent C."""

from __future__ import annotations

import asyncio
import contextvars

import anyio.to_thread

from audit_logging.semantic.context import (
    audit,
    close_bag,
    compute_diff,
    current_bag,
    open_bag,
)
from audit_logging.semantic.model import DiffEntry


def test_FR_54_no_bag_every_method_is_a_noop() -> None:
    assert current_bag() is None
    audit.target(label="x", id="1", type="user")
    audit.diff({"a": 1}, {"a": 2})
    audit.detail(k=1)
    audit.count(3)
    audit.code("a.b.c")
    assert current_bag() is None


def test_FR_54_open_close_restores_previous() -> None:
    outer = open_bag()
    first = current_bag()
    inner = open_bag()
    assert current_bag() is not first
    close_bag(inner)
    assert current_bag() is first
    close_bag(outer)
    assert current_bag() is None


def test_FR_54_close_bag_with_used_or_foreign_token_never_raises() -> None:
    token = open_bag()
    close_bag(token)
    close_bag(token)  # already used
    foreign = contextvars.copy_context().run(open_bag)
    close_bag(foreign)  # created in another context
    assert current_bag() is None


def test_FR_54_facade_writes_into_bag() -> None:
    token = open_bag()
    try:
        audit.target(label="Aliyev Vali", id=2, type="user")  # type: ignore[arg-type]
        audit.detail(a=1)
        audit.detail(b=2, a=3)
        audit.count(5)
        audit.code("admin.user.password_reset")
        audit.diff({"role_id": 1, "x": 0}, {"role_id": 2, "x": 0}, labels={"role_id": "Rol"})
        bag = current_bag()
        assert bag is not None
        assert (bag.target_label, bag.target_id, bag.target_type) == ("Aliyev Vali", "2", "user")
        assert bag.detail == {"a": 3, "b": 2}
        assert bag.count == 5
        assert bag.code == "admin.user.password_reset"
        assert bag.diff == [DiffEntry("role_id", "Rol", 1, 2)]
        assert bag.before == {"role_id": 1, "x": 0} and bag.after == {"role_id": 2, "x": 0}
    finally:
        close_bag(token)


def test_FR_54_invalid_code_and_count_are_ignored() -> None:
    token = open_bag()
    try:
        audit.code("Not A Code")
        audit.code(None)  # type: ignore[arg-type]
        audit.count("7")  # type: ignore[arg-type]
        audit.count(True)
        bag = current_bag()
        assert bag is not None and bag.code is None and bag.count is None
        audit.target(label=None)
        assert bag.target_label is None
    finally:
        close_bag(token)


def test_FR_54_diff_with_bad_input_never_raises() -> None:
    token = open_bag()
    try:
        audit.diff(42, None)  # type: ignore[arg-type]
        audit.detail(**{"x": object()})
    finally:
        close_bag(token)


def test_FR_54_compute_diff_added_removed_changed_sorted() -> None:
    d = compute_diff({"b": 1, "c": 1, "z": None}, {"a": 1, "b": 2, "c": 1, "z": None}, {"a": "A"})
    assert d == [DiffEntry("a", "A", None, 1), DiffEntry("b", "b", 1, 2)]
    assert compute_diff(None, None) == []
    assert compute_diff({"k": 1}, None) == [DiffEntry("k", "k", 1, None)]


def test_FR_54_compute_diff_survives_raising_eq() -> None:
    class Weird:
        def __eq__(self, other: object) -> bool:
            raise RuntimeError

        __hash__ = object.__hash__

    w = Weird()
    assert compute_diff({"k": w}, {"k": w}) == []
    assert len(compute_diff({"k": w}, {"k": Weird()})) == 1


async def test_FR_54_async_handler_writes_visible() -> None:
    async def handler() -> None:
        await asyncio.sleep(0)
        audit.detail(seen=True)

    token = open_bag()
    try:
        await handler()
        bag = current_bag()
        assert bag is not None and bag.detail == {"seen": True}
    finally:
        close_bag(token)


async def test_FR_54_sync_handler_in_threadpool_mutates_same_bag() -> None:
    def handler(n: int) -> None:
        audit.count(n)
        audit.detail(thread=True)

    token = open_bag()
    try:
        await anyio.to_thread.run_sync(handler, 3)  # what Starlette does
        await asyncio.to_thread(audit.target, label="t")
        bag = current_bag()
        assert bag is not None
        assert bag.count == 3 and bag.detail == {"thread": True} and bag.target_label == "t"
    finally:
        close_bag(token)


async def test_FR_54_concurrent_requests_isolated() -> None:
    gate = asyncio.Event()

    async def request(name: str) -> dict[str, object]:
        token = open_bag()
        try:
            audit.detail(who=name)
            audit.target(label=name)
            await gate.wait()  # both requests in flight at once
            bag = current_bag()
            assert bag is not None and bag.target_label == name
            return dict(bag.detail)
        finally:
            close_bag(token)

    t1 = asyncio.create_task(request("a"))
    t2 = asyncio.create_task(request("b"))
    await asyncio.sleep(0)
    gate.set()
    assert list(await asyncio.gather(t1, t2)) == [{"who": "a"}, {"who": "b"}]
    assert current_bag() is None
