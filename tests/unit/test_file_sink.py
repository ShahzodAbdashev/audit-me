"""Unit tests for ``audit_logging.sinks.file_sink`` (Agent A4).

FR-18/FR-19 (byte-bounded queue and the drop path), FR-20r (interval and size
triggered flushing, submission order, one ``os.write``), FR-21r (write failure
accounting, one retry, log-once), FR-22 (rotation and backup count), FR-26
(one file per service and PID) and FR-27 (bounded, idempotent ``close``).
"""

from __future__ import annotations

import asyncio
import errno
import json
import logging
import math
import os
import threading
import time
from collections.abc import AsyncIterator, Callable
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from audit_logging.config import AuditConfig
from audit_logging.metrics import InMemoryMetrics
from audit_logging.sinks import file_sink as fs
from audit_logging.sinks.file_sink import FileSink

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_config(log_dir: Path, **overrides: Any) -> AuditConfig:
    """A config tuned for tests: tiny interval, temp directory."""
    kwargs: dict[str, Any] = {
        "service_name": "test-service",
        "service_version": "0.0.1",
        "environment": "test",
        "log_dir": log_dir,
        "flush_interval_seconds": 0.05,
        "shutdown_flush_timeout": 2.0,
    }
    kwargs.update(overrides)
    return AuditConfig(**kwargs)


def doc(index: int, pad: int = 0) -> dict[str, Any]:
    """A document with a stable, monotonic ``i`` for order assertions."""
    body: dict[str, Any] = {"i": index, "event": {"outcome": "success"}}
    if pad:
        body["pad"] = "x" * pad
    return body


def fixed_doc(index: int, target: int = 96) -> dict[str, Any]:
    """A document whose serialised line is exactly ``target`` bytes."""
    document: dict[str, Any] = {"i": index, "pad": ""}
    document["pad"] = "x" * max(0, target - line_size(document))
    return document


def line_size(document: dict[str, Any]) -> int:
    """Exactly how many bytes ``document`` occupies in the file."""
    return len(fs._dumps(document)) + 1


def all_generations(sink: FileSink) -> list[Path]:
    """The active file plus every ``.1``…``.N`` backup that exists."""
    paths = [sink.path] if sink.path.exists() else []
    index = 1
    while True:
        candidate = Path(f"{sink.path}.{index}")
        if not candidate.exists():
            return paths
        paths.append(candidate)
        index += 1


def rotated_indices(sink: FileSink) -> list[int]:
    """Every ``.N`` generation that exists on disk, in numeric order.

    Unlike :func:`all_generations` this does not stop at the first missing
    number, so a *gap* in the sequence is visible rather than invisible.
    """
    prefix = sink.path.name + "."
    found: list[int] = []
    for path in sink.path.parent.iterdir():
        suffix = path.name[len(prefix) :] if path.name.startswith(prefix) else ""
        if suffix.isdigit():
            found.append(int(suffix))
    return sorted(found)


def generation_sizes(sink: FileSink) -> dict[str, int]:
    """``name -> size`` for the active file and every ``.N`` backup."""
    sizes = {sink.path.name: sink.path.stat().st_size} if sink.path.exists() else {}
    for index in rotated_indices(sink):
        path = Path(f"{sink.path}.{index}")
        sizes[path.name] = path.stat().st_size
    return sizes


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    return [line for line in text.split("\n") if line]


def read_indices(path: Path) -> list[int]:
    return [int(json.loads(line)["i"]) for line in read_lines(path)]


@pytest.fixture
async def make_sink(tmp_path: Path) -> AsyncIterator[Callable[..., FileSink]]:
    created: list[FileSink] = []

    def factory(**overrides: Any) -> FileSink:
        metrics = overrides.pop("metrics", None) or InMemoryMetrics()
        log_dir = overrides.pop("log_dir", tmp_path / "audit")
        sink = FileSink(make_config(Path(log_dir), **overrides), metrics)
        created.append(sink)
        return sink

    yield factory

    for sink in created:
        try:
            await asyncio.wait_for(sink.close(), timeout=5)
        except Exception:
            pass


def patch_os_write(
    monkeypatch: pytest.MonkeyPatch, hook: Callable[[int, Any], int | None]
) -> None:
    """Replace ``os.write`` with ``hook``; ``None`` from the hook means "real".

    Scoped by the hook itself on the fd, so pytest's own capture writes are
    untouched.
    """
    real_write = os.write

    def fake_write(fd: int, data: Any) -> int:
        result = hook(fd, data)
        if result is None:
            return real_write(fd, data)
        return result

    monkeypatch.setattr(os, "write", fake_write)


# ---------------------------------------------------------------------------
# FR-18 — the queue is bounded in bytes, not in documents
# ---------------------------------------------------------------------------


async def test_FR_18_queue_is_bounded_in_bytes_not_documents(
    make_sink: Callable[..., FileSink],
) -> None:
    """A handful of big documents fill the same bound as many small ones."""
    small = doc(0)
    big = doc(0, pad=4000)
    cap = line_size(big) * 2
    sink = make_sink(queue_max_bytes=cap, flush_max_bytes=cap)

    assert sink.submit(big) is True
    assert sink.submit(big) is True
    assert sink.submit(small) is False  # bytes, not documents, are the bound
    assert sink.queue_depth == 2
    assert sink.held_bytes <= cap


async def test_FR_18_many_small_documents_fit_where_one_big_one_does_not(
    make_sink: Callable[..., FileSink],
) -> None:
    small = doc(0)
    cap = line_size(small) * 10
    sink = make_sink(queue_max_bytes=cap, flush_max_bytes=cap)

    accepted = sum(1 for i in range(50) if sink.submit(doc(i)))
    assert accepted == 10
    assert sink.held_bytes == cap


async def test_FR_18_queue_bytes_gauge_tracks_the_queue(
    make_sink: Callable[..., FileSink],
) -> None:
    metrics = InMemoryMetrics()
    sink = make_sink(metrics=metrics)
    expected = 0
    for i in range(5):
        document = doc(i)
        expected += line_size(document)
        sink.submit(document)
        assert metrics.get("audit_queue_bytes") == float(expected)

    await sink.start()
    await sink.flush()
    assert metrics.get("audit_queue_bytes") == 0.0
    assert sink.held_bytes == 0


async def test_FR_18_queue_bytes_equals_the_bytes_that_reach_the_file(
    make_sink: Callable[..., FileSink],
) -> None:
    sink = make_sink()
    await sink.start()
    total = 0
    for i in range(20):
        document = doc(i, pad=i * 7)
        total += line_size(document)
        sink.submit(document)
    assert sink.held_bytes == total
    await sink.flush()
    assert sink.path.stat().st_size == total


# ---------------------------------------------------------------------------
# FR-19 — a full queue drops, counts, and returns False
# ---------------------------------------------------------------------------


async def test_FR_19_submit_returns_false_and_counts_when_the_queue_is_full(
    make_sink: Callable[..., FileSink],
) -> None:
    metrics = InMemoryMetrics()
    cap = line_size(doc(0)) * 3
    sink = make_sink(queue_max_bytes=cap, flush_max_bytes=cap, metrics=metrics)

    results = [sink.submit(doc(i)) for i in range(10)]

    assert results[:3] == [True, True, True]
    assert all(r is False for r in results[3:])
    assert metrics.get("audit_documents_submitted_total") == 3.0
    assert metrics.get("audit_documents_dropped_total") == 7.0


async def test_FR_19_the_api_side_never_sees_an_exception_when_full(
    make_sink: Callable[..., FileSink],
) -> None:
    """AC-09 in miniature: 200 'requests' against a queue too small for one."""
    metrics = InMemoryMetrics()
    sink = make_sink(queue_max_bytes=1, flush_max_bytes=1, metrics=metrics)

    handled = 0
    for i in range(200):
        # This stands in for the request path: nothing may propagate.
        assert sink.submit(doc(i, pad=100)) is False
        handled += 1

    assert handled == 200
    assert metrics.get("audit_documents_dropped_total") == 200.0
    assert metrics.get("audit_documents_submitted_total") == 0.0


async def test_FR_19_the_queue_recovers_after_a_flush(
    make_sink: Callable[..., FileSink],
) -> None:
    cap = line_size(doc(0)) * 2
    sink = make_sink(queue_max_bytes=cap, flush_max_bytes=cap)
    await sink.start()

    assert sink.submit(doc(0)) is True
    assert sink.submit(doc(1)) is True
    assert sink.submit(doc(2)) is False

    await sink.flush()
    assert sink.submit(doc(3)) is True
    await sink.flush()
    assert read_indices(sink.path) == [0, 1, 3]


async def test_FR_19_a_line_larger_than_the_whole_queue_is_dropped(
    make_sink: Callable[..., FileSink],
) -> None:
    metrics = InMemoryMetrics()
    sink = make_sink(queue_max_bytes=64, flush_max_bytes=64, metrics=metrics)
    assert sink.submit(doc(0, pad=10_000)) is False
    assert metrics.get("audit_documents_dropped_total") == 1.0


# ---------------------------------------------------------------------------
# FR-20r — background flushing, order, one os.write
# ---------------------------------------------------------------------------


async def test_FR_20r_background_task_flushes_on_the_interval(
    make_sink: Callable[..., FileSink],
) -> None:
    sink = make_sink(flush_interval_seconds=0.05, flush_max_bytes=8 * 1024 * 1024)
    await sink.start()
    for i in range(5):
        sink.submit(doc(i))
    assert read_lines(sink.path) == []

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and len(read_lines(sink.path)) < 5:
        await asyncio.sleep(0.02)

    assert read_indices(sink.path) == [0, 1, 2, 3, 4]


async def test_FR_20r_size_trigger_flushes_before_the_interval_elapses(
    make_sink: Callable[..., FileSink],
) -> None:
    """The size trigger must not wait out flush_interval_seconds."""
    threshold = line_size(doc(0)) * 4
    sink = make_sink(
        flush_interval_seconds=30.0,
        flush_max_bytes=threshold,
        queue_max_bytes=8 * 1024 * 1024,
    )
    await sink.start()

    started = time.monotonic()
    for i in range(4):
        sink.submit(doc(i))

    deadline = started + 3.0
    while time.monotonic() < deadline and len(read_lines(sink.path)) < 4:
        await asyncio.sleep(0.01)
    elapsed = time.monotonic() - started

    assert read_indices(sink.path) == [0, 1, 2, 3]
    assert elapsed < 2.0, "size trigger waited for the interval"


async def test_FR_20r_a_batch_is_written_with_a_single_os_write(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink()
    await sink.start()
    target_fd = sink._fd
    assert target_fd is not None

    calls: list[int] = []
    patch_os_write(
        monkeypatch, lambda fd, data: calls.append(len(data)) if fd == target_fd else None
    )

    for i in range(25):
        sink.submit(doc(i))
    await sink.flush()

    assert len(calls) == 1, f"expected one os.write, got {calls}"
    assert calls[0] == sum(line_size(doc(i)) for i in range(25))


async def test_FR_20r_lines_are_written_in_submission_order(
    make_sink: Callable[..., FileSink],
) -> None:
    """AC-15: 1000 documents, in submission order, on disk."""
    sink = make_sink(flush_interval_seconds=0.1)
    await sink.start()

    for i in range(1000):
        assert sink.submit(doc(i, pad=200)) is True

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and len(read_lines(sink.path)) < 1000:
        await asyncio.sleep(0.02)

    assert read_indices(sink.path) == list(range(1000))


async def test_FR_20r_order_survives_interleaved_flushes(
    make_sink: Callable[..., FileSink],
) -> None:
    sink = make_sink()
    await sink.start()
    n = 0
    for _round in range(20):
        for _ in range(13):
            sink.submit(doc(n))
            n += 1
        await sink.flush()
    assert read_indices(sink.path) == list(range(n))


async def test_FR_20r_fsync_is_off_by_default(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink()
    await sink.start()
    synced: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: synced.append(fd))
    sink.submit(doc(0))
    await sink.flush()
    assert synced == []


async def test_FR_20r_fsync_happens_when_configured(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(fsync=True)
    await sink.start()
    synced: list[int] = []
    monkeypatch.setattr(os, "fsync", lambda fd: synced.append(fd))
    sink.submit(doc(0))
    await sink.flush()
    assert synced == [sink._fd]


async def test_FR_20r_flush_seconds_is_recorded(
    make_sink: Callable[..., FileSink],
) -> None:
    metrics = InMemoryMetrics()
    sink = make_sink(metrics=metrics)
    await sink.start()
    sink.submit(doc(0))
    await sink.flush()
    assert metrics.get("audit_flush_seconds") >= 0.0
    assert math.isfinite(metrics.get("audit_flush_seconds"))


async def test_FR_20r_only_one_background_task_per_sink(
    make_sink: Callable[..., FileSink],
) -> None:
    sink = make_sink()
    await sink.start()
    first = sink._task
    await sink.start()
    await sink.start()
    assert sink._task is first
    assert sum(1 for t in asyncio.all_tasks() if t.get_name() == "audit-file-sink") == 1


async def test_FR_20r_flush_writes_everything_currently_queued(
    make_sink: Callable[..., FileSink],
) -> None:
    sink = make_sink(flush_interval_seconds=30.0, flush_max_bytes=8 * 1024 * 1024)
    await sink.start()
    for i in range(100):
        sink.submit(doc(i))
    await sink.flush()
    assert len(read_lines(sink.path)) == 100
    assert sink.queue_depth == 0


# ---------------------------------------------------------------------------
# FR-21r — write failures are counted, retried once, logged once
# ---------------------------------------------------------------------------


async def test_FR_21r_write_failure_counts_the_batch_and_retries_once(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    metrics = InMemoryMetrics()
    sink = make_sink(
        metrics=metrics, flush_interval_seconds=30.0, flush_max_bytes=8 * 1024 * 1024
    )
    await sink.start()
    target_fd = sink._fd

    attempts: list[int] = []

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd:
            return None
        attempts.append(len(data))
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    for i in range(3):
        sink.submit(doc(i))

    await sink.flush()  # first attempt, first retry, then the batch is dropped

    assert len(attempts) == 2, "the batch must be tried exactly twice"
    # Counted once, on the attempt after which the batch is discarded — the
    # counter means "documents lost", not "write attempts" (review S-9).
    assert metrics.get("audit_documents_failed_total") == 3.0
    assert sink._retry is None, "the batch must be dropped after one retry"


async def test_FR_21r_a_dropped_batch_does_not_block_later_documents(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(flush_interval_seconds=30.0, flush_max_bytes=8 * 1024 * 1024)
    await sink.start()
    target_fd = sink._fd
    failing = True

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd or not failing:
            return None
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    for i in range(3):
        sink.submit(doc(i))
    await sink.flush()

    failing = False
    for i in range(100, 103):
        sink.submit(doc(i))
    await sink.flush()

    assert read_indices(sink.path) == [100, 101, 102]


async def test_FR_21r_the_error_is_logged_once_per_distinct_error_type(
    make_sink: Callable[..., FileSink],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = make_sink(flush_interval_seconds=30.0, flush_max_bytes=8 * 1024 * 1024)
    await sink.start()
    target_fd = sink._fd

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd:
            return None
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    with caplog.at_level(logging.ERROR, logger="audit_logging.sinks.file_sink"):
        for _round in range(5):
            for i in range(4):
                sink.submit(doc(i))
            await sink.flush()

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1, [r.getMessage() for r in errors]
    assert "OSError" in errors[0].getMessage()


async def test_FR_21r_a_second_error_type_is_logged_once_too(
    make_sink: Callable[..., FileSink],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = make_sink(flush_interval_seconds=30.0, flush_max_bytes=8 * 1024 * 1024)
    await sink.start()
    target_fd = sink._fd
    raise_class: list[type[Exception]] = [OSError]

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd:
            return None
        raise raise_class[0]("boom")

    patch_os_write(monkeypatch, hook)

    with caplog.at_level(logging.ERROR, logger="audit_logging.sinks.file_sink"):
        sink.submit(doc(0))
        await sink.flush()
        raise_class[0] = ValueError
        sink.submit(doc(1))
        await sink.flush()

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 2
    assert "OSError" in errors[0].getMessage()
    assert "ValueError" in errors[1].getMessage()


async def test_FR_21r_write_failure_never_reaches_the_request_path(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    metrics = InMemoryMetrics()
    sink = make_sink(metrics=metrics, flush_interval_seconds=0.02)
    await sink.start()
    target_fd = sink._fd

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd:
            return None
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    for i in range(100):
        assert sink.submit(doc(i)) is True  # no exception, still accepted
        if i % 10 == 0:
            await asyncio.sleep(0.01)

    await sink.flush()
    assert metrics.get("audit_documents_failed_total") >= 50.0


@pytest.mark.skipif(IS_ROOT, reason="root ignores directory permissions")
async def test_FR_21r_an_unwritable_directory_does_not_kill_the_process(
    tmp_path: Path,
) -> None:
    """AC-16: the log directory is unwritable; the app keeps going."""
    log_dir = tmp_path / "readonly"
    log_dir.mkdir()
    os.chmod(log_dir, 0o500)
    metrics = InMemoryMetrics()
    sink = FileSink(make_config(log_dir, flush_interval_seconds=30.0), metrics)
    try:
        await sink.start()  # the open fails, and must not raise
        for i in range(50):
            assert sink.submit(doc(i)) is True
        await sink.flush()
        assert metrics.get("audit_documents_failed_total") >= 50.0
        assert not any(log_dir.iterdir())
    finally:
        os.chmod(log_dir, 0o700)
        await sink.close()


# ---------------------------------------------------------------------------
# FR-22 — rotation and backup count
# ---------------------------------------------------------------------------


async def test_FR_22_no_rotation_exactly_at_the_boundary(
    make_sink: Callable[..., FileSink],
) -> None:
    """`file_max_bytes` is a ceiling: filling it exactly does not rotate."""
    metrics = InMemoryMetrics()
    size = line_size(doc(0))
    sink = make_sink(file_max_bytes=size * 4, metrics=metrics)
    await sink.start()

    for i in range(4):
        sink.submit(doc(i))
        await sink.flush()

    assert sink.path.stat().st_size == size * 4
    assert not Path(f"{sink.path}.1").exists()
    assert metrics.get("audit_file_rotations_total") == 0.0


async def test_FR_22_rotation_when_the_boundary_is_passed(
    make_sink: Callable[..., FileSink],
) -> None:
    metrics = InMemoryMetrics()
    size = line_size(doc(0))
    sink = make_sink(file_max_bytes=size * 4, metrics=metrics)
    await sink.start()

    for i in range(5):
        sink.submit(doc(i))
        await sink.flush()

    assert metrics.get("audit_file_rotations_total") == 1.0
    assert read_indices(Path(f"{sink.path}.1")) == [0, 1, 2, 3]
    assert read_indices(sink.path) == [4]


async def test_FR_22_multiple_generations_respect_file_backup_count(
    make_sink: Callable[..., FileSink],
) -> None:
    metrics = InMemoryMetrics()
    size = line_size(doc(0))
    sink = make_sink(file_max_bytes=size, file_backup_count=3, metrics=metrics)
    await sink.start()

    for i in range(6):
        sink.submit(doc(i))
        await sink.flush()

    assert metrics.get("audit_file_rotations_total") == 5.0
    assert read_indices(sink.path) == [5]
    assert read_indices(Path(f"{sink.path}.1")) == [4]
    assert read_indices(Path(f"{sink.path}.2")) == [3]
    assert read_indices(Path(f"{sink.path}.3")) == [2]
    assert not Path(f"{sink.path}.4").exists()

    generation_files = sorted(p.name for p in sink.path.parent.iterdir())
    assert len(generation_files) == 4, generation_files


async def test_FR_22_no_line_is_ever_split_across_a_rotation(
    make_sink: Callable[..., FileSink],
) -> None:
    """AC-12's 'every line reaches Elasticsearch' half: nothing is corrupted."""
    size = line_size(fixed_doc(0))
    sink = make_sink(file_max_bytes=size * 3, file_backup_count=20)
    await sink.start()
    for i in range(60):
        sink.submit(fixed_doc(i))
        await sink.flush()

    seen: list[int] = []
    for path in [sink.path] + [Path(f"{sink.path}.{n}") for n in range(1, 21)]:
        for line in read_lines(path):
            seen.append(int(json.loads(line)["i"]))
    assert sorted(seen) == list(range(60))
    assert Path(f"{sink.path}.19").exists()
    assert not Path(f"{sink.path}.20").exists()


async def test_FR_22_backup_count_zero_discards_the_active_file(
    make_sink: Callable[..., FileSink],
) -> None:
    metrics = InMemoryMetrics()
    size = line_size(doc(0))
    sink = make_sink(file_max_bytes=size, file_backup_count=0, metrics=metrics)
    await sink.start()

    for i in range(4):
        sink.submit(doc(i))
        await sink.flush()

    assert metrics.get("audit_file_rotations_total") == 3.0
    assert read_indices(sink.path) == [3]
    assert not Path(f"{sink.path}.1").exists()
    assert [p.name for p in sink.path.parent.iterdir()] == [sink.path.name]


async def test_FR_22_a_batch_bigger_than_the_file_limit_is_split_not_overshot(
    make_sink: Callable[..., FileSink],
) -> None:
    """An oversized batch is split across files; it never overshoots (S-10).

    This test used to assert the opposite ("overshoots by design"): all 29
    lines landed in one 4.4 KB file against a 200-byte limit. That premise was
    the defect — `file_max_bytes` is a bound, so the batch is cut instead.
    """
    limit = 200
    sink = make_sink(file_max_bytes=limit, file_backup_count=40)
    await sink.start()
    sink.submit(doc(0))
    await sink.flush()
    for i in range(1, 30):
        sink.submit(doc(i, pad=100))
    await sink.flush()

    seen: list[int] = []
    for path in all_generations(sink):
        assert path.stat().st_size <= limit, f"{path.name} is over the bound"
        seen.extend(read_indices(path))
    assert sorted(seen) == list(range(30)), "AC-25: every line survives"


async def test_FR_22_rotation_reopens_the_same_active_path(
    make_sink: Callable[..., FileSink],
) -> None:
    size = line_size(doc(0))
    sink = make_sink(file_max_bytes=size)
    await sink.start()
    for i in range(3):
        sink.submit(doc(i))
        await sink.flush()
    sink.submit(doc(99))
    await sink.flush()
    assert sink.path.exists()
    assert 99 in read_indices(sink.path)


# ---------------------------------------------------------------------------
# FR-26 — one file per service per PID
# ---------------------------------------------------------------------------


def test_FR_26_file_name_is_service_and_pid(tmp_path: Path) -> None:
    config = make_config(tmp_path / "audit")
    sink = FileSink(config)
    assert sink.path.name == f"test-service-{os.getpid()}.jsonl"
    assert sink.path.parent == tmp_path / "audit"


def test_FR_26_service_name_is_sanitised_for_the_filesystem(tmp_path: Path) -> None:
    config = make_config(tmp_path / "audit", service_name="../evil svc/name:v1")
    sink = FileSink(config)
    assert "/" not in sink.path.name
    assert sink.path.parent == tmp_path / "audit"
    assert sink.path.name == f".._evil_svc_name_v1-{os.getpid()}.jsonl".lstrip(".")
    assert not sink.path.name.startswith(".")


@pytest.mark.parametrize(
    "raw", ["...", " ", "///", "\x00\x01", "ünïcødé", "a" * 300]
)
def test_FR_26_sanitised_name_is_always_a_usable_single_component(
    tmp_path: Path, raw: str
) -> None:
    config = make_config(tmp_path / "audit", service_name=raw)
    sink = FileSink(config)
    assert os.sep not in sink.path.name
    assert sink.path.name.endswith(f"-{os.getpid()}.jsonl")
    assert len(sink.path.name) > len(f"-{os.getpid()}.jsonl")


async def test_FR_26_one_file_per_pid(make_sink: Callable[..., FileSink]) -> None:
    sink = make_sink()
    await sink.start()
    sink.submit(doc(0))
    await sink.flush()

    files = list(sink.path.parent.iterdir())
    assert [p.name for p in files] == [f"test-service-{os.getpid()}.jsonl"]

    # A second sink in the same process shares the file; a different PID would
    # get its own, which is exactly what multiple uvicorn workers rely on.
    other = FileSink(make_config(sink.path.parent))
    assert other.path == sink.path
    other._pid = os.getpid() + 1
    assert (
        Path(sink.path.parent) / f"test-service-{other._pid}.jsonl"
    ).name != sink.path.name


async def test_FR_26_log_dir_is_created_when_absent(tmp_path: Path) -> None:
    log_dir = tmp_path / "deep" / "nested" / "audit"
    assert not log_dir.exists()
    sink = FileSink(make_config(log_dir))
    try:
        await sink.start()
        assert log_dir.is_dir()
        assert sink.path.exists()
    finally:
        await sink.close()


# ---------------------------------------------------------------------------
# FR-27 — close drains within the timeout and returns regardless
# ---------------------------------------------------------------------------


async def test_FR_27_close_drains_the_queue(tmp_path: Path) -> None:
    sink = FileSink(make_config(tmp_path, flush_interval_seconds=30.0))
    await sink.start()
    for i in range(250):
        sink.submit(doc(i))
    await sink.close()
    assert read_indices(sink.path) == list(range(250))


async def test_FR_27_close_returns_within_the_timeout_when_the_write_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    released = threading.Event()
    sink = FileSink(
        make_config(tmp_path, flush_interval_seconds=30.0, shutdown_flush_timeout=0.3)
    )
    await sink.start()
    target_fd = sink._fd

    real_write = os.write

    def fake_write(fd: int, data: Any) -> int:
        if fd != target_fd:
            return real_write(fd, data)
        released.wait(30)
        return len(data)  # do not touch the fd: close() may have shut it

    monkeypatch.setattr(os, "fsync", lambda fd: None)
    monkeypatch.setattr(os, "write", fake_write)

    try:
        for i in range(10):
            sink.submit(doc(i))
        started = time.monotonic()
        await sink.close()
        elapsed = time.monotonic() - started
        assert elapsed < 2.0, f"close() took {elapsed:.3f}s"
        assert elapsed >= 0.25
    finally:
        released.set()
        await asyncio.sleep(0.05)


async def test_FR_27_close_is_idempotent(tmp_path: Path) -> None:
    sink = FileSink(make_config(tmp_path))
    await sink.start()
    sink.submit(doc(0))
    await sink.close()
    await sink.close()
    await sink.close()
    assert read_indices(sink.path) == [0]


async def test_FR_27_close_without_start_still_drains(tmp_path: Path) -> None:
    sink = FileSink(make_config(tmp_path))
    sink.submit(doc(0))
    sink.submit(doc(1))
    await sink.close()
    assert read_indices(sink.path) == [0, 1]


async def test_FR_27_close_leaves_no_running_task(tmp_path: Path) -> None:
    sink = FileSink(make_config(tmp_path))
    await sink.start()
    await sink.close()
    await asyncio.sleep(0.05)
    assert not [t for t in asyncio.all_tasks() if t.get_name() == "audit-file-sink"]


async def test_FR_27_submit_after_close_is_dropped_not_raised(
    tmp_path: Path,
) -> None:
    metrics = InMemoryMetrics()
    sink = FileSink(make_config(tmp_path), metrics)
    await sink.start()
    await sink.close()
    assert sink.submit(doc(0)) is False
    # Counted, but on the shutdown-window counter — FR-19's stays clean (N-8).
    assert metrics.get("audit_documents_dropped_after_close_total") == 1.0
    assert metrics.get("audit_documents_dropped_total") == 0.0
    assert sink.dropped_after_close == 1


async def test_FR_27_start_after_close_is_a_no_op(tmp_path: Path) -> None:
    sink = FileSink(make_config(tmp_path))
    await sink.start()
    await sink.close()
    await sink.start()
    assert sink._task is None


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


async def test_concurrent_submit_from_many_tasks_produces_valid_lines(
    make_sink: Callable[..., FileSink],
) -> None:
    sink = make_sink(flush_interval_seconds=0.02)
    await sink.start()

    async def worker(base: int) -> None:
        for offset in range(20):
            assert sink.submit(doc(base + offset, pad=offset * 3)) is True
            if offset % 5 == 0:
                await asyncio.sleep(0)

    await asyncio.gather(*(worker(w * 100) for w in range(50)))
    await sink.flush()

    lines = read_lines(sink.path)
    assert len(lines) == 1000
    seen = set()
    for line in lines:
        parsed = json.loads(line)  # every line must be valid JSON on its own
        seen.add(parsed["i"])
    assert len(seen) == 1000


async def test_concurrent_submit_and_flush_do_not_interleave(
    make_sink: Callable[..., FileSink],
) -> None:
    sink = make_sink(flush_interval_seconds=0.01)
    await sink.start()

    async def producer(base: int) -> None:
        for offset in range(50):
            sink.submit(doc(base + offset, pad=500))
            await asyncio.sleep(0)

    async def flusher() -> None:
        for _ in range(30):
            await sink.flush()
            await asyncio.sleep(0.005)

    await asyncio.gather(
        *(producer(w * 1000) for w in range(10)), flusher(), flusher()
    )
    await sink.flush()

    lines = read_lines(sink.path)
    assert len(lines) == 500
    for line in lines:
        json.loads(line)


async def test_per_task_order_is_preserved(make_sink: Callable[..., FileSink]) -> None:
    """Documents submitted by one task appear in that task's own order."""
    sink = make_sink(flush_interval_seconds=0.01)
    await sink.start()

    async def worker(tag: int) -> None:
        for seq in range(40):
            sink.submit({"i": tag * 1000 + seq, "tag": tag, "seq": seq})
            await asyncio.sleep(0)

    await asyncio.gather(*(worker(t) for t in range(10)))
    await sink.flush()

    per_tag: dict[int, list[int]] = {}
    for line in read_lines(sink.path):
        parsed = json.loads(line)
        per_tag.setdefault(parsed["tag"], []).append(parsed["seq"])
    assert len(per_tag) == 10
    for tag, seqs in per_tag.items():
        assert seqs == list(range(40)), tag


# ---------------------------------------------------------------------------
# Lazy start
# ---------------------------------------------------------------------------


async def test_submit_starts_the_background_task_lazily(tmp_path: Path) -> None:
    """AGENTS.md: 'the first submit() starts it lazily from the running loop'."""
    sink = FileSink(make_config(tmp_path, flush_interval_seconds=0.02))
    try:
        assert sink._task is None
        assert sink.submit(doc(0)) is True

        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not read_lines(sink.path):
            await asyncio.sleep(0.01)
        assert read_indices(sink.path) == [0]
    finally:
        await sink.close()


def test_submit_outside_a_running_loop_still_enqueues(tmp_path: Path) -> None:
    sink = FileSink(make_config(tmp_path))
    assert sink.submit(doc(0)) is True
    assert sink.queue_depth == 1
    assert sink._task is None


# ---------------------------------------------------------------------------
# Serialisation policy
# ---------------------------------------------------------------------------


def test_awkward_values_stay_strictly_valid_json() -> None:
    document = {
        "nan": float("nan"),
        "inf": float("inf"),
        "ninf": float("-inf"),
        "utf8_bytes": "héllo".encode(),
        "binary_bytes": b"\xff\xfe\x00\x01",
        "when": datetime(2024, 3, 1, 12, 30, 45, 123456, tzinfo=timezone.utc),
        "day": date(2024, 3, 1),
        "amount": Decimal("12.3400"),
        "tags": {"only"},
        "path": Path("/var/log/audit"),
        "nested": {"deep": [float("nan"), b"\xff", Decimal("1")]},
    }
    line = fs._dumps(document)
    assert b"\n" not in line
    parsed = json.loads(line.decode("utf-8"))  # strict: rejects bare NaN

    assert parsed["nan"] is None
    assert parsed["inf"] is None
    assert parsed["ninf"] is None
    assert parsed["utf8_bytes"] == "héllo"
    assert parsed["binary_bytes"].startswith("base64:")
    assert parsed["when"].startswith("2024-03-01T12:30:45")
    assert parsed["day"] == "2024-03-01"
    assert parsed["amount"] == "12.3400"
    assert parsed["tags"] == ["only"]
    assert parsed["nested"]["deep"][0] is None


def test_stdlib_path_never_emits_bare_nan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs, "_ORJSON", None)
    line = fs._dumps({"a": float("nan"), "b": [float("inf")]}).decode()
    assert "NaN" not in line
    assert "Infinity" not in line
    assert json.loads(line) == {"a": None, "b": [None]}


def test_stdlib_path_uses_compact_separators(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs, "_ORJSON", None)
    assert fs._dumps({"a": 1, "b": [1, 2]}) == b'{"a":1,"b":[1,2]}'


def test_stdlib_path_does_not_escape_non_ascii(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fs, "_ORJSON", None)
    assert fs._dumps({"k": "héllo"}) == '{"k":"héllo"}'.encode()


def test_orjson_and_stdlib_produce_identical_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("orjson")
    document: dict[str, Any] = {
        "@timestamp": "2024-03-01T12:00:00Z",
        "when": datetime(2024, 3, 1, 12, 30, 45, 123456, tzinfo=timezone.utc),
        "naive": datetime(2024, 3, 1, 12, 30, 45),
        "day": date(2024, 3, 1),
        "amount": Decimal("12.3400"),
        "utf8_bytes": "héllo".encode(),
        "binary_bytes": b"\xff\xfe\x00\x01",
        "nan": float("nan"),
        "inf": float("inf"),
        "tags": {"only"},
        "unicode": "héllo wörld ☃",
        "nested": {"a": [1, 2, {"b": None, "c": True}]},
        "int_key_map": {1: "one"},
    }
    assert fs._ORJSON is not None, "orjson should be the default backend here"
    with_orjson = fs._dumps(document)

    monkeypatch.setattr(fs, "_ORJSON", None)
    without_orjson = fs._dumps(document)

    assert with_orjson == without_orjson
    json.loads(with_orjson)


async def test_both_backends_write_equivalent_files(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    document = {"i": 0, "amount": Decimal("1.50"), "raw": b"\xff", "nan": float("nan")}

    fast = FileSink(make_config(tmp_path / "fast"))
    await fast.start()
    fast.submit(dict(document))
    await fast.close()

    monkeypatch.setattr(fs, "_ORJSON", None)
    slow = FileSink(make_config(tmp_path / "slow"))
    await slow.start()
    slow.submit(dict(document))
    await slow.close()

    assert fast.path.read_bytes() == slow.path.read_bytes()


def test_submit_drops_an_unserialisable_document_without_raising(
    tmp_path: Path,
) -> None:
    class Hostile:
        def __str__(self) -> str:
            raise RuntimeError("no string for you")

        def __repr__(self) -> str:
            raise RuntimeError("nor a repr")

    metrics = InMemoryMetrics()
    sink = FileSink(make_config(tmp_path), metrics)
    # Whatever the backend does with this, submit() must return, not raise.
    result = sink.submit({"bad": Hostile()})
    assert result in (True, False)
    if result is False:
        # A serialisation refusal is *not* queue pressure (review N2-1).
        assert metrics.get("audit_documents_failed_total") == 1.0
        assert metrics.get("audit_documents_dropped_total") == 0.0


def test_submit_survives_a_cyclic_document(tmp_path: Path) -> None:
    """A cycle is depth-clipped and written, not dropped.

    This is the stdlib encoder's long-standing behaviour (``_sanitise`` is
    depth-bounded, so the recursion terminates and the line is finite); since
    N2-1 made that encoder ``orjson``'s fallback rather than merely its
    alternative, both backends now agree on it. A clipped document beats no
    document, and neither loss counter has any business ticking here.
    """
    metrics = InMemoryMetrics()
    sink = FileSink(make_config(tmp_path), metrics)
    cyclic: dict[str, Any] = {"i": 0}
    cyclic["self"] = cyclic
    assert sink.submit(cyclic) is True
    assert metrics.get("audit_documents_dropped_total") == 0.0
    assert metrics.get("audit_documents_failed_total") == 0.0
    assert sink.queue_depth == 1
    line = sink._queue[0]
    assert b"\n" == line[-1:] and b"\n" not in line[:-1]
    assert json.loads(line)["i"] == 0


def test_every_written_line_is_one_json_document(tmp_path: Path) -> None:
    """No embedded newlines, whatever the payload contains."""
    line = fs._dumps({"text": "a\nb\r\nc", "tab": "\t"})
    assert b"\n" not in line
    assert json.loads(line)["text"] == "a\nb\r\nc"


# ---------------------------------------------------------------------------
# Contract / hygiene
# ---------------------------------------------------------------------------


def test_no_network_client_is_imported(tmp_path: Path) -> None:
    """NFR-4: the package writes files; Filebeat ships them."""
    source = Path(fs.__file__).read_text(encoding="utf-8")
    for banned in ("elasticsearch", "kafka", "httpx", "requests", "urllib3", "socket"):
        assert f"import {banned}" not in source, banned


def test_default_metrics_is_in_memory(tmp_path: Path) -> None:
    sink = FileSink(make_config(tmp_path))
    assert isinstance(sink.metrics, InMemoryMetrics)


def test_repr_is_useful(tmp_path: Path) -> None:
    sink = FileSink(make_config(tmp_path))
    sink.submit(doc(0))
    text = repr(sink)
    assert "FileSink(" in text and "queued=1" in text
    # The repr spells the byte counts out; `bytes=` alone said which one?
    assert "queued_bytes=" in text and "inflight_bytes=" in text
    assert "held_bytes=" in text


async def test_submit_is_fast_enough_for_the_request_path(
    make_sink: Callable[..., FileSink],
) -> None:
    """NFR-2: submit is a serialisation plus a deque.append, nothing more."""
    sink = make_sink(queue_max_bytes=256 * 1024 * 1024, flush_max_bytes=64 * 1024 * 1024)
    await sink.start()
    payload = doc(0, pad=2048)

    for _ in range(200):  # warm up
        sink.submit(payload)
    sink._drain()

    started = time.perf_counter()
    rounds = 5000
    for _ in range(rounds):
        sink.submit(payload)
    per_call_us = (time.perf_counter() - started) / rounds * 1e6

    sink._drain()
    # Generous: the real number is single-digit microseconds. This only has to
    # catch a submit() that started doing I/O.
    assert per_call_us < 200, f"submit() took {per_call_us:.1f} us"


# ===========================================================================
# Regression tests for the adversarial review (REVIEW.md §4–§6) and for the
# two acceptance criteria the orchestrator added from it (AC-25, AC-26).
# ===========================================================================


# ---------------------------------------------------------------------------
# S-7 — _log_once keyed on the exception class alone collapsed distinct faults
# ---------------------------------------------------------------------------


def test_S_7_distinct_errnos_are_not_collapsed_into_one_line(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A8's repro: five distinct failures used to produce two ERROR lines.

    `ENOSPC`, `EDQUOT` and `EIO` are all bare `OSError`, so "disk full" and
    "disk failing" were indistinguishable in the logs.
    """
    sink = FileSink(make_config(tmp_path))
    with caplog.at_level(logging.ERROR, logger="audit_logging.sinks.file_sink"):
        sink._log_once(OSError(errno.ENOSPC, "No space left on device"), "write")
        sink._log_once(OSError(errno.EDQUOT, "Disk quota exceeded"), "write")
        sink._log_once(OSError(errno.EIO, "I/O error"), "write")
        sink._log_once(PermissionError(errno.EACCES, "Permission denied"), "open")
        sink._log_once(OSError(errno.ENOSPC, "No space left"), "open")

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 5, [r.getMessage() for r in errors]
    text = " | ".join(r.getMessage() for r in errors)
    for code in (errno.ENOSPC, errno.EDQUOT, errno.EIO, errno.EACCES):
        assert f"errno {code}" in text


def test_S_7_an_open_failure_does_not_silence_later_write_failures(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The pod whose hostPath is not yet mounted: one boot-time `OSError` at
    `open` used to permanently suppress every `OSError` at `write`."""
    sink = FileSink(make_config(tmp_path))
    with caplog.at_level(logging.ERROR, logger="audit_logging.sinks.file_sink"):
        sink._log_once(OSError(errno.ENOENT, "No such file or directory"), "open")
        sink._log_once(OSError(errno.ENOSPC, "No space left on device"), "write")

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 2
    assert "open" in errors[0].getMessage()
    assert "write" in errors[1].getMessage()


def test_S_7_the_same_failure_is_still_logged_only_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """FR-21r's actual requirement is unchanged by the finer key."""
    sink = FileSink(make_config(tmp_path))
    with caplog.at_level(logging.ERROR, logger="audit_logging.sinks.file_sink"):
        for _ in range(50):
            sink._log_once(OSError(errno.ENOSPC, "No space left on device"), "write")
    assert len([r for r in caplog.records if r.levelno >= logging.ERROR]) == 1


def test_S_7_the_log_once_key_set_is_bounded(tmp_path: Path) -> None:
    """The key now carries an errno, so the set must not grow without bound."""
    sink = FileSink(make_config(tmp_path))
    for code in range(1, 500):
        sink._log_once(OSError(code, "synthetic"), "write")
    assert len(sink._logged_errors) <= fs._MAX_LOGGED_ERROR_KEYS


# ---------------------------------------------------------------------------
# S-8 — every in-memory byte is under one accounting, and the gauge sees it
# ---------------------------------------------------------------------------


async def test_S_8_the_gauge_sees_a_batch_parked_for_a_retry(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`audit_queue_bytes` used to read 0.00 MiB with a full batch in `_retry`."""
    metrics = InMemoryMetrics()
    sink = make_sink(
        metrics=metrics, flush_interval_seconds=30.0, flush_max_bytes=8 * 1024 * 1024
    )
    await sink.start()
    target_fd = sink._fd

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd:
            return None
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    expected = 0
    for i in range(5):
        expected += line_size(doc(i))
        sink.submit(doc(i))

    await sink._flush_once()  # first attempt: fails, batch is parked

    assert sink._retry is not None, "precondition: a batch is held for a retry"
    assert sink.queued_bytes == 0, "the deque really is empty"
    assert sink.inflight_bytes == expected
    assert sink.held_bytes == expected
    assert metrics.get("audit_queue_bytes") == float(expected), (
        "S-8: the gauge must not read zero while a batch is resident"
    )


async def test_S_8_a_parked_batch_counts_against_queue_max_bytes(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR-18's bound covers everything held, not just the deque."""
    metrics = InMemoryMetrics()
    cap = line_size(doc(0)) * 4
    sink = make_sink(
        metrics=metrics,
        queue_max_bytes=cap,
        flush_max_bytes=cap,
        flush_interval_seconds=30.0,
    )
    await sink.start()
    target_fd = sink._fd

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd:
            return None
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    for i in range(4):
        assert sink.submit(doc(i)) is True
    await sink._flush_once()
    assert sink._retry is not None

    # The queue looks empty, but the sink is still holding 4 documents.
    assert sink.submit(doc(99)) is False, "S-8: an in-flight batch is still ours"
    assert metrics.get("audit_documents_dropped_total") == 1.0
    assert sink.held_bytes <= cap


async def test_S_8_the_gauge_returns_to_zero_once_the_batch_lands(
    make_sink: Callable[..., FileSink],
) -> None:
    metrics = InMemoryMetrics()
    sink = make_sink(metrics=metrics)
    await sink.start()
    for i in range(10):
        sink.submit(doc(i))
    await sink.flush()
    assert sink.inflight_bytes == 0
    assert sink.held_bytes == 0
    assert metrics.get("audit_queue_bytes") == 0.0


async def test_S_8_the_write_payload_copy_is_bounded_by_file_max_bytes(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The third copy A8 measured — `b"".join(batch)` — is now segment-sized.

    With `file_max_bytes` below the batch size, no single `os.write` payload
    can be larger than the file bound, whatever `flush_max_bytes` says.
    """
    limit = 4096
    sink = make_sink(
        file_max_bytes=limit,
        file_backup_count=200,
        flush_interval_seconds=30.0,
        flush_max_bytes=8 * 1024 * 1024,
    )
    await sink.start()
    target_fd: list[int | None] = [sink._fd]
    payloads: list[int] = []

    def hook(fd: int, data: Any) -> int | None:
        if fd == target_fd[0] or fd == sink._fd:
            payloads.append(len(data))
        return None

    patch_os_write(monkeypatch, hook)

    for i in range(400):
        sink.submit(doc(i, pad=200))
    await sink.flush()

    assert payloads, "the write path was not exercised"
    assert max(payloads) <= limit, f"a single os.write carried {max(payloads)} bytes"


# ---------------------------------------------------------------------------
# S-9 / D-A6-1 — audit_documents_failed_total double-counted every document
# ---------------------------------------------------------------------------


async def test_S_9_a_failed_batch_is_counted_once_not_twice(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A8's repro: 10 documents, write always fails, counter read 20."""
    metrics = InMemoryMetrics()
    sink = make_sink(
        metrics=metrics, flush_interval_seconds=30.0, flush_max_bytes=8 * 1024 * 1024
    )
    await sink.start()
    target_fd = sink._fd
    attempts: list[int] = []

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd:
            return None
        attempts.append(len(data))
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    for i in range(10):
        sink.submit(doc(i))
    await sink.flush()

    assert len(attempts) == 2, "still exactly one retry (FR-21r)"
    assert metrics.get("audit_documents_failed_total") == 10.0
    assert metrics.get("audit_documents_dropped_total") == 0.0


async def test_S_9_D_A6_1_one_hundred_and_eighty_lost_documents_report_as_180(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-A6-1 is the same bug as S-9: A6's 180-document repro, scaled down.

    90 batches of 2 into a sink whose every write fails. The old counter said
    360; an operator sizing the incident from it was 2x out.
    """
    metrics = InMemoryMetrics()
    sink = make_sink(
        metrics=metrics, flush_interval_seconds=30.0, flush_max_bytes=8 * 1024 * 1024
    )
    await sink.start()
    target_fd = sink._fd

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd:
            return None
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    submitted = 0
    for _batch in range(90):
        for _ in range(2):
            sink.submit(doc(submitted))
            submitted += 1
        await sink.flush()

    assert submitted == 180
    assert metrics.get("audit_documents_failed_total") == 180.0
    assert read_lines(sink.path) == [], "nothing reached the file"


async def test_S_9_a_batch_that_succeeds_on_the_retry_is_not_counted(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing was lost, so nothing may be counted as lost."""
    metrics = InMemoryMetrics()
    sink = make_sink(
        metrics=metrics, flush_interval_seconds=30.0, flush_max_bytes=8 * 1024 * 1024
    )
    await sink.start()
    target_fd = sink._fd
    failing = [True]

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd or not failing[0]:
            return None
        failing[0] = False
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    for i in range(5):
        sink.submit(doc(i))
    await sink.flush()

    assert metrics.get("audit_documents_failed_total") == 0.0
    assert read_indices(sink.path) == [0, 1, 2, 3, 4]


async def test_S_9_lines_that_landed_before_the_failure_are_neither_lost_nor_doubled(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch split across a rotation can fail halfway. The lines already on
    disk are not counted as failed, and the retry does not write them twice."""
    metrics = InMemoryMetrics()
    size = line_size(fixed_doc(0))
    sink = make_sink(
        metrics=metrics,
        file_max_bytes=size * 2,
        file_backup_count=20,
        flush_interval_seconds=30.0,
        flush_max_bytes=8 * 1024 * 1024,
    )
    await sink.start()

    writes = [0]
    real_rotate = sink._rotate

    def rotate_then_break() -> None:
        writes[0] += 1
        if writes[0] >= 2:
            raise OSError(errno.EACCES, "Permission denied")
        real_rotate()

    monkeypatch.setattr(sink, "_rotate", rotate_then_break)

    for i in range(6):
        sink.submit(fixed_doc(i))
    await sink.flush()

    on_disk: list[int] = []
    for path in all_generations(sink):
        on_disk.extend(read_indices(path))
    lost = metrics.get("audit_documents_failed_total")

    assert len(set(on_disk)) == len(on_disk), f"a line was written twice: {on_disk}"
    assert on_disk, "precondition: the failure happened part-way through"
    assert len(on_disk) + lost == 6, (
        f"{len(on_disk)} landed + {lost} counted lost != 6 submitted"
    )


async def test_S_9_a_cancelled_retry_is_counted_rather_than_lost_silently(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A8's aside: a batch discarded on `CancelledError` *during a retry* was
    the only silent-loss path inside the sink."""
    metrics = InMemoryMetrics()
    sink = make_sink(
        metrics=metrics, flush_interval_seconds=30.0, flush_max_bytes=8 * 1024 * 1024
    )
    await sink.start()
    for i in range(4):
        sink.submit(doc(i))
    sink._retry = sink._drain()
    sink._inflight_bytes = sum(len(x) for x in sink._retry)

    async def cancel(*_args: Any, **_kwargs: Any) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "to_thread", cancel)

    with pytest.raises(asyncio.CancelledError):
        await sink._flush_once()

    assert metrics.get("audit_documents_failed_total") == 4.0
    assert sink.inflight_bytes == 0


# ---------------------------------------------------------------------------
# S-10 / AC-25 — file_max_bytes is a bound
# ---------------------------------------------------------------------------


async def test_S_10_a_fresh_file_still_rotates(
    make_sink: Callable[..., FileSink],
) -> None:
    """The leading `if self._file_bytes and ...` truthiness test was the bug:
    a freshly opened or freshly rotated 0-byte file never rotated, whatever
    the payload size."""
    limit = line_size(fixed_doc(0)) * 2
    metrics = InMemoryMetrics()
    sink = make_sink(
        metrics=metrics,
        file_max_bytes=limit,
        file_backup_count=40,
        flush_interval_seconds=30.0,
        flush_max_bytes=8 * 1024 * 1024,
    )
    await sink.start()
    assert sink.path.stat().st_size == 0, "precondition: the file is empty"

    for i in range(10):  # one batch, 5x the file limit, onto an empty file
        sink.submit(fixed_doc(i))
    await sink.flush()

    assert metrics.get("audit_file_rotations_total") >= 4.0
    for path in all_generations(sink):
        assert path.stat().st_size <= limit, f"{path.name} is over the bound"


async def test_S_10_one_batch_never_pushes_a_file_past_the_bound(
    make_sink: Callable[..., FileSink],
) -> None:
    """A8's repro B: `file_max_bytes=1024`, four flushes of ~2.4 KB each,
    every file came out 2466 bytes."""
    limit = 1024
    sink = make_sink(
        file_max_bytes=limit,
        file_backup_count=40,
        flush_interval_seconds=30.0,
        flush_max_bytes=8 * 1024 * 1024,
    )
    await sink.start()
    for _round in range(4):
        for i in range(26):
            sink.submit(doc(i, pad=60))
        await sink.flush()

    sizes = [p.stat().st_size for p in all_generations(sink)]
    assert sizes, "nothing was written"
    assert max(sizes) <= limit, f"largest file is {max(sizes)} > {limit}"


async def test_S_10_a_line_larger_than_the_bound_lands_alone(
    make_sink: Callable[..., FileSink],
) -> None:
    """AC-25 allows exactly one line of overshoot, and no more."""
    limit = 256
    sink = make_sink(
        file_max_bytes=limit, file_backup_count=10, flush_interval_seconds=30.0
    )
    await sink.start()
    sink.submit(doc(0))
    await sink.flush()
    big = doc(1, pad=4000)
    sink.submit(big)
    await sink.flush()

    for path in all_generations(sink):
        lines = read_lines(path)
        size = path.stat().st_size
        assert size <= limit or len(lines) == 1, (
            f"{path.name} is {size} bytes over a {limit} bound with {len(lines)} lines"
        )
    assert 1 in read_indices(sink.path)


async def test_S_10_no_line_is_split_across_two_files(
    make_sink: Callable[..., FileSink],
) -> None:
    """Splitting a *batch* must never mean splitting a *line*."""
    sink = make_sink(
        file_max_bytes=line_size(fixed_doc(0)) * 3 + 7,  # deliberately unaligned
        file_backup_count=60,
        flush_interval_seconds=30.0,
        flush_max_bytes=8 * 1024 * 1024,
    )
    await sink.start()
    for i in range(120):
        sink.submit(fixed_doc(i))
    await sink.flush()

    seen: list[int] = []
    for path in all_generations(sink):
        for raw in read_lines(path):
            seen.append(int(json.loads(raw)["i"]))  # raises if a line is torn
    assert sorted(seen) == list(range(120))


async def test_S_10_a_batch_that_fits_is_still_one_os_write(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """FR-20r's syscall count survives for every sane configuration: one
    `os.write` per file segment is one per batch when the batch fits."""
    sink = make_sink(file_max_bytes=8 * 1024 * 1024, flush_interval_seconds=30.0)
    await sink.start()
    target_fd = sink._fd
    calls: list[int] = []
    patch_os_write(
        monkeypatch, lambda fd, data: calls.append(len(data)) if fd == target_fd else None
    )
    for i in range(500):
        sink.submit(doc(i))
    await sink.flush()
    assert len(calls) == 1, f"expected one os.write, got {len(calls)}"


async def test_AC_25_file_max_bytes_is_a_bound_under_the_default_flush(
    make_sink: Callable[..., FileSink],
) -> None:
    """AC-25, verbatim: 64 KiB files, the default 4 MiB flush, 2000 documents.

    A8 measured a 1,872,890-byte active file and `rotations = 0`.

    `file_backup_count` is 40 rather than AC-12's 8 because 2000 documents of
    ~940 bytes is 1.8 MB and nine 64 KiB generations physically cannot hold
    them — retention, not the bound, is what would delete lines there.
    """
    metrics = InMemoryMetrics()
    limit = 64 * 1024
    sink = make_sink(
        metrics=metrics,
        file_max_bytes=limit,
        file_backup_count=40,
        flush_max_bytes=4 * 1024 * 1024,
        flush_interval_seconds=30.0,
    )
    await sink.start()
    for i in range(2000):
        assert sink.submit({"@timestamp": "x", "pad": "y" * 900, "i": i}) is True
    await sink.flush()

    generations = all_generations(sink)
    biggest = max(p.stat().st_size for p in generations)
    longest_line = max(
        len(raw.encode()) + 1 for p in generations for raw in read_lines(p)
    )
    seen = sorted(int(json.loads(raw)["i"]) for p in generations for raw in read_lines(p))

    assert biggest <= limit + longest_line, (
        f"AC-25: {biggest} bytes exceeds {limit} by more than one line"
    )
    assert biggest <= limit, "in fact no line here is bigger than the bound"
    assert metrics.get("audit_file_rotations_total") >= 27.0, "rotations are counted"
    assert seen == list(range(2000)), "AC-25: every line survives"


# ---------------------------------------------------------------------------
# S-11 — two FileSinks on one path destroyed 35% of the lines
# ---------------------------------------------------------------------------


async def test_S_11_two_live_sinks_do_not_share_a_path(
    tmp_path: Path,
) -> None:
    """A8's repro: 120 documents submitted, 78 lines survived.

    The trigger is in-process (a mounted sub-application with its own
    middleware, `add_middleware` twice, a test harness) because the PID in
    FR-26's name already separates processes.
    """
    log_dir = tmp_path / "audit"
    config = make_config(
        log_dir,
        service_name="s",
        file_max_bytes=2000,
        file_backup_count=30,
        flush_interval_seconds=0.01,
        flush_max_bytes=256,
    )
    a = FileSink(config, InMemoryMetrics())
    b = FileSink(config, InMemoryMetrics())
    await a.start()
    await b.start()
    try:
        for i in range(60):
            a.submit({"who": "A", "i": i, "pad": "a" * 60})
            b.submit({"who": "B", "i": i, "pad": "b" * 60})
            await asyncio.sleep(0.002)
    finally:
        await a.close()
        await b.close()

    assert a.path != b.path, "S-11: the two sinks must not share a file"
    survived = sum(len(read_lines(p)) for p in log_dir.iterdir())
    assert survived == 120, f"S-11: {survived} of 120 lines survived"


def test_S_11_the_first_sink_keeps_FR_26s_name(tmp_path: Path) -> None:
    """FR-26 is unchanged for the uncontended case, so A5's glob, the runbook
    and `docs/schema.md` all keep describing what is really on disk."""
    sink = FileSink(make_config(tmp_path / "audit"))
    sink._claim_path()
    try:
        assert sink.path.name == f"test-service-{os.getpid()}.jsonl"
    finally:
        sink._release_path()


def test_S_11_a_contending_sink_takes_a_tokenised_name(tmp_path: Path) -> None:
    first = FileSink(make_config(tmp_path / "audit"))
    second = FileSink(make_config(tmp_path / "audit"))
    (tmp_path / "audit").mkdir()
    first._claim_path()
    second._claim_path()
    try:
        assert first.path.name == f"test-service-{os.getpid()}.jsonl"
        assert second.path != first.path
        assert second.path.name.startswith(f"test-service-{os.getpid()}-")
    finally:
        first._release_path()
        second._release_path()


@pytest.mark.parametrize("rotation", ["", ".1", ".8"])
def test_S_11_the_new_name_still_matches_A5s_filebeat_globs(
    tmp_path: Path, rotation: str
) -> None:
    """`infra/filebeat/filebeat.yml`: the input glob is
    `/var/log/audit/*/*.jsonl` and `prospector.scanner.exclude_files` drops
    `\\.jsonl\\.\\d+$`. A tokenised name must behave identically."""
    import fnmatch
    import re

    pod_dir = tmp_path / "audit" / "some-pod-name"
    pod_dir.mkdir(parents=True)
    first = FileSink(make_config(pod_dir))
    second = FileSink(make_config(pod_dir))
    first._claim_path()
    second._claim_path()
    try:
        assert second.path != first.path
        for sink in (first, second):
            name = f"{sink.path}{rotation}"
            matches_input = fnmatch.fnmatch(name, str(tmp_path / "audit" / "*" / "*.jsonl"))
            excluded = re.search(r"\.jsonl\.\d+$", name) is not None
            if rotation:
                assert not matches_input and excluded, name
            else:
                assert matches_input and not excluded, name
    finally:
        first._release_path()
        second._release_path()


async def test_S_11_the_claim_is_released_on_close(tmp_path: Path) -> None:
    """A closed sink is not a live sink: its name is free again."""
    config = make_config(tmp_path / "audit")
    first = FileSink(config)
    await first.start()
    expected = first.path
    await first.close()

    second = FileSink(config)
    await second.start()
    try:
        assert second.path == expected
    finally:
        await second.close()


# ---------------------------------------------------------------------------
# N-8 — submit() after close() was a silent drop
# ---------------------------------------------------------------------------


async def test_N_8_a_post_close_drop_is_counted_separately_and_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """`AGENTS.md` has the middleware close the sink *before* forwarding the
    lifespan shutdown, so requests still completing lose their documents. That
    is not FR-19's "disk is not keeping up" paging event and must not read
    like one."""
    metrics = InMemoryMetrics()
    sink = FileSink(make_config(tmp_path), metrics)
    await sink.start()
    await sink.close()

    with caplog.at_level(logging.WARNING, logger="audit_logging.sinks.file_sink"):
        for i in range(5):
            assert sink.submit(doc(i)) is False

    assert sink.dropped_after_close == 5
    assert metrics.get("audit_documents_dropped_after_close_total") == 5.0
    # The two counters are disjoint. This used to assert 5.0 here, back when
    # the post-close name was not yet in METRIC_NAMES and FR-19's counter was
    # the only frozen place to put the number. Both names exist now, and a
    # clean shutdown must not move the counter an operator pages on.
    assert metrics.get("audit_documents_dropped_total") == 0.0, (
        "a graceful shutdown is not disk pressure: it must not tick FR-19's "
        "dropped counter, or every alert on that counter has to subtract this "
        "one first"
    )
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1, "one WARN per sink, not one per document"
    assert "shutdown window" in warnings[0].getMessage()


async def test_N_8_a_normal_queue_full_drop_is_not_a_post_close_drop(
    make_sink: Callable[..., FileSink],
) -> None:
    metrics = InMemoryMetrics()
    cap = line_size(doc(0))
    sink = make_sink(metrics=metrics, queue_max_bytes=cap, flush_max_bytes=cap)
    sink.submit(doc(0))
    assert sink.submit(doc(1)) is False
    assert metrics.get("audit_documents_dropped_total") == 1.0
    assert metrics.get("audit_documents_dropped_after_close_total") == 0.0
    assert sink.dropped_after_close == 0
    # The other direction of the same disjointness.
    assert sink.submit(doc(2)) is False
    assert metrics.get("audit_documents_dropped_total") == 2.0
    assert metrics.get("audit_documents_dropped_after_close_total") == 0.0


# ---------------------------------------------------------------------------
# The byte-accounting names an operator reads under pressure
# ---------------------------------------------------------------------------


async def test_the_three_byte_counts_add_up(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`held_bytes == queued_bytes + inflight_bytes`, with a batch in flight.

    The total used to be `queue_bytes`, one letter from `queued_bytes` and
    meaning something else entirely — the deque alone versus everything the
    sink is holding. Same numbers, names that cannot be misread.
    """
    metrics = InMemoryMetrics()
    sink = make_sink(metrics=metrics, flush_interval_seconds=30.0)
    await sink.start()

    for i in range(4):
        assert sink.submit(doc(i))
    queued = sink.queued_bytes
    assert queued > 0
    assert sink.inflight_bytes == 0
    assert sink.held_bytes == queued
    assert sink.queue_depth == 4, "documents, not bytes"

    # Park the batch in flight: `_drain` moves the bytes but does not lose them.
    batch = sink._drain()
    assert sink.queued_bytes == 0
    assert sink.inflight_bytes == queued
    assert sink.held_bytes == queued, "held_bytes still sees the batch (S-8)"
    assert sink.held_bytes == sink.queued_bytes + sink.inflight_bytes

    sink._inflight_bytes = 0
    del batch
    sink._publish_queue_bytes()
    assert metrics.get("audit_queue_bytes") == 0.0


async def test_the_frozen_gauge_name_reports_held_bytes(
    make_sink: Callable[..., FileSink],
) -> None:
    """`audit_queue_bytes` is frozen in METRIC_NAMES and keeps its spelling;
    what it reports is `held_bytes`, not `queued_bytes`."""
    metrics = InMemoryMetrics()
    sink = make_sink(metrics=metrics, flush_interval_seconds=30.0)
    for i in range(3):
        sink.submit(doc(i))
    sink._drain()  # everything is now in flight, nothing is queued
    sink._publish_queue_bytes()
    assert sink.queued_bytes == 0
    assert metrics.get("audit_queue_bytes") == float(sink.held_bytes)
    assert metrics.get("audit_queue_bytes") != float(sink.queued_bytes)
    sink._inflight_bytes = 0


# ---------------------------------------------------------------------------
# D-A6-5 — a reopen racing a rotation used to steal the file (FR-22 bound)
# ---------------------------------------------------------------------------


async def test_D_A6_5_a_reopen_during_rotation_cannot_take_the_file(
    make_sink: Callable[..., FileSink], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The race, forced rather than waited for.

    `_rotate` runs on the `asyncio.to_thread` worker and `_ensure_open` runs on
    the event loop (`start()`, and `flush()` before the first write). Before
    the fix the rotation's close -> rename -> reopen was three separate steps
    and the loop could squeeze in between the first two: it resolved the base
    name to the *pre-rename* inode, installed an fd on it, and the worker's own
    reopen then found an fd already there and did nothing. The worker went on
    appending to a file that had just been renamed to `.1`, believing it was
    empty — so one generation reached 2x `file_max_bytes`, and no new base file
    existed at all, which is the gap A6 saw in the `.N` numbering.

    A6 hit it about one run in three. Here `os.replace` is held open on an
    event, so the interleaving is guaranteed: unfixed code fails this every
    time, fixed code cannot reach the state at all. The watchdog timer exists
    so that the fixed code — where the `_ensure_open` below blocks on
    `_open_lock` until the rotation finishes, which is the whole point — cannot
    deadlock the test.
    """
    limit = 4096
    per_line = 128
    sink = make_sink(
        file_max_bytes=limit, file_backup_count=5, flush_interval_seconds=30.0
    )
    await sink.start()
    base = sink.path

    # Fill the active file to just under the bound: 30 x 128 B = 3840 B.
    first = [fs._dumps(fixed_doc(i, per_line)) + b"\n" for i in range(30)]
    await asyncio.to_thread(sink._write_batch, first)
    assert sink.rotations == 0
    assert base.stat().st_size == 30 * per_line

    rotating = threading.Event()
    release = threading.Event()
    real_replace = os.replace

    def blocking_replace(src: Any, dst: Any) -> None:
        if str(src) == str(base):
            # The fd is already closed and the file is not yet renamed: the
            # exact instant A6's MainThread `_ensure_open` landed in.
            rotating.set()
            release.wait(5.0)
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", blocking_replace)

    # 10 more lines do not fit, so `_write_batch` closes the file out first.
    second = [fs._dumps(fixed_doc(30 + i, per_line)) + b"\n" for i in range(10)]
    writer = asyncio.create_task(asyncio.to_thread(sink._write_batch, second))
    deadline = time.monotonic() + 5.0
    while not rotating.is_set():
        assert time.monotonic() < deadline, "the rotation never reached os.replace"
        await asyncio.sleep(0.005)

    assert sink._fd is None, "the premise: the rotation has closed the file"
    threading.Timer(0.5, release.set).start()
    began = time.monotonic()
    sink._ensure_open()  # on the event loop thread, exactly like start()
    waited = time.monotonic() - began
    release.set()
    await writer

    assert sink.rotations == 1
    assert base.exists(), (
        "D-A6-5: the rotation left no active file; the reopen took the inode "
        f"that was renamed away. On disk: {sorted(p.name for p in base.parent.iterdir())}"
    )
    assert rotated_indices(sink) == [1], "the .N sequence has no gaps"
    sizes = generation_sizes(sink)
    for name, size in sizes.items():
        assert size <= limit + per_line, (
            f"FR-22: {name} is {size} B against a {limit} B bound (+ one "
            f"{per_line} B line); D-A6-5 doubles a generation"
        )
    assert sizes[base.name] == 10 * per_line
    ordered = read_indices(Path(f"{base}.1")) + read_indices(base)
    assert ordered == list(range(40)), "and not one line moved or vanished"
    # The mechanism, corroborating the outcome above: the reopen has to have
    # waited for the rotation (the watchdog releases it at 0.5 s), not slipped
    # between the close and the rename.
    assert waited > 0.05, (
        f"D-A6-5: _ensure_open returned in {waited * 1e3:.2f} ms while a "
        "rotation was mid-flight; it must wait for close -> rename -> reopen "
        "to finish, not observe the file part-way through it"
    )


async def test_D_A6_5_many_rotations_keep_the_bound_and_the_numbering(
    make_sink: Callable[..., FileSink],
) -> None:
    """The symptom itself, asserted: no oversized generation, no gap in `.N`.

    This is the plain property AC-25's bound clause could not see, because it
    only ever looked at the files it could *find* by walking `.1`, `.2`, … and
    stopping at the first missing number. A background task calls
    `_ensure_open` from the event loop throughout — the same call `start()` and
    `flush()` make — so a rotation that is not atomic gets many chances to be
    caught in the act.
    """
    limit = 8 * 1024
    per_line = 128
    total = 400  # 51200 B => ~6 rotations
    sink = make_sink(
        file_max_bytes=limit,
        file_backup_count=64,
        flush_max_bytes=4 * 1024,
        flush_interval_seconds=30.0,
        queue_max_bytes=4 * 1024 * 1024,
    )
    await sink.start()

    running = True

    async def churn() -> None:
        while running:
            sink._ensure_open()
            await asyncio.sleep(0)

    churning = asyncio.create_task(churn())
    try:
        for i in range(total):
            assert sink.submit(fixed_doc(i, per_line))
            if i % 8 == 7:
                await sink.flush()
        await sink.flush()
    finally:
        running = False
        await churning

    assert sink.rotations >= 5, "the premise: this run has to rotate many times"
    indices = rotated_indices(sink)
    assert indices == list(range(1, len(indices) + 1)), (
        f"FR-22: the .N sequence has gaps at "
        f"{sorted(set(range(1, max(indices) + 1)) - set(indices))}"
    )
    assert len(indices) == sink.rotations, "one generation per rotation, all kept"
    sizes = generation_sizes(sink)
    for name, size in sizes.items():
        assert size <= limit + per_line, (
            f"FR-22: {name} is {size} B, over the {limit} B bound by more than "
            f"one {per_line} B line. All: {sizes}"
        )
    ordered: list[int] = []
    for index in sorted(indices, reverse=True):
        ordered += read_indices(Path(f"{sink.path}.{index}"))
    ordered += read_indices(sink.path)
    assert ordered == list(range(total)), "FR-20r: submission order across rotations"


def open_fds_under(directory: Path) -> list[str]:
    """Every fd this process holds on a file inside ``directory`` (Linux)."""
    fd_dir = Path("/proc/self/fd")
    if not fd_dir.exists():  # pragma: no cover - non-Linux
        return []
    found: list[str] = []
    for entry in fd_dir.iterdir():
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        if target.startswith(str(directory) + os.sep):
            found.append(target)
    return sorted(found)


async def test_shutdown_during_a_rotation_leaves_no_file_and_no_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`close()` is terminal even for a rotation that outlives it (D-A6-6).

    FR-27 lets `close()` return on a timeout, and cancelling the flusher task
    does *not* stop the worker thread parked inside `asyncio.to_thread` — so a
    rotation can still be sitting in `os.replace` when `close()` has already
    run `_close_fd` and `_release_path`. That rotation then reopened the file
    it had just renamed away: a live fd on a sink the application believes is
    shut down, a re-created active file no one will ever drain, and an S-11
    path claim re-added to the process-wide registry *after* `close()` gave it
    up, so the next sink on that path would take a tokenised name forever.

    `close()` cannot take `_open_lock` to prevent this — that is the very lock
    the stuck rotation is holding, and blocking on it would break the bound
    FR-27 exists for. The `_terminated` flag is the synchronisation instead.
    Here the rename is held past the shutdown timeout, so the interleaving is
    guaranteed rather than hoped for.
    """
    log_dir = tmp_path / "audit"
    limit = 4096
    per_line = 128
    metrics = InMemoryMetrics()
    sink = FileSink(
        make_config(
            log_dir,
            file_max_bytes=limit,
            file_backup_count=5,
            flush_max_bytes=16 * 1024 * 1024,  # no size-triggered early flush
            flush_interval_seconds=30.0,
            shutdown_flush_timeout=0.3,
        ),
        metrics,
    )
    await sink.start()
    base = sink.path
    assert str(base) in fs._CLAIMED_PATHS

    # Fill the active file to just under the bound, so the queued batch below
    # cannot fit and `_write_batch` must rotate first.
    first = [fs._dumps(fixed_doc(i, per_line)) + b"\n" for i in range(30)]
    await asyncio.to_thread(sink._write_batch, first)
    assert sink.rotations == 0

    rotating = threading.Event()
    real_replace = os.replace

    def slow_replace(src: Any, dst: Any) -> None:
        if str(src) == str(base):
            rotating.set()
            # Outlives shutdown_flush_timeout, so close() returns first.
            time.sleep(1.0)
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", slow_replace)

    for i in range(10):
        assert sink.submit(fixed_doc(30 + i, per_line))

    began = time.monotonic()
    await sink.close()
    closed_after = time.monotonic() - began
    assert closed_after < 2.0, (
        f"FR-27: close() took {closed_after:.2f}s — it must not block on the "
        "rotation's lock"
    )
    assert rotating.is_set(), "the premise: a rotation was in flight at shutdown"
    assert sink._fd is None

    # Let the stranded rotation finish. `rotations` is incremented after the
    # reopen, so it is the point at which the worker is done with the file.
    deadline = time.monotonic() + 5.0
    while sink.rotations < 1:
        assert time.monotonic() < deadline, "the rotation never completed"
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.1)  # and past the rest of _write_batch

    assert sink._fd is None, (
        "D-A6-6: the rotation reopened the file after close() returned — the "
        "sink owns a live fd nothing will ever close"
    )
    assert open_fds_under(log_dir) == [], (
        f"D-A6-6: leaked fd(s) on {log_dir} after close(): "
        f"{open_fds_under(log_dir)}"
    )
    assert not base.exists(), (
        "D-A6-6: close() tore the sink down and the rotation put the active "
        f"file back. On disk: {sorted(p.name for p in log_dir.iterdir())}"
    )
    assert str(base) not in fs._CLAIMED_PATHS, (
        "S-11: the path claim was re-taken after close() released it, so it is "
        "now leaked for the life of the process"
    )
    assert Path(f"{base}.1").exists(), "the rename itself still completed"


async def test_shutdown_is_terminal_for_a_later_flush(tmp_path: Path) -> None:
    """A `flush()` after `close()` writes nothing and reopens nothing.

    The same `_terminated` guard, reached the easy way. `start()` after
    `close()` is already a no-op (FR-27), so a closed sink is terminal in both
    directions and never resurrects its file.
    """
    metrics = InMemoryMetrics()
    sink = FileSink(make_config(tmp_path, flush_interval_seconds=30.0), metrics)
    await sink.start()
    sink.submit(doc(0))
    await sink.close()
    assert read_indices(sink.path) == [0]
    sink.path.unlink()

    # submit() refuses (N-8), so put a line in the queue directly to prove the
    # write path itself refuses too.
    sink._queue.append(fs._dumps(doc(1)) + b"\n")
    sink._queue_bytes = len(sink._queue[0])
    await sink.flush()

    assert sink._fd is None
    assert not sink.path.exists(), "a closed sink must not re-create its file"
    await sink.start()
    assert sink._task is None, "FR-27: start() after close() stays a no-op"


# ---------------------------------------------------------------------------
# AC-26 — bounded shutdown, honest failure count, bounded memory
# ---------------------------------------------------------------------------


async def test_AC_26_close_is_bounded_and_the_failure_count_is_honest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-26: sustained load, a failing disk, then `close()`."""
    metrics = InMemoryMetrics()
    sink = FileSink(
        make_config(
            tmp_path,
            flush_interval_seconds=0.01,
            shutdown_flush_timeout=3.0,
            queue_max_bytes=4 * 1024 * 1024,
            flush_max_bytes=64 * 1024,
        ),
        metrics,
    )
    await sink.start()
    target_fd = sink._fd

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd:
            return None
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    accepted = 0
    for i in range(400):
        if sink.submit(doc(i, pad=100)):
            accepted += 1
        if i % 25 == 0:
            await asyncio.sleep(0.005)

    started = time.monotonic()
    await sink.close()
    elapsed = time.monotonic() - started

    assert elapsed < 3.0 + 1.0, f"FR-27: close() took {elapsed:.2f}s"
    landed = len(read_lines(sink.path))
    failed = metrics.get("audit_documents_failed_total")
    dropped = metrics.get("audit_documents_dropped_total")
    assert landed == 0, "the disk was dead throughout"
    assert failed == float(accepted), (
        f"AC-26: {failed} counted failed, {accepted} accepted and lost"
    )
    assert failed + dropped == 400.0, "every submitted document is accounted for"


async def test_AC_26_in_memory_bytes_stay_within_twice_queue_max_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-26's memory half, measured in bytes the sink can actually be holding.

    A8 measured 3x `queue_max_bytes` of RSS with a batch in flight, a batch in
    `_retry` and a `b"".join` copy, none of which the gauge could see.
    """
    metrics = InMemoryMetrics()
    cap = 512 * 1024
    file_limit = 64 * 1024
    sink = FileSink(
        make_config(
            tmp_path,
            queue_max_bytes=cap,
            flush_max_bytes=cap,
            file_max_bytes=file_limit,
            file_backup_count=50,
            flush_interval_seconds=30.0,
        ),
        metrics,
    )
    await sink.start()
    target_fd = sink._fd
    biggest_payload = [0]
    release = threading.Event()

    def hook(fd: int, data: Any) -> int | None:
        if fd != target_fd:
            return None
        biggest_payload[0] = max(biggest_payload[0], len(data))
        release.wait(2.0)
        raise OSError(errno.ENOSPC, "No space left on device")

    patch_os_write(monkeypatch, hook)

    document = doc(0, pad=900)
    while sink.submit(document):
        pass
    first_fill = sink.held_bytes
    assert first_fill <= cap

    flushing = asyncio.create_task(sink._flush_once())
    await asyncio.sleep(0.2)  # the batch is in the worker thread now

    refilled = 0
    while sink.submit(document):
        refilled += 1
    held = sink.held_bytes

    assert held <= cap, f"S-8/AC-26: the sink is holding {held} against a {cap} bound"
    assert metrics.get("audit_queue_bytes") == float(held), "the gauge tells the truth"
    assert refilled == 0, "an in-flight batch leaves no room, and says so"

    release.set()
    await flushing
    assert biggest_payload[0] <= file_limit, (
        "the join copy is bounded by file_max_bytes, so the true ceiling is "
        f"cap + {file_limit} < 2 x cap"
    )
    assert sink.held_bytes <= cap
    sink._queue.clear()
    sink._queue_bytes = 0
    sink._retry = None
    sink._inflight_bytes = 0
    await sink.close()


async def test_submit_stays_cheap_after_the_fixes(
    make_sink: Callable[..., FileSink],
) -> None:
    """NFR-2 re-measured: the S-8 accounting adds one add to the hot path."""
    sink = make_sink(queue_max_bytes=256 * 1024 * 1024, flush_max_bytes=64 * 1024 * 1024)
    await sink.start()
    payload = doc(0, pad=2048)
    for _ in range(200):
        sink.submit(payload)
    sink._drain()
    sink._inflight_bytes = 0

    started = time.perf_counter()
    rounds = 5000
    for _ in range(rounds):
        sink.submit(payload)
    per_call_us = (time.perf_counter() - started) / rounds * 1e6
    sink._drain()
    sink._inflight_bytes = 0
    assert per_call_us < 200, f"submit() took {per_call_us:.1f} us"


# ---------------------------------------------------------------------------
# N2-1 — a lone surrogate in a value used to delete its own audit record
# ---------------------------------------------------------------------------
#
# `{"a":"\ud800"}` is 14 bytes and any client can send it. `orjson.dumps`
# refuses a lone surrogate — and refuses it *without consulting* `default=`,
# because a `str` holding one is not a type error — so `_dumps` raised, and
# `submit()` swallowed the exception and counted it as queue pressure. Two
# separate defects: the record was lost (FR-01), and the loss was filed under
# FR-19's page-me counter, so an attacker could point an operator at the disk
# or mask a genuine disk alert at will.

SURROGATE_PLACEMENTS: list[tuple[str, dict[str, Any]]] = [
    ("bare value", {"a": "\ud800"}),
    ("nested in a list", {"a": {"b": ["\udfff"]}}),
    ("high and low apart", {"a": "\ud800x\udc00"}),
    ("in a key", {"\ud800": 1}),
    ("in a key and a value", {"\ud800": "\udfff"}),
]


@pytest.mark.parametrize(
    "where,document", SURROGATE_PLACEMENTS, ids=[p[0] for p in SURROGATE_PLACEMENTS]
)
def test_N2_1_dumps_never_raises_on_a_lone_surrogate(
    where: str, document: dict[str, Any]
) -> None:
    """Every placement the reviewer swept, and the line stays one valid JSON."""
    line = fs._dumps(document)
    assert isinstance(line, bytes)
    assert b"\n" not in line, "a document must never break the JSONL line"
    line.decode("utf-8")  # strict: the bytes really are UTF-8
    parsed = json.loads(line)
    assert isinstance(parsed, dict)


@pytest.mark.parametrize(
    "where,document", SURROGATE_PLACEMENTS, ids=[p[0] for p in SURROGATE_PLACEMENTS]
)
def test_N2_1_both_backends_agree_on_a_lone_surrogate(
    where: str, document: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback must not make the on-disk format depend on the backend."""
    pytest.importorskip("orjson")
    assert fs._ORJSON is not None
    with_orjson = fs._dumps(document)
    monkeypatch.setattr(fs, "_ORJSON", None)
    without_orjson = fs._dumps(document)
    assert with_orjson == without_orjson


async def test_N2_1_a_surrogate_body_does_not_delete_its_audit_record(
    tmp_path: Path,
) -> None:
    """FR-01: one line on disk per submitted document, whatever the body.

    The reviewer's repro exactly: two documents in, one line out, and the
    missing one counted as disk pressure.
    """
    metrics = InMemoryMetrics()
    sink = FileSink(make_config(tmp_path, flush_interval_seconds=30.0), metrics)
    await sink.start()

    assert sink.submit({"i": 0}) is True
    assert sink.submit({"i": 1, "a": "\ud800"}) is True, (
        "N2-1: a 14-byte body took its own audit record out"
    )
    await sink.close()

    lines = read_lines(sink.path)
    assert len(lines) == 2, f"N2-1: {len(lines)} line(s) on disk for 2 documents"
    assert read_indices(sink.path) == [0, 1]
    assert json.loads(lines[1])["a"] == "?", "the surrogate itself is replaced"
    assert metrics.get("audit_documents_submitted_total") == 2.0
    assert metrics.get("audit_documents_dropped_total") == 0.0, (
        "N2-1: a client-chosen body must not tick FR-19's disk-pressure counter"
    )
    assert metrics.get("audit_documents_failed_total") == 0.0
    assert sink.serialisation_failures == 0


def test_N2_1_a_serialisation_failure_is_not_a_queue_pressure_drop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The misattribution, fixed independently of the fallback.

    Forced rather than found: after the fallback, no realistic document
    reaches this path at all, and the counter it lands on is the half of N2-1
    that must hold even if some *future* document does.
    """

    def refuse(document: dict[str, Any]) -> bytes:
        raise TypeError("nothing will serialise this")

    monkeypatch.setattr(fs, "_dumps", refuse)
    metrics = InMemoryMetrics()
    sink = FileSink(make_config(tmp_path), metrics)

    with caplog.at_level(logging.ERROR, logger="audit_logging.sinks.file_sink"):
        assert sink.submit({"i": 0}) is False

    assert metrics.get("audit_documents_dropped_total") == 0.0, (
        "N2-1: 'the disk is not keeping up' (FR-19) must not tick because a "
        "document could not be encoded — that is not what it means, and an "
        "operator paged by it would look at the wrong subsystem"
    )
    assert metrics.get("audit_documents_failed_total") == 1.0, (
        "a document the sink held and could not write is a *failed* document"
    )
    assert metrics.get("audit_documents_submitted_total") == 0.0
    assert metrics.get("audit_documents_dropped_after_close_total") == 0.0
    assert sink.serialisation_failures == 1
    assert sink.queue_depth == 0
    assert any("serialise" in record.getMessage() for record in caplog.records), (
        "and it is visible in the log, once per distinct failure (FR-21r)"
    )


def test_N2_1_the_two_loss_counters_stay_disjoint(tmp_path: Path) -> None:
    """dropped / dropped_after_close / failed each mean one thing (FR-19)."""
    metrics = InMemoryMetrics()
    tiny = line_size(doc(0)) - 1
    sink = FileSink(
        make_config(tmp_path, queue_max_bytes=tiny, flush_max_bytes=tiny), metrics
    )
    assert sink.submit(doc(0)) is False  # queue pressure
    assert metrics.get("audit_documents_dropped_total") == 1.0
    assert metrics.get("audit_documents_failed_total") == 0.0
    assert metrics.get("audit_documents_dropped_after_close_total") == 0.0

    sink._closed = True
    assert sink.submit(doc(1)) is False  # shutdown window
    assert metrics.get("audit_documents_dropped_total") == 1.0, "still just the one"
    assert metrics.get("audit_documents_dropped_after_close_total") == 1.0
    assert metrics.get("audit_documents_failed_total") == 0.0


# ---------------------------------------------------------------------------
# N2-5 — close() used to free an fd number a worker was still writing to
# ---------------------------------------------------------------------------


async def test_N2_5_a_write_outliving_close_cannot_land_in_another_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit documents appended to an unrelated file, forced deterministically.

    FR-27 lets `close()` return on a timeout and cancelling the flusher does
    not stop the thread parked in `asyncio.to_thread`, so a worker really can
    be inside `os.write` when `close()` runs `_close_fd`. Closing the
    descriptor there frees the *number*: the kernel hands the same integer to
    the next `os.open` in the process and the straggling write lands in that
    file. The reviewer saw five whole audit documents appended to an unrelated
    file with the audit file left at 0 bytes.

    The interleaving is forced, not waited for: `os.write` on the sink's own fd
    parks on an event until well past `shutdown_flush_timeout`, so `close()`
    always returns first and the victim file is always opened while the write
    is still in flight.
    """
    log_dir = tmp_path / "audit"
    metrics = InMemoryMetrics()
    sink = FileSink(
        make_config(
            log_dir,
            flush_interval_seconds=0.02,
            shutdown_flush_timeout=0.2,
            flush_max_bytes=16 * 1024 * 1024,
        ),
        metrics,
    )
    await sink.start()
    audit_fd = sink._fd
    assert audit_fd is not None

    writing = threading.Event()
    release = threading.Event()

    def hook(fd: int, data: Any) -> int | None:
        if fd != audit_fd:
            return None
        writing.set()
        release.wait(10.0)  # outlives shutdown_flush_timeout by a long way
        return None  # then do the real write, on whatever fd now is

    patch_os_write(monkeypatch, hook)

    for i in range(5):
        assert sink.submit(doc(i, pad=64)) is True

    deadline = time.monotonic() + 5.0
    while not writing.is_set():
        assert time.monotonic() < deadline, "the worker never reached os.write"
        await asyncio.sleep(0.005)

    began = time.monotonic()
    await sink.close()
    closed_after = time.monotonic() - began
    assert closed_after < 2.0, (
        f"FR-27: close() took {closed_after:.2f}s — it must not block on the "
        "in-flight write"
    )
    assert sink._fd is None, "the sink itself has let the descriptor go"

    # The mechanism, recorded now and asserted at the end so that the symptom
    # below is the first thing a failure shows: the number is still ours, so
    # nothing else in the process can be handed it.
    link = Path(f"/proc/self/fd/{audit_fd}")
    still_ours = link.exists() and os.readlink(link) == str(sink.path)

    # The symptom: an unrelated file opened during shutdown, exactly as the
    # reviewer's repro did.
    victim_path = tmp_path / "VICTIM.txt"
    victim_fd = os.open(victim_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        recycled = victim_fd == audit_fd
        os.write(victim_fd, b"IMPORTANT APPLICATION DATA\n")
    finally:
        os.close(victim_fd)

    release.set()
    deadline = time.monotonic() + 5.0
    while link.exists():
        assert time.monotonic() < deadline, (
            "the writer never released the descriptor it owns"
        )
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.05)  # and past the rest of _write_batch

    assert victim_path.read_bytes() == b"IMPORTANT APPLICATION DATA\n", (
        f"N2-5: audit documents were appended to an unrelated file (it was "
        f"handed fd {victim_fd}, the audit fd was {audit_fd}):\n"
        + victim_path.read_text()
    )
    assert not recycled, (
        f"N2-5: the victim file was handed fd {victim_fd} — the very number "
        "the in-flight audit write was aimed at"
    )
    assert still_ours, (
        f"N2-5: fd {audit_fd} was closed while a worker was inside os.write on "
        "it; the number was free for the kernel to hand to the next open"
    )
    assert read_indices(sink.path) == list(range(5)), (
        "and the lines went where they were always meant to go"
    )


async def test_N2_5_the_common_close_still_releases_the_descriptor(
    tmp_path: Path,
) -> None:
    """No writer, no deferral: `close()` closes, exactly as it always did.

    The fd handover must not turn every clean shutdown into a leak — that is
    the whole reason the trade in `_close_fd` is affordable.
    """
    log_dir = tmp_path / "audit"
    sink = FileSink(make_config(log_dir, flush_interval_seconds=30.0), InMemoryMetrics())
    await sink.start()
    for i in range(5):
        sink.submit(doc(i))
    await sink.close()

    assert sink._fd is None
    assert sink._writers == 0
    assert sink._orphan_fds == set()
    assert open_fds_under(log_dir) == [], (
        f"leaked fd(s) after a clean close: {open_fds_under(log_dir)}"
    )
    assert read_indices(sink.path) == list(range(5))


async def test_N2_5_close_does_not_wait_on_the_fd_handover(tmp_path: Path) -> None:
    """`_fd_lock` is bookkeeping only, so FR-27's bound cannot hide behind it.

    A thread that borrows the descriptor and never gives it back is exactly the
    stalled-disk case; `close()` must still return promptly.
    """
    sink = FileSink(
        make_config(tmp_path, flush_interval_seconds=30.0, shutdown_flush_timeout=0.2),
        InMemoryMetrics(),
    )
    await sink.start()
    borrowed = sink._acquire_fd()
    assert borrowed is not None

    began = time.monotonic()
    await sink.close()
    elapsed = time.monotonic() - began
    assert elapsed < 1.0, f"FR-27: close() took {elapsed:.2f}s"
    assert sink._fd is None
    assert sink._orphan_fds == {borrowed}, (
        "the descriptor is retired but not closed: the writer owns it now"
    )

    sink._release_fd()
    assert sink._orphan_fds == set()
    with pytest.raises(OSError):
        os.fstat(borrowed)
