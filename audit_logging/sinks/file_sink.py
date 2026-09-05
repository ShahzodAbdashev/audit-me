"""``FileSink`` — byte-bounded queue to a rotating JSONL file.

Owned by **Agent A4**. See plan §4.2 and ``docs/REQUIREMENTS.md``
FR-18…FR-22, FR-26, FR-27.

Shape of the thing
------------------

``submit()`` is the only method on the request path. It serialises the
document to one JSON line, appends the bytes to a ``collections.deque`` and
returns. No awaits, no locks, no I/O, no exceptions — a line that would push
the queue past ``queue_max_bytes`` is dropped and counted instead (FR-18,
FR-19, NFR-2).

Everything expensive happens in one background ``asyncio.Task``: it wakes on
``flush_interval_seconds`` *or* immediately when ``submit`` signals that the
queue passed ``flush_max_bytes``, drains the deque in submission order, and
hands the joined bytes to a worker thread that does one ``os.write``
(FR-20r). The write lives in a thread so that a blocked disk cannot wedge the
event loop and so that ``close()`` can actually honour its timeout (FR-27).

Which thread touches what
-------------------------

Three threads reach this object. The **request thread** only ever runs
``submit`` (a serialise and a ``deque.append`` — no lock, no I/O). The **event
loop** runs the lifecycle and the flusher. The **worker thread** behind
``asyncio.to_thread`` does every write and every rotation. Only the last two
touch the file, and everything that changes the sink's *file identity* — the
open in ``_ensure_open``, the whole close/rename/reopen in ``_rotate`` — runs
under ``_open_lock`` so that neither thread can see the file part-way through
a rotation (review D-A6-5). That lock is never taken on the request path — and
never by ``close()`` either, which must stay bounded (FR-27) and so tells a
still-running rotation that the sink is gone with the ``_terminated`` flag
instead (review D-A6-6). ``close()`` is terminal: nothing reopens after it.

Who closes the descriptor
-------------------------

``close()`` may return while a write is still in flight — that is the point of
FR-27's timeout, and cancelling the flusher does not stop the thread parked in
``asyncio.to_thread``. So **the writer owns the close**, not ``close()``. A
write borrows the fd across ``_acquire_fd``/``_release_fd``; ``_close_fd``
takes the fd out of the sink and, if a writer is holding it, leaves the number
allocated and hands the close to that writer instead (review N2-5). Closing it
underneath a live ``os.write`` frees the *number*, the kernel hands the same
integer to the next ``os.open`` or ``accept``, and the in-flight write lands in
an unrelated file or socket — audit content emitted somewhere it was never
meant to go. The deliberate cost is that a write which never returns leaves one
descriptor unclosed for the remaining life of a process that is already
exiting; ``_close_fd`` documents that trade. The handover lock (``_fd_lock``)
is never held across a syscall, so ``close()`` cannot block behind a stalled
disk on it.

Two bounds, and what "one ``os.write``" now means
-------------------------------------------------

``file_max_bytes`` is a **bound**, not a hint (FR-22, AC-25). The active file
is closed out when it cannot take the whole batch, and a batch too big for an
empty file is written in *segments* — as many whole lines as fit, one
``os.write`` per segment, a rotation between segments. So the FR-20r guarantee
is one ``os.write`` **per file segment**, which whenever ``flush_max_bytes <=
file_max_bytes`` (the shipped defaults included) is still exactly one
``os.write`` per batch. A line is never split across two files, and only a
line that is itself larger than ``file_max_bytes`` can push a file past the
bound — by that one line, which is what AC-25 allows.

``queue_max_bytes`` is likewise a bound on **everything the sink holds**, not
just on the deque (FR-18, AC-26; review S-8). ``held_bytes`` and the
``audit_queue_bytes`` gauge count the queued lines *plus* the batch currently
being written or parked for a retry. The only audit bytes outside that count
are the joined payload handed to ``os.write``, which segmenting bounds at
``max(file_max_bytes, one line)``. Peak in-memory is therefore

    queue_max_bytes + min(queue_max_bytes, max(file_max_bytes, one line))

i.e. at most **2×** ``queue_max_bytes``, and less than that whenever
``file_max_bytes`` is the smaller number.

Serialisation policy for values JSON has no opinion about (all of these keep
the output strictly valid JSON, one document per line):

===========================  ============================================
value                        written as
===========================  ============================================
``NaN`` / ``±Infinity``      ``null`` (stdlib's bare ``NaN`` is not JSON)
lone surrogates              ``?`` (UTF-8 cannot express them at all)
``bytes`` / ``bytearray``    UTF-8 text, else ``"base64:<...>"``
``datetime`` / ``date``      ``.isoformat()``
``Decimal``                  the exact value as a string
``set`` / ``frozenset``      a list
``UUID``                     ``str(uuid)``
anything else                ``str(obj)``, else ``"<unserialisable T>"``
===========================  ============================================

The ``orjson`` and stdlib paths are deliberately routed through the same
``default`` hook (``OPT_PASSTHROUGH_DATETIME``/``DATACLASS``) so the two
produce byte-identical lines — which is also what lets the stdlib encoder be
``orjson``'s *fallback* rather than merely its alternative. It has to be:
``orjson`` refuses some input without ever consulting ``default``, and a
document that cannot be serialised must never be a document that is lost
(review N2-1). No document reaches ``submit``'s failure path for being
awkward; and one that does is counted as **failed**, not dropped, because
``audit_documents_dropped_total`` means "the disk is not keeping up" (FR-19)
and nothing else may be allowed to make it tick.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import datetime as _dt
import decimal
import json
import logging
import math
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from .._contracts import Metrics, Sink
from ..config import AuditConfig
from ..metrics import InMemoryMetrics

__all__ = ["FileSink"]

logger = logging.getLogger(__name__)

#: Characters kept verbatim in the file name built from ``service_name``.
_SAFE_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
)

#: Guard on the ``_flush_all`` loop so a pathological caller cannot spin.
_MAX_FLUSH_ROUNDS = 64

#: Depth cap for the NaN-sanitising fallback (also terminates cyclic input).
_SANITISE_MAX_DEPTH = 64

#: How many distinct ``_log_once`` keys a process will ever emit. The key now
#: carries an errno, and an attacker-influenced disk can in principle produce
#: many; the set must not grow without bound (FR-18's spirit).
_MAX_LOGGED_ERROR_KEYS = 64

#: How many names ``_claim_path`` will try before giving up and sharing
#: (review S-11). Each attempt draws 3 fresh random bytes.
_MAX_NAME_ATTEMPTS = 8

#: Bytes of randomness in the uniqueness token, rendered as hex.
_NAME_TOKEN_BYTES = 3

_OPEN_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_APPEND
_OPEN_MODE = 0o644

#: Advisory flock, when the platform has it. Best effort: it catches a second
#: *process* on the same path (a recycled PID, a shared hostPath without
#: ``subPathExpr``); the in-process registry below catches the realistic case.
try:  # pragma: no cover - platform dependent
    import fcntl as _fcntl

    _FCNTL: Any | None = _fcntl
except ImportError:  # pragma: no cover - non-POSIX
    _FCNTL = None

#: Paths a live ``FileSink`` in *this* process has claimed. Two sinks on one
#: path silently destroy each other's data — measured at 35% loss (review
#: S-11) — and every realistic live collision is in-process, because the PID
#: in the name already separates processes. Guarded by a plain
#: ``threading.Lock``: only ``_ensure_open`` and ``close`` touch it, never the
#: request path.
_CLAIMED_PATHS: set[str] = set()
_CLAIM_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

_ORJSON: Any | None
_ORJSON_OPTS: int = 0
try:  # pragma: no cover - depends on whether the 'fast' extra is installed
    import orjson as _orjson_mod

    _ORJSON = _orjson_mod
    _ORJSON_OPTS = (
        _orjson_mod.OPT_PASSTHROUGH_DATETIME
        | _orjson_mod.OPT_PASSTHROUGH_DATACLASS
        | _orjson_mod.OPT_NON_STR_KEYS
    )
except ImportError:  # pragma: no cover - depends on the environment
    _ORJSON = None


def _json_default(obj: Any) -> Any:
    """Coerce whatever JSON cannot express into something it can.

    Used by *both* backends, so ``orjson`` and the stdlib agree byte for byte.
    """
    if isinstance(obj, (bytes, bytearray, memoryview)):
        raw = bytes(obj)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return "base64:" + base64.b64encode(raw).decode("ascii")
    if isinstance(obj, (_dt.datetime, _dt.date, _dt.time)):
        return obj.isoformat()
    if isinstance(obj, _dt.timedelta):
        return obj.total_seconds()
    if isinstance(obj, decimal.Decimal):
        # str() keeps the exact value; float() would round and could produce a
        # non-finite float we would then have to sanitise again.
        return str(obj)
    if isinstance(obj, (set, frozenset)):
        return list(obj)
    if isinstance(obj, complex):
        return [obj.real, obj.imag]
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, BaseException):
        return f"{type(obj).__name__}: {obj}"
    try:
        return str(obj)
    except Exception:
        return f"<unserialisable {type(obj).__name__}>"


def _sanitise(obj: Any, depth: int = 0) -> Any:
    """Replace non-finite floats with ``None``; bounded, so cycles terminate.

    Only reached on the stdlib path, and only when ``json.dumps`` refused the
    document because it contained ``NaN``/``Infinity``.
    """
    if depth >= _SANITISE_MAX_DEPTH:
        return None
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {k: _sanitise(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitise(v, depth + 1) for v in obj]
    return obj


def _encode(text: str) -> bytes:
    """The JSON text as UTF-8, with anything UTF-8 cannot express replaced.

    The one thing that reaches here and is not encodable is a **lone
    surrogate** (``"\\ud800"``): it is a perfectly ordinary ``str`` to Python
    and to the stdlib encoder, and it cannot be represented in UTF-8 at all —
    so it would break the JSONL *line*, not just the field (review N2-1).
    ``errors="replace"`` turns each one into ``?`` — one C-level pass over the
    text, which keeps the line valid JSON and valid UTF-8. The rest of the
    document survives intact. (``U+FFFD`` would read better, and is what
    ``redact.sanitize_key`` uses, but every way of producing it here is a
    per-character Python loop over the whole serialised document — on a path a
    client can select with 14 bytes. A cheap ``?`` beats an attacker-selectable
    O(n) loop on the request path.)
    """
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace")


def _dumps_stdlib(doc: dict[str, Any]) -> bytes:
    """The stdlib encoder, used as the backend *and* as orjson's fallback."""
    try:
        text = json.dumps(
            doc,
            default=_json_default,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except ValueError:
        # `allow_nan=False` refused a non-finite float (or the document was
        # cyclic). Sanitise once and retry; _sanitise is depth-bounded.
        text = json.dumps(
            _sanitise(doc),
            default=_json_default,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    return _encode(text)


def _dumps(doc: dict[str, Any]) -> bytes:
    """One document to one line of UTF-8 JSON (no trailing newline).

    ``orjson`` is tried first and the stdlib is the **fallback**, not merely
    the other backend (review N2-1). The ``default=`` hook above cannot be the
    whole answer, because ``orjson`` also refuses input the hook is never
    consulted about: a lone surrogate inside a ``str`` is not a *type* error,
    so ``dumps`` raises ``TypeError: surrogates not allowed`` without ever
    calling ``default``. That made a 14-byte request body — ``{"a":"\\ud800"}``
    — delete its own audit record, which is FR-01 defeated by a client at will.
    Since both backends run through the same ``default`` hook, the fallback
    produces the same bytes the stdlib backend would have produced anyway, so
    nothing about the on-disk format depends on which path ran.
    """
    if _ORJSON is not None:
        try:
            # orjson already emits `null` for NaN/Infinity, which is valid JSON.
            result: bytes = _ORJSON.dumps(
                doc, default=_json_default, option=_ORJSON_OPTS
            )
            return result
        except Exception:
            # Anything orjson refuses, the stdlib gets a turn at. It accepts
            # NaN (sanitised below), lone surrogates (replaced in `_encode`)
            # and cycles (depth-bounded in `_sanitise`).
            pass
    return _dumps_stdlib(doc)


def _batch_bytes(batch: list[bytes]) -> int:
    """Total size on disk of a list of already-serialised lines."""
    return sum(map(len, batch))


def _whole_lines_within(segment: list[bytes], landed: int) -> int:
    """How many leading lines of ``segment`` fit entirely in ``landed`` bytes.

    ``os.write`` can return short (``ENOSPC`` mid-write is the realistic one).
    Only lines that reached the file *whole* are treated as written; the line
    the write stopped inside is retried from its start, so the file may hold
    one torn line, never a silently missing one.
    """
    consumed = 0
    for count, line in enumerate(segment):
        consumed += len(line)
        if consumed > landed:
            return count
    return len(segment)


def _try_flock(fd: int) -> bool:
    """Take an advisory exclusive lock. ``False`` if someone else holds it.

    ``True`` also when the platform or filesystem has no working ``flock`` —
    this is insurance on top of ``_CLAIMED_PATHS``, never the only guard.
    """
    if _FCNTL is None:  # pragma: no cover - non-POSIX
        return True
    try:
        _FCNTL.flock(fd, _FCNTL.LOCK_EX | _FCNTL.LOCK_NB)
    except (BlockingIOError, PermissionError):
        return False
    except OSError:  # pragma: no cover - filesystem without flock support
        return True
    return True


def _close_quietly(fd: int) -> None:
    """``os.close`` that cannot raise. Never called on a borrowed fd (N2-5)."""
    try:
        os.close(fd)
    except OSError:  # pragma: no cover - defensive
        pass


def _new_name_token() -> str:
    """A short, filesystem-safe uniqueness token (review S-11)."""
    return os.urandom(_NAME_TOKEN_BYTES).hex()


def _safe_service_name(name: str) -> str:
    """``service_name`` reduced to something safe as a path component."""
    cleaned = "".join(ch if ch in _SAFE_NAME_CHARS else "_" for ch in name)
    cleaned = cleaned.strip(".")
    return cleaned or "service"


# ---------------------------------------------------------------------------
# FileSink
# ---------------------------------------------------------------------------


class FileSink(Sink):
    """Serialises to JSONL and writes from a background task."""

    def __init__(self, config: AuditConfig, metrics: Metrics | None = None) -> None:
        self.config = config
        self.metrics: Metrics = metrics if metrics is not None else InMemoryMetrics()

        self._queue: deque[bytes] = deque()
        self._queue_bytes: int = 0
        self._queue_max_bytes: int = config.queue_max_bytes
        self._flush_max_bytes: int = config.flush_max_bytes

        #: A batch whose write failed, held for exactly one retry (FR-21r).
        self._retry: list[bytes] | None = None
        #: Bytes of the batch being written *or* parked in ``_retry``. Counted
        #: against ``queue_max_bytes`` alongside the deque so that FR-18's
        #: bound is the whole truth and the gauge can see it (review S-8).
        self._inflight_bytes: int = 0

        self._fd: int | None = None
        self._file_bytes: int = 0
        self._pid: int = os.getpid()
        self._safe_name: str = _safe_service_name(config.service_name)
        #: FR-26's name. ``_claim_path`` may append a uniqueness token to it on
        #: first open if another live sink already holds it (review S-11).
        self.path: Path = Path(config.log_dir) / f"{self._safe_name}-{self._pid}.jsonl"
        self._claimed: bool = False
        #: Guards every change to the sink's *file identity*: the open in
        #: ``_ensure_open`` **and** the whole close -> rename -> reopen of
        #: ``_rotate`` (review D-A6-5). Both run on more than one thread —
        #: ``start()`` opens on the event loop, ``_write_batch``/``_rotate``
        #: run on an ``asyncio.to_thread`` worker — and a rotation that is not
        #: atomic against an open lets the other thread resolve the *old*
        #: inode and then keep writing to it after it has been renamed away.
        #: Never taken on the request path (NFR-2).
        #:
        #: It is a plain, non-reentrant ``Lock``: everything that runs under it
        #: is spelled ``*_locked`` and calls only other ``*_locked`` helpers, so
        #: the locked region has exactly one entry point per public method and
        #: cannot be taken twice on one thread.
        self._open_lock = threading.Lock()
        #: Guards the *descriptor handover* only — ``_fd`` capture, the
        #: in-flight writer count and the orphan set (review N2-5). Held for a
        #: handful of attribute assignments and never across a syscall, so
        #: unlike ``_open_lock`` it is always safe for ``close()`` to take: a
        #: stuck disk cannot be behind it.
        #:
        #: Lock order, and it only ever goes one way: ``_open_lock`` ->
        #: ``_fd_lock`` (``_rotate_locked`` calls ``_close_fd``). Nothing takes
        #: ``_open_lock`` while holding ``_fd_lock``, so the pair cannot
        #: deadlock.
        self._fd_lock = threading.Lock()
        #: Threads currently between "captured the fd" and "finished writing
        #: to it". While this is non-zero the descriptor must not be closed.
        self._writers = 0
        #: Descriptors ``close()``/``_rotate`` wanted closed while a writer
        #: still held them. The *writer* closes these when it is done — see
        #: ``_release_fd``.
        self._orphan_fds: set[int] = set()

        self._task: asyncio.Task[None] | None = None
        self._wake: asyncio.Event | None = None
        self._lock: asyncio.Lock | None = None
        self._stopping = False
        self._closed = False
        self._starting = False
        #: Set by ``close()`` *after* the drain, immediately before the final
        #: ``_close_fd``/``_release_path``. From that instant the sink owns no
        #: file and must never open one again — including from a rotation that
        #: was still in flight on the worker thread when the shutdown timeout
        #: fired (review D-A6-6). A plain bool, written on the event loop and
        #: read on the worker: never take ``_open_lock`` to set it, or FR-27's
        #: bounded ``close()`` could block behind a slow rotation.
        self._terminated = False

        self._logged_errors: set[str] = set()
        self.rotations = 0
        #: Documents ``submit()`` refused because ``close()`` had already run —
        #: the graceful-shutdown window, not disk pressure (review N-8).
        self.dropped_after_close = 0
        #: Documents no encoder would take — counted under
        #: ``audit_documents_failed_total``, never under ``dropped_total``
        #: (review N2-1). See ``_drop_unserialisable``.
        self.serialisation_failures = 0

    # -- request path -------------------------------------------------------

    def submit(self, doc: dict[str, Any]) -> bool:
        """Serialise and enqueue one document. Sync, non-blocking, never raises.

        Returns ``False`` when the document was dropped — queue full (FR-19),
        sink closed, or the document could not be serialised at all.
        """
        try:
            if self._closed:
                return self._drop_after_close()
            try:
                line = _dumps(doc) + b"\n"
            except Exception as exc:
                # Unserialisable beyond rescue: count it, drop it, do not
                # propagate into the request (NFR-3).
                return self._drop_unserialisable(exc)

            size = len(line)
            # FR-18's bound covers everything held in memory, not just the
            # deque: a batch in flight or parked for a retry is still ours
            # (review S-8).
            if self._queue_bytes + self._inflight_bytes + size > self._queue_max_bytes:
                self.metrics.inc("audit_documents_dropped_total")
                return False

            self._queue.append(line)
            queued = self._queue_bytes = self._queue_bytes + size
            self.metrics.inc("audit_documents_submitted_total")
            # `_publish_queue_bytes` inlined: this is the request path.
            self.metrics.set("audit_queue_bytes", float(queued + self._inflight_bytes))

            if self._task is None:
                self._start_lazily()
            elif self._queue_bytes >= self._flush_max_bytes and self._wake is not None:
                self._wake.set()
            return True
        except Exception:  # pragma: no cover - last-ditch, submit cannot raise
            return False

    def _publish_queue_bytes(self) -> None:
        """Republish the gauge from *every* byte the sink is holding (S-8)."""
        self.metrics.set(
            "audit_queue_bytes", float(self._queue_bytes + self._inflight_bytes)
        )

    def _drop_after_close(self) -> bool:
        """A document that arrived after ``close()`` — say so (review N-8).

        These are requests that were still in flight when the lifespan
        shutdown reached the sink. They are lost either way, but they are
        *not* the "disk is not keeping up" paging event FR-19 describes, and
        collapsing the two teaches an operator to ignore the wrong alert.

        So the two counters are **disjoint**: a shutdown-window drop increments
        ``audit_documents_dropped_after_close_total`` and nothing else. It used
        to increment ``audit_documents_dropped_total`` as well, because that
        was the only frozen name available at the time; now that both names are
        in ``METRIC_NAMES`` that double count is only harmful — it makes FR-19's
        page-me counter tick on every *clean* shutdown, so an alert on it has to
        subtract this counter before it means anything. ``dropped_total`` now
        means disk pressure and only disk pressure. A caller that wants "every
        document this sink did not write" adds the two.
        """
        self.dropped_after_close += 1
        self.metrics.inc("audit_documents_dropped_after_close_total")
        if self.dropped_after_close == 1:
            logger.warning(
                "audit file sink %s was closed while requests were still in "
                "flight; their documents are dropped (see "
                "FileSink.dropped_after_close for the running total). This is "
                "the shutdown window, not disk pressure.",
                self.path,
            )
        return False

    def _drop_unserialisable(self, exc: BaseException) -> bool:
        """A document no encoder would take — *not* a queue-pressure drop.

        ``audit_documents_dropped_total`` means one thing (FR-19): the queue
        was full, i.e. **the disk is not keeping up** — page someone. A
        document that could not be serialised says nothing whatsoever about
        the disk, and filing it there points the operator at the wrong
        subsystem and, worse, lets a client fire or mask that page at will by
        choosing its request body (review N2-1). So this goes where the other
        "the sink held a document and could not write it" losses go:
        ``audit_documents_failed_total``, whose documented meaning is already
        exactly *documents actually lost*, and which is disjoint from FR-19's
        counter — the same split ``_drop_after_close`` makes for the shutdown
        window. Adding a third name was not an option worth taking:
        ``METRIC_NAMES`` is frozen in ``_contracts`` (not this agent's file)
        and ``PrometheusMetrics`` **ignores** any name that is not in it, so an
        invented counter would be invisible in exactly the deployment that
        matters. ``dropped_total`` therefore keeps meaning disk pressure and
        only disk pressure.

        After the ``_dumps`` fallback this path is very hard to reach at all —
        it needs a document both backends refuse (a recursion blow-up, an
        object whose ``__iter__`` raises) rather than merely awkward data — so
        one log line per distinct failure is affordable and worth having.
        """
        self.serialisation_failures += 1
        self.metrics.inc("audit_documents_failed_total")
        self._log_once(exc, "serialise")
        return False

    def _start_lazily(self) -> None:
        """Kick off the background task if a loop is running (AGENTS.md §lifespan).

        Cheap: only reached while ``self._task is None``.
        """
        if self._starting or self._closed:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._starting = True
        loop.create_task(self.start())

    # -- lifecycle ----------------------------------------------------------

    async def start(self) -> None:
        """Open the file and spawn the flusher. Idempotent."""
        self._starting = False
        if self._closed or self._task is not None:
            return
        if self._wake is None:
            self._wake = asyncio.Event()
        if self._lock is None:
            self._lock = asyncio.Lock()
        try:
            self._ensure_open()
        except OSError as exc:
            # A bad log_dir must not stop the app from booting; every flush
            # retries the open and counts the failure (FR-21r).
            self._log_once(exc, "open")
        self._stopping = False
        self._task = asyncio.create_task(self._run(), name="audit-file-sink")

    async def flush(self) -> None:
        """Write everything currently queued before returning."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        await self._flush_all()

    async def close(self) -> None:
        """Drain within ``shutdown_flush_timeout`` and return regardless (FR-27).

        Terminal. A sink that has been closed never opens a file again — see
        ``_terminated`` and ``_open_locked``. ``start()`` after ``close()`` is
        already a documented no-op (it returns on ``_closed``), so this adds no
        new restriction: a restart was never supported, and now it cannot
        silently half-happen on a worker thread either.
        """
        if self._closed:
            return
        self._closed = True
        self._stopping = True
        if self._wake is not None:
            self._wake.set()
        if self._lock is None:
            self._lock = asyncio.Lock()

        task = self._task
        try:
            await asyncio.wait_for(
                self._shutdown_drain(task), timeout=self.config.shutdown_flush_timeout
            )
        except Exception:
            # TimeoutError included: a slow disk must not hang shutdown.
            logger.debug("audit file sink did not drain within the timeout", exc_info=True)
        finally:
            self._task = None
            if task is not None and not task.done():
                task.cancel()
            # Ordering, and it is the whole guarantee (review D-A6-6):
            # `_terminated` is set *before* the teardown, so a worker that
            # reaches `_open_locked`'s guard after this point never opens.
            # A worker that is already *past* that guard is caught the other
            # way round — it re-reads the flag after installing the fd, and
            # since it installed the fd before that re-read, either it sees
            # the flag and undoes itself, or the flag was set later still and
            # the `_close_fd` below sees its fd. Cancelling the task does not
            # stop the thread it parked in `asyncio.to_thread`, which is
            # exactly how a rotation outlives `close()`.
            self._terminated = True
            self._close_fd()
            self._release_path()

    async def _shutdown_drain(self, task: asyncio.Task[None] | None) -> None:
        if task is not None:
            await task  # the loop notices _stopping and does a final drain
        else:
            await self._flush_all()

    # -- background loop ----------------------------------------------------

    async def _run(self) -> None:
        assert self._wake is not None
        interval = self.config.flush_interval_seconds
        while not self._is_stopping():
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=interval)
            except TimeoutError:
                pass
            except asyncio.CancelledError:
                raise
            self._wake.clear()
            if self._is_stopping():
                break
            try:
                await self._flush_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                self._log_once(exc, "flush")
        try:
            await self._flush_all()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            self._log_once(exc, "flush")

    def _is_stopping(self) -> bool:
        """Indirection so the flag is re-read (and not narrowed away)."""
        return self._stopping

    async def _flush_all(self) -> None:
        for _ in range(_MAX_FLUSH_ROUNDS):
            if not self._queue and self._retry is None:
                return
            await self._flush_once()

    async def _flush_once(self) -> None:
        """Drain (or retry) one batch and write it. Serialised by ``_lock``."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self._retry is not None:
                batch = self._retry
                self._retry = None
                is_retry = True
            else:
                batch = self._drain()
                is_retry = False
            if not batch:
                self._inflight_bytes = 0
                self._publish_queue_bytes()
                return

            started = time.monotonic()
            try:
                await asyncio.to_thread(self._write_batch, batch)
            except asyncio.CancelledError:
                # Shutdown raced the write. `batch` now holds only the lines
                # that did NOT reach the file.
                self._keep_or_lose(batch, is_retry)
                raise
            except Exception as exc:
                self._log_once(exc, "write")
                self._keep_or_lose(batch, is_retry)
            else:
                self._inflight_bytes = 0
            finally:
                self.metrics.set("audit_flush_seconds", time.monotonic() - started)
                self._publish_queue_bytes()

    def _keep_or_lose(self, batch: list[bytes], is_retry: bool) -> None:
        """Park a failed batch for its one retry, or count it as lost.

        ``audit_documents_failed_total`` means "documents actually lost", so it
        is incremented **once**, on the attempt after which the batch is
        discarded — not on the first failure *and* again on the retry, which
        reported 180 lost documents as 360 (review S-9 / D-A6-1). The
        ``CancelledError``-during-a-retry path counts here too; it used to
        discard the batch with no counter at all.

        ``batch`` is whatever ``_write_batch`` could not place, so lines that
        did reach the file are neither counted as lost nor written twice.
        """
        if is_retry:
            if batch:
                self.metrics.inc("audit_documents_failed_total", len(batch))
            self._inflight_bytes = 0
            return
        if not batch:  # every line landed after all
            self._inflight_bytes = 0
            return
        self._retry = batch  # exactly one retry, then dropped
        self._inflight_bytes = _batch_bytes(batch)

    def _drain(self) -> list[bytes]:
        """Take everything queued, in submission order.

        The bytes move from ``_queue_bytes`` to ``_inflight_bytes``; they do
        not leave the accounting, because they have not left memory (S-8).
        """
        queue = self._queue
        batch: list[bytes] = []
        while True:
            try:
                batch.append(queue.popleft())
            except IndexError:
                break
        # Exact: nothing can append between the loop and here (no await).
        self._inflight_bytes = self._queue_bytes
        self._queue_bytes = 0
        return batch

    # -- file I/O (runs on a worker thread) ---------------------------------

    def _write_batch(self, batch: list[bytes]) -> None:
        """Write ``batch`` in file-sized segments — one ``os.write`` each.

        ``file_max_bytes`` is a bound (FR-22, AC-25). The old code checked it
        once per batch *and* skipped the check entirely on a 0-byte file — the
        leading ``if self._file_bytes and …`` — so a freshly opened or freshly
        rotated file never rotated whatever the payload size, and a 64 KiB
        limit with the default 4 MiB flush produced a 1.8 MB file with zero
        rotations (review S-10). Two rules replace it:

        1. **The active file is closed out when it cannot take the whole
           batch.** So a batch that fits in an empty file is always written
           with exactly one ``os.write``, which is every configuration where
           ``flush_max_bytes <= file_max_bytes`` — the shipped defaults
           included. The cost is under-filling a file by at most one batch.
        2. **A batch that does not fit even in an empty file is split** at
           whole-line boundaries, one ``os.write`` per segment, a rotation
           between segments. FR-20r's "a single ``os.write`` of the joined
           bytes" therefore reads *per file segment*; the bound was the
           requirement, the single syscall never was.

        A line is never split across two files, and the only way past the
        bound is a single line larger than it — written alone into a fresh
        file, which is the one-line overshoot AC-25 allows.

        **Mutates ``batch``**: every line that reached the file is removed. A
        caller that catches an exception is left holding exactly the lines
        that did not land, so a retry neither duplicates a written line nor
        counts it as lost.
        """
        limit = self.config.file_max_bytes
        total = len(batch)
        placed = 0
        # Each pass either writes at least one line or rotates, and a rotation
        # is always followed by a write, so this cannot spin.
        guard = 2 * total + 4
        try:
            self._ensure_open()
            if self._is_terminated():
                # `close()` has torn the sink down. Refuse before rotating —
                # a terminated sink must not shuffle files on disk either.
                raise OSError("audit file sink is closed")
            # Rule 1: close the file out rather than start a batch it cannot
            # finish. Never on an empty file — that would rotate nothing.
            if self._file_bytes and self._file_bytes + _batch_bytes(batch) > limit:
                self._rotate()
            index = 0
            while index < total:
                guard -= 1
                if guard < 0:  # pragma: no cover - defensive
                    raise OSError("audit file sink made no progress rotating")
                start = index
                segment_bytes = 0
                while index < total:
                    size = len(batch[index])
                    used = self._file_bytes + segment_bytes
                    if used and used + size > limit:
                        break
                    segment_bytes += size
                    index += 1
                if index == start:
                    # Not even one more line fits. Make room, then retry it.
                    self._rotate()
                    continue
                segment = batch[start:index]
                before = self._file_bytes
                try:
                    self._write_segment(segment)
                except BaseException:
                    placed += _whole_lines_within(segment, self._file_bytes - before)
                    raise
                placed = index
        finally:
            if placed:
                del batch[:placed]

    def _write_segment(self, segment: list[bytes]) -> None:
        """One ``os.write`` of the joined lines into the active file.

        The descriptor is **borrowed** for the duration (review N2-5). It used
        to be read into a local and then written to, which is a use-after-close
        the moment ``close()`` runs its final ``_close_fd`` while this thread
        is parked in ``os.write`` on a stalled disk: the number is freed, the
        kernel hands the same integer to the next ``os.open`` or ``accept`` in
        the process, and the in-flight write lands in **that** file or socket.
        A reviewer demonstrated five whole audit documents appended to an
        unrelated file with the audit file left at 0 bytes. That is worse than
        losing the lines: it is audit content — paths, user ids, the flattened
        body — emitted somewhere it was never meant to go.
        """
        fd = self._acquire_fd()
        if fd is None:
            # Reachable only when `close()` terminated the sink part-way
            # through this batch (D-A6-6): the rotation above deliberately did
            # not reopen. A real error beats an `assert`, which reports badly
            # and disappears under `-O`.
            raise OSError("audit file sink is closed")
        try:
            view = memoryview(b"".join(segment))
            while view:
                written = os.write(fd, view)
                if written <= 0:  # pragma: no cover - defensive
                    raise OSError("os.write accepted no bytes")
                self._file_bytes += written
                view = view[written:]
            if self.config.fsync:
                os.fsync(fd)
        finally:
            self._release_fd()

    def _is_open(self) -> bool:
        """Indirection so the fd is re-read (and not narrowed away)."""
        return self._fd is not None

    def _is_terminated(self) -> bool:
        """Indirection so the flag is re-read on every check.

        Another thread sets ``_terminated`` between the two reads in
        ``_open_locked`` — that is the entire point of the second one — and a
        bare attribute test would let the type checker narrow the second read
        away as unreachable. Same reason as ``_is_open``/``_is_stopping``.
        """
        return self._terminated

    def _ensure_open(self) -> None:
        """Open the active file if it is not open. Callable from any thread.

        The unlocked fast path is safe because ``_fd`` is only ever cleared
        under ``_open_lock`` (by ``_rotate_locked``) or after the writer has
        been stopped (by ``close``): seeing an fd means the file identity is
        settled, and seeing ``None`` costs one uncontended lock acquisition.
        """
        if self._is_open():
            return
        with self._open_lock:
            self._open_locked()

    def _open_locked(self) -> None:
        """Open the active file. **The caller must hold ``_open_lock``.**

        Split out of ``_ensure_open`` so that ``_rotate_locked`` can reopen
        without releasing the lock between the rename and the reopen — the
        window that produced D-A6-5.

        Refuses once ``close()`` has torn the sink down (D-A6-6). ``close()``
        cannot take ``_open_lock`` — FR-27's timeout exists precisely because a
        rotation may be stuck on a slow disk, and blocking on it would defeat
        the bound — so the two synchronise on the ``_terminated`` bool instead,
        which under the GIL is a single store against a single load. The guard
        below stops every worker that has not yet opened; the *re-check* after
        the fd is installed stops the one that was already past the guard when
        the flag was set. Together they leave no interleaving in which the sink
        ends up owning a file after ``close()`` has returned.
        """
        if self._is_open():  # opened while we waited for the lock
            return
        if self._is_terminated():
            return
        directory = Path(self.config.log_dir)
        os.makedirs(directory, exist_ok=True)
        self._claim_path()
        fd = os.open(self.path, _OPEN_FLAGS, _OPEN_MODE)
        _try_flock(fd)
        try:
            self._file_bytes = os.fstat(fd).st_size
        except OSError:  # pragma: no cover - defensive
            self._file_bytes = 0
        self._fd = fd
        if self._is_terminated():
            # `close()` ran while this open was in progress. Undo it: the fd,
            # and the path claim that `_claim_path` may have re-taken after
            # `close()`'s `_release_path` had already given it up. Both are
            # idempotent, so the claim is still released exactly once whether
            # or not this branch is the one that does it.
            self._close_fd()
            self._release_path()

    def _claim_path(self) -> None:
        """Settle on a file no other live sink is writing (review S-11).

        FR-26's ``{service}-{pid}.jsonl`` has no uniqueness token, and two
        live ``FileSink``s on one path destroy each other: each tracks
        ``_file_bytes`` for its own writes only, so rotation fires at the
        wrong size, and one sink's ``os.replace`` moves the file the other
        still holds an fd on. Measured: 120 documents in, 78 lines out.

        The PID in the name already separates *processes*, so every realistic
        live collision is in-process — a mounted sub-application with its own
        middleware, ``add_middleware`` called twice, a test harness. Those are
        caught exactly by ``_CLAIMED_PATHS``; ``flock`` additionally catches a
        second process that reached the same path anyway (a shared hostPath
        with no ``subPathExpr``, a PID namespace collision).

        The first sink keeps FR-26's name verbatim, so the documented name,
        A5's ``/var/log/audit/*/*.jsonl`` glob and its ``\\.jsonl\\.\\d+$``
        rotation exclude all keep working unchanged. Only a *contending* sink
        takes ``{service}-{pid}-{token}.jsonl``, which matches the same glob
        and is excluded by the same regex once rotated.
        """
        if self._claimed:
            return
        base = self.path
        candidate = base
        for _attempt in range(_MAX_NAME_ATTEMPTS):
            key = str(candidate)
            with _CLAIM_LOCK:
                free = key not in _CLAIMED_PATHS
                if free:
                    _CLAIMED_PATHS.add(key)
            if free and self._flock_is_free(candidate):
                if candidate != base:
                    logger.warning(
                        "audit file sink: %s is already being written by "
                        "another live sink; using %s instead so neither "
                        "loses lines (FR-26 + review S-11)",
                        base.name,
                        candidate.name,
                    )
                self.path = candidate
                self._claimed = True
                return
            if free:
                with _CLAIM_LOCK:
                    _CLAIMED_PATHS.discard(key)
            candidate = base.with_name(
                f"{self._safe_name}-{self._pid}-{_new_name_token()}.jsonl"
            )
        # Astronomically unlikely; sharing beats refusing to log at all.
        with _CLAIM_LOCK:  # pragma: no cover - unreachable in practice
            _CLAIMED_PATHS.add(str(base))
        self._claimed = True  # pragma: no cover

    def _flock_is_free(self, candidate: Path) -> bool:
        """Probe ``candidate`` with a non-blocking ``flock``, then let go."""
        try:
            probe = os.open(candidate, _OPEN_FLAGS, _OPEN_MODE)
        except OSError:
            # Cannot even open it — let the real open report the error.
            return True
        try:
            return _try_flock(probe)
        finally:
            try:
                os.close(probe)
            except OSError:  # pragma: no cover - defensive
                pass

    def _release_path(self) -> None:
        if not self._claimed:
            return
        self._claimed = False
        with _CLAIM_LOCK:
            _CLAIMED_PATHS.discard(str(self.path))

    def _acquire_fd(self) -> int | None:
        """Borrow the active descriptor for one write (review N2-5).

        Between this and the matching ``_release_fd`` no other thread will
        ``os.close`` the returned fd — ``_close_fd`` hands it over instead. The
        capture and the count move together under ``_fd_lock``, so there is no
        instant at which a thread holds an fd the bookkeeping does not know
        about.
        """
        with self._fd_lock:
            fd = self._fd
            if fd is None:
                return None
            self._writers += 1
            return fd

    def _release_fd(self) -> None:
        """Give the descriptor back, and close it if ``close()`` asked us to.

        **The writer owns the close.** If ``close()`` (or a rotation) ran while
        this thread was inside ``os.write``, the fd is in ``_orphan_fds`` and
        was deliberately left open; now that no thread can be writing to it,
        this is the safe moment to release the number.
        """
        orphans: list[int] = []
        with self._fd_lock:
            self._writers -= 1
            if self._writers == 0 and self._orphan_fds:
                orphans = list(self._orphan_fds)
                self._orphan_fds.clear()
        for fd in orphans:
            _close_quietly(fd)

    def _close_fd(self) -> None:
        """Retire the active descriptor. Never closes one being written to.

        The whole of N2-5 is in the ``self._writers`` branch. ``close()`` must
        return within ``shutdown_flush_timeout`` (FR-27) and cancelling the
        flusher does not stop the thread parked in ``asyncio.to_thread``, so a
        write really can still be in flight here — and closing the fd out from
        under it frees the *number*, which the kernel then hands to the next
        ``os.open``/``accept`` in the process while the straggling write is
        still aimed at it.

        So the descriptor is not closed here; ownership of the close passes to
        the writer thread (``_release_fd``), which is the only thread that
        knows when the write is finished. The write completes into the file it
        was always meant for — no bytes lost, and none misdirected.

        **The trade, deliberately:** if that writer never returns — a disk that
        never completes the ``os.write``, which is precisely the scenario
        FR-27's timeout exists for — the descriptor is never closed and leaks
        for the remaining life of the process. That is accepted. The process is
        already shutting down, so the leak lasts seconds; one stranded fd in a
        dying process is enormously cheaper than audit records appended to an
        unrelated file or written down a client socket. ``close()`` itself is
        unaffected either way: it takes only ``_fd_lock``, which is never held
        across a syscall, so the bound in FR-27 still holds.

        The common case is untouched: no writer, and the fd is closed right
        here exactly as before — outside the lock, because ``os.close`` can
        itself block on a network filesystem.
        """
        with self._fd_lock:
            fd, self._fd = self._fd, None
            if fd is None:
                return
            if self._writers:
                self._orphan_fds.add(fd)
                return
        _close_quietly(fd)

    def _rotate(self) -> None:
        """``x.jsonl`` -> ``x.jsonl.1`` -> … -> dropped past ``file_backup_count``.

        The whole close -> rename -> reopen sequence is **one atomic step** with
        respect to ``_ensure_open`` (review D-A6-5). It used to be three, and
        the gap between them was reachable: ``_rotate`` runs on the
        ``asyncio.to_thread`` worker while ``start()``'s ``_ensure_open`` runs
        on the event loop, so the loop could see the momentarily closed sink,
        resolve ``base`` to the *pre-rename* inode and install an fd on it. The
        worker then renamed that inode to ``.1`` and its own reopen found an fd
        already there and did nothing — leaving the sink appending to a file it
        believed was empty and was in fact a full generation, and leaving no
        ``base`` at all until the next rotation. One generation reached 2x
        ``file_max_bytes`` and the ``.N`` numbering gained a permanent gap: no
        line lost, but ``file_max_bytes`` was no longer a bound, which is
        exactly the FR-22 property S-10 was filed for. Reproduced about one run
        in three; every failing run had exactly one ``MainThread``
        ``_ensure_open`` that found a non-empty file.
        """
        with self._open_lock:
            self._rotate_locked()
        self.rotations += 1
        self.metrics.inc("audit_file_rotations_total")

    def _rotate_locked(self) -> None:
        """**The caller must hold ``_open_lock``.** No other thread may open,
        observe or create the active file while this runs."""
        self._close_fd()
        backups = self.config.file_backup_count
        base = str(self.path)
        try:
            if backups <= 0:
                self._unlink(base)
            else:
                self._unlink(f"{base}.{backups}")
                for index in range(backups - 1, 0, -1):
                    source = f"{base}.{index}"
                    if os.path.exists(source):
                        os.replace(source, f"{base}.{index + 1}")
                if os.path.exists(base):
                    os.replace(base, f"{base}.1")
        finally:
            self._file_bytes = 0
            self._open_locked()

    @staticmethod
    def _unlink(path: str) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

    # -- diagnostics --------------------------------------------------------

    def _log_once(self, exc: BaseException, phase: str) -> None:
        """One ERROR line per distinct *failure*, per process (FR-21r).

        The key used to be ``type(exc).__name__`` alone, which is far too
        coarse (review S-7): ``ENOSPC``, ``EDQUOT`` and ``EIO`` are all bare
        ``OSError``, so "disk full" and "disk failing" shared a single line —
        and because the phase was not in the key either, one transient
        ``OSError`` at ``open`` during boot permanently silenced every later
        ``OSError`` at ``write``. Phase and errno are both in the key now.
        """
        code = getattr(exc, "errno", None)
        key = f"{phase}:{type(exc).__name__}:{code}"
        if key in self._logged_errors:
            return
        if len(self._logged_errors) >= _MAX_LOGGED_ERROR_KEYS:
            return  # bounded, like everything else here
        self._logged_errors.add(key)
        logger.error(
            "audit file sink %s failed on %s: %s%s: %s "
            "(further %s errors are suppressed for this process)",
            phase,
            self.path,
            type(exc).__name__,
            f" [errno {code}]" if code is not None else "",
            exc,
            key,
        )

    # -- how much the sink is holding ---------------------------------------
    #
    # Three numbers, and the invariant an operator can lean on at 3am:
    #
    #     held_bytes == queued_bytes + inflight_bytes
    #
    # ``held_bytes`` is FR-18's bound and the value published as the
    # ``audit_queue_bytes`` gauge (a frozen name; it keeps its spelling). The
    # total used to be called ``queue_bytes``, one letter from ``queued_bytes``
    # and meaning something else — the pair you least want to misread while
    # deciding whether a sink is backing up or a disk has stalled.

    @property
    def held_bytes(self) -> int:
        """Every audit byte this sink holds in memory (FR-18's bound).

        Queued lines **plus** the batch in flight or parked for a retry — the
        two thirds the gauge used to be blind to (review S-8). This is exactly
        what the ``audit_queue_bytes`` gauge reports.
        """
        return self._queue_bytes + self._inflight_bytes

    @property
    def queued_bytes(self) -> int:
        """Just the deque: bytes waiting for their first write attempt."""
        return self._queue_bytes

    @property
    def inflight_bytes(self) -> int:
        """The batch being written, or parked for its one retry."""
        return self._inflight_bytes

    @property
    def queue_depth(self) -> int:
        """Documents currently queued (a count, not bytes)."""
        return len(self._queue)

    def __repr__(self) -> str:
        return (
            f"FileSink(path={str(self.path)!r}, queued={len(self._queue)}, "
            f"queued_bytes={self._queue_bytes}, "
            f"inflight_bytes={self._inflight_bytes}, "
            f"held_bytes={self.held_bytes}, "
            f"closed={self._closed})"
        )
