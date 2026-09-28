"""Optional background enricher (FR-55). OWNER: agent K.

A service registers ``enricher(doc) -> dict | None`` (sync, may do I/O such as a DB
lookup of a target label). It runs OFF the request path, in the FileSink writer
thread, just before a batch is written. Contract:
- per-document hard timeout (AUDIT_ENRICH_TIMEOUT_MS, default 200): on timeout or
  exception the document is written unchanged plus tag TAG_ENRICH_TIMEOUT (timeout only);
- the returned dict is a PATCH limited to: audit.target.label, audit.detail (merged),
  user.full_name, user.department — anything else in the patch is ignored;
- if the patch sets audit.target.label, `message` is re-rendered with the new label
  from audit.i18n.key/params (params.target replaced) when the doc carries i18n;
- a TTL cache (AUDIT_ENRICH_CACHE_SECONDS, default 60; max 10 000 entries) keyed by
  (event.action, audit.target.type, audit.target.id) avoids repeated lookups.
Workers: 4 daemon threads owned by the Enricher (not a ThreadPoolExecutor: its
atexit join would hang interpreter exit on a lookup that never returns).

Details (as built):
- A patch path may be nested (``{"audit": {"target": {"label": "x"}}}``) or dotted
  (``{"audit.target.label": "x"}``). Labels/names must be non-empty strings and
  ``audit.detail`` a dict; anything else is ignored.
- Re-render rule: the template is not in the document, so ``message`` is patched,
  not rebuilt. Only when ``audit.i18n.params.target`` was the MISSING word (or
  empty) or equal to ``audit.target.id`` — the sentence shows a placeholder, not a
  real label — the FIRST occurrence of that rendered text in ``message`` is
  replaced by the new label (rendered as render.render renders a value) and
  ``params.target`` becomes the new label. Text not found: ``message`` and
  ``params`` stay as they were (the label field is still patched).
- Only documents with an ``audit.target.id`` are cached (otherwise the key would
  be shared by unrelated documents); ``None`` results are cached too. Equal keys
  in one batch are looked up once.
- ``fn`` gets a deep copy, so a lookup that outlives its timeout cannot mutate a
  document the writer is serialising.
- An ``fn`` exception counts ``audit_semantic_errors_total`` (no tag).
- Bounded wait: one deadline per batch, timeout x rounds of the free workers,
  capped at ``_MAX_BATCH_WAIT`` whatever the batch size. A lookup still running
  after its batch keeps its worker; when no worker is free the batch is not
  submitted at all and every lookup is tagged at once (a hung DB cannot stall
  the writer thread and overflow the sink queue). Lookups past what fits in the
  capped wait are tagged without being submitted, so the queue stays bounded.
"""

from __future__ import annotations

import copy
import math
import queue
import threading
import time
from concurrent.futures import Future, wait
from typing import Any, Callable

from . import render
from .model import DEFAULT_LANG, TAG_ENRICH_TIMEOUT

EnricherFn = Callable[[dict[str, Any]], "dict[str, Any] | None"]

_WORKERS = 4
_MAX_BATCH_WAIT = 1.0  # seconds the writer thread may wait on one batch
_CacheKey = tuple[Any, Any, str]


def _get(d: Any, path: str) -> Any:
    """``d[path]`` for a dotted key, else the nested lookup; ``None`` when absent."""
    if not isinstance(d, dict):
        return None
    if path in d:
        return d[path]
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _child(parent: dict[str, Any], name: str) -> dict[str, Any]:
    cur = parent.get(name)
    if not isinstance(cur, dict):
        cur = parent[name] = {}
    return cur


def _cache_key(doc: dict[str, Any]) -> _CacheKey | None:
    target = _get(doc, "audit.target")
    if not isinstance(target, dict) or target.get("id") in (None, ""):
        return None
    return (_get(doc, "event.action"), target.get("type"), str(target.get("id")))


def _rendered(value: Any) -> str:
    return render._debrace(render._text(value, render.MISSING[DEFAULT_LANG]))


def _rerender(doc: dict[str, Any], audit: dict[str, Any], target: dict[str, Any], label: str) -> None:
    i18n = audit.get("i18n")
    message = doc.get("message")
    if not isinstance(i18n, dict) or not isinstance(message, str):
        return
    params = i18n.get("params")
    if not isinstance(params, dict):
        return
    old = params.get("target")
    missing = list(render.MISSING.values())
    if old is None or old == "" or old in missing:
        candidates = missing
    elif target.get("id") is not None and str(old) == str(target.get("id")):
        candidates = [_rendered(old)]
    else:
        return  # already a real label: leave the sentence alone
    for text in candidates:
        if text and text in message:
            # ponytail: first-occurrence replace; an id that also appears earlier
            # (e.g. inside the actor name) is hit instead. Store the template in
            # the doc and re-render properly if that ever bites.
            doc["message"] = message.replace(text, _rendered(label), 1)
            params["target"] = label
            return


def _apply_patch(doc: dict[str, Any], patch: Any) -> None:
    if not isinstance(patch, dict):
        return
    label = _get(patch, "audit.target.label")
    detail = _get(patch, "audit.detail")
    if isinstance(label, str) and label:
        audit = _child(doc, "audit")
        target = _child(audit, "target")
        target["label"] = label
        _rerender(doc, audit, target, label)
    if isinstance(detail, dict) and detail:
        _child(_child(doc, "audit"), "detail").update(detail)
    for key in ("full_name", "department"):
        value = _get(patch, "user." + key)
        if isinstance(value, str) and value:
            _child(doc, "user")[key] = value


def _add_tag(doc: dict[str, Any], tag: str) -> None:
    tags = doc.get("tags")
    if not isinstance(tags, list):
        tags = doc["tags"] = [] if tags is None else [tags]
    if tag not in tags:
        tags.append(tag)


_Job = tuple["Future[Any]", EnricherFn, dict[str, Any]]


class _Pool:
    """Daemon worker threads + a count of the ones busy (possibly stuck) in ``fn``."""

    def __init__(self) -> None:
        self._jobs: queue.SimpleQueue[_Job | None] = queue.SimpleQueue()
        self._lock = threading.Lock()
        self._busy = 0
        self._threads: list[threading.Thread] = []

    def free(self) -> int:
        with self._lock:
            return _WORKERS - self._busy

    def submit(self, fn: EnricherFn, arg: dict[str, Any]) -> Future[Any]:
        if not self._threads:
            for n in range(_WORKERS):
                t = threading.Thread(target=self._run, name=f"audit-enrich-{n}", daemon=True)
                t.start()
                self._threads.append(t)
        fut: Future[Any] = Future()
        self._jobs.put((fut, fn, arg))
        return fut

    def _run(self) -> None:
        while True:
            job = self._jobs.get()
            if job is None:
                return
            fut, fn, arg = job
            if not fut.set_running_or_notify_cancel():
                continue
            with self._lock:
                self._busy += 1
            try:
                fut.set_result(fn(arg))
            except BaseException as exc:  # noqa: BLE001 - reported through the future
                fut.set_exception(exc)
            finally:
                with self._lock:
                    self._busy -= 1

    def shutdown(self) -> None:
        while True:  # cancel what never started
            try:
                job = self._jobs.get_nowait()
            except queue.Empty:
                break
            if job is not None:
                job[0].cancel()
        for _ in self._threads:
            self._jobs.put(None)


class Enricher:
    def __init__(self, fn: EnricherFn, *, timeout_ms: int = 200, cache_seconds: float = 60.0,
                 max_cache: int = 10_000, metrics: Any = None) -> None:
        self._fn = fn
        self._timeout = max(int(timeout_ms), 1) / 1000.0
        self._ttl = max(float(cache_seconds), 0.0)
        self._max_cache = max(int(max_cache), 0)
        self._metrics = metrics
        #: key -> (expires_at, patch). One TTL for all, so insertion order is
        #: expiry order and the first key is always the one to evict.
        #: Touched only by the thread calling ``apply`` (the writer thread).
        self._cache: dict[_CacheKey, tuple[float, Any]] = {}
        self._pool = _Pool()
        self._closed = False

    def apply(self, docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enrich a batch in place (waits at most max(_MAX_BATCH_WAIT, timeout_ms), 4 workers).
        Never raises."""
        try:
            if self._closed or not docs:
                return docs
            now = time.monotonic()
            free = self._pool.free()
            # Lookups that fit in one capped wait; the rest are tagged unsubmitted.
            budget = free * max(1, int(_MAX_BATCH_WAIT / self._timeout))
            patches: dict[int, Any] = {}
            skipped: list[int] = []
            submitted = 0
            by_doc: dict[int, Future[Any]] = {}
            by_key: dict[_CacheKey, Future[Any]] = {}
            items: list[Any] = docs  # junk tolerated: apply never raises
            for i, doc in enumerate(items):
                if not isinstance(doc, dict):
                    continue
                key = _cache_key(doc)
                hit = self._cache.get(key) if key is not None else None
                if hit is not None and hit[0] > now:
                    patches[i] = hit[1]
                    continue
                if key is not None and key in by_key:
                    by_doc[i] = by_key[key]
                    continue
                if submitted >= budget:
                    skipped.append(i)
                    continue
                submitted += 1
                fut = self._pool.submit(self._fn, copy.deepcopy(doc))
                by_doc[i] = fut
                if key is not None:
                    by_key[key] = fut
            for i in skipped:
                _add_tag(docs[i], TAG_ENRICH_TIMEOUT)
            if by_doc:
                futures = set(by_doc.values())
                # ponytail: one deadline per batch (timeout x rounds of the free
                # workers, capped), not a clock per document; a lookup queued behind
                # a fast one may run a little past timeout_ms.
                rounds = math.ceil(len(futures) / max(free, 1))
                wait(futures, timeout=min(self._timeout * rounds, max(_MAX_BATCH_WAIT, self._timeout)))
                for fut in futures:
                    if not fut.done():
                        fut.cancel()  # not started yet: it will never run
                    elif not fut.cancelled() and fut.exception() is not None:
                        self._count_error()
                for i, fut in by_doc.items():
                    if not fut.done() or fut.cancelled():
                        _add_tag(docs[i], TAG_ENRICH_TIMEOUT)
                    elif fut.exception() is None:
                        patches[i] = fut.result()
                for key, fut in by_key.items():
                    if fut.done() and not fut.cancelled() and fut.exception() is None:
                        self._remember(key, fut.result(), now)
            for i, patch in patches.items():
                try:
                    _apply_patch(docs[i], patch)
                except Exception:
                    self._count_error()
        except Exception:
            self._count_error()
        return docs

    def _remember(self, key: _CacheKey, patch: Any, now: float) -> None:
        if self._ttl <= 0 or self._max_cache <= 0:
            return
        self._cache.pop(key, None)
        while len(self._cache) >= self._max_cache:
            del self._cache[next(iter(self._cache))]
        self._cache[key] = (now + self._ttl, copy.deepcopy(patch))

    def _count_error(self) -> None:
        try:
            if self._metrics is not None:
                self._metrics.inc("audit_semantic_errors_total")
        except Exception:
            pass

    def close(self) -> None:
        """Stop the workers without waiting on stuck lookups (daemon threads)."""
        self._closed = True
        try:
            self._pool.shutdown()
        except Exception:
            pass
