"""``ElasticsearchShipper`` — send the JSONL files to Elasticsearch, no Filebeat.

Why this exists, and why it ships from the *file*
-------------------------------------------------

The package's core promise is that Elasticsearch cannot hurt your API (D-13):
the request path only appends to a queue, and a background task writes JSONL to
a local file. A sink that POSTed straight to Elasticsearch would give you a
one-step setup and quietly destroy that promise — the first cluster hiccup
would back-pressure into the application.

So this does what Filebeat does, in-process: it **tails the files the FileSink
has already written** and bulk-posts them. The file stays the durable buffer.
If Elasticsearch is down, the files accumulate and the shipper retries; the API
never notices. Demonstrated: stop Elasticsearch, serve 25 requests, restart it,
and all 25 records arrive.

It is strictly optional. Nothing in ``middleware.py``, ``document.py``,
``redact.py`` or ``sinks/`` imports this module, and it imports ``httpx`` only
when a shipper is actually constructed, so a deployment using Filebeat carries
no HTTP client at all.

Which files it ships
--------------------

``FileSink`` writes one file per process (``{service}-{pid}.jsonl``). Several
workers share a directory, so a shipper that took everything would duplicate
every record N times. This one claims:

* its **own** process's file and that file's rotations, and
* any file whose owning PID is **no longer alive** — otherwise a worker that
  crashed would leave its unshipped tail on disk forever.

Progress is kept in ``.audit-shipper-{pid}.json`` beside the logs — one file
per worker, never shared — keyed by ``(device, inode)`` rather than by name, so
a rotation cannot make it re-send a file it has already read. Adopting an
orphan means reading the dead worker's file too, so that its tail is shipped
from where it stopped rather than from zero.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import AuditConfig
from ._contracts import Metrics
from .semantic.model import SCHEMA_VERSION, TAG_CLOCK_SKEW

__all__ = ["ElasticsearchShipper"]

_LOG = logging.getLogger("audit_logging.shipper")

#: ``{service}-{pid}.jsonl`` and its rotations ``.1`` … ``.N``.
_FILENAME = re.compile(r"^(?P<service>.+)-(?P<pid>\d+)\.jsonl(?:\.(?P<gen>\d+))?$")

#: Progress is per **process**, not per directory. Several uvicorn workers
#: share a log directory, and a single shared file was being overwritten by
#: each of them from its own in-memory copy every tick — so workers clobbered
#: each other's offsets, which means records re-shipped or skipped. One file
#: per pid removes the sharing entirely.
_STATE_FILE = ".audit-shipper-{pid}.json"

#: What versions before the per-process split wrote. Read once, never written.
_LEGACY_STATE_FILE = ".audit-shipper-state.json"


def _pid_is_alive(pid: int) -> bool:
    """True if a process with this id exists. Never raises."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    except Exception:
        return True  # be conservative: do not steal a file on a strange error
    return True


#: FR-41 default when the config has no ``max_clock_skew_s``.
DEFAULT_MAX_CLOCK_SKEW_S = 300.0


def _bulk_payload(
    lines: list[bytes], index: str, ingested: str, max_skew_s: float = DEFAULT_MAX_CLOCK_SKEW_S,
    data_stream: dict[str, str] | None = None,
) -> bytes:
    """The NDJSON body: a ``create`` action (with ``_id`` = event.id) per stamped line.
    CPU-bound (a parse and a dump per line), so it runs in a worker thread."""
    parts: list[bytes] = []
    for line in lines:
        doc, doc_id = _stamp(line, ingested, max_skew_s, data_stream)
        meta: dict[str, Any] = {"_index": index}
        if doc_id is not None:
            meta["_id"] = doc_id
        parts += (json.dumps({"create": meta}).encode(), doc)
    return b"\n".join(parts) + b"\n"


def _now_iso_ms() -> str:
    """UTC now as ``2026-09-28T05:41:09.020Z``."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo is not None else None


def _mark_skew(doc: dict[str, Any], ingested: str, max_skew_s: float) -> None:
    """FR-41: past the threshold, record the signed skew (ingested - @timestamp)
    in ``audit.clock_skew_ms`` and tag the document ``clock_skew``."""
    at, now = _parse_ts(doc.get("@timestamp")), _parse_ts(ingested)
    if at is None or now is None:
        return
    skew_ms = round((now - at).total_seconds() * 1000)
    if abs(skew_ms) <= max_skew_s * 1000:
        return
    audit = doc.setdefault("audit", {})
    if not isinstance(audit, dict):
        return  # not ours to reshape
    audit["clock_skew_ms"] = skew_ms
    tags = doc.get("tags")
    if isinstance(tags, list):
        if TAG_CLOCK_SKEW not in tags:
            tags.append(TAG_CLOCK_SKEW)
    else:
        doc["tags"] = ([tags] if isinstance(tags, str) else []) + [TAG_CLOCK_SKEW]


def _stamp(
    line: bytes, ingested: str, max_skew_s: float = DEFAULT_MAX_CLOCK_SKEW_S,
    data_stream: dict[str, str] | None = None,
) -> tuple[bytes, str | None]:
    """Set ``event.ingested`` and the skew tag (FR-41); return the line and its ``event.id``.

    ``data_stream`` (FR-61): the CURRENT dataset/namespace. A line written under
    an earlier ``AUDIT_DATASET`` still carries the old values; shipped as-is into
    the current data stream it would fix that stream's constant_keyword to the
    old value on first write and every later record would be refused.

    A line that is not a JSON object is shipped unchanged, without an id.
    """
    try:
        doc = json.loads(line)
    except ValueError:
        return line, None
    if not isinstance(doc, dict):
        return line, None
    event = doc.setdefault("event", {})
    if not isinstance(event, dict):
        return line, None
    event["ingested"] = ingested
    _mark_skew(doc, ingested, max_skew_s)
    if data_stream:
        current = doc.get("data_stream")
        doc["data_stream"] = {**(current if isinstance(current, dict) else {}), **data_stream}
    doc_id = event.get("id")
    stamped = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode()
    return stamped, doc_id if isinstance(doc_id, str) and doc_id else None


class ElasticsearchShipper:
    """Reads the audit JSONL files and bulk-posts them to Elasticsearch.

    Constructed by the middleware when ``config.elasticsearch_url`` is set, and
    driven by its own background task. Every failure is caught and retried; it
    never raises into the application and never touches the request path.
    """

    def __init__(self, config: AuditConfig, metrics: Metrics | None = None) -> None:
        if not config.elasticsearch_url:
            raise ValueError("elasticsearch_url is required to build a shipper")
        self.config = config
        self.metrics = metrics
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()
        self._client: Any = None
        self._state: dict[str, int] = {}
        self._state_path = Path(config.log_dir) / _STATE_FILE.format(pid=os.getpid())
        self._state_dirty = False
        self._bootstrapped = False
        self._logged: set[str] = set()
        self._orphans: dict[str, Any] = {}

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self._task is not None:
            return
        self._load_state()
        self._task = asyncio.get_running_loop().create_task(self._run())

    async def close(self) -> None:
        """Ship whatever is left, then stop. Bounded, like the sink's close."""
        self._stopping.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._task), timeout=self.config.shutdown_flush_timeout
                )
            except (TimeoutError, asyncio.TimeoutError):
                self._task.cancel()
            except Exception as exc:  # noqa: BLE001
                self._warn_once("shipper task failed on close", exc)
            self._task = None
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:  # noqa: BLE001 - closing must not raise
                pass
            self._client = None

    # -- the loop ----------------------------------------------------------

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                await self._tick()
            except Exception as exc:  # noqa: BLE001 - a shipper must not die
                self._warn_once("ship cycle failed", exc)
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self.config.ship_interval_seconds
                )
            except (TimeoutError, asyncio.TimeoutError):
                pass
        # Final drain, so a graceful shutdown does not strand the last records.
        try:
            await self._tick()
        except Exception as exc:  # noqa: BLE001
            self._warn_once("final ship cycle failed", exc)

    async def _tick(self) -> None:
        if not self._bootstrapped:
            await self._bootstrap()
            if not self._bootstrapped:
                # The template is not installed. Shipping now would create the
                # data stream with a dynamic mapping, which no later fix can
                # undo without a reindex (D-11). The records stay on disk and
                # this retries on the next tick; that is the recoverable
                # failure, and the one to prefer.
                return
        for path in self._claimable_files():
            await self._ship_file(path)
        self._prune()
        self._save_state()

    def _prune(self) -> None:
        """Forget files that no longer exist, drop their locks and their state.

        All three grow by one entry per file and never shrink otherwise.
        Rotation deletes files continuously — with daily rollover and no
        retention limit that is a new entry every day, forever, in a file
        rewritten on every change.
        """
        # Keyed on what EXISTS, not on what this worker can currently claim.
        # Another live worker's file is not claimable by us, but its offset
        # must survive: when that worker dies we adopt its file, and a pruned
        # offset would restart it from zero and duplicate every record in it.
        log_dir = Path(self.config.log_dir)
        present: set[str] = set()
        pids_with_files: set[int] = set()
        for path in log_dir.glob("*.jsonl*"):
            key = self._key(path)
            if key is not None:
                present.add(key)
            match = _FILENAME.match(path.name)
            if match is not None:
                pids_with_files.add(int(match.group("pid")))
        gone = [k for k in self._state if k not in present]
        for key in gone:
            del self._state[key]
        if gone:
            self._state_dirty = True

        for name in [n for n in self._orphans if not Path(n).exists()]:
            handle = self._orphans.pop(name)
            try:
                handle.close()   # releases the flock
            except Exception:  # noqa: BLE001
                pass

        self._reap_state_files(log_dir, pids_with_files)

    def _reap_state_files(self, log_dir: Path, pids_with_files: set[int]) -> None:
        """Delete the state file of a dead worker whose logs are all gone.

        A dead worker's offsets are read exactly once, when we adopt one of its
        files (:meth:`_adopt_offset`), so the file has to stay while any of
        them is on disk — another worker may not have claimed its share yet.
        Once rotation and retention have taken the last one, nothing can ever
        need it again, and without this it stays there forever: one more file
        per restart, in the directory the logs live in.
        """
        mine = os.getpid()
        for state_file in log_dir.glob(_STATE_FILE.format(pid="*")):
            name = state_file.stem.rpartition("-")[2]
            if not name.isdigit():
                continue  # _LEGACY_STATE_FILE: new workers still inherit it
            pid = int(name)
            if pid == mine or pid in pids_with_files or _pid_is_alive(pid):
                continue
            try:
                state_file.unlink()
            except OSError:  # already gone, or another worker got there first
                pass

    # -- which files are ours ---------------------------------------------

    def _claimable_files(self) -> list[Path]:
        """Our own process's files, plus any orphaned by a dead worker."""
        log_dir = Path(self.config.log_dir)
        if not log_dir.is_dir():
            return []
        mine = os.getpid()
        claimed: list[Path] = []
        for path in sorted(log_dir.glob("*.jsonl*")):
            match = _FILENAME.match(path.name)
            if match is None:
                continue
            pid = int(match.group("pid"))
            if pid == mine:
                claimed.append(path)
            elif not _pid_is_alive(pid) and self._claim_orphan(path, pid):
                claimed.append(path)
        return claimed

    def _claim_orphan(self, path: Path, pid: int) -> bool:
        """Take an exclusive flock on a dead worker's file.

        Every live worker can see an orphan, and without this they would all
        ship it — one copy of those records per worker. The lock is held for
        the life of this process and released by the kernel if it dies, so a
        second crash cannot strand the file permanently.
        """
        key = str(path)
        if key in self._orphans:
            return True
        try:
            import fcntl

            handle = path.open("rb")
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:  # noqa: BLE001 - another worker holds it, or no fcntl
            return False
        self._orphans[key] = handle
        self._adopt_offset(path, pid)
        return True

    def _adopt_offset(self, path: Path, pid: int) -> None:
        """Continue the dead worker's progress through the file it left.

        Its offsets are in its own ``.audit-shipper-{pid}.json``, which nothing
        else reads. Without this the orphan is shipped from zero and every
        record already indexed from it is sent a second time -- a 0.1 line
        carries no ``event.id``, so its bulk action has no ``_id`` and
        Elasticsearch stores the duplicate. Four gunicorn workers and a restart make that four whole
        files, up to the rotation ceiling each.
        """
        key = self._key(path)
        if key is None or key in self._state:
            return
        state_path = Path(self.config.log_dir) / _STATE_FILE.format(pid=pid)
        try:
            offsets = json.loads(state_path.read_text())
        except (OSError, ValueError):
            return  # no state left behind: the whole file is genuinely unsent
        offset = offsets.get(key)
        if isinstance(offset, int) and offset > 0:
            self._state[key] = offset
            self._state_dirty = True
            _LOG.info(
                "audit_logging shipper: adopted %s at offset %d from dead pid %d",
                path.name,
                offset,
                pid,
            )

    # -- progress ----------------------------------------------------------

    @staticmethod
    def _key(path: Path) -> str | None:
        """``device:inode`` — survives a rename, unlike the file's name."""
        try:
            st = path.stat()
        except OSError:
            return None
        return f"{st.st_dev}:{st.st_ino}"

    def _load_state(self) -> None:
        try:
            self._state = json.loads(self._state_path.read_text())
            return
        except Exception:  # noqa: BLE001 - a missing or corrupt file starts fresh
            self._state = {}
        # No per-process file yet. Before adopting the empty state, inherit any
        # offsets from the single shared file older versions wrote: starting
        # from zero would re-read every existing JSONL file from the beginning
        # and duplicate every record already in the index. Keys are
        # (device, inode) either way, so entries for another worker's files are
        # simply never looked up.
        legacy = Path(self.config.log_dir) / _LEGACY_STATE_FILE
        try:
            inherited = json.loads(legacy.read_text())
        except Exception:  # noqa: BLE001
            return
        if isinstance(inherited, dict):
            self._state = {k: int(v) for k, v in inherited.items() if isinstance(v, int)}
            _LOG.info(
                "audit_logging shipper: inherited %d offset(s) from %s",
                len(self._state),
                _LEGACY_STATE_FILE,
            )

    def _save_state(self) -> None:
        # Only when something moved. This used to rewrite every tick forever,
        # so an idle service still churned the file every few seconds.
        if not self._state_dirty:
            return
        try:
            tmp = self._state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._state))
            os.replace(tmp, self._state_path)
            self._state_dirty = False
        except Exception as exc:  # noqa: BLE001
            self._warn_once("could not persist shipper state", exc)

    # -- shipping ----------------------------------------------------------

    async def _ship_file(self, path: Path) -> None:
        key = self._key(path)
        if key is None:
            return
        offset = self._state.get(key, 0)
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size <= offset:
            return  # nothing new; also the case for a fully shipped rotation

        with path.open("rb") as handle:
            handle.seek(offset)
            while not self._stopping.is_set():
                lines: list[bytes] = []
                consumed = 0
                while len(lines) < self.config.ship_batch_size:
                    raw = handle.readline()
                    if not raw:
                        break
                    if not raw.endswith(b"\n"):
                        # A partial line: the sink is mid-write. Leave it for
                        # the next tick rather than shipping half a document.
                        break
                    consumed += len(raw)
                    stripped = raw.strip()
                    if stripped:
                        lines.append(stripped)
                if not lines:
                    break
                if await self._bulk(lines):
                    offset += consumed
                    self._state[key] = offset
                    self._state_dirty = True
                    self._save_state()
                else:
                    break  # leave the offset; retry the same lines next tick

    async def _bulk(self, lines: list[bytes]) -> bool:
        """POST one bulk request. ``True`` if it was accepted.

        A line carrying ``event.id`` is sent with that id as ``_id`` (FR-36), so
        a replay — an adopted orphan, a lost state file — is refused with 409
        instead of stored twice, and 409 therefore counts as delivered. Any
        other per-document refusal is logged once per error type, counted as
        rejected and lost, and skipped (X-8: no dead-letter file).
        """
        client = await self._http()
        if client is None:
            return False
        index = self.config.index_name
        # Off the loop: a 500-line batch of large documents is seconds of JSON work.
        max_skew = float(getattr(self.config, "max_clock_skew_s", DEFAULT_MAX_CLOCK_SKEW_S))
        data_stream = {"type": "logs", "dataset": self.config.data_stream_dataset,
                       "namespace": self.config.data_stream_namespace}
        payload = await asyncio.to_thread(_bulk_payload, lines, index, _now_iso_ms(), max_skew,
                                          data_stream)
        try:
            response = await client.post(
                "/_bulk",
                content=payload,
                headers={"content-type": "application/x-ndjson"},
            )
        except Exception as exc:  # noqa: BLE001 - the cluster being unreachable is normal
            self._warn_once("elasticsearch unreachable", exc)
            self._count("audit_ship_failures_total", len(lines))
            return False

        if response.status_code >= 300:
            self._warn_once(
                f"bulk rejected with HTTP {response.status_code}",
                RuntimeError(response.text[:400]),
            )
            self._count("audit_ship_failures_total", len(lines))
            return False

        body = response.json()
        if not body.get("errors"):
            self._count("audit_ship_documents_total", len(lines))
            return True

        # Partial failure. The batch still counts as consumed: retrying it
        # forever would block every later record behind a document
        # Elasticsearch will never accept (a mapping conflict, say). Items come
        # back in request order, one per action.
        failed = 0
        for item in body.get("items", []):
            for op in item.values():
                status = op.get("status", 200)
                if status >= 300 and status != 409:  # 409: already indexed
                    failed += 1
                    self._warn_refused(op.get("error"))
        if failed:
            self._count("audit_ship_rejected_total", failed)
            self._count("audit_documents_lost_total", failed)
        self._count("audit_ship_documents_total", len(lines) - failed)
        return True

    def _warn_refused(self, error: Any) -> None:
        """Once per ES error type, with the reason (X-8). Never raises."""
        kind = error.get("type") if isinstance(error, dict) else None
        reason = error.get("reason") if isinstance(error, dict) else error
        key = f"refused:{kind}"
        if key in self._logged:
            return
        self._logged.add(key)
        _LOG.warning(
            "audit_logging shipper: elasticsearch refused a document, skipped and "
            "counted lost (%s: %s)",
            kind,
            str(reason)[:400],
        )

    # -- one-time cluster setup -------------------------------------------

    async def _push_mapping_to_write_index(self, client: Any, template: dict[str, Any]) -> None:
        """FR-60: a template applies only when a backing index is created, so a
        field added in a newer package would be stored but NOT searchable in the
        data stream's current backing index until the next rollover. Adding
        fields to a live mapping is allowed; push them onto the write index.
        404 = the data stream does not exist yet (the template covers it);
        anything else is warned once and shipping continues."""
        mappings = template.get("template", {}).get("mappings", {})
        body = {k: mappings[k] for k in ("properties", "dynamic", "date_detection",
                                         "numeric_detection", "_meta") if k in mappings}
        if "properties" in body:
            # constant_keyword values are fixed by the first document
            # (data_stream.namespace = "live"); re-sending the template's
            # value-less definition is a conflict, and a constant cannot
            # change anyway.
            body["properties"] = _without_constants(body["properties"])
        try:
            response = await client.put(
                f"/{self.config.index_name}/_mapping?write_index_only=true", json=body
            )
        except Exception as exc:  # noqa: BLE001
            self._warn_once("could not update the data stream mapping (continuing)", exc)
            return
        if response.status_code >= 300 and response.status_code != 404:
            self._warn_once(
                "could not update the data stream mapping; new fields are stored but "
                "not searchable until the next rollover (continuing)",
                RuntimeError(response.text[:400]),
            )

    async def _bootstrap(self) -> None:
        """Install the ILM policy and index template, once, before shipping.

        A data stream created before its template gets a dynamic mapping and
        only a reindex fixes it, so this runs first and the shipper does not
        send anything until it has succeeded. Idempotent: Elasticsearch treats
        a repeated PUT as an update.
        """
        if not self.config.elasticsearch_setup:
            self._bootstrapped = True
            return
        client = await self._http()
        if client is None:
            return
        from .templates import ILM_POLICY, index_template_for

        try:
            policy = json.loads(json.dumps(ILM_POLICY))
            phases = policy["policy"]["phases"]
            if self.config.retention_days is None:
                # Keep forever, which is the shipped default: ILM simply never
                # deletes. An audit trail that erases itself on a timer is
                # worse than one that costs disk. The template carries no
                # delete phase, so usually there is nothing to remove — the
                # pop is for an operator-supplied policy that has one.
                phases.pop("delete", None)
            else:
                # Added back rather than edited in place: the shipped policy
                # has no delete phase at all, because never is the default.
                phases.setdefault(
                    "delete", {"actions": {"delete": {"delete_searchable_snapshot": False}}}
                )["min_age"] = f"{self.config.retention_days}d"
            rollover = phases["hot"]["actions"]["rollover"]
            rollover.pop("max_age", None)
            rollover.pop("max_primary_shard_size", None)
            if self.config.rollover_max_age:
                rollover["max_age"] = self.config.rollover_max_age
            if self.config.rollover_max_size:
                rollover["max_primary_shard_size"] = self.config.rollover_max_size
            dataset = self.config.data_stream_dataset
            template = index_template_for(dataset)
            if not await self._schema_version_allows_install(client):
                return
            r1 = await client.put(
                f"/_ilm/policy/{self.config.ilm_policy_name}", json=policy
            )
            r2 = await client.put(
                f"/_index_template/{self.config.index_template_name}", json=template
            )
        except Exception as exc:  # noqa: BLE001
            self._warn_once("could not reach elasticsearch to install the template", exc)
            return

        if r2.status_code >= 300:
            # Do NOT start shipping. Without the template the first document
            # creates a data stream with a dynamic mapping, which is the one
            # failure here that cannot be undone without a reindex.
            self._warn_once(
                "index template install failed — NOT shipping, because the first "
                "document would create a data stream with a dynamic mapping",
                RuntimeError(r2.text[:400]),
            )
            return
        if r1.status_code >= 300:
            self._warn_once("ILM policy install failed (continuing)", RuntimeError(r1.text[:200]))
        await self._push_mapping_to_write_index(client, template)
        _LOG.info(
            "audit_logging: elasticsearch ready, shipping to %s", self.config.index_name
        )
        self._bootstrapped = True

    async def _schema_version_allows_install(self, client: Any) -> bool:
        """FR-48: never overwrite a template written for another schema version.

        No template (404), or one without ``_meta.schema_version`` (0.1, whose
        fields v2 keeps), may be installed over. A different version is only
        replaced with ``schema_upgrade``; otherwise this logs an ERROR once and
        the shipper stays un-bootstrapped, like a failed template install. An
        unreadable answer also refuses, and retries next tick.
        """
        name = self.config.index_template_name
        response = await client.get(f"/_index_template/{name}")
        if response.status_code == 404:
            return True
        if response.status_code >= 300:
            self._warn_once(
                "could not read the existing index template — NOT shipping",
                RuntimeError(response.text[:400]),
            )
            return False
        existing = None
        for entry in response.json().get("index_templates", []):
            meta = entry.get("index_template", {}).get("_meta") or {}
            existing = meta.get("schema_version", existing)
        if existing is None or existing == SCHEMA_VERSION:
            return True
        if getattr(self.config, "schema_upgrade", False) is True:
            _LOG.warning(
                "audit_logging shipper: replacing index template %s schema_version %s "
                "with %s (schema_upgrade)", name, existing, SCHEMA_VERSION,
            )
            return True
        if "schema_version" not in self._logged:
            self._logged.add("schema_version")
            _LOG.error(
                "audit_logging shipper: index template %s has schema_version %s, this "
                "package writes %s — NOT overwriting it and NOT shipping; records stay "
                "on disk. Set schema_upgrade to replace it.",
                name, existing, SCHEMA_VERSION,
            )
        return False

    # -- plumbing ----------------------------------------------------------

    async def _http(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import httpx
        except ImportError:
            self._warn_once(
                "httpx is not installed",
                RuntimeError("pip install 'audit-me[elasticsearch]' to ship without Filebeat"),
            )
            return None
        auth = None
        headers = {}
        if self.config.elasticsearch_api_key:
            headers["authorization"] = f"ApiKey {self.config.elasticsearch_api_key}"
        elif self.config.elasticsearch_username:
            auth = (
                self.config.elasticsearch_username,
                self.config.elasticsearch_password or "",
            )
        self._client = httpx.AsyncClient(
            base_url=str(self.config.elasticsearch_url).rstrip("/"),
            auth=auth,
            headers=headers,
            verify=self.config.elasticsearch_verify_certs,
            timeout=self.config.ship_timeout_seconds,
        )
        return self._client

    def _count(self, name: str, value: int) -> None:
        if self.metrics is None or value <= 0:
            return
        try:
            self.metrics.inc(name, value)
        except Exception:  # noqa: BLE001 - a broken counter must not cost records
            pass

    def _warn_once(self, message: str, exc: BaseException) -> None:
        """One line per distinct failure kind, not one per occurrence.

        A cluster that is down produces a failure every tick; logging each one
        turns an outage into a second outage in the log pipeline.
        """
        kind = f"{message}:{type(exc).__name__}"
        if kind in self._logged:
            return
        self._logged.add(kind)
        _LOG.warning("audit_logging shipper: %s (%s: %s)", message, type(exc).__name__, exc)


def _without_constants(properties: dict[str, Any]) -> dict[str, Any]:
    """A mapping ``properties`` tree minus every ``constant_keyword`` leaf (and
    any object left empty by removing them). Pure; the input is not mutated."""
    out: dict[str, Any] = {}
    for name, spec in properties.items():
        if not isinstance(spec, dict) or spec.get("type") == "constant_keyword":
            continue
        if "properties" in spec:
            inner = _without_constants(spec["properties"])
            if not inner:
                continue
            spec = {**spec, "properties": inner}
        out[name] = spec
    return out
