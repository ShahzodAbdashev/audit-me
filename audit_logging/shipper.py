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

Progress is kept in ``.audit-shipper-state.json`` beside the logs, keyed by
``(device, inode)`` rather than by name, so a rotation cannot make it re-send a
file it has already read.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from .config import AuditConfig
from ._contracts import Metrics

__all__ = ["ElasticsearchShipper"]

_LOG = logging.getLogger("audit_logging.shipper")

#: ``{service}-{pid}.jsonl`` and its rotations ``.1`` … ``.N``.
_FILENAME = re.compile(r"^(?P<service>.+)-(?P<pid>\d+)\.jsonl(?:\.(?P<gen>\d+))?$")

_STATE_FILE = ".audit-shipper-state.json"


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
        self._state_path = Path(config.log_dir) / _STATE_FILE
        self._bootstrapped = False
        self._logged: set[str] = set()

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
        self._save_state()

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
            if pid == mine or not _pid_is_alive(pid):
                claimed.append(path)
        return claimed

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
        except Exception:  # noqa: BLE001 - a missing or corrupt file starts fresh
            self._state = {}

    def _save_state(self) -> None:
        try:
            tmp = self._state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._state))
            os.replace(tmp, self._state_path)
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
                    self._save_state()
                else:
                    break  # leave the offset; retry the same lines next tick

    async def _bulk(self, lines: list[bytes]) -> bool:
        """POST one bulk request. ``True`` if it was accepted."""
        client = await self._http()
        if client is None:
            return False
        index = self.config.index_name
        action = json.dumps({"create": {"_index": index}}).encode()
        payload = b"\n".join(part for line in lines for part in (action, line)) + b"\n"
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
        if body.get("errors"):
            # Partial failure. The batch still counts as consumed: retrying it
            # forever would block every later record behind a document
            # Elasticsearch will never accept (a mapping conflict, say).
            rejected = sum(
                1
                for item in body.get("items", [])
                for op in item.values()
                if op.get("status", 200) >= 300
            )
            first = next(
                (
                    op.get("error")
                    for item in body.get("items", [])
                    for op in item.values()
                    if op.get("status", 200) >= 300
                ),
                None,
            )
            self._warn_once(
                f"elasticsearch rejected {rejected} of {len(lines)} documents",
                RuntimeError(json.dumps(first)[:400]),
            )
            self._count("audit_ship_rejected_total", rejected)
            self._count("audit_ship_documents_total", len(lines) - rejected)
            return True
        self._count("audit_ship_documents_total", len(lines))
        return True

    # -- one-time cluster setup -------------------------------------------

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
        from .templates import ILM_POLICY, ILM_POLICY_NAME, INDEX_TEMPLATE, INDEX_TEMPLATE_NAME

        try:
            policy = json.loads(json.dumps(ILM_POLICY))
            policy["policy"]["phases"]["delete"]["min_age"] = f"{self.config.retention_days}d"
            r1 = await client.put(f"/_ilm/policy/{ILM_POLICY_NAME}", json=policy)
            r2 = await client.put(
                f"/_index_template/{INDEX_TEMPLATE_NAME}", json=INDEX_TEMPLATE
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
        _LOG.info(
            "audit_logging: elasticsearch ready, shipping to %s", self.config.index_name
        )
        self._bootstrapped = True

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
