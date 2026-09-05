"""Fixtures shared by both acceptance tiers (Agent A6).

Owned by A6. ``tests/conftest.py`` (A1) still applies — this file adds, it does
not replace.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from audit_logging.config import AuditConfig
from audit_logging.metrics import InMemoryMetrics
from audit_logging.middleware import AuditMiddleware
from audit_logging.sinks.file_sink import FileSink

from ._apps import Received, make_app
from ._es_double import InProcessElasticsearch, IndexTemplate

__all__ = ["Audited", "IS_ROOT"]

#: Root ignores file-mode bits, which makes AC-16's permission story untestable.
IS_ROOT = os.geteuid() == 0


@dataclass
class Audited:
    """One wired-up application: middleware, a real FileSink, a real log dir."""

    app: FastAPI
    config: AuditConfig
    sink: FileSink
    metrics: InMemoryMetrics
    received: Received
    log_dir: Path
    client: httpx.AsyncClient

    # -- the file the sink writes -------------------------------------------

    @property
    def path(self) -> Path:
        """The active JSONL file (FR-26: ``{service}-{pid}.jsonl``)."""
        return self.sink.path

    def rotated_paths(self) -> list[Path]:
        """``.1`` … ``.N``, newest first, as FR-22 names them.

        Globs the directory rather than walking ``.1``, ``.2``, … until one is
        missing. The walk was a real defect in this harness: `FileSink._rotate`
        can leave a **gap** in the sequence (see `tests/AC-matrix.md` §7,
        D-A6-5), and a walk silently stops at the gap — so every older
        generation vanished from `lines()` and the loss was reported against
        the package as "94 lines did not survive rotation" when the lines were
        on disk the whole time. A test harness that turns one defect into a
        different, louder, wrong one is worse than no harness.

        `rotated_indices()` exposes the raw numbering so a test can assert on
        the gap itself rather than inferring it.
        """
        return [path for _, path in self._rotated_by_index()]

    def rotated_indices(self) -> list[int]:
        """The ``N`` of every ``.N`` on disk, ascending. Contiguous when sane."""
        return [index for index, _ in self._rotated_by_index()]

    def _rotated_by_index(self) -> list[tuple[int, Path]]:
        prefix = f"{self.sink.path.name}."
        found: list[tuple[int, Path]] = []
        for candidate in self.sink.path.parent.glob(f"{prefix}*"):
            suffix = candidate.name[len(prefix) :]
            if suffix.isdigit():
                found.append((int(suffix), candidate))
        return sorted(found)

    async def flush(self) -> None:
        """Force the background flusher to write what is queued, now."""
        await self.sink.flush()

    def lines(self, *, include_rotated: bool = False) -> list[str]:
        """Every JSONL line on disk, oldest first."""
        files: list[Path] = []
        if include_rotated:
            files.extend(reversed(self.rotated_paths()))
        if self.sink.path.exists():
            files.append(self.sink.path)
        out: list[str] = []
        for path in files:
            with path.open(encoding="utf-8") as handle:
                out.extend(line for line in (raw.strip() for raw in handle) if line)
        return out

    def documents(self, *, include_rotated: bool = False) -> list[dict[str, Any]]:
        """Every audit document on disk, parsed."""
        return [json.loads(line) for line in self.lines(include_rotated=include_rotated)]

    async def indexed(
        self, es: InProcessElasticsearch, *, include_rotated: bool = False, strict: bool = True
    ) -> list[dict[str, Any]]:
        """Flush, then push every line through the template-enforcing double.

        This is the Tier 2 stand-in for "the document is in Elasticsearch":
        the same bytes Filebeat would ship, validated against the same mapping
        Elasticsearch would apply.
        """
        await self.flush()
        for line in self.lines(include_rotated=include_rotated):
            es.index_line(line, strict=strict)
        return es.documents


@pytest.fixture
def template() -> IndexTemplate:
    """The real ``infra/elasticsearch/template-apiaudit.json``."""
    return IndexTemplate.load()


@pytest.fixture
def es(template: IndexTemplate) -> InProcessElasticsearch:
    """A fresh in-process Elasticsearch double, per test."""
    return InProcessElasticsearch(template)


@pytest.fixture(autouse=True)
def _reset_warn_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """``middleware._WARNED`` is a per-process latch; unlatch it per test."""
    import audit_logging.middleware as middleware_module

    monkeypatch.setattr(middleware_module, "_WARNED", False)


@pytest.fixture
def audit_log_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "audit"
    directory.mkdir()
    return directory


def build_config(log_dir: Path, **overrides: Any) -> AuditConfig:
    """A config sane for an integration test: temp dir, quick flush."""
    values: dict[str, Any] = {
        "service_name": "orders-api",
        "service_version": "1.4.2",
        "environment": "test",
        "log_dir": log_dir,
        "flush_interval_seconds": 0.05,
        "shutdown_flush_timeout": 5.0,
        "exclude_paths": ["/health", "/metrics"],
    }
    values.update(overrides)
    return AuditConfig(**values)


@pytest.fixture
async def make_audited(
    audit_log_dir: Path,
) -> AsyncIterator[Callable[..., Any]]:
    """Factory: build an audited app + client with config overrides."""
    built: list[Audited] = []

    async def factory(app: FastAPI | None = None, **overrides: Any) -> Audited:
        config = build_config(audit_log_dir, **overrides)
        metrics = InMemoryMetrics()
        sink = FileSink(config, metrics)
        if app is None:
            app, received = make_app()
        else:
            received = Received()
        app.add_middleware(AuditMiddleware, config=config, sink=sink, metrics=metrics)
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://audit.test"
        )
        wired = Audited(
            app=app,
            config=config,
            sink=sink,
            metrics=metrics,
            received=received,
            log_dir=audit_log_dir,
            client=client,
        )
        built.append(wired)
        return wired

    yield factory

    for wired in built:
        try:
            await wired.client.aclose()
        finally:
            await wired.sink.close()


@pytest.fixture
async def audited(make_audited: Callable[..., Any]) -> Audited:
    """The default audited app: real FileSink, real redaction, temp log dir."""
    result: Audited = await make_audited()
    return result


@pytest.fixture
def restore_modes() -> Iterator[list[tuple[Path, int]]]:
    """Remember file modes a test changes, and put them back (AC-16)."""
    saved: list[tuple[Path, int]] = []
    yield saved
    for path, mode in reversed(saved):
        try:
            os.chmod(path, mode)
        except OSError:  # pragma: no cover - best effort teardown
            pass
