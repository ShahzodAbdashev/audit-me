"""Shared fixtures. Owned by A1; extend rather than replace."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_logging.config import AuditConfig  # noqa: E402
from audit_logging.sinks.null_sink import NullSink  # noqa: E402


@pytest.fixture
def log_dir(tmp_path: Path) -> Path:
    d = tmp_path / "audit"
    d.mkdir()
    return d


@pytest.fixture
def config(log_dir: Path) -> AuditConfig:
    """A config safe for unit tests: tiny flush interval, temp directory."""
    return AuditConfig(
        service_name="test-service",
        service_version="0.0.1",
        environment="test",
        log_dir=log_dir,
        flush_interval_seconds=0.05,
        shutdown_flush_timeout=2.0,
    )


@pytest.fixture
def sink() -> NullSink:
    return NullSink()


@pytest.fixture(autouse=True)
def _clear_audit_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Stop a stray AUDIT_* var in the shell from changing a test's meaning."""
    import os

    for key in [k for k in os.environ if k.startswith("AUDIT_")]:
        monkeypatch.delenv(key, raising=False)
    yield


@pytest.fixture
def asgi_scope() -> dict[str, Any]:
    """A minimal, valid HTTP scope."""
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/items/1",
        "raw_path": b"/items/1",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver")],
        "client": ("10.0.0.1", 51234),
        "server": ("testserver", 80),
    }
