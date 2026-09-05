"""AuditConfig validation and environment loading. Owned by A1."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from audit_logging.config import MAX_ALLOWED_BODY_BYTES, AuditConfig


def test_defaults_match_the_plan() -> None:
    c = AuditConfig(service_name="orders-api")
    assert c.enabled is True
    assert c.max_body_bytes == 1_048_576          # D-4
    assert c.queue_max_bytes == 64 * 1024 * 1024  # D-9 / FR-18
    assert c.flush_max_bytes == 4 * 1024 * 1024
    assert c.flush_interval_seconds == 1.0
    assert c.shutdown_flush_timeout == 10.0
    assert c.file_max_bytes == 256 * 1024 * 1024  # §5
    assert c.file_backup_count == 8
    assert c.fsync is False
    assert c.log_dir == Path("/var/log/audit")
    assert "/health" in c.exclude_paths and "/metrics" in c.exclude_paths


def test_service_name_is_required() -> None:
    with pytest.raises(ValidationError):
        AuditConfig()  # type: ignore[call-arg]


@pytest.mark.parametrize("bad", [0, -1, MAX_ALLOWED_BODY_BYTES + 1])
def test_max_body_bytes_bounds(bad: int) -> None:
    with pytest.raises(ValidationError):
        AuditConfig(service_name="s", max_body_bytes=bad)


def test_max_body_bytes_accepts_the_ceiling() -> None:
    assert AuditConfig(service_name="s", max_body_bytes=MAX_ALLOWED_BODY_BYTES).max_body_bytes


def test_queue_must_be_at_least_one_flush() -> None:
    with pytest.raises(ValidationError):
        AuditConfig(service_name="s", queue_max_bytes=1024, flush_max_bytes=2048)
    AuditConfig(service_name="s", queue_max_bytes=2048, flush_max_bytes=2048)


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        AuditConfig(service_name="s", sampling_rate=0.1)  # type: ignore[call-arg]


def test_FR_15_kill_switch_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_SERVICE_NAME", "orders-api")
    monkeypatch.setenv("AUDIT_ENABLED", "false")
    assert AuditConfig().enabled is False


def test_env_prefix_loads_every_kind_of_field(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_SERVICE_NAME", "billing")
    monkeypatch.setenv("AUDIT_MAX_BODY_BYTES", "2048")
    monkeypatch.setenv("AUDIT_FSYNC", "true")
    monkeypatch.setenv("AUDIT_FLUSH_INTERVAL_SECONDS", "0.25")
    monkeypatch.setenv("AUDIT_LOG_DIR", "/tmp/x")
    c = AuditConfig()
    assert (c.service_name, c.max_body_bytes, c.fsync) == ("billing", 2048, True)
    assert c.flush_interval_seconds == 0.25
    assert c.log_dir == Path("/tmp/x")


@pytest.mark.parametrize(
    "raw, expected",
    [("/a,/b", ["/a", "/b"]), ('["/a", "/b"]', ["/a", "/b"]), ("/a", ["/a"])],
)
def test_list_fields_accept_csv_and_json(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: list[str]
) -> None:
    monkeypatch.setenv("AUDIT_SERVICE_NAME", "s")
    monkeypatch.setenv("AUDIT_EXCLUDE_PATHS", raw)
    assert AuditConfig().exclude_paths == expected


@pytest.mark.parametrize(
    "name, dataset",
    [
        ("orders-api", "apiaudit.orders_api"),
        ("Orders API", "apiaudit.orders_api"),
        ("billing.v2", "apiaudit.billing.v2"),
        ("SVC/../etc", "apiaudit.svc_.._etc"),
    ],
)
def test_data_stream_dataset_is_sanitised(name: str, dataset: str) -> None:
    assert AuditConfig(service_name=name).data_stream_dataset == dataset


def test_user_resolver_is_callable_and_optional() -> None:
    assert AuditConfig(service_name="s").user_resolver is None
    c = AuditConfig(service_name="s", user_resolver=lambda scope: {"id": "u1"})
    assert c.user_resolver is not None
    assert c.user_resolver({}) == {"id": "u1"}
