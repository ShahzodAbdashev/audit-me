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
        ("orders-api", "orders_api"),
        ("Orders API", "orders_api"),
        ("billing.v2", "billing.v2"),
        ("SVC/../etc", "svc_.._etc"),
    ],
)
def test_data_stream_dataset_is_sanitised(name: str, dataset: str) -> None:
    assert AuditConfig(service_name=name).data_stream_dataset == dataset


def test_user_resolver_is_callable_and_optional() -> None:
    assert AuditConfig(service_name="s").user_resolver is None
    c = AuditConfig(service_name="s", user_resolver=lambda scope: {"id": "u1"})
    assert c.user_resolver is not None
    assert c.user_resolver({}) == {"id": "u1"}


# ---------------------------------------------------------------------------
# FR-33 — declaring where the documents land
# ---------------------------------------------------------------------------


def test_FR_33_index_name_is_derived_from_service_and_environment() -> None:
    c = AuditConfig(service_name="Orders API", environment="prod")
    assert c.data_stream_dataset == "orders_api"
    assert c.data_stream_namespace == "prod"
    assert c.index_name == "logs-orders_api-prod"


def test_FR_33_dataset_and_namespace_can_be_overridden() -> None:
    c = AuditConfig(service_name="anything", dataset="billing", namespace="tenant-a")
    assert c.index_name == "logs-billing-tenant_a"


def test_FR_33_several_services_can_share_one_index() -> None:
    """The same `dataset` in every service collects them in one data stream.

    They stay distinguishable by `service.name`, which every document carries
    as an indexed keyword.
    """
    orders = AuditConfig(service_name="orders-api", dataset="platform", environment="prod")
    payments = AuditConfig(service_name="payments-api", dataset="platform", environment="prod")
    assert orders.index_name == payments.index_name == "logs-platform-prod"
    assert orders.index_template_name == payments.index_template_name == "logs-platform"


@pytest.mark.parametrize("bad", ["has-a-dash", "wild*card", "logs-foo", ".leading_dot", "   "])
def test_FR_33_a_dataset_that_would_widen_the_template_is_refused(bad: str) -> None:
    """The guard that matters.

    The template is installed as `logs-<dataset>` matching `logs-<dataset>-*`,
    at `priority: 500` — which outranks Elasticsearch's built-in `logs`
    template (100). A dataset carrying `-` or `*` widens that pattern onto data
    streams this package does not own, and imposes its `dynamic: false` mapping
    on them: their documents then index with none of their fields. Silent at
    every layer, so it has to be refused here.
    """
    with pytest.raises(ValidationError):
        AuditConfig(service_name="s", dataset=bad)


def test_FR_33_template_and_policy_names_are_scoped_to_the_dataset() -> None:
    """Two datasets must not share a template, or the last one to start wins."""
    c = AuditConfig(service_name="orders-api", environment="prod")
    assert c.index_template_name == "logs-orders_api"
    assert c.index_template_pattern == "logs-orders_api-*"
    assert c.ilm_policy_name == "orders_api-ilm"


def test_FR_33_overrides_are_sanitised_like_the_derived_form() -> None:
    """Elasticsearch rejects a data stream name with uppercase or `,\\\\/*?"<>|`
    or a space, so an override cannot be passed through unchecked."""
    c = AuditConfig(service_name="s", dataset="Billing V2", namespace="Tenant A")
    assert c.index_name == "logs-billing_v2-tenant_a"


def test_FR_33_env_vars_reach_the_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_SERVICE_NAME", "s")
    monkeypatch.setenv("AUDIT_DATASET", "custom")
    monkeypatch.setenv("AUDIT_NAMESPACE", "staging")
    assert AuditConfig().index_name == "logs-custom-staging"


def test_config_uses_no_pydantic_settings_api_newer_than_the_declared_floor() -> None:
    """pyproject declares `pydantic-settings>=2`; keep the code honest to that.

    `NoDecode` was the original way this module stopped the env source from
    JSON-decoding its list fields. It only exists in pydantic-settings >= 2.8,
    so importing it made the whole package unimportable for anyone on an older
    pin — a real ImportError in a real service, from a floor we never declared.

    A library does not get to dictate its consumer's stack. `_RawListEnvSource`
    does the same job across 2.x. Verified working on 2.0.3 through 2.15.
    """
    import ast
    import pathlib

    source = (
        pathlib.Path(__file__).resolve().parents[2] / "audit_logging" / "config.py"
    ).read_text()
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "pydantic_settings"
        ):
            imported |= {a.name for a in node.names}

    too_new = {"NoDecode", "CliApp", "CliSettingsSource", "SettingsError"}
    assert not (imported & too_new), (
        f"{imported & too_new} needs a newer pydantic-settings than pyproject declares"
    )


def test_list_fields_accept_csv_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The form people actually write, and the one that used to raise.

    The default env source calls `json.loads` on any field it considers
    complex, so `/health,/metrics` failed before a validator could see it.
    """
    monkeypatch.setenv("AUDIT_SERVICE_NAME", "s")
    monkeypatch.setenv("AUDIT_EXCLUDE_PATHS", "/health,/metrics,/live")
    monkeypatch.setenv("AUDIT_EXTRA_REDACT_KEYS", "email,phone")
    c = AuditConfig()
    assert c.exclude_paths == ["/health", "/metrics", "/live"]
    assert c.extra_redact_keys == ["email", "phone"]
