"""The packaged template must not drift from the one operators apply."""

from __future__ import annotations

import json
from pathlib import Path

from audit_logging.templates import (
    DATASET_PLACEHOLDER,
    DEFAULT_RETENTION_DAYS,
    ILM_POLICY,
    INDEX_TEMPLATE,
    ilm_policy_name_for,
    index_template_for,
    index_template_name_for,
)

INFRA = Path(__file__).resolve().parents[2] / "infra" / "elasticsearch"


def test_the_packaged_template_matches_infra() -> None:
    """Two copies of a mapping is two chances to be wrong.

    `infra/elasticsearch/*.json` is what an operator applies with curl or
    bootstrap.py; `audit_logging/templates.py` is what the built-in shipper
    installs. If they drift, one set of clusters silently gets a different
    mapping from the other — so this fails instead.
    """
    on_disk = json.loads((INFRA / "template-apiaudit.json").read_text())
    assert INDEX_TEMPLATE == on_disk


def test_the_packaged_ilm_matches_infra_minus_its_meta_envelope() -> None:
    on_disk = json.loads((INFRA / "ilm-apiaudit.json").read_text())
    meta = on_disk.pop("_meta", {})
    assert ILM_POLICY == on_disk
    assert DEFAULT_RETENTION_DAYS == meta.get("RETENTION_DAYS", 90)


def test_dynamic_false_is_present_at_every_level() -> None:
    """The property the whole mapping bound rests on (D-11).

    A nested object that forgets it re-opens dynamic mapping for that subtree,
    which is exactly the silent failure this template exists to prevent.
    """
    mappings = INDEX_TEMPLATE["template"]["mappings"]
    assert mappings["dynamic"] is False

    def walk(node: dict, path: str = "") -> list[str]:
        bad = []
        for name, spec in node.get("properties", {}).items():
            here = f"{path}.{name}".lstrip(".")
            if "properties" in spec:
                if spec.get("dynamic") is not False:
                    bad.append(here)
                bad += walk(spec, here)
        return bad

    assert walk(mappings) == []


def test_the_unbound_template_carries_the_placeholder() -> None:
    """The shipped constant is a template *for* a dataset, not for one dataset."""
    assert INDEX_TEMPLATE["index_patterns"] == [f"logs-{DATASET_PLACEHOLDER}-*"]


def test_binding_scopes_the_pattern_to_exactly_one_dataset() -> None:
    """The pattern must never widen past the dataset that installs it.

    This template is `priority: 500`, which outranks Elasticsearch's built-in
    `logs` template (100). A pattern of `logs-*-*` would therefore apply this
    `dynamic: false` audit mapping to every unrelated logs data stream in the
    cluster, and their documents would be indexed with none of their fields.
    """
    bound = index_template_for("orders_api")
    assert bound["index_patterns"] == ["logs-orders_api-*"]
    assert "*" not in "".join(bound["index_patterns"]).replace("-*", "")


def test_binding_does_not_mutate_the_module_constant() -> None:
    """The shipper edits the policy it installs; the next caller must not see it."""
    bound = index_template_for("orders_api")
    bound["index_patterns"] = ["logs-tampered-*"]
    assert INDEX_TEMPLATE["index_patterns"] == [f"logs-{DATASET_PLACEHOLDER}-*"]
    assert index_template_for("orders_api")["index_patterns"] == ["logs-orders_api-*"]


def test_names_match_the_operator_script() -> None:
    """bootstrap.py derives the same two names, or it installs orphans."""
    source = (INFRA / "bootstrap.py").read_text()
    assert 'INDEX_TEMPLATE_NAME = f"logs-{DATASET}"' in source
    assert 'ILM_POLICY_NAME = f"{DATASET}-ilm"' in source
    assert f'DATASET_PLACEHOLDER = "{DATASET_PLACEHOLDER}"' in source


def test_names_match_what_the_config_derives() -> None:
    """AuditConfig and templates.py must agree, or the shipper installs orphans."""
    from audit_logging.config import AuditConfig

    config = AuditConfig(service_name="orders-api", environment="prod")
    dataset = config.data_stream_dataset
    assert config.index_template_name == index_template_name_for(dataset)
    assert config.ilm_policy_name == ilm_policy_name_for(dataset)
    assert config.index_template_pattern == index_template_for(dataset)["index_patterns"][0]
    assert config.index_name == "logs-orders_api-prod"


def test_the_bound_template_references_the_ilm_policy_by_its_real_name() -> None:
    """A policy installed under another name silently never attaches."""
    bound = index_template_for("orders_api")
    lifecycle = bound["template"]["settings"]["index"]["lifecycle"]["name"]
    assert lifecycle == ilm_policy_name_for("orders_api")
    assert bound["_meta"]["ilm_policy"] == ilm_policy_name_for("orders_api")
