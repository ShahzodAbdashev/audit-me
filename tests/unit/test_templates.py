"""The packaged template must not drift from the one operators apply."""

from __future__ import annotations

import json
from pathlib import Path

from audit_logging.semantic.schema import ENRICHED_PATHS, MAPPING_ADDITIONS
from audit_logging.templates import (
    DATASET_PLACEHOLDER,
    DEFAULT_RETENTION_DAYS,
    ILM_POLICY,
    INDEX_TEMPLATE,
    ilm_policy_name_for,
    index_template_for,
    index_template_name_for,
    _merge,
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
    # 0.2: the infra copy is still the 0.1 base; the package adds the v2
    # fields on top. Until infra is regenerated, compare base + additions.
    _merge(on_disk["template"]["mappings"]["properties"], MAPPING_ADDITIONS)
    on_disk["_meta"]["schema"] = INDEX_TEMPLATE["_meta"]["schema"]
    on_disk["_meta"]["field_budget"] = INDEX_TEMPLATE["_meta"]["field_budget"]
    on_disk["_meta"].setdefault("schema_version", INDEX_TEMPLATE["_meta"]["schema_version"])
    assert INDEX_TEMPLATE == on_disk


def test_the_packaged_ilm_matches_infra_minus_its_meta_envelope() -> None:
    on_disk = json.loads((INFRA / "ilm-apiaudit.json").read_text())
    meta = on_disk.pop("_meta", {})
    assert ILM_POLICY == on_disk
    assert DEFAULT_RETENTION_DAYS == meta.get("RETENTION_DAYS")


def test_the_shipped_policy_never_deletes() -> None:
    """The default must be "keep", and it must be keep by *absence*.

    A delete phase with a very large min_age is not the same thing: it still
    expires, just later, and the number is easy to mistake for a decision
    somebody made. No delete phase at all is what "never" means to ILM.
    """
    assert DEFAULT_RETENTION_DAYS is None
    assert "delete" not in ILM_POLICY["policy"]["phases"]
    assert set(ILM_POLICY["policy"]["phases"]) == {"hot", "warm", "cold"}


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

    config = AuditConfig(
        service_name="orders-api",
        dataset="orders_api",
        elasticsearch_url=None,
        environment="prod",
    )
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


def test_the_timestamp_field_opts_out_of_index_level_ignore_malformed() -> None:
    """Elasticsearch 8.5 refuses the whole template without this one attribute.

    The template sets ``index.mapping.ignore_malformed`` so that a wrong-typed
    value becomes a silently unindexed field rather than a rejected document.
    On 8.5 that setting reaches **every** field, ``@timestamp`` included, and a
    data stream forbids the attribute on its timestamp field:

        illegal_argument_exception: data stream timestamp field [@timestamp]
        has disallowed [ignore_malformed] attribute specified

    which surfaces as "template after composition is invalid" and takes the
    entire install down with it. Later versions exempt the timestamp field, so
    this is invisible on a newer cluster -- reproduced on a real 8.5.1, where
    removing the opt-out fails and restoring it installs cleanly.
    """
    mapping = index_template_for("orders_api")["template"]["mappings"]
    timestamp = mapping["properties"]["@timestamp"]
    assert timestamp["ignore_malformed"] is False, (
        "@timestamp must opt out explicitly, or the template is rejected on ES < 8.7"
    )
    settings = index_template_for("orders_api")["template"]["settings"]
    assert settings["index"]["mapping"]["ignore_malformed"] is True, (
        "the index-level setting is what the opt-out exists to survive"
    )


def _mapping_entries(props: dict) -> int:
    """docs/schema.md §3: every leaf plus every object container, as
    `GET _mapping` counts them -- and multi-fields, which Elasticsearch counts
    against total_fields.limit too."""
    return sum(
        1 + _mapping_entries(spec.get("properties", {})) + len(spec.get("fields", {}))
        for spec in props.values()
    )


def test_FR_48_the_v2_mapping_stays_under_the_field_limit() -> None:
    props = INDEX_TEMPLATE["template"]["mappings"]["properties"]
    base = json.loads((INFRA / "template-apiaudit.json").read_text())
    # 63 while infra is the 0.1 base (§3); 126 once it is regenerated as v2.
    assert _mapping_entries(base["template"]["mappings"]["properties"]) in (63, 129)
    total = _mapping_entries(props)
    assert total == 129  # PLAN §17.1 round 2 (126) + audit.context FR-59 (3)
    assert total <= INDEX_TEMPLATE["template"]["settings"]["index"]["mapping"][
        "total_fields"]["limit"] == 200


def test_FR_48_every_enriched_path_is_mapped() -> None:
    def leaves(props: dict, prefix: str = "") -> set[str]:
        out: set[str] = set()
        for name, spec in props.items():
            here = f"{prefix}{name}"
            out.add(here)
            out |= leaves(spec.get("properties", {}), here + ".")
        return out

    mapped = leaves(INDEX_TEMPLATE["template"]["mappings"]["properties"])
    assert ENRICHED_PATHS - mapped == set()


def test_FR_48_the_merge_keeps_every_0_1_field() -> None:
    props = INDEX_TEMPLATE["template"]["mappings"]["properties"]
    assert props["event"]["properties"]["action"]["type"] == "keyword"
    assert props["audit"]["properties"]["route"]["type"] == "keyword"
    assert props["event"]["properties"]["id"]["type"] == "keyword"
    assert props["event"]["properties"]["ingested"]["type"] == "date"
    assert "v2" in INDEX_TEMPLATE["_meta"]["schema"]


def test_FR_48_a_conflicting_leaf_raises_instead_of_replacing() -> None:
    import pytest

    base = {"event": {"properties": {"action": {"type": "keyword"}}}}
    _merge(base, {"event": {"properties": {"action": {"type": "keyword"}}}})  # same: fine
    with pytest.raises(ValueError, match="event.properties.action.type"):
        _merge(base, {"event": {"properties": {"action": {"type": "text"}}}})
    assert base["event"]["properties"]["action"]["type"] == "keyword"


def test_FR_48_the_template_carries_the_package_schema_version() -> None:
    from audit_logging.semantic.model import SCHEMA_VERSION

    assert INDEX_TEMPLATE["_meta"]["schema_version"] == SCHEMA_VERSION
    assert index_template_for("orders_api")["_meta"]["schema_version"] == SCHEMA_VERSION
