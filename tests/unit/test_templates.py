"""The packaged template must not drift from the one operators apply."""

from __future__ import annotations

import json
from pathlib import Path

from audit_logging.templates import (
    DEFAULT_RETENTION_DAYS,
    ILM_POLICY,
    ILM_POLICY_NAME,
    INDEX_TEMPLATE,
    INDEX_TEMPLATE_NAME,
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


def test_the_index_pattern_matches_what_the_config_can_produce() -> None:
    """`AuditConfig` refuses a dataset outside this prefix; keep them agreed."""
    assert INDEX_TEMPLATE["index_patterns"] == ["logs-apiaudit.*-*"]


def test_names_match_the_operator_script() -> None:
    source = (INFRA / "bootstrap.py").read_text()
    assert f'INDEX_TEMPLATE_NAME = "{INDEX_TEMPLATE_NAME}"' in source
    assert f'ILM_POLICY_NAME = "{ILM_POLICY_NAME}"' in source


def test_the_template_references_the_ilm_policy_by_its_real_name() -> None:
    """A policy installed under another name silently never attaches."""
    lifecycle = INDEX_TEMPLATE["template"]["settings"]["index"]["lifecycle"]["name"]
    assert lifecycle == ILM_POLICY_NAME
