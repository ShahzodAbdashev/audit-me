"""infra/elasticsearch/template-apiaudit.json is exactly templates.INDEX_TEMPLATE (scripts/regen_template.py)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from audit_logging.templates import INDEX_TEMPLATE

ROOT = Path(__file__).resolve().parents[2]


def test_infra_template_equals_the_packaged_one() -> None:
    on_disk = json.loads((ROOT / "infra" / "elasticsearch" / "template-apiaudit.json").read_text("utf-8"))
    assert on_disk == INDEX_TEMPLATE, "run: ./.venv/bin/python scripts/regen_template.py"


def test_regen_script_output_is_what_is_on_disk() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import regen_template
    finally:
        sys.path.pop(0)
    assert regen_template.TARGET.read_text("utf-8") == regen_template.render()
