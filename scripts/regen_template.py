"""Rewrite infra/elasticsearch/template-apiaudit.json from audit_logging.templates.INDEX_TEMPLATE.

Run: ./.venv/bin/python scripts/regen_template.py   (tests/unit/test_infra_template.py checks it)
"""

from __future__ import annotations

import json
from pathlib import Path

from audit_logging.templates import INDEX_TEMPLATE

TARGET = Path(__file__).resolve().parents[1] / "infra" / "elasticsearch" / "template-apiaudit.json"


def render() -> str:
    return json.dumps(INDEX_TEMPLATE, indent=2) + "\n"


if __name__ == "__main__":
    TARGET.write_text(render(), encoding="utf-8")
    print(f"wrote {TARGET}")
