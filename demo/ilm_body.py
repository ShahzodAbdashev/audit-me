"""Print the ILM request body for `PUT _ilm/policy/apiaudit`.

`infra/elasticsearch/ilm-apiaudit.json` carries a top-level `_meta` envelope
holding `RETENTION_DAYS` — the single retention knob (infra/README §4). The
ILM API accepts only the `policy` key and rejects anything else outright:

    unknown field [_meta]

`bootstrap.py` strips it and resolves the retention into the delete phase, so
the knob and the policy can never drift. Anything else that PUTs this file by
hand has to do the same, which is what this script is for.
"""

from __future__ import annotations

import json
import pathlib
import sys

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "infra/elasticsearch/ilm-apiaudit.json"


def main() -> int:
    doc = json.loads(SOURCE.read_text())
    meta = doc.pop("_meta", {})
    days = meta.get("RETENTION_DAYS")
    if days is not None:
        doc["policy"]["phases"]["delete"]["min_age"] = f"{days}d"
    json.dump({"policy": doc["policy"]}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
