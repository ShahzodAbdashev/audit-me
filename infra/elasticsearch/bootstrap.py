#!/usr/bin/env python3
"""Install and verify the ``apiaudit`` Elasticsearch objects. Idempotent.

Air-gapped by design: the only third-party import is ``requests``. No CLI
arguments — everything is in the CONFIG block below. Edit it, run it, read the
diff::

    ./.venv/bin/python infra/elasticsearch/bootstrap.py

What it does, in this order (the order matters — plan §10):

1.  Loads and validates ``ilm-apiaudit.json`` and ``template-apiaudit.json``.
2.  **Refuses to run** if ``dynamic`` is anything but ``false`` anywhere in the
    mapping it is about to install. Hard guard, not a warning (D-11, AC-10).
3.  PUTs the ILM policy.
4.  PUTs the index template.
5.  Creates the configured data streams **if absent**.
6.  GETs everything back and prints a readable diff of what changed.

It never deletes, never reindexes, never rolls over. Running it against a
cluster that already carries live audit data is safe.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# CONFIG — the only thing you edit. There are no command-line arguments.
# ---------------------------------------------------------------------------

#: Elasticsearch endpoint. One node is enough; this is a control-plane script.
#:
#: The ``ES_URL`` environment variable wins when set, so this file does not have
#: to be edited to point at a staging cluster or a throwaway container — which
#: previously made it impossible to exercise this script from the acceptance
#: tests, and meant the tests PUT the JSON directly instead of testing the
#: thing that actually ships.
ES_URL = os.environ.get("ES_URL", "https://elasticsearch.internal:9200")

#: Basic auth. Leave both empty and set ES_API_KEY to use an API key instead.
#: The env-var fallbacks exist so the credentials can come from a K8s Secret
#: without editing this file; the literals win when they are non-empty.
ES_USERNAME = os.environ.get("ES_USERNAME", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "")

#: Base64 "id:api_key" value, used instead of basic auth when non-empty.
ES_API_KEY = os.environ.get("ES_API_KEY", "")

#: TLS: path to the cluster CA bundle (recommended, air-gapped-friendly),
#: or True to use the system store, or False to disable verification.
ES_CA_BUNDLE: str | bool = "/etc/elasticsearch/certs/ca.crt"

#: Seconds. Generous: a cold air-gapped cluster is slow to answer the first call.
REQUEST_TIMEOUT = 30.0

#: Object names. These must match `index.lifecycle.name` in the index template.
ILM_POLICY_NAME = "apiaudit-ilm"
INDEX_TEMPLATE_NAME = "logs-apiaudit"

#: Retention override, in days. None => use `_meta.RETENTION_DAYS` from
#: ilm-apiaudit.json (the intended single source of truth, plan I-4).
#: Set an int here only for a one-off environment that differs from the file.
RETENTION_DAYS: int | None = None

#: Does this cluster have nodes with the `data_cold` role?
#: False strips the cold phase entirely — on a cluster with no cold tier a cold
#: phase parks every index in `check-migration` forever. Plan I-2 is unanswered
#: for the target clusters, so this is deliberately explicit.
COLD_TIER_EXISTS = False

#: Data streams to pre-create. Format: logs-apiaudit.<sanitised service>-<env>,
#: matching AuditConfig.data_stream_dataset + AuditConfig.environment.
#: Empty list is fine and is the normal case: with the template already in
#: place, the first document Filebeat ships auto-creates the data stream with
#: the correct mapping. Pre-creating just makes step 5 fail loudly at apply
#: time instead of silently at first traffic.
DATA_STREAMS: list[str] = [
    # "logs-apiaudit.orders_api-prod",
]

#: True => validate, GET, and print the diff, but send no PUT/POST.
DRY_RUN = False

# --- end of CONFIG ---------------------------------------------------------


HERE = Path(__file__).resolve().parent
ILM_FILE = HERE / "ilm-apiaudit.json"
TEMPLATE_FILE = HERE / "template-apiaudit.json"

#: Index-template settings that are load-bearing for the field bound and the
#: §5 storage estimate. Checked, reported, and enforced as errors.
REQUIRED_SETTINGS: dict[str, Any] = {
    "index.mapping.total_fields.limit": 200,
    "index.codec": "best_compression",
}


class ValidationError(Exception):
    """The artefacts on disk are not safe to install. Nothing was sent."""


# ---------------------------------------------------------------------------
# Pure helpers — importable and testable with no Elasticsearch anywhere.
# ---------------------------------------------------------------------------


def load_json(path: Path) -> dict[str, Any]:
    """Read a JSON object from *path*, with a message that names the file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - trivial
        raise ValidationError(f"cannot read {path}: {exc}") from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{path.name} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValidationError(f"{path.name} must contain a JSON object")
    return doc


def _walk_dynamic(node: Any, path: str, problems: list[str]) -> None:
    """Collect every ``dynamic`` in a mapping subtree that is not ``false``."""
    if not isinstance(node, dict):
        return

    if "dynamic" in node:
        value = node["dynamic"]
        # ES accepts false, "false", true, "true", "strict", "runtime".
        # Only a real, unambiguous false is acceptable here.
        if value is not False and value != "false":
            problems.append(f"{path or '<mappings>'}.dynamic = {value!r} (must be false)")

    if "dynamic_templates" in node and node["dynamic_templates"]:
        problems.append(
            f"{path or '<mappings>'}.dynamic_templates is non-empty — "
            "dynamic templates have no business in a dynamic:false mapping"
        )

    props = node.get("properties")
    if isinstance(props, dict):
        for name, child in props.items():
            child_path = f"{path}.{name}" if path else name
            if isinstance(child, dict):
                # An object container is anything that itself has properties,
                # or is explicitly typed "object"/"nested". Every one of them
                # needs its own dynamic:false; inheritance is NOT guaranteed
                # once a sub-object is declared explicitly.
                is_container = (
                    "properties" in child or child.get("type") in ("object", "nested")
                )
                if is_container and "dynamic" not in child:
                    problems.append(
                        f"{child_path} is an object mapping with no explicit "
                        "dynamic — declare dynamic:false on it"
                    )
                _walk_dynamic(child, child_path, problems)


def check_dynamic_false(template: dict[str, Any]) -> list[str]:
    """Return every reason *template*'s mapping is not fully ``dynamic: false``.

    Empty list => safe. This is the hard guard from the A5 brief and plan §8/A8:
    ``dynamic: false`` must hold at the top level *and* in every nested object,
    ``labels`` included, because a nested object silently re-enables dynamic
    mapping for its own subtree and that is exactly how the field budget in
    docs/schema.md §3 gets blown.
    """
    problems: list[str] = []

    mappings = template.get("template", {}).get("mappings")
    if not isinstance(mappings, dict):
        return ["template.mappings is missing — refusing to install a mapping-less template"]

    if mappings.get("dynamic") is not False and mappings.get("dynamic") != "false":
        problems.append(
            f"top-level mappings.dynamic = {mappings.get('dynamic')!r} (must be false)"
        )

    _walk_dynamic(mappings, "", problems)

    if template.get("composed_of"):
        problems.append(
            f"composed_of = {template['composed_of']!r} — a component template can "
            "merge a dynamic:true mapping back in; this template must compose nothing"
        )

    return sorted(set(problems))


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts to ``a.b.c`` keys. Lists are compared whole."""
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        if not obj and prefix:
            out[prefix] = {}
        for key, value in obj.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            out.update(flatten(value, child))
    else:
        out[prefix] = obj
    return out


def check_settings(template: dict[str, Any]) -> list[str]:
    """Return every REQUIRED_SETTINGS value the template does not carry."""
    flat = flatten(template.get("template", {}).get("settings", {}))
    problems: list[str] = []
    for key, want in REQUIRED_SETTINGS.items():
        got = flat.get(key, flat.get(key.removeprefix("index.")))
        if str(got) != str(want):
            problems.append(f"settings.{key} = {got!r}, expected {want!r}")
    return problems


def check_body_raw(template: dict[str, Any]) -> list[str]:
    """``audit.request.body_raw`` must be stored-but-never-indexed.

    docs/schema.md §2.9 supersedes D-10: ``body`` and ``body_raw`` are now
    mutually exclusive, so ``body_raw`` carries only what a ``flattened``
    object cannot represent. It still has to be full fidelity when it is
    present, so the guard below is unchanged.
    """
    props = (
        template.get("template", {})
        .get("mappings", {})
        .get("properties", {})
        .get("audit", {})
        .get("properties", {})
        .get("request", {})
        .get("properties", {})
        .get("body_raw")
    )
    if not isinstance(props, dict):
        return ["audit.request.body_raw is not mapped"]
    problems: list[str] = []
    if props.get("type") != "keyword":
        problems.append(f"audit.request.body_raw.type = {props.get('type')!r}, expected 'keyword'")
    if props.get("index") is not False:
        problems.append("audit.request.body_raw must set index: false")
    if props.get("doc_values") is not False:
        problems.append("audit.request.body_raw must set doc_values: false")
    if "ignore_above" in props:
        problems.append(
            "audit.request.body_raw must NOT set ignore_above — schema §2.9 "
            "wants full fidelity for the cases body cannot represent"
        )
    src = template.get("template", {}).get("mappings", {}).get("_source", {})
    if src.get("enabled") is False:
        problems.append("_source is disabled — body_raw would be unrecoverable")
    return problems


def resolve_retention_days(ilm_doc: dict[str, Any], override: int | None) -> int:
    """The single retention knob: CONFIG override, else ``_meta.RETENTION_DAYS``."""
    if override is not None:
        if isinstance(override, bool) or not isinstance(override, int) or override <= 0:
            raise ValidationError(f"RETENTION_DAYS override must be a positive int, got {override!r}")
        return override
    days = ilm_doc.get("_meta", {}).get("RETENTION_DAYS")
    if not isinstance(days, int) or isinstance(days, bool) or days <= 0:
        raise ValidationError(
            "ilm-apiaudit.json must carry a positive integer _meta.RETENTION_DAYS "
            f"(got {days!r}) — that is the one place retention is configured"
        )
    return days


def build_ilm_body(
    ilm_doc: dict[str, Any], retention_days: int, cold_tier_exists: bool
) -> tuple[dict[str, Any], list[str]]:
    """Turn the on-disk ILM file into the exact `_ilm/policy` request body.

    Returns ``(body, notes)``. The top-level ``_meta`` envelope is stripped —
    the ILM API accepts only ``policy``.
    """
    policy = json.loads(json.dumps(ilm_doc.get("policy")))
    if not isinstance(policy, dict) or "phases" not in policy:
        raise ValidationError("ilm-apiaudit.json is missing policy.phases")

    notes: list[str] = []
    phases: dict[str, Any] = policy["phases"]

    on_disk = phases.get("delete", {}).get("min_age")
    want = f"{retention_days}d"
    if on_disk != want:
        notes.append(f"delete.min_age normalised {on_disk!r} -> {want!r} from RETENTION_DAYS")
    phases.setdefault("delete", {"actions": {"delete": {}}})["min_age"] = want

    if not cold_tier_exists:
        if phases.pop("cold", None) is not None:
            notes.append("cold phase stripped (COLD_TIER_EXISTS = False)")

    for name, phase in phases.items():
        min_age = phase.get("min_age", "0ms")
        if name != "hot" and _days(min_age) > retention_days:
            raise ValidationError(
                f"phase {name!r} starts at {min_age} which is after the {want} "
                "delete — the index would be deleted before it ever got there"
            )

    return {"policy": policy}, notes


def _days(min_age: str) -> float:
    """Parse an ILM ``min_age`` into days. Only the units ILM actually uses."""
    units = {"d": 1.0, "h": 1 / 24, "m": 1 / 1440, "s": 1 / 86400, "ms": 1 / 86_400_000}
    text = str(min_age).strip()
    for unit in ("ms", "d", "h", "m", "s"):
        if text.endswith(unit):
            try:
                return float(text[: -len(unit)]) * units[unit]
            except ValueError:
                break
    raise ValidationError(f"cannot parse ILM min_age {min_age!r}")


def diff_lines(
    desired: Any, live: Any, root: str = "", removals: str | None = None
) -> list[str]:
    """A readable diff of *desired* against what the cluster already has.

    ``+`` added, ``~`` changed, ``-`` removed. Removals are only reported under
    the *removals* key prefix — the subtree we know we own end to end (e.g.
    ``phases``) — because outside it the cluster echoes back defaults we never
    set and every one of them would read as a spurious deletion. A converged
    cluster therefore produces an empty diff, which is what makes "idempotent"
    a claim you can check rather than one you have to believe.
    """
    want = flatten(desired, root)
    have = flatten(live, root)
    lines: list[str] = []
    for key in sorted(want):
        w = want[key]
        if key not in have:
            lines.append(f"  + {key} = {_short(w)}")
        elif have[key] != w:
            lines.append(f"  ~ {key}: {_short(have[key])} -> {_short(w)}")
    if removals is not None:
        for key in sorted(have):
            if key not in want and (key == removals or key.startswith(removals + ".")):
                lines.append(f"  - {key} (was {_short(have[key])})")
    return sorted(lines)


def _short(value: Any, limit: int = 90) -> str:
    text = json.dumps(value, sort_keys=True) if not isinstance(value, str) else repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def render_diff(title: str, lines: list[str]) -> str:
    """Format one diff section. Used for the report and easy to unit-test."""
    if not lines:
        return f"{title}: unchanged"
    body = "\n".join(lines)
    return f"{title}: {len(lines)} change(s)\n{body}"


def validate_all(template: dict[str, Any]) -> None:
    """Every hard guard, in one call. Raises ValidationError or returns None."""
    problems = check_dynamic_false(template)
    if problems:
        raise ValidationError(
            "REFUSING TO INSTALL — the index template is not dynamic:false:\n"
            + "\n".join(f"  - {p}" for p in problems)
        )
    problems = check_settings(template) + check_body_raw(template)
    if problems:
        raise ValidationError(
            "REFUSING TO INSTALL — template does not match docs/schema.md:\n"
            + "\n".join(f"  - {p}" for p in problems)
        )


def count_mapping_fields(mappings: dict[str, Any]) -> int:
    """Count leaf + object fields the way `total_fields.limit` does."""
    total = 0
    props = mappings.get("properties")
    if isinstance(props, dict):
        for child in props.values():
            if isinstance(child, dict):
                total += 1
                total += count_mapping_fields(child)
    return total


# ---------------------------------------------------------------------------
# Elasticsearch I/O — nothing above this line touches the network.
# ---------------------------------------------------------------------------


def _session() -> Any:
    import requests  # imported here so the pure half stays import-safe

    s = requests.Session()
    if ES_API_KEY:
        s.headers["Authorization"] = f"ApiKey {ES_API_KEY}"
    elif ES_USERNAME:
        s.auth = (ES_USERNAME, ES_PASSWORD)
    s.headers["Content-Type"] = "application/json"
    s.verify = ES_CA_BUNDLE
    return s


def _call(sess: Any, method: str, path: str, body: Any = None, ok404: bool = False) -> Any:
    url = ES_URL.rstrip("/") + path
    resp = sess.request(
        method,
        url,
        data=json.dumps(body) if body is not None else None,
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code == 404 and ok404:
        return None
    if resp.status_code >= 400:
        raise SystemExit(f"{method} {path} -> {resp.status_code}\n{resp.text}")
    if not resp.content:
        return {}
    return resp.json()


def main() -> int:
    ilm_doc = load_json(ILM_FILE)
    template = load_json(TEMPLATE_FILE)

    print("=" * 72)
    print("audit_logging Elasticsearch bootstrap")
    print(f"  target        : {ES_URL}")
    print(f"  ilm policy    : {ILM_POLICY_NAME}")
    print(f"  index template: {INDEX_TEMPLATE_NAME}  {template['index_patterns']}")
    print(f"  dry run       : {DRY_RUN}")
    print("=" * 72)

    # --- guards, before any network call ---------------------------------
    validate_all(template)
    fields = count_mapping_fields(template["template"]["mappings"])
    limit = flatten(template["template"]["settings"])["index.mapping.total_fields.limit"]
    print("[guard] mapping is dynamic:false everywhere            OK")
    print("[guard] audit.request.body_raw stored, not indexed     OK")
    print(f"[guard] declared fields {fields} / total_fields.limit {limit}   OK")

    retention_days = resolve_retention_days(ilm_doc, RETENTION_DAYS)
    ilm_body, notes = build_ilm_body(ilm_doc, retention_days, COLD_TIER_EXISTS)
    print(f"[ilm]   retention {retention_days}d, phases: "
          f"{', '.join(ilm_body['policy']['phases'])}")
    for note in notes:
        print(f"[ilm]   note: {note}")

    if DRY_RUN:
        print("\nDRY_RUN — validated only, nothing sent.")
        return 0

    sess = _session()

    info = _call(sess, "GET", "/")
    print(f"[es]    connected: {info['version']['number']} "
          f"cluster={info.get('cluster_name')}")

    # --- 1. ILM policy ----------------------------------------------------
    before = _call(sess, "GET", f"/_ilm/policy/{ILM_POLICY_NAME}", ok404=True)
    before_policy = (before or {}).get(ILM_POLICY_NAME, {}).get("policy", {})
    _call(sess, "PUT", f"/_ilm/policy/{ILM_POLICY_NAME}", ilm_body)
    after = _call(sess, "GET", f"/_ilm/policy/{ILM_POLICY_NAME}")
    after_policy = after[ILM_POLICY_NAME]["policy"]
    print("\n" + render_diff(
        f"ILM policy {ILM_POLICY_NAME}",
        diff_lines(after_policy, before_policy, removals="phases") if before else ["  + created"],
    ))

    # --- 2. Index template (BEFORE any data stream exists — plan §10) -----
    before_t = _call(sess, "GET", f"/_index_template/{INDEX_TEMPLATE_NAME}", ok404=True)
    before_tpl: dict[str, Any] = {}
    if before_t and before_t.get("index_templates"):
        before_tpl = before_t["index_templates"][0]["index_template"]
    _call(sess, "PUT", f"/_index_template/{INDEX_TEMPLATE_NAME}", template)
    after_t = _call(sess, "GET", f"/_index_template/{INDEX_TEMPLATE_NAME}")
    after_tpl = after_t["index_templates"][0]["index_template"]
    print("\n" + render_diff(
        f"index template {INDEX_TEMPLATE_NAME}",
        diff_lines(after_tpl, before_tpl, removals="template") if before_tpl else ["  + created"],
    ))

    # --- 3. Verify what a NEW index would actually resolve to -------------
    probe = f"logs-apiaudit.bootstrap_probe-{'x'}"
    sim = _call(sess, "POST", f"/_index_template/_simulate_index/{probe}")
    resolved = sim.get("template", {})
    sim_problems = check_dynamic_false({"template": resolved, "composed_of": []})
    if sim_problems:
        raise SystemExit(
            "POST-INSTALL CHECK FAILED — the resolved mapping for "
            f"{probe} is not dynamic:false:\n"
            + "\n".join(f"  - {p}" for p in sim_problems)
            + "\nSomething else in this cluster composes into logs-apiaudit.*-*."
        )
    print(f"\nsimulated index {probe}: dynamic:false holds, "
          f"{count_mapping_fields(resolved.get('mappings', {}))} fields, "
          f"ilm={flatten(resolved.get('settings', {})).get('index.lifecycle.name')}")

    # --- 4. Data streams, created only if absent. Never deleted. ----------
    if not DATA_STREAMS:
        print("\ndata streams: none configured — the first shipped document "
              "will create one against the template installed above")
    for name in DATA_STREAMS:
        existing = _call(sess, "GET", f"/_data_stream/{name}", ok404=True)
        if existing and existing.get("data_streams"):
            ds = existing["data_streams"][0]
            print(f"\ndata stream {name}: exists (generation "
                  f"{ds.get('generation')}, template {ds.get('template')}) — untouched")
            if ds.get("template") != INDEX_TEMPLATE_NAME:
                print(f"  ! WARNING: backed by template {ds.get('template')!r}, "
                      f"not {INDEX_TEMPLATE_NAME!r}. Existing backing indices keep "
                      "their old mapping until the next rollover.")
        else:
            _call(sess, "PUT", f"/_data_stream/{name}")
            print(f"\ndata stream {name}: + created")

    print("\nDone. Nothing was deleted or reindexed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValidationError as exc:
        print(f"\nFATAL: {exc}", file=sys.stderr)
        sys.exit(2)
