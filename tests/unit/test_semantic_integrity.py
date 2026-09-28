"""Hash chain: stamp in file order, verify catches tamper / delete / reorder / repeat."""

from __future__ import annotations

import copy
import json
from typing import Any

from audit_logging.semantic.integrity import GENESIS, Chain, canonical, verify


def _docs(n: int, chain: Chain | None = None) -> list[dict[str, Any]]:
    chain = chain or Chain("svc", 42, 1000)
    return [chain.stamp({"event": {"action": f"a{i}"}, "audit": {"n": i}}) for i in range(n)]


def test_chain_id_seq_and_genesis() -> None:
    c = Chain("users-adminka", 7, 1700000000000)
    assert c.chain_id == "users-adminka-7-1700000000000"
    d1, d2 = (c.stamp({"x": i}) for i in range(2))
    i1, i2 = d1["audit"]["integrity"], d2["audit"]["integrity"]
    assert (i1["seq"], i1["prev_hash"], i1["chain"]) == (1, GENESIS, c.chain_id)
    assert (i2["seq"], i2["prev_hash"]) == (2, i1["hash"])
    assert len(i1["hash"]) == 64


def test_intact_chain_ok() -> None:
    r = verify(_docs(5))
    assert (r.ok, r.chains, r.documents, r.broken) == (True, 1, 5, [])


def test_survives_json_roundtrip() -> None:
    docs = [json.loads(json.dumps(d)) for d in _docs(3)]
    assert verify(docs).ok


def test_tampered_field_is_broken() -> None:
    docs = _docs(3)
    docs[1]["audit"]["n"] = 999
    r = verify(docs)
    assert not r.ok and r.broken == ["svc-42-1000:2 hash mismatch"]


def test_deleted_doc_is_gap() -> None:
    docs = _docs(4)
    del docs[1]
    r = verify(docs)
    assert r.broken == ["svc-42-1000:3 seq gap (expected 2)"]


def test_rotated_away_head_is_reported_not_broken() -> None:
    """Retention (file rotation, ILM delete) removes the oldest documents: the chain
    anchors at its lowest surviving seq (review: verify required seq 1)."""
    r = verify(_docs(10)[5:])
    assert (r.ok, r.broken, r.truncated) == (True, [], ["svc-42-1000 starts at seq 6"])


def test_require_genesis_keeps_the_strict_check() -> None:
    r = verify(_docs(3)[1:], require_genesis=True)
    assert r.broken == ["svc-42-1000:2 seq gap (expected 1)"]


def test_a_gap_after_a_truncated_head_is_still_broken() -> None:
    docs = _docs(10)[5:]
    del docs[2]
    assert verify(docs).broken == ["svc-42-1000:9 seq gap (expected 8)"]


def test_a_forked_child_starts_its_own_chain(monkeypatch: Any) -> None:
    """Built before gunicorn forks (--preload): each worker must not reuse the
    master's chain id and seq 1 (review: chain id fixed at construction)."""
    from audit_logging.semantic import integrity

    c = Chain("svc", 42, 1000)
    first = c.stamp({"x": 0})["audit"]["integrity"]
    monkeypatch.setattr(integrity.os, "getpid", lambda: 4242)
    child = c.stamp({"x": 1})["audit"]["integrity"]
    assert child["chain"].startswith("svc-4242-") and child["chain"] != first["chain"]
    assert (child["seq"], child["prev_hash"]) == (1, GENESIS)


def test_reorder_detected() -> None:
    docs = _docs(4)
    # swap the positions of events 2 and 3 in the chain by exchanging their seq numbers
    docs[1]["audit"]["integrity"]["seq"], docs[2]["audit"]["integrity"]["seq"] = 3, 2
    r = verify(docs)
    assert not r.ok and any("hash mismatch" in b for b in r.broken)


def test_file_order_alone_does_not_matter() -> None:
    # documents come back from Elasticsearch in any order; seq decides
    assert verify(list(reversed(_docs(4)))).ok


def test_repeat_and_prev_mismatch() -> None:
    docs = _docs(3)
    r = verify(docs + [copy.deepcopy(docs[1])])
    assert r.broken == ["svc-42-1000:2 seq repeat"]
    # rewrite prev_hash consistently (hash recomputed) -> the link breaks, not the hash
    forged = _docs(3)
    other = Chain("svc", 42, 1000)
    other.stamp({"unrelated": True})
    forged[1] = other.stamp({"event": {"action": "a1"}, "audit": {"n": 1}})
    # a substituted doc breaks the link on both sides
    assert verify(forged).broken == ["svc-42-1000:2 prev mismatch", "svc-42-1000:3 prev mismatch"]


def test_event_ingested_added_later_ok() -> None:
    docs = _docs(2)
    docs[0]["event"]["ingested"] = "2026-09-28T10:00:00Z"
    doc = Chain("svc", 1, 1).stamp({"message": "no event yet"})
    doc["event"] = {"ingested": "2026-09-28T10:00:00Z"}
    assert verify(docs).ok and verify([doc]).ok


def test_docs_without_integrity_ignored() -> None:
    r = verify(_docs(2) + [{"event": {"action": "plain"}}, {"audit": {"n": 1}}])
    assert (r.ok, r.documents) == (True, 2)


def test_two_chains_independent() -> None:
    a = _docs(3, Chain("svc", 1, 10))
    b = _docs(3, Chain("svc", 2, 20))
    mixed = [a[0], b[0], a[1], b[1], a[2], b[2]]
    assert verify(mixed).chains == 2 and verify(mixed).ok
    b[1]["audit"]["n"] = "x"
    assert verify(mixed).broken == ["svc-2-20:2 hash mismatch"]


def test_canonical_excludes_only_integrity_and_ingested() -> None:
    base: dict[str, Any] = {"b": 1, "a": {"z": "ü"}, "event": {"action": "x"}}
    extra = copy.deepcopy(base)
    extra["event"]["ingested"] = "later"
    extra["audit"] = {"integrity": {"seq": 1}}
    assert canonical(base) == canonical(extra) == '{"a":{"z":"ü"},"b":1,"event":{"action":"x"}}'.encode()
    assert "ingested" in extra["event"]  # input not mutated
    assert canonical({"t": object()})  # default=str, never raises on odd types


def test_malformed_integrity_reported() -> None:
    assert not verify([{"audit": {"integrity": {"chain": "c", "seq": "1"}}}]).ok
