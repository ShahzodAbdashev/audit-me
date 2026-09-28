"""Per-process hash chain — tamper evidence without shared state (PLAN §17.5). OWNER: agent J.

Off by default (AUDIT_INTEGRITY_ENABLED=false). One chain per process:
chain id = "<service>-<pid>-<start_epoch_ms>", seq starts at 1.
hash = sha256( f"{chain}|{seq}|{prev_hash}|" + canonical_json(doc_without_integrity_and_event.ingested) )
canonical_json = json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).
prev_hash of seq 1 is 64 zeros. FileSink.submit() serialises each document to bytes
immediately, so the chain is stamped in the WRITER THREAD, per batch, in file order
(parse line -> enrich -> Chain.stamp -> dumps -> write); file order == seq order.
event.ingested is excluded because the shipper adds it later.

verify() orders by seq (documents may come back from Elasticsearch in any order), so a
reorder is caught through the hashes, not file position. Deleting the newest documents
of a chain (the tail) is not detectable from the chain alone; nor, by default, is
deleting the oldest (the head), because retention does exactly that: each chain is
anchored at its lowest surviving seq and a missing head is reported in
``ChainReport.truncated``, not as a break (``require_genesis=True`` restores the check).

A Chain built before a fork (gunicorn --preload) re-ids itself in the child on its
first stamp (new pid, new start ms, seq 1), so workers never share a chain id.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

GENESIS = "0" * 64


def canonical(doc: Mapping[str, Any]) -> bytes:
    """Canonical bytes of doc minus audit.integrity and event.ingested.

    A parent object left empty by the removal is dropped too, so stamping a doc that had
    no ``audit`` key (stamp creates it) hashes the same before and after.
    """
    out = dict(doc)
    for parent, key in (("audit", "integrity"), ("event", "ingested")):
        sub = out.get(parent)
        if isinstance(sub, Mapping) and key in sub:
            sub = {k: v for k, v in sub.items() if k != key}
            if sub:
                out[parent] = sub
            else:
                del out[parent]
    return json.dumps(out, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def _hash(chain: str, seq: int, prev: str, doc: Mapping[str, Any]) -> str:
    return hashlib.sha256(f"{chain}|{seq}|{prev}|".encode("utf-8") + canonical(doc)).hexdigest()


class Chain:
    """Not thread-safe by design: called only from the sink's writer thread, in file order."""

    def __init__(self, service: str, pid: int, start_ms: int) -> None:
        self._service = service
        self._id = f"{service}-{pid}-{start_ms}"
        self._seq = 0
        self._prev = GENESIS
        self._born = os.getpid()  # the process that built it; a fork child differs

    @property
    def chain_id(self) -> str:
        return self._id

    def stamp(self, doc: dict[str, Any]) -> dict[str, Any]:
        """Set doc["audit"]["integrity"] = {chain, seq, prev_hash, hash}; return doc.

        The hash is computed before any state changes, so if it raises the chain does
        not advance and no seq is burned.
        """
        pid = os.getpid()
        if pid != self._born:  # forked after construction: start this process's own chain
            self._id = f"{self._service}-{pid}-{int(time.time() * 1000)}"
            self._seq, self._prev, self._born = 0, GENESIS, pid
        seq = self._seq + 1
        digest = _hash(self._id, seq, self._prev, doc)
        audit = doc.setdefault("audit", {})
        audit["integrity"] = {"chain": self._id, "seq": seq, "prev_hash": self._prev, "hash": digest}
        self._seq, self._prev = seq, digest
        return doc


@dataclass(frozen=True)
class ChainReport:
    chains: int
    documents: int
    broken: list[str]      # "chain:seq reason" (hash mismatch, seq gap, seq repeat, prev mismatch)
    ok: bool
    #: "chain starts at seq N": the head was removed (rotation / retention). Info only.
    truncated: list[str] = field(default_factory=list)


def verify(docs: Iterable[Mapping[str, Any]], *, require_genesis: bool = False) -> ChainReport:
    """Group by audit.integrity.chain, order by seq, recompute. Documents without
    integrity are ignored (counted neither ok nor broken). A chain whose lowest seq
    is above 1 is anchored there (listed in ``truncated``) unless ``require_genesis``."""
    chains: dict[str, list[tuple[int, Mapping[str, Any], Mapping[str, Any]]]] = {}
    broken: list[str] = []
    truncated: list[str] = []
    count = 0
    for doc in docs:
        audit = doc.get("audit")
        integ = audit.get("integrity") if isinstance(audit, Mapping) else None
        if integ is None:
            continue
        count += 1
        chain = integ.get("chain") if isinstance(integ, Mapping) else None
        seq = integ.get("seq") if isinstance(integ, Mapping) else None
        if not isinstance(chain, str) or not isinstance(seq, int) or isinstance(seq, bool):
            broken.append(f"{chain}:{seq} malformed integrity")
            continue
        chains.setdefault(chain, []).append((seq, integ, doc))

    for chain, entries in chains.items():
        entries.sort(key=lambda e: e[0])
        expected, prev = 1, GENESIS
        first_seq, first_integ = entries[0][0], entries[0][1]
        if first_seq > 1 and not require_genesis:
            truncated.append(f"{chain} starts at seq {first_seq}")
            claimed = first_integ.get("prev_hash")
            expected, prev = first_seq, claimed if isinstance(claimed, str) else ""
        for seq, integ, doc in entries:
            where = f"{chain}:{seq}"
            recorded = integ.get("hash")
            claimed_prev = integ.get("prev_hash")
            if not isinstance(claimed_prev, str):
                claimed_prev = ""
            if recorded != _hash(chain, seq, claimed_prev, doc):
                broken.append(f"{where} hash mismatch")
            if seq < expected:
                broken.append(f"{where} seq repeat")
                continue  # keep the first copy as the link anchor
            if seq > expected:
                broken.append(f"{where} seq gap (expected {expected})")
            elif claimed_prev != prev:
                broken.append(f"{where} prev mismatch")
            expected = seq + 1
            prev = recorded if isinstance(recorded, str) else ""
    return ChainReport(chains=len(chains), documents=count, broken=broken, ok=not broken,
                       truncated=truncated)
