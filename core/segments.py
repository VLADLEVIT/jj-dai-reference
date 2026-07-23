# -*- coding: utf-8 -*-
"""
core.segments — Witness SEGMENT replication + recovery (v0.5, drop 6)
=====================================================================
Root replication (core.replication) proves that deletion or rewrite
HAPPENED — but a proof of arson does not rebuild the library. This module
replicates the RECORDS themselves, so a witness log lost with its disk can
be RESTORED from peers and verified against a quorum-anchored root.

    make_segment      — the origin's signed envelope over records [start, end)
    verify_segment    — full offline verification: per-record body hashes,
                        per-record Ed25519 signatures, internal hash-chain
                        continuity, index sequence, envelope signature
    SegmentStore      — durable per-origin store with a coverage map;
                        overlapping segments that DISAGREE about a record
                        are captured as self-proving SEGMENT_DIVERGENCE
                        evidence (two validly signed records, same origin,
                        same index, different hash)
    recover_records   — assemble records [0, count) from stored segments and
                        verify the reconstruction against a TRUSTED signed
                        root (one the operator has quorum receipts for)
    write_recovered_log — emit a JSONL witness log readable by WitnessChain
                        (the node resumes appending with its keystore)

Trust model (honest statement):
  * Recovery restores WHAT THE ORIGIN SIGNED. It cannot restore records the
    origin never replicated (the coverage map names the gaps), and it cannot
    restore the hiding-commitment SALTS — openings of request/response
    commitments are local-only by design and die with the disk. Provenance
    survives; secret content does not. That asymmetry is intentional.
  * The trusted root must come from OUTSIDE the recovery path: a quorum
    receipt the operator holds, or a root pinned by independent peers.
    Recovering against a root supplied by the same single peer that supplies
    the segments proves only internal consistency of that peer's story.

INV-9 intact: replication and recovery are acts of the NODE. The Witness
plane itself never acts; the recovered chain is what it always was — a log.
"""
from __future__ import annotations

import json
import os
import time

from jjdai.canonical import canonical
from jjdai.crypto import H_hex, SigningKey, verify, canonical_node_id
from jjdai.merkle import mth_root
from jjdai.durable import durable_append, read_journal
from jjdai.witness import GENESIS

SEGMENT_DOMAIN = b"jjdai/replication/segment/v1:"

MAX_SEGMENT_RECORDS = 512      # served per request; keeps envelopes bounded


class SegmentError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
#  Envelopes
# --------------------------------------------------------------------------- #

def make_segment(chain, sk: SigningKey, start: int, end: int) -> dict:
    """Signed envelope over the origin's OWN records [start, end)."""
    n = len(chain.records)
    if not (0 <= start < end <= n):
        raise SegmentError(f"segment [{start}, {end}) outside [0, {n})")
    if end - start > MAX_SEGMENT_RECORDS:
        raise SegmentError(
            f"segment of {end - start} records exceeds the "
            f"{MAX_SEGMENT_RECORDS}-record cap; chunk the request")
    records = [dict(r) for r in chain.records[start:end]]
    body = {
        "kind": "WITNESS_SEGMENT",
        "node_id": chain.node_id,
        "start": start,
        "end": end,
        "prev_hash": records[0]["prev_hash"],
        "segment_hash": H_hex(canonical(records)),
        "ts": time.time(),
    }
    sig = sk.sign(SEGMENT_DOMAIN + canonical(body))
    return {"body": body, "records": records,
            "pub": sk.public.hex(), "sig": sig.hex()}


def verify_segment(env: dict) -> tuple:
    """-> (ok, reason). Fully offline; verifies EVERYTHING an honest segment
    must satisfy: envelope signature, segment hash, index sequence, internal
    hash-chain continuity, per-record body hashes and per-record Ed25519
    signatures under the origin key. start=0 must chain from GENESIS."""
    try:
        body = env["body"]
        records = env["records"]
        pub = bytes.fromhex(env["pub"])
        sig = bytes.fromhex(env["sig"])
    except (KeyError, TypeError, ValueError):
        return False, "malformed envelope"
    if body.get("kind") != "WITNESS_SEGMENT":
        return False, "wrong kind"
    origin = body.get("node_id")
    if canonical_node_id(pub) != origin:
        return False, "node_id does not match public key"
    if not verify(pub, SEGMENT_DOMAIN + canonical(body), sig):
        return False, "bad envelope signature"
    start, end = body.get("start"), body.get("end")
    if not (isinstance(start, int) and isinstance(end, int)
            and 0 <= start < end):
        return False, "bad range"
    if len(records) != end - start:
        return False, f"{len(records)} record(s) != range [{start}, {end})"
    if H_hex(canonical(records)) != body.get("segment_hash"):
        return False, "segment hash mismatch"
    prev = body.get("prev_hash")
    if start == 0 and prev != GENESIS:
        return False, "segment at 0 must chain from GENESIS"
    for off, rec in enumerate(records):
        i = start + off
        if rec.get("index") != i:
            return False, f"index gap at {i}: got {rec.get('index')}"
        if rec.get("node_id") != origin:
            return False, f"record {i} signed as a different node"
        if rec.get("prev_hash") != prev:
            return False, f"chain break at {i}: prev_hash mismatch"
        rbody = {k: v for k, v in rec.items() if k not in ("this_hash", "sig")}
        if rec.get("this_hash") != H_hex(canonical(rbody)):
            return False, f"tampered record at {i}: hash mismatch"
        if not verify(pub, rec["this_hash"].encode(),
                      bytes.fromhex(rec.get("sig", ""))):
            return False, f"bad record signature at {i}"
        prev = rec["this_hash"]
    return True, "ok"


# --------------------------------------------------------------------------- #
#  Store (receiver side)
# --------------------------------------------------------------------------- #

class SegmentStore:
    """Durable store of OTHER nodes' verified witness segments.

    accept() outcomes:
        "stored"     — new records verified and durably persisted
        "duplicate"  — every record in the segment already held identically
        "divergence" — a validly signed record CONTRADICTS a held validly
                       signed record at the same index (same origin):
                       self-proving SEGMENT_DIVERGENCE evidence
        "rejected"   — verification failed; nothing retained
    Reload is FAIL CLOSED: every persisted segment is re-verified before its
    records are trusted; a forged journal line refuses the boot.
    """

    def __init__(self, path: str = None):
        self.path = path
        self._records: dict = {}    # origin -> {index -> record}
        self._diverged: dict = {}   # origin -> [evidence, ...]
        if path and os.path.exists(path):
            entries, _ = read_journal(path)
            for e in entries:
                if e.get("kind") == "REPLICA_SEGMENT":
                    ok, reason = verify_segment(e["env"])
                    if not ok:
                        raise SegmentError(
                            "segment journal integrity failure on reload: "
                            f"{reason}")
                    self._hold(e["env"])
                elif e.get("kind") == "SEGMENT_DIVERGENCE":
                    self._diverged.setdefault(e["origin"], []).append(e)

    def _hold(self, env: dict):
        origin = env["body"]["node_id"]
        held = self._records.setdefault(origin, {})
        for rec in env["records"]:
            held[rec["index"]] = rec

    def _persist(self, obj: dict):
        if self.path:
            durable_append(self.path, obj)

    def accept(self, env: dict) -> tuple:
        ok, reason = verify_segment(env)
        if not ok:
            return "rejected", reason
        origin = env["body"]["node_id"]
        held = self._records.get(origin, {})
        fresh, conflict = 0, None
        for rec in env["records"]:
            have = held.get(rec["index"])
            if have is None:
                fresh += 1
            elif have["this_hash"] != rec["this_hash"]:
                conflict = (rec["index"], have, rec)
                break
        if conflict is not None:
            idx, a, b = conflict
            evidence = {"kind": "SEGMENT_DIVERGENCE", "origin": origin,
                        "index": idx, "record_a": a, "record_b": b,
                        "env_b": env, "detected_at": time.time()}
            self._diverged.setdefault(origin, []).append(evidence)
            self._persist(evidence)
            return "divergence", f"conflicting signed record at index {idx}"
        if fresh == 0:
            return "duplicate", "all records already held"
        self._hold(env)
        self._persist({"kind": "REPLICA_SEGMENT", "env": env})
        return "stored", f"{fresh} new record(s)"

    # ---- coverage ------------------------------------------------------- #

    def coverage(self, origin: str) -> list:
        """Merged sorted list of held [start, end) ranges for an origin."""
        idxs = sorted(self._records.get(origin, {}))
        ranges = []
        for i in idxs:
            if ranges and i == ranges[-1][1]:
                ranges[-1][1] = i + 1
            else:
                ranges.append([i, i + 1])
        return [tuple(r) for r in ranges]

    def missing(self, origin: str, count: int) -> list:
        """Gaps in [0, count) not yet covered for an origin."""
        gaps, cursor = [], 0
        for s, e in self.coverage(origin):
            if s > cursor:
                gaps.append((cursor, min(s, count)))
            cursor = max(cursor, e)
            if cursor >= count:
                break
        if cursor < count:
            gaps.append((cursor, count))
        return [g for g in gaps if g[0] < g[1]]

    def next_gap(self, origin: str, count: int) -> dict | None:
        gaps = self.missing(origin, count)
        if not gaps:
            return None
        s, e = gaps[0]
        return {"start": s, "end": min(e, s + MAX_SEGMENT_RECORDS)}

    def divergence(self, origin: str = None) -> list:
        if origin is not None:
            return list(self._diverged.get(origin, []))
        return [e for evs in self._diverged.values() for e in evs]

    def records(self, origin: str) -> dict:
        return dict(self._records.get(origin, {}))


# --------------------------------------------------------------------------- #
#  Recovery
# --------------------------------------------------------------------------- #

def recover_records(store: SegmentStore, origin: str,
                    trusted_root_env: dict) -> dict:
    """Reconstruct records [0, count) for `origin` from the store and verify
    the reconstruction against a TRUSTED signed root (quorum-anchored —
    see the module docstring for why the root must come from outside the
    recovery path).

    Returns {"ok": bool, "records": [...] | None, "count": int,
             "root": str, "missing": [...], "reason": str}.
    FAIL HONEST: gaps or a root mismatch return ok=False with the exact
    deficiency named — never a silently partial "recovery"."""
    from core.replication import verify_signed_root
    ok, why = verify_signed_root(trusted_root_env)
    if not ok:
        return {"ok": False, "records": None, "count": 0, "root": None,
                "missing": [], "reason": f"trusted root invalid: {why}"}
    b = trusted_root_env["body"]
    if b["node_id"] != origin:
        return {"ok": False, "records": None, "count": 0, "root": None,
                "missing": [], "reason": "trusted root is for another origin"}
    if b.get("root_alg") != "rfc6962":
        return {"ok": False, "records": None, "count": b["count"],
                "root": b["root"], "missing": [],
                "reason": "trusted root is legacy v1; recovery requires an "
                          "rfc6962 root"}
    count, want_root = b["count"], b["root"]
    gaps = store.missing(origin, count)
    if gaps:
        return {"ok": False, "records": None, "count": count,
                "root": want_root, "missing": gaps,
                "reason": f"{len(gaps)} coverage gap(s); pull more segments"}
    held = store.records(origin)
    records = [held[i] for i in range(count)]
    # continuity re-check across segment boundaries (each segment verified
    # internally on accept; the SEAMS are re-verified here):
    prev = GENESIS
    for i, rec in enumerate(records):
        if rec["prev_hash"] != prev:
            return {"ok": False, "records": None, "count": count,
                    "root": want_root, "missing": [],
                    "reason": f"chain break at seam index {i}"}
        prev = rec["this_hash"]
    got_root = mth_root([r["this_hash"].encode() for r in records])
    if got_root != want_root:
        return {"ok": False, "records": None, "count": count,
                "root": want_root, "missing": [],
                "reason": "reconstruction does not match the trusted root: "
                          "the stored segments tell a different history"}
    if b["head_hash"] != (records[-1]["this_hash"] if records else GENESIS):
        return {"ok": False, "records": None, "count": count,
                "root": want_root, "missing": [],
                "reason": "head hash mismatch against the trusted root"}
    return {"ok": True, "records": records, "count": count,
            "root": want_root, "missing": [], "reason": "ok"}


def write_recovered_log(records: list, path: str) -> int:
    """Emit a JSONL witness log readable by WitnessChain/_load and
    WitnessReader. Refuses to overwrite an existing file: recovery must
    never destroy a log that still exists."""
    if os.path.exists(path):
        raise SegmentError(f"refusing to overwrite existing log at {path!r}")
    for rec in records:
        durable_append(path, rec)
    return len(records)
