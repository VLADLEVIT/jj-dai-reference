# -*- coding: utf-8 -*-
"""
jjdai.witness — hash-chained, signed, append-only witness log (M2, generalised).

Record kinds:
  INFER     — provenance attestation for an inference; trust via REPLICATION
  SANDBOX   — replayable execution proof; trust via REPLAY
  GROUNDING — Plane H gate decision (M5)

Each record is Ed25519-signed and linked: this_hash = HASH(canonical(body)).
Commitments are HIDING (jjdai.crypto.commit): only the commitment enters the
chain; the per-record salt is kept in a LOCAL salt store and never persisted to
the chain — so the log carries provenance without leaking content.

Integrity model (M2):
  * verify_chain() catches tamper / reorder (a broken link or bad signature)
  * the external anchor catches truncation / consistent rewrite (a moved root)
"""

import os
import json
import threading
from .canonical import canonical
from .crypto import H_hex, SigningKey, verify, node_id, canonical_node_id, commit
from .merkle import merkle_root

GENESIS = "0" * 64
KINDS = ("INFER", "SANDBOX", "GROUNDING", "REGISTRY", "CONTAINMENT", "MEMORY",
         "DELIBERATION", "IDENTITY", "ROUTE",
         "ANCHOR_QUORUM",   # v0.5 P1/M6: quorum-replication anchor record
         "SALT_ISSUE",      # v0.5 P1: witnessed cross-chain salt issuance
         "PEER_ROOT",       # v0.5 drop 6: witnessed acceptance of a peer's
                            # signed root — the issuer-side checkpoint of the
                            # entanglement cross-link
         "ATTESTATION",     # v0.5.1: witnessed weight attestation /
                            # deployment manifest of THIS node
         "ANCHOR_EXTERNAL", # v0.5.1: one external-anchoring round
                            # (core.anchoring: local / peer-quorum / OTS)
         "TASK",            # v0.5.3: one lifecycle transition of a Being
                            # task (runtime.state_machine — the organism)
         "CHALLENGE",       # v0.5.4: adversarial round events (open/seat/
                            # commit/reveal/fraud/resolve — core.challenge)
         "RATE_LIMIT")      # v0.5.4: systematic-abuse evidence from the
                            # daemon rate limiter (one per offender/window)


# --------------------------------------------------------------------------- #
# Anchor port
# --------------------------------------------------------------------------- #

class LocalAnchor:
    """LOCAL-ONLY dev anchor (v0.4.1 P0-10 labeling): records (root, count) on
    THIS host. Detects truncation/rewrite by remembering the last anchored
    root — but provides NO replication, NO quorum, NO external timestamp.
    A witness anchored only locally is NOT inextinguishable: an attacker with
    host access can rewrite chain and anchor together. Production requires
    peer replication + external anchoring (M6, roadmap P1)."""
    def __init__(self):
        self.anchors = []

    def submit(self, node: str, root: str) -> dict:
        rec = {"node": node, "root": root, "seq": len(self.anchors)}
        self.anchors.append(rec)
        return rec

    def latest(self):
        return self.anchors[-1] if self.anchors else None


class OpenTimestampsAnchor:
    """Historic seam, now implemented: see core.anchoring.OtsCalendarAnchor
    (calendar client with proof custody) and core.anchoring.AnchorScheduler.
    This class remains for import compatibility and still raises — new code
    must use core.anchoring, which states its guarantees honestly."""
    def submit(self, node: str, root: str) -> dict:
        raise NotImplementedError(
            "use core.anchoring.OtsCalendarAnchor via AnchorScheduler")


# --------------------------------------------------------------------------- #
# Witness chain
# --------------------------------------------------------------------------- #

class WitnessChain:
    def __init__(self, signing_key: SigningKey = None, *, anchor=None, log_path=None):
        self.sk = signing_key or SigningKey.generate()
        self.node_id = canonical_node_id(self.sk.public)
        self.lock = threading.RLock()     # guards append (v0.5.3)
        self.anchor = anchor or LocalAnchor()
        self.log_path = log_path or os.environ.get("JJDAI_WITNESS_LOG")
        self.records = []
        self._salts = {}          # (index, field) -> salt   [LOCAL ONLY]
        self._last_anchor_index = 0
        if self.log_path and os.path.exists(self.log_path):
            self._load()

    # ---- core ----------------------------------------------------------- #
    def head_hash(self) -> str:
        return self.records[-1]["this_hash"] if self.records else GENESIS

    def next_index(self) -> int:
        return len(self.records)

    def _commit(self, index: int, field: str, obj):
        cm, salt = commit(canonical(obj))
        self._salts[(index, field)] = salt       # kept local, off-chain
        return cm

    def append(self, kind, *, request=None, response=None, provenance=None,
               semantic_digest=None, timestamp="1970-01-01T00:00:00Z",
               entanglement=None) -> dict:
        if kind not in KINDS:
            raise ValueError(f"unknown record kind {kind!r}")
        idx = self.next_index()
        body = {
            "index": idx,
            "prev_hash": self.head_hash(),
            "timestamp": timestamp,
            "node_id": self.node_id,
            "kind": kind,
            "request_commitment": self._commit(idx, "request", request) if request is not None else None,
            "response_commitment": self._commit(idx, "response", response) if response is not None else None,
            "provenance_hash": H_hex(canonical(provenance)) if provenance is not None else None,
            "semantic_digest": semantic_digest,
        }
        if entanglement is not None:
            # v0.5 P1: externally witnessed anteriority anchor. Included in
            # the hashed body — a beacon cannot be swapped after signing.
            # Omitted entirely when absent so pre-v0.5 records stay
            # byte-identical.
            body["entanglement"] = entanglement
        body["this_hash"] = H_hex(canonical(body))
        body["sig"] = self.sk.sign(body["this_hash"].encode()).hex()
        # ATOMICITY (v0.5): persist BEFORE exposing the record in memory.
        # The old order (append-then-persist) could leave a record visible
        # in RAM that never reached disk — the next append would then chain
        # onto a phantom prev_hash and the reloaded chain would be broken.
        # On persistence failure we roll back the commitment salts minted
        # for this index so no orphaned opening material survives.
        try:
            self._persist(body)
        except BaseException:
            for field in ("request", "response"):
                self._salts.pop((idx, field), None)
            raise
        self.records.append(body)
        return {"index": idx, "this_hash": body["this_hash"],
                "kind": kind, "anchored": False, "anchor_eta": "batch@root"}

    # ---- verification --------------------------------------------------- #
    def verify_chain(self, public: bytes = None) -> bool:
        pub = public or self.sk.public
        prev = GENESIS
        for i, rec in enumerate(self.records):
            if rec["index"] != i or rec["prev_hash"] != prev:
                return False
            body = {k: v for k, v in rec.items() if k not in ("this_hash", "sig")}
            if rec["this_hash"] != H_hex(canonical(body)):
                return False
            if not verify(pub, rec["this_hash"].encode(), bytes.fromhex(rec["sig"])):
                return False
            prev = rec["this_hash"]
        return True

    def replay(self) -> str:
        """Re-derive the head hash from record bodies alone (offline audit)."""
        prev = GENESIS
        for rec in self.records:
            body = {k: v for k, v in rec.items() if k not in ("this_hash", "sig")}
            body = dict(body); body["prev_hash"] = prev
            prev = H_hex(canonical(body))
        return prev

    # ---- anchoring ------------------------------------------------------ #
    def anchor_root(self) -> dict:
        new = self.records[self._last_anchor_index:]
        if not new:
            return {"anchored": 0}
        root = merkle_root([r["this_hash"].encode() for r in new])
        submitted = self.anchor.submit(self.node_id, root)
        self._last_anchor_index = len(self.records)
        return {"anchored": len(new), "root": root, "receipt": submitted}

    # ---- commitment opening (local, needs salt) ------------------------- #
    def open(self, index: int, field: str, obj) -> bool:
        from .crypto import open_commit
        salt = self._salts.get((index, field))
        if salt is None:
            return False
        rec = self.records[index]
        return open_commit(rec[field + "_commitment"], salt, canonical(obj))

    # ---- persistence (JSONL; salts are NOT written here) ---------------- #
    def _persist(self, body):
        if self.log_path:
            # DURABLE (v0.3.1.3): fsynced. Without this the witness — the one
            # thing that must survive a crash — lived in the page cache.
            from .durable import durable_append
            durable_append(self.log_path, body)

    def _load(self):
        # Crash-tolerant: a torn TRAILING line is the append that never
        # completed; drop it and repair the file so the next append is clean.
        from .durable import read_journal, truncate_torn_tail
        self.records, report = read_journal(self.log_path)
        if report.get("torn_tail"):
            truncate_torn_tail(self.log_path)
        self.torn_tail_repaired = bool(report.get("torn_tail"))
        # NOTE: _last_anchor_index is NOT set to len(records) here. Doing that
        # (the old behaviour) marked never-anchored records as anchored, so
        # after a restart they could never be anchored at all. Anchoring
        # position is restored from PERSISTED RECEIPTS via
        # core.durable.AnchorScheduler; absent receipts we start at 0 and
        # re-anchor, which is safe (an extra anchor costs nothing; a missing
        # one costs the truncation proof).
        self._last_anchor_index = 0

    def raw(self) -> str:
        return "\n".join(json.dumps(r, sort_keys=True) for r in self.records)


# --------------------------------------------------------------------------- #
# Read-only reader (ported from the M2 prototype — the Smriti half of the
# split: Sakshi writes and never judges; Smriti reads and never writes)
# --------------------------------------------------------------------------- #

class WitnessReader:
    """Read-only view of a jjdai-format witness log (JSONL of record bodies,
    each carrying this_hash + sig). Exposes iteration and verification ONLY;
    it deliberately has no append()/anchor_root() — the no-write invariant is
    STRUCTURAL (you cannot call a write it does not have), not a convention."""

    def __init__(self, path: str):
        self._path = path

    def records(self) -> list:
        if not os.path.exists(self._path):
            return []
        with open(self._path) as f:
            return [json.loads(line) for line in f if line.strip()]

    def head(self) -> str:
        recs = self.records()
        return recs[-1]["this_hash"] if recs else GENESIS

    def verify(self, pubkey_resolver=None) -> tuple:
        """Walk the chain: re-hash every body (JCS) and check every Ed25519
        signature. `pubkey_resolver`: node_id -> 32-byte pubkey (records are
        self-labelled with node_id, so multi-writer logs resolve per record).
        Returns (n_records, head_hash); raises ChainError on the first break.
        """
        prev = GENESIS
        n = 0
        for rec in self.records():
            if rec["index"] != n:
                raise ChainError(f"index gap at record {n}: got {rec['index']}")
            if rec["prev_hash"] != prev:
                raise ChainError(f"chain break at index {n}: prev_hash mismatch")
            body = {k: v for k, v in rec.items() if k not in ("this_hash", "sig")}
            if rec["this_hash"] != H_hex(canonical(body)):
                raise ChainError(f"tampered record at index {n}: hash mismatch")
            if pubkey_resolver is not None:
                pub = pubkey_resolver(rec.get("node_id"))
                if pub is None:
                    raise ChainError(f"unknown signer at index {n}")
                if not verify(pub, rec["this_hash"].encode(),
                              bytes.fromhex(rec["sig"])):
                    raise ChainError(f"bad signature at index {n}")
            prev = rec["this_hash"]
            n += 1
        return n, prev


class ChainError(RuntimeError):
    """Raised by readers/verifiers on any break: tampered, reordered, or
    truncated-in-middle."""


# --------------------------------------------------------------------------- #
# Legacy-log verification (cv-dispatch, ported verbatim in semantics from the
# retired M2 prototype WitnessLog). History shall not be erased (Manifesto
# Art. VII): every pre-migration log stays auditable from the new module.
#   Legacy line format: {"h", "body"{seq,ts,kind,prev_hash,payload},
#                        "cv"?, "node_id"?, "sig"?}
#   cv="jcs"    -> RFC 8785 body hash (records written v0.1+)
#   cv absent   -> "legacy" compact-json canon (sorted keys, no number norm)
#   sig         -> Ed25519 over (node_id ‖ h), envelope-level
# --------------------------------------------------------------------------- #

def _legacy_rec_hash(body: dict, cv: str) -> str:
    if cv == "jcs":
        return H_hex(canonical(body))
    return H_hex(json.dumps(body, ensure_ascii=False, sort_keys=True,
                            separators=(",", ":")).encode())


def verify_legacy_chain(path: str, pubkey_resolver=None) -> tuple:
    """Verify a prototype-format (M2) witness log. Returns (n, head_hash);
    raises ChainError on the first break. Per-record cv dispatch keeps
    unsigned pre-v0.1 logs verifying byte-for-byte."""
    prev = GENESIS
    n = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            body = rec["body"]
            if body["seq"] != n:
                raise ChainError(f"seq gap at record {n}: got {body['seq']}")
            if body["prev_hash"] != prev:
                raise ChainError(f"chain break at seq {n}: prev_hash mismatch")
            h = _legacy_rec_hash(body, rec.get("cv", "legacy"))
            if h != rec["h"]:
                raise ChainError(f"tampered record at seq {n}: hash mismatch")
            if pubkey_resolver is not None and "sig" in rec:
                pub = pubkey_resolver(rec.get("node_id"))
                if pub is None:
                    raise ChainError(f"unknown signer at seq {n}")
                if not verify(pub, (rec["node_id"] + h).encode(),
                              bytes.fromhex(rec["sig"])):
                    raise ChainError(f"bad signature at seq {n}")
            prev = h
            n += 1
    return n, prev
