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
from .canonical import canonical
from .crypto import H_hex, SigningKey, verify, node_id, commit
from .merkle import merkle_root

GENESIS = "0" * 64
KINDS = ("INFER", "SANDBOX", "GROUNDING")


# --------------------------------------------------------------------------- #
# Anchor port
# --------------------------------------------------------------------------- #

class LocalAnchor:
    """Dev anchor: records (root, count) locally. Detects truncation/rewrite by
    remembering the last anchored root."""
    def __init__(self):
        self.anchors = []

    def submit(self, node: str, root: str) -> dict:
        rec = {"node": node, "root": root, "seq": len(self.anchors)}
        self.anchors.append(rec)
        return rec

    def latest(self):
        return self.anchors[-1] if self.anchors else None


class OpenTimestampsAnchor:
    """Production seam: anchor the root to Bitcoin via OpenTimestamps.
    Network + `opentimestamps` client required; left as a seam."""
    def submit(self, node: str, root: str) -> dict:
        raise NotImplementedError("OpenTimestamps anchor: production seam, network required")


# --------------------------------------------------------------------------- #
# Witness chain
# --------------------------------------------------------------------------- #

class WitnessChain:
    def __init__(self, signing_key: SigningKey = None, *, anchor=None, log_path=None):
        self.sk = signing_key or SigningKey.generate()
        self.node_id = node_id(self.sk.public)
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
               semantic_digest=None, timestamp="1970-01-01T00:00:00Z") -> dict:
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
        body["this_hash"] = H_hex(canonical(body))
        body["sig"] = self.sk.sign(body["this_hash"].encode()).hex()
        self.records.append(body)
        self._persist(body)
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
            with open(self.log_path, "a") as f:
                f.write(json.dumps(body, sort_keys=True) + "\n")

    def _load(self):
        with open(self.log_path) as f:
            self.records = [json.loads(line) for line in f if line.strip()]
        self._last_anchor_index = len(self.records)

    def raw(self) -> str:
        return "\n".join(json.dumps(r, sort_keys=True) for r in self.records)
