"""JJ DAI v0.1 — M2 witness log.

Append-only, hash-chained record log (whitepaper §13 / §7.4). Replaces the M1
flat stub. Properties:

  * every record carries prev_hash -> tampering with ANY record breaks the
    chain from that point forward (tamper-EVIDENT, not tamper-proof);
  * two record kinds, interleaved in ONE chain per node:
      INFER   — provenance attestation of the config that produced an answer
                (trust via replication);
      SANDBOX — replayable execution proof (trust via replay);
  * the log head can be anchored externally (see anchor.py) so the state at
    time T cannot be silently rewritten later;
  * the witness OBSERVES and never gates (§12.1): appends are fire-and-forget
    for the hot path; verification is offline.

Format: JSONL. Each line: {"h": sha256(canonical(body)), "body": {...}}.
body = {seq, ts, kind, prev_hash, payload}. Canonicalization = sorted-keys
compact JSON of body — stable across writers.
"""
from __future__ import annotations
import json
import os
import time
from dataclasses import asdict, is_dataclass

from proto import sha256_text, sha256
from crypto import SigningKey, verify as _ed_verify, node_id as _node_id_of
from canonical import canonical as _jcs_canon

GENESIS = "0" * 64


def _canon(body: dict) -> str:
    # legacy compact-json (pre-v0.1+): sorted keys, compact, no number norm.
    return json.dumps(body, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def _rec_hash(body: dict, cv: str = "jcs") -> str:
    """Record-body hash, dispatched by canonicalization version.

    cv="jcs"    -> RFC 8785 JSON Canonicalization (cross-node deterministic:
                   1.0 and 1 hash identically; float ts normalised). Default
                   for records written from v0.1+.
    cv="legacy" -> the original compact-json canon, so pre-existing unsigned
                   logs still verify byte-for-byte (backward-compatible).
    """
    if cv == "jcs":
        return sha256(_jcs_canon(body))
    return sha256_text(_canon(body))


class ChainError(RuntimeError):
    """Raised by verify_chain on any break: tampered, reordered, or truncated-in-middle."""


class WitnessLog:
    def __init__(self, path: str, signing_key: SigningKey = None, canon: str = "jcs"):
        self.path = path
        # Signature graft (v0.1+): if a key is provided, every appended record
        # is Ed25519-signed at the ENVELOPE level (sibling of h/body). The body
        # and its hash stay UNCHANGED, so existing unsigned logs and all M2
        # tamper/anchor guarantees are preserved byte-for-byte. Purusha keeps
        # only witnessing — the signature adds attribution, not judgement.
        self._sk = signing_key
        self._node_id = _node_id_of(signing_key.public) if signing_key else None
        # Canonicalisation version for NEW records ("jcs" = RFC 8785, cross-node
        # deterministic). Each record self-labels its cv; verify dispatches per
        # record, so old ("legacy") logs still verify — fully backward-compatible.
        self._canon_ver = canon
        self._seq, self._head = self._load_tip()

    # ---------- internal ----------
    def _load_tip(self) -> tuple[int, str]:
        if not os.path.exists(self.path):
            return 0, GENESIS
        seq, head = 0, GENESIS
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                seq = rec["body"]["seq"] + 1
                head = rec["h"]
        return seq, head

    # ---------- write path ----------
    def append(self, kind: str, payload) -> str:
        """Append a record; returns its hash (the new head)."""
        if is_dataclass(payload):
            payload = asdict(payload)
        body = {
            "seq": self._seq,
            "ts": time.time(),
            "kind": kind,                 # "INFER" | "SANDBOX" | "ANCHOR"
            "prev_hash": self._head,
            "payload": payload,
        }
        h = _rec_hash(body, self._canon_ver)
        line = {"h": h, "body": body}
        if self._canon_ver != "legacy":
            line["cv"] = self._canon_ver         # self-labelling for verify dispatch
        if self._sk is not None:
            # sign (node_id ‖ h): binds identity so a signature cannot be
            # replayed under a different node_id. Body and h stay untouched.
            line["node_id"] = self._node_id
            line["sig"] = self._sk.sign((self._node_id + h).encode()).hex()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._seq += 1
        self._head = h
        return h

    def emit_infer(self, provenance: dict) -> str:
        return self.append("INFER", provenance)

    def emit_sandbox(self, verdict) -> str:
        return self.append("SANDBOX", verdict)

    def head(self) -> str:
        return self._head

    # ---------- read/verify path (offline) ----------
    @staticmethod
    def read_all(path: str) -> list[dict]:
        out = []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    @staticmethod
    def verify_chain(path: str, pubkey_resolver=None) -> tuple[int, str]:
        """Re-hash every record and walk the chain.

        Returns (n_records, head_hash) if intact; raises ChainError on the
        first break. This is what an auditor runs against a copied log.

        If `pubkey_resolver` is given (node_id -> 32-byte pubkey), signed
        records are additionally checked for a valid Ed25519 signature over
        (node_id ‖ h). Unsigned logs verify exactly as before (resolver=None),
        so this is fully backward-compatible with the M2 acceptance tests.
        """
        prev = GENESIS
        n = 0
        for rec in WitnessLog.read_all(path):
            body = rec["body"]
            if body["seq"] != n:
                raise ChainError(f"seq gap at record {n}: got {body['seq']}")
            if body["prev_hash"] != prev:
                raise ChainError(f"chain break at seq {n}: prev_hash mismatch")
            h = _rec_hash(body, rec.get("cv", "legacy"))
            if h != rec["h"]:
                raise ChainError(f"tampered record at seq {n}: hash mismatch")
            if pubkey_resolver is not None and "sig" in rec:
                pub = pubkey_resolver(rec.get("node_id"))
                if pub is None:
                    raise ChainError(f"unknown signer at seq {n}: {rec.get('node_id')}")
                if not _ed_verify(pub, (rec["node_id"] + h).encode(),
                                  bytes.fromhex(rec["sig"])):
                    raise ChainError(f"bad signature at seq {n}")
            prev = h
            n += 1
        return n, prev

    @staticmethod
    def replay(path: str, seq: int) -> dict:
        """Return the verified record at seq (verifies chain up to it)."""
        prev = GENESIS
        for rec in WitnessLog.read_all(path):
            body = rec["body"]
            if body["prev_hash"] != prev or _rec_hash(body, rec.get("cv", "legacy")) != rec["h"]:
                raise ChainError(f"chain invalid at seq {body['seq']}")
            prev = rec["h"]
            if body["seq"] == seq:
                return rec
        raise KeyError(f"seq {seq} not found")


class WitnessReader:
    """Read-only view of a witness log for consumers that must NEVER write to
    the ledger — notably Smriti, the Memory Keeper. It exposes iteration and
    verification only; it deliberately has no append()/emit_*. The no-write
    invariant is therefore STRUCTURAL (you cannot call a write it does not
    have), not a convention that could be forgotten.

        Sākṣī (WitnessLog)  writes and never judges.
        Smriti (via Reader) reads and never writes.
    """

    def __init__(self, path: str):
        self._path = path

    def records(self) -> list:
        return WitnessLog.read_all(self._path)

    def verify(self, pubkey_resolver=None) -> tuple:
        return WitnessLog.verify_chain(self._path, pubkey_resolver)

    def head(self) -> str:
        recs = WitnessLog.read_all(self._path)
        return recs[-1]["h"] if recs else GENESIS
