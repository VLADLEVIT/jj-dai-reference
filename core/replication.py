# -*- coding: utf-8 -*-
"""
core.replication — Witness replication protocol (v0.5, P1 / M6)
================================================================
Closes the "single-disk witness is not inextinguishable" gap:

    local append
      -> signed root            (make_signed_root)
      -> peer replication       (ReplicaStore.accept on the receiver)
      -> peer acknowledgement   (make_ack / verify_ack)
      -> quorum receipt         (QuorumTracker -> verify_quorum_receipt)
      -> anchor record          (the origin appends ANCHOR_QUORUM to its chain)
      -> reconciliation         (reconcile: lag / divergence report)

Design constraints honored:
  * INV-9 (v1.1) — the Witness plane is non-executive, not causally inert:
    it never commands, selects or executes. Replication is performed by the
    NODE; the chain only receives records ABOUT achieved quorum.
  * Stdlib-only; all envelopes are JCS-canonical and Ed25519-signed with
    domain separation; everything is verifiable OFFLINE from the bundle.
  * Equivocation (two different roots signed by the same origin for the
    same count) is captured as durable DIVERGENCE_EVIDENCE — the signed
    envelopes themselves are the proof, admissible without trusting the
    reporter.

v0.5 drop 6 (Replication Soundness): roots are now RFC 6962 tree heads
(`root_alg: "rfc6962"`), so prefix consistency between two honest roots at
DIFFERENT counts is provable CT-style. A signed WITNESS_CONSISTENCY envelope
whose proof FAILS verification is itself durable evidence: the origin signed
a false prefix claim (INCONSISTENCY_EVIDENCE). Legacy v1 (duplicate-padding)
root envelopes still verify as signatures, but carry no consistency power.
"""
from __future__ import annotations

import os
import time

from jjdai.canonical import canonical
from jjdai.crypto import SigningKey, verify, node_id, canonical_node_id
from jjdai.merkle import (merkle_root, mth_root, consistency_proof,
                          verify_consistency)
from jjdai.durable import durable_append, read_journal

ROOT_DOMAIN = b"jjdai/replication/root/v1:"
ACK_DOMAIN = b"jjdai/replication/ack/v1:"
CONS_DOMAIN = b"jjdai/replication/consistency/v1:"


class ReplicationError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
#  Signed root envelopes
# --------------------------------------------------------------------------- #

def chain_leaves(chain) -> list:
    return [r["this_hash"].encode() for r in chain.records]


def chain_root(chain) -> str:
    """RFC 6962 tree head over the FULL record-hash list of a chain (v2).
    The legacy duplicate-padding root (v1, drop 1) is superseded: it could
    detect equal-count divergence but could not prove prefix consistency."""
    return mth_root(chain_leaves(chain))


def make_signed_root(chain, sk: SigningKey) -> dict:
    body = {
        "kind": "WITNESS_ROOT",
        "node_id": chain.node_id,
        "count": len(chain.records),
        "head_hash": chain.head_hash(),
        "root": chain_root(chain),
        "root_alg": "rfc6962",     # v2: consistency-provable tree head
        "ts": time.time(),
    }
    sig = sk.sign(ROOT_DOMAIN + canonical(body))
    return {"body": body, "pub": sk.public.hex(), "sig": sig.hex()}


def verify_signed_root(env: dict) -> tuple:
    """-> (ok: bool, reason: str). Offline: needs only the envelope."""
    try:
        body, pub, sig = env["body"], bytes.fromhex(env["pub"]), bytes.fromhex(env["sig"])
    except (KeyError, ValueError):
        return False, "malformed envelope"
    if body.get("kind") != "WITNESS_ROOT":
        return False, "wrong kind"
    if canonical_node_id(pub) != body.get("node_id"):
        return False, "node_id does not match public key"
    if not isinstance(body.get("count"), int) or body["count"] < 0:
        return False, "bad count"
    if not verify(pub, ROOT_DOMAIN + canonical(body), sig):
        return False, "bad signature"
    return True, "ok"


# --------------------------------------------------------------------------- #
#  CT-style consistency (v0.5 drop 6)
# --------------------------------------------------------------------------- #

def make_consistency(chain, sk: SigningKey, old_count: int) -> dict:
    """The origin's SIGNED claim that its current tree extends the tree it
    had at `old_count` — with the RFC 6962 proof attached. Because the claim
    is signed, a proof that fails verification is not noise: it is durable
    evidence that the origin asserted a false prefix relation."""
    leaves = chain_leaves(chain)
    if not (0 < old_count <= len(leaves)):
        raise ReplicationError(
            f"consistency: old_count {old_count} outside (0, {len(leaves)}]")
    body = {
        "kind": "WITNESS_CONSISTENCY",
        "node_id": chain.node_id,
        "old_count": old_count,
        "old_root": mth_root(leaves[:old_count]),
        "new_count": len(leaves),
        "new_root": mth_root(leaves),
        "proof": consistency_proof(leaves, old_count),
        "ts": time.time(),
    }
    sig = sk.sign(CONS_DOMAIN + canonical(body))
    return {"body": body, "pub": sk.public.hex(), "sig": sig.hex()}


def verify_consistency_envelope(env: dict, *, old_env: dict = None,
                                new_env: dict = None) -> tuple:
    """-> (status, reason). Fully offline.

    status:
      "consistent"   — signature valid AND the RFC 6962 proof verifies
      "inconsistent" — signature VALID but the proof FAILS, or the claimed
                       roots contradict the pinned signed root envelopes:
                       the origin signed a false prefix claim. EVIDENCE.
      "rejected"     — malformed / bad signature / not bound to the given
                       root envelopes' origin: carries no evidential weight.

    old_env/new_env: previously verified WITNESS_ROOT envelopes to pin the
    claim against (recommended — otherwise only the internal claim is
    checked)."""
    try:
        body, pub, sig = env["body"], bytes.fromhex(env["pub"]), bytes.fromhex(env["sig"])
    except (KeyError, TypeError, ValueError):
        return "rejected", "malformed envelope"
    if body.get("kind") != "WITNESS_CONSISTENCY":
        return "rejected", "wrong kind"
    if canonical_node_id(pub) != body.get("node_id"):
        return "rejected", "node_id does not match public key"
    if not verify(pub, CONS_DOMAIN + canonical(body), sig):
        return "rejected", "bad signature"
    m, n = body.get("old_count"), body.get("new_count")
    if not (isinstance(m, int) and isinstance(n, int) and 0 < m <= n):
        return "rejected", "bad counts"
    for pin, which in ((old_env, "old"), (new_env, "new")):
        if pin is None:
            continue
        pb = pin["body"]
        if pb.get("node_id") != body["node_id"]:
            return "rejected", f"{which} root envelope is for another origin"
        if pb.get("root_alg") != "rfc6962":
            return "rejected", f"{which} root is legacy v1 (no consistency power)"
        if pb.get("count") != body[f"{which}_count"] \
                or pb.get("root") != body[f"{which}_root"]:
            return ("inconsistent",
                    f"claimed {which} root/count contradicts the pinned "
                    f"signed root at count {pb.get('count')}")
    if not verify_consistency(m, n, body["old_root"], body["new_root"],
                              body.get("proof") or []):
        return "inconsistent", "signed consistency proof FAILS verification"
    return "consistent", "ok"


# --------------------------------------------------------------------------- #
#  Acknowledgements
# --------------------------------------------------------------------------- #

def make_ack(root_env: dict, sk: SigningKey) -> dict:
    """A receiver's signed receipt that it durably stored origin's root."""
    b = root_env["body"]
    body = {
        "kind": "ROOT_ACK",
        "origin_node": b["node_id"],
        "count": b["count"],
        "root": b["root"],
        "head_hash": b["head_hash"],
        "receiver_node": canonical_node_id(sk.public),
        "ts": time.time(),
    }
    sig = sk.sign(ACK_DOMAIN + canonical(body))
    return {"body": body, "pub": sk.public.hex(), "sig": sig.hex()}


def verify_ack(env: dict, *, origin_node: str = None, root: str = None,
               count: int = None) -> tuple:
    try:
        body, pub, sig = env["body"], bytes.fromhex(env["pub"]), bytes.fromhex(env["sig"])
    except (KeyError, ValueError):
        return False, "malformed envelope"
    if body.get("kind") != "ROOT_ACK":
        return False, "wrong kind"
    if canonical_node_id(pub) != body.get("receiver_node"):
        return False, "receiver_node does not match public key"
    if origin_node is not None and body.get("origin_node") != origin_node:
        return False, "origin mismatch"
    if root is not None and body.get("root") != root:
        return False, "root mismatch"
    if count is not None and body.get("count") != count:
        return False, "count mismatch"
    if not verify(pub, ACK_DOMAIN + canonical(body), sig):
        return False, "bad signature"
    return True, "ok"


# --------------------------------------------------------------------------- #
#  Replica store (receiver side)
# --------------------------------------------------------------------------- #

class ReplicaStore:
    """Durable, append-only store of OTHER nodes' signed roots.

    accept() outcomes:
        "stored"     — new, verified, durably persisted
        "duplicate"  — byte-identical (root, count) already held
        "stale"      — older count than the latest held for that origin
        "divergence" — SAME count, DIFFERENT root, valid signature from the
                       same origin: equivocation. Both envelopes are kept as
                       DIVERGENCE_EVIDENCE and the origin is marked.
        "rejected"   — signature/format verification failed
    """

    def __init__(self, path: str = None):
        self.path = path
        # origin -> {count -> env}; origin -> latest count
        self._roots: dict = {}
        self._diverged: dict = {}      # origin -> [evidence, ...]
        self._verified_prefix: dict = {}   # origin -> highest consistent old_count
        self._verified_pairs: dict = {}    # origin -> {(old, new), ...}
        if path and os.path.exists(path):
            entries, _ = read_journal(path)
            for e in entries:
                if e.get("kind") == "REPLICA_ROOT":
                    # FAIL CLOSED: a persisted root is re-verified before it
                    # is trusted as an existing origin checkpoint.
                    ok, reason = verify_signed_root(e["env"])
                    if not ok:
                        raise ReplicationError(
                            f"replica journal integrity failure on reload: "
                            f"{reason}")
                    self._hold(e["env"])
                elif e.get("kind") == "DIVERGENCE_EVIDENCE":
                    self._diverged.setdefault(e["origin"], []).append(e)
                elif e.get("kind") == "CONSISTENCY_VERIFIED":
                    # FAIL CLOSED: the persisted consistency envelope is
                    # re-verified before the prefix marker is trusted.
                    st, why = verify_consistency_envelope(e["env"])
                    if st != "consistent":
                        raise ReplicationError(
                            "replica journal integrity failure on reload: "
                            f"persisted consistency envelope {st}: {why}")
                    o = e["env"]["body"]["node_id"]
                    b = e["env"]["body"]
                    self._verified_prefix[o] = max(
                        self._verified_prefix.get(o, 0), b["old_count"])
                    self._verified_pairs.setdefault(o, set()).add(
                        (b["old_count"], b["new_count"]))
                elif e.get("kind") == "INCONSISTENCY_EVIDENCE":
                    self._diverged.setdefault(e["origin"], []).append(e)

    def _hold(self, env: dict):
        b = env["body"]
        self._roots.setdefault(b["node_id"], {})[b["count"]] = env

    def _persist(self, obj: dict):
        if self.path:
            durable_append(self.path, obj)

    def accept(self, env: dict) -> tuple:
        ok, reason = verify_signed_root(env)
        if not ok:
            return "rejected", reason
        b = env["body"]
        origin, count, root = b["node_id"], b["count"], b["root"]
        held = self._roots.get(origin, {})
        if count in held:
            if held[count]["body"]["root"] == root:
                return "duplicate", "already held"
            # Divergence is only provable within ONE root algorithm: a v1
            # (duplicate-padding) and a v2 (rfc6962) root over the same
            # records legitimately differ. Cross-alg pairs are not evidence.
            if held[count]["body"].get("root_alg") != b.get("root_alg"):
                self._hold(env)
                self._persist({"kind": "REPLICA_ROOT", "env": env})
                return "stored", "alg upgrade at same count (not divergence)"
            evidence = {
                "kind": "DIVERGENCE_EVIDENCE",
                "origin": origin,
                "count": count,
                "env_a": held[count],
                "env_b": env,
                "detected_at": time.time(),
            }
            self._diverged.setdefault(origin, []).append(evidence)
            self._persist(evidence)
            return "divergence", f"equivocation at count {count}"
        latest = max(held) if held else -1
        if count < latest:
            return "stale", f"held count {latest} > offered {count}"
        self._hold(env)
        self._persist({"kind": "REPLICA_ROOT", "env": env})
        return "stored", "ok"

    def latest(self, origin: str) -> dict | None:
        held = self._roots.get(origin, {})
        return held[max(held)] if held else None

    def divergence(self, origin: str = None) -> list:
        if origin is not None:
            return list(self._diverged.get(origin, []))
        return [e for evs in self._diverged.values() for e in evs]

    def origins(self) -> list:
        return sorted(self._roots)

    # ---- CT-style consistency (v0.5 drop 6) ----------------------------- #

    def consistency_wanted(self, origin: str) -> dict | None:
        """The (old, new) pair this store wants proven for `origin`:
        the previous held checkpoint linked to the newest one. Every new
        root gets ONE proof link to its predecessor; RFC 6962 consistency
        is transitive, so the linked sequence proves every held checkpoint
        a prefix of the newest. None when there is nothing (left) to prove."""
        held = self._roots.get(origin, {})
        v2 = sorted(c for c, e in held.items()
                    if e["body"].get("root_alg") == "rfc6962")
        if len(v2) < 2:
            return None
        old, new = v2[-2], v2[-1]
        if (old, new) in self._verified_pairs.get(origin, set()):
            return None
        return {"old": old, "new": new}

    def record_consistency(self, env: dict) -> tuple:
        """Verify a signed WITNESS_CONSISTENCY envelope against the roots
        this store already holds, and record the outcome durably.

        -> ("consistent"|"inconsistent"|"rejected", reason).
        "inconsistent" writes durable INCONSISTENCY_EVIDENCE: the origin's
        own signature makes the false prefix claim self-proving."""
        body = (env or {}).get("body") or {}
        origin = body.get("node_id")
        held = self._roots.get(origin, {})
        old_env = held.get(body.get("old_count"))
        new_env = held.get(body.get("new_count"))
        status, reason = verify_consistency_envelope(
            env, old_env=old_env, new_env=new_env)
        if status == "consistent":
            self._verified_prefix[origin] = max(
                self._verified_prefix.get(origin, 0), body["old_count"])
            self._verified_pairs.setdefault(origin, set()).add(
                (body["old_count"], body["new_count"]))
            self._persist({"kind": "CONSISTENCY_VERIFIED", "env": env})
        elif status == "inconsistent":
            evidence = {"kind": "INCONSISTENCY_EVIDENCE", "origin": origin,
                        "env": env, "detail": reason,
                        "pinned_old": old_env, "pinned_new": new_env,
                        "detected_at": time.time()}
            self._diverged.setdefault(origin, []).append(evidence)
            self._persist(evidence)
        return status, reason

    def verified_prefix(self, origin: str) -> int:
        return self._verified_prefix.get(origin, 0)


# --------------------------------------------------------------------------- #
#  Quorum (origin side)
# --------------------------------------------------------------------------- #

class QuorumTracker:
    """Collects acks for the origin's own roots and assembles receipts."""

    def __init__(self, origin_node: str, k: int):
        if k < 1:
            raise ReplicationError("quorum k must be >= 1")
        self.origin_node = origin_node
        self.k = k
        self._acks: dict = {}          # (count, root) -> {receiver -> ack}

    def add_ack(self, env: dict) -> tuple:
        ok, reason = verify_ack(env, origin_node=self.origin_node)
        if not ok:
            return False, reason
        b = env["body"]
        key = (b["count"], b["root"])
        self._acks.setdefault(key, {})[b["receiver_node"]] = env
        return True, "ok"

    def receipt(self, count: int, root: str) -> dict | None:
        """A verifiable QUORUM_RECEIPT once >= k DISTINCT receivers acked."""
        acks = self._acks.get((count, root), {})
        if len(acks) < self.k:
            return None
        return {
            "kind": "QUORUM_RECEIPT",
            "origin_node": self.origin_node,
            "count": count,
            "root": root,
            "k": self.k,
            "acks": [acks[r] for r in sorted(acks)],
            "assembled_at": time.time(),
        }


def verify_quorum_receipt(receipt: dict, *, origin_node: str = None,
                          k: int = None) -> tuple:
    """Fully offline verification of a quorum receipt bundle."""
    if receipt.get("kind") != "QUORUM_RECEIPT":
        return False, "wrong kind"
    origin = origin_node or receipt.get("origin_node")
    need = k or receipt.get("k")
    if receipt.get("origin_node") != origin:
        return False, "origin mismatch"
    receivers = set()
    for ack in receipt.get("acks", []):
        ok, reason = verify_ack(ack, origin_node=origin,
                                root=receipt.get("root"),
                                count=receipt.get("count"))
        if not ok:
            return False, f"invalid ack: {reason}"
        receivers.add(ack["body"]["receiver_node"])
    if origin in receivers:
        return False, "origin cannot ack itself"
    if len(receivers) < need:
        return False, f"{len(receivers)} distinct receiver(s) < k={need}"
    return True, "ok"


# --------------------------------------------------------------------------- #
#  Reconciliation
# --------------------------------------------------------------------------- #

def reconcile(own_root_env: dict, store: ReplicaStore) -> dict:
    """Periodic root reconciliation report: who lags, who diverged."""
    report = {"origin": own_root_env["body"]["node_id"],
              "own_count": own_root_env["body"]["count"],
              "peers": {}, "divergence": store.divergence()}
    for origin in store.origins():
        env = store.latest(origin)
        report["peers"][origin] = {
            "count": env["body"]["count"],
            "root": env["body"]["root"],
            "age_s": max(0.0, time.time() - env["body"]["ts"]),
        }
    return report
