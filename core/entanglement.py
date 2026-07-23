# -*- coding: utf-8 -*-
"""
core.entanglement — Cross-chain salt entanglement (v0.5, P1)
============================================================
Idea (V.L.): a node takes a pseudorandom SALT from a neighbor before
signing; the neighbor WITNESSES the issuance in its own chain. A record
embedding that salt provably could not exist before the issuance — the
"not-before" bound. Root replication (core.replication) provides the
"not-after" bound. Together they sandwich every record's creation time
between two externally witnessed events.

What this adds over replication alone: replication detects that TWO
histories exist (divergence); entanglement supplies EVIDENCE about which
one is anachronistic — a rewritten chain's "old" records embed salts
issued later than the agreed checkpoint.

STATUS (v0.5 drop 6): the cryptographic CROSS-LINK exists. A salt request
now carries the recipient's SIGNED root; the issuer verifies it, embeds it
in the salt envelope, and witnesses stored peer roots (PEER_ROOT records)
on its own chain. That closes the chain of custody the drop-5 audit asked
for:  origin agreed root <-> issuer chain checkpoint <-> salt issuance.
When the link is present, judge_divergence() can return confidence
"cryptographic": a record claimed to sit BELOW the agreed count that embeds
a salt issued AFTER the issuer witnessed the origin's root AT the agreed
count is a proven rewrite — proven by the origin's OWN signature on that
root, the issuer's hash-chain ordering, and the salt inside the record's
signed body. The remaining trust assumption is the ISSUER's chain itself
(anchor it; use m-of-n distinct issuers against collusion). Without the
link, output degrades honestly to confidence "evidential" — an
investigative signal for Stewards, never an automatic verdict.

This is distributed linked timestamping (Haber–Stornetta) across JJ DAI
nodes: the Sākṣī witness each other.

Collusion note: a single issuer can conspire with the rewriter, so
beacons support MULTIPLE issuers; strict policies should demand m-of-n
distinct salts. Salts are public — their power is freshness binding via
the issuer's witnessed sequence, not secrecy.

Envelopes are JCS-canonical, Ed25519-signed, domain-separated,
offline-verifiable against the issuer's chain export.
"""
from __future__ import annotations

import os
import time

from jjdai.canonical import canonical
from jjdai.crypto import H_hex, SigningKey, verify, node_id, canonical_node_id

SALT_DOMAIN = b"jjdai/entangle/salt/v1:"


class EntanglementError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
#  Issuer side — the salt beacon
# --------------------------------------------------------------------------- #

class SaltBeacon:
    """Issues witnessed salts. The issuance is appended to the ISSUER's
    witness chain BEFORE the envelope is released: the salt does not exist,
    as far as the network is concerned, until the issuer's Sākṣī has seen
    it. The envelope binds the issuer's chain state (index + head hash) at
    the moment of issuance — that is the anteriority anchor."""

    def __init__(self, chain, sk: SigningKey):
        self.chain = chain
        self.sk = sk

    def issue(self, recipient_node: str, *, recipient_root: dict = None) -> dict:
        """recipient_root (v0.5 drop 6, optional): the recipient's SIGNED
        WITNESS_ROOT envelope at request time. When present it is VERIFIED,
        embedded in the salt body, and witnessed in the issuance digest —
        the cryptographic cross-link. A recipient that supplies its root is
        committing, under its own key, to its chain length at this moment;
        every later attempt to 'historically' embed this salt below that
        count is self-refuting."""
        salt = os.urandom(32).hex()
        body = {
            "kind": "SALT_ISSUE",
            "issuer_node": self.chain.node_id,
            "recipient_node": recipient_node,
            "salt": salt,
            "salt_hash": H_hex(bytes.fromhex(salt)),
            # chain state BEFORE the issuance record is appended:
            "issuer_index": len(self.chain.records),
            "issuer_head": self.chain.head_hash(),
            "issued_at": time.time(),
        }
        digest = {
            "recipient_node": recipient_node,
            "salt_hash": body["salt_hash"],
            "issuer_index": body["issuer_index"],
            "issuer_head": body["issuer_head"]}
        if recipient_root is not None:
            from core.replication import verify_signed_root
            ok, why = verify_signed_root(recipient_root)
            if not ok:
                raise EntanglementError(
                    f"refusing to cross-link an invalid recipient root: {why}")
            rb = recipient_root["body"]
            if rb["node_id"] != recipient_node:
                raise EntanglementError(
                    "recipient root is signed by a different node than the "
                    "salt recipient — refusing the cross-link")
            body["recipient_count"] = rb["count"]
            body["recipient_root"] = rb["root"]
            body["recipient_head"] = rb["head_hash"]
            digest["recipient_count"] = rb["count"]
            digest["recipient_root"] = rb["root"]
        sig = self.sk.sign(SALT_DOMAIN + canonical(body))
        env = {"body": body, "pub": self.sk.public.hex(), "sig": sig.hex()}
        # witness the issuance on the issuer's own chain (public digest —
        # issuance is meant to be auditable, nothing to hide):
        self.chain.append("SALT_ISSUE", semantic_digest=digest)
        return env


def verify_salt_envelope(env: dict) -> tuple:
    try:
        body, pub, sig = env["body"], bytes.fromhex(env["pub"]), bytes.fromhex(env["sig"])
    except (KeyError, TypeError, ValueError):
        return False, "malformed envelope"
    if body.get("kind") != "SALT_ISSUE":
        return False, "wrong kind"
    if canonical_node_id(pub) != body.get("issuer_node"):
        return False, "issuer_node does not match public key"
    if H_hex(bytes.fromhex(body.get("salt", ""))) != body.get("salt_hash"):
        return False, "salt hash mismatch"
    if not verify(pub, SALT_DOMAIN + canonical(body), sig):
        return False, "bad signature"
    return True, "ok"


# --------------------------------------------------------------------------- #
#  Recipient side — beacons embedded in records
# --------------------------------------------------------------------------- #

def beacon_from(envs: list, *, recipient_node: str = None) -> dict:
    """The compact entanglement object a recipient embeds into its witness
    records. Multiple issuers supported (collusion resistance: strict
    policies demand m-of-n distinct issuers).

    recipient_node: when given, every salt MUST have been issued to this
    node — a salt handed to someone else cannot be re-used here."""
    salts = []
    min_issued = None
    for env in envs:
        ok, why = verify_salt_envelope(env)
        if not ok:
            raise EntanglementError(f"refusing bad salt envelope: {why}")
        b = env["body"]
        if recipient_node is not None and b["recipient_node"] != recipient_node:
            raise EntanglementError(
                f"salt was issued to {b['recipient_node'][:16]}…, not to this "
                "node — refusing a salt bound to another recipient")
        entry = {"issuer_node": b["issuer_node"],
                 "issuer_index": b["issuer_index"],
                 "issuer_head": b["issuer_head"],
                 "salt_hash": b["salt_hash"],
                 "issued_at": b["issued_at"],           # SIGNED time
                 "envelope": env}
        if "recipient_count" in b:                      # cross-linked (drop 6)
            entry["recipient_count"] = b["recipient_count"]
            entry["recipient_root"] = b["recipient_root"]
        salts.append(entry)
        if min_issued is None or b["issued_at"] < min_issued:
            min_issued = b["issued_at"]
    if not salts:
        raise EntanglementError("beacon requires at least one salt")
    return {"kind": "ENTANGLEMENT_BEACON",
            "salts": sorted(salts, key=lambda s: s["issuer_node"]),
            "distinct_issuers": len({s["issuer_node"] for s in salts}),
            # freshness is judged on the SIGNED issuance time, never on a
            # locally-chosen taken_at (which an attacker could backdate-wrap):
            "min_issued_at": min_issued,
            "taken_at": time.time()}


def verify_beacon_against_issuer(beacon: dict, issuer_export: dict) -> tuple:
    """Offline anteriority check of ONE issuer's salt inside a beacon
    against that issuer's exported chain: the SALT_ISSUE witness record
    must exist at the claimed index with the matching salt hash and the
    claimed pre-issuance head must equal the hash of the preceding record.
    issuer_export: {"node_id":…, "records":[…]} (daemon /witness/chain)."""
    issuer_id = issuer_export.get("node_id")
    recs = issuer_export.get("records", [])
    match = [s for s in beacon.get("salts", [])
             if s["issuer_node"] == issuer_id]
    if not match:
        return False, "beacon carries no salt from this issuer"
    s = match[0]
    ok, why = verify_salt_envelope(s["envelope"])
    if not ok:
        return False, f"salt envelope invalid: {why}"
    idx = s["issuer_index"]
    if idx >= len(recs):
        return False, (f"issuer chain has {len(recs)} record(s); issuance "
                       f"claims index {idx} — salt not witnessed (yet?)")
    rec = recs[idx]
    if rec.get("kind") != "SALT_ISSUE":
        return False, f"issuer record {idx} is {rec.get('kind')!r}, not SALT_ISSUE"
    dig = rec.get("semantic_digest") or {}
    if dig.get("salt_hash") != s["salt_hash"]:
        return False, "issuer record does not witness this salt"
    prev_head = recs[idx - 1]["this_hash"] if idx > 0 else None
    if idx > 0 and s["issuer_head"] != prev_head:
        return False, "claimed issuer head does not match issuer chain"
    return True, "ok"


# --------------------------------------------------------------------------- #
#  Verified issuer exports (v0.5 drop 6)
# --------------------------------------------------------------------------- #

def issuance_inclusion(issuer_export: dict, salt_hash: str,
                       issuer_root_env: dict) -> dict:
    """A compact, offline-verifiable proof that a SALT_ISSUE record sits in
    the issuer's chain UNDER the issuer's signed (ideally quorum-anchored)
    root — verifiers no longer need the issuer's full chain, only this
    bundle. Uses the RFC 6962 tree of record hashes."""
    from jjdai.merkle import mth_inclusion
    from core.replication import verify_signed_root
    ok, why = verify_signed_root(issuer_root_env)
    if not ok:
        raise EntanglementError(f"issuer root invalid: {why}")
    rb = issuer_root_env["body"]
    if rb.get("root_alg") != "rfc6962":
        raise EntanglementError("issuer root is legacy v1; inclusion proofs "
                                "require an rfc6962 root")
    recs = issuer_export.get("records", [])[:rb["count"]]
    idx = next((i for i, r in enumerate(recs)
                if r.get("kind") == "SALT_ISSUE"
                and (r.get("semantic_digest") or {}).get("salt_hash") == salt_hash),
               None)
    if idx is None:
        raise EntanglementError("no SALT_ISSUE record for this salt under "
                                "the given root")
    leaves = [r["this_hash"].encode() for r in recs]
    return {"kind": "ISSUANCE_INCLUSION",
            "issuer_node": issuer_export.get("node_id"),
            "record": recs[idx], "index": idx,
            "tree_size": rb["count"],
            "proof": mth_inclusion(leaves, idx),
            "root_env": issuer_root_env}


def verify_issuance_inclusion(bundle: dict, *, salt_hash: str = None) -> tuple:
    """Offline verification of an issuance_inclusion bundle: root envelope
    signature, record body hash + record signature under the issuer key,
    and the RFC 6962 audit path from the record to the signed root."""
    from jjdai.crypto import H_hex as _H
    from jjdai.canonical import canonical as _c
    from jjdai.merkle import mth_verify_inclusion
    from core.replication import verify_signed_root
    try:
        env = bundle["root_env"]
        rec = bundle["record"]
        idx = bundle["index"]
        n = bundle["tree_size"]
        proof = bundle["proof"]
    except (KeyError, TypeError):
        return False, "malformed bundle"
    ok, why = verify_signed_root(env)
    if not ok:
        return False, f"issuer root invalid: {why}"
    rb = env["body"]
    if rb.get("root_alg") != "rfc6962" or rb.get("count") != n:
        return False, "root/tree_size mismatch or legacy root"
    if rec.get("kind") != "SALT_ISSUE":
        return False, "record is not a SALT_ISSUE"
    if salt_hash is not None and \
            (rec.get("semantic_digest") or {}).get("salt_hash") != salt_hash:
        return False, "record witnesses a different salt"
    body = {k: v for k, v in rec.items() if k not in ("this_hash", "sig")}
    if rec.get("this_hash") != _H(_c(body)):
        return False, "tampered record body"
    if rec.get("node_id") != rb["node_id"]:
        return False, "record signed as a different node"
    if not verify(bytes.fromhex(env["pub"]), rec["this_hash"].encode(),
                  bytes.fromhex(rec.get("sig", ""))):
        return False, "bad record signature"
    if not mth_verify_inclusion(rec["this_hash"].encode(), idx, n, proof,
                                rb["root"]):
        return False, "inclusion proof fails against the signed root"
    return True, "ok"


def find_issuer_checkpoint(issuer_export: dict, origin_node: str,
                           min_count: int, *, root: str = None) -> dict | None:
    """The earliest record in the issuer's chain that witnesses the ORIGIN's
    chain at count >= min_count — either a PEER_ROOT record (the issuer
    accepted the origin's signed root) or a SALT_ISSUE whose cross-link
    embeds the origin's root. Every issuer record at a HIGHER index is
    hash-chain-provably later than this witnessed fact."""
    for i, rec in enumerate(issuer_export.get("records", [])):
        dig = rec.get("semantic_digest") or {}
        if rec.get("kind") == "PEER_ROOT" \
                and dig.get("origin") == origin_node \
                and isinstance(dig.get("count"), int) \
                and dig["count"] >= min_count \
                and (root is None or dig.get("root") == root):
            return {"index": i, "record": rec, "via": "PEER_ROOT",
                    "witnessed_count": dig["count"]}
        if rec.get("kind") == "SALT_ISSUE" \
                and dig.get("recipient_node") == origin_node \
                and isinstance(dig.get("recipient_count"), int) \
                and dig["recipient_count"] >= min_count \
                and (root is None or dig.get("recipient_root") == root):
            return {"index": i, "record": rec, "via": "SALT_ISSUE",
                    "witnessed_count": dig["recipient_count"]}
    return None


# --------------------------------------------------------------------------- #
#  Divergence judgment — WHICH history is fabricated
# --------------------------------------------------------------------------- #

def judge_divergence(chain_a: dict, chain_b: dict, issuer_export: dict,
                     *, agreed_count: int, agreed_root_env: dict = None) -> dict:
    """Temporal attribution of two same-origin histories diverging at/below
    `agreed_count`.

    CRYPTOGRAPHIC path (drop 6, requires agreed_root_env — the origin's
    SIGNED root at agreed_count): find the issuer's checkpoint record that
    witnesses the origin's chain at count >= agreed_count. Any salt issued
    at a HIGHER issuer index is hash-chain-provably issued AFTER the origin
    itself signed that its chain had agreed_count records. A record claimed
    to sit BELOW agreed_count that embeds such a salt is therefore a proven
    rewrite: proven by (1) the origin's own signature on the agreed root,
    (2) the issuer chain's ordering, (3) the salt inside the record's signed
    body. confidence: "cryptographic", with the per-record proof bundle.
    Remaining assumption: the issuer's chain is honest (anchor it; use
    m-of-n distinct issuers).

    EVIDENTIAL fallback (no cross-link available): the side whose
    'historical' records embed salts at HIGHER issuer indices is the more
    likely fabrication — an investigative signal for Stewards, never an
    automatic verdict. Inconclusive when neither (or both equally) show
    anachronism; absence of beacons is not evidence."""
    issuer_id = issuer_export.get("node_id")

    checkpoint = None
    if agreed_root_env is not None:
        from core.replication import verify_signed_root
        ok, why = verify_signed_root(agreed_root_env)
        rb = agreed_root_env.get("body", {})
        if ok and rb.get("count") == agreed_count:
            checkpoint = find_issuer_checkpoint(
                issuer_export, rb["node_id"], agreed_count,
                root=rb.get("root"))

    def scan(chain: dict):
        best, proven = None, []
        for rec in chain.get("records", [])[:agreed_count]:
            beacon = rec.get("entanglement")
            if not beacon:
                continue
            for s in beacon.get("salts", []):
                if s["issuer_node"] != issuer_id:
                    continue
                ok, _ = verify_beacon_against_issuer(
                    {"salts": [s]}, issuer_export)
                if not ok:
                    continue
                if best is None or s["issuer_index"] > best:
                    best = s["issuer_index"]
                if checkpoint and s["issuer_index"] > checkpoint["index"]:
                    proven.append({
                        "record_index": rec.get("index"),
                        "record_hash": rec.get("this_hash"),
                        "salt_hash": s["salt_hash"],
                        "salt_issuer_index": s["issuer_index"],
                        "checkpoint_index": checkpoint["index"],
                        "checkpoint_via": checkpoint["via"],
                        "witnessed_count": checkpoint["witnessed_count"]})
        return best, proven

    (a_max, a_proof), (b_max, b_proof) = scan(chain_a), scan(chain_b)

    if checkpoint and (a_proof or b_proof) and not (a_proof and b_proof):
        side = "a" if a_proof else "b"
        return {"verdict": f"{side}_anachronistic",
                "confidence": "cryptographic",
                "proof": a_proof or b_proof,
                "checkpoint": {"index": checkpoint["index"],
                               "via": checkpoint["via"],
                               "witnessed_count": checkpoint["witnessed_count"]},
                "agreed_root_env": agreed_root_env,
                "max_issuer_index": {"a": a_max, "b": b_max},
                "agreed_count": agreed_count,
                "issuer_node": issuer_id,
                "assumption": "issuer chain honest (anchor it; m-of-n issuers)"}

    verdict = "inconclusive"
    if a_max is not None and b_max is not None and a_max != b_max:
        verdict = "a_anachronistic" if a_max > b_max else "b_anachronistic"
    return {"verdict": verdict,
            "confidence": "evidential",   # no cross-link: signal, not proof
            "max_issuer_index": {"a": a_max, "b": b_max},
            "agreed_count": agreed_count,
            "issuer_node": issuer_id}
