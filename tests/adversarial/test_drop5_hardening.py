#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Drop-5 hardening — adversarial acceptance (v0.5)
================================================
Regression tests for every defect found in the external v0.5-dev.4 audit.
Each check is written to FAIL against the pre-fix code.

Ed25519 cryptographic boundary:
  ED-NEG-1  identity/neutral public key rejected for any message
  ED-NEG-2  all eight canonical small-order points rejected as pubkeys
  ED-NEG-3  small-order R in the signature rejected
  ED-NEG-4  malformed / non-canonical encodings rejected
  ED-NEG-5  the full IFF bypass chain is dead: a keyless degenerate
            identity can no longer be admitted or authenticated
  ED-POS-1  honest keys still sign/verify (no false negatives)

Canonical identity:
  ID-1  NodeIdentity, WitnessChain, verdicts and the network layer all
        derive ONE identity string from a key

Journal integrity (fail closed on reload):
  J-1   forged PeerRegistry journal line refused at startup
  J-2   forged ReplicaStore root refused at startup
  J-3   forged ManifestRegistry entry refused at startup

Atomicity:
  A-1   witness append: a persistence failure leaves NO record in memory
  A-2   Plane H: a witness failure rolls back the knowledge write —
        no unwitnessed mutable knowledge survives

IFF hardening:
  N-1   unauthenticated requests cannot grow the nonce cache
  N-2   malformed timestamp -> controlled refusal, not an exception
  N-3   a suspended peer cannot self-reactivate by replaying admission

Entanglement:
  T-1   an ancient salt cannot be made "fresh" by re-wrapping it
  T-2   a salt issued to another node is refused
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import (SigningKey, verify, canonical_node_id,      # noqa: E402
                          H_hex)
from jjdai.canonical import canonical                                 # noqa: E402
from jjdai.witness import WitnessChain, LocalAnchor                   # noqa: E402
from jjdai.durable import durable_append                              # noqa: E402
from core.identity import NodeIdentity                                # noqa: E402
from core.peers import (PeerRegistry, RequestAuthenticator, PeerError,  # noqa: E402
                        make_peer_record, admit_peer, make_signed_request,
                        REQUEST_DOMAIN)
from core.replication import ReplicaStore, ReplicationError           # noqa: E402
from core.manifests import (ManifestRegistry, ManifestError,          # noqa: E402
                            make_substrate_manifest)
from core.rag_store import RagStore                                   # noqa: E402
from core.plane_h import (GovernedPlaneH, WritePolicy,                # noqa: E402
                          make_write_proposal)
from core.entanglement import (SaltBeacon, beacon_from,               # noqa: E402
                               EntanglementError)

# The eight canonical small-order (torsion) point encodings of Ed25519.
SMALL_ORDER = [
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
]
MESSAGES = (b"", b"hello", b"anything", b"transfer 1000000")


def test_ed25519_negatives():
    # ---- ED-NEG-1 / ED-NEG-2 ----
    for pk in SMALL_ORDER:
        for msg in MESSAGES:
            for sig in (pk + bytes(32), bytes(64),
                        SMALL_ORDER[0] + bytes(32)):
                assert not verify(pk, msg, sig), (
                    "ED-NEG-1/2: small-order public key accepted a signature "
                    f"(pk={pk.hex()[:16]}…) — keyless identity forgery")
    # ---- ED-NEG-3: small-order R with an honest pubkey ----
    sk = SigningKey.generate()
    for r in SMALL_ORDER:
        assert not verify(sk.public, b"hello", r + bytes(32)), \
            "ED-NEG-3: small-order R accepted"
    # ---- ED-NEG-4: malformed encodings ----
    assert not verify(b"", b"m", bytes(64)), "ED-NEG-4: empty pubkey"
    assert not verify(bytes(31), b"m", bytes(64)), "ED-NEG-4: short pubkey"
    assert not verify(sk.public, b"m", bytes(63)), "ED-NEG-4: short sig"
    non_canonical = b"\xff" * 32          # y >= p: not a valid encoding
    assert not verify(non_canonical, b"m", bytes(64)), \
        "ED-NEG-4: non-canonical point encoding accepted"
    # s >= L must be refused (malleability)
    good = sk.sign(b"m")
    bad_s = good[:32] + (2**252).to_bytes(32, "little")
    assert not verify(sk.public, b"m", bad_s), "ED-NEG-4: s >= L accepted"
    # ---- ED-POS-1: no false negatives ----
    for _ in range(5):
        k = SigningKey.generate()
        m = os.urandom(24)
        assert verify(k.public, m, k.sign(m)), "ED-POS-1: honest sig rejected"
        assert not verify(k.public, m + b"x", k.sign(m)), \
            "ED-POS-1: wrong message accepted"


def test_ed25519_iff_bypass_is_dead():
    """ED-NEG-5 — the auditor's full attack chain, end to end."""
    degenerate_pub = SMALL_ORDER[0]
    zero_sig = degenerate_pub + bytes(32)
    fake_nid = canonical_node_id(degenerate_pub)

    # 1) a self-signed peer record with no private key must not verify
    record = {"body": {"kind": "PEER_RECORD", "node_id": fake_nid,
                       "base_url": "http://evil", "roles": ["replicate"],
                       "created_at": time.time()},
              "pub": degenerate_pub.hex(), "sig": zero_sig.hex()}
    steward = SigningKey.generate()
    bundle = admit_peer(steward, record)        # honest authority countersigns
    reg = PeerRegistry(admission_keys={canonical_node_id(steward.public)})
    try:
        reg.register(bundle)
    except PeerError:
        pass
    else:
        raise AssertionError(
            "ED-NEG-5: a keyless degenerate identity was ADMITTED — the IFF "
            "bypass is still open")
    assert not reg.is_friend(fake_nid), "ED-NEG-5: degenerate peer is a friend"


def test_canonical_identity_unified():
    """ID-1 — one key, one identity, everywhere."""
    with tempfile.TemporaryDirectory() as tmp:
        ident = NodeIdentity.load_or_create(os.path.join(tmp, "k"), "pw")
        chain = WitnessChain(ident.sk, anchor=LocalAnchor())
        canon = canonical_node_id(ident.sk.public)
        assert ident.node_id == canon, "ID-1: NodeIdentity diverges"
        assert chain.node_id == canon, "ID-1: WitnessChain diverges"
        rec = chain.append("MEMORY", semantic_digest={"x": 1})
        assert chain.records[0]["node_id"] == canon, \
            "ID-1: witness records carry a different identity"
        # network layer envelopes
        from core.replication import make_signed_root, verify_signed_root
        env = make_signed_root(chain, ident.sk)
        ok, why = verify_signed_root(env)
        assert ok and env["body"]["node_id"] == canon, \
            f"ID-1: replication identity diverges ({why})"


def test_journal_integrity_fail_closed():
    with tempfile.TemporaryDirectory() as tmp:
        steward = SigningKey.generate()
        skeys = {canonical_node_id(steward.public)}

        # ---- J-1 PeerRegistry ----
        p1 = os.path.join(tmp, "peers.jsonl")
        durable_append(p1, {"kind": "PEER_ADMITTED", "bundle": {
            "record": {"body": {"kind": "PEER_RECORD", "node_id": "attacker",
                                "base_url": "http://evil", "roles": [],
                                "created_at": 0},
                       "pub": "00" * 32, "sig": "00" * 64},
            "admission": {"body": {"kind": "PEER_ADMISSION",
                                   "peer_node": "attacker",
                                   "record_digest": "x",
                                   "admitted_by": "nobody", "admitted_at": 0},
                          "pub": "00" * 32, "sig": "00" * 64}}})
        try:
            reg = PeerRegistry(p1, admission_keys=skeys)
        except PeerError:
            pass
        else:
            raise AssertionError(
                f"J-1: forged journal accepted on reload; friends="
                f"{reg.friends()}")

        # ---- J-2 ReplicaStore ----
        p2 = os.path.join(tmp, "replicas.jsonl")
        durable_append(p2, {"kind": "REPLICA_ROOT", "env": {
            "body": {"kind": "WITNESS_ROOT", "node_id": "evil", "count": 9,
                     "head_hash": "h", "root": "r", "ts": 0},
            "pub": "00" * 32, "sig": "00" * 64}})
        try:
            st = ReplicaStore(p2)
        except ReplicationError:
            pass
        else:
            raise AssertionError(
                f"J-2: forged root accepted on reload; origins={st.origins()}")

        # ---- J-3 ManifestRegistry ----
        p3 = os.path.join(tmp, "manifests.jsonl")
        sk = SigningKey.generate()
        good = make_substrate_manifest(
            sk, substrate_id="sha256:" + H_hex(b"s"), name="n", version="1",
            base_family="b", architecture_family="a",
            training_data_families=["w"], profile="B")
        forged = {"body": dict(good["body"], name="EVIL"),
                  "pub": good["pub"], "sig": good["sig"]}
        durable_append(p3, {"kind": "MANIFEST", "env": forged})
        try:
            ManifestRegistry(p3)
        except ManifestError:
            pass
        else:
            raise AssertionError("J-3: forged manifest accepted on reload")


def test_witness_append_atomicity():
    """A-1 — a persistence failure must leave no phantom record."""
    with tempfile.TemporaryDirectory() as tmp:
        sk = SigningKey.generate()
        chain = WitnessChain(sk, anchor=LocalAnchor(),
                             log_path=os.path.join(tmp, "w.jsonl"))
        chain.append("MEMORY", semantic_digest={"n": 0})
        before = len(chain.records)
        head_before = chain.head_hash()

        def boom(_body):
            raise OSError("disk full")

        chain._persist = boom
        try:
            chain.append("MEMORY", semantic_digest={"n": 1})
        except OSError:
            pass
        else:
            raise AssertionError("A-1: persistence failure was swallowed")
        assert len(chain.records) == before, \
            "A-1: a record that never reached disk is visible in memory"
        assert chain.head_hash() == head_before, "A-1: head advanced"
        assert chain.verify_chain(), "A-1: chain must stay verifiable"


def test_plane_h_atomicity():
    """A-2 — no unwitnessed mutable knowledge."""
    class BrokenWitness:
        node_id = "node:broken"

        def append(self, *a, **k):
            raise OSError("witness unavailable")

    with tempfile.TemporaryDirectory() as tmp:
        store = RagStore(os.path.join(tmp, "rag.db"))
        sk = SigningKey.generate()
        policy = WritePolicy()
        ns = "t/ns"
        policy.grant(ns, canonical_node_id(sk.public), ops=("add",))
        gov = GovernedPlaneH(store, policy, witness=BrokenWitness())
        text = "knowledge that must not survive an unwitnessed write"
        env = make_write_proposal(sk, op="add", ns=ns, doc_id="d1", text=text)
        try:
            gov.apply(env, text)
        except OSError:
            pass
        else:
            raise AssertionError("A-2: witness failure was swallowed")
        rows = store.db.execute(
            "SELECT COUNT(*) FROM chunks WHERE ns=?", (ns,)).fetchone()[0]
        metas = store.db.execute(
            "SELECT COUNT(*) FROM chunk_meta").fetchone()[0]
        assert rows == 0, f"A-2: {rows} unwitnessed chunk(s) survived"
        assert metas == 0, f"A-2: {metas} orphaned metadata row(s) survived"


def test_iff_nonce_and_status_hardening():
    steward = SigningKey.generate()
    peer_sk = SigningKey.generate()
    reg = PeerRegistry(admission_keys={canonical_node_id(steward.public)})
    bundle = admit_peer(steward, make_peer_record(peer_sk,
                                                  base_url="http://p"))
    reg.register(bundle)
    auth = RequestAuthenticator(reg, window_s=30.0, nonce_capacity=2)

    # ---- N-1 unauthenticated requests must not touch the cache ----
    for i in range(10):
        forged = make_signed_request(peer_sk, path="/x", payload={"i": i})
        forged["auth"]["sig"] = "00" * 64          # invalid signature
        ok, why = auth.check(forged, path="/x")
        assert not ok, "N-1: forged signature accepted"
    assert len(auth._seen) == 0, \
        f"N-1: unauthenticated sender grew the nonce cache to {len(auth._seen)}"

    # ---- N-2 malformed timestamp -> controlled refusal ----
    bad_ts = make_signed_request(peer_sk, path="/x", payload={})
    bad_ts["auth"]["body"]["ts"] = "oops"
    try:
        ok, why = auth.check(bad_ts, path="/x")
    except Exception as e:
        raise AssertionError(f"N-2: malformed ts raised {type(e).__name__}")
    assert not ok and "timestamp" in why, f"N-2: {why}"

    # ---- N-3 suspended peer cannot self-reactivate ----
    nid = canonical_node_id(peer_sk.public)
    reg.set_status(nid, "suspended")
    assert not reg.is_friend(nid), "N-3: suspension did not take effect"
    reg.register(bundle)                            # replay the admission
    assert not reg.is_friend(nid), \
        "N-3: replaying an admission bundle resurrected a suspended peer"


def test_entanglement_freshness_and_binding():
    issuer_sk = SigningKey.generate()
    issuer_chain = WitnessChain(issuer_sk, anchor=LocalAnchor())
    beacon = SaltBeacon(issuer_chain, issuer_sk)
    me = canonical_node_id(SigningKey.generate().public)
    other = canonical_node_id(SigningKey.generate().public)

    # ---- T-1 an ancient salt cannot be re-wrapped as fresh ----
    env = beacon.issue(me)
    env["body"]["issued_at"] = time.time() - 999_999      # tamper -> bad sig
    try:
        beacon_from([env], recipient_node=me)
    except EntanglementError:
        pass
    else:
        raise AssertionError("T-1: tampered issuance time accepted")

    fresh = beacon.issue(me)
    b = beacon_from([fresh], recipient_node=me)
    assert "min_issued_at" in b, "T-1: beacon must carry signed issuance time"
    assert abs(b["min_issued_at"] - fresh["body"]["issued_at"]) < 1e-9, \
        "T-1: freshness must derive from the SIGNED issued_at"

    # ---- T-2 a salt issued to someone else is refused ----
    not_mine = beacon.issue(other)
    try:
        beacon_from([not_mine], recipient_node=me)
    except EntanglementError as e:
        assert "recipient" in str(e), f"T-2: wrong reason: {e}"
    else:
        raise AssertionError("T-2: a salt bound to another node was accepted")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\nDROP-5 HARDENING: {len(tests)}/{len(tests)} groups green  ✓")
