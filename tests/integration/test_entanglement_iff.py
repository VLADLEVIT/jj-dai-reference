#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IFF + cross-chain entanglement (v0.5, P1 items 6+7 + salt) — acceptance
=======================================================================
IFF (friend-or-foe):
  I-1  signed requests: valid passes; replay (same nonce) refused; stale
       timestamp refused; non-admitted sender is a foe (unit level)
  I-2  admission: a steward-countersigned peer record is admitted via
       /peers/hello; a bundle without recognized admission is 403 FOE
  I-3  /entangle/salt under --require-admission: foe 403, friend 200
  I-4  /replicate/root under --require-admission: non-admitted origin 403

Entanglement (witnessed salts):
  E-1  a node pulls salts from TWO issuers; the beacon counts 2 distinct
       issuers; each issuer's chain witnessed a SALT_ISSUE record
  E-2  INFER records embed the beacon; anteriority verifies OFFLINE
       against each issuer's chain export
  E-3  --entangle-strict refuses inference without a fresh beacon (503)
       and serves it after /entangle/pull (200)
  E-4  divergence judgment: a same-key rewritten history embeds salts
       issued LATER than the agreed count — judge_divergence names the
       fabricated side (the forgery dates itself)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import canonical_node_id, SigningKey, node_id                        # noqa: E402
from jjdai.witness import WitnessChain, LocalAnchor                 # noqa: E402
from core.identity import NodeIdentity                              # noqa: E402
from core.peers import (PeerRegistry, RequestAuthenticator,         # noqa: E402
                        make_peer_record, admit_peer,
                        make_signed_request)
from core.entanglement import (SaltBeacon, beacon_from,             # noqa: E402
                               verify_beacon_against_issuer,
                               judge_divergence)
from smoke_two_nodes import get, post, wait_up, jii, spawn          # noqa: E402

P_A, P_B, P_C, P_D = 8651, 8652, 8653, 8654
BASE = {p: f"http://127.0.0.1:{p}" for p in (P_A, P_B, P_C, P_D)}
PASS = "iff-test-pass"


def test_iff_unit():
    # ---- I-1 ----
    steward = SigningKey.generate()
    peer_sk = SigningKey.generate()
    reg = PeerRegistry(admission_keys={canonical_node_id(steward.public)})
    reg.register(admit_peer(steward, make_peer_record(
        peer_sk, base_url="http://127.0.0.1:9999")))
    auth = RequestAuthenticator(reg, window_s=30.0)

    env = make_signed_request(peer_sk, path="/x", payload={"a": 1})
    ok, who = auth.check(env, path="/x")
    assert ok and who == canonical_node_id(peer_sk.public), f"I-1: valid must pass: {who}"
    ok, why = auth.check(env, path="/x")
    assert not ok and "replay" in why, f"I-1: replay must be refused: {why}"

    stale = make_signed_request(peer_sk, path="/x", payload={})
    stale["auth"]["body"]["ts"] -= 3600            # tamper -> also bad sig
    ok, why = auth.check(stale, path="/x")
    assert not ok, "I-1: tampered/stale request must be refused"

    foe_sk = SigningKey.generate()
    foe = make_signed_request(foe_sk, path="/x", payload={})
    ok, why = auth.check(foe, path="/x")
    assert not ok and "foe" in why.lower() or "admitted" in why, \
        f"I-1: non-admitted sender must be a foe: {why}"

    wrong_path = make_signed_request(peer_sk, path="/x", payload={})
    ok, why = auth.check(wrong_path, path="/y")
    assert not ok and "bound to" in why, "I-1: path binding must be enforced"


def test_iff_and_entanglement_live():
    os.environ.setdefault("JJDAI_KEYSTORE_PASSPHRASE", PASS)
    steward = SigningKey.generate()
    steward_nid = canonical_node_id(steward.public)
    with tempfile.TemporaryDirectory() as tmp:
        def ks(name):
            return os.path.join(tmp, f"{name}.keystore")

        procs = []
        # B, C: salt issuers, admission required, steward is the authority
        for port, name in ((P_B, "iff-B"), (P_C, "iff-C")):
            procs.append(spawn(port, name, f"fp-{name}", [
                "--log", os.path.join(tmp, f"{name}.jsonl"),
                "--node-keystore", ks(name),
                "--require-admission", "--admission-key", steward_nid,
                "--peer-registry", os.path.join(tmp, f"{name}.peers.jsonl")]))
        # A: draws salts from B and C (m=2), relaxed embedding
        procs.append(spawn(P_A, "iff-A", "fp-iff-A", [
            "--log", os.path.join(tmp, "iff-A.jsonl"),
            "--node-keystore", ks("iff-A"),
            "--salt-peers", f"{BASE[P_B]},{BASE[P_C]}",
            "--entangle-min", "2"]))
        # D: strict entanglement, single issuer B
        procs.append(spawn(P_D, "iff-D", "fp-iff-D", [
            "--log", os.path.join(tmp, "iff-D.jsonl"),
            "--node-keystore", ks("iff-D"),
            "--salt-peers", BASE[P_B],
            "--entangle-strict"]))
        try:
            caps = {p: wait_up(BASE[p]) for p in BASE}

            # ---- I-2 admission of A and D on B and C ----
            for name in ("iff-A", "iff-D"):
                ident = NodeIdentity.load_or_create(ks(name), PASS)
                bundle = admit_peer(steward, make_peer_record(
                    ident.sk, base_url="http://127.0.0.1:0"))
                for issuer in (P_B, P_C):
                    code, resp = post(BASE[issuer] + "/peers/hello", bundle)
                    assert code == 200, f"I-2: admission failed: {resp}"
            rogue = SigningKey.generate()
            bad_bundle = admit_peer(rogue, make_peer_record(
                rogue, base_url="http://127.0.0.1:0"))
            code, resp = post(BASE[P_B] + "/peers/hello", bad_bundle)
            assert code == 403, "I-2: unrecognized admission must be 403 FOE"

            # ---- I-3 salt gating ----
            code, resp = post(BASE[P_B] + "/entangle/salt",
                              {"payload": {"recipient_node": "nobody"}})
            assert code == 403, "I-3: foe must not draw salts"

            # ---- I-4 replication gating ----
            root_c = get(BASE[P_C] + "/witness/root")[1]
            # C is NOT admitted on B (only A and D were) -> foe
            code, resp = post(BASE[P_B] + "/replicate/root", root_c)
            assert code == 403, \
                f"I-4: non-admitted origin must be 403, got {code} {resp}"

            # ---- E-1 pull salts (A is admitted -> friend) ----
            code, pull = post(BASE[P_A] + "/entangle/pull", {})
            assert code == 200 and pull["received"] == 2 \
                and pull["beacon"]["distinct_issuers"] == 2, \
                f"E-1: expected 2 salts from 2 issuers: {pull}"
            for issuer in (P_B, P_C):
                exp = get(BASE[issuer] + "/witness/chain")[1]
                issued = [r for r in exp["records"]
                          if r["kind"] == "SALT_ISSUE"]
                assert issued, f"E-1: issuer :{issuer} must witness issuance"

            # ---- E-2 INFER embeds beacon; offline anteriority ----
            code, _ = post(BASE[P_A] + "/v1/messages",
                           jii(caps[P_A], prompt="entangled ping"))
            assert code == 200
            exp_a = get(BASE[P_A] + "/witness/chain")[1]
            infers = [r for r in exp_a["records"] if r["kind"] == "INFER"]
            assert infers and infers[-1].get("entanglement"), \
                "E-2: INFER record must embed the beacon"
            beacon = infers[-1]["entanglement"]
            for issuer in (P_B, P_C):
                exp_i = get(BASE[issuer] + "/witness/chain")[1]
                ok, why = verify_beacon_against_issuer(beacon, exp_i)
                assert ok, f"E-2: anteriority vs :{issuer} failed: {why}"

            # ---- E-3 strict mode ----
            code, resp = post(BASE[P_D] + "/v1/messages",
                              jii(caps[P_D], prompt="strict ping"))
            assert code == 503 and "ENTANGLEMENT" in resp["error"], \
                f"E-3: strict node must refuse without beacon: {code} {resp}"
            code, pull_d = post(BASE[P_D] + "/entangle/pull", {})
            assert code == 200 and pull_d["received"] == 1, f"E-3: {pull_d}"
            code, resp = post(BASE[P_D] + "/v1/messages",
                              jii(caps[P_D], prompt="strict ping 2"))
            assert code == 200, f"E-3: with beacon inference must pass: {resp}"
        finally:
            for p in procs:
                p.terminate()
            for p in procs:
                p.wait(timeout=5)


def test_divergence_judgment():
    """E-4 — the forgery dates itself (library level, offline)."""
    issuer_sk = SigningKey.generate()
    issuer_chain = WitnessChain(issuer_sk, anchor=LocalAnchor())
    beaconer = SaltBeacon(issuer_chain, issuer_sk)

    victim_sk = SigningKey.generate()   # the node that later rewrites itself

    # HONEST history: salts drawn EARLY (issuer indices 0 and 1)
    honest = WitnessChain(victim_sk, anchor=LocalAnchor())
    for i in range(2):
        b = beacon_from([beaconer.issue(honest.node_id)])
        honest.append("MEMORY", semantic_digest={"n": i}, entanglement=b)
    agreed_count = len(honest.records)          # peers hold a root here
    honest_export = {"node_id": honest.node_id, "records": honest.records}

    # time passes; the issuer's chain grows independently
    for _ in range(5):
        issuer_chain.append("MEMORY", semantic_digest={"filler": True})

    # REWRITE: same key, "history" rebuilt — but salts can only be drawn NOW
    rewritten = WitnessChain(victim_sk, anchor=LocalAnchor())
    for i in range(2):
        b = beacon_from([beaconer.issue(rewritten.node_id)])
        rewritten.append("MEMORY", semantic_digest={"n": i, "forged": True},
                         entanglement=b)
    rewritten_export = {"node_id": rewritten.node_id,
                        "records": rewritten.records}
    issuer_export = {"node_id": issuer_chain.node_id,
                     "records": issuer_chain.records}

    verdict = judge_divergence(honest_export, rewritten_export,
                               issuer_export, agreed_count=agreed_count)
    assert verdict["verdict"] == "b_anachronistic", \
        f"E-4: the rewrite must be flagged anachronistic: {verdict}"
    assert verdict["max_issuer_index"]["b"] > verdict["max_issuer_index"]["a"], \
        "E-4: anachronistic side must show later salts"
    # and symmetrically:
    verdict2 = judge_divergence(rewritten_export, honest_export,
                                issuer_export, agreed_count=agreed_count)
    assert verdict2["verdict"] == "a_anachronistic", "E-4: symmetric judgment"


if __name__ == "__main__":
    test_iff_unit()
    print("  ok  IFF unit (I-1)")
    test_iff_and_entanglement_live()
    print("  ok  IFF + entanglement live (I-2..I-4, E-1..E-3)")
    test_divergence_judgment()
    print("  ok  divergence judgment (E-4)")
    print("\nIFF + ENTANGLEMENT: 8/8 groups green  ✓ certified")
