#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Entanglement cryptographic cross-link (v0.5, drop 6) — acceptance
=================================================================
  X-1  a salt request carrying the recipient's SIGNED root embeds the
       cross-link; an invalid or foreign recipient root refuses issuance
  X-2  PEER_ROOT checkpoint: the issuer witnesses a stored origin root;
       find_issuer_checkpoint locates it (and cross-linked SALT_ISSUE too)
  X-3  CRYPTOGRAPHIC attribution: a same-key rewrite that 'historically'
       embeds a post-checkpoint salt is convicted with confidence
       "cryptographic" and a per-record proof bundle; the honest history
       is not
  X-4  HONEST DEGRADATION: without the agreed root the same facts yield
       only confidence "evidential"; a mismatching agreed root yields no
       cryptographic verdict
  X-5  verified issuer exports: issuance_inclusion bundles verify offline
       against the issuer's signed root; tampers rejected
  X-6  live: /entangle/pull sends the recipient root; the issuer's chain
       witnesses the cross-linked issuance
"""
from __future__ import annotations

import copy
import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import SigningKey                                # noqa: E402
from jjdai.witness import WitnessChain                             # noqa: E402
from core.replication import make_signed_root                      # noqa: E402
from core.entanglement import (SaltBeacon, beacon_from,            # noqa: E402
                               EntanglementError,
                               find_issuer_checkpoint,
                               issuance_inclusion,
                               verify_issuance_inclusion,
                               judge_divergence)
from smoke_two_nodes import get, post, wait_up, spawn              # noqa: E402

PORT_I, PORT_R = 8661, 8662


def _export(chain):
    return {"node_id": chain.node_id, "records": list(chain.records)}


def test_crosslink_offline():
    sk_o = SigningKey.generate()       # origin (the one who may rewrite)
    sk_i = SigningKey.generate()       # issuer (neighboring Sākṣī)
    issuer = WitnessChain(sk_i)
    beacon_src = SaltBeacon(issuer, sk_i)

    # origin builds honest history up to the agreed count
    origin = WitnessChain(sk_o)
    for i in range(6):
        origin.append("INFER", semantic_digest={"i": i})
    agreed_env = make_signed_root(origin, sk_o)
    agreed_count = agreed_env["body"]["count"]

    # ---- X-1 ----
    env = beacon_src.issue(origin.node_id, recipient_root=agreed_env)
    b = env["body"]
    assert b["recipient_count"] == agreed_count \
        and b["recipient_root"] == agreed_env["body"]["root"], \
        "X-1: the salt must embed the recipient's committed chain state"
    dig = issuer.records[-1]["semantic_digest"]
    assert dig["recipient_count"] == agreed_count, \
        "X-1: the issuance WITNESS must carry the cross-link"
    bad_root = copy.deepcopy(agreed_env)
    bad_root["body"]["count"] = 999
    try:
        beacon_src.issue(origin.node_id, recipient_root=bad_root)
        assert False, "X-1: tampered recipient root must refuse issuance"
    except EntanglementError:
        pass
    stranger = WitnessChain(SigningKey.generate())
    foreign = make_signed_root(stranger, stranger.sk)
    try:
        beacon_src.issue(origin.node_id, recipient_root=foreign)
        assert False, "X-1: a root signed by another node must be refused"
    except EntanglementError:
        pass
    print("  [PASS] X-1  cross-linked issuance; invalid/foreign roots refused")

    # ---- X-2 ----
    # issuer also witnesses the origin's root the replication way (PEER_ROOT)
    issuer.append("PEER_ROOT", semantic_digest={
        "origin": origin.node_id, "count": agreed_count,
        "root": agreed_env["body"]["root"], "root_alg": "rfc6962"})
    cp = find_issuer_checkpoint(_export(issuer), origin.node_id, agreed_count,
                                root=agreed_env["body"]["root"])
    assert cp and cp["via"] in ("PEER_ROOT", "SALT_ISSUE") \
        and cp["witnessed_count"] >= agreed_count, f"X-2: {cp}"
    assert find_issuer_checkpoint(_export(issuer), origin.node_id,
                                  agreed_count + 1) is None, \
        "X-2: a checkpoint must never overclaim the witnessed count"
    print(f"  [PASS] X-2  issuer checkpoint located via {cp['via']} "
          f"at issuer index {cp['index']}")

    # ---- X-3 ----
    # a POST-checkpoint salt is drawn...
    late_salt = beacon_src.issue(origin.node_id)
    assert late_salt["body"]["issuer_index"] > cp["index"]
    late_beacon = beacon_from([late_salt], recipient_node=origin.node_id)
    # honest history: the salt lands ABOVE the agreed count (new record)
    origin.append("INFER", semantic_digest={"i": 6}, entanglement=late_beacon)
    honest = {"node_id": origin.node_id, "records": list(origin.records)}
    # forged history: same key, record BELOW the agreed count embeds it
    rewrite = WitnessChain(sk_o)
    for i in range(6):
        ent = late_beacon if i == 3 else None
        rewrite.append("INFER", semantic_digest={"i": i, "rw": True},
                       entanglement=ent)
    forged = {"node_id": rewrite.node_id, "records": list(rewrite.records)}

    verdict = judge_divergence(forged, honest, _export(issuer),
                               agreed_count=agreed_count,
                               agreed_root_env=agreed_env)
    assert verdict["verdict"] == "a_anachronistic" \
        and verdict["confidence"] == "cryptographic", f"X-3: {verdict}"
    pf = verdict["proof"][0]
    assert pf["record_index"] == 3 \
        and pf["salt_issuer_index"] > pf["checkpoint_index"], \
        "X-3: the proof bundle must name record, salt and checkpoint"
    # symmetric: swap sides, verdict follows the forgery
    verdict2 = judge_divergence(honest, forged, _export(issuer),
                                agreed_count=agreed_count,
                                agreed_root_env=agreed_env)
    assert verdict2["verdict"] == "b_anachronistic" \
        and verdict2["confidence"] == "cryptographic"
    print("  [PASS] X-3  rewrite convicted with confidence=cryptographic; "
          "proof bundle names record/salt/checkpoint")

    # ---- X-4 ----
    v_no_root = judge_divergence(forged, honest, _export(issuer),
                                 agreed_count=agreed_count)
    assert v_no_root["confidence"] == "evidential", \
        "X-4: without the agreed root the verdict must degrade honestly"
    wrong = copy.deepcopy(agreed_env)
    wrong["body"]["count"] = agreed_count - 1     # breaks the signature
    v_wrong = judge_divergence(forged, honest, _export(issuer),
                               agreed_count=agreed_count,
                               agreed_root_env=wrong)
    assert v_wrong["confidence"] == "evidential", \
        "X-4: an invalid agreed root must never yield a cryptographic verdict"
    print("  [PASS] X-4  honest degradation to evidential without/with-bad "
          "agreed root")

    # ---- X-5 ----
    issuer_root = make_signed_root(issuer, sk_i)
    bundle = issuance_inclusion(_export(issuer),
                                late_salt["body"]["salt_hash"], issuer_root)
    ok, why = verify_issuance_inclusion(
        bundle, salt_hash=late_salt["body"]["salt_hash"])
    assert ok, f"X-5: {why}"
    for name, mut in {
        "record": lambda x: x["record"].update(kind="INFER"),
        "index": lambda x: x.update(index=x["index"] - 1),
        "proof": lambda x: x["proof"].__setitem__(
            0, (x["proof"][0][0], "ff" * 32)),
        "root": lambda x: x["root_env"]["body"].update(root="00" * 32),
    }.items():
        bad = copy.deepcopy(bundle)
        mut(bad)
        ok, _ = verify_issuance_inclusion(bad)
        assert not ok, f"X-5: tamper not caught: {name}"
    print("  [PASS] X-5  issuance inclusion bundle verifies offline; "
          "4 tamper classes caught")


def test_crosslink_live():
    # env is process-global and other live suites pin their own
    # passphrase constants — set for our spawns, restore after.
    _prev_pass = os.environ.get("JJDAI_KEYSTORE_PASSPHRASE")
    os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = "xl-test-pass"
    base_i = f"http://127.0.0.1:{PORT_I}"
    base_r = f"http://127.0.0.1:{PORT_R}"
    with tempfile.TemporaryDirectory() as tmp:
        procs = [
            spawn(PORT_I, "xl-issuer", "fp-xl-I", [
                "--log", os.path.join(tmp, "issuer.jsonl"),
                "--node-keystore", os.path.join(tmp, "issuer.keystore")]),
            spawn(PORT_R, "xl-recipient", "fp-xl-R", [
                "--log", os.path.join(tmp, "recipient.jsonl"),
                "--node-keystore", os.path.join(tmp, "recipient.keystore"),
                "--salt-peers", base_i]),
        ]
        try:
            wait_up(base_i)
            wait_up(base_r)
            r_root = get(base_r + "/witness/root")[1]
            r_nid, r_count = r_root["body"]["node_id"], r_root["body"]["count"]

            code, pulled = post(base_r + "/entangle/pull", {})
            assert code == 200 and pulled["received"] == 1, f"X-6: {pulled}"

            issuer_export = get(base_i + "/witness/chain")[1]
            issued = [r for r in issuer_export["records"]
                      if r["kind"] == "SALT_ISSUE"]
            assert issued, "X-6: issuance must be witnessed"
            dig = issued[-1]["semantic_digest"]
            assert dig["recipient_node"] == r_nid \
                and dig.get("recipient_count") == r_count \
                and dig.get("recipient_root") == r_root["body"]["root"], \
                f"X-6: the live issuance witness must carry the cross-link: {dig}"
            cp = find_issuer_checkpoint(issuer_export, r_nid, r_count,
                                        root=r_root["body"]["root"])
            assert cp and cp["via"] == "SALT_ISSUE", f"X-6: {cp}"
            print("  [PASS] X-6  live pull embeds the recipient root; "
                  "issuer witnesses the cross-link; checkpoint locatable")
        finally:
            if _prev_pass is None:
                os.environ.pop("JJDAI_KEYSTORE_PASSPHRASE", None)
            else:
                os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = _prev_pass
            for pr in procs:
                pr.terminate()
            for pr in procs:
                try:
                    pr.wait(timeout=10)
                except Exception:
                    pr.kill()


if __name__ == "__main__":
    test_crosslink_offline()
    test_crosslink_live()
    print("\nENTANGLEMENT CROSS-LINK: all groups green  ✓ certified")
