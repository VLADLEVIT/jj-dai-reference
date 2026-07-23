#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Replication Soundness (v0.5, drop 6) — acceptance
=================================================
Segments + recovery:
  S-1  signed segments verify offline; every tamper class caught
  S-2  SegmentStore: stored / duplicate / self-proving SEGMENT_DIVERGENCE /
       fail-closed reload
  S-3  recovery FAILS HONEST on gaps (names them), succeeds with full
       coverage, refuses a mismatching trusted root, and the recovered log
       reloads as a live chain that RESUMES appending
CT-style consistency:
  C-1  honest extension: signed consistency envelope verifies offline and
       against pinned roots
  C-2  rewrite: the origin's signed consistency claim FAILS the proof —
       durable INCONSISTENCY_EVIDENCE, self-proving
  C-3  ReplicaStore: consistency_wanted names the (old, new) link;
       verified_prefix advances; state survives a reload
Live 3-node:
  L-1  push propagates root + consistency + segments; receiver coverage
       becomes complete; verified_prefix advances on the receiver
  L-2  a receiver's copy is sufficient: origin's history recovered from the
       receiver's segment store against the quorum-anchored root
  L-3  restart restoration: rebooted origin restores quorum receipts and
       _anchor_covered from the durable journal (no re-anchor of covered
       history)
Locking:
  T-1  signed_root under concurrent appends is always internally
       consistent (count/head/root coexist)
"""
from __future__ import annotations

import copy
import os
import sys
import tempfile
import threading
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import SigningKey                                # noqa: E402
from jjdai.witness import WitnessChain, WitnessReader              # noqa: E402
from jjdai.merkle import mth_root                                  # noqa: E402
from core.replication import (make_signed_root, verify_signed_root,  # noqa: E402
                              make_consistency,
                              verify_consistency_envelope, ReplicaStore)
from core.segments import (make_segment, verify_segment,           # noqa: E402
                           SegmentStore, SegmentError,
                           recover_records, write_recovered_log)
from smoke_two_nodes import get, post, wait_up, jii, spawn         # noqa: E402

PORT_A, PORT_B, PORT_C = 8651, 8652, 8653
BASE = {p: f"http://127.0.0.1:{p}" for p in (PORT_A, PORT_B, PORT_C)}


def _chain_with(sk, n, tag="x"):
    ch = WitnessChain(sk)
    for i in range(n):
        ch.append("INFER", semantic_digest={"tag": tag, "i": i})
    return ch


def test_segments_offline():
    sk = SigningKey.generate()
    ch = _chain_with(sk, 9)

    # ---- S-1 ----
    seg = make_segment(ch, sk, 2, 7)
    assert verify_segment(seg) == (True, "ok"), "S-1: honest segment"
    tampers = {
        "record body": lambda e: e["records"][1].update(kind="SANDBOX"),
        "record swap": lambda e: e["records"].reverse(),
        "range lie": lambda e: e["body"].update(start=1),
        "foreign signer": lambda e: e.update(
            pub=SigningKey.generate().public.hex()),
        "dropped record": lambda e: e["records"].pop(),
    }
    for name, mut in tampers.items():
        bad = copy.deepcopy(seg)
        mut(bad)
        ok, why = verify_segment(bad)
        assert not ok, f"S-1: tamper not caught: {name}"
    zero = make_segment(ch, sk, 0, 4)
    assert verify_segment(zero)[0], "S-1: genesis segment"
    print("  [PASS] S-1  signed segments verify offline; 5 tamper classes caught")

    # ---- S-2 ----
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "segs.jsonl")
        st = SegmentStore(path)
        assert st.accept(seg)[0] == "stored"
        assert st.accept(seg)[0] == "duplicate"
        assert st.coverage(ch.node_id) == [(2, 7)]
        # same-key rewrite of index 5 -> conflicting signed records
        ch_rw = WitnessChain(sk)
        for i in range(9):
            ch_rw.append("INFER", semantic_digest={"tag": "x",
                                                   "i": i if i != 5 else -1})
        rw = make_segment(ch_rw, sk, 2, 7)
        status, why = st.accept(rw)
        assert status == "divergence", f"S-2: {status} {why}"
        ev = st.divergence(ch.node_id)[-1]
        assert ev["index"] == 5 and \
            ev["record_a"]["this_hash"] != ev["record_b"]["this_hash"], \
            "S-2: evidence must carry both signed records"
        # fail-closed reload: intact journal reloads; corrupted one refuses
        st2 = SegmentStore(path)
        assert st2.coverage(ch.node_id) == [(2, 7)] and st2.divergence()
        with open(path) as f:
            lines = f.read().strip().split("\n")
        import json as _json
        forged = _json.loads(lines[0])
        forged["env"]["records"][0]["semantic_digest"] = {"forged": True}
        with open(path, "w") as f:
            f.write(_json.dumps(forged) + "\n")
        try:
            SegmentStore(path)
            assert False, "S-2: forged journal must refuse the boot"
        except SegmentError:
            pass
    print("  [PASS] S-2  store: stored/duplicate/divergence + fail-closed reload")

    # ---- S-3 ----
    root_env = make_signed_root(ch, sk)
    with tempfile.TemporaryDirectory() as tmp:
        st = SegmentStore(os.path.join(tmp, "segs.jsonl"))
        st.accept(make_segment(ch, sk, 4, 9))
        r = recover_records(st, ch.node_id, root_env)
        assert not r["ok"] and r["missing"] == [(0, 4)], \
            "S-3: gaps must be NAMED, not papered over"
        st.accept(make_segment(ch, sk, 0, 4))
        r = recover_records(st, ch.node_id, root_env)
        assert r["ok"] and len(r["records"]) == 9, r["reason"]
        # a mismatching trusted root refuses the reconstruction
        other = _chain_with(sk, 9, tag="other")
        wrong_root = make_signed_root(other, sk)
        r_bad = recover_records(st, ch.node_id, wrong_root)
        assert not r_bad["ok"] and "different history" in r_bad["reason"]
        # recovered log reloads as a LIVE chain and resumes appending
        out = os.path.join(tmp, "recovered.jsonl")
        assert write_recovered_log(r["records"], out) == 9
        try:
            write_recovered_log(r["records"], out)
            assert False, "S-3: must refuse to overwrite an existing log"
        except SegmentError:
            pass
        live = WitnessChain(sk, log_path=out)
        assert live.verify_chain() and live.head_hash() == ch.head_hash()
        live.append("INFER", semantic_digest={"resumed": True})
        assert live.verify_chain(), "S-3: resumed chain must verify"
        n, head = WitnessReader(out).verify(
            pubkey_resolver=lambda nid: sk.public)
        assert n == 10 and head == live.head_hash()
    print("  [PASS] S-3  recovery fails honest on gaps; restores; resumes; "
          "refuses wrong root")


def test_consistency_offline():
    sk = SigningKey.generate()
    ch = _chain_with(sk, 5)
    root5 = make_signed_root(ch, sk)
    for i in range(5, 12):
        ch.append("INFER", semantic_digest={"i": i})
    root12 = make_signed_root(ch, sk)

    # ---- C-1 ----
    cons = make_consistency(ch, sk, 5)
    st, why = verify_consistency_envelope(cons, old_env=root5, new_env=root12)
    assert st == "consistent", f"C-1: {st} {why}"
    st, why = verify_consistency_envelope(cons)
    assert st == "consistent", "C-1: internal claim alone must also verify"
    print("  [PASS] C-1  honest extension: signed consistency proof verifies")

    # ---- C-2 ----
    rw = WitnessChain(sk)
    for i in range(12):
        rw.append("INFER", semantic_digest={"i": i if i != 2 else -1})
    forged = make_consistency(rw, sk, 5)      # rewritten prefix, honest count
    st, why = verify_consistency_envelope(forged, old_env=root5)
    assert st == "inconsistent", \
        f"C-2: a rewrite must contradict the pinned old root: {st} {why}"
    # and a doctored proof under a valid signature is rejected (not evidence)
    doctored = copy.deepcopy(cons)
    doctored["body"]["proof"] = forged["body"]["proof"]
    st, why = verify_consistency_envelope(doctored, old_env=root5)
    assert st == "rejected" and "signature" in why, \
        "C-2: an unsigned mutation carries no evidential weight"
    print("  [PASS] C-2  rewrite: signed false prefix claim -> inconsistent; "
          "unsigned mutation -> rejected")

    # ---- C-3 ----
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "replicas.jsonl")
        store = ReplicaStore(path)
        assert store.accept(root5)[0] == "stored"
        assert store.accept(root12)[0] == "stored"
        wanted = store.consistency_wanted(ch.node_id)
        assert wanted == {"old": 5, "new": 12}, f"C-3: {wanted}"
        st, why = store.record_consistency(cons)
        assert st == "consistent" and store.verified_prefix(ch.node_id) == 5
        assert store.consistency_wanted(ch.node_id) is None, \
            "C-3: the proven link must not be re-requested"
        # a signed FALSE claim leaves durable evidence
        st, why = store.record_consistency(forged)
        assert st == "inconsistent" and store.divergence(ch.node_id), \
            "C-3: inconsistency evidence must be durable"
        # reload restores both the verified prefix and the evidence
        store2 = ReplicaStore(path)
        assert store2.verified_prefix(ch.node_id) == 5
        assert store2.consistency_wanted(ch.node_id) is None
        assert store2.divergence(ch.node_id), "C-3: evidence survives reload"
    print("  [PASS] C-3  store: wanted-link protocol, verified_prefix, "
          "durable evidence, reload")


def _spawn_all(tmp):
    procs = []
    for port, name in ((PORT_A, "snd-A"), (PORT_B, "snd-B"),
                       (PORT_C, "snd-C")):
        peers = ",".join(BASE[p] for p in (PORT_A, PORT_B, PORT_C)
                         if p != port)
        procs.append(spawn(port, name, f"fp-{name}", [
            "--log", os.path.join(tmp, f"{name}.jsonl"),
            "--node-keystore", os.path.join(tmp, f"{name}.keystore"),
            "--peers", peers, "--quorum", "2"]))
    return procs


def test_replication_soundness_live():
    # env is process-global and other live suites pin their own
    # passphrase constants — set for our spawns, restore after.
    _prev_pass = os.environ.get("JJDAI_KEYSTORE_PASSPHRASE")
    os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = "snd-test-pass"
    with tempfile.TemporaryDirectory() as tmp:
        procs = _spawn_all(tmp)
        try:
            caps = {p: wait_up(BASE[p]) for p in BASE}
            nid = {p: get(BASE[p] + "/witness/root")[1]["body"]["node_id"]
                   for p in BASE}

            for i in range(4):
                code, _ = post(BASE[PORT_A] + "/v1/messages",
                               jii(caps[PORT_A], prompt=f"snd ping {i}"))
                assert code == 200

            # ---- L-1: first push — roots + segments propagate ----
            code, push1 = post(BASE[PORT_A] + "/replicate/push", {})
            assert code == 200 and push1["quorum_reached"] and push1["anchored"]
            for peer in (BASE[PORT_B], BASE[PORT_C]):
                assert push1["peers"][peer].get("segments_pushed", 0) >= 1, \
                    f"L-1: {peer} did not receive segments: {push1['peers'][peer]}"
            count1 = push1["count"]

            # more history, second push: receiver now wants the consistency
            # link old->new and the missing tail segments
            for i in range(3):
                post(BASE[PORT_A] + "/v1/messages",
                     jii(caps[PORT_A], prompt=f"snd more {i}"))
            code, push2 = post(BASE[PORT_A] + "/replicate/push", {})
            assert code == 200
            for peer in (BASE[PORT_B], BASE[PORT_C]):
                assert push2["peers"][peer].get("consistency") == "consistent", \
                    f"L-1: consistency link not verified at {peer}: " \
                    f"{push2['peers'][peer]}"
            st_b = get(BASE[PORT_B] + "/replicate/status")[1]
            assert st_b["verified_prefix"].get(nid[PORT_A]) == count1, \
                f"L-1: B's verified prefix must equal the first checkpoint " \
                f"({count1}): {st_b['verified_prefix']}"
            cov = st_b["segment_coverage"].get(nid[PORT_A])
            held_count = st_b["reconcile"]["peers"][nid[PORT_A]]["count"]
            assert cov and cov[0][0] == 0 and cov[0][1] >= held_count, \
                f"L-1: B's coverage of A must be complete: {cov}"
            print("  [PASS] L-1  push propagates root+consistency+segments; "
                  "receiver coverage complete; verified_prefix advances")

            # ---- L-2: recover A's history from B's copy ----
            # one sync push: the ANCHOR_QUORUM record appended after push2
            # is itself part of A's history and must reach B's segments.
            # The recursion guard guarantees this converges (a push whose
            # only new records are anchors is never re-anchored).
            code, push_sync = post(BASE[PORT_A] + "/replicate/push", {})
            assert code == 200 and not push_sync["anchored"], \
                f"L-2: anchor-only tail must not re-anchor: {push_sync}"
            root_a = get(BASE[PORT_A] + "/witness/root")[1]
            b_store = SegmentStore(os.path.join(tmp, "snd-B.jsonl.segments.jsonl"))
            rec = recover_records(b_store, nid[PORT_A], root_a)
            assert rec["ok"], f"L-2: recovery from B's store failed: {rec['reason']}"
            got_root = mth_root([r["this_hash"].encode()
                                 for r in rec["records"]])
            assert got_root == root_a["body"]["root"]
            print("  [PASS] L-2  origin history recovered from a PEER's "
                  "segment store against the anchored root")

            # ---- L-3: restart restoration ----
            st_a = get(BASE[PORT_A] + "/replicate/status")[1]
            receipts_before = st_a["receipts_held"]
            covered_before = st_a["anchor_covered"]
            assert receipts_before and covered_before > 0
            head_before = get(BASE[PORT_A] + "/witness/head")[1]
            procs[0].terminate()
            procs[0].wait(timeout=10)
            time.sleep(0.3)
            procs[0] = spawn(PORT_A, "snd-A", "fp-snd-A", [
                "--log", os.path.join(tmp, "snd-A.jsonl"),
                "--node-keystore", os.path.join(tmp, "snd-A.keystore"),
                "--peers", ",".join((BASE[PORT_B], BASE[PORT_C])),
                "--quorum", "2"])
            wait_up(BASE[PORT_A])
            st_a2 = get(BASE[PORT_A] + "/replicate/status")[1]
            assert st_a2["receipts_held"] == receipts_before, \
                f"L-3: receipts lost across restart: {st_a2['receipts_held']}"
            assert st_a2["anchor_covered"] == covered_before, \
                f"L-3: _anchor_covered lost across restart"
            head_after = get(BASE[PORT_A] + "/witness/head")[1]
            assert head_after["count"] == head_before["count"], \
                "L-3: restart must not grow the chain"
            # an idle re-push must NOT re-anchor covered history
            code, push3 = post(BASE[PORT_A] + "/replicate/push", {})
            assert code == 200 and not push3["anchored"], \
                f"L-3: covered history re-anchored after restart: {push3}"
            print("  [PASS] L-3  restart restores receipts + anchor coverage; "
                  "no re-anchor of covered history")
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


def test_signed_root_race():
    # T-1: hammer signed_root while a writer appends. Every envelope must be
    # internally consistent: `count` records reproduce `root`, and the
    # head_hash is the hash of record count-1. Before the lock fix the three
    # reads could interleave with an append.
    sys.path.insert(0, os.path.join(_ROOT, "node"))
    from daemon import Node, HashEngine
    node = Node(name="race", profile="B", substrates=["sha256:base-A"],
                adapters={}, engine=HashEngine("fp-race"))
    stop = threading.Event()
    bad = []

    def writer():
        i = 0
        while not stop.is_set():
            with node._lock:
                node.chain.append("INFER", semantic_digest={"i": i})
            i += 1

    def reader():
        while not stop.is_set():
            env = node.signed_root()
            b = env["body"]
            recs = node.chain.records[:b["count"]]
            if len(recs) != b["count"]:
                bad.append(("count", b)); continue
            root = mth_root([r["this_hash"].encode() for r in recs])
            head = recs[-1]["this_hash"] if recs else "0" * 64
            if root != b["root"] or head != b["head_hash"]:
                bad.append(("mismatch", b))

    threads = [threading.Thread(target=writer)] + \
              [threading.Thread(target=reader) for _ in range(3)]
    for t in threads:
        t.start()
    time.sleep(1.5)
    stop.set()
    for t in threads:
        t.join(timeout=10)
    assert not bad, f"T-1: {len(bad)} internally inconsistent root(s): {bad[:2]}"
    assert len(node.chain.records) > 10, "T-1: writer must have made progress"
    print(f"  [PASS] T-1  signed_root under {len(node.chain.records)} "
          "concurrent appends: every envelope internally consistent")


if __name__ == "__main__":
    test_segments_offline()
    test_consistency_offline()
    test_replication_soundness_live()
    test_signed_root_race()
    print("\nREPLICATION SOUNDNESS: all groups green  ✓ certified")
