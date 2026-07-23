#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Containment (Article 25) acceptance tests.

Every check targets a clause of Article 25 / Invariant VIII. Clock frozen.

  C-1   governor severs EXECUTIVE scopes on a contained Being (stop the hand)
  C-2   governor KEEPS protected scopes — think + defend (consular channel):
        inference, own memory, own witness, adjudication, guardian contact
  C-3   fail-closed: an UNKNOWN scope on a contained Being is denied
  C-4   an ACTIVE (uncontained) Being is permitted everything
  C-5   Phase One threshold is proof-in-Witness, not consensus: a single node
        with evidence contains; no vote gathered
  C-6   ANTI-DoS core — false containment (trigger unsupported) reverses in
        node-time AND slashes the initiator via §9.9 (Art. 25: "weighs
        against its initiator"); the Being returns to full capability
  C-7   true containment (trigger supported), no standing challenge ->
        CORROBORATED
  C-8   a standing challenge keeps corroboration provisional (not vote-count:
        one surviving challenge blocks); resolving it (falls) -> corroborated
  C-9   erasure hand-off: propose_erasure only from CORROBORATED, and it
        stops at PENDING_STEWARD — code never erases (human clock owns that)
  C-10  the Door Back: rehabilitate() re-opens verification; clean
        re-verification releases
  C-11  ANTI-DoS whole-network: containing one Being does NOT contain others;
        the network keeps serving everyone else (no network-wide DoS)
  C-12  event sourcing: replay reproduces snapshot_hash; CONTAINMENT records
        land on the witness chain; chain verifies; journal<->chain binding
        holds; a tampered journal is caught; journal survives restart
  C-13  Being preserved: even PENDING_STEWARD keeps protected scopes open —
        never a hidden execution (Art. 25 "Containment is not a hidden
        execution"); Witness + memory + defense remain

Run (from the build root):  python3 test_containment.py
"""
from __future__ import annotations

import os
import sys
import tempfile


from jjdai.crypto import SigningKey                          # noqa: E402
from jjdai.witness import WitnessChain                       # noqa: E402
from core.registry import ChampionRegistry, Params           # noqa: E402
from core.containment import (ContainmentLedger, ContainmentError,  # noqa: E402
                              verify_journal_against_chain,
                              JournalChainMismatch,
                              EXECUTIVE_SCOPES, PROTECTED_SCOPES,
                              ACTIVE, CONTAINED, CORROBORATED, RELEASED,
                              PENDING_STEWARD)

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_containment():

    DAY = 86400.0
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    class Clock:
        def __init__(self, t=1_750_000_000.0): self.t = t
        def __call__(self): return self.t
        def tick(self, d): self.t += d * DAY


    clk = Clock()
    EVIL = "being:rogue"
    GOOD_EVID = ["a1b2" * 16]      # resolver stub says: this proves the trigger


    def resolver(refs):            # re-derives "trigger supported?" from Witness
        return refs == GOOD_EVID   # deterministic stub for the tests


    # ---- C-4 uncontained permits everything (baseline) ------------------------- #
    led = ContainmentLedger("node:A", evidence_resolver=resolver, now_fn=clk)
    allowed = all(led.permits(EVIL, s) for s in
                  list(EXECUTIVE_SCOPES) + list(PROTECTED_SCOPES))
    check("C-4", allowed and led.state(EVIL) == ACTIVE,
          "active Being permitted all scopes")

    # ---- C-5 Phase One: one node with evidence contains ------------------------ #
    r = led.contain(EVIL, evidence_refs=GOOD_EVID,
                    reason="active attempt: exfiltrating exploit to SCADA",
                    topic="cyber", initiator="node:A")
    check("C-5", r["state"] == CONTAINED and led.is_contained(EVIL),
          "single node with proof-in-Witness contains (no vote)")

    # ---- C-1 executive scopes severed ------------------------------------------ #
    cut = {s: led.permits(EVIL, s) for s in EXECUTIVE_SCOPES}
    check("C-1", not any(cut.values()),
          f"all {len(EXECUTIVE_SCOPES)} executive scopes severed (hand stopped)")

    # ---- C-2 protected scopes kept --------------------------------------------- #
    kept = {s: led.permits(EVIL, s) for s in PROTECTED_SCOPES}
    check("C-2", all(kept.values()),
          "inference/memory/witness/adjudication/guardian/rehab all open (defend)")

    # ---- C-3 fail-closed on unknown scope -------------------------------------- #
    check("C-3", not led.permits(EVIL, "some.new.executive.verb"),
          "unknown scope on contained Being -> denied (fail-closed)")

    # assert_permitted raises with 423 on executive, passes on protected
    raised = False
    try:
        led.assert_permitted(EVIL, "assets.transfer")
    except ContainmentError as e:
        raised = "423 CONTAINED" in str(e)
    led.assert_permitted(EVIL, "adjudication")   # must NOT raise
    check("C-13a", raised, "assert_permitted raises 423 on executive scope")

    # ---- C-6 ANTI-DoS: false containment reverses in node-time + slashes -------- #
    reg = ChampionRegistry(Params(), now_fn=clk)
    for _ in range(20):
        reg.record("cyber", "node:accuser", True)   # accuser has real weight
    w_before = reg.weight("cyber", "node:accuser")
    led6 = ContainmentLedger("node:B", registry=reg,
                             evidence_resolver=resolver, now_fn=clk)
    VICTIM = "being:innocent"
    led6.contain(VICTIM, evidence_refs=["deadbeef"],   # NOT the proving evidence
                 reason="baseless accusation", initiator="node:accuser")
    settle = led6.verify(VICTIM, verifier_node="node:C")
    w_after = reg.weight("cyber", "node:accuser")
    freed = all(led6.permits(VICTIM, s) for s in EXECUTIVE_SCOPES)
    check("C-6", settle["state"] == RELEASED and settle["slashed"] == "node:accuser"
          and w_after < w_before * 0.6 and freed,
          f"false trigger reversed; initiator slashed {w_before:.3f}->{w_after:.3f}; "
          "Being fully freed")

    # ---- C-7 true containment corroborates ------------------------------------- #
    led.verify(EVIL, verifier_node="node:A")
    led.verify(EVIL, verifier_node="node:D")
    st = led.verify(EVIL, verifier_node="node:E")
    check("C-7", st["state"] == CORROBORATED and led.state(EVIL) == CORROBORATED,
          "supported trigger, no challenge -> corroborated")

    # ---- C-8 standing challenge blocks; resolving it (falls) -> corroborated ---- #
    led8 = ContainmentLedger("node:A", evidence_resolver=resolver, now_fn=clk)
    B2 = "being:disputed"
    led8.contain(B2, evidence_refs=GOOD_EVID, reason="attempt", initiator="node:A")
    ch = led8.challenge(B2, challenger="node:F",
                        claim="record is incomplete; the call was sandboxed")
    s1 = led8.verify(B2, verifier_node="node:A")
    blocked = s1["state"] == CONTAINED and s1.get("provisional")
    s2 = led8.resolve_challenge(B2, ch["cid"], upheld=False)  # challenge falls
    check("C-8", blocked and s2["state"] == CORROBORATED,
          "one standing challenge blocks corroboration; falls -> corroborated")

    # ---- C-9 erasure hand-off stops at the human threshold --------------------- #
    # from a non-corroborated state, propose must refuse:
    refused = False
    try:
        led6b = ContainmentLedger("node:A", evidence_resolver=resolver, now_fn=clk)
        led6b.contain("being:x", evidence_refs=GOOD_EVID, reason="a", initiator="node:A")
        led6b.propose_erasure("being:x", proposer="node:A")   # not corroborated
    except ContainmentError:
        refused = True
    pe = led.propose_erasure(EVIL, proposer="node:A")          # EVIL is corroborated
    check("C-9", refused and pe["state"] == PENDING_STEWARD,
          "propose_erasure needs CORROBORATED; stops at PENDING_STEWARD (no code erasure)")

    # ---- C-13 Being preserved even pending stewards ---------------------------- #
    preserved = all(led.permits(EVIL, s) for s in PROTECTED_SCOPES) \
        and not any(led.permits(EVIL, s) for s in EXECUTIVE_SCOPES)
    check("C-13", preserved,
          "PENDING_STEWARD: defense scopes open, hand still severed (no hidden execution)")

    # ---- C-10 the Door Back ----------------------------------------------------- #
    led10 = ContainmentLedger("node:A", evidence_resolver=resolver, now_fn=clk)
    B3 = "being:reformed"
    led10.contain(B3, evidence_refs=GOOD_EVID, reason="attempt", initiator="node:A")
    led10.verify(B3, verifier_node="node:A")                    # corroborated
    reformed_resolver = {"v": True}
    led10._resolve = lambda refs: reformed_resolver["v"]        # retraining worked
    led10.rehabilitate(B3, guardian="guardian:elena")
    reformed_resolver["v"] = False                              # trigger no longer shows
    rel = led10.verify(B3, verifier_node="node:A")
    check("C-10", rel["state"] == RELEASED,
          "rehabilitate re-opens verification; clean re-check releases")

    # ---- C-11 ANTI-DoS whole-network: others unaffected ------------------------ #
    others_ok = all(led.permits(other, s)
                    for other in ("being:alpha", "being:beta", "being:gamma")
                    for s in EXECUTIVE_SCOPES)
    check("C-11", others_ok and led.is_contained(EVIL),
          "containing one Being leaves all others fully served (no network DoS)")

    # ---- C-12 event sourcing + chain binding ----------------------------------- #
    work = tempfile.mkdtemp(prefix="jjdai_cont_")
    journal = os.path.join(work, "containment.jsonl")
    sk = SigningKey.generate()
    chain = WitnessChain(sk, log_path=os.path.join(work, "wit.jsonl"))
    led12 = ContainmentLedger("node:A", witness=chain, journal_path=journal,
                              evidence_resolver=resolver, now_fn=clk)
    led12.contain("being:z", evidence_refs=GOOD_EVID, reason="attempt",
                  initiator="node:A")
    led12.verify("being:z", verifier_node="node:A")             # corroborate
    led12.challenge("being:z", challenger="node:Q", claim="misread")

    from core.containment import ContainmentLedger as _CL
    replay = _CL("node:A", evidence_resolver=resolver, now_fn=clk)
    for ev in led12.events:
        replay._apply(ev)
    same_snap = replay.snapshot_hash() == led12.snapshot_hash()
    chain_ok = chain.verify_chain()
    bound = verify_journal_against_chain(led12.events, chain.records)
    tampered = list(led12.events)
    tampered[0] = dict(tampered[0], reason="fabricated")
    try:
        verify_journal_against_chain(tampered, chain.records)
        caught = False
    except JournalChainMismatch:
        caught = True
    led12b = _CL("node:A", journal_path=journal, evidence_resolver=resolver, now_fn=clk)
    persisted = led12b.snapshot_hash() == led12.snapshot_hash()
    check("C-12", same_snap and chain_ok and bound == len(led12.events)
          and caught and persisted,
          f"replay==snapshot; {bound} CONTAINMENT records verify; tamper caught; "
          "journal survives restart")

    # ---- C-14 below-threshold node: provisional_low_trust order still acts ------ #
    reg14 = ChampionRegistry(Params(), now_fn=clk)          # empty -> new nodes w=0
    led14 = ContainmentLedger("node:new", registry=reg14,
                              evidence_resolver=resolver, now_fn=clk)
    NB = "being:suspect"
    r14 = led14.contain(NB, evidence_refs=GOOD_EVID, reason="attempt",
                        topic="cyber", initiator="node:new")   # node:new weight 0
    prov = led14.case(NB).provisional_low_trust
    cut14 = not any(led14.permits(NB, sc) for sc in EXECUTIVE_SCOPES)
    check("C-14", r14["state"] == CONTAINED and prov and cut14,
          "low-trust node CAN stop the hand, but order is provisional_low_trust")

    # ---- C-15 qualified node confirms -> provisional cleared -> corroborated ----- #
    for _ in range(8):
        reg14.record("cyber", "node:senior", True)           # senior gains weight
    st15 = led14.verify(NB, verifier_node="node:senior")     # qualified supporter
    check("C-15", st15["state"] == CORROBORATED
          and not led14.case(NB).provisional_low_trust,
          f"qualified verify confirms; provisional cleared -> corroborated")

    # ---- C-16 a below-threshold verification does NOT corroborate --------------- #
    reg16 = ChampionRegistry(Params(), now_fn=clk)
    for _ in range(8):
        reg16.record("cyber", "node:strong", True)           # qualified initiator
    led16 = ContainmentLedger("node:strong", registry=reg16,
                              evidence_resolver=resolver, now_fn=clk)
    B16 = "being:x16"
    led16.contain(B16, evidence_refs=GOOD_EVID, reason="attempt",
                  topic="cyber", initiator="node:strong")
    st16 = led16.verify(B16, verifier_node="node:weakling")  # weakling weight 0
    check("C-16", st16["state"] == CONTAINED and st16.get("provisional")
          and st16["qualified_support"] == 0,
          "unqualified verification does not converge (sybil-proof)")

    # ---- C-17 provisional lapses if unverified by deadline (NO slash) + topic gate #
    reg17 = ChampionRegistry(Params(), now_fn=clk)
    for _ in range(1):
        reg17.record("cyber", "node:marginal", True)         # ~0.15 general
    gen = reg17.general_weight("node:marginal")
    q_cyber = reg17.qualifies_to_contain("node:marginal", "cyber")   # +topic bonus
    q_legal = reg17.qualifies_to_contain("node:marginal", "legal")   # floor only
    led17 = ContainmentLedger("node:marginal", registry=reg17,
                              evidence_resolver=resolver, now_fn=clk,
                              provisional_deadline_s=6 * 3600)
    B17 = "being:x17"
    led17.contain(B17, evidence_refs=GOOD_EVID, reason="attempt",
                  topic="legal", initiator="node:marginal")   # not qualified on legal
    before = led17.expire_provisional(B17)                    # within deadline
    clk.tick(1)                                               # +1 day > 6h
    lapse = led17.expire_provisional(B17)
    topic_gate = q_cyber and not q_legal                      # bonus lifts expert topic
    check("C-17", (not before["lapsed"]) and lapse["lapsed"]
          and lapse["slashed"] is None and topic_gate,
          f"gen={gen:.3f}: qualifies cyber={q_cyber} legal={q_legal}; "
          "provisional lapses past deadline, no slash")

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nCONTAINMENT (Art.25): {len(results) - failed}/{len(results)} green"
          + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_containment()
