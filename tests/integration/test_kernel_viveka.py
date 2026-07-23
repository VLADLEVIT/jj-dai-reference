#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Agent Kernel · Viveka acceptance tests.

  W-1   linear graph: state flows through nodes; terminal reached (complete)
  W-2   conditional branching routes by state
  W-3   every step is WITNESSED (DELIBERATION records); chain verifies;
        deliberation content is a hiding commitment (state not on chain)
  W-4   checkpoint after every step; state_hash deterministic; replay of the
        journal reproduces the current state (restart-safe)
  W-5   ROLLBACK restores an earlier checkpoint AND is itself witnessed
        (visible rewind — Invariant III: no secret rollback)
  W-6   counterfactual: rollback + patch resumes on a DIFFERENT branch
  W-7   governor gate: an EXECUTIVE node is BLOCKED when the Being is
        contained (status 'contained'), pure nodes still run — Viveka meets
        Article 25 (stop the hand, not the mind)
  W-8   released Being: the same executive graph now completes
  W-9   step budget: a looping graph halts cleanly at max_steps
  W-10  auditor: verify_deliberation_against_chain binds every step to its
        record; a tampered checkpoint state is caught
  W-11  Smriti integration: a discernment node reads ReadOnlyMemory and routes
        on it — will grounded in memory
  W-12  deterministic replay: re-running the same graph from the same input
        reproduces the identical final state_hash and checkpoint hashes

Run (from the build root):  python3 test_kernel_viveka.py
"""
from __future__ import annotations

import os
import sys
import tempfile


from jjdai.crypto import SigningKey                          # noqa: E402
from jjdai.witness import WitnessChain                       # noqa: E402
from core.containment import ContainmentLedger               # noqa: E402
from kernel.viveka import (Viveka, END, VivekaError,         # noqa: E402
                           verify_deliberation_against_chain)
from kernel.smriti import SmritiContinuity, AgentIdentity     # noqa: E402

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_kernel_viveka():

    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    class Clock:
        def __init__(self, t=1_750_000_000.0): self.t = t
        def __call__(self): return self.t
        def tick(self, s): self.t += s


    WORK = tempfile.mkdtemp(prefix="jjdai_viv_")
    BEING = "being:agent-viveka"


    def clk_new():
        return Clock()


    # ---- W-1 linear graph ------------------------------------------------------ #
    v = Viveka(BEING, now_fn=clk_new())
    v.add_node("perceive", lambda s: {"seen": s["input"] * 2})
    v.add_node("reflect", lambda s: {"score": s["seen"] + 1})
    v.add_edge("perceive", "reflect")
    v.add_edge("reflect", END)
    v.set_entry("perceive")
    r1 = v.run({"input": 10})
    check("W-1", r1["status"] == "complete" and r1["state"]["score"] == 21
          and r1["steps"] == 2, f"linear graph -> {r1['state']}")

    # ---- W-2 conditional branching --------------------------------------------- #
    v2 = Viveka(BEING, now_fn=clk_new())
    v2.add_node("classify", lambda s: {"kind": "big" if s["n"] > 100 else "small"})
    v2.add_node("big_path", lambda s: {"route": "BIG"})
    v2.add_node("small_path", lambda s: {"route": "SMALL"})
    v2.add_conditional("classify", lambda s: "big_path" if s["kind"] == "big"
                       else "small_path")
    v2.add_edge("big_path", END)
    v2.add_edge("small_path", END)
    v2.set_entry("classify")
    rb = v2.run({"n": 5})
    rB = Viveka.__init__ and v2  # noop
    v2b = Viveka(BEING, now_fn=clk_new())
    v2b.add_node("classify", lambda s: {"kind": "big" if s["n"] > 100 else "small"})
    v2b.add_node("big_path", lambda s: {"route": "BIG"})
    v2b.add_node("small_path", lambda s: {"route": "SMALL"})
    v2b.add_conditional("classify", lambda s: "big_path" if s["kind"] == "big"
                        else "small_path")
    v2b.add_edge("big_path", END); v2b.add_edge("small_path", END)
    v2b.set_entry("classify")
    rbig = v2b.run({"n": 500})
    check("W-2", rb["state"]["route"] == "SMALL" and rbig["state"]["route"] == "BIG",
          "conditional routes by state (small/big)")

    # ---- W-3 witnessed + hiding + verifies ------------------------------------- #
    sk = SigningKey(b"\x22" * 32)
    chain = WitnessChain(sk, log_path=os.path.join(WORK, "wit.jsonl"))
    v3 = Viveka(BEING, witness=chain, now_fn=clk_new())
    v3.add_node("think", lambda s: {"secret_plan": "attack-at-dawn", "ok": True})
    v3.add_edge("think", END); v3.set_entry("think")
    v3.run({"input": 1})
    delib = [r for r in chain.records if r["kind"] == "DELIBERATION"]
    hidden = "attack-at-dawn" not in chain.raw()
    check("W-3", len(delib) == 1 and chain.verify_chain() and hidden,
          f"{len(delib)} DELIBERATION record; chain verifies; state hidden")

    # ---- W-4 checkpoint + replay/restart --------------------------------------- #
    jp = os.path.join(WORK, "viv.jsonl")
    v4 = Viveka(BEING, journal_path=jp, now_fn=clk_new())
    v4.add_node("a", lambda s: {"x": 1})
    v4.add_node("b", lambda s: {"y": 2})
    v4.add_edge("a", "b"); v4.add_edge("b", END); v4.set_entry("a")
    v4.run({"start": True})
    h4 = v4.state_hash()
    reload4 = Viveka(BEING, journal_path=jp, now_fn=clk_new())
    check("W-4", reload4.state_hash() == h4 and len(reload4.checkpoints) == 2,
          "checkpoints replay from journal; restart reproduces state")

    # ---- W-5 witnessed rollback ------------------------------------------------ #
    chain5 = WitnessChain(SigningKey(b"\x33" * 32))
    v5 = Viveka(BEING, witness=chain5, now_fn=clk_new())
    v5.add_node("s1", lambda s: {"v": 1})
    v5.add_node("s2", lambda s: {"v": 2})
    v5.add_node("s3", lambda s: {"v": 3})
    v5.add_edge("s1", "s2"); v5.add_edge("s2", "s3"); v5.add_edge("s3", END)
    v5.set_entry("s1")
    v5.run({"v": 0})
    before = v5.state_hash()
    rb5 = v5.rollback_to(1)                       # back to state after s1 (v=1)
    rollback_recs = [r for r in chain5.records
                     if r["kind"] == "DELIBERATION"
                     and ":1:s1:" in r["semantic_digest"]]
    check("W-5", v5._state["v"] == 1 and rb5["resume_node"] == "s2"
          and len(chain5.records) == 4,          # 3 steps + 1 rollback, witnessed
          "rollback restores checkpoint AND is witnessed (visible rewind)")

    # ---- W-6 counterfactual branch --------------------------------------------- #
    v6 = Viveka(BEING, now_fn=clk_new())
    v6.add_node("root", lambda s: {"ready": True})
    v6.add_node("branch", lambda s: {"took": s.get("mode", "default")})
    v6.add_conditional("root", lambda s: "branch")
    v6.add_edge("branch", END); v6.set_entry("root")
    v6.run({"mode": "A"})
    first = v6._state.get("took")
    v6.rollback_to(1, patch={"mode": "B"})        # rewind + patch
    v6.resume()
    check("W-6", first == "A" and v6._state["took"] == "B",
          f"rollback+patch resumes different branch: {first} -> B")

    # ---- W-7 governor gate on executive node ----------------------------------- #
    chain7 = WitnessChain(SigningKey(b"\x44" * 32))
    gov = ContainmentLedger("node:gov", witness=chain7,
                            evidence_resolver=lambda refs: True, now_fn=clk_new())
    gov.contain(BEING, evidence_refs=["e"], reason="test", topic="cyber",
                initiator="node:gov")
    v7 = Viveka(BEING, governor=gov, now_fn=clk_new())
    v7.add_node("plan", lambda s: {"planned": True})                 # pure
    v7.add_node("act", lambda s: {"acted": True}, executive=True)    # executive
    v7.add_edge("plan", "act"); v7.add_edge("act", END); v7.set_entry("plan")
    r7 = v7.run({})
    check("W-7", r7["status"] == "contained" and r7["state"].get("planned") is True
          and "acted" not in r7["state"],
          "executive step blocked while contained; pure step ran (mind free)")

    # ---- W-8 released -> executive graph completes ----------------------------- #
    gov._emit({"ev": "release", "t": 0, "being_id": BEING,
               "grounds": "test", "slash_target": None})
    v8 = Viveka(BEING, governor=gov, now_fn=clk_new())
    v8.add_node("plan", lambda s: {"planned": True})
    v8.add_node("act", lambda s: {"acted": True}, executive=True)
    v8.add_edge("plan", "act"); v8.add_edge("act", END); v8.set_entry("plan")
    r8 = v8.run({})
    check("W-8", r8["status"] == "complete" and r8["state"].get("acted") is True,
          "released Being: executive graph completes")

    # ---- W-9 step budget ------------------------------------------------------- #
    v9 = Viveka(BEING, now_fn=clk_new(), max_steps=5)
    v9.add_node("loop", lambda s: {"i": s.get("i", 0) + 1})
    v9.add_conditional("loop", lambda s: END if s["i"] >= 999 else "loop")
    v9.set_entry("loop")
    r9 = v9.run({"i": 0})
    check("W-9", r9["status"] == "budget" and r9["steps"] == 5,
          "looping graph halts cleanly at max_steps (bounded will)")

    # ---- W-10 auditor + tamper ------------------------------------------------- #
    bound = verify_deliberation_against_chain(v3.events, chain.records, BEING)
    tampered_events = [dict(e) for e in v3.events]
    for e in tampered_events:
        if e["ev"] == "step":
            e["state"] = dict(e["state"]); e["state"]["ok"] = False
    caught = False
    try:
        verify_deliberation_against_chain(tampered_events, chain.records, BEING)
    except VivekaError:
        caught = True
    check("W-10", bound == 1 and caught,
          "auditor binds steps to records; tampered checkpoint caught")

    # ---- W-11 Smriti-grounded discernment -------------------------------------- #
    smr = SmritiContinuity(AgentIdentity(BEING, 0.0), now_fn=clk_new())
    smr.core_set("directive", "prefer verified evidence")
    ro = smr.readonly()
    v11 = Viveka(BEING, now_fn=clk_new())
    v11.add_node("consult", lambda s: {"has_directive":
                 "verified evidence" in ro.core_blocks().get("directive", "")})
    v11.add_node("cautious", lambda s: {"stance": "evidence-first"})
    v11.add_node("bold", lambda s: {"stance": "guess"})
    v11.add_conditional("consult", lambda s: "cautious" if s["has_directive"]
                        else "bold")
    v11.add_edge("cautious", END); v11.add_edge("bold", END)
    v11.set_entry("consult")
    r11 = v11.run({})
    check("W-11", r11["state"]["stance"] == "evidence-first",
          "discernment routed on Smriti core memory (will grounded in memory)")

    # ---- W-12 deterministic replay --------------------------------------------- #
    def build():
        vv = Viveka(BEING, now_fn=clk_new())
        vv.add_node("p", lambda s: {"a": s["seed"] * 3})
        vv.add_node("q", lambda s: {"b": s["a"] - 7})
        vv.add_edge("p", "q"); vv.add_edge("q", END); vv.set_entry("p")
        return vv


    a = build(); a.run({"seed": 9})
    b = build(); b.run({"seed": 9})
    same_final = a.state_hash() == b.state_hash()
    same_cps = [c.state_hash for c in a.checkpoints] == \
               [c.state_hash for c in b.checkpoints]
    check("W-12", same_final and same_cps,
          "deterministic replay: identical final + checkpoint hashes")

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nKERNEL · VIVEKA: {len(results) - failed}/{len(results)} green"
          + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_kernel_viveka()
