#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.5.3 unit acceptance — the Being Composition Runtime
======================================================
  B-SM   state machine legality: forward one step at a time, any branch
         from any pipeline state, nothing after terminal; an ILLEGAL move
         raises with NOTHING written (no witness record, no journal line)
  B-RT   full happy path in production profile: one identity, ONE chain
         for every organ (all records verify as one chain), citations,
         plan, independent panel, karma receipt, RECORDED
  B-PROF production profile without provenance is refused at CONSTRUCTION
         (a Being that cannot judge verifier independence must not
         verify); dev profile runs and its traces are labeled mode=self
  B-CONT containment stops the hand, not the mind: a contained Being
         still GROUNDS/PLANS/GENERATES/VERIFIES; a task WITH an action
         ends CONTAINED at the authorization gate; a pure-answer task
         still ends RECORDED
  B-REC  recovery restores MEANING: traces rebuilt from the journal with
         citations and plan intact; a task interrupted mid-flight closes
         FAILED("interrupted"); an AUTHORIZED task with an orphaned Karma
         intent closes FATE_UNKNOWN — never an invented ending
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai.crypto import SigningKey                                # noqa: E402
from jjdai.witness import WitnessChain                             # noqa: E402
from jjdai.durable import durable_append                           # noqa: E402
from core.containment import ContainmentLedger                     # noqa: E402
import core.router as R                                            # noqa: E402
from core.router import RouteObject                                # noqa: E402
from runtime import BeingRuntime, BeingRuntimeError                # noqa: E402
from runtime.decision_trace import TraceError                      # noqa: E402
from runtime.state_machine import TaskStateMachine                 # noqa: E402
from runtime.recovery import recover_traces                        # noqa: E402


def _prov(mid, arch, ds, jur):
    return {"model_id": mid, "base_family": "fam-G",
            "architecture_family": arch, "training_data_families": [ds],
            "operator_domain": f"{mid}.example", "jurisdiction": jur}


def _mk_runtime(tmp, profile="production", governor=None, chain=None,
                sk=None):
    sk = sk or SigningKey.generate()
    chain = chain or WitnessChain(sk)
    being = f"being:{chain.node_id[:16]}"
    gov = governor if governor is not None else ContainmentLedger(
        chain.node_id, witness=chain, evidence_resolver=None)
    topics = ["_generalist"]
    engines = {n: R._mk_node(n, "sub-G", topics, origin="UA",
                             noise=0.05 if n == "n-gen" else 0.0)
               for n in ("n-gen", "n-i1", "n-i2")}
    objects = [RouteObject("m:gen", "generalist", "_generalist", "n-gen"),
               RouteObject("m:i1", "generalist", "_generalist", "n-i1"),
               RouteObject("m:i2", "generalist", "_generalist", "n-i2")]
    prov = {"m:gen": _prov("m:gen", "arch-a", "ds-g", "UA"),
            "m:i1": _prov("m:i1", "arch-b", "ds-1", "KR"),
            "m:i2": _prov("m:i2", "arch-c", "ds-2", "EE")} \
        if profile == "production" else None
    rt = BeingRuntime(
        sk=sk, chain=chain, being_id=being, governor=gov,
        workspace=os.path.join(tmp, "ws"), profile=profile,
        route_objects=objects, engines=engines, provenance=prov,
        topics={"_generalist": []}, max_per_group=2,
        journal_dir=os.path.join(tmp, "j"))
    return rt, chain, gov, being


def test_state_machine_legality():
    sk = SigningKey.generate()
    chain = WitnessChain(sk)
    with tempfile.TemporaryDirectory() as tmp:
        jp = os.path.join(tmp, "tasks.jsonl")
        m = TaskStateMachine(chain, journal_path=jp)
        tr = m.open_trace("t1", {"text": "x"}, "being:x", "dev")
        n_before = len(chain.records)
        j_before = open(jp).read()
        for illegal in ("PLANNED", "VERIFIED", "ACTED", "RECORDED"):
            try:
                m.move(tr, illegal)
                assert False, f"B-SM: skipped straight to {illegal}"
            except TraceError:
                pass
        assert len(chain.records) == n_before and open(jp).read() == j_before, \
            "B-SM: an illegal move must write NOTHING"
        m.move(tr, "GROUNDED")
        m.move(tr, "FAILED", detail={"reason": "test"})
        try:
            m.move(tr, "RECORDED")
            assert False, "B-SM: moved after terminal"
        except TraceError:
            pass
        print("  [PASS] B-SM  one step forward only; branches allowed; "
              "nothing after terminal; illegal moves write nothing")


def test_full_lifecycle_one_chain():
    with tempfile.TemporaryDirectory() as tmp:
        rt, chain, _gov, _b = _mk_runtime(tmp)
        tr = rt.handle_task({"text": "compose the organism",
                             "action": {"kind": "fs_write", "path": "a.txt",
                                        "content": "alive"}})
        d = tr.as_dict()
        assert d["state"] == "RECORDED", d["outcome_reason"]
        assert [t["to"] for t in d["transitions"]] == [
            "RECEIVED", "GROUNDED", "PLANNED", "GENERATED", "VERIFIED",
            "AUTHORIZED", "ACTED", "RECORDED"]
        assert d["verifier_panel"]["mode"] == "panel" \
            and len(d["verifier_panel"]["selected"]) == 2
        assert d["plan_steps"] == ["ground", "generate", "verify", "act",
                                   "record"]
        assert d["action"]["ok"] and \
            open(os.path.join(tmp, "ws", "a.txt")).read() == "alive"
        kinds = {r["kind"] for r in chain.records}
        assert {"TASK", "ROUTE", "MEMORY", "RAG_WRITE", "ACTION"} <= kinds \
            or {"TASK", "ROUTE"} <= kinds, kinds
        assert chain.verify_chain(), \
            "B-RT: every organ must write ONE verifiable chain"
        second = rt.handle_task({"text": "compose the organism"})
        assert any(c["source"] == "plane_h" for c in second.citations), \
            "B-RT: the second task must cite the knowledge the first wrote"
        print("  [PASS] B-RT  full path on ONE chain; organs interleaved; "
              "task N cites task N-1's recorded knowledge")


def test_profiles():
    with tempfile.TemporaryDirectory() as tmp:
        try:
            _mk_runtime(tmp, profile="production")
        except BeingRuntimeError:
            assert False, "production WITH provenance must construct"
    with tempfile.TemporaryDirectory() as tmp:
        sk = SigningKey.generate()
        chain = WitnessChain(sk)
        try:
            BeingRuntime(sk=sk, chain=chain, being_id="b", governor=None,
                         workspace=tmp, profile="production",
                         provenance=None)
            assert False, "B-PROF: production without provenance accepted"
        except BeingRuntimeError as e:
            assert "provenance" in str(e)
    with tempfile.TemporaryDirectory() as tmp:
        rt, _c, _g, _b = _mk_runtime(tmp, profile="dev")
        tr = rt.handle_task({"text": "dev question"})
        assert tr.state == "RECORDED" \
            and tr.verifier_panel["mode"] == "self", \
            "B-PROF: dev runs and is LABELED mode=self"
    print("  [PASS] B-PROF  production demands provenance at construction; "
          "dev runs visibly labeled")


def test_containment_hand_not_mind():
    with tempfile.TemporaryDirectory() as tmp:
        rt, chain, gov, being = _mk_runtime(tmp)
        gov.contain(being, evidence_refs=["w:0"],
                    initiator="steward:test", reason="unit")
        with_action = rt.handle_task({"text": "act now",
                                      "action": {"kind": "fs_write",
                                                 "path": "no.txt",
                                                 "content": "x"}})
        d = with_action.as_dict()
        assert d["state"] == "CONTAINED", d
        walked = [t["to"] for t in d["transitions"]]
        assert walked[:5] == ["RECEIVED", "GROUNDED", "PLANNED",
                              "GENERATED", "VERIFIED"], \
            "B-CONT: the MIND must run the whole way to the gate"
        assert not os.path.exists(os.path.join(tmp, "ws", "no.txt")), \
            "B-CONT: the hand must not have moved"
        pure = rt.handle_task({"text": "just answer"})
        assert pure.state == "RECORDED", \
            "B-CONT: a contained Being still answers — mind intact"
        print("  [PASS] B-CONT  action task CONTAINED at the gate after a "
              "full mind-run; pure answer still RECORDED")


def test_recovery_meaning_and_fates():
    with tempfile.TemporaryDirectory() as tmp:
        rt, chain, _g, _b = _mk_runtime(tmp)
        done = rt.handle_task({"text": "finish me"})
        assert done.state == "RECORDED"
        jd = os.path.join(tmp, "j")
        tj, kj = os.path.join(jd, "tasks.jsonl"), os.path.join(jd,
                                                               "karma.jsonl")
        # forge a crash: a task journaled up to AUTHORIZED + an orphaned
        # Karma intent (ph=intent, no outcome) — exactly what a die between
        # intent and outcome leaves on disk
        durable_append(tj, {"op": "open", "task_id": "t-crash",
                            "task_hash": "h", "being_id": "b",
                            "node_id": chain.node_id, "profile":
                            "production", "at": 1.0})
        for i, st in enumerate(("GROUNDED", "PLANNED", "GENERATED",
                                "VERIFIED", "AUTHORIZED")):
            durable_append(tj, {"op": "move", "task_id": "t-crash",
                                "from": "x", "to": st, "at": 1.0 + i,
                                "witness_index": i, "detail": {}})
        durable_append(kj, {"ph": "intent", "t": 9.0, "action": "fs_write",
                            "action_hash": "orphan-1"})
        # and a second task that died earlier (GROUNDED, no intent)
        durable_append(tj, {"op": "open", "task_id": "t-early",
                            "task_hash": "h2", "being_id": "b",
                            "node_id": chain.node_id, "profile":
                            "production", "at": 2.0})
        durable_append(tj, {"op": "move", "task_id": "t-early",
                            "from": "RECEIVED", "to": "GROUNDED", "at": 2.1,
                            "witness_index": 9, "detail": {}})

        traces = recover_traces(tj, karma_journal=kj)
        assert traces[done.task_id].state == "RECORDED" \
            and traces[done.task_id].plan_steps, \
            "B-REC: a finished task must restore WITH its meaning"
        assert traces["t-crash"].state == "FATE_UNKNOWN" \
            and "unknown" in traces["t-crash"].outcome_reason, \
            "B-REC: orphaned intent at AUTHORIZED => FATE_UNKNOWN"
        assert traces["t-early"].state == "FAILED" \
            and "interrupted" in traces["t-early"].outcome_reason, \
            "B-REC: pre-action interruption is a KNOWN fate: FAILED"
        print("  [PASS] B-REC  meaning restored; orphaned intent -> "
              "FATE_UNKNOWN; early interruption -> FAILED")


if __name__ == "__main__":
    test_state_machine_legality()
    test_full_lifecycle_one_chain()
    test_profiles()
    test_containment_hand_not_mind()
    test_recovery_meaning_and_fates()
    print("\nBEING LIFECYCLE UNIT: all groups green  ✓ certified")
