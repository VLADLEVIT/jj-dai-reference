#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The four false greens of the first recut (v0.6.7 recut)
=======================================================
Every check here corrupts or configures something REAL and asserts the node
says so. The first recut's readiness checks all fed hand-built snapshot dicts
to the rule engine — which proved the rules and nothing about whether the
daemon could gather the facts. It could not: it probed for a verifier under
two names the chain does not have, and gave up on the engine at the first
`NotSupported`.

  WIT-VERIFY-1  a corrupted REAL chain makes witness readiness NOT_READY
  WIT-VERIFY-2  the probe uses verify_chain(), the method that exists
  ENG-READY-1   NotSupported falls through to the legacy healthy() probe
  ENG-READY-2   a backend that is genuinely down is still not ready
  ANCH-LOCK-1   two concurrent rounds produce ONE ANCHOR_EXTERNAL
  ANCH-POLICY-1 local-only reports external anchoring NOT_CONFIGURED
  ANCH-POLICY-2 a working OTS calendar in custody is not NOT_READY forever
  BADGE-1       the badge comes from a recorded run, not a count
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time

_ROOT = os.path.abspath(os.path.join(_d := os.path.dirname(__file__), "..",
                                     ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import readiness as R                                        # noqa: E402
from core.anchoring import AnchorLog, AnchorScheduler         # noqa: E402
from jjdai.adapters.errors import NotSupported                # noqa: E402
from jjdai.crypto import SigningKey                           # noqa: E402
from jjdai.witness import WitnessChain                        # noqa: E402


class _Backend:
    def __init__(self, name, status="recorded", delay=0.0):
        self.name, self.status, self.delay = name, status, delay
        self.calls = 0

    def submit(self, node_id, root, count):
        self.calls += 1
        time.sleep(self.delay)
        return {"backend": self.name, "node": node_id, "root": root,
                "count": count, "status": self.status, "ts": time.time()}


class _Chain:
    node_id = "node:recut2"

    def __init__(self, n=3):
        self.records = [{"kind": "INFER", "this_hash": f"{i:064x}"}
                        for i in range(n)]
        self.appends = 0
        self.lock = threading.RLock()

    def append(self, kind, **kw):
        with self.lock:
            self.appends += 1
            self.records.append({"kind": "ANCHOR_EXTERNAL",
                                 "this_hash": f"{len(self.records):064x}"})


def _log():
    return AnchorLog(os.path.join(tempfile.mkdtemp(), "a.jsonl"))


class _Node:
    """The two probe methods, lifted onto a stub carrying REAL objects."""
    from node.daemon import Node as _real            # noqa: E402
    _chain_verdict = _real._chain_verdict
    _engine_readiness = _real._engine_readiness

    def __init__(self, chain=None, engine=None):
        self.chain = chain
        self.engine = engine
        self._chain_checked_at = 0.0
        self._chain_verdict_cached = ""
        self.chain_check_interval_s = 0.0        # never serve a stale verdict


def test_recut2_false_greens():
    passed = 0

    # ---- WIT-VERIFY-1 / 2 : a REAL chain, really corrupted ----
    sk = SigningKey.generate()
    ch = WitnessChain(sk)
    for i in range(3):
        ch.append("INFER", semantic_digest={"i": i})
    node = _Node(chain=ch)
    assert ch.verify_chain() is True
    assert node._chain_verdict() == "", "a sound chain must read clean"
    ch.records[1]["this_hash"] = "ff" * 32          # tamper
    assert ch.verify_chain() is False, "fixture failed to corrupt the chain"
    verdict = node._chain_verdict()
    assert verdict, ("a corrupted chain still read clean — the probe is not "
                     "calling the real verifier")
    rep = R.evaluate({"identity_loaded": True, "chain_loaded": True,
                      "chain_broken": verdict, "anchoring_configured": False,
                      "engine_configured": False, "isolation_declared": [],
                      "being_configured": False})
    assert rep["subsystems"]["witness"]["state"] == R.NOT_READY
    assert rep["ready"] is False
    print("  [PASS] WIT-VERIFY-1 a corrupted real chain unreadies the node")
    passed += 1

    assert not hasattr(ch, "verify_head"), (
        "if this ever exists, revisit the probe")
    assert callable(getattr(ch, "verify_chain", None))
    print("  [PASS] WIT-VERIFY-2 the probe names the method that exists")
    passed += 1

    # ---- ENG-READY-1 : NotSupported must not end the search ----
    class _Legacy:
        backend = "dwarfstar"

        def readiness(self):
            raise NotSupported(self.backend, "readiness")

        def healthy(self):
            return True

    ok, why, name = _Node(engine=_Legacy())._engine_readiness()
    assert ok is True, f"legacy probe never reached: {why}"
    assert name == "dwarfstar", name
    print("  [PASS] ENG-READY-1 NotSupported falls through to healthy()")
    passed += 1

    # ---- ENG-READY-2 : down is still down ----
    class _Down(_Legacy):
        def healthy(self):
            return False

    ok, why, _ = _Node(engine=_Down())._engine_readiness()
    assert ok is False and why, "a down backend must not read ready"
    print("  [PASS] ENG-READY-2 a genuinely down backend is not ready")
    passed += 1

    # ---- ANCH-LOCK-1 : one round, not two ----
    ch2, lg = _Chain(), _log()
    be = _Backend("xmr", "recorded", delay=0.05)
    sch = AnchorScheduler(ch2, [be], lg, lock=ch2.lock)
    out = []
    ts = [threading.Thread(target=lambda: out.append(sch.anchor_now()))
          for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert ch2.appends == 1, (
        f"{ch2.appends} ANCHOR_EXTERNAL records for one round — the "
        f"scheduler ran twice in parallel")
    assert be.calls == 1, f"{be.calls} backend submissions for one range"
    assert sum(1 for r in out if r.get("skipped")) == 1, (
        "the second caller must observe the first round, not repeat it")
    print("  [PASS] ANCH-LOCK-1 concurrent rounds serialize to one record")
    passed += 1

    # ---- ANCH-POLICY-1 : local-only is NOT external anchoring ----
    ch3, lg = _Chain(), _log()
    sch = AnchorScheduler(ch3, [_Backend("local", "recorded")], lg)
    st = sch.anchor_status()
    assert st["required_backends"] == [], st["required_backends"]
    assert st["external_configured"] is False
    anch = R.evaluate({"identity_loaded": True, "chain_loaded": True,
                       "chain_broken": "", "anchoring_configured": True,
                       "anchor_external_configured": False,
                       "engine_configured": False, "isolation_declared": [],
                       "being_configured": False})["subsystems"]["anchoring"]
    assert anch["state"] == R.NOT_CONFIGURED, anch
    assert "local" in anch["reason"]
    print("  [PASS] ANCH-POLICY-1 local-only reports NOT_CONFIGURED, "
          "not READY")
    passed += 1

    # ---- ANCH-POLICY-2 : custody is not permanent failure ----
    ch4, lg = _Chain(), _log()
    ots = _Backend("ots-calendar", "pending-attestation")
    sch = AnchorScheduler(ch4, [_Backend("local"), ots], lg,
                          retry_backoff_s=0.0)
    sch.anchor_now()
    st = sch.anchor_status()
    assert st["required_backends"] == ["ots-calendar"]
    assert "ots-calendar" in st["in_custody"], st
    assert st["behind"] == [], "custody discharges the duty to submit"
    anch = R.evaluate({"identity_loaded": True, "chain_loaded": True,
                       "chain_broken": "",
                       "engine_configured": False, "isolation_declared": [],
                       "being_configured": False,
                       **R.anchor_facts(st)})["subsystems"]["anchoring"]
    assert anch["state"] == R.DEGRADED, anch
    assert "custody" in anch["reason"]
    before = ots.calls
    sch.anchor_now()
    assert ots.calls == before, (
        "a held proof was resubmitted — the calendar gets spammed")
    print("  [PASS] ANCH-POLICY-2 a working OTS in custody is degraded, "
          "not failed forever")
    passed += 1

    # ---- BADGE-1 : the badge is evidence of a run ----
    from run_acceptance import read_result
    import gen_architecture_docs as G
    res = read_result()
    assert res is not None, (
        "no recorded acceptance run — the badge would be a claim about "
        "nothing")
    badge = G.acceptance_badge()
    assert str(res["passed"]) in badge and str(res["total"]) in badge
    if res["passed"] == res["total"] and not res["import_errors"]:
        assert "green" in badge and "recorded run" in badge
    else:
        assert "NOT GREEN" in badge, badge
    print(f"  [PASS] BADGE-1 badge derives from a recorded run: {badge[:48]}…")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_recut2_false_greens()
