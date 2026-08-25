#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Readiness must receive real anchoring facts (v0.6.6 recut)
==========================================================
Audit response. `readiness_snapshot()` read `anchor_scheduler.last_anchor_at`
and `.unanchored_depth`. Neither attribute existed. `getattr` defaults turned
an ABSENT MEASUREMENT into `state=ready, anchor_lag_s=None, depth=0` — a
green light produced by the absence of the thing it claims to measure, in the
drop written to remove exactly that class of error.

  READY-ANCH-1  a stopped required backend eventually reads NOT_READY
  READY-ANCH-2  depth past policy answers 503
  READY-ANCH-3  UNKNOWN is reported honestly and never as green
  READY-ANCH-4  readiness returns only after a CONFIRMED successful anchor
  READY-ANCH-5  the scheduler really publishes what readiness reads
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import readiness as R                                        # noqa: E402
from core.anchoring import AnchorLog, AnchorScheduler         # noqa: E402


class _Backend:
    def __init__(self, name, status="recorded"):
        self.name, self.status, self.calls = name, status, 0

    def submit(self, node_id, root, count):
        self.calls += 1
        return {"backend": self.name, "node": node_id, "root": root,
                "count": count, "status": self.status, "ts": time.time()}


class _Chain:
    node_id = "node:ready-anch"

    def __init__(self, n=4):
        self.records = [{"kind": "INFER", "this_hash": f"{i:064x}"}
                        for i in range(n)]

    def append(self, kind, **kw):
        self.records.append({"kind": "ANCHOR_EXTERNAL",
                             "this_hash": f"{len(self.records):064x}"})


def _facts(name="xmr", **over):
    """One required backend's facts, in the shape anchor_facts() produces."""
    f = {"required": True, "never": False, "in_custody": False,
         "behind": False, "depth": 0, "lag_s": 10.0}
    f.update(over)
    return {name: f}


def _base(**over):
    snap = {"identity_loaded": True, "identity_ephemeral": False,
            "signer_mismatch": False, "chain_loaded": True,
            "chain_broken": "", "records": 4,
            "anchoring_configured": True, "anchor_lag_s": 10.0,
            "unanchored_depth": 0, "anchor_lag_max_s": 900,
            "unanchored_depth_max": 256,
            "anchor_external_configured": True,
            "anchor_required": ["xmr"],
            "anchor_configured_backends": ["local", "xmr"],
            "anchor_shadow_backends": [],
            "anchor_backend_facts": _facts(),
            "engine_configured": False, "engine_ready": False,
            "engine_name": None, "engine_reason": "",
            "isolation_declared": ["reference"],
            "isolation_ready": ["reference"],
            "being_configured": False, "being_contained": False}
    snap.update(over)
    return snap


def test_ready_anch_recut():
    passed = 0

    # READY-ANCH-1
    rep = R.evaluate(_base(unanchored_depth=4, anchor_lag_s=None,
                           anchor_backend_facts=_facts(
                               never=True, behind=True, depth=4,
                               lag_s=None)))
    assert rep["ready"] is False, rep
    assert rep["subsystems"]["anchoring"]["state"] == R.NOT_READY
    print("  [PASS] READY-ANCH-1 a required backend that never worked blocks")
    passed += 1

    # READY-ANCH-2 — the node-level depth is now INFORMATIONAL; the policy
    # is enforced against the backend that is actually behind, so the fact
    # has to be stated where the rule reads it.
    rep = R.evaluate(_base(unanchored_depth=9999,
                           anchor_backend_facts=_facts(behind=True,
                                                       depth=9999)))
    assert R.http_status(rep) == 503, R.http_status(rep)
    print("  [PASS] READY-ANCH-2 depth past policy answers 503")
    passed += 1

    # READY-ANCH-3 — the defect, stated as a check
    rep = R.evaluate(_base(anchor_lag_s=None, unanchored_depth=1,
                           anchor_backend_facts=_facts(never=True, depth=1,
                                                       lag_s=None)))
    anch = rep["subsystems"]["anchoring"]
    assert anch["state"] != R.READY, (
        "unknown anchoring state was reported as ready — the v0.6.6 defect")
    assert "never anchored" in anch["reason"], anch["reason"]
    print("  [PASS] READY-ANCH-3 unknown is reported honestly, never green")
    passed += 1

    # READY-ANCH-4
    rep = R.evaluate(_base(unanchored_depth=0,
                           anchor_backend_facts=_facts(never=True, depth=0,
                                                       lag_s=None)))
    assert rep["ready"] is True, "nothing to anchor is not a failure"
    assert rep["subsystems"]["anchoring"]["state"] == R.DEGRADED
    rep = R.evaluate(_base(anchor_lag_s=5.0, unanchored_depth=0,
                           anchor_backend_facts=_facts(lag_s=5.0)))
    assert rep["subsystems"]["anchoring"]["state"] == R.READY
    print("  [PASS] READY-ANCH-4 green only after a confirmed anchor")
    passed += 1

    # READY-ANCH-5 — the scheduler publishes what readiness consumes
    lg = AnchorLog(os.path.join(tempfile.mkdtemp(), "a.jsonl"))
    sch = AnchorScheduler(_Chain(), [_Backend("xmr", "failed")], lg,
                          retry_backoff_s=0.0)
    sch.anchor_now()
    st = sch.anchor_status()
    for field in ("last_success_at", "unanchored_depth", "never_succeeded",
                  "behind", "covered_by", "required_backends",
                  "per_backend", "configured_backends", "shadow_backends"):
        assert field in st, f"anchor_status() omits {field}"
    # Through the SAME converter the daemon uses — a hand-built snapshot
    # would prove the rule and nothing about whether the facts can be
    # gathered, which is the defect this file was written for.
    snap = _base(**R.anchor_facts(st))
    assert R.evaluate(snap)["ready"] is False, (
        "a real failing scheduler still produced a green node")
    print("  [PASS] READY-ANCH-5 real scheduler facts reach the rule")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_ready_anch_recut()
