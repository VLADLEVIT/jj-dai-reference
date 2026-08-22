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


def _base(**over):
    snap = {"identity_loaded": True, "identity_ephemeral": False,
            "signer_mismatch": False, "chain_loaded": True,
            "chain_broken": "", "records": 4,
            "anchoring_configured": True, "anchor_lag_s": 10.0,
            "unanchored_depth": 0, "anchor_lag_max_s": 900,
            "unanchored_depth_max": 256, "anchor_never_succeeded": False,
            "anchor_behind": [],
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
    rep = R.evaluate(_base(anchor_never_succeeded=True, unanchored_depth=4,
                           anchor_behind=["xmr"], anchor_lag_s=None))
    assert rep["ready"] is False, rep
    assert rep["subsystems"]["anchoring"]["state"] == R.NOT_READY
    print("  [PASS] READY-ANCH-1 a required backend that never worked blocks")
    passed += 1

    # READY-ANCH-2
    rep = R.evaluate(_base(unanchored_depth=9999))
    assert R.http_status(rep) == 503, R.http_status(rep)
    print("  [PASS] READY-ANCH-2 depth past policy answers 503")
    passed += 1

    # READY-ANCH-3 — the defect, stated as a check
    rep = R.evaluate(_base(anchor_lag_s=None, anchor_never_succeeded=True,
                           unanchored_depth=1))
    anch = rep["subsystems"]["anchoring"]
    assert anch["state"] != R.READY, (
        "unknown anchoring state was reported as ready — the v0.6.6 defect")
    assert "never succeeded" in anch["reason"], anch["reason"]
    print("  [PASS] READY-ANCH-3 unknown is reported honestly, never green")
    passed += 1

    # READY-ANCH-4
    rep = R.evaluate(_base(anchor_never_succeeded=True, unanchored_depth=0))
    assert rep["ready"] is True, "nothing to anchor is not a failure"
    assert rep["subsystems"]["anchoring"]["state"] == R.DEGRADED
    rep = R.evaluate(_base(anchor_never_succeeded=False, anchor_lag_s=5.0,
                           unanchored_depth=0))
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
                  "behind", "covered_by", "required_backends"):
        assert field in st, f"anchor_status() omits {field}"
    snap = _base(anchor_lag_s=None,
                 unanchored_depth=st["unanchored_depth"],
                 anchor_never_succeeded=st["never_succeeded"],
                 anchor_behind=st["behind"])
    assert R.evaluate(snap)["ready"] is False, (
        "a real failing scheduler still produced a green node")
    print("  [PASS] READY-ANCH-5 real scheduler facts reach the rule")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_ready_anch_recut()
