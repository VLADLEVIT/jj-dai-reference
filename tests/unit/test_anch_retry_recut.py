#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Anchor coverage and retry (v0.6.6 recut)
========================================
Audit response. `anchor_now()` assigned `_covered = count` after submitting,
regardless of what the receipts said, and a restart rebuilt `_covered` from
any receipt at all. A FAILED Monero or calendar anchor therefore retired its
range permanently: the log said "failed", the scheduler said "covered", and
the range was never attempted again. External anchoring is the one mechanism
whose entire value is that somebody outside can check us.

  ANCH-RETRY-1  a failed backend is retried without new cognition
  ANCH-RETRY-2  a pending receipt is not coverage
  ANCH-RETRY-3  a successful backend advances only its own position
  ANCH-RETRY-4  restart rebuilds coverage only from successful receipts
  ANCH-RETRY-5  local success does not discharge an external requirement
  ANCH-RETRY-6  retries do not emit an endless stream of bookkeeping
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.anchoring import AnchorLog, AnchorScheduler         # noqa: E402


class _Backend:
    def __init__(self, name, status="recorded"):
        self.name = name
        self.status = status
        self.calls = 0

    def submit(self, node_id, root, count):
        self.calls += 1
        return {"backend": self.name, "node": node_id, "root": root,
                "count": count, "status": self.status, "ts": time.time()}


class _Chain:
    node_id = "node:anch-test"

    def __init__(self, n=3):
        self.records = [{"kind": "INFER", "this_hash": f"{i:064x}"}
                        for i in range(n)]
        self.appends = 0

    def append(self, kind, **kw):
        self.appends += 1
        self.records.append({"kind": "ANCHOR_EXTERNAL",
                             "this_hash": f"{len(self.records):064x}"})


def _log():
    return AnchorLog(os.path.join(tempfile.mkdtemp(), "anchors.jsonl"))


def test_anch_retry_recut():
    passed = 0

    # ANCH-RETRY-1
    xmr = _Backend("xmr", "failed")
    ch, lg = _Chain(), _log()
    sch = AnchorScheduler(ch, [xmr], lg, retry_backoff_s=0.0)
    sch.anchor_now()
    before = xmr.calls
    sch.anchor_now()                       # no new cognition in between
    assert xmr.calls > before, (
        "a failed anchor waited for unrelated work before retrying")
    assert sch._covered == 0, sch._covered
    print("  [PASS] ANCH-RETRY-1 a failed backend is retried on its own")
    passed += 1

    # ANCH-RETRY-2
    pend = _Backend("ots-calendar", "pending")
    ch, lg = _Chain(), _log()
    sch = AnchorScheduler(ch, [pend], lg, retry_backoff_s=0.0)
    sch.anchor_now()
    st = sch.anchor_status()
    assert st["covered"] == 0, "a pending proof is not a proof"
    assert st["never_succeeded"] is True
    assert "ots-calendar" in st["behind"]
    print("  [PASS] ANCH-RETRY-2 pending is attempted, never covered")
    passed += 1

    # ANCH-RETRY-3
    ok = _Backend("ots-calendar", "recorded")
    bad = _Backend("xmr", "failed")
    ch, lg = _Chain(), _log()
    sch = AnchorScheduler(ch, [ok, bad], lg, retry_backoff_s=0.0)
    res = sch.anchor_now()
    st = sch.anchor_status()
    assert st["covered_by"]["ots-calendar"] == len(ch.records) - ch.appends
    assert st["covered_by"]["xmr"] == 0
    assert st["covered"] == 0, "the ratchet moves at the pace of the slowest"
    assert res.get("partial") is True and res.get("fully_covered") is False
    print("  [PASS] ANCH-RETRY-3 success advances only its own backend")
    passed += 1

    # ANCH-RETRY-4
    ch2 = _Chain()
    sch2 = AnchorScheduler(ch2, [_Backend("ots-calendar"), _Backend("xmr")],
                           lg, retry_backoff_s=0.0)
    st2 = sch2.anchor_status()
    assert st2["covered_by"]["xmr"] == 0, (
        "restart resurrected coverage from a failed receipt")
    assert st2["covered_by"]["ots-calendar"] > 0, (
        "restart lost coverage that really happened")
    print("  [PASS] ANCH-RETRY-4 restart trusts only successful receipts")
    passed += 1

    # ANCH-RETRY-5
    loc = _Backend("local", "recorded")
    xmr2 = _Backend("xmr", "failed")
    ch, lg = _Chain(), _log()
    sch = AnchorScheduler(ch, [loc, xmr2], lg, retry_backoff_s=0.0)
    sch.anchor_now()
    st = sch.anchor_status()
    assert st["required_backends"] == ["xmr"], st["required_backends"]
    assert st["covered"] == 0, (
        "a local file was accepted as external anchoring")
    assert st["never_succeeded"] is True
    print("  [PASS] ANCH-RETRY-5 local success is not external anchoring")
    passed += 1

    # ANCH-RETRY-6
    ch, lg = _Chain(), _log()
    bad = _Backend("xmr", "failed")
    sch = AnchorScheduler(ch, [bad], lg, retry_backoff_s=0.0)
    sch.anchor_now()
    appends_after_first = ch.appends
    for _ in range(20):
        sch.anchor_now()
    assert ch.appends == appends_after_first, (
        f"{ch.appends - appends_after_first} bookkeeping records written by "
        f"retries that changed nothing")
    assert bad.calls >= 20, "but the backend WAS retried"
    print("  [PASS] ANCH-RETRY-6 fruitless retries write no chain records")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_anch_retry_recut()
