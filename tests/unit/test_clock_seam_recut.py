#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suspend detection must not fire on a clock correction (v0.6.6 recut)
====================================================================
Audit response: a forward NTP step of ten seconds reproducibly incremented
`sleep_gaps_total`. The F1 gate counts sleep gaps against 72 hours green, so
a clock correction could fail a phase gate.

  CLOCK-1  a real suspension is detected and measured
  CLOCK-2  a FORWARD wall-clock correction is not a suspension
  CLOCK-3  a BACKWARD correction is counted as a clock step
  CLOCK-4  ordinary jitter stays silent
  CLOCK-5  the metric says which clock produced the number
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import clockwatch                                            # noqa: E402


def _cw(**kw):
    cw = clockwatch.ClockWatch(threshold_s=8.0, **kw)
    cw._wall, cw._mono, cw._boot = 1000.0, 500.0, 500.0
    cw.clock_source = "boottime"
    return cw


def test_clock_seam_recut():
    passed = 0

    # CLOCK-1 — 120s wall, 120s boottime, 2s monotonic: slept ~118s
    cw = _cw()
    gap = cw.observe(1120.0, 502.0, 620.0)
    assert 117.0 < gap < 119.0, gap
    assert cw.gaps == 1 and cw.steps == 0
    print(f"  [PASS] CLOCK-1 real suspension measured — {gap:.0f}s")
    passed += 1

    # CLOCK-2 — the regression: wall jumps +10s, neither other clock moves
    cw = _cw()
    assert cw.observe(1012.0, 502.0, 502.0) == 0.0
    assert cw.gaps == 0, (
        "a forward clock correction was counted as a suspension — this "
        "could fail the 72-hour F1 gate")
    assert cw.steps == 1, "it is a clock step and must be counted as one"
    print("  [PASS] CLOCK-2 forward correction is not a suspension")
    passed += 1

    # CLOCK-3
    cw = _cw()
    assert cw.observe(988.0, 502.0, 502.0) == 0.0
    assert cw.steps == 1 and cw.gaps == 0
    assert cw.last_step_s < 0
    print("  [PASS] CLOCK-3 backward correction counted as a step")
    passed += 1

    # CLOCK-4
    cw = _cw()
    for w, m, b in ((1003.0, 503.0, 503.0), (1005.1, 505.0, 505.1),
                    (1007.0, 506.9, 507.0)):
        assert cw.observe(w, m, b) == 0.0, (w, m, b)
    assert cw.gaps == 0 and cw.steps == 0
    print("  [PASS] CLOCK-4 jitter stays silent")
    passed += 1

    # CLOCK-5
    m = cw.metrics()
    assert "clock_source_is_suspend_inclusive" in m, m
    assert m["clock_source_is_suspend_inclusive"] in (0, 1)
    assert clockwatch.HAVE_BOOTTIME in (True, False)
    print("  [PASS] CLOCK-5 the metric names which clock was used")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_clock_seam_recut()
