#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sleep-gap detection (v0.6.6) — the Mac node's invisible failure
===============================================================
The F1 gate requires /healthz green for 72 consecutive hours on every node
including the Mac node, "without sleep breaks". A suspended host does not
crash, does not log and does not fail a health check; it comes back with its
uptime intact. These checks pin the detector that makes it visible.

  C-1  a suspension (wall advances, monotonic does not) is detected and
       measured
  C-2  ordinary jitter below the threshold is silent — a detector that
       fires on scheduler noise is muted within a month
  C-3  a BACKWARDS clock step is counted as a step, never as a suspension:
       otherwise every NTP correction fires the sleep alert
  C-4  metrics expose gaps and steps as separate series
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import clockwatch                                            # noqa: E402


def test_clockwatch_sleep():
    passed = 0
    seen = []

    cw = clockwatch.ClockWatch(threshold_s=8.0, on_gap=seen.append)
    cw._wall, cw._mono = 1000.0, 500.0

    # C-1 — 120s of wall time, 2s of monotonic: the machine slept ~118s
    gap = cw.observe(1120.0, 502.0)
    assert 117.0 < gap < 119.0, gap
    assert cw.gaps == 1 and seen and 117.0 < seen[0] < 119.0
    assert 117.0 < cw.last_gap_s < 119.0
    print(f"  [PASS] C-1 suspension detected and measured — {gap:.0f}s")
    passed += 1

    # C-2 — both clocks advance together, plus a little jitter
    before = cw.gaps
    for w, m in ((1123.0, 505.0), (1125.2, 507.0), (1127.0, 508.9)):
        assert cw.observe(w, m) == 0.0, (w, m)
    assert cw.gaps == before, "jitter must not count as a suspension"
    assert cw.steps == 0
    print("  [PASS] C-2 sub-threshold jitter is silent")
    passed += 1

    # C-3 — NTP steps the wall clock back 60s while monotonic ticks on
    steps = []
    cw.on_step = steps.append
    before_gaps = cw.gaps
    assert cw.observe(1067.0, 511.0) == 0.0, "a step is not a gap"
    assert cw.steps == 1, cw.steps
    assert cw.gaps == before_gaps, "a backwards step must not count as sleep"
    assert steps and steps[0] < 0
    print("  [PASS] C-3 backwards clock step counted apart from suspension")
    passed += 1

    # C-4
    m = cw.metrics()
    for k in ("sleep_gaps_total", "sleep_gap_last_seconds",
              "sleep_gap_seconds_total", "clock_steps_total",
              "clock_step_last_seconds"):
        assert k in m, k
    assert m["sleep_gaps_total"] == 1 and m["clock_steps_total"] == 1
    print("  [PASS] C-4 gaps and steps are separate metric series")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_clockwatch_sleep()
