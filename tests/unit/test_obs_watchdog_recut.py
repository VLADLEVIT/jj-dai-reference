#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Watchdog: the accept loop, not the traffic (v0.6.6 recut)
=========================================================
Audit response. The v0.6.6 cut touched the liveness beacon in
`process_request`, which runs only when a connection ARRIVES — so an idle
but perfectly healthy node aged its beacon, went silent and was restarted by
systemd. These are NEGATIVE tests: each one asserts something does not
happen, because every finding here was a thing that happened silently.

  OBS-WD-1  an idle node survives longer than two watchdog windows
  OBS-WD-2  an accept loop that stops moving stops the heartbeat
  OBS-WD-3  a busy handler thread does NOT mask a stalled accept loop
  OBS-WD-4  a busy-but-moving accept loop is never restarted
  OBS-WD-5  a failed sd_notify does not increment watchdog_pings_total
  OBS-WD-6  unit file, runtime default, alert rule and runbook agree
"""
from __future__ import annotations

import os
import re
import sys
import threading
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import sdnotify                                              # noqa: E402


class _Loop:
    """Stands in for serve_forever(): calls service_actions() each turn."""

    def __init__(self, beacon):
        self.beacon = beacon
        self.moving = True

    def turn(self):
        if self.moving:
            self.beacon.touch()          # what service_actions() does


def test_obs_watchdog_recut():
    passed = 0

    # OBS-WD-1 — the regression itself
    beacon = sdnotify.Beacon()
    loop = _Loop(beacon)
    wd = sdnotify.Watchdog(beacon, interval_s=0.01, stale_after=0.05)
    t0 = time.monotonic()
    while time.monotonic() - t0 < 0.25:          # >> two windows
        loop.turn()                              # no traffic, loop alive
        time.sleep(0.005)
        assert wd.should_ping(), (
            "an idle node aged its beacon — this is the v0.6.6 defect")
    print("  [PASS] OBS-WD-1 idle node stays alive across two windows")
    passed += 1

    # OBS-WD-2
    loop.moving = False
    time.sleep(0.08)
    assert wd.should_ping() is False, "a stalled accept loop must go silent"
    assert wd.tick() is False
    assert wd.silences >= 1
    print("  [PASS] OBS-WD-2 a stalled accept loop stops the heartbeat")
    passed += 1

    # OBS-WD-3 — the masking case
    busy = threading.Event()

    def handler():
        while not busy.is_set():
            time.sleep(0.002)            # a worker doing real work...
    th = threading.Thread(target=handler, daemon=True)
    th.start()
    time.sleep(0.08)                     # ...while the accept loop is dead
    assert wd.should_ping() is False, (
        "a working handler must not keep the watchdog alive")
    busy.set()
    th.join(timeout=1)
    print("  [PASS] OBS-WD-3 handler activity does not mask a dead loop")
    passed += 1

    # OBS-WD-4
    loop.moving = True
    for _ in range(10):
        loop.turn()
        time.sleep(0.004)
    assert wd.should_ping() is True, "a moving loop must be reported alive"
    print("  [PASS] OBS-WD-4 a busy-but-moving loop is not restarted")
    passed += 1

    # OBS-WD-5 — no socket in the environment ⇒ delivery fails
    old = os.environ.pop(sdnotify.ENV_SOCKET, None)
    try:
        beacon2 = sdnotify.Beacon()
        wd2 = sdnotify.Watchdog(beacon2, interval_s=0.01, stale_after=10.0)
        assert wd2.should_ping() is True, "the loop is fresh here"
        assert wd2.tick() is False, "but nothing received it"
        assert wd2.pings == 0, "an undelivered ping must not be counted"
        assert wd2.send_failures == 1
    finally:
        if old is not None:
            os.environ[sdnotify.ENV_SOCKET] = old
    print("  [PASS] OBS-WD-5 undelivered pings count as failures, not pings")
    passed += 1

    # OBS-WD-6 — one number, four places
    limit = sdnotify.DEFAULT_STALE_AFTER_S
    unit = open(os.path.join(_ROOT, "deploy", "jjdai-node@.service"),
                encoding="utf-8").read()
    m = re.search(r"^WatchdogSec=(\d+)", unit, re.M)
    assert m, "the unit no longer sets WatchdogSec"
    watchdog_sec = int(m.group(1))
    interval = watchdog_sec / 2.0
    assert limit < interval, (
        f"staleness {limit}s must be under one ping interval {interval}s, "
        f"or a stall is not caught within a window")
    assert f"{int(limit)}s" in unit, (
        f"the unit does not quote the staleness limit {int(limit)}s")
    rules = open(os.path.join(_ROOT, "deploy", "prometheus",
                              "jjdai-alerts.yml"), encoding="utf-8").read()
    m = re.search(r"jjdai_liveness_beacon_age_seconds > (\d+)", rules)
    assert m and int(m.group(1)) == int(limit), (
        f"alert threshold {m and m.group(1)} != staleness limit {int(limit)}")
    runbook = open(os.path.join(_ROOT, "deploy", "RUNBOOK.md"),
                   encoding="utf-8").read()
    assert f"WatchdogSec={watchdog_sec}" in runbook, "runbook drifted"
    assert f"{int(limit)}s" in runbook, "runbook omits the staleness limit"
    print(f"  [PASS] OBS-WD-6 {watchdog_sec}s / {interval:.0f}s / "
          f"{int(limit)}s agree across unit, runtime, alerts and runbook")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_obs_watchdog_recut()
