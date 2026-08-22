"""node/clockwatch.py — sleep-gap detection (build v0.6.6).

The Ф1 gate requires `/healthz` green for 72 consecutive hours on every node
INCLUDING the Mac node, and says so with an explicit parenthesis: without
sleep breaks. A laptop-class host is in the testnet-0 topology on purpose —
it carries the inference path — and a host that suspends does not crash, does
not log an error and does not fail a health check. It simply is not there for
a while, and comes back with its uptime intact and its witness replication
behind. Nothing in the stack notices.

THE DETECTOR
------------
`time.monotonic()` is suspend-aware on both target platforms: CLOCK_MONOTONIC
on Linux and mach_absolute_time on Darwin both STOP while the machine is
suspended. Wall-clock time does not. So the two clocks diverge by exactly the
duration of the suspension, and comparing them across a short tick needs no
platform API, no privileges and no daemon:

    tick:  d_wall = now_wall - last_wall
           d_mono = now_mono - last_mono
           gap    = d_wall - d_mono        # ≈ 0 normally, ≈ sleep duration after

A threshold well above scheduler jitter and NTP step keeps this quiet in
normal operation. NTP steps are worth a word: a large backwards step produces
a NEGATIVE gap, which is not a sleep and is reported separately as a clock
step rather than folded into the sleep counter. Conflating them would make
the sleep metric fire on every clock correction and be muted within a month.

WHAT IT DOES NOT DO
-------------------
It writes nothing to the witness plane. A host suspending is an operational
fact about a machine, not an act of a being, and the witness plane records
what a being did. It is metrics and a log line, and the alert rule lives in
deploy/prometheus/jjdai-alerts.yml.
"""
from __future__ import annotations

import threading
import time

#: Below this a divergence is scheduler noise, not a suspension.
DEFAULT_THRESHOLD_S = 8.0
#: How often the two clocks are compared.
DEFAULT_TICK_S = 2.0


class ClockWatch(threading.Thread):
    """Compares wall and monotonic clocks; records gaps and steps."""

    def __init__(self, tick_s: float = DEFAULT_TICK_S,
                 threshold_s: float = DEFAULT_THRESHOLD_S, on_gap=None,
                 on_step=None):
        super().__init__(name="jjdai-clockwatch", daemon=True)
        self.tick_s = float(tick_s)
        self.threshold_s = float(threshold_s)
        self.on_gap = on_gap
        self.on_step = on_step
        self.gaps = 0
        self.last_gap_s = 0.0
        self.total_gap_s = 0.0
        self.steps = 0
        self.last_step_s = 0.0
        self._wall = time.time()
        self._mono = time.monotonic()
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def observe(self, now_wall: float, now_mono: float) -> float:
        """One comparison. Returns the gap in seconds (0 when nothing to
        report). Pure enough to test by handing it two pairs of numbers."""
        d_wall = now_wall - self._wall
        d_mono = now_mono - self._mono
        self._wall, self._mono = now_wall, now_mono
        gap = d_wall - d_mono
        if gap >= self.threshold_s:
            self.gaps += 1
            self.last_gap_s = gap
            self.total_gap_s += gap
            if self.on_gap:
                self.on_gap(gap)
            return gap
        if gap <= -self.threshold_s:
            # Wall clock moved BACKWARDS relative to monotonic: a clock step,
            # not a suspension. Counted apart so the sleep alert stays honest.
            self.steps += 1
            self.last_step_s = gap
            if self.on_step:
                self.on_step(gap)
        return 0.0

    def run(self) -> None:
        while not self._stop.wait(self.tick_s):
            try:
                self.observe(time.time(), time.monotonic())
            except Exception:
                pass

    def metrics(self) -> dict:
        return {"sleep_gaps_total": self.gaps,
                "sleep_gap_last_seconds": round(self.last_gap_s, 3),
                "sleep_gap_seconds_total": round(self.total_gap_s, 3),
                "clock_steps_total": self.steps,
                "clock_step_last_seconds": round(self.last_step_s, 3)}
