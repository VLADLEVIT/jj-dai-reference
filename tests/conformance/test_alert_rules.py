#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Prometheus alert rules (v0.6.6) — the rules file is a deliverable, not a doc
============================================================================
The rules ship with the build, so they are checked with the build. Parsing is
done by a small stdlib reader rather than PyYAML on purpose: the codebase is
stdlib-only, and a check that skips itself when a dependency is absent is not
evidence — the same reasoning that keeps the live wasm group opt-in instead
of self-skipping.

  A-1  the file parses and every alert carries expr, severity and owner
  A-2  digest drift and a missing module are SEPARATE alerts at DIFFERENT
       severities — the whole reason the fault codes were split
  A-3  drift is critical and owned by security; a missing module never
       pages anyone (this build ships no compiled modules, so a fresh node
       is expected to be in that state)
  A-4  every metric an alert names is one the node can actually emit
  A-5  the readiness aggregate and the beacon both have an alert — the two
       facts v0.6.6 exists to expose
"""
from __future__ import annotations

import os
import re
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import readiness as R                                        # noqa: E402

RULES = os.path.join(_ROOT, "deploy", "prometheus", "jjdai-alerts.yml")


def parse_alerts(text: str) -> dict:
    """{alert_name: {field: value}} for the flat fields we care about."""
    alerts, cur, section = {}, None, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip() if raw.lstrip().startswith("#") \
            else raw.rstrip()
        if not line.strip():
            continue
        m = re.match(r"\s*-\s*alert:\s*(\S+)", line)
        if m:
            cur = {"name": m.group(1)}
            alerts[m.group(1)] = cur
            section = None
            continue
        if cur is None:
            continue
        m = re.match(r"\s*(labels|annotations):\s*$", line)
        if m:
            section = m.group(1)
            continue
        m = re.match(r"\s*(expr|for|severity|owner|summary):\s*(.+)$", line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key in ("severity", "owner") and section != "labels":
                continue
            cur[key] = val
    return alerts


def test_alert_rules():
    passed = 0
    assert os.path.exists(RULES), RULES
    text = open(RULES, encoding="utf-8").read()
    alerts = parse_alerts(text)

    # A-1
    assert len(alerts) >= 10, f"only {len(alerts)} alerts parsed"
    for name, a in sorted(alerts.items()):
        for field in ("expr", "severity", "owner"):
            assert a.get(field), f"{name} has no {field}"
    print(f"  [PASS] A-1 {len(alerts)} alerts, each with expr, severity, owner")
    passed += 1

    # A-2
    drift = alerts.get("JJDaiToolsetDigestDrift")
    missing = alerts.get("JJDaiToolsetModuleMissing")
    assert drift and missing, "both toolset alerts must exist"
    assert drift["expr"] != missing["expr"], "distinct conditions"
    assert drift["severity"] != missing["severity"], (
        "merging severities is exactly the failure the codes were split to "
        "prevent")
    print("  [PASS] A-2 drift and missing-module are separate alerts")
    passed += 1

    # A-3
    assert drift["severity"] == "critical", drift
    assert drift["owner"] == "security", drift
    assert missing["severity"] == "info", missing
    assert missing["owner"] == "ops", missing
    print("  [PASS] A-3 drift pages security; a missing module pages nobody")
    passed += 1

    # A-4 — every jjdai_ metric named in an expr must be emittable
    emittable = set()
    for k in R.gauge_values(R.evaluate({})):
        emittable.add("jjdai_" + k)
    emittable |= {"jjdai_" + k for k in (
        "requests_total", "denied_authz_total", "rate_limited_total",
        "revoked_rejected_total", "body_too_large_total", "bad_framing_total",
        "overloaded_total", "refusal_dropped_total", "tasks_total",
        "challenge_rounds_total", "witness_records", "uptime_seconds",
        "anchor_lag_seconds", "unanchored_depth",
        "toolset_digest_drift", "toolset_module_missing",
        "toolset_other_fault", "liveness_beacon_age_seconds",
        "watchdog_pings_total", "watchdog_silences_total",
        "watchdog_send_failures_total",
        "clock_source_is_suspend_inclusive",
        "sleep_gaps_total", "sleep_gap_last_seconds",
        "sleep_gap_seconds_total", "clock_steps_total",
        "clock_step_last_seconds")}
    named = set()
    for a in alerts.values():
        named |= set(re.findall(r"\bjjdai_[a-z0-9_]+", a["expr"]))
    unknown = sorted(named - emittable)
    assert not unknown, f"alerts name metrics the node never emits: {unknown}"
    print(f"  [PASS] A-4 all {len(named)} named metrics are emittable")
    passed += 1

    # A-6 — a gauge must never be spelled like a counter
    for a in alerts.values():
        for metric in re.findall(r"\bjjdai_[a-z0-9_]+", a["expr"]):
            if metric.startswith("jjdai_toolset_"):
                assert not metric.endswith("_total"), (
                    f"{metric} is recomputed from current state and can go "
                    f"DOWN; a Prometheus _total must be monotonic")
    print("  [PASS] A-6 toolset fault metrics are not spelled as counters")

    # A-5
    assert any("jjdai_ready ==" in a["expr"] for a in alerts.values()), \
        "no alert on the readiness aggregate"
    assert any("liveness_beacon_age_seconds" in a["expr"]
               for a in alerts.values()), "no alert on a stalled accept loop"
    assert any("sleep_gaps_total" in a["expr"] for a in alerts.values()), \
        "no alert on host suspension — the F1 gate needs it"
    print("  [PASS] A-5 readiness, beacon staleness and suspension all alert")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_alert_rules()
