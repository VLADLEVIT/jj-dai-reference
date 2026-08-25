#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Readiness rules (v0.6.6) — the core/non-core split, stated as checks
====================================================================
These test the RULE, not the daemon. node/readiness.py evaluates a plain
dict; the daemon gathers the dict. Keeping them apart is the direct answer
to the v0.6.5 finding that a check named after a claim while measuring
something adjacent to it is worse than no check at all.

  R-1  a healthy node is ready and names nothing as degraded
  R-2  a core subsystem down ⇒ NOT ready, and the reason NAMES it
  R-3  a non-core subsystem down ⇒ still ready, listed as degraded
  R-4  an unprovisioned wasm toolset does NOT make the node unready
       (the arithmetic reason the single-boolean design was rejected:
        this build ships no compiled modules, so every fresh node would
        otherwise report unready forever)
  R-5  absence and failure are different: no anchoring configured is
       NOT_CONFIGURED, not NOT_READY
  R-6  an ephemeral identity degrades but does not stop the node
  R-7  containment degrades and never reads as a fault
  R-8  gauges carry one numeric scale, aggregate included
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import readiness as R                                        # noqa: E402


def _healthy(**over) -> dict:
    snap = {
        "identity_loaded": True, "identity_ephemeral": False,
        "signer_mismatch": False,
        "chain_loaded": True, "chain_broken": "", "records": 12,
        # v0.6.7 vertical: the being's identity is reported beside the
        # node's, and a healthy fixture has to state both. An ephemeral or
        # unbound being is DEGRADED, deliberately.
        "being_ephemeral": False, "being_bound": True,
        "anchoring_configured": True, "anchor_lag_s": 30.0,
        "unanchored_depth": 4, "anchor_lag_max_s": 900,
        "unanchored_depth_max": 256,
        # v0.6.7 audit: anchoring is evaluated PER REQUIRED BACKEND, so a
        # healthy fixture has to name one. A snapshot with no per-backend
        # facts is deliberately NOT_READY — an absent measurement is not a
        # green light.
        "anchor_external_configured": True,
        "anchor_required": ["ots"],
        "anchor_configured_backends": ["local", "ots"],
        "anchor_shadow_backends": [],
        "anchor_backend_facts": {
            "ots": {"required": True, "never": False, "in_custody": False,
                    "behind": False, "depth": 4, "lag_s": 30.0}},
        "engine_configured": True, "engine_ready": True,
        "engine_name": "dwarfstar", "engine_reason": "",
        "isolation_declared": ["reference"], "isolation_ready": ["reference"],
        "being_configured": True, "being_contained": False,
        "being_profile": "production",
    }
    snap.update(over)
    return snap


def test_readiness_rules():
    passed = 0

    # R-1
    rep = R.evaluate(_healthy())
    assert rep["ready"] is True, rep
    assert rep["degraded"] == [], rep["degraded"]
    assert rep["reason"] == "", rep["reason"]
    print("  [PASS] R-1 healthy node is ready with nothing degraded")
    passed += 1

    # R-2 — every core subsystem, one at a time
    for name, broken in (("identity", {"identity_loaded": False}),
                         ("witness", {"chain_broken": "hash mismatch at 7"}),
                         ("anchoring", {"anchor_backend_facts": {
                             "ots": {"required": True, "never": False,
                                     "in_custody": False, "behind": True,
                                     "depth": 4, "lag_s": 5000.0}}})):
        rep = R.evaluate(_healthy(**broken))
        assert rep["ready"] is False, (name, rep)
        assert name in rep["reason"], (name, rep["reason"])
        assert rep["subsystems"][name]["state"] == R.NOT_READY
    print("  [PASS] R-2 each core subsystem can block, and is named")
    passed += 1

    # R-3 — non-core down must not take the node out of the network
    rep = R.evaluate(_healthy(engine_ready=False,
                              engine_reason="model not loaded"))
    assert rep["ready"] is True, rep
    assert "engine" in rep["degraded"], rep["degraded"]
    assert rep["subsystems"]["engine"]["state"] == R.NOT_READY
    print("  [PASS] R-3 non-core failure degrades without unreadying")
    passed += 1

    # R-4 — the unprovisioned-toolset case, stated explicitly
    rep = R.evaluate(_healthy(isolation_declared=["reference", "wasm-wasi"],
                              isolation_ready=["reference"]))
    assert rep["ready"] is True, rep
    assert rep["subsystems"]["isolation"]["state"] == R.DEGRADED
    rep = R.evaluate(_healthy(isolation_declared=["wasm-wasi"],
                              isolation_ready=[]))
    assert rep["ready"] is True, "a dark isolation surface is not unready"
    assert rep["subsystems"]["isolation"]["state"] == R.NOT_READY
    print("  [PASS] R-4 an unexecutable wasm toolset never unreadies the node")
    passed += 1

    # R-5 — absence ≠ failure
    rep = R.evaluate(_healthy(anchoring_configured=False))
    assert rep["subsystems"]["anchoring"]["state"] == R.NOT_CONFIGURED
    assert rep["ready"] is True, "no anchoring configured is not a fault"
    assert "anchoring" not in rep["degraded"]
    rep = R.evaluate(_healthy(engine_configured=False))
    assert rep["subsystems"]["engine"]["state"] == R.NOT_CONFIGURED
    print("  [PASS] R-5 not-configured is its own state, not a failure")
    passed += 1

    # R-6
    rep = R.evaluate(_healthy(identity_ephemeral=True))
    assert rep["ready"] is True, rep
    assert rep["subsystems"]["identity"]["state"] == R.DEGRADED
    assert "identity" in rep["degraded"]
    assert "ephemeral" in rep["subsystems"]["identity"]["reason"]
    print("  [PASS] R-6 ephemeral identity degrades, visibly, without stopping")
    passed += 1

    # R-7 — governance is not an incident
    rep = R.evaluate(_healthy(being_contained=True))
    assert rep["ready"] is True, rep
    assert rep["subsystems"]["being"]["state"] == R.DEGRADED
    assert "not a fault" in rep["subsystems"]["being"]["reason"]
    print("  [PASS] R-7 containment degrades and reads as governance")
    passed += 1

    # R-8 — one scale
    g = R.gauge_values(R.evaluate(_healthy(anchoring_configured=False,
                                           identity_ephemeral=True)))
    assert g["ready"] == 1
    assert g["ready_anchoring"] == -1, g
    assert g["ready_identity"] == 0.5, g
    assert g["ready_witness"] == 1, g
    g = R.gauge_values(R.evaluate(_healthy(chain_loaded=False)))
    assert g["ready"] == 0 and g["ready_witness"] == 0, g
    assert set(g) == {"ready"} | {f"ready_{n}" for n in R.SUBSYSTEMS}
    print("  [PASS] R-8 gauges use one scale and cover every subsystem")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_readiness_rules()


def test_readiness_http_status():
    """R-9  the status-code contract, checked directly.

    An orchestrator that reads only the code must behave correctly without
    parsing the body. That is the contract; an untested contract is a
    comment.
    """
    assert R.http_status(R.evaluate(_healthy())) == 200
    assert R.http_status(R.evaluate(_healthy(chain_loaded=False))) == 503
    # degraded but serving is still 200 — the whole point of the split
    assert R.http_status(R.evaluate(
        _healthy(isolation_declared=["wasm-wasi"],
                 isolation_ready=[]))) == 200
    print("  [PASS] R-9 ready->200, core failure->503, degraded stays 200")
    print("\nsummary: 1 passed, 0 failed")
