#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_anchor_required_backends — v0.6.7 audit: one boolean for many backends
===========================================================================
The audit found a false green in anchoring readiness. `anchor_status()`
published `never_succeeded` as ONE boolean over all required backends while
`in_custody` was per backend, and the NOT_READY branch was gated on
`not custody`. So an OpenTimestamps proof sitting in ordinary custody
suppressed the verdict about a DIFFERENT required backend that had never
anchored at all: the same node, with the same thousands of unanchored
records, answered 503 without the custody proof and 200 with it.

The lesson is the one this codebase keeps relearning in new clothes — an
absent or aggregated measurement becomes a green light. A node-wide boolean
cannot carry a per-backend fact, and no better boolean fixes that.

Every check here drives a REAL `AnchorScheduler` with real backends and
converts its real status through the same `anchor_facts()` the daemon uses.
A hand-built snapshot proves the rule and says nothing about whether the
node can gather the facts.

  ANCH-REQ-1  the audited scenario: a custody proof on one required backend
              does not suppress the verdict on another that never anchored.
              Fails against v0.6.7. Both policy ceilings are switched off so
              the depth breach cannot carry the check in the branch's place.
  ANCH-REQ-2  each failing backend is NAMED in the reason — an operator
              must not have to guess which one.
  ANCH-REQ-3  SHADOW: a configured backend that is not required cannot
              unready the node, and is still reported as shadow.
  ANCH-REQ-4  a required backend with NO measurement is NOT_READY, not
              skipped.
  ANCH-REQ-5  custody does not mask a backend's OWN policy breach: order of
              evaluation puts the breach first.
  ANCH-REQ-6  the daemon's flag reaches the scheduler: --required-anchor-
              backends narrows the required set, and naming an unconfigured
              backend refuses at startup rather than at the first scrape.
"""
from __future__ import annotations

import os
import re
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
    node_id = "node:anch-req"

    def __init__(self, n=5000):
        self.records = [{"kind": "INFER", "this_hash": f"{i:064x}"}
                        for i in range(n)]

    def append(self, kind, **kw):
        self.records.append({"kind": "ANCHOR_EXTERNAL",
                             "this_hash": f"{len(self.records):064x}"})


def _log():
    return AnchorLog(os.path.join(tempfile.mkdtemp(), "a.jsonl"))


def _node(backends, required=None, records=5000):
    sch = AnchorScheduler(_Chain(records), backends, _log(),
                          retry_backoff_s=0.0, required_backends=required)
    sch.anchor_now()
    return sch


def _report(sch, **over):
    snap = {"identity_loaded": True, "identity_ephemeral": False,
            "signer_mismatch": False, "chain_loaded": True,
            "chain_broken": "", "records": 5000,
            "anchor_lag_max_s": 300, "unanchored_depth_max": 256,
            "engine_configured": False, "isolation_declared": [],
            "being_configured": False}
    snap.update(R.anchor_facts(sch.anchor_status()))
    snap.update(over)
    return R.evaluate(snap)


def test_custody_does_not_mask_another_backend():
    ots = _Backend("ots", "pending-attestation")
    xmr = _Backend("xmr", "failed")
    sch = _node([_Backend("local"), ots, xmr])
    st = sch.anchor_status()
    assert st["required_backends"] == ["ots", "xmr"], st["required_backends"]
    assert st["per_backend"]["ots"]["in_custody"] is True
    assert st["per_backend"]["xmr"]["never"] is True

    # BOTH policy ceilings are switched off on purpose. With them on, the
    # depth breach alone produces NOT_READY and this check passes without
    # the branch it is named after ever running — verified: with the
    # never-anchored branch disabled, the check stayed green. That is the
    # defect this project keeps shipping under new names, so the only
    # surviving path to NOT_READY here is "a required backend has never
    # anchored and records are waiting".
    rep = _report(sch, anchor_lag_max_s=0, unanchored_depth_max=0)
    anch = rep["subsystems"]["anchoring"]
    assert anch["state"] == R.NOT_READY, (
        "a proof held by ONE backend suppressed the verdict about another "
        f"that never anchored — the audited false green: {anch}")
    assert "never anchored" in anch["reason"], anch["reason"]
    assert R.http_status(rep) == 503, R.http_status(rep)

    # control: the same node with the custody proof gone must be no greener
    ots2 = _Backend("ots", "failed")
    rep2 = _report(_node([_Backend("local"), ots2, _Backend("xmr", "failed")]),
                   anchor_lag_max_s=0, unanchored_depth_max=0)
    assert rep2["subsystems"]["anchoring"]["state"] == R.NOT_READY

    # and the mirror: with nothing waiting, the same "never" state is only
    # DEGRADED — so the check is measuring the branch and not the word
    idle = _node([_Backend("local"), _Backend("ots", "pending-attestation"),
                  _Backend("xmr", "failed")], records=0)
    assert _report(idle, anchor_lag_max_s=0,
                   unanchored_depth_max=0)["ready"] is True
    print("  [PASS] ANCH-REQ-1 custody on one backend does not green another")


def test_every_failing_backend_is_named():
    sch = _node([_Backend("local"), _Backend("ots", "pending-attestation"),
                 _Backend("xmr", "failed")])
    reason = _report(sch)["subsystems"]["anchoring"]["reason"]
    assert "ots" in reason and "xmr" in reason, reason
    assert "custody" in reason, reason
    assert re.search(r"xmr: .*(unanchored|never anchored)", reason), reason
    print("  [PASS] ANCH-REQ-2 each backend is named with its own reason")


def test_shadow_backend_cannot_unready_the_node():
    sch = _node([_Backend("local"), _Backend("ots"), _Backend("xmr", "failed")],
                required=["ots"])
    st = sch.anchor_status()
    assert st["required_backends"] == ["ots"], st["required_backends"]
    assert st["shadow_backends"] == ["xmr"], st["shadow_backends"]
    rep = _report(sch)
    anch = rep["subsystems"]["anchoring"]
    assert rep["ready"] is True, (
        f"a shadow backend blocked the node: {anch}")
    assert anch["state"] == R.READY, anch
    assert anch["shadow"] == ["xmr"], (
        "the shadow backend vanished from the report — running one unnoticed "
        "is how it silently becomes load-bearing")
    print("  [PASS] ANCH-REQ-3 a shadow backend is reported and never blocks")


def test_missing_measurement_is_not_green():
    sch = _node([_Backend("local"), _Backend("ots")])
    facts = R.anchor_facts(sch.anchor_status())
    facts["anchor_backend_facts"] = {}          # the measurement disappears
    rep = _report(sch, **facts)
    anch = rep["subsystems"]["anchoring"]
    assert anch["state"] == R.NOT_READY, anch
    assert "no measurement" in anch["reason"], anch["reason"]

    # and the shape contradiction — external configured, nothing required
    facts2 = R.anchor_facts(sch.anchor_status())
    facts2["anchor_required"] = []
    anch2 = _report(sch, **facts2)["subsystems"]["anchoring"]
    assert anch2["state"] == R.NOT_READY, anch2
    print("  [PASS] ANCH-REQ-4 an absent measurement is not a green light")


def test_custody_does_not_mask_its_own_breach():
    """A held proof discharges the duty to SUBMIT, not every duty.

    If the chain grows past the policy depth while a proof sits in custody,
    that is the backend's own breach and custody must not answer for it.
    The rule checks the policy breach BEFORE the custody state for exactly
    this reason.
    """
    f = {"required": True, "never": True, "in_custody": True,
         "behind": False, "depth": 9999, "lag_s": None}
    state, why = R._backend_anchor_state(f, max_lag=300, max_depth=256)
    assert state == R.NOT_READY, (state, why)
    assert "over policy" in why, why
    # within policy, the same custody state is the ordinary steady state
    f2 = dict(f, depth=0)
    state2, why2 = R._backend_anchor_state(f2, max_lag=300, max_depth=256)
    assert state2 == R.DEGRADED and "custody" in why2, (state2, why2)
    print("  [PASS] ANCH-REQ-5 custody covers submission, never a breach")


def test_daemon_flag_reaches_the_scheduler():
    daemon = open(os.path.join(_ROOT, "node", "daemon.py"),
                  encoding="utf-8").read()
    assert '"--required-anchor-backends"' in daemon, \
        "ANCH-REQ-6: the flag does not exist"
    assert "required_anchor_backends=required_anchor" in daemon, \
        "ANCH-REQ-6: the flag is parsed and never passed to the Node"
    assert "required_backends=required_anchor_backends" in daemon, \
        "ANCH-REQ-6: the Node accepts it and never passes it to the scheduler"
    assert "are not configured" in daemon, \
        ("ANCH-REQ-6: naming an unconfigured backend must refuse at startup "
         "— the scheduler drops unknown names, so the node would report "
         "green on a policy nobody is serving")
    # the narrowing itself, on a real scheduler
    sch = _node([_Backend("local"), _Backend("ots"), _Backend("xmr")],
                required=["ots"])
    assert sch.required_backends == ["ots"]
    assert sch.anchor_status()["configured_backends"] == \
        ["local", "ots", "xmr"], "configured and required are the same list"
    print("  [PASS] ANCH-REQ-6 the flag narrows required without hiding "
          "configured")


if __name__ == "__main__":
    for t in (test_custody_does_not_mask_another_backend,
              test_every_failing_backend_is_named,
              test_shadow_backend_cannot_unready_the_node,
              test_missing_measurement_is_not_green,
              test_custody_does_not_mask_its_own_breach,
              test_daemon_flag_reaches_the_scheduler):
        t()
    print("\nanchor required backends — 6/6 checks green")
