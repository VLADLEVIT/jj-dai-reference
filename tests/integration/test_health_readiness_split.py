#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Liveness / readiness split, live (v0.6.6)
=========================================
The v0.6.3 audit recorded that `/healthz` is liveness-only and that a
liveness answer read as permission to send work is a hazard. This drop splits
the two. These checks run a real daemon and read the real endpoints.

  H-1  /healthz answers liveness and NOTHING about internal state — the
       isolation fields that rode there since v0.6.4 are gone
  H-2  /readyz answers readiness: every subsystem named, with a state, and
       the aggregate present
  H-3  the isolation declaration has MOVED to /readyz — it did not simply
       disappear
  H-4  a ready node answers 200 (the 503 branch is pinned directly by
       R-9 in tests/unit/test_readiness_rules.py, which tests the mapping
       function the handler calls)
  H-5  /metrics carries the readiness gauges, the beacon age and the
       toolset fault counters split by cause
  H-6  the shipped authz policy keeps /healthz anonymous and does NOT let
       anonymous reach /readyz — readiness names loaded engines, broken
       toolsets and anchoring lag, which is a map for choosing where to push
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from authz import AuthzPolicy                                # noqa: E402
import readiness as R                                        # noqa: E402

DAEMON = os.path.join(_ROOT, "node", "daemon.py")
PORT = 8697


def _get(path, timeout=5.0):
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}",
                                timeout=timeout) as r:
        return r.status, r.read().decode()


def _wait_up(deadline=25.0):
    t0 = time.time()
    while time.time() - t0 < deadline:
        try:
            code, _ = _get("/healthz", timeout=1.0)
            if code == 200:
                return True
        except Exception:
            time.sleep(0.25)
    return False


def test_health_readiness_split():
    passed = 0
    tmp = tempfile.mkdtemp(prefix="jjdai-readyz-")
    proc = subprocess.Popen(
        [sys.executable, DAEMON, "--host", "127.0.0.1", "--port", str(PORT),
         "--name", "readyz-node", "--log", os.path.join(tmp, "w.jsonl")],
        cwd=_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert _wait_up(), "daemon did not come up"

        # H-1
        code, body = _get("/healthz")
        h = json.loads(body)
        assert code == 200 and h["ok"] is True, h
        # v0.6.6 recut: the cut claimed this endpoint leaked nothing while
        # publishing the node id, the uptime and the witness record count —
        # an identity and an activity volume, to anyone who asked.
        for leaked in ("isolation_declared", "isolation_ready", "isolation",
                       "subsystems", "engine", "node_id", "records",
                       "uptime_s"):
            assert leaked not in h, f"/healthz still leaks {leaked!r}"
        assert set(h) == {"ok"}, sorted(h)
        print("  [PASS] H-1 /healthz is liveness only — nothing else at all")
        passed += 1

        # H-2
        code, body = _get("/readyz")
        rz = json.loads(body)
        assert "ready" in rz and isinstance(rz["ready"], bool), rz
        assert set(rz["subsystems"]) == set(R.SUBSYSTEMS), sorted(
            rz["subsystems"])
        for name, sub in rz["subsystems"].items():
            assert sub["state"] in (R.READY, R.DEGRADED, R.NOT_READY,
                                    R.NOT_CONFIGURED), (name, sub)
        print("  [PASS] H-2 /readyz names every subsystem with a state")
        passed += 1

        # H-3
        iso = rz["subsystems"]["isolation"]
        assert "declared" in iso or iso["state"] == R.NOT_CONFIGURED, iso
        if iso["state"] != R.NOT_CONFIGURED:
            assert "reference" in iso["declared"], iso
        print("  [PASS] H-3 the isolation declaration moved here, not away")
        passed += 1

        # H-4
        assert code == (200 if rz["ready"] else 503), (code, rz["ready"])
        assert rz["ready"] is True, (
            f"a fresh node must be ready; reason: {rz['reason']}")
        assert rz["node_id"], "readiness still identifies the node"
        print("  [PASS] H-4 a ready node answers 200 on /readyz")
        passed += 1

        # H-5
        code, metrics = _get("/metrics")
        assert code == 200
        for want in ("jjdai_ready ", "jjdai_ready_witness ",
                     "jjdai_ready_isolation ",
                     "jjdai_liveness_beacon_age_seconds ",
                     "jjdai_toolset_digest_drift ",
                     "jjdai_toolset_module_missing ",
                     "jjdai_sleep_gaps_total "):
            assert want in metrics, f"{want!r} missing from /metrics"
        assert "jjdai_toolset_digest_drift 0" in metrics
        print("  [PASS] H-5 /metrics carries readiness, beacon and fault "
              "counters split by cause")
        passed += 1

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # H-6 — the shipped policy, read as the operators will deploy it
    pol = AuthzPolicy.load(os.path.join(_ROOT, "deploy",
                                        "authz.testnet.json"))
    ok_anon_health, _ = pol.check("/healthz", "anonymous")
    ok_anon_ready, _ = pol.check("/readyz", "anonymous")
    ok_peer_ready, _ = pol.check("/readyz", "peer")
    ok_admin_ready, _ = pol.check("/readyz", "admin")
    assert ok_anon_health is True, "liveness must stay anonymous"
    assert ok_anon_ready is False, "readiness must not be anonymous"
    assert ok_peer_ready and ok_admin_ready, "peers and admins need readiness"
    print("  [PASS] H-6 policy: /healthz anonymous, /readyz peer+admin only")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_health_readiness_split()
