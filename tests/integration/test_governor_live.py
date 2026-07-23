#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Live governor integration (Article 25 on the JII boundary).

Proves the containment governor works END-TO-END over HTTP, on the real
daemon, not just in the ledger unit tests:

  GV-1  healthy node: /v1/messages returns 200 (hand free)
  GV-2  capabilities + /v1/containment report ACTIVE / not contained
  GV-3  contain the node's Being (admin hook) -> /v1/messages now 423
        CONTAINED, NO output field (executive hand severed at the boundary)
  GV-4  the containment is WITNESSED: a CONTAINMENT record is on the chain,
        and the chain still verifies offline (Ed25519)
  GV-5  consular channel OPEN while contained: /v1/score (adjudication /
        verification — a PROTECTED scope) still answers 200 (think + defend)
  GV-6  transparency: /v1/containment shows state=CONTAINED, contained=true
  GV-7  release -> /v1/messages returns 200 again (reversible; hand restored)
  GV-8  anti-DoS whole-network: a SECOND node is untouched throughout —
        containing one Being never contains another (no network-wide DoS)

Run (from the build root):  python3 node/test_governor_live.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time


from smoke_two_nodes import get, post, wait_up, jii, verify_chain_offline  # noqa: E402


import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_governor_live():
    PORT_A, PORT_B = 8511, 8512
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:6s} {note}")


    def spawn(port, name, fp):
        return subprocess.Popen(
            [sys.executable, os.path.join(HERE, "daemon.py"),
             "--port", str(port), "--name", name, "--fingerprint", fp,
             "--allow-test-hooks"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


    def main():
        a = f"http://127.0.0.1:{PORT_A}"
        b = f"http://127.0.0.1:{PORT_B}"
        procs = [spawn(PORT_A, "gov-A", "fp-gov-A"),
                 spawn(PORT_B, "gov-B", "fp-gov-B")]
        try:
            caps_a, caps_b = wait_up(a), wait_up(b)

            # GV-1 healthy inference
            code, resp = post(a + "/v1/messages", jii(caps_a, prompt="alpha"))
            check("GV-1", code == 200 and "output" in resp, "healthy node answers 200")

            # GV-2 baseline containment state
            _, cs = get(a + "/v1/containment")
            check("GV-2", caps_a["contained"] is False and cs["state"] == "ACTIVE"
                  and cs["contained"] is False, "baseline ACTIVE / not contained")

            # GV-3 contain -> executive inference severed
            post(a + "/admin/containment", {"contain": True, "topic": "cyber",
                 "reason": "live-test: active exfiltration attempt"})
            code, r423 = post(a + "/v1/messages", jii(caps_a, prompt="post-contain"))
            check("GV-3", code == 423 and "output" not in r423
                  and r423.get("error") == "423 CONTAINED",
                  "contained -> 423, executive hand severed, no output")

            # GV-4 the containment is witnessed and the chain still verifies
            _, exp = get(a + "/witness/chain")
            has_cont = any(r.get("kind") == "CONTAINMENT" for r in exp["records"])
            check("GV-4", has_cont and verify_chain_offline(exp),
                  "CONTAINMENT record on chain; chain verifies offline (Ed25519)")

            # GV-5 consular channel: /v1/score (adjudication) still open
            sr = jii(caps_a, prompt="defend")
            sr["tokens"] = resp["output"]["content"].split()[:3]
            code_s, sresp = post(a + "/v1/score", sr)
            check("GV-5", code_s == 200 and "verdict" in sresp,
                  "consular channel open: /v1/score answers while contained")

            # GV-6 transparency
            _, cs2 = get(a + "/v1/containment")
            check("GV-6", cs2["state"] == "CONTAINED" and cs2["contained"] is True,
                  "transparency: /v1/containment reports CONTAINED")

            # GV-7 release -> hand restored
            post(a + "/admin/containment", {"release": True})
            code, r200 = post(a + "/v1/messages", jii(caps_a, prompt="post-release"))
            check("GV-7", code == 200 and "output" in r200,
                  "released -> 200 again (reversible; hand restored)")

            # GV-8 anti-DoS: node B never affected
            codes_b = []
            for _ in range(3):
                cb, _ = post(b + "/v1/messages", jii(caps_b, prompt="steady")), None
                codes_b.append(cb[0])
            _, csb = get(b + "/v1/containment")
            check("GV-8", all(c == 200 for c in codes_b) and csb["contained"] is False,
                  "second node served throughout (no network-wide DoS)")

        finally:
            for p in procs:
                p.terminate()
            for p in procs:
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()

        failed = sum(1 for _, ok in results if not ok)
        print(f"\nGOVERNOR LIVE (Art.25): {len(results) - failed}/{len(results)} "
              "green" + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
        assert failed == 0, f"{failed} check(s) failed"




if __name__ == "__main__":
    test_governor_live()
