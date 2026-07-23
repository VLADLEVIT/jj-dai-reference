#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rate limiting, live (v0.5.4) — the daemon's first operational boundary
======================================================================
  R-1  budgets are per endpoint CLASS: with infer=3/4s, the 4th
       inference inside the window gets 429 + Retry-After while READ
       endpoints keep answering 200 — one class exhausted never
       silences another
  R-2  systematic abuse becomes EVIDENCE: hammering past the abuse
       threshold lands EXACTLY ONE witnessed RATE_LIMIT record per
       offender per window (the limiter must never become a witness-
       flooding vector), carrying the key hash and rejection count
  R-3  the budget is a WINDOW, not a ban: after the window passes, the
       same identity is served again with 200
  R-4  a malformed --rate-limit spec refuses the boot (fail closed on
       configuration, like every other flag)
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from smoke_two_nodes import get, post, wait_up, jii, spawn         # noqa: E402

PORT = 8684
DAEMON = os.path.join(_ROOT, "node", "daemon.py")


def _post_raw(url, payload):
    """post() variant that surfaces the status code even for 429."""
    import json
    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode()), dict(e.headers)


def test_rate_limit_live():
    _prev = os.environ.get("JJDAI_KEYSTORE_PASSPHRASE")
    os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = "rl-test-pass"
    base = f"http://127.0.0.1:{PORT}"
    procs = []
    with tempfile.TemporaryDirectory() as tmp:
        try:
            procs.append(spawn(PORT, "rl-A", "fp-rl-A", [
                "--log", os.path.join(tmp, "rl-A.jsonl"),
                "--node-keystore", os.path.join(tmp, "rl-A.keystore"),
                "--rate-limit", "infer=3/4,read=50/4"]))
            caps = wait_up(base)

            # ---- R-1 ------------------------------------------------------ #
            for i in range(3):
                code, hdrs = _post_raw(base + "/v1/messages",
                                       jii(caps, prompt=f"in-budget {i}"))[0::2]
                assert code == 200, f"R-1: request {i} refused in budget"
            code, body, hdrs = _post_raw(base + "/v1/messages",
                                         jii(caps, prompt="over budget"))
            assert code == 429 and "RATE_LIMITED" in body["error"], body
            assert int(hdrs.get("Retry-After", 0)) >= 1, \
                "R-1: 429 must carry Retry-After"
            code, _ = get(base + "/witness/head")
            assert code == 200, \
                "R-1: the READ class must survive an exhausted INFER class"
            print("  [PASS] R-1  infer budget 3/4s: 4th -> 429 + "
                  "Retry-After; reads keep answering")

            # ---- R-2 ------------------------------------------------------ #
            for i in range(6):                 # push past ABUSE_THRESHOLD
                _post_raw(base + "/v1/messages", jii(caps, prompt="flood"))
            code, chain = get(base + "/witness/chain")
            rl = [r for r in chain["records"] if r["kind"] == "RATE_LIMIT"]
            assert len(rl) == 1, \
                f"R-2: exactly ONE abuse record expected, got {len(rl)}"
            dg = rl[0]["semantic_digest"]
            assert dg["cls"] == "infer" and dg["rejected"] >= 3 \
                and dg["key_hash"], dg
            print(f"  [PASS] R-2  {dg['rejected']} rejections -> ONE "
                  "witnessed RATE_LIMIT record (no witness flooding)")

            # ---- R-3 ------------------------------------------------------ #
            time.sleep(4.2)
            code, body, _ = _post_raw(base + "/v1/messages",
                                      jii(caps, prompt="new window"))
            assert code == 200, \
                f"R-3: a fresh window must serve again, got {code}"
            print("  [PASS] R-3  window rollover: the same identity is "
                  "served again — a budget, not a ban")

            # ---- R-4 ------------------------------------------------------ #
            r = subprocess.run(
                [sys.executable, DAEMON, "--port", "8685",
                 "--name", "rl-bad", "--fingerprint", "fp-bad",
                 "--rate-limit", "warp=9/1"],
                capture_output=True, text=True, timeout=30)
            assert r.returncode == 2 and "unknown rate class" in r.stderr
            print("  [PASS] R-4  unknown rate class refuses the boot")
        finally:
            if _prev is None:
                os.environ.pop("JJDAI_KEYSTORE_PASSPHRASE", None)
            else:
                os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = _prev
            for pr in procs:
                pr.terminate()
            for pr in procs:
                try:
                    pr.wait(timeout=10)
                except Exception:
                    pr.kill()


if __name__ == "__main__":
    test_rate_limit_live()
    print("\nRATE LIMIT LIVE: all groups green  ✓ certified")
