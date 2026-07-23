#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Cross-verification loop (iteration I1 closing test).

Two LIVE daemons over HTTP: a generator produces output, a peer verifier
scores it, the loop RE-AUDITS the peer's signed verdict offline, and only
then credits the §9.9 registry. Proves the loop turns certified nodes into
reputation-earning ones — without trusting the peer's word.

  X-1  generator produces output over /v1/messages
  X-2  peer verifier scores it; loop re-audits the peer's SIGNED witness
       record and records a PASS into the registry (weight starts to grow)
  X-3  repeated verified passes raise the generator's champion weight; it
       becomes topic champion
  X-4  anti-self-dealing: a node cannot verify its OWN generation into
       reputation (no independent peer -> refused)
  X-5  lying peer: a verifier whose returned verdict does NOT match its
       signed chain record is caught in re-audit and DISCARDED (never
       reaches the registry)
  X-6  the registry credit is itself event-sourced & on the chain (REGISTRY
       record present; registry journal replays to the same snapshot)

Run (from the build root):  python3 node/test_crossverify_live.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import time


from smoke_two_nodes import get, post, wait_up, jii            # noqa: E402
from core.registry import ChampionRegistry, Params             # noqa: E402
from core.crossverify import CrossVerifier, CrossVerifyError    # noqa: E402


import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_crossverify_live():
    GEN_PORT, VER_PORT = 8521, 8522
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    def spawn(port, name, fp):
        return subprocess.Popen(
            [sys.executable, os.path.join(HERE, "daemon.py"),
             "--port", str(port), "--name", name, "--fingerprint", fp,
             "--allow-test-hooks"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


    def main():
        gen = f"http://127.0.0.1:{GEN_PORT}"
        ver = f"http://127.0.0.1:{VER_PORT}"
        procs = [spawn(GEN_PORT, "generator", "fp-shared"),
                 spawn(VER_PORT, "verifier", "fp-shared")]
        try:
            caps_g = wait_up(gen)
            wait_up(ver)
            GEN_ID = "ne:generator"

            # X-1 generator produces output
            req = jii(caps_g, prompt="alpha beta")
            code, resp = post(gen + "/v1/messages", req)
            tokens = resp["output"]["content"].split()
            check("X-1", code == 200 and tokens, f"generator output {len(tokens)} tok")

            # cross-verify loop wired to a real registry, real HTTP
            reg = ChampionRegistry(Params())
            loop = CrossVerifier(reg, http_post=post, http_get=get, min_verifiers=1)

            # X-2 peer scores, loop re-audits the signed verdict, records PASS
            trace = loop.verify_and_record(
                topic="maglev", generator_id=GEN_ID, generator_url=gen,
                verifier_urls=[ver], jii_request=req, output_tokens=tokens)
            w1 = reg.weight("maglev", GEN_ID)
            audited_ok = trace["audited"] and trace["audited"][0]["ok"] is True
            check("X-2", trace["recorded"] and audited_ok and w1 > 0.0,
                  f"peer verdict re-audited & recorded; weight {w1:.3f}")

            # X-3 repeated verified passes -> champion
            for _ in range(6):
                r = jii(caps_g, prompt="alpha beta")
                _, rr = post(gen + "/v1/messages", r)
                loop.verify_and_record(
                    topic="maglev", generator_id=GEN_ID, generator_url=gen,
                    verifier_urls=[ver], jii_request=r,
                    output_tokens=rr["output"]["content"].split())
            champ = reg.champion("maglev")
            check("X-3", champ and champ["object_id"] == GEN_ID,
                  f"generator became champion, weight {champ['weight']:.3f}")

            # X-4 anti-self-dealing
            refused = False
            try:
                loop.verify_and_record(
                    topic="maglev", generator_id=GEN_ID, generator_url=gen,
                    verifier_urls=[gen],       # only itself
                    jii_request=req, output_tokens=tokens)
            except CrossVerifyError:
                refused = True
            check("X-4", refused, "node cannot verify its own work into reputation")

            # X-5 lying peer: verdict reply doctored to disagree with signed record
            reg5 = ChampionRegistry(Params())

            def lying_post(url, obj):
                status, reply = post(url, obj)
                if url.endswith("/v1/score") and "verdict" in reply:
                    # flip reachability in the RETURNED json only; the peer's
                    # signed chain record still binds the TRUE reachability
                    reply = dict(reply)
                    v = dict(reply["verdict"])
                    v["reachable"] = [not x for x in v["reachable"]] or [False]
                    v["ok"] = True
                    reply["verdict"] = v
                return status, reply

            loop5 = CrossVerifier(reg5, http_post=lying_post, http_get=get,
                                  min_verifiers=1)
            r = jii(caps_g, prompt="gamma delta")
            _, rr = post(gen + "/v1/messages", r)
            trace5 = loop5.verify_and_record(
                topic="cyber", generator_id=GEN_ID, generator_url=gen,
                verifier_urls=[ver], jii_request=r,
                output_tokens=rr["output"]["content"].split())
            discarded = (not trace5["recorded"]
                         and trace5["audited"][0]["ok"] is None
                         and "re-audit failed" in trace5["audited"][0]["discarded"])
            check("X-5", discarded and reg5.weight("cyber", GEN_ID) == 0.0,
                  "lying peer caught in re-audit; verdict discarded, no credit")

            # X-6 registry credit is event-sourced & replayable
            from core.registry import ChampionRegistry as _CR
            replay = _CR.replay(reg.events, Params())
            check("X-6", replay.snapshot_hash() == reg.snapshot_hash()
                  and len(reg.events) >= 7,
                  f"{len(reg.events)} registry events replay to same snapshot")

        finally:
            for p in procs:
                p.terminate()
            for p in procs:
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()

        failed = sum(1 for _, ok in results if not ok)
        print(f"\nCROSS-VERIFY LOOP: {len(results) - failed}/{len(results)} green"
              + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
        assert failed == 0, f"{failed} check(s) failed"




if __name__ == "__main__":
    test_crossverify_live()
