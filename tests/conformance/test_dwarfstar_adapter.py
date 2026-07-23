#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Tier-1 DwarfStar Adapter Certification (v0.1)
======================================================
Certifies the DS4 path end-to-end with NO GPU/Metal and NO third-party deps:

    mock_dwarfstar.py  (executable wire contract, BOTH dialects)
        ▲
    engine_dwarfstar.py  (adapter under test, auto-probing dialect)
        ▲
    daemon.py --engine dwarfstar  (envelope + Ed25519 witness OUTSIDE engine)

Suite (D = DwarfStar):
  D-1   dialect auto-probe: "oai" server detected, model identity read
  D-2   dialect auto-probe: "gen" server detected, model identity read
  D-3   JII generate through daemon->adapter->mock (oai dialect)
  D-4   byte-identical repeat against the deterministic mock
  D-5   PROFILE B ENFORCED: adapter_ids -> no silent downgrade — daemon
        rejects unknown adapters (404) before the engine; and the ENGINE
        itself refuses adapters even if handed them directly
  D-6   score() on a logprob-capable "gen" build: genuine tokens reachable
  D-7   score() catches a forged token (verifier teeth)
  D-8   score() on a non-logprob build fails CLOSED (raises; daemon => 503)
  D-9   engine killed -> 503 ENGINE_UNAVAILABLE, no output
  D-10  witness chain (incl. DS4 inferences) verifies offline (Ed25519)
  D-11  mixed federation: DS4 node vs hash node diverge, same substrate

Run (from the build root):  python3 node/test_dwarfstar_adapter.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time


from smoke_two_nodes import get, post, wait_up, jii, verify_chain_offline  # noqa: E402
from engine_dwarfstar import DwarfStarEngine, DwarfStarError               # noqa: E402


import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_dwarfstar_adapter():
    OAI_PORT, GEN_PORT, DS_PORT, H_PORT = 31011, 31012, 8491, 8492
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:6s} {note}")


    def spawn(cmd):
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)


    def wait_engine(eng, tries=50):
        for _ in range(tries):
            if eng.healthy():
                return True
            time.sleep(0.1)
        return False


    def main():
        py = sys.executable
        oai = f"http://127.0.0.1:{OAI_PORT}"
        gen = f"http://127.0.0.1:{GEN_PORT}"
        ds = f"http://127.0.0.1:{DS_PORT}"
        hs = f"http://127.0.0.1:{H_PORT}"
        procs = [
            spawn([py, os.path.join(HERE, "mock_dwarfstar.py"), str(OAI_PORT), "oai"]),
            spawn([py, os.path.join(HERE, "mock_dwarfstar.py"), str(GEN_PORT), "gen"]),
        ]
        eng_oai = DwarfStarEngine(oai, fingerprint="fp-ds4-probe",
                                  determinism_level="reproducible")
        eng_gen = DwarfStarEngine(gen, fingerprint="fp-ds4-probe",
                                  determinism_level="reproducible",
                                  supports_logprobs=True)
        assert wait_engine(eng_oai) and wait_engine(eng_gen), "mocks did not start"

        try:
            # D-1 / D-2 dialect auto-probe + identity
            i1, i2 = eng_oai.probe(), eng_gen.probe()
            check("D-1", i1 == {"model_path": "ds4-flash", "dialect": "oai"},
                  f"oai probe: {i1['model_path']}")
            check("D-2", i2 == {"model_path": "ds4-flash", "dialect": "gen"},
                  f"gen probe: {i2['model_path']}")

            # daemon on the oai mock + a hash node for the federation check
            procs += [
                spawn([py, os.path.join(HERE, "daemon.py"),
                       "--port", str(DS_PORT), "--name", "tier1-ds4",
                       "--engine", "dwarfstar", "--engine-url", oai,
                       "--engine-determinism", "reproducible",
                       "--fingerprint", "fp-tier1-ds4", "--allow-test-hooks"]),
                spawn([py, os.path.join(HERE, "daemon.py"),
                       "--port", str(H_PORT), "--name", "tier1-hash",
                       "--fingerprint", "fp-tier1-hash", "--allow-test-hooks"]),
            ]
            caps, caps_h = wait_up(ds), wait_up(hs)

            # D-3 JII generate over the wire
            r = jii(caps, prompt="alpha beta")
            code, resp = post(ds + "/v1/messages", r)
            check("D-3", code == 200 and resp["nonce"] == r["nonce"]
                  and "witness_receipt" in resp,
                  f"output={resp['output']['content'][:32]}…")

            # D-4 determinism against the deterministic mock
            _, resp2 = post(ds + "/v1/messages", r)
            check("D-4", resp2["output"] == resp["output"], "byte-identical repeat")

            # D-5 Profile B: daemon has NO adapters configured -> 404 before
            # engine; and the engine itself refuses adapters if handed them
            code_a, bad = post(ds + "/v1/messages",
                               jii(caps, adapters=["sha256:adp-any"]))
            try:
                eng_oai.generate([{"role": "user", "content": "x"}],
                                 {"temperature": 0.0}, ["sha256:adp-any"])
                engine_refused = False
            except DwarfStarError:
                engine_refused = True
            check("D-5", code_a == 404 and "output" not in bad and engine_refused,
                  "no silent downgrade: daemon 404 + engine refusal")

            # D-6 verifier on a logprob-capable gen build: genuine completion
            msgs = [{"role": "user", "content": "gamma delta"}]
            genuine = eng_gen.generate(msgs, {"temperature": 0.0,
                                              "max_tokens": 6}).split()
            v = eng_gen.score(msgs, genuine, {"temperature": 0.0})
            check("D-6", v["ok"] and all(v["reachable"]),
                  f"{len(genuine)} tokens reachable")

            # D-7 forged token caught
            forged = list(genuine)
            forged[min(2, len(forged) - 1)] = "FORGED"
            vb = eng_gen.score(msgs, forged, {"temperature": 0.0})
            check("D-7", not vb["ok"], vb["note"])

            # D-8 non-logprob build: score fails CLOSED
            try:
                eng_oai.score(msgs, genuine, {"temperature": 0.0})
                closed = False
            except DwarfStarError as e:
                closed = "verifier role unavailable" in str(e)
            check("D-8", closed, "no logprobs -> score raises (daemon => 503)")

            # D-9 engine death -> fail closed
            procs[0].terminate()
            procs[0].wait(timeout=5)
            code, dead = post(ds + "/v1/messages", jii(caps, prompt="post-mortem"))
            check("D-9", code == 503 and "output" not in dead,
                  "engine down -> 503, no output")

            # D-10 witness chain incl. DS4 inferences verifies offline
            _, exp = get(ds + "/witness/chain")
            check("D-10", verify_chain_offline(exp) and len(exp["records"]) >= 2,
                  f"chain of {len(exp['records'])} verifies (Ed25519)")

            # D-11 mixed federation divergence
            rq = jii(caps_h, prompt="same-question")
            _, oh = post(hs + "/v1/messages", rq)
            check("D-11", oh["output"] != resp["output"] and
                  oh["provenance"]["substrate_id"] ==
                  resp["provenance"]["substrate_id"],
                  "ds4/hash divergence, shared substrate family")

        finally:
            for p in procs:
                if p.poll() is None:
                    p.terminate()
            for p in procs:
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()

        failed = sum(1 for _, ok in results if not ok)
        print(f"\nTIER-1 DWARFSTAR ADAPTER: {len(results) - failed}/{len(results)} "
              f"green" + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
        assert failed == 0, f"{failed} check(s) failed"




if __name__ == "__main__":
    test_dwarfstar_adapter()
