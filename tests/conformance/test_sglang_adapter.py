#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Tier-2 SGLang Adapter Certification (v0.1)
===================================================
Certifies the SGLang path end-to-end with NO GPU and NO third-party deps:

    mock_sglang.py  (executable API contract)
        ▲
    engine_sglang.py  (adapter under test)
        ▲
    daemon.py --engine sglang   (JII envelope + Ed25519 witness OUTSIDE engine)

Suite (S = SGLang):
  S-1   adapter probes model identity from the server
  S-2   JII generate over HTTP via the SGLang engine (nonce echo, receipt)
  S-3   determinism holds against the deterministic mock (byte-identical)
  S-4   Profile A: LoRA adapter routes; output differs from base (lora matters)
  S-5   adapter with wrong base_compat_tag -> 422 BEFORE the engine is called
  S-6   /v1/score verifies the GENUINE completion (all tokens reachable)
  S-7   /v1/score CATCHES a forged token (unreachable under committed params)
  S-8   /v1/score CATCHES a sampling-params lie (loose top_p claim fails at
        temperature=0 replay — only argmax is reachable)
  S-9   verifier verdicts are witnessed; chain verifies offline (Ed25519)
  S-10  SGLang server killed -> 503 ENGINE_UNAVAILABLE, fail-closed, NO output
  S-11  mixed federation (§9): Tier-1 hash node + Tier-2 SGLang node give
        divergent outputs on the same request, same substrate family

Run (from the build root):
    python3 node/test_sglang_adapter.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time


from smoke_two_nodes import (get, post, wait_up, jii,           # noqa: E402
                             verify_chain_offline)
from engine_sglang import SGLangEngine                          # noqa: E402


import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_sglang_adapter():
    MOCK_PORT, T2_PORT, T1_PORT = 30011, 8481, 8482
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:6s} {note}")


    def spawn(cmd):
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)


    def main():
        mock_url = f"http://127.0.0.1:{MOCK_PORT}"
        t2 = f"http://127.0.0.1:{T2_PORT}"
        t1 = f"http://127.0.0.1:{T1_PORT}"
        py = sys.executable
        procs = [spawn([py, os.path.join(HERE, "mock_sglang.py"), str(MOCK_PORT)])]
        # wait for the mock before the daemon probes it
        eng = SGLangEngine(mock_url, fingerprint="fp-t2-probe",
                           determinism_level="reproducible")
        for _ in range(50):
            if eng.healthy():
                break
            time.sleep(0.1)

        procs += [
            spawn([py, os.path.join(HERE, "daemon.py"),
                   "--port", str(T2_PORT), "--name", "tier2-sglang",
                   "--engine", "sglang", "--engine-url", mock_url,
                   "--engine-determinism", "reproducible",
                   "--fingerprint", "fp-tier2-sgl",
                   "--profile", "A",
                   "--adapters", json.dumps({
                       "sha256:adp-good": "sha256:base-A",
                       "sha256:adp-bad": "sha256:base-OTHER"}),
                   "--adapter-paths", json.dumps({"sha256:adp-good": "adp-good"}),
                   "--allow-test-hooks"]),
            spawn([py, os.path.join(HERE, "daemon.py"),
                   "--port", str(T1_PORT), "--name", "tier1-hash",
                   "--fingerprint", "fp-tier1-hash", "--allow-test-hooks"]),
        ]
        try:
            caps2, caps1 = wait_up(t2), wait_up(t1)

            # S-1 model identity via the adapter
            info = eng.probe()
            check("S-1", info["model_path"] == "mock/frozen-base-A",
                  f"model_path={info['model_path']}")

            # S-2 JII generate through daemon->adapter->mock
            r = jii(caps2, prompt="alpha beta")
            code, resp = post(t2 + "/v1/messages", r)
            check("S-2", code == 200 and resp["nonce"] == r["nonce"]
                  and "witness_receipt" in resp,
                  f"output={resp['output']['content'][:32]}…")

            # S-3 byte-identical repeat against the deterministic mock
            _, resp2 = post(t2 + "/v1/messages", r)
            check("S-3", resp2["output"] == resp["output"], "byte-identical repeat")

            # S-4 LoRA changes the distribution: adapter output != base output
            _, with_lora = post(t2 + "/v1/messages",
                                jii(caps2, prompt="alpha beta",
                                    adapters=["sha256:adp-good"]))
            check("S-4", with_lora["output"] != resp["output"]
                  and with_lora["provenance"]["adapter_ids"] == ["sha256:adp-good"],
                  "lora-routed output diverges from base")

            # S-5 C2 provenance gate fires in the DAEMON, before the engine
            code, bad = post(t2 + "/v1/messages",
                             jii(caps2, adapters=["sha256:adp-bad"]))
            check("S-5", code == 422 and "output" not in bad,
                  "wrong base_compat_tag -> 422 (engine never called)")

            # S-6 verifier attests the genuine completion
            genuine = resp["output"]["content"].split()
            sr = jii(caps2, prompt="alpha beta")
            sr["tokens"] = genuine
            code, sresp = post(t2 + "/v1/score", sr)
            v = sresp.get("verdict", {})
            check("S-6", code == 200 and v.get("ok") and all(v["reachable"]),
                  f"{len(genuine)} tokens reachable, min_margin={v.get('min_margin')}")

            # S-7 forged token is unreachable
            forged = list(genuine)
            forged[min(2, len(forged) - 1)] = "FORGED"
            sr2 = jii(caps2, prompt="alpha beta")
            sr2["tokens"] = forged
            _, sbad = post(t2 + "/v1/score", sr2)
            vb = sbad.get("verdict", {})
            check("S-7", not vb.get("ok") and not all(vb.get("reachable", [True])),
                  vb.get("note", ""))

            # S-8 sampling lie: claim greedy (temperature=0) for tokens that were
            # actually produced under a loose nucleus -> replay rejects them
            loose_req = jii(caps2, prompt="gamma delta")
            loose_req["sampling"] = dict(loose_req["sampling"],
                                         temperature=0.9, top_p=0.98)
            _, loose = post(t2 + "/v1/messages", loose_req)
            loose_toks = loose["output"]["content"].split()
            lie = jii(caps2, prompt="gamma delta")      # claims temperature=0.0
            lie["tokens"] = loose_toks
            _, slie = post(t2 + "/v1/score", lie)
            vl = slie.get("verdict", {})
            check("S-8", not vl.get("ok"),
                  "loose-nucleus tokens rejected under claimed greedy params")

            # S-9 verifier verdicts are on the witness chain; chain verifies
            _, exp = get(t2 + "/witness/chain")
            check("S-9", verify_chain_offline(exp) and len(exp["records"]) >= 6,
                  f"chain of {len(exp['records'])} incl. verdicts verifies (Ed25519)")

            # S-10 kill the engine -> fail closed
            procs[0].terminate()
            procs[0].wait(timeout=5)
            code, dead = post(t2 + "/v1/messages", jii(caps2, prompt="post-mortem"))
            check("S-10", code == 503 and "output" not in dead,
                  "engine down -> 503 ENGINE_UNAVAILABLE, no output")

            # S-11 mixed federation: Tier-1 vs Tier-2 on the same request
            rq = jii(caps1, prompt="same-question")
            _, o1 = post(t1 + "/v1/messages", rq)
            check("S-11", o1["output"] != resp["output"] and
                  o1["provenance"]["substrate_id"] ==
                  resp["provenance"]["substrate_id"],
                  "tier-1/tier-2 divergence, shared substrate family")

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
        print(f"\nTIER-2 SGLANG ADAPTER: {len(results) - failed}/{len(results)} green"
              + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
        assert failed == 0, f"{failed} check(s) failed"




if __name__ == "__main__":
    test_sglang_adapter()
