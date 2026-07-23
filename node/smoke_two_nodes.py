#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Two-Node Tier-1 Smoke Certification (v0.1)
===================================================
Whitepaper §13 step-1 milestone made executable: spin up TWO node daemons,
certify each over HTTP against the NECS contracts, and cross-audit their
Ed25519-signed witness chains OFFLINE — the auditor trusts crypto, not the
node's word.

This is the REMOTE counterpart of necs_harness.py: where the harness reaches
into `ne.chain` in-process, this suite fetches /witness/chain over the wire
and re-verifies every hash and signature with the real jjdai primitives.

Suite (R = remote):
  R-C1-a  nonce / request_id / champion_context echoed verbatim
  R-C1-b  unknown substrate -> HTTP 404, no inference
  R-C1-c  determinism: identical request twice -> byte-identical output
  R-C1-d  witness down -> HTTP 503 fail-closed, NO output (test hook)
  R-C1-e  provenance + witness_receipt present on success
  R-C2-a  missing envelope field -> HTTP 400
  R-C2-b  Profile A: good adapter serves; wrong base_compat_tag -> HTTP 422
  R-C2-c  provenance carries engine_fingerprint + determinism_level
  R-C3-a  fetched chain verifies offline (JCS re-hash + real Ed25519 sigs)
  R-C3-b  tampering with a fetched record breaks offline verification
  R-C3-c  hiding commitments: secret prompt never appears in the chain
  R-C3-d  replay from bodies reproduces the reported head (anchor-ready)
  R-C3-e  cross-node: same request -> divergent outputs, same substrate family
  R-C3-f  batch anchoring returns a Merkle root over the new records

Run (from the build root):
    python3 node/smoke_two_nodes.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import H_hex, verify                      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
GENESIS = "0" * 64
PORT_A, PORT_B = 8471, 8472
results = []


def check(tid: str, ok: bool, note: str = ""):
    results.append((tid, bool(ok)))
    print(f"  [{'PASS' if ok else 'FAIL'}] {tid:8s} {note}")


# --------------------------------------------------------------------------- #
# HTTP helpers (stdlib only)
# --------------------------------------------------------------------------- #

def get(url: str):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, json.loads(r.read().decode())


def post(url: str, obj: dict):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def wait_up(base: str, tries: int = 50):
    for _ in range(tries):
        try:
            return get(base + "/capabilities")[1]
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"node at {base} did not come up")


def jii(caps: dict, *, prompt="ping", substrate=None, adapters=None,
        drop: str = None) -> dict:
    r = {
        "substrate_id": substrate or caps["substrates"][0],
        "adapter_ids": adapters or [],
        "champion_context": "topic:demo@v1",
        "messages": [{"role": "user", "content": prompt}],
        "sampling": {"seed": 42, "temperature": 0.0, "top_p": 1.0,
                     "top_k": 0, "max_tokens": 256},
        "request_id": "uuidv7:018f-smoke",
        "nonce": "hex:7c9a-" + H_hex(prompt.encode())[:8],
    }
    if drop:
        del r[drop]
    return r


# --------------------------------------------------------------------------- #
# Offline chain verification — the auditor's half of NECS C3
# --------------------------------------------------------------------------- #

def verify_chain_offline(export: dict) -> bool:
    """Re-hash every body with JCS and check every Ed25519 signature against
    the node's published pubkey. Exactly what an independent auditor runs."""
    pub = bytes.fromhex(export["pubkey"])
    prev = GENESIS
    for i, rec in enumerate(export["records"]):
        if rec["index"] != i or rec["prev_hash"] != prev:
            return False
        body = {k: v for k, v in rec.items() if k not in ("this_hash", "sig")}
        if rec["this_hash"] != H_hex(canonical(body)):
            return False
        if not verify(pub, rec["this_hash"].encode(),
                      bytes.fromhex(rec["sig"])):
            return False
        prev = rec["this_hash"]
    return prev == export["head"] or not export["records"]


def replay_head(export: dict) -> str:
    prev = GENESIS
    for rec in export["records"]:
        body = {k: v for k, v in rec.items() if k not in ("this_hash", "sig")}
        body = dict(body)
        body["prev_hash"] = prev
        prev = H_hex(canonical(body))
    return prev


# --------------------------------------------------------------------------- #
# Spawn two nodes and certify
# --------------------------------------------------------------------------- #

def spawn(port: int, name: str, fingerprint: str, extra: list) -> subprocess.Popen:
    cmd = [sys.executable, os.path.join(HERE, "daemon.py"),
           "--port", str(port), "--name", name,
           "--fingerprint", fingerprint, "--allow-test-hooks"] + extra
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def main():
    a = f"http://127.0.0.1:{PORT_A}"
    b = f"http://127.0.0.1:{PORT_B}"
    procs = [
        spawn(PORT_A, "node-A", "fp-node-A", []),
        spawn(PORT_B, "node-B", "fp-node-B", [
            "--profile", "A",
            "--adapters", json.dumps({"sha256:adp-good": "sha256:base-A",
                                      "sha256:adp-bad": "sha256:base-OTHER"}),
        ]),
    ]
    try:
        caps_a, caps_b = wait_up(a), wait_up(b)
        print(f"node-A {caps_a['witness']['node_id'][:12]}…  "
              f"node-B {caps_b['witness']['node_id'][:12]}…\n")

        # ---- R-C1: interface --------------------------------------------- #
        r = jii(caps_a)
        code, resp = post(a + "/v1/messages", r)
        check("R-C1-a", code == 200 and resp["nonce"] == r["nonce"]
              and resp["request_id"] == r["request_id"]
              and resp["champion_context"] == r["champion_context"],
              "nonce/request_id/champion_context echoed")

        code, rb = post(a + "/v1/messages", jii(caps_a, substrate="sha256:nope"))
        check("R-C1-b", code == 404 and "output" not in rb,
              "unknown substrate rejected, no inference")

        code2, resp2 = post(a + "/v1/messages", r)
        check("R-C1-c", code2 == 200 and resp2["output"] == resp["output"],
              "byte-identical repeat (reproducible engine)")

        post(a + "/admin/witness", {"up": False})
        code, rd = post(a + "/v1/messages", jii(caps_a))
        check("R-C1-d", code == 503 and "output" not in rd,
              "fail-closed: witness down -> 503, NO output")
        post(a + "/admin/witness", {"up": True})

        check("R-C1-e", "provenance" in resp and "witness_receipt" in resp,
              "provenance + witness receipt returned")

        # ---- R-C2: substrate + provenance -------------------------------- #
        code, r400 = post(a + "/v1/messages", jii(caps_a, drop="nonce"))
        check("R-C2-a", code == 400 and r400.get("missing") == "nonce",
              "missing field -> 400 BAD_ENVELOPE")

        code_g, good = post(b + "/v1/messages",
                            jii(caps_b, adapters=["sha256:adp-good"]))
        code_x, bad = post(b + "/v1/messages",
                           jii(caps_b, adapters=["sha256:adp-bad"]))
        check("R-C2-b", code_g == 200 and "output" in good and code_x == 422,
              "adapter base_compat mismatch -> 422")

        prov = resp["provenance"]
        check("R-C2-c", bool(prov.get("engine_fingerprint"))
              and bool(prov.get("determinism_level")),
              "provenance descriptor complete")

        # ---- R-C3: witness (offline audit with REAL Ed25519) ------------- #
        for i in range(3):                      # drive a few more inferences
            post(a + "/v1/messages", jii(caps_a, prompt=f"q{i}"))
        post(a + "/v1/messages", jii(caps_a, prompt="SECRET-PLAINTEXT-XYZ"))

        _, exp_a = get(a + "/witness/chain")
        check("R-C3-a", verify_chain_offline(exp_a) and
              [x["index"] for x in exp_a["records"]] ==
              list(range(len(exp_a["records"]))),
              f"chain of {len(exp_a['records'])} verifies offline (JCS + Ed25519)")

        tampered = json.loads(json.dumps(exp_a))
        tampered["records"][1]["response_commitment"] = "sha256:tampered"
        check("R-C3-b", not verify_chain_offline(tampered),
              "tampered record caught by offline auditor")

        raw = json.dumps(exp_a["records"])
        check("R-C3-c", "SECRET-PLAINTEXT-XYZ" not in raw,
              "hiding commitments only — no plaintext on chain")

        check("R-C3-d", replay_head(exp_a) == exp_a["head"],
              "replay from bodies reproduces head")

        rq = jii(caps_a, prompt="same-question")
        _, ra = post(a + "/v1/messages", rq)
        _, rb2 = post(b + "/v1/messages", rq)
        check("R-C3-e", ra["output"] != rb2["output"] and
              ra["provenance"]["substrate_id"] == rb2["provenance"]["substrate_id"],
              "cross-node divergence, shared substrate family")

        _, anc_a = post(a + "/witness/anchor", {})
        _, anc_b = post(b + "/witness/anchor", {})
        check("R-C3-f", anc_a.get("anchored", 0) > 0 and "root" in anc_a
              and anc_b.get("anchored", 0) > 0 and "root" in anc_b,
              f"anchored roots  A:{anc_a.get('root', '')[:10]}…  "
              f"B:{anc_b.get('root', '')[:10]}…")

    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            p.wait(timeout=5)

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nTIER-1 SMOKE: {len(results) - failed}/{len(results)} green"
          + ("  ✓ both nodes certified" if not failed else "  ✗ FAILURES"))
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
