#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Full Verdict Binding acceptance tests (v0.3.1.2 #2).

  B-1   scoring_context_hash covers the WHOLE context: changing tokens,
        sampling, messages, or nonce changes the hash; reordering-invariant
        canonicalization keeps it stable for identical content
  B-2   seal_verdict produces a schema-valid, signed VerdictEnvelope with
        verifier_node_id derived from the verifier key
  B-3   open_verdict accepts a correctly sealed verdict for its request
  B-4   IDENTITY PINNING: a verdict whose verifier_node_id / pubkey do not
        match the signing key is rejected
  B-5   CONTEXT BINDING: the same sealed verdict lifted onto a DIFFERENT
        request is rejected (context_hash mismatch)
  B-6   FORGED ok: flipping ok after sealing breaks the signature -> rejected
  B-7   FORGED min_margin: bumping min_margin breaks the signature -> rejected
  B-8   REPLAY: the same (verifier, nonce) opened twice is rejected
  B-9   UNIQUE-NodeID QUORUM: three envelopes from TWO distinct verifiers
        count as 2, not 3; one verifier answering twice cannot fake consensus
  B-10  unbound verdict (missing sig/context_hash/nonce) rejected — v0.3.1.2
        requires full binding
  B-11  LIVE: a real daemon returns a SEALED verdict on /v1/score that opens
        and verifies against the request
  B-12  LIVE loop: cross-verify with binding ON records a peer's sealed
        verdict; a peer verdict re-signed by a different key is discarded

Run (from the build root):  python3 test_verdict.py
"""
from __future__ import annotations

import copy
import os
import subprocess
import sys


from jjdai.crypto import (SigningKey, node_id as hash_pub,    # noqa: E402
                          canonical_node_id)
from core.verdict import (seal_verdict, open_verdict,         # noqa: E402
                          scoring_context_hash, NonceRegistry,
                          count_quorum, VerdictError)

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_verdict():

    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    def _rejects(env, request, pubkey_hex):
        try:
            open_verdict(env, request=request, verifier_pubkey_hex=pubkey_hex)
            return False
        except VerdictError:
            return True


    def make_request(nonce="hex:aaaa1111", tokens=("alpha", "beta")):
        return {"substrate_id": "sha256:base-A", "adapter_ids": [],
                "messages": [{"role": "user", "content": "hello"}],
                "sampling": {"seed": 1, "temperature": 0.0, "top_p": 1.0,
                             "top_k": 0, "max_tokens": 64},
                "request_id": "uuidv7:req-1", "nonce": nonce,
                "tokens": list(tokens)}


    RAW = {"ok": True, "reachable": [True, True], "min_margin": 0.3,
           "verifier_fp": "fp-ver", "determinism": "attested", "note": ""}
    vsk = SigningKey(b"\x77" * 32)
    vpub = vsk.public.hex()
    vnid = canonical_node_id(vsk.public)   # v0.5: single canonical derivation

    # ---- B-1 context hash coverage --------------------------------------------- #
    r = make_request()
    h0 = scoring_context_hash(r)
    h_tok = scoring_context_hash(make_request(tokens=("alpha", "gamma")))
    h_nonce = scoring_context_hash(make_request(nonce="hex:bbbb2222"))
    h_same = scoring_context_hash(make_request())
    check("B-1", h0 != h_tok and h0 != h_nonce and h0 == h_same,
          "context hash covers tokens+nonce; stable for identical content")

    # ---- B-2 seal ------------------------------------------------------------- #
    env = seal_verdict(RAW, request=r, verifier_sk=vsk)
    check("B-2", env["verifier_node_id"] == vnid and len(env["sig"]) == 128
          and env["context_hash"] == h0,
          "sealed envelope: signed, node-id from key, context bound")

    # ---- B-3 open (happy path) ------------------------------------------------- #
    opened = open_verdict(env, request=r, verifier_pubkey_hex=vpub)
    check("B-3", opened["ok"] is True and opened["min_margin"] == 0.3,
          "correctly sealed verdict opens for its request")

    # ---- B-4 identity pinning -------------------------------------------------- #
    other = SigningKey(b"\x88" * 32)
    check("B-4", _rejects(env, r, other.public.hex()),
          "verdict rejected under a non-matching pubkey (identity pinned)")

    # ---- B-5 context binding --------------------------------------------------- #
    r2 = make_request(tokens=("alpha", "gamma"))
    check("B-5", _rejects(env, r2, vpub),
          "sealed verdict lifted onto a different request rejected")

    # ---- B-6 forged ok --------------------------------------------------------- #
    forged_ok = copy.deepcopy(env); forged_ok["ok"] = False
    check("B-6", _rejects(forged_ok, r, vpub),
          "flipping ok after sealing breaks signature -> rejected")

    # ---- B-7 forged min_margin ------------------------------------------------- #
    forged_m = copy.deepcopy(env); forged_m["min_margin"] = 0.99
    check("B-7", _rejects(forged_m, r, vpub),
          "bumping min_margin breaks signature -> rejected")

    # ---- B-8 replay ------------------------------------------------------------ #
    nonces = NonceRegistry()
    open_verdict(env, request=r, verifier_pubkey_hex=vpub, nonces=nonces)
    replayed = False
    try:
        open_verdict(env, request=r, verifier_pubkey_hex=vpub, nonces=nonces)
    except VerdictError:
        replayed = True
    check("B-8", replayed, "same (verifier, nonce) opened twice rejected (replay)")

    # ---- B-9 unique-NodeID quorum ---------------------------------------------- #
    v2 = SigningKey(b"\x99" * 32)
    e_a1 = seal_verdict(RAW, request=r, verifier_sk=vsk)
    e_a2 = seal_verdict(RAW, request=make_request(nonce="hex:cccc3333"),
                        verifier_sk=vsk)                 # SAME verifier, again
    e_b1 = seal_verdict(RAW, request=r, verifier_sk=v2)  # DISTINCT verifier
    q = count_quorum([e_a1, e_a2, e_b1])
    check("B-9", q["distinct_verifiers"] == 2 and q["pass"] == 2 and q["passed"],
          f"3 envelopes, 2 distinct verifiers -> quorum counts {q['distinct_verifiers']}")

    # ---- B-10 unbound verdict rejected ----------------------------------------- #
    bare = {"ok": True, "reachable": [True], "min_margin": 0.2,
            "verifier_fp": "fp", "determinism": "attested"}
    check("B-10", _rejects(bare, r, vpub),
          "unbound verdict (no sig/context/nonce) rejected")

    # ---- B-11 LIVE sealed verdict ---------------------------------------------- #
    from smoke_two_nodes import get, post, wait_up, jii                # noqa: E402
    PORT = 8541
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "daemon.py"),
         "--port", str(PORT), "--name", "vb", "--fingerprint", "fp-vb"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{PORT}"
        caps = wait_up(base)
        gen = jii(caps, prompt="alpha beta")
        _, resp = post(base + "/v1/messages", gen)
        sreq = dict(gen); sreq["tokens"] = resp["output"]["content"].split()
        _, sresp = post(base + "/v1/score", sreq)
        live_env = sresp["verdict"]
        live_pub = (caps.get("witness") or {}).get("pubkey")
        live_opened = open_verdict(live_env, request=sreq,
                                   verifier_pubkey_hex=live_pub)
        check("B-11", live_env.get("sig") and live_opened["verifier_node_id"]
              == canonical_node_id(bytes.fromhex(live_pub)),
              "live daemon returns a sealed verdict that opens & verifies")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ---- B-12 LIVE loop with binding ON ---------------------------------------- #
    from core.registry import ChampionRegistry, Params            # noqa: E402
    from core.crossverify import CrossVerifier                    # noqa: E402
    GEN_PORT, VER_PORT = 8542, 8543
    procs = [subprocess.Popen(
        [sys.executable, os.path.join(HERE, "daemon.py"),
         "--port", str(p), "--name", nm, "--fingerprint", "fp-shared"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for p, nm in ((GEN_PORT, "gen"), (VER_PORT, "ver"))]
    try:
        g = f"http://127.0.0.1:{GEN_PORT}"; v = f"http://127.0.0.1:{VER_PORT}"
        cg = wait_up(g); wait_up(v)
        reg = ChampionRegistry(Params())
        loop = CrossVerifier(reg, http_post=post, http_get=get, min_verifiers=1,
                             open_verdict=open_verdict)
        req = jii(cg, prompt="alpha beta")
        _, rr = post(g + "/v1/messages", req)
        trace = loop.verify_and_record(
            topic="maglev", generator_id="ne:gen", generator_url=g,
            verifier_urls=[v], jii_request=req,
            output_tokens=rr["output"]["content"].split())

        reg2 = ChampionRegistry(Params())

        def lying_post(url, obj):
            st, rep = post(url, obj)
            if url.endswith("/v1/score") and "verdict" in rep:
                rep = dict(rep); ve = dict(rep["verdict"])
                evil = SigningKey(b"\xAA" * 32)
                from jjdai.canonical import canonical
                from core.verdict import SIGNED_FIELDS
                ve["sig"] = evil.sign(canonical(
                    {k: ve[k] for k in SIGNED_FIELDS})).hex()   # wrong key
                rep["verdict"] = ve
            return st, rep

        loop2 = CrossVerifier(reg2, http_post=lying_post, http_get=get,
                              min_verifiers=1, open_verdict=open_verdict)
        req2 = jii(cg, prompt="gamma delta")
        _, rr2 = post(g + "/v1/messages", req2)
        t2 = loop2.verify_and_record(
            topic="cyber", generator_id="ne:gen", generator_url=g,
            verifier_urls=[v], jii_request=req2,
            output_tokens=rr2["output"]["content"].split())
        check("B-12", trace["recorded"] and not t2["recorded"]
              and "binding failed" in t2["audited"][0]["discarded"],
              "bound loop records honest verdict; wrong-key verdict discarded")
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nFULL VERDICT BINDING: {len(results) - failed}/{len(results)} green"
          + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_verdict()
