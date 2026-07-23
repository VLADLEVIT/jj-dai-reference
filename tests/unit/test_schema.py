#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Typed protocol boundaries acceptance tests (v0.3.1 #5).

Each of the nine types must ACCEPT what is well-formed and REFUSE precisely
what is not — on type, range, size, enum, pattern, and unknown fields.

  T-1   NodeDescriptor: valid passes; bad pubkey (not 64-hex) rejected
  T-2   BeingDescriptor/Manifest: valid passes; bad being_id pattern rejected
  T-3   SubstrateManifest: valid passes; bad profile enum rejected
  T-4   AdapterManifest: valid passes; rank out of range rejected
  T-5   InferenceRequest: valid passes; TYPE violation (temperature "hot"),
        RANGE violation (top_p 47), SIZE violation (too many adapters),
        ENUM violation (role "root") each rejected with the right path
  T-6   InferenceReceipt: valid passes; missing provenance rejected
  T-7   VerdictEnvelope: valid passes; ok as string "true" rejected;
        min_margin > 1 rejected
  T-8   ContainmentOrder: valid passes; unknown event kind rejected
  T-9   RegistryEvent: valid passes; difficulty out of range rejected
  T-10  STRICT: an unknown field is rejected (not silently ignored)
  T-11  bool is NOT an int: sampling.max_tokens=True rejected
  T-12  errors carry path + code (machine-readable 4xx, no leak)
  T-13  LIVE: the daemon refuses a malformed request at the JII boundary
        with 400 + typed detail, and still accepts a well-formed one

Run (from the build root):  python3 test_schema.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import time


from jjdai.schema import (validate, ValidationError, MAX_ADAPTERS)  # noqa: E402

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_schema():

    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    def rejects(schema_name, obj, expect_code=None, expect_path=None):
        """True if validation refuses `obj` (optionally with a given code/path)."""
        try:
            validate(schema_name, obj)
            return False
        except ValidationError as e:
            if expect_code and e.code != expect_code:
                return False
            if expect_path and e.path != expect_path:
                return False
            return True


    def accepts(schema_name, obj):
        try:
            validate(schema_name, obj)
            return True
        except ValidationError as e:
            print(f"        (unexpected reject: {e})")
            return False


    HEX64 = "ab" * 32
    SIG = "cd" * 64

    # ---- T-1 NodeDescriptor ---------------------------------------------------- #
    nd = {"kind": "NodeDescriptor", "node_id": "node:abc123ef",
          "pubkey": HEX64, "version": "1"}
    check("T-1", accepts("NodeDescriptor", nd)
          and rejects("NodeDescriptor", dict(nd, pubkey="xyz"), "pattern"),
          "valid node descriptor; bad pubkey rejected")

    # ---- T-2 BeingDescriptor --------------------------------------------------- #
    bd = {"kind": "BeingManifest", "being_id": "being:9f3c",
          "pubkey": HEX64, "genesis_node_id": "node:abc123ef",
          "genesis_ts": 1750000000.0, "version": "1", "sig": SIG}
    check("T-2", accepts("BeingDescriptor", bd)
          and rejects("BeingDescriptor", dict(bd, being_id="not-a-being"), "pattern"),
          "valid being manifest; bad being_id pattern rejected")

    # ---- T-3 SubstrateManifest ------------------------------------------------- #
    sm = {"substrate_id": "sha256:base-A", "weights_hash": HEX64, "profile": "B"}
    check("T-3", accepts("SubstrateManifest", sm)
          and rejects("SubstrateManifest", dict(sm, profile="C"), "enum"),
          "valid substrate; profile enum enforced (A/B only)")

    # ---- T-4 AdapterManifest --------------------------------------------------- #
    am = {"adapter_id": "sha256:adp-good", "base_compat_tag": "sha256:base-A",
          "weights_hash": HEX64, "method": "lora", "rank": 16}
    check("T-4", accepts("AdapterManifest", am)
          and rejects("AdapterManifest", dict(am, rank=99999), "max_val"),
          "valid adapter; rank range enforced")

    # ---- T-5 InferenceRequest: type / range / size / enum ---------------------- #
    ir = {"substrate_id": "sha256:base-A", "adapter_ids": [],
          "messages": [{"role": "user", "content": "ping"}],
          "sampling": {"seed": 42, "temperature": 0.0, "top_p": 1.0,
                       "top_k": 0, "max_tokens": 256},
          "request_id": "uuidv7:018f", "nonce": "hex:7c9a1234"}
    bad_type = {**ir, "sampling": {**ir["sampling"], "temperature": "hot"}}
    bad_range = {**ir, "sampling": {**ir["sampling"], "top_p": 47.0}}
    bad_size = {**ir, "adapter_ids": [f"sha256:a{i}" for i in range(MAX_ADAPTERS + 5)]}
    bad_enum = {**ir, "messages": [{"role": "root", "content": "x"}]}
    check("T-5", accepts("InferenceRequest", ir)
          and rejects("InferenceRequest", bad_type, "type",
                      "InferenceRequest.sampling.temperature")
          and rejects("InferenceRequest", bad_range, "max_val")
          and rejects("InferenceRequest", bad_size, "max_items")
          and rejects("InferenceRequest", bad_enum, "enum"),
          "type/range/size/enum violations each rejected with precise path")

    # ---- T-6 InferenceReceipt -------------------------------------------------- #
    rc = {"request_id": "uuidv7:018f", "nonce": "hex:7c9a1234",
          "champion_context": "topic:demo@v1",
          "output": {"role": "assistant", "content": "out:abc"},
          "provenance": {"engine_fingerprint": "fp-1",
                         "determinism_level": "reproducible"}}
    no_prov = {k: v for k, v in rc.items() if k != "provenance"}
    check("T-6", accepts("InferenceReceipt", rc)
          and rejects("InferenceReceipt", no_prov, "missing"),
          "valid receipt; missing provenance rejected")

    # ---- T-7 VerdictEnvelope --------------------------------------------------- #
    ve = {"ok": True, "reachable": [True, True], "min_margin": 0.25,
          "verifier_fp": "fp-ver", "determinism": "attested", "note": ""}
    check("T-7", accepts("VerdictEnvelope", ve)
          and rejects("VerdictEnvelope", dict(ve, ok="true"), "type")
          and rejects("VerdictEnvelope", dict(ve, min_margin=1.5), "max_val"),
          "valid verdict; string 'true' and margin>1 rejected")

    # ---- T-8 ContainmentOrder -------------------------------------------------- #
    co = {"ev": "contain", "t": 1750000000.0, "being_id": "being:rogue",
          "initiator": "node:a1", "evidence_refs": [HEX64], "reason": "attempt",
          "topic": "cyber"}
    check("T-8", accepts("ContainmentOrder", co)
          and rejects("ContainmentOrder", dict(co, ev="obliterate"), "enum"),
          "valid order; unknown event kind rejected")

    # ---- T-9 RegistryEvent ----------------------------------------------------- #
    re_ = {"ev": "verdict", "t": 1750000000.0, "object_id": "ne:alpha",
           "topic": "maglev", "scope": "global", "ok": True, "margin": 0.3,
           "difficulty": 1.0}
    check("T-9", accepts("RegistryEvent", re_)
          and rejects("RegistryEvent", dict(re_, difficulty=500.0), "max_val"),
          "valid registry event; difficulty range enforced")

    # ---- T-10 strict: unknown field rejected ----------------------------------- #
    check("T-10", rejects("InferenceRequest", dict(ir, evil_field="payload"),
                          "unknown"),
          "unknown field rejected, not silently ignored (fail-closed)")

    # ---- T-11 bool is not an int ----------------------------------------------- #
    bool_tokens = {**ir, "sampling": {**ir["sampling"], "max_tokens": True}}
    check("T-11", rejects("InferenceRequest", bool_tokens, "type"),
          "bool refused where int expected (Python's True==1 is a hazard)")

    # ---- T-12 error carries path + code ---------------------------------------- #
    try:
        validate("InferenceRequest", bad_range)
        err = None
    except ValidationError as e:
        err = e.as_dict()
    check("T-12", err and err["path"] == "InferenceRequest.sampling.top_p"
          and err["code"] == "max_val" and "above" in err["detail"],
          f"machine-readable error: {err['path']} [{err['code']}]" if err else "")

    # ---- T-13 LIVE daemon refuses at the boundary ------------------------------ #
    from smoke_two_nodes import get, post, wait_up, jii                # noqa: E402

    PORT = 8531
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "daemon.py"),
         "--port", str(PORT), "--name", "typed", "--fingerprint", "fp-typed"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{PORT}"
        caps = wait_up(base)
        good_code, good = post(base + "/v1/messages", jii(caps, prompt="alpha"))
        malformed = jii(caps, prompt="alpha")
        malformed["sampling"] = dict(malformed["sampling"], temperature="hot")
        bad_code, bad = post(base + "/v1/messages", malformed)
        unknown = jii(caps, prompt="alpha")
        unknown["injected"] = "surprise"
        unk_code, unk = post(base + "/v1/messages", unknown)
        check("T-13", good_code == 200 and "output" in good
              and bad_code == 400 and bad["detail"]["code"] == "type"
              and "output" not in bad
              and unk_code == 400 and unk["detail"]["code"] == "unknown",
              "live JII boundary: well-formed 200; bad type & unknown field -> 400")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nTYPED PROTOCOL BOUNDARIES: {len(results) - failed}/{len(results)} "
          "green" + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_schema()
