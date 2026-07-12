#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Self-tests for the jjdai primitive layer.  Run from repo root:
    python3 test_primitives.py
"""
import os, tempfile
from jjdai import canonical as jc, merkle as jm, crypto as cc
from jjdai.witness import WitnessChain

n = [0]
def ok(cond, name):
    assert cond, "FAIL: " + name
    n[0] += 1; print("  [PASS]", name)

def test_canonical():
    ok(jc.canonical(1.0) == b"1", "RFC8785: 1.0 -> 1")
    ok(jc.canonical(0.0) == b"0" and jc.canonical(-0.0) == b"0", "RFC8785: 0.0/-0.0 -> 0")
    ok(jc.canonical(0.5) == b"0.5", "RFC8785: 0.5")
    ok(jc.canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}', "RFC8785: keys sorted")
    ok(jc.canonical({"s": {"temperature": 0.0, "top_p": 1.0}})
       == b'{"s":{"temperature":0,"top_p":1}}', "RFC8785: nested float normalise")
    ok(jc.canonical("\u00e9\n") == '"\u00e9\\n"'.encode("utf-8"), "RFC8785: utf-8 literal + escape")

def test_crypto():
    sk = cc.SigningKey(bytes(range(32)))
    ok(cc.SigningKey(sk.seed).public == sk.public, "Ed25519: deterministic pubkey")
    for m in (b"", b"hi", b"x" * 999):
        s = sk.sign(m)
        ok(len(s) == 64 and cc.verify(sk.public, m, s), "Ed25519: sign/verify " + repr(m[:4]))
        ok(sk.sign(m) == s, "Ed25519: deterministic sig")
    s = sk.sign(b"hello")
    ok(not cc.verify(sk.public, b"hellp", s), "Ed25519: reject wrong msg")
    bad = bytearray(s); bad[10] ^= 1
    ok(not cc.verify(sk.public, b"hello", bytes(bad)), "Ed25519: reject tampered sig")
    ok(not cc.verify(cc.SigningKey.generate().public, b"hello", s), "Ed25519: reject wrong key")
    cm, salt = cc.commit(b"x")
    ok(cc.open_commit(cm, salt, b"x") and not cc.open_commit(cm, salt, b"y"), "commitment: open")
    ok(cc.commit(b"x")[0] != cm, "commitment: hiding (salted)")
    p = tempfile.mktemp(); cc.save_keystore(sk, p, "pw")
    ok(cc.load_keystore(p, "pw").seed == sk.seed, "keystore: round trip")
    try:
        cc.load_keystore(p, "bad"); ok(False, "keystore: reject wrong pw")
    except ValueError:
        ok(True, "keystore: reject wrong pw")
    os.remove(p)

def test_merkle():
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    root = jm.merkle_root(leaves)
    for i, l in enumerate(leaves):
        ok(jm.merkle_verify(l, jm.merkle_proof(leaves, i), root), f"merkle: proof {i}")
    ok(not jm.merkle_verify(b"z", jm.merkle_proof(leaves, 0), root), "merkle: reject absent leaf")
    ok(jm.merkle_root([b"a", b"X", b"c", b"d", b"e"]) != root, "merkle: tamper shifts root")

def test_witness():
    ch = WitnessChain()
    for i in range(4):
        ch.append("INFER", request={"content": "SECRET", "n": i},
                  response={"r": i}, provenance={"substrate_id": "s"},
                  semantic_digest="1", timestamp="2026-07-04T00:00:00Z")
    ok(ch.verify_chain(), "witness: chain verifies")
    sv = ch.records[2]["response_commitment"]; ch.records[2]["response_commitment"] = "T"
    ok(not ch.verify_chain(), "witness: tamper caught"); ch.records[2]["response_commitment"] = sv
    ok("SECRET" not in ch.raw(), "witness: hiding \u2014 no plaintext")
    ok(ch.replay() == ch.head_hash(), "witness: replayable")
    ok(ch.open(0, "request", {"content": "SECRET", "n": 0}), "witness: open with salt")
    ok(ch.anchor_root()["anchored"] == 4, "witness: anchor batches")

if __name__ == "__main__":
    for t in (test_canonical, test_crypto, test_merkle, test_witness):
        print(t.__name__ + ":"); t()
    print(f"\njjdai primitive layer \u2014 {n[0]}/{n[0]} checks green")
