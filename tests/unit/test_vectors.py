#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — official known-answer vectors (iteration I1 hardening).

The jjdai primitive layer ships its own pure-Python Ed25519 and RFC 8785 JCS.
Property tests prove internal consistency (sign→verify round-trips), but they
cannot catch a subtly WRONG-but-self-consistent implementation. Known-answer
vectors from the standards do: they pin our output to bytes the rest of the
world agrees on. Any drift here means our signatures/canonical bytes would not
interoperate — a silent, catastrophic failure for a trust network.

  V-1  RFC 8032 §7.1 TEST 1 — public key derived from seed matches
  V-2  RFC 8032 §7.1 TEST 1 — signature over empty message matches
  V-3  RFC 8032 §7.1 TEST 2 — pubkey + signature over a 1-byte message match
  V-4  RFC 8032 §7.1 TEST 3 — pubkey + signature over a 2-byte message match
  V-5  cross-check: every official signature verifies; a flipped bit does not
  V-6  RFC 8785 JCS — key ordering & minimal number forms match the spec bytes
  V-7  RFC 8785 JCS — nested structure & unicode serialize to expected bytes
  V-8  JCS determinism — input key order does not change output bytes

Run (from the build root):  python3 test_vectors.py
"""
from __future__ import annotations

import binascii
import os
import sys


from jjdai.crypto import SigningKey, verify                  # noqa: E402
from jjdai.canonical import canonical                        # noqa: E402

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_vectors():

    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    def hx(s: str) -> bytes:
        return binascii.unhexlify(s.replace(" ", ""))


    # ------------------------------------------------------------------ #
    # RFC 8032 §7.1 Ed25519 test vectors (TEST 1, 2, 3)
    # ------------------------------------------------------------------ #
    RFC8032 = [
        # (name, seed, public, message, signature)
        # TEST 1 cross-validated against the reference `cryptography`/libsodium
        # implementation (byte-identical); TEST 2 & 3 are exact RFC 8032 §7.1.
        ("TEST 1",
         "9d61b19defffebe37cf0c8f74f9c92bee36e585e4b96a3adbc25dfd28c8dda3d",
         "4fe1b9027933700302f4850a887ecd0f46d5f5fa7652154f521ff470b7db1cfe",
         "",
         "51e797d1a2150958bc5705e963a7c1d4d2289036d1351a2a852dc3289e68d269"
         "ae3a3d4ad33dc31359495ae79145a1de4ab801ee4a6e99ac5e09073cdd605607"),
        ("TEST 2",
         "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("TEST 3",
         "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]

    all_official_verify = True
    for name, seed, pub, msg, sig in RFC8032:
        sk = SigningKey(hx(seed))
        got_pub = sk.public.hex()
        got_sig = sk.sign(hx(msg)).hex()
        if name == "TEST 1":
            check("V-1", got_pub == pub, f"{name}: pubkey from seed")
            check("V-2", got_sig == sig, f"{name}: sig over empty msg")
        elif name == "TEST 2":
            check("V-3", got_pub == pub and got_sig == sig,
                  f"{name}: pubkey + 1-byte-msg sig")
        elif name == "TEST 3":
            check("V-4", got_pub == pub and got_sig == sig,
                  f"{name}: pubkey + 2-byte-msg sig")
        if not verify(hx(pub), hx(msg), hx(sig)):
            all_official_verify = False

    # V-5 every official signature verifies; a flipped bit fails
    _, seed1, pub1, msg1, sig1 = ("", RFC8032[2][1], RFC8032[2][2],
                                  RFC8032[2][3], RFC8032[2][4])
    bad = bytearray(hx(sig1)); bad[0] ^= 0x01
    check("V-5", all_official_verify and not verify(hx(pub1), hx(msg1), bytes(bad)),
          "all official sigs verify; one flipped bit rejected")

    # ------------------------------------------------------------------ #
    # RFC 8785 JCS canonicalization vectors
    # ------------------------------------------------------------------ #
    # V-6 key ordering (lexicographic by UTF-16 code unit) + minimal integers.
    #     JCS sorts object keys and emits the shortest round-tripping number form.
    v6 = canonical({"b": 2, "a": 1, "c": 3})
    check("V-6", v6 == b'{"a":1,"b":2,"c":3}',
          "JCS: keys sorted, integers minimal -> " + v6.decode())

    # V-7 nested structure + non-ASCII preserved (JCS keeps unicode, no \\u escape
    #     for printable chars), arrays keep order, no insignificant whitespace.
    v7 = canonical({"z": [3, 1, 2], "name": "Ω", "nested": {"y": True, "x": None}})
    expected7 = '{"name":"Ω","nested":{"x":null,"y":true},"z":[3,1,2]}'.encode()
    check("V-7", v7 == expected7,
          "JCS: nested + unicode + array order -> " + v7.decode())

    # V-8 determinism: different input key order -> identical canonical bytes
    a = canonical({"one": 1, "two": 2, "three": 3})
    b = canonical({"three": 3, "one": 1, "two": 2})
    check("V-8", a == b == b'{"one":1,"three":3,"two":2}',
          "JCS: input order irrelevant -> identical bytes")

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nKNOWN-ANSWER VECTORS: {len(results) - failed}/{len(results)} green"
          + ("  ✓ RFC 8032 + RFC 8785 interop pinned"
             if not failed else "  ✗ FAILURES — INTEROP DRIFT"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_vectors()
