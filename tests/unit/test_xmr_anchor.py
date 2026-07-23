#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.5.2 unit acceptance — Monero anchoring primitives
====================================================
  X-K   Keccak-256 is the LEGACY Keccak (0x01 padding): known vectors,
        explicitly different from NIST SHA3-256; multi-block absorption
  X-B   Monero block-wise base58: full/partial block sizes, alphabet
  X-D   THE VECTOR: root d2a8…4a26 derives the exact mainnet address
        monero-wallet-cli produced for the same spend key (validates
        keccak + sc_reduce32 + deterministic view key + ed25519
        scalarmult + varint prefix + checksum + base58 in one shot);
        network prefixes distinct; malformed roots refused
  X-R   receipt binding verifies offline: right root -> ok; wrong root,
        wrong network, unknown derivation tag -> refused with reasons
  X-S   derivation is deterministic and root-sensitive (1-bit avalanche
        on the address)
"""
from __future__ import annotations

import hashlib
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.anchoring_xmr import (keccak256, base58_xmr,             # noqa: E402
                                keys_from_root, xmr_address_from_root,
                                verify_receipt_binding,
                                XMR_DERIVATION, XmrAnchorError)

VECTOR_ROOT = "d2a84f4b8b650937ec8f73cd8be2c74add5a911ba64df27458ed8229da804a26"
VECTOR_ADDR = ("437M8FuCJFAhUC3kLvn1iYDDn2uUbi36gaidRPQigUgZAwfmGCL8ZS1C76NFL"
               "rZjN4EEgVBEBeD4D2MJKEWSW936BQXCYTB")


def test_keccak_legacy():
    assert keccak256(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"abc").hex() == \
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    assert keccak256(b"") != hashlib.sha3_256(b"").digest(), \
        "X-K: legacy Keccak must differ from NIST SHA-3 padding"
    big = b"\xa5" * 1000                       # crosses several 136B blocks
    assert len(keccak256(big)) == 32 and keccak256(big) == keccak256(big)
    print("  [PASS] X-K  legacy Keccak-256: vectors, != SHA3-256, "
          "multi-block")


def test_base58_blocks():
    assert base58_xmr(b"") == ""
    assert len(base58_xmr(b"\x00" * 8)) == 11, "full block -> 11 chars"
    assert len(base58_xmr(b"\x00" * 69)) == 95, "std address size -> 95 chars"
    assert base58_xmr(b"\x00" * 8) == "1" * 11, "zero block is all ones"
    for ch in base58_xmr(os.urandom(64)):
        assert ch not in "0OIl", "X-B: ambiguous glyphs are excluded"
    print("  [PASS] X-B  Monero block base58: sizes, zero block, alphabet")


def test_derivation_vector():
    addr = xmr_address_from_root(VECTOR_ROOT, "mainnet")
    assert addr == VECTOR_ADDR, f"X-D: derivation drifted:\n{addr}"
    k = keys_from_root(VECTOR_ROOT)
    from jjdai.crypto import _L
    b_sec = int.from_bytes(bytes.fromhex(k["spend_sec"]), "little")
    assert b_sec < _L and b_sec == \
        int.from_bytes(bytes.fromhex(VECTOR_ROOT), "little") % _L, \
        "X-D: the spend scalar must be the reduced root (as wallet-cli " \
        "reduces it — the address match above proves both sides agree)"
    tn = xmr_address_from_root(VECTOR_ROOT, "testnet")
    sn = xmr_address_from_root(VECTOR_ROOT, "stagenet")
    assert len({addr, tn, sn}) == 3 and tn[0] != addr[0], \
        "X-D: network prefixes must produce distinct addresses"
    for bad in ("zz" * 32, "ab", ""):
        try:
            xmr_address_from_root(bad)
            assert False, f"X-D: malformed root accepted: {bad!r}"
        except (XmrAnchorError, ValueError):
            pass
    print("  [PASS] X-D  wallet-cli vector reproduced byte-for-byte; "
          "networks distinct; malformed roots refused")


def test_receipt_binding():
    receipt = {"backend": "xmr", "network": "mainnet",
               "derivation": XMR_DERIVATION, "address": VECTOR_ADDR,
               "root": VECTOR_ROOT, "count": 7, "status":
               "pending-confirmation", "ts": 0.0}
    assert verify_receipt_binding(VECTOR_ROOT, receipt) == (True, "ok")
    other_root = "ab" * 32
    ok, why = verify_receipt_binding(other_root, receipt)
    assert not ok and "derive" in why, "X-R: wrong root must be refused"
    wrong_net = dict(receipt, network="stagenet")
    ok, _ = verify_receipt_binding(VECTOR_ROOT, wrong_net)
    assert not ok, "X-R: a receipt for another network must not bind"
    unknown = dict(receipt, derivation="future-v9")
    ok, why = verify_receipt_binding(VECTOR_ROOT, unknown)
    assert not ok and "derivation" in why, \
        "X-R: unknown derivation tags fail closed"
    print("  [PASS] X-R  binding: right root ok; wrong root/network/"
          "derivation refused")


def test_avalanche():
    a = xmr_address_from_root("00" * 32)
    flipped = "01" + "00" * 31
    b = xmr_address_from_root(flipped)
    assert a != b and a == xmr_address_from_root("00" * 32), \
        "X-S: deterministic and root-sensitive"
    print("  [PASS] X-S  deterministic; 1-bit root flip changes the address")


if __name__ == "__main__":
    test_keccak_legacy()
    test_base58_blocks()
    test_derivation_vector()
    test_receipt_binding()
    test_avalanche()
    print("\nXMR ANCHOR UNIT: all groups green  ✓ certified")
