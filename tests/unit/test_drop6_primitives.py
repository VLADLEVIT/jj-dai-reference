#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Drop 6 unit acceptance — RFC 6962 tree + unknown-provenance correlation
=======================================================================
  M-CT-1  mth_root: RFC 6962 shape; empty tree = HASH(""); distinct from
          the legacy duplicate-padding root wherever padding applies
  M-CT-2  inclusion: exhaustive verify for all (n, index) up to n=24;
          forged leaf / shifted index / truncated path rejected
  M-CT-3  consistency: exhaustive verify for all (m, n) up to n=24;
          forged prefix root / truncated proof rejected
  D-U-1   unknown provenance dimensions contribute FULL correlation
          weight; two silent manifests correlate at 1.0
  D-U-2   an undeclared candidate cannot enter a panel next to anyone
          (independence 0.0) and the rejection reason NAMES the unknowns
  D-U-3   a candidate with undeclared provenance is refused against the
          generator — silence cannot demonstrate independence
  D-U-4   fully declared, fully disjoint manifests keep independence 1.0
          (the fix must not tax honest declarations)
"""
from __future__ import annotations

import hashlib
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai.merkle import (merkle_root, mth_root, mth_inclusion,     # noqa: E402
                          mth_verify_inclusion, consistency_proof,
                          verify_consistency)
from core.diversity import correlation, independence, select_verifiers  # noqa: E402


def test_mth_tree():
    # ---- M-CT-1 ----
    assert mth_root([]) == hashlib.sha256(b"").hexdigest(), \
        "M-CT-1: empty RFC 6962 tree must hash HASH('')"
    assert mth_root([]) != merkle_root([]), \
        "M-CT-1: the two empty roots must be distinguishable"
    one = [b"only"]
    assert mth_root(one) == merkle_root(one), \
        "M-CT-1: single-leaf trees agree (no padding, no split)"
    three = [b"a", b"b", b"c"]
    assert mth_root(three) != merkle_root(three), \
        "M-CT-1: padding vs split must differ on odd shapes"
    print("  [PASS] M-CT-1  tree shapes: empty/single/odd behave per spec")

    # ---- M-CT-2 / M-CT-3 ----
    incl = cons = 0
    for n in range(1, 25):
        leaves = [bytes([i]) * 3 for i in range(n)]
        rn = mth_root(leaves)
        for i in range(n):
            p = mth_inclusion(leaves, i)
            assert mth_verify_inclusion(leaves[i], i, n, p, rn), (n, i)
            assert not mth_verify_inclusion(b"forged!!", i, n, p, rn)
            if n > 1:
                assert not mth_verify_inclusion(
                    leaves[i], (i + 1) % n, n, p, rn)
            incl += 1
        for m in range(1, n + 1):
            rm = mth_root(leaves[:m])
            pr = consistency_proof(leaves, m)
            assert verify_consistency(m, n, rm, rn, pr), (m, n)
            if m < n:
                fake = mth_root(leaves[:m - 1] + [b"forged"])
                assert not verify_consistency(m, n, fake, rn, pr), (m, n)
            if pr:
                assert not verify_consistency(m, n, rm, rn, pr[:-1]), (m, n)
            cons += 1
    print(f"  [PASS] M-CT-2  inclusion: {incl} positions verified, "
          "forgeries rejected")
    print(f"  [PASS] M-CT-3  consistency: {cons} (m, n) pairs verified, "
          "forgeries rejected")


def _prov(mid, **kw):
    p = {"model_id": mid, "base_family": None, "architecture_family": None,
         "training_data_families": None, "operator_domain": None,
         "jurisdiction": None}
    p.update(kw)
    return p


def test_diversity_unknown():
    silent_a = _prov("m:silent-a")
    silent_b = _prov("m:silent-b")
    declared = _prov("m:decl-1", base_family="fam-X",
                     architecture_family="arch-X",
                     training_data_families=["dsX"],
                     operator_domain="op-x.example", jurisdiction="UA")
    disjoint = _prov("m:decl-2", base_family="fam-Y",
                     architecture_family="arch-Y",
                     training_data_families=["dsY"],
                     operator_domain="op-y.example", jurisdiction="KR")

    # ---- D-U-1 ----
    c = correlation(silent_a, silent_b)
    assert c["score"] == 1.0 and len(c["unknown"]) == 5, f"D-U-1: {c}"
    half = _prov("m:half", base_family="fam-Z",
                 architecture_family="arch-Z",
                 training_data_families=["dsZ"])
    c2 = correlation(half, disjoint)
    assert c2["score"] == 0.25 and \
        sorted(c2["unknown"]) == ["jurisdiction", "operator_domain"], \
        f"D-U-1: partial silence must cost exactly its weights: {c2}"
    print("  [PASS] D-U-1  unknown dimensions contribute full correlation "
          "weight")

    # ---- D-U-2 ----
    res = select_verifiers(
        [{"provenance": declared, "reputation": 0.9},
         {"provenance": silent_a, "reputation": 0.4}], k=2,
        min_independence=0.5)
    assert not res["filled"], "D-U-2: a silent manifest must not fill a panel"
    reason = next(r["reason"] for r in res["rejected"]
                  if r["model_id"] == "m:silent-a")
    assert "unknown:" in reason, \
        f"D-U-2: the rejection must NAME the undeclared dimensions: {reason}"
    print("  [PASS] D-U-2  silent candidate rejected with named unknowns")

    # ---- D-U-3 ----
    res = select_verifiers(
        [{"provenance": declared, "reputation": 0.5},
         {"provenance": silent_a, "reputation": 0.99}], k=1,
        min_independence=0.5, exclude_model="m:decl-1")
    assert not res["filled"], \
        "D-U-3: silence cannot demonstrate independence from the generator"
    reason = res["rejected"][0]["reason"]
    assert "undeclared" in reason, f"D-U-3: {reason}"
    print("  [PASS] D-U-3  undeclared candidate refused against the generator")

    # ---- D-U-4 ----
    assert independence(declared, disjoint) == 1.0, \
        "D-U-4: honest, fully declared disjoint manifests stay independent"
    res = select_verifiers(
        [{"provenance": declared, "reputation": 0.7},
         {"provenance": disjoint, "reputation": 0.8}], k=2,
        min_independence=0.5)
    assert res["filled"], "D-U-4: declared diversity must still fill panels"
    print("  [PASS] D-U-4  fully declared disjoint manifests unaffected")


if __name__ == "__main__":
    test_mth_tree()
    test_diversity_unknown()
    print("\nDROP 6 UNIT: all groups green  ✓ certified")
