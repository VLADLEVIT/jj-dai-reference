#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manifests + diversity selection (v0.5, P1) — acceptance
=======================================================
  M-1  substrate manifest signs and verifies offline; tampering fails
  M-2  adapter manifest binds to a substrate; provenance composition
       refuses a mismatched binding
  M-3  registry verifies before holding; conflicting re-registration of
       an immutable id is refused; identical re-registration idempotent
  M-4  publisher ACL fails closed when enabled
  M-5  registry persistence: manifests reload from disk
  M-6  provenance is DERIVED: lineage/architecture from the substrate,
       data families are the union of substrate+adapters
  D-1  correlation extremes: clones -> 1.0 (independence 0), fully
       disjoint provenances -> independence 1.0
  D-2  min pairwise independence is enforced with a named clash reason
  D-3  correlation-group cap: no two panel members share a base family
       when max_per_group=1
  D-4  FAIL HONEST: an insufficient pool returns a SHORT panel with
       diagnostics, never silently relaxed constraints
  D-5  reputation orders admission subject to constraints
  D-6  generator exclusion: a model never verifies itself, and its
       full clones are refused
"""
from __future__ import annotations

import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import canonical_node_id, SigningKey, node_id, H_hex                 # noqa: E402
from core.manifests import (ManifestRegistry, ManifestError,        # noqa: E402
                            make_substrate_manifest,
                            make_adapter_manifest, verify_manifest)
from core.diversity import (correlation, independence,              # noqa: E402
                            select_verifiers)


def _sid(tag):
    return "sha256:" + H_hex(tag.encode())


def _prov(mid, base, arch, data, op, jur):
    return {"kind": "PROVENANCE_MANIFEST", "model_id": mid,
            "substrate_id": _sid(mid), "adapter_ids": [],
            "base_family": base, "architecture_family": arch,
            "training_data_families": sorted(data),
            "operator_domain": op, "jurisdiction": jur}


def test_manifests():
    sk = SigningKey.generate()
    sk2 = SigningKey.generate()

    # ---- M-1 ----
    sub = make_substrate_manifest(
        sk, substrate_id=_sid("dwarf-7b"), name="DwarfStar-7B",
        version="1.0", base_family="dwarfstar", architecture_family="llama",
        training_data_families=["web-2025", "code-2025"], profile="B")
    ok, why = verify_manifest(sub)
    assert ok, f"M-1: {why}"
    tampered = {"body": dict(sub["body"], version="6.6"),
                "pub": sub["pub"], "sig": sub["sig"]}
    ok, _ = verify_manifest(tampered)
    assert not ok, "M-1: tampered manifest must fail"

    # ---- M-2 ----
    adp = make_adapter_manifest(
        sk, adapter_id=_sid("adp-energy"), base_compat_tag=_sid("dwarf-7b"),
        task_domain="energy", training_data_families=["aton-docs"])
    ok, why = verify_manifest(adp)
    assert ok, f"M-2: {why}"

    with tempfile.TemporaryDirectory() as tmp:
        reg = ManifestRegistry(os.path.join(tmp, "manifests.jsonl"))
        reg.register(sub)
        reg.register(adp)

        try:
            reg.provenance(model_id="m-x", substrate_id=_sid("dwarf-7b"),
                           adapter_ids=[_sid("adp-alien")])
        except ManifestError:
            pass
        else:
            raise AssertionError("M-2: unknown adapter must be refused")
        alien = make_adapter_manifest(
            sk, adapter_id=_sid("adp-alien"), base_compat_tag=_sid("other"),
            task_domain="x", training_data_families=[])
        reg.register(alien)
        try:
            reg.provenance(model_id="m-x", substrate_id=_sid("dwarf-7b"),
                           adapter_ids=[_sid("adp-alien")])
        except ManifestError as e:
            assert "bound to" in str(e), f"M-2: wrong reason {e}"
        else:
            raise AssertionError("M-2: mismatched binding must be refused")

        # ---- M-3 ----
        assert reg.register(sub) == _sid("dwarf-7b"), "M-3: idempotent"
        conflicting = make_substrate_manifest(
            sk, substrate_id=_sid("dwarf-7b"), name="DwarfStar-7B-EVIL",
            version="1.0", base_family="dwarfstar",
            architecture_family="llama",
            training_data_families=["web-2025"], profile="B")
        try:
            reg.register(conflicting)
        except ManifestError as e:
            assert "immutable" in str(e), f"M-3: wrong reason {e}"
        else:
            raise AssertionError("M-3: conflicting re-registration allowed")

        # ---- M-4 ----
        acl_reg = ManifestRegistry(
            None, allowed_publishers={canonical_node_id(sk.public)})
        acl_reg.register(sub)
        foreign = make_substrate_manifest(
            sk2, substrate_id=_sid("foreign"), name="F", version="1",
            base_family="f", architecture_family="f",
            training_data_families=[], profile="A")
        try:
            acl_reg.register(foreign)
        except ManifestError as e:
            assert "admission" in str(e), f"M-4: wrong reason {e}"
        else:
            raise AssertionError("M-4: ACL must fail closed")

        # ---- M-5 ----
        reg2 = ManifestRegistry(os.path.join(tmp, "manifests.jsonl"))
        assert reg2.substrate(_sid("dwarf-7b")) is not None \
            and reg2.adapter(_sid("adp-energy")) is not None, \
            "M-5: manifests must reload from disk"

        # ---- M-6 ----
        prov = reg2.provenance(model_id="m-energy",
                               substrate_id=_sid("dwarf-7b"),
                               adapter_ids=[_sid("adp-energy")],
                               operator_domain="aton.ua")
        assert prov["base_family"] == "dwarfstar" \
            and prov["architecture_family"] == "llama" \
            and prov["training_data_families"] == \
                ["aton-docs", "code-2025", "web-2025"] \
            and prov["operator_domain"] == "aton.ua", \
            f"M-6: derived provenance wrong: {prov}"


def test_diversity():
    a = _prov("A", "dwarfstar", "llama", ["web", "code"], "jj-dai.org", "UA")
    a_clone = _prov("A2", "dwarfstar", "llama", ["web", "code"],
                    "jj-dai.org", "UA")
    b = _prov("B", "qwen", "qwen2", ["cn-web"], "alibaba.com", "CN")
    c = _prov("C", "mistral", "mistral", ["eu-web"], "mistral.ai", "FR")
    d = _prov("D", "dwarfstar", "llama", ["web"], "woojin.kr", "KR")
    e = _prov("E", "gpt-oss", "moe", ["us-web"], "openai.com", "US")

    # ---- D-1 ----
    assert independence(a, a_clone) == 0.0, "D-1: clones must correlate 1.0"
    assert independence(b, c) == 1.0, "D-1: disjoint must be independent"

    # ---- D-2 / D-3 / D-5 ----
    pool = [{"provenance": p, "reputation": r} for p, r in
            ((a, 0.99), (a_clone, 0.98), (d, 0.97), (b, 0.90), (c, 0.85),
             (e, 0.80))]
    res = select_verifiers(pool, 3, min_independence=0.5, max_per_group=1)
    ids = [x["provenance"]["model_id"] for x in res["selected"]]
    assert res["filled"] and len(ids) == 3, f"D-2: {res}"
    assert ids[0] == "A", "D-5: best reputation admitted first"
    assert "A2" not in ids and "D" not in ids, \
        "D-2/D-3: correlated family members must be rejected"
    reasons = {r["model_id"]: r["reason"] for r in res["rejected"]}
    assert "independence" in reasons["A2"] or "group cap" in reasons["A2"], \
        f"D-2: named reason required, got {reasons.get('A2')}"
    bases = [x["provenance"]["base_family"] for x in res["selected"]]
    assert len(bases) == len(set(bases)), "D-3: no shared base family"

    # ---- D-4 fail honest ----
    small = [{"provenance": p, "reputation": 0.9} for p in (a, a_clone, d)]
    res2 = select_verifiers(small, 3, min_independence=0.5, max_per_group=1)
    assert not res2["filled"] and len(res2["selected"]) == 1, \
        f"D-4: short panel expected, got {res2}"
    assert len(res2["rejected"]) == 2, "D-4: diagnostics for each rejection"

    # ---- D-6 generator exclusion ----
    res3 = select_verifiers(pool, 3, min_independence=0.3, max_per_group=2,
                            exclude_model="A")
    ids3 = [x["provenance"]["model_id"] for x in res3["selected"]]
    assert "A" not in ids3, "D-6: generator must not verify itself"
    reasons3 = {r["model_id"]: r["reason"] for r in res3["rejected"]}
    assert "generator" in reasons3["A"], "D-6: named reason for generator"
    assert "A2" not in ids3 and "correlated with the generator" in \
        reasons3.get("A2", ""), "D-6: generator clones must be refused"


if __name__ == "__main__":
    test_manifests()
    print("  ok  manifests (M-1..M-6)")
    test_diversity()
    print("  ok  diversity (D-1..D-6)")
    print("\nMANIFESTS + DIVERSITY: 12/12 groups green  ✓ certified")
