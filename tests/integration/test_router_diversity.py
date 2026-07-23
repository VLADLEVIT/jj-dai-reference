#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Diversity → live router (v0.5.1) — acceptance
=============================================
  R-1  with provenance wired, verification runs through a
       diversity-constrained PANEL: the generator's clone is rejected BY
       NAME, independent verifiers are selected, the panel is witnessed
       (route.panel with selected/rejected/constraints)
  R-2  the generator's provenance is passed EXPLICITLY: the panel is
       correct even though the generator never appears in its own
       candidate pool
  R-3  FAIL HONEST: an insufficient pool refuses the route (short panel,
       constraints never relaxed silently); allow_degraded_panel=True
       proceeds and the witness marks degraded=true
  R-4  a generator with NO ProvenanceManifest cannot be panel-verified —
       the route refuses instead of guessing
  R-5  panel verdicts feed the §9.9 registry (loop closure) and the
       route.verify record carries mode="panel"
  R-6  the legacy path (no provenance) still works and its witness record
       says mode="self" — the downgrade is visible, never silent
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import core.router as R                                            # noqa: E402
from core.router import (Router, RoutingPolicy, RuleClassifier,    # noqa: E402
                         RouteObject, Query, RefusalError,
                         ChampionRegistry, WitnessChain, DenyRule)


def _mk_node(node_id, substrate, topics, noise=0.0):
    return R._mk_node(node_id, substrate, topics, origin="UA", noise=noise)


def _prov(mid, fam, *, op=None, ds=None, arch=None, jur="UA"):
    return {"model_id": mid, "base_family": fam,
            "architecture_family": arch or f"arch-{fam}",
            "training_data_families": ds or [f"ds-{fam}"],
            "operator_domain": op or f"{mid}.example",
            "jurisdiction": jur}


def _build(provenance, **router_kw):
    policy = RoutingPolicy(
        classifier_rules={"neutronics": ["reactor", "smr", "neutron"]},
        abac_rules=[])
    topics = ["neutronics", "_generalist"]
    # ONE frozen substrate across all nodes — the JJ DAI model (Profile B):
    # verifiers are INDEPENDENT IMPLEMENTATIONS of the same frozen weights,
    # so teacher-forcing is meaningful; independence lives in the serving
    # stack (operator, jurisdiction, architecture, adapter data), not in
    # divergent weights.
    nodes = {
        "n-gen": _mk_node("n-gen", "sub-G", topics, noise=0.1),
        "n-clone": _mk_node("n-clone", "sub-G", topics),
        "n-i1": _mk_node("n-i1", "sub-G", topics),
        "n-i2": _mk_node("n-i2", "sub-G", topics),
    }
    objects = [
        RouteObject("m:gen", "specialist", "neutronics", "n-gen"),
        RouteObject("m:clone", "specialist", "neutronics", "n-clone"),
        RouteObject("m:i1", "specialist", "neutronics", "n-i1"),
        RouteObject("m:i2", "specialist", "neutronics", "n-i2"),
    ]
    registry = ChampionRegistry()
    # give the generator verified history so the leaderboard picks it
    for _ in range(4):
        registry.record("neutronics", "m:gen", True, 0.5)
    witness = WitnessChain()
    router = Router(policy, RuleClassifier(policy),
                    objects, nodes, registry, witness,
                    provenance=provenance, **router_kw)
    return router, registry, witness


def _full_prov():
    # shared frozen substrate => shared base_family for EVERYONE (0.35
    # correlation floor); the clone also shares operator, data and serving
    # architecture (correlation 1.0). Independents differ on everything
    # the serving stack controls.
    gen = _prov("m:gen", "fam-G")
    clone = _prov("m:clone", "fam-G", op=gen["operator_domain"],
                  ds=gen["training_data_families"],
                  arch=gen["architecture_family"])
    return {"m:gen": gen, "m:clone": clone,
            "m:i1": _prov("m:i1", "fam-G", arch="arch-metal",
                          ds=["ds-i1"], jur="KR"),
            "m:i2": _prov("m:i2", "fam-G", arch="arch-cuda",
                          ds=["ds-i2"], jur="EE")}


def test_router_diversity_panel():
    # ---- R-1 / R-2 / R-5 ----
    router, registry, witness = _build(_full_prov(), panel_k=2,
                                   max_per_group=2)
    res = router.route(Query(text="neutron flux in the smr core",
                             require_verification=True))
    st = res.per_subtask[0]
    assert st["verified"], "R-1: independent panel must verify the champion"
    events = [(v.event_type, v.payload) for v in witness._views]
    kinds = [k for k, _ in events]
    assert "route.panel" in kinds and "route.panel_verify" in kinds, kinds
    panel_ev = next(p for k, p in events if k == "route.panel")
    assert panel_ev["generator_provenance_model"] == "m:gen", \
        "R-2: the generator's manifest is passed explicitly and witnessed"
    assert sorted(panel_ev["selected"]) == ["m:i1", "m:i2"], panel_ev
    rejected = {r["model_id"] for r in panel_ev["rejected"]}
    assert "m:clone" in rejected, \
        "R-1: the generator's clone must be rejected BY NAME"
    verify_ev = next(p for k, p in events if k == "route.verify")
    assert verify_ev["mode"] == "panel" and verify_ev["recorded_to_registry"]
    lead = registry.leaderboard("neutronics", "global")
    assert any(oid == "m:gen" for oid, _ in lead), \
        "R-5: panel outcomes must feed the §9.9 registry"
    print("  [PASS] R-1/R-2/R-5  panel selected {i1,i2}, clone rejected by "
          "name, explicit generator manifest witnessed, registry fed, "
          "mode=panel")

    # ---- R-3 fail honest ----
    small = {k: v for k, v in _full_prov().items()
             if k in ("m:gen", "m:clone", "m:i1")}
    router3, _, w3 = _build(small, panel_k=2, max_per_group=2)
    router3.objects = [o for o in router3.objects if o.object_id != "m:i2"]
    try:
        router3.route(Query(text="neutron flux", require_verification=True))
        assert False, "R-3: a short panel must refuse, never relax"
    except RefusalError as e:
        assert "fail-honest" in str(e), e
    routerd, _, wd = _build(small, panel_k=2, max_per_group=2,
                        allow_degraded_panel=True)
    routerd.objects = [o for o in routerd.objects if o.object_id != "m:i2"]
    res_d = routerd.route(Query(text="neutron flux",
                                require_verification=True))
    ev_d = [(v.event_type, v.payload) for v in wd._views]
    vd = next(p for k, p in ev_d if k == "route.verify")
    assert vd["degraded"] is True and res_d.per_subtask[0]["verified"], \
        "R-3: degraded mode proceeds and SAYS SO in the witness"
    print("  [PASS] R-3  short panel refuses (fail-honest); degraded mode "
          "is explicit in the witness")

    # ---- R-4 no generator manifest ----
    nogen = {k: v for k, v in _full_prov().items() if k != "m:gen"}
    router4, _, _ = _build(nogen, panel_k=2, max_per_group=2)
    try:
        router4.route(Query(text="neutron flux", require_verification=True))
        assert False, "R-4: an unmanifested generator cannot be panel-verified"
    except RefusalError as e:
        assert "ProvenanceManifest" in str(e), e
    print("  [PASS] R-4  unmanifested generator refused, not guessed")

    # ---- R-6 legacy visible ----
    router6, _, w6 = _build(None)
    res6 = router6.route(Query(text="neutron flux",
                               require_verification=True))
    ev6 = [(v.event_type, v.payload) for v in w6._views]
    v6 = next(p for k, p in ev6 if k == "route.verify")
    assert v6["mode"] == "self" and res6.per_subtask[0]["verified"], \
        "R-6: the legacy path must label itself"
    print("  [PASS] R-6  legacy self-verification labeled mode=self")


if __name__ == "__main__":
    test_router_diversity_panel()
    print("\nROUTER DIVERSITY: all groups green  ✓ certified")
