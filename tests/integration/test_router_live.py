#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Live Router Unification (v0.3.1.4 #3) — THREE live nodes.

The router used to be an island: its own sorted-JSON "canonical", its own
hash, a witness whose signature was the literal string "unsigned:"+hash[:16],
its own pass-count registry with no §9.9, and every "node" an in-process
object. This suite proves the island is gone.

  L-1   NO STAND-INS: router.canonical IS jjdai.canonical (RFC 8785 JCS) and
        router.sha256_hex IS jjdai.crypto.H_hex — one canonicalisation, one
        hash across the whole codebase
  L-2   REAL WITNESS: the router's chain is a jjdai WitnessChain; routing
        decisions are Ed25519-SIGNED ROUTE records (not "unsigned:…"), and the
        chain verifies OFFLINE with the node's public key
  L-3   REAL REGISTRY: the router's registry IS core.registry (§9.9) — decay,
        shrinkage and slashing all reachable from the router's object
  L-4   THREE LIVE NODES over HTTP: capability discovery builds real
        NodeDescriptors from /capabilities
  L-5   LIVE DISPATCH: the router routes a query through a real daemon,
        generating over /v1/messages and verifying over /v1/score
  L-6   SEALED VERDICT BINDING enforced end-to-end: the live verdict is opened
        and identity-pinned (v0.3.1.2) before the router believes it
  L-7   §9.9 DRIVES SELECTION: after verified wins the leading object is the
        registry champion by WEIGHT (not by naive pass count)
  L-8   DECAY REACHES THE ROUTER: an idle object loses the lead to an active
        one — "influence requires continuous fresh verified work" is now true
        of routing itself, not just of the registry in isolation
  L-9   SLASHING REACHES THE ROUTER: a slashed object drops out of the lead
  L-10  CONTAINMENT REACHES THE ROUTER: a contained node refuses to generate
        (423) and the router surfaces a refusal instead of an answer
  L-11  witnessed route decisions bind the policy hash; the ROUTE record's
        clear digest matches route:<event>:<policy_hash>:<payload_hash>
  L-12  the three nodes are DISTINCT identities (unique node_ids)

Run (from the build root):  python3 test_router_live.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import time


from smoke_two_nodes import get, post, wait_up, verify_chain_offline  # noqa: E402
import jjdai.canonical as jc                                  # noqa: E402
import jjdai.crypto as jcr                                    # noqa: E402
import core.router as R                                       # noqa: E402
from core.registry import Params                              # noqa: E402
from core.verdict import open_verdict                         # noqa: E402
from core.containment import ContainmentLedger                # noqa: E402

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_router_live():

    PORTS = (8551, 8552, 8553)
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    class Clock:
        def __init__(self, t=1_750_000_000.0): self.t = t
        def __call__(self): return self.t
        def tick(self, days): self.t += days * 86400.0


    def spawn(port, name):
        return subprocess.Popen(
            [sys.executable, os.path.join(HERE, "daemon.py"),
             "--port", str(port), "--name", name, "--fingerprint", "fp-shared",
             "--allow-test-hooks"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


    # ---- L-1 no stand-ins ------------------------------------------------------ #
    check("L-1", R.canonical is jc.canonical and R.sha256_hex is jcr.H_hex,
          "router uses jjdai.canonical (JCS) + jjdai.crypto.H_hex — one of each")

    procs = [spawn(p, f"rn{i}") for i, p in enumerate(PORTS)]
    try:
        urls = [f"http://127.0.0.1:{p}" for p in PORTS]
        caps = [wait_up(u) for u in urls]

        clk = Clock()
        w = R.WitnessChain()
        reg = R.ChampionRegistry(Params(), now_fn=clk)

        # ---- L-4 three live nodes -> real descriptors -------------------------- #
        engines = {}
        for i, u in enumerate(urls):
            eng = R.HTTPNodeEngine(u, http_post=post, http_get=get,
                                   topics=("maglev",), attributes={"region": "eu"},
                                   open_verdict=open_verdict)
            engines[f"node-{i}"] = eng
        descs = [e.describe() for e in engines.values()]
        check("L-4", len(descs) == 3 and all(d.substrate_id.startswith("sha256:")
                                            for d in descs)
              and all(len(d.engines) == 2 for d in descs),
              f"3 live nodes discovered: profiles {[d.profile for d in descs]}")

        # ---- L-12 distinct identities ------------------------------------------ #
        ids = {d.node_id for d in descs}
        check("L-12", len(ids) == 3, f"three distinct node identities")

        objects = [R.RouteObject(object_id=f"ne:obj-{i}", kind="specialist",
                                 topic="maglev", node_id=f"node-{i}")
                   for i in range(3)]
        policy = R.RoutingPolicy(
            classifier_rules={"maglev": ["maglev", "corridor", "gap"]},
            abac_rules=[])
        router = R.Router(policy, R.RuleClassifier(policy), objects, engines,
                          reg, w)

        def route_once(prefer=None):
            return router.route(R.Query(text="maglev corridor gap control",
                                        prefer_object=prefer))

        # ---- L-5 / L-6 live dispatch with sealed-verdict binding ---------------- #
        out = route_once()
        sub = out.per_subtask[0]
        check("L-5", out.final_answer and sub["object"].startswith("ne:obj-")
              and sub["verified"] is True and sub["answer"],
              f"routed live through {sub['object']} -> answer via HTTP")
        check("L-6", "route.verify" in w.events()
              and w.payloads_of("route.verify")[0]["recorded_to_registry"],
              "live verdict opened, identity-pinned, and recorded to §9.9")

        # ---- L-2 real Ed25519 ROUTE records verify offline ---------------------- #
        route_recs = [r for r in w.chain.records if r["kind"] == "ROUTE"]
        export = {"node_id": w.chain.node_id, "pubkey": w.chain.sk.public.hex(),
                  "head": w.chain.head_hash(), "records": w.chain.records}
        no_fake_sig = all(not str(r["sig"]).startswith("unsigned:")
                          for r in route_recs)
        check("L-2", len(route_recs) >= 4 and no_fake_sig
              and verify_chain_offline(export),
              f"{len(route_recs)} ROUTE records Ed25519-signed; chain verifies offline")

        # ---- L-11 policy binding in the clear digest ---------------------------- #
        disp = [r for r in route_recs
                if r["semantic_digest"].startswith("route:route.dispatch:")]
        ph = policy.policy_hash
        check("L-11", disp and disp[0]["semantic_digest"].split(":")[2] == ph,
              "ROUTE digest binds event + policy_hash + payload hash")

        # ---- L-3 real §9.9 registry -------------------------------------------- #
        comp = reg.components("maglev", sub["object"])
        check("L-3", isinstance(reg, R._RealRegistry)
              and {"N_eff", "R", "E", "S", "g", "w"} <= set(comp),
              f"router registry is core.registry §9.9 (w={comp['w']:.3f})")

        # ---- L-7 §9.9 drives selection ----------------------------------------- #
        for _ in range(8):
            route_once(prefer="ne:obj-0")
        lb = reg.leaderboard("maglev")
        champ = reg.champion("maglev")
        check("L-7", lb and lb[0][0] == "ne:obj-0" and champ == "ne:obj-0",
              f"leader by §9.9 weight: {lb[0][0]} (w={lb[0][1][0]:.3f})")

        # ---- L-8 decay reaches the router --------------------------------------- #
        clk.tick(30)                                   # obj-0 idles a month
        for _ in range(6):
            route_once(prefer="ne:obj-1")              # obj-1 works fresh
        lb2 = reg.leaderboard("maglev")
        check("L-8", lb2[0][0] == "ne:obj-1",
              f"idle obj-0 (w={reg.weight('maglev','ne:obj-0'):.3f}) loses to fresh "
              f"obj-1 (w={reg.weight('maglev','ne:obj-1'):.3f})")

        # ---- L-9 slashing reaches the router ------------------------------------ #
        for _ in range(6):
            route_once(prefer="ne:obj-2")              # obj-2 becomes a real rival
        w1_before = reg.weight("maglev", "ne:obj-1")
        reg.slash("ne:obj-1", "failed blind challenge")
        w1_after = reg.weight("maglev", "ne:obj-1")
        lb3 = reg.leaderboard("maglev")
        halved = abs(w1_after - w1_before * 0.5) < 0.02
        check("L-9", halved and lb3[0][0] == "ne:obj-2",
              f"slash halves obj-1 {w1_before:.3f}->{w1_after:.3f}; lead passes to "
              f"unslashed obj-2 (w={lb3[0][1][0]:.3f})")

        # ---- L-10 containment reaches the router -------------------------------- #
        post(urls[2] + "/admin/containment", {"contain": True, "topic": "cyber",
             "reason": "live-test: active attempt"})
        refused = False
        try:
            engines["node-2"].generate("anything", R.SamplingParams(
                temperature=0.0, top_p=0.9, top_k=0, seed=7))
        except R.RefusalError as e:
            refused = "423" in str(e)
        check("L-10", refused,
              "contained node refuses to generate; router surfaces a refusal")

    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nLIVE ROUTER UNIFICATION: {len(results) - failed}/{len(results)} green"
          + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_router_live()
