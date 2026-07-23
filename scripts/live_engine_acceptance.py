#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/live_engine_acceptance.py — audit gate 7, operator-run
==============================================================
CI proves the composition with deterministic reference engines; THIS
script proves it against a REAL serving engine (SGLang or DwarfStar) on
operator hardware. It is not part of run_acceptance because it needs a
GPU endpoint; run it before calling any deployment "tested on real
engines".

    python3 scripts/live_engine_acceptance.py \
        --engine sglang --url http://gpu-host:30000 \
        [--second-url http://gpu-host-2:30000]

What it does (and what it honestly cannot):
  1. wraps the engine behind the router NodeEngine protocol
     (generate + teacher-forcing score via the node/engine_* adapters);
  2. runs one BeingRuntime task through the FULL lifecycle in the
     production profile: grounding, plan, generation on the real engine,
     verifier panel scoring on the real engine(s), witnessed action,
     record; prints the DecisionTrace;
  3. verifies the chain end-to-end afterwards.
  With ONE physical endpoint the panel's serving-stack independence is
  degraded (same host serves generator and verifiers); pass
  --second-url to make the panel physically independent. The script
  prints which of the two you actually ran — put THAT sentence in the
  release notes, not a better one.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import SigningKey                                # noqa: E402
from jjdai.witness import WitnessChain                             # noqa: E402
from core.containment import ContainmentLedger                     # noqa: E402
from core.router import RouteObject                                # noqa: E402
from runtime import BeingRuntime                                   # noqa: E402


def _engine(kind: str, url: str):
    if kind == "sglang":
        from engine_sglang import SglangEngine
        return SglangEngine(url)
    if kind == "dwarfstar":
        from engine_dwarfstar import DwarfStarEngine
        return DwarfStarEngine(url)
    raise SystemExit(f"unknown engine {kind!r}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True,
                    choices=("sglang", "dwarfstar"))
    ap.add_argument("--url", required=True)
    ap.add_argument("--second-url", default=None,
                    help="second physical endpoint for the verifier panel")
    ap.add_argument("--prompt", default="State the invariant INV-9 of a "
                                        "witness in one sentence.")
    args = ap.parse_args()

    sk = SigningKey.generate()
    chain = WitnessChain(sk)
    being = f"being:{chain.node_id[:16]}"
    gov = ContainmentLedger(chain.node_id, witness=chain,
                            evidence_resolver=None)
    gen = _engine(args.engine, args.url)
    ver = _engine(args.engine, args.second_url) if args.second_url else gen
    engines = {"n-gen": gen, "n-v1": ver, "n-v2": ver}
    objects = [RouteObject("m:gen", "generalist", "_generalist", "n-gen"),
               RouteObject("m:v1", "generalist", "_generalist", "n-v1"),
               RouteObject("m:v2", "generalist", "_generalist", "n-v2")]

    def prov(mid, arch, ds, jur, op):
        return {"model_id": mid, "base_family": "fam-live",
                "architecture_family": arch,
                "training_data_families": [ds],
                "operator_domain": op, "jurisdiction": jur}
    provenance = {
        "m:gen": prov("m:gen", "arch-live", "ds-live", "UA", args.url),
        "m:v1": prov("m:v1", "arch-live-v", "ds-live-v", "KR",
                     args.second_url or args.url),
        "m:v2": prov("m:v2", "arch-live-v2", "ds-live-v2", "EE",
                     args.second_url or args.url)}

    with tempfile.TemporaryDirectory() as tmp:
        rt = BeingRuntime(
            sk=sk, chain=chain, being_id=being, governor=gov,
            workspace=os.path.join(tmp, "ws"), profile="production",
            route_objects=objects, engines=engines, provenance=provenance,
            topics={"_generalist": []}, max_per_group=3,
            journal_dir=os.path.join(tmp, "j"))
        tr = rt.handle_task({"text": args.prompt,
                             "action": {"kind": "fs_write",
                                        "path": "live.txt",
                                        "content": "live gate"}})
        d = tr.as_dict()
        print("state:", d["state"])
        print("path :", " -> ".join(t["to"] for t in d["transitions"]))
        print("panel:", d["verifier_panel"])
        print("answer:", (d["answer"] or "")[:300])
        print("chain verifies:", chain.verify_chain())
        if args.second_url:
            print("\nPANEL INDEPENDENCE: generator and verifiers ran on "
                  "PHYSICALLY SEPARATE endpoints.")
        else:
            print("\nPANEL INDEPENDENCE: DEGRADED — one physical endpoint "
                  "served generator and verifiers. Do not claim more.")
        return 0 if d["state"] == "RECORDED" else 1


if __name__ == "__main__":
    sys.exit(main())
