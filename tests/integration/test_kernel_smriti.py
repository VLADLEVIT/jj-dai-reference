#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Agent Kernel · Smriti continuity acceptance tests.

Every check targets one property of the memory & continuity organ.

  K-1   CORE tier: set/append labeled blocks; char limit refuses overflow
        (identity is never silently truncated)
  K-2   RECALL tier: witnessed append + local search
  K-3   every memory op is WITNESSED (MEMORY record on chain); chain verifies
        (Ed25519); content is a hiding commitment (plaintext not on chain)
  K-4   state_hash changes on each op and is deterministic; replay of the
        journal reproduces it; journal survives restart
  K-5   ARCHIVAL tier: grounded recall with Merkle-proofed citations, via the
        existing Memory Keeper (kernel wraps core.smriti)
  K-6   structural no-write: ReadOnlyMemory (thinking view) has NO mutation
        method — the invariant cannot be violated because the method is absent
  K-7   PORTABILITY: export bundle; import on a FRESH host verifies
        authenticity against the origin's signed records and reconstructs the
        identical state_hash (pull-by-choice for the mind)
  K-8   tamper in transit: an edited CORE block in the bundle breaks the
        op/state binding -> import REFUSES (PortabilityError)
  K-9   misattribution: re-labeling the bundle to a different being_id is
        caught (identity nailed to the signed records)
  K-10  forged records: a bundle whose MEMORY records are re-signed by a
        DIFFERENT key fails signature verification on import
  K-11  auditor: verify_memory_against_chain binds every op to its record
  K-12  continuity across restart: reload from journal alone reproduces the
        full self (core + recall + state_hash)

Run (from the build root):  python3 test_kernel_smriti.py
"""
from __future__ import annotations

import os
import sys
import tempfile


from jjdai.crypto import SigningKey                          # noqa: E402
from jjdai.witness import WitnessChain                       # noqa: E402
from core.rag_store import RagStore                          # noqa: E402
from core.smriti import Smriti, MockMemoryEngine             # noqa: E402
from kernel.smriti import (SmritiContinuity, AgentIdentity,  # noqa: E402
                           ReadOnlyMemory, CoreBlockFull,
                           PortabilityError,
                           verify_memory_against_chain)

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_kernel_smriti():

    DAY = 86400.0
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    class Clock:
        def __init__(self, t=1_750_000_000.0): self.t = t
        def __call__(self): return self.t
        def tick(self, s): self.t += s


    clk = Clock()
    WORK = tempfile.mkdtemp(prefix="jjdai_kern_")
    BEING = "being:agent-vega"

    sk = SigningKey(b"\x11" * 32)
    chain = WitnessChain(sk, log_path=os.path.join(WORK, "wit.jsonl"))
    journal = os.path.join(WORK, "mem.jsonl")
    ident = AgentIdentity(BEING, created_at=clk())
    smriti = SmritiContinuity(ident, witness=chain, journal_path=journal, now_fn=clk)

    # ---- K-1 core tier + char limit -------------------------------------------- #
    smriti.core_set("persona", "I am Vega, a maglev-systems specialist agent.")
    smriti.core_append("persona", "I value verified evidence over confidence.")
    overflow_caught = False
    try:
        smriti.core_set("persona", "x" * 50, char_limit=10)
    except CoreBlockFull:
        overflow_caught = True
    persona = smriti.readonly().core_blocks()["persona"]
    check("K-1", "Vega" in persona and "verified evidence" in persona
          and overflow_caught, "core set/append; overflow refused")

    # ---- K-2 recall tier ------------------------------------------------------- #
    clk.tick(10)
    smriti.recall_add("user", "What stabilizes the EMS gap at low speed?")
    smriti.recall_add("assistant", "Active control loops adjust the electromagnet current.")
    hits = smriti.recall_search("gap stabilizes", k=3)
    check("K-2", len(hits) >= 1 and any("EMS" in h["text"] for h in hits),
          f"recall append + search found {len(hits)}")

    # ---- K-3 witnessed + hiding + chain verifies ------------------------------- #
    mem_recs = [r for r in chain.records if r["kind"] == "MEMORY"]
    chain_ok = chain.verify_chain()
    raw = chain.raw()
    hidden = "maglev-systems specialist" not in raw and "EMS gap" not in raw
    check("K-3", len(mem_recs) == 4 and chain_ok and hidden,
          f"{len(mem_recs)} MEMORY records; chain verifies; content hidden")

    # ---- K-4 state hash determinism + replay + restart ------------------------- #
    h_now = smriti.state_hash()
    reloaded = SmritiContinuity(AgentIdentity(BEING, ident.created_at),
                                journal_path=journal, now_fn=clk)
    check("K-4", reloaded.state_hash() == h_now and len(reloaded.events) == 4,
          "journal replay reproduces state_hash; survives restart")

    # ---- K-5 archival tier via Memory Keeper ----------------------------------- #
    rag = RagStore(os.path.join(WORK, "rag.db"))
    for t in ["EMS suspension needs active gap control",
              "EDS levitation is passively stable at speed",
              "long-stator LSM provides propulsion"]:
        rag.add(BEING, "kb", t)
    from jjdai.witness import WitnessReader                      # noqa: E402
    keeper = Smriti(rag, MockMemoryEngine(),
                    WitnessReader(os.path.join(WORK, "none.jsonl")))
    smriti2 = SmritiContinuity(ident, archival=keeper, now_fn=clk)
    arch = smriti2.recall_archival("active gap control", k=2)
    check("K-5", arch["grounded"] and all(c["verified"] for c in arch["citations"]),
          f"archival grounded recall, {len(arch['citations'])} proofed citations")

    # ---- K-6 structural no-write ----------------------------------------------- #
    ro = smriti.readonly()
    no_write = not any(hasattr(ro, m) for m in
                       ("core_set", "core_append", "recall_add", "_emit", "_apply"))
    check("K-6", isinstance(ro, ReadOnlyMemory) and no_write,
          "thinking view has no mutation method (invariant structural)")

    # ---- K-7 portability: export -> import on a fresh host --------------------- #
    bundle = smriti.export_portable()
    imported = SmritiContinuity.import_portable(
        bundle, verify=True, pubkey_hex=sk.public.hex())
    check("K-7", imported.state_hash() == smriti.state_hash()
          and imported.readonly().core_blocks()["persona"] == persona,
          "exported self imported & authenticated on fresh host")

    # ---- K-8 tamper in transit ------------------------------------------------- #
    import copy
    tampered = copy.deepcopy(bundle)
    # edit a core value in the reconstructed 'core' AND leave journal/records —
    # import replays the journal, so tamper the journal op to diverge from record
    tampered["journal"][0] = dict(tampered["journal"][0],
                                  value="I am someone else entirely.")
    caught8 = False
    try:
        SmritiContinuity.import_portable(tampered, verify=True,
                                         pubkey_hex=sk.public.hex())
    except PortabilityError:
        caught8 = True
    check("K-8", caught8, "edited core block in transit -> import refuses")

    # ---- K-9 misattribution ---------------------------------------------------- #
    mis = copy.deepcopy(bundle)
    mis["identity"] = dict(mis["identity"], being_id="being:impostor")
    caught9 = False
    try:
        SmritiContinuity.import_portable(mis, verify=True,
                                         pubkey_hex=sk.public.hex())
    except PortabilityError:
        caught9 = True
    check("K-9", caught9, "re-attributed identity caught (nailed to records)")

    # ---- K-10 forged records (different key) ----------------------------------- #
    evil = SigningKey(b"\x99" * 32)
    forged = copy.deepcopy(bundle)
    # re-sign every record with the evil key so this_hash still matches body but
    # signature is by the wrong key
    for rec in forged["witness"]["records"]:
        rec["sig"] = evil.sign(rec["this_hash"].encode()).hex()
    caught10 = False
    try:
        SmritiContinuity.import_portable(forged, verify=True,
                                         pubkey_hex=sk.public.hex())
    except PortabilityError:
        caught10 = True
    check("K-10", caught10, "records re-signed by a different key rejected")

    # ---- K-11 auditor ---------------------------------------------------------- #
    bound = verify_memory_against_chain(smriti.events, chain.records)
    check("K-11", bound == 4, f"auditor binds {bound} ops to their records")

    # ---- K-12 continuity across restart (full self) ---------------------------- #
    restart = SmritiContinuity(AgentIdentity(BEING, ident.created_at),
                               journal_path=journal, now_fn=clk)
    same_core = restart.readonly().core_blocks() == smriti.readonly().core_blocks()
    same_recall = len(restart._recall) == 2
    check("K-12", same_core and same_recall
          and restart.state_hash() == smriti.state_hash(),
          "full self reconstructed from journal after restart")

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nKERNEL · SMRITI CONTINUITY: {len(results) - failed}/{len(results)} "
          "green" + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_kernel_smriti()
