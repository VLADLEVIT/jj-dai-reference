#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — README-migration acceptance tests (W29 step 2).

Proves the migration is complete AND lossless:

  M-1  ROOT CONTINUITY: for identical chunks, the migrated core.rag_store
       (jjdai.merkle) produces a root BYTE-IDENTICAL to the retired
       prototype's domain-v2 root — no re-baseline, M5 history stays valid.
  M-2  migrated proofs verify via jjdai.merkle; swapped leaf / root fail.
  M-3  migrated Smriti: grounded recall, all citations verify.
  M-4  no-write invariant vs the REAL jjdai WitnessChain is structural.
  M-5  witnessed_recall writes through the node's WitnessChain; the chain
       verifies with real Ed25519; receipt returned.
  M-6  hiding commitments: query/answer plaintext never on the chain.
  M-7  jjdai WitnessReader (ported): reads/verifies a persisted node log,
       has no write methods, and Smriti can audit through it.
  M-8  legacy cv-dispatch (ported): a signed prototype-format log (written
       by the RETIRED m1m5 WitnessLog) verifies via
       jjdai.witness.verify_legacy_chain; tampering is caught.

Run (from the build root):  python3 test_migration.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile


from jjdai.crypto import canonical_node_id, SigningKey, node_id                    # noqa: E402
from jjdai.witness import (WitnessChain, WitnessReader,         # noqa: E402
                           verify_legacy_chain, ChainError)
from core.rag_store import RagStore                             # noqa: E402
from core.smriti import Smriti, MockMemoryEngine, witnessed_recall  # noqa: E402

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_migration():

    WORK = tempfile.mkdtemp(prefix="jjdai_migr_")
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    CHUNKS = ["maglev uses long-stator LSM propulsion",
              "EMS suspension needs active gap control",
              "EDS levitation is passively stable at speed",
              "the corridor is a 900 km dual-bore cut-and-cover",
              "the witness observes and never governs"]

    # ---- M-1 root continuity vs the retired prototype ------------------------- #
    new = RagStore(os.path.join(WORK, "new.db"))
    for t in CHUNKS:
        new.add("mag", "doc1", t)
    new_root = new.merkle_root("mag")

    sys.path.insert(0, os.path.join(_ROOT, "m1m5"))
    import rag_store as legacy_rs                                   # noqa: E402
    old = legacy_rs.RagStore(os.path.join(WORK, "old.db"))
    for t in CHUNKS:
        old.add("mag", "doc1", t)
    old_root = old.merkle_root("mag")
    check("M-1", new_root == old_root,
          f"root continuity: {new_root[:12]}… == legacy domain-v2 (no re-baseline)")

    # ---- M-2 proof soundness on the migrated store ----------------------------- #
    p = new.prove("mag", 3)
    ok_valid = RagStore.verify_proof(p) and p["scheme"] == "jjdai-merkle"
    bad_leaf = dict(p); bad_leaf["leaf"] = new.get(1)["hash"]
    bad_root = dict(p); bad_root["root"] = "ff" * 32
    check("M-2", ok_valid and not RagStore.verify_proof(bad_leaf)
          and not RagStore.verify_proof(bad_root),
          "valid verifies; swapped leaf/root fail")

    # ---- M-3 migrated Smriti recall -------------------------------------------- #
    reader0 = WitnessReader(os.path.join(WORK, "nowhere.jsonl"))
    smriti = Smriti(new, MockMemoryEngine(), reader0)
    res = smriti.recall("mag", "how does the suspension control the gap?")
    check("M-3", res["grounded"] and res["all_verified"]
          and len(res["citations"]) > 0, res["answer"])

    # ---- M-4 structural no-write vs the REAL WitnessChain ---------------------- #
    sk = SigningKey.generate()
    nid = canonical_node_id(sk.public)
    LOG = os.path.join(WORK, "node.jsonl")
    chain = WitnessChain(sk, log_path=LOG)
    try:
        Smriti(new, MockMemoryEngine(), chain)
        check("M-4", False)
    except TypeError:
        check("M-4", True, "WitnessChain refused — no-write invariant structural")

    # ---- M-5 witnessed recall through the node's chain ------------------------- #
    class _Daemon:
        def __init__(self, w): self.witness = w

    out = witnessed_recall(smriti, _Daemon(chain), "mag", "propulsion?")
    check("M-5", bool(out.get("witness_receipt"))
          and chain.verify_chain(sk.public) and len(chain.records) == 1,
          f"receipt idx={out['witness_receipt']['index']}, signed chain verifies")

    # ---- M-6 hiding commitments ------------------------------------------------ #
    raw = chain.raw()
    check("M-6", "propulsion?" not in raw and out["answer"] not in raw,
          "query/answer plaintext absent from chain")

    # ---- M-7 ported WitnessReader on the persisted log ------------------------- #
    reader = WitnessReader(LOG)
    resolver = lambda x: sk.public if x == nid else None
    n, head = reader.verify(resolver)
    no_write = not any(hasattr(reader, m) for m in
                       ("append", "emit_infer", "anchor_root"))
    smriti_ro = Smriti(new, MockMemoryEngine(), reader)
    an, _ = smriti_ro.audit(resolver)
    check("M-7", n == 1 and head == chain.head_hash() and no_write and an == 1,
          "reader verifies persisted log; Smriti audits read-only")

    # ---- M-8 legacy cv-dispatch port -------------------------------------------- #
    import importlib
    legacy_w = importlib.import_module("witness")        # m1m5 prototype (RETIRED)
    LEG = os.path.join(WORK, "legacy.jsonl")
    lsk = SigningKey.generate()
    lnid = node_id(lsk.public)   # LEGACY raw-hex id: m1m5 wrote it that way
    llog = legacy_w.WitnessLog(LEG, signing_key=lsk)     # jcs records, signed
    llog.emit_infer({"i": 0})
    legacy_w.WitnessLog(LEG, canon="legacy").emit_infer({"i": 1})   # legacy cv
    lres = lambda x: lsk.public if x == lnid else None
    n2, _ = verify_legacy_chain(LEG, lres)
    tampered = False
    lines = [json.loads(l) for l in open(LEG) if l.strip()]
    lines[0]["body"]["payload"]["i"] = 999
    TMP = os.path.join(WORK, "legacy_tampered.jsonl")
    with open(TMP, "w") as f:
        for l in lines:
            f.write(json.dumps(l, sort_keys=True) + "\n")
    try:
        verify_legacy_chain(TMP, lres)
    except ChainError:
        tampered = True
    check("M-8", n2 == 2 and tampered,
          "mixed jcs+legacy prototype log verifies; tamper caught (cv port OK)")

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nMIGRATION: {len(results) - failed}/{len(results)} green"
          + ("  ✓ README migration complete" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_migration()
