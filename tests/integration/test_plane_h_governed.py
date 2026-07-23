#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Governed Plane H (v0.5, P1) — signed RAG writes acceptance
==========================================================
  G-1   valid signed ADD applies; a MEMORY witness record is appended with
        a public digest (op, ns, chunk, author, ns_root); proof verifies
  G-2   tampered text (content-hash mismatch) is rejected before storage
  G-3   forged author (pub does not match author_node) is rejected
  G-4   unauthorized author is refused; unknown namespace fails CLOSED
  G-5   SUPERSEDE: v2 replaces v1 — retrieval returns only v2; the v1
        governance card points forward via superseded_by
  G-6   double-supersede of the same target is refused
  G-7   REDACT: text is gone, hash remains, namespace Merkle root is
        UNCHANGED, retrieval excludes the chunk, the historical proposal
        envelope still verifies (authors sign hashes, not text)
  G-8   unauthorized REDACT is refused (redaction is a privileged op)
  G-9   access policy: restricted chunks invisible at public access
  G-10  retention "until" in the past excludes the chunk from retrieval
  G-11  provenance surfaces in retrieval results (author, source,
        confidence, evidence_refs)
  G-12  persistence: store reopened from disk keeps lifecycle state and
        namespace root; the witness chain verifies end-to-end
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import canonical_node_id, SigningKey, node_id                        # noqa: E402
from jjdai.witness import WitnessChain, LocalAnchor                 # noqa: E402
from core.rag_store import RagStore                                 # noqa: E402
from core.plane_h import (GovernedPlaneH, WritePolicy,              # noqa: E402
                          make_write_proposal, verify_write_proposal,
                          ValidationError, AuthorizationError)

NS = "aton/boilers"


def _mk(tmp):
    sk_gov = SigningKey.generate()
    sk_auth = SigningKey.generate()
    sk_intruder = SigningKey.generate()
    chain = WitnessChain(sk_gov, anchor=LocalAnchor(),
                         log_path=os.path.join(tmp, "w.jsonl"))
    store = RagStore(os.path.join(tmp, "rag.db"))
    policy = WritePolicy()
    policy.grant(NS, canonical_node_id(sk_auth.public), ops=("add", "supersede"))
    gov = GovernedPlaneH(store, policy, witness=chain,
                         governor_node=chain.node_id)
    return gov, chain, sk_auth, sk_intruder, policy


def test_governed_plane_h():
    with tempfile.TemporaryDirectory() as tmp:
        gov, chain, sk_auth, sk_x, policy = _mk(tmp)

        # ---- G-1 signed add + witness + proof ----
        text1 = "Membrane panel spec: P91 steel, 30 MW water-tube boiler."
        env1 = make_write_proposal(
            sk_auth, op="add", ns=NS, doc_id="spec-001", text=text1,
            source={"type": "datasheet", "uri": "aton://specs/panel-p91"},
            confidence=0.95, evidence_refs=["rfq:PCHE-001"],
            access_policy="internal")
        r1 = gov.apply(env1, text1)
        assert r1["op"] == "add" and r1["version"] == 1
        assert gov.store.verify_proof(r1["proof"]), "G-1: proof must verify"
        mem = [r for r in chain.records if r["kind"] == "MEMORY"]
        assert len(mem) == 1, "G-1: one MEMORY witness record expected"
        d = mem[0]["semantic_digest"]
        assert d["op"] == "add" and d["ns"] == NS \
            and d["chunk_id"] == r1["chunk_id"] \
            and d["author_node"] == canonical_node_id(sk_auth.public) \
            and d["ns_root"] == r1["ns_root"], "G-1: digest must be public"

        # ---- G-2 tampered text ----
        env_bad = make_write_proposal(sk_auth, op="add", ns=NS,
                                      doc_id="spec-002", text="original")
        try:
            gov.apply(env_bad, "tampered")
        except ValidationError as e:
            assert "hash mismatch" in str(e), f"G-2: wrong reason {e}"
        else:
            raise AssertionError("G-2: tampered text must be rejected")

        # ---- G-3 forged author ----
        env_forged = make_write_proposal(sk_x, op="add", ns=NS,
                                         doc_id="spec-003", text="x")
        env_forged["body"]["author_node"] = canonical_node_id(sk_auth.public)
        ok, why = verify_write_proposal(env_forged, "x")
        assert not ok, "G-3: forged author_node must fail verification"

        # ---- G-4 unauthorized / unknown ns fail closed ----
        env_un = make_write_proposal(sk_x, op="add", ns=NS,
                                     doc_id="spec-004", text="y")
        try:
            gov.apply(env_un, "y")
        except AuthorizationError:
            pass
        else:
            raise AssertionError("G-4: unauthorized author must be refused")
        env_ns = make_write_proposal(sk_auth, op="add", ns="unknown/ns",
                                     doc_id="d", text="z")
        try:
            gov.apply(env_ns, "z")
        except AuthorizationError:
            pass
        else:
            raise AssertionError("G-4: unknown namespace must fail CLOSED")

        # ---- G-5 supersede ----
        text2 = "Membrane panel spec v2: P92 steel, 30 MW water-tube boiler."
        env2 = make_write_proposal(sk_auth, op="supersede", ns=NS,
                                   doc_id="spec-001", text=text2,
                                   target_chunk=r1["chunk_id"],
                                   access_policy="internal")
        r2 = gov.apply(env2, text2)
        assert r2["version"] == 2 and r2["supersedes"] == r1["chunk_id"]
        hits = gov.retrieve(NS, "membrane panel boiler", k=5,
                            access="internal")
        ids = [h["chunk_id"] for h in hits]
        assert r2["chunk_id"] in ids and r1["chunk_id"] not in ids, \
            "G-5: retrieval must return only the latest version"
        card1 = gov.describe(r1["chunk_id"])
        assert card1["superseded_by"] == r2["chunk_id"], \
            "G-5: v1 card must point forward"

        # ---- G-6 double supersede refused ----
        env_dbl = make_write_proposal(sk_auth, op="supersede", ns=NS,
                                      doc_id="spec-001", text="v3?",
                                      target_chunk=r1["chunk_id"])
        try:
            gov.apply(env_dbl, "v3?")
        except ValidationError as e:
            assert "already superseded" in str(e)
        else:
            raise AssertionError("G-6: double supersede must be refused")

        # ---- G-7 redact (privileged: grant to governor identity) ----
        sk_steward = SigningKey.generate()
        policy.grant(NS, canonical_node_id(sk_steward.public), ops=("redact",))
        root_before = gov.store.merkle_root(NS)
        env_red = make_write_proposal(sk_steward, op="redact", ns=NS,
                                      doc_id="spec-001",
                                      target_chunk=r2["chunk_id"])
        r3 = gov.apply(env_red)
        assert r3["op"] == "redact" and r3["chunk_id"] == r2["chunk_id"]
        root_after = gov.store.merkle_root(NS)
        assert root_before == root_after, \
            "G-7: redaction must NOT change the namespace Merkle root"
        row = gov.store.get(r2["chunk_id"])
        assert row["text"] is None and row["hash"] == r2["hash"], \
            "G-7: text gone, hash retained (content-addressed tombstone)"
        assert gov.retrieve(NS, "membrane panel boiler", k=5,
                            access="internal") == [], \
            "G-7: redacted (and superseded) content must not be retrievable"
        ok, why = verify_write_proposal(env2, text2)
        assert ok, "G-7: the historical proposal must still verify"

        # ---- G-8 unauthorized redact ----
        env_red2 = make_write_proposal(sk_auth, op="redact", ns=NS,
                                       doc_id="spec-001",
                                       target_chunk=r1["chunk_id"])
        try:
            gov.apply(env_red2)
        except AuthorizationError:
            pass
        else:
            raise AssertionError("G-8: redact must be a privileged op")

        # ---- G-9 access policy ----
        t_r = "Restricted: KVBZ bogie cost breakdown."
        env_r = make_write_proposal(sk_auth, op="add", ns=NS,
                                    doc_id="conf-001", text=t_r,
                                    access_policy="restricted")
        rr = gov.apply(env_r, t_r)
        pub_hits = gov.retrieve(NS, "KVBZ bogie cost", k=5, access="public")
        res_hits = gov.retrieve(NS, "KVBZ bogie cost", k=5, access="restricted")
        assert rr["chunk_id"] not in [h["chunk_id"] for h in pub_hits], \
            "G-9: restricted chunk visible at public access"
        assert rr["chunk_id"] in [h["chunk_id"] for h in res_hits], \
            "G-9: restricted chunk must be visible at restricted access"

        # ---- G-10 retention expiry ----
        t_e = "Expired tender notice for boiler unit 7."
        env_e = make_write_proposal(sk_auth, op="add", ns=NS,
                                    doc_id="tender-7", text=t_e,
                                    access_policy="public",
                                    retention={"policy": "until",
                                               "until": time.time() - 60})
        re_ = gov.apply(env_e, t_e)
        hits = gov.retrieve(NS, "tender boiler unit", k=5, access="public")
        assert re_["chunk_id"] not in [h["chunk_id"] for h in hits], \
            "G-10: retention-expired chunk must be excluded"

        # ---- G-11 provenance in results ----
        t_p = "Provenance probe: Qingdao membrane panels shipment QA."
        env_p = make_write_proposal(
            sk_auth, op="add", ns=NS, doc_id="qa-001", text=t_p,
            source={"type": "inspection", "uri": "aton://qa/qingdao-01"},
            confidence=0.8, evidence_refs=["photo:qa-17"],
            access_policy="public")
        rp = gov.apply(env_p, t_p)
        hit = [h for h in gov.retrieve(NS, "Qingdao membrane shipment", k=3,
                                       access="public")
               if h["chunk_id"] == rp["chunk_id"]]
        assert hit, "G-11: probe chunk must be retrievable"
        h0 = hit[0]
        assert h0["author_node"] == canonical_node_id(sk_auth.public) \
            and h0["source"]["uri"] == "aton://qa/qingdao-01" \
            and h0["confidence"] == 0.8 \
            and h0["evidence_refs"] == ["photo:qa-17"], \
            "G-11: provenance must surface in retrieval results"

        # ---- G-12 persistence + chain verify ----
        root_now = gov.store.merkle_root(NS)
        gov.store.db.close()
        store2 = RagStore(os.path.join(tmp, "rag.db"))
        gov2 = GovernedPlaneH(store2, policy, witness=None)
        assert store2.merkle_root(NS) == root_now, \
            "G-12: namespace root must be stable across reopen"
        card = gov2.describe(r2["chunk_id"])
        assert card["redacted"] and card["version"] == 2, \
            "G-12: lifecycle state must survive reopen"
        assert chain.verify_chain(), "G-12: witness chain must verify"
        mems = [r for r in chain.records if r["kind"] == "MEMORY"]
        assert len(mems) == 6, f"G-12: 6 MEMORY records expected, {len(mems)}"

        print("GOVERNED PLANE H: 12/12 groups green  ✓ certified")


if __name__ == "__main__":
    test_governed_plane_h()
