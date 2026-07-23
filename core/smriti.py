# -*- coding: utf-8 -*-
"""
core.smriti — Smriti, the Memory Keeper (स्मृति), MIGRATED onto jjdai.

The organ split is unchanged and now binds to the canonical modules:

    Sakshi  = jjdai.witness.WitnessChain   — writes and never judges.
    Smriti  = this module + WitnessReader  — reads and never writes.

  * Smriti is an AGENT — it retrieves, ranks, synthesizes. It may "think",
    because it is watched.
  * The no-write invariant is STRUCTURAL: Smriti is handed a read-only
    jjdai.witness.WitnessReader; construction REFUSES anything exposing
    append()/emit_infer()/anchor_root() — a WitnessChain cannot get in.
  * Smriti's outputs are witnessed by the NODE (an INFER record on the node's
    WitnessChain, with HIDING commitments — query/answer plaintext never
    touches the ledger), never by Smriti itself.
  * Every citation carries a jjdai.merkle inclusion proof and Smriti grounds
    strictly in citations that verify — memory is checkable provenance.

ENGINE SEAM: MemoryEngine is the narrow waist for the (future) narrowly-
trained memory model; MockMemoryEngine stands in, deterministic and honest
about grounding only in what was retrieved. (HOLA surprise-weighted ranking
remains backlog on the retrieval side.)
"""
from __future__ import annotations

import os
import sys
from typing import Protocol

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.crypto import H_hex                                  # noqa: E402
from core.rag_store import RagStore                             # noqa: E402

_WRITE_METHODS = ("append", "emit_infer", "emit_sandbox", "anchor_root")


def _semantic_digest(text: str) -> str:
    buckets = [0] * 8
    for ch in text:
        buckets[ord(ch) % 8] += 1
    return ",".join(str(b) for b in buckets)


class MemoryEngine(Protocol):
    def synthesize(self, query: str, chunks: list) -> str: ...


class MockMemoryEngine:
    """Deterministic stand-in. Grounds strictly in retrieved chunks; never
    free-generates beyond what memory supplied."""
    def synthesize(self, query: str, chunks: list) -> str:
        if not chunks:
            return "[smriti] no grounded memory for this query"
        cited = "; ".join(f"#{c['chunk_id']}" for c in chunks)
        return (f"[smriti] recalled {len(chunks)} verified chunk(s) for "
                f"{query!r} (cited {cited})")


class Smriti:
    """The Memory Keeper: an agent that recalls, bound by a no-write invariant."""

    def __init__(self, rag: RagStore, engine: MemoryEngine, witness):
        for m in _WRITE_METHODS:
            if hasattr(witness, m):
                raise TypeError(
                    "Smriti must receive a read-only jjdai WitnessReader, "
                    f"never a write-capable ledger (found .{m}()) — the "
                    "no-write invariant is structural.")
        self._rag = rag
        self._engine = engine
        self._witness = witness

    def recall(self, ns: str, query: str, k: int = 3) -> dict:
        """Retrieve, verify each citation's Merkle proof, synthesize grounded.
        Pure: no side effects, no ledger write."""
        hits = self._rag.retrieve(ns, query, k)
        citations = []
        for h in hits:
            proof = h.get("proof")
            verified = bool(proof) and RagStore.verify_proof(proof)
            citations.append({
                "chunk_id": h["chunk_id"], "text": h["text"],
                "score": h["score"], "verified": verified,
                "root": proof["root"] if proof else None,
            })
        verified_hits = [c for c in citations if c["verified"]]
        answer = self._engine.synthesize(query, verified_hits)
        return {
            "ns": ns, "query": query, "answer": answer,
            "citations": citations,
            "grounded": len(verified_hits) > 0,
            "all_verified": (all(c["verified"] for c in citations)
                             if citations else True),
        }

    def audit(self, pubkey_resolver=None) -> tuple:
        """Smriti CAN read and verify the ledger — Purusha's record is public
        — it simply cannot write to it."""
        return self._witness.verify(pubkey_resolver)


def witnessed_recall(smriti: Smriti, daemon, ns: str, query: str) -> dict:
    """Run a recall and have the NODE witness it (INFER record on the node's
    jjdai WitnessChain), so Smriti's output is attributable without Smriti
    ever touching the ledger. Hiding commitments only — the query and answer
    plaintext never enter the chain."""
    result = smriti.recall(ns, query)
    receipt = daemon.witness.append(
        "INFER",
        request={"smriti_recall": {"ns": ns, "query": query}},
        response={"answer_hash": H_hex(result["answer"].encode()),
                  "citations": [c["chunk_id"] for c in result["citations"]],
                  "grounded": result["grounded"]},
        provenance={"role": "smriti", "engine": type(smriti._engine).__name__},
        semantic_digest=_semantic_digest(result["answer"]),
    )
    result["witness_receipt"] = receipt
    return result
