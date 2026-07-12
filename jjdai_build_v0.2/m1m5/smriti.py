"""JJ DAI v0.1 — Smriti, the Memory Keeper (स्मृति, "remembrance").

The complement of the witness. Where Sākṣī (WitnessLog) writes and never judges,
Smriti reads and never writes:

  * Smriti is an AGENT — it retrieves, ranks, and synthesizes memory. It may
    "think", because it is watched.
  * Smriti is a NON-WRITER — it holds a read-only WitnessReader and a RagStore,
    never a write-capable WitnessLog. The no-write invariant is STRUCTURAL: the
    write methods are simply absent from what it is handed.
  * Smriti's own outputs are witnessed like any inference — through the NODE's
    daemon (an INFER record), never by Smriti touching the ledger itself.

This is the resolution of "can the witness be an agent?": no. Split the organ.
The one who decides (Smriti) is never the one who attests (Sākṣī). Memory here
is checkable provenance, not trust-me text: every citation carries a Merkle
inclusion proof (M5), and Smriti grounds strictly in citations that verify.

ENGINE SEAM: MemoryEngine is the narrow-waist for the (future) narrowly-trained
memory model. In this container MockMemoryEngine stands in — deterministic, and
honest about grounding only in what was retrieved.
"""
from __future__ import annotations
from typing import Protocol

from proto import sha256_text
from rag_store import RagStore
from witness import WitnessReader


class MemoryEngine(Protocol):
    """Narrow-waist seam for the memory model. Production: a small model trained
    to store/retrieve and synthesize grounded answers behind /v1/messages."""
    def synthesize(self, query: str, chunks: list) -> str: ...


class MockMemoryEngine:
    """Deterministic stand-in (v0.1). Grounds strictly in retrieved chunks;
    never free-generates beyond what memory supplied."""
    def synthesize(self, query: str, chunks: list) -> str:
        if not chunks:
            return "[smriti] no grounded memory for this query"
        cited = "; ".join(f"#{c['chunk_id']}" for c in chunks)
        return (f"[smriti] recalled {len(chunks)} verified chunk(s) for "
                f"{query!r} (cited {cited})")


class Smriti:
    """The Memory Keeper: an agent that recalls, bound by a no-write invariant."""

    def __init__(self, rag: RagStore, engine: MemoryEngine, witness: WitnessReader):
        # Structural no-write guard: refuse anything that can append to a ledger.
        if hasattr(witness, "append") or hasattr(witness, "emit_infer"):
            raise TypeError(
                "Smriti must receive a read-only WitnessReader, never a "
                "write-capable WitnessLog — the no-write invariant is structural.")
        self._rag = rag
        self._engine = engine
        self._witness = witness

    def recall(self, ns: str, query: str, k: int = 3) -> dict:
        """Retrieve, verify each citation's Merkle proof, synthesize grounded.

        Pure: no side effects, no ledger write. Returns the answer plus
        per-citation verification, so a caller can see memory is checkable."""
        hits = self._rag.retrieve(ns, query, k)
        citations = []
        for h in hits:
            proof = h.get("proof")
            verified = bool(proof) and RagStore.verify_proof(proof)
            citations.append({
                "chunk_id": h["chunk_id"], "text": h["text"], "score": h["score"],
                "verified": verified, "root": proof["root"] if proof else None,
            })
        verified_hits = [c for c in citations if c["verified"]]
        answer = self._engine.synthesize(query, verified_hits)
        return {
            "ns": ns, "query": query, "answer": answer,
            "citations": citations,
            "grounded": len(verified_hits) > 0,
            "all_verified": all(c["verified"] for c in citations) if citations else True,
        }

    def audit(self, pubkey_resolver=None) -> tuple:
        """Smriti CAN read and verify the ledger — Purusha's record is public —
        it simply cannot write to it."""
        return self._witness.verify(pubkey_resolver)


def witnessed_recall(smriti: Smriti, daemon, ns: str, query: str) -> dict:
    """Run a recall and have the NODE witness it (INFER record), so Smriti's
    output is attributable without Smriti ever touching the ledger.

    `daemon` is a NodeDaemon (or anything exposing a write-capable `.witness`).
    The witness write is performed by the NODE, not by Smriti — that is the
    whole point of the split.
    """
    result = smriti.recall(ns, query)
    head = daemon.witness.append("INFER", {
        "smriti_recall": {
            "ns": ns, "query": query,
            "answer_hash": sha256_text(result["answer"]),
            "citations": [c["chunk_id"] for c in result["citations"]],
            "grounded": result["grounded"],
        }
    })
    result["witness_head"] = head
    return result
