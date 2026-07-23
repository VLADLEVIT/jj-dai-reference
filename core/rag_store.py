# -*- coding: utf-8 -*-
"""
core.rag_store — M5 RAG store, MIGRATED onto the jjdai primitive layer.

README migration executed: the inline Merkle implementation is gone — roots,
proofs, and verification now come from `jjdai.merkle` (the single, domain-
separated implementation shared with the witness anchor and substrate
content-addressing). Hashing goes through `jjdai.crypto.H_hex`.

CONTINUITY NOTE (proved by test_migration.py): jjdai.merkle was factored out
of this store's domain-v2 scheme — leaf = H(0x00 ‖ chunk_hash_bytes), node =
H(0x01 ‖ L ‖ R), odd node duplicated — so namespace roots computed here are
BYTE-IDENTICAL to the legacy prototype's roots. No re-baseline was needed;
M5 grounding history remains valid. Only the proof PATH format changed:
elements are now (side, sibling) with side ∈ {"L","R"} naming the sibling's
position (jjdai convention), and proofs are labelled scheme="jjdai-merkle".

Everything else is unchanged from the prototype: sqlite chunk store, the
eval/RAG separation guard (canaries must never become open-book), and the
honest retrieval seam (naive token overlap; production = sqlite-vec + a real
embedder — checkability of citations is what M5 proves, not ranking).
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.crypto import H_hex                                  # noqa: E402
from jjdai.merkle import merkle_root, merkle_proof, merkle_verify  # noqa: E402

SCHEME = "jjdai-merkle"


class EvalRagOverlapError(RuntimeError):
    """Eval (canary) store and RAG store share a path — canaries would become
    open-book."""


def _overlaps(a: str, b: str) -> bool:
    ra = os.path.realpath(os.path.abspath(a)).rstrip(os.sep) + os.sep
    rb = os.path.realpath(os.path.abspath(b)).rstrip(os.sep) + os.sep
    return ra.startswith(rb) or rb.startswith(ra)


def _tok(s: str) -> set:
    return set(re.findall(r"[\w\u0400-\u04FF]{3,}", s.lower()))


def sha256_text(text: str) -> str:
    return H_hex(text.encode("utf-8"))


class RagStore:
    def __init__(self, db_path: str, eval_dir: str | None = None):
        if eval_dir and _overlaps(os.path.dirname(os.path.abspath(db_path))
                                  or ".", eval_dir):
            raise EvalRagOverlapError(
                f"RAG store {db_path!r} overlaps eval store {eval_dir!r}: "
                "canaries would become open-book. Separate them.")
        # check_same_thread=False (v0.5.3): the BeingRuntime serves tasks from
        # HTTP handler threads; access is serialized by the runtime's task
        # lock, sqlite itself runs in the default serialized threading mode.
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS chunks ("
            " id INTEGER PRIMARY KEY, ns TEXT, doc_id TEXT,"
            " text TEXT, hash TEXT)")
        self.db.commit()

    # ---------- write ----------
    def add(self, ns: str, doc_id: str, text: str, *, commit: bool = True) -> tuple:
        """Append a chunk. commit=False defers the COMMIT to the caller so a
        governance layer can bind the write to a witness record atomically
        (see core.plane_h.GovernedPlaneH.apply)."""
        h = sha256_text(text)
        cur = self.db.execute(
            "INSERT INTO chunks (ns, doc_id, text, hash) VALUES (?,?,?,?)",
            (ns, doc_id, text, h))
        if commit:
            self.db.commit()
        return cur.lastrowid, h

    # ---------- merkle (via jjdai.merkle — leaf inputs are BYTES) ----------
    def _leaves(self, ns: str) -> list:
        return list(self.db.execute(
            "SELECT id, hash FROM chunks WHERE ns=? ORDER BY id", (ns,)))

    def _leaf_bytes(self, ns: str) -> list:
        return [bytes.fromhex(h) for _, h in self._leaves(ns)]

    def merkle_root(self, ns: str) -> str:
        return merkle_root(self._leaf_bytes(ns))

    def prove(self, ns: str, chunk_id: int) -> dict | None:
        """Inclusion proof for one chunk, in jjdai.merkle path format."""
        leaves = self._leaves(ns)
        idx = next((i for i, (cid, _) in enumerate(leaves)
                    if cid == chunk_id), None)
        if idx is None:
            return None
        lb = self._leaf_bytes(ns)
        return {"chunk_id": chunk_id, "leaf": leaves[idx][1],
                "path": merkle_proof(lb, idx),
                "root": merkle_root(lb), "scheme": SCHEME}

    @staticmethod
    def verify_proof(proof: dict) -> bool:
        if proof.get("scheme") != SCHEME:
            return False
        return merkle_verify(bytes.fromhex(proof["leaf"]),
                             proof["path"], proof["root"])

    # ---------- read ----------
    def get(self, chunk_id: int) -> dict | None:
        row = self.db.execute(
            "SELECT id, ns, doc_id, text, hash FROM chunks WHERE id=?",
            (chunk_id,)).fetchone()
        if not row:
            return None
        return dict(zip(("id", "ns", "doc_id", "text", "hash"), row))

    def retrieve(self, ns: str, query: str, k: int = 3) -> list:
        """Top-k chunks by naive token overlap, each with an inclusion proof.
        HONEST SEAM: production swaps in sqlite-vec + a real embedder; the
        interface (chunks + proofs) and all Merkle machinery stay unchanged."""
        q = _tok(query)
        scored = []
        for cid, doc, text, h in self.db.execute(
                "SELECT id, doc_id, text, hash FROM chunks"
                " WHERE ns=? AND text IS NOT NULL", (ns,)):
            s = len(q & _tok(text))
            if s:
                scored.append((s, cid, doc, text, h))
        scored.sort(key=lambda r: (-r[0], r[1]))
        return [{"chunk_id": cid, "doc_id": doc, "text": text, "hash": h,
                 "score": s, "proof": self.prove(ns, cid)}
                for s, cid, doc, text, h in scored[:k]]
