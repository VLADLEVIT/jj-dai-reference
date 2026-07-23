"""JJ DAI v0.1 — M1 canary (eval) store.

Holds the control tasks ("canaries") in a directory that is STRUCTURALLY
separated from any RAG namespace the model can read. If the eval store lived
inside (or contained) the RAG store, canaries would become open-book: the
model could retrieve the expected answers, and the eval would measure lookup,
not reasoning (whitepaper §6 — Plane B trust anchor).

The separation is enforced at construction, in BOTH directions:

    CanaryStore(eval_dir=..., rag_dir=...)   raises EvalRagOverlapError if
                                             either path contains the other.
    RagStore(db_path, eval_dir=...)          performs the mirror check.

Storage: one JSON file per canary (append-friendly, diffable, no deps).

(Reconstructed 2026-07-12 to the original M1 interface — CanaryStore,
_overlaps, EvalRagOverlapError — as exercised by demo.py and rag_store.py.)
"""
from __future__ import annotations
import json
import os
from dataclasses import asdict

from proto import Canary


class EvalRagOverlapError(RuntimeError):
    """Raised when the eval (canary) store and a RAG store share a path —
    the configuration that turns every canary into an open-book question."""


def _overlaps(a: str, b: str) -> bool:
    """True if path `a` contains `b` or `b` contains `a` (or they are equal).

    Comparison is on absolute, normalised, real paths with a trailing
    separator appended, so "/x/rag" does NOT falsely match "/x/rag_evals".
    """
    ra = os.path.realpath(os.path.abspath(a))
    rb = os.path.realpath(os.path.abspath(b))
    pa = ra.rstrip(os.sep) + os.sep
    pb = rb.rstrip(os.sep) + os.sep
    return pa.startswith(pb) or pb.startswith(pa)


class CanaryStore:
    """Directory-backed store of Canary records, guarded against RAG overlap."""

    def __init__(self, eval_dir: str, rag_dir: str | None = None):
        if rag_dir and _overlaps(eval_dir, rag_dir):
            raise EvalRagOverlapError(
                f"eval store {eval_dir!r} overlaps RAG store {rag_dir!r}: "
                "canaries would become open-book. Separate them.")
        self.eval_dir = os.path.abspath(eval_dir)
        os.makedirs(self.eval_dir, exist_ok=True)

    # ---------- write ----------
    def add(self, canary: Canary) -> str:
        """Persist a canary; returns its file path."""
        path = self._path(canary.id)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(canary), f, ensure_ascii=False, sort_keys=True)
        return path

    # ---------- read ----------
    def get(self, canary_id: str) -> Canary | None:
        path = self._path(canary_id)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return Canary(**json.load(f))

    def all(self) -> list[Canary]:
        out = []
        for name in sorted(os.listdir(self.eval_dir)):
            if name.endswith(".json"):
                with open(os.path.join(self.eval_dir, name),
                          encoding="utf-8") as f:
                    out.append(Canary(**json.load(f)))
        return out

    def ids(self) -> list[str]:
        return [c.id for c in self.all()]

    # ---------- internal ----------
    def _path(self, canary_id: str) -> str:
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_"
                       for ch in canary_id)
        return os.path.join(self.eval_dir, safe + ".json")
