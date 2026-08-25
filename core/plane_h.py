# -*- coding: utf-8 -*-
"""
core.plane_h — Governed knowledge lifecycle for Plane H (v0.5, P1)
==================================================================
The write path required by the Whitepaper, layered OVER the M5 RagStore
(composition, not modification — RagStore stays the continuity component):

    proposal (signed)
      -> validation        (signature, node_id, content hash, schema)
      -> authorization     (per-namespace ACL, fail closed)
      -> append            (RagStore chunk + governance metadata)
      -> Merkle commitment (namespace root, jjdai.merkle)
      -> witness record    (kind MEMORY: committed envelope + public digest)

Every record carries: author identity + signature, source provenance,
created_at, supersedes/version, access policy, retention policy, redaction
status, jurisdiction, confidence, evidence references.

Lifecycle semantics:
  * SUPERSEDE — new version appended; the old chunk remains (history is
    append-only) but is excluded from retrieval and points forward via
    `superseded_by`.
  * REDACT — the TEXT is removed from the store; the content HASH remains
    as the Merkle leaf (content-addressed tombstone). Namespace roots are
    therefore UNCHANGED by redaction: history integrity survives content
    removal. The signed proposal itself stays verifiable because authors
    sign the content hash, not the text.

Authorization is deliberately store-level in this drop: exposing writes
over the node's HTTP surface belongs to the authenticated node-to-node
protocol (P1 item 6) — an unauthenticated write endpoint would be a hole,
not a feature.
"""
from __future__ import annotations

import json
import time

from jjdai.canonical import canonical
from jjdai.crypto import (H_hex, SigningKey, verify, node_id,
                          canonical_being_id, canonical_node_id)
from jjdai.reserved import check_namespace_free
from core.rag_store import RagStore, sha256_text

PROPOSAL_DOMAIN = b"jjdai/plane-h/proposal/v1:"
#: The AUTHOR's statement, separate from the node's (recut5, audit P0.3).
#: A proposal is authored by a BEING and witnessed by a NODE; before this
#: the being key existed and signed nothing, so even a Being-authored
#: knowledge write carried only the node signature and "authored by the
#: being" was a sentence with no cryptography behind it.
AUTHOR_DOMAIN = b"jjdai/plane-h/author/v1:"

OPS = ("add", "supersede", "redact")
ACCESS_LEVELS = ("public", "internal", "restricted")
_ACCESS_RANK = {a: i for i, a in enumerate(ACCESS_LEVELS)}


class PlaneHError(RuntimeError):
    pass


class AuthorizationError(PlaneHError):
    pass


class ValidationError(PlaneHError):
    pass


# --------------------------------------------------------------------------- #
#  Signed write proposals
# --------------------------------------------------------------------------- #

def make_write_proposal(sk: SigningKey, *, op: str, ns: str, doc_id: str,
                        text: str = None, target_chunk: int = None,
                        source: dict = None, jurisdiction: str = "UA",
                        confidence: float = 1.0, evidence_refs: list = None,
                        access_policy: str = "internal",
                        retention: dict = None,
                        being_sk: SigningKey = None) -> dict:
    """Author-side construction of a signed proposal. The TEXT itself is not
    inside the signed body — only its hash — so redaction can later remove
    content without invalidating the historical envelope.

    TWO SIGNATURES, TWO DIFFERENT CLAIMS (recut5, audit P0.3). `sk` is the
    NODE key: it says this node accepted the write and will carry it. When
    `being_sk` is given the body additionally names `author_being` and the
    envelope carries that being's own signature over the same payload: the
    being says it authored this. The being's signature is INSIDE what the
    node then witnesses, which is the shape INV-9 requires — the witness
    plane is never signed BY the being, and what the being authored is
    never merely attributed to it.
    """
    if op not in OPS:
        raise ValidationError(f"unknown op {op!r}")
    if op in ("add", "supersede") and not text:
        raise ValidationError(f"op {op!r} requires text")
    if op in ("supersede", "redact") and target_chunk is None:
        raise ValidationError(f"op {op!r} requires target_chunk")
    body = {
        "kind": "RAG_WRITE_PROPOSAL",
        "op": op,
        "ns": ns,
        "doc_id": doc_id,
        "content_hash": sha256_text(text) if text is not None else None,
        "target_chunk": target_chunk,
        "source": source or {"type": "unspecified"},
        "jurisdiction": jurisdiction,
        "confidence": float(confidence),
        "evidence_refs": list(evidence_refs or []),
        "access_policy": access_policy,
        "retention": retention or {"policy": "indefinite", "until": None},
        "author_node": canonical_node_id(sk.public),
        "author_being": (canonical_being_id(being_sk.public)
                         if being_sk is not None else None),
        "created_at": time.time(),
    }
    payload = PROPOSAL_DOMAIN + canonical(body)
    env = {"body": body, "pub": sk.public.hex(),
           "sig": sk.sign(payload).hex()}
    if being_sk is not None:
        env["being_pub"] = being_sk.public.hex()
        env["being_sig"] = being_sk.sign(AUTHOR_DOMAIN
                                         + canonical(body)).hex()
    return env


def verify_write_proposal(env: dict, text: str = None) -> tuple:
    """Offline verification of a proposal envelope (+ text binding)."""
    try:
        body, pub, sig = env["body"], bytes.fromhex(env["pub"]), bytes.fromhex(env["sig"])
    except (KeyError, TypeError, ValueError):
        return False, "malformed envelope"
    if body.get("kind") != "RAG_WRITE_PROPOSAL":
        return False, "wrong kind"
    if body.get("op") not in OPS:
        return False, "unknown op"
    if canonical_node_id(pub) != body.get("author_node"):
        return False, "author_node does not match public key"
    if body.get("access_policy") not in ACCESS_LEVELS:
        return False, "unknown access policy"
    conf = body.get("confidence")
    if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
        return False, "confidence out of range"
    if body["op"] in ("add", "supersede"):
        if text is None:
            return False, "text required for this op"
        if sha256_text(text) != body.get("content_hash"):
            return False, "content hash mismatch"
    if not verify(pub, PROPOSAL_DOMAIN + canonical(body), sig):
        return False, "bad signature"
    # The author statement, when the body claims one. Fail-closed: a body
    # that NAMES an authoring being without the being's signature is worse
    # than one that names none, because it reads as authored.
    author_being = body.get("author_being")
    if author_being is not None:
        try:
            bpub = bytes.fromhex(env["being_pub"])
            bsig = bytes.fromhex(env["being_sig"])
        except (KeyError, TypeError, ValueError):
            return False, "author_being named without a being signature"
        if canonical_being_id(bpub) != author_being:
            return False, "author_being does not match the being public key"
        if not verify(bpub, AUTHOR_DOMAIN + canonical(body), bsig):
            return False, "bad being signature"
    elif "being_sig" in env:
        return False, "being signature without an author_being in the body"
    return True, "ok"


# --------------------------------------------------------------------------- #
#  Authorization policy
# --------------------------------------------------------------------------- #

class WritePolicy:
    """Per-namespace ACL. FAIL CLOSED: unknown namespace or unlisted author
    means refusal. Grants are per-op sets of author node_ids."""

    def __init__(self):
        self._grants: dict = {}      # ns -> op -> set(node_id)

    def grant(self, ns: str, author_node: str, ops=OPS):
        # v0.6.8: a reserved namespace is refused at the door where authority
        # over it would be created, not only where a write arrives.
        check_namespace_free(ns, op="grant")
        for op in ops:
            if op not in OPS:
                raise ValidationError(f"unknown op {op!r}")
            self._grants.setdefault(ns, {}).setdefault(op, set()).add(author_node)

    def revoke(self, ns: str, author_node: str, ops=OPS):
        for op in ops:
            self._grants.get(ns, {}).get(op, set()).discard(author_node)

    def permits(self, ns: str, op: str, author_node: str) -> bool:
        return author_node in self._grants.get(ns, {}).get(op, set())

    def snapshot(self) -> dict:
        return {ns: {op: sorted(v) for op, v in ops.items()}
                for ns, ops in self._grants.items()}


# --------------------------------------------------------------------------- #
#  Governed store
# --------------------------------------------------------------------------- #

class GovernedPlaneH:
    """Governance layer over RagStore: signed writes, lifecycle, witness."""

    def __init__(self, store: RagStore, policy: WritePolicy,
                 witness=None, governor_node: str = None):
        self.store = store
        self.policy = policy
        self.witness = witness            # WitnessChain or None
        self.governor_node = governor_node
        self.store.db.execute(
            "CREATE TABLE IF NOT EXISTS chunk_meta ("
            " chunk_id INTEGER PRIMARY KEY,"
            " version INTEGER NOT NULL DEFAULT 1,"
            " supersedes INTEGER,"
            " superseded_by INTEGER,"
            " redacted INTEGER NOT NULL DEFAULT 0,"
            " author_node TEXT NOT NULL,"
            " envelope TEXT NOT NULL,"
            " redaction_envelope TEXT,"
            " created_at REAL NOT NULL)")
        self.store.db.commit()

    # ---- pipeline -------------------------------------------------------- #
    def apply(self, env: dict, text: str = None) -> dict:
        """proposal -> validation -> authorization -> append -> Merkle
        -> witness. Returns the applied record with an inclusion proof.

        ATOMICITY (v0.5): the store mutation and the witness record commit
        together or not at all. The SQLite work runs inside an explicit
        transaction that is COMMITted only after the witness append has
        durably succeeded; any witness failure rolls the knowledge back.
        There must be no unwitnessed mutable knowledge — a chunk that the
        Sākṣī never saw must not exist.
        """
        ok, reason = verify_write_proposal(env, text)
        if not ok:
            raise ValidationError(f"proposal rejected: {reason}")
        b = env["body"]
        ns, op, author = b["ns"], b["op"], b["author_node"]
        check_namespace_free(ns, op=op)          # v0.6.8, pre-genesis reserve
        if not self.policy.permits(ns, op, author):
            raise AuthorizationError(
                f"author {author[:16]}… not authorized for {op!r} in {ns!r}")

        db = self.store.db
        try:
            if op == "add":
                applied = self._apply_add(env, text)
            elif op == "supersede":
                applied = self._apply_supersede(env, text)
            else:
                applied = self._apply_redact(env)

            root = self.store.merkle_root(ns)
            applied["ns_root"] = root
            if self.witness is not None:
                self.witness.append(
                    "MEMORY",
                    response=env,                       # committed (hiding)
                    semantic_digest={                   # public, auditable
                        "plane": "H", "op": op, "ns": ns,
                        "doc_id": b["doc_id"],
                        "chunk_id": applied["chunk_id"],
                        "content_hash": b["content_hash"],
                        "author_node": author,
                        "authorized_by": self.governor_node,
                        "ns_root": root})
        except BaseException:
            db.rollback()          # unwitnessed knowledge must not survive
            raise
        db.commit()
        return applied

    # ---- op semantics ----------------------------------------------------- #
    def _meta_row(self, chunk_id: int) -> dict | None:
        row = self.store.db.execute(
            "SELECT chunk_id, version, supersedes, superseded_by, redacted,"
            " author_node, envelope, redaction_envelope, created_at"
            " FROM chunk_meta WHERE chunk_id=?", (chunk_id,)).fetchone()
        if not row:
            return None
        keys = ("chunk_id", "version", "supersedes", "superseded_by",
                "redacted", "author_node", "envelope", "redaction_envelope",
                "created_at")
        return dict(zip(keys, row))

    def _apply_add(self, env: dict, text: str) -> dict:
        b = env["body"]
        chunk_id, h = self.store.add(b["ns"], b["doc_id"], text,
                                     commit=False)
        self.store.db.execute(
            "INSERT INTO chunk_meta (chunk_id, version, author_node,"
            " envelope, created_at) VALUES (?,?,?,?,?)",
            (chunk_id, 1, b["author_node"], json.dumps(env), b["created_at"]))
        return {"op": "add", "chunk_id": chunk_id, "hash": h, "version": 1,
                "proof": self.store.prove(b["ns"], chunk_id)}

    def _apply_supersede(self, env: dict, text: str) -> dict:
        b = env["body"]
        target = b["target_chunk"]
        told = self.store.get(target)
        tmeta = self._meta_row(target)
        if not told or not tmeta:
            raise ValidationError(f"supersede target {target} not found")
        if told["ns"] != b["ns"] or told["doc_id"] != b["doc_id"]:
            raise ValidationError("supersede must stay within ns/doc_id")
        if tmeta["superseded_by"] is not None:
            raise ValidationError(
                f"target {target} already superseded by {tmeta['superseded_by']}")
        if tmeta["redacted"]:
            raise ValidationError("cannot supersede a redacted chunk")
        chunk_id, h = self.store.add(b["ns"], b["doc_id"], text,
                                     commit=False)
        version = tmeta["version"] + 1
        self.store.db.execute(
            "INSERT INTO chunk_meta (chunk_id, version, supersedes,"
            " author_node, envelope, created_at) VALUES (?,?,?,?,?,?)",
            (chunk_id, version, target, b["author_node"], json.dumps(env),
             b["created_at"]))
        self.store.db.execute(
            "UPDATE chunk_meta SET superseded_by=? WHERE chunk_id=?",
            (chunk_id, target))
        return {"op": "supersede", "chunk_id": chunk_id, "hash": h,
                "version": version, "supersedes": target,
                "proof": self.store.prove(b["ns"], chunk_id)}

    def _apply_redact(self, env: dict) -> dict:
        b = env["body"]
        target = b["target_chunk"]
        told = self.store.get(target)
        tmeta = self._meta_row(target)
        if not told or not tmeta:
            raise ValidationError(f"redact target {target} not found")
        if told["ns"] != b["ns"]:
            raise ValidationError("redact must name the chunk's namespace")
        if tmeta["redacted"]:
            raise ValidationError(f"chunk {target} already redacted")
        # CONTENT-ADDRESSED TOMBSTONE: text goes, hash stays (Merkle leaf
        # unchanged — namespace root survives redaction).
        self.store.db.execute(
            "UPDATE chunks SET text=NULL WHERE id=?", (target,))
        self.store.db.execute(
            "UPDATE chunk_meta SET redacted=1, redaction_envelope=?"
            " WHERE chunk_id=?", (json.dumps(env), target))
        return {"op": "redact", "chunk_id": target,
                "hash": told["hash"], "version": tmeta["version"],
                "proof": self.store.prove(b["ns"], target)}

    # ---- governed reads ---------------------------------------------------- #
    def describe(self, chunk_id: int) -> dict | None:
        """Full governance card of a chunk (metadata + lifecycle state)."""
        row = self.store.get(chunk_id)
        meta = self._meta_row(chunk_id)
        if not row or not meta:
            return None
        env = json.loads(meta["envelope"])
        b = env["body"]
        return {
            "chunk_id": chunk_id, "ns": row["ns"], "doc_id": row["doc_id"],
            "hash": row["hash"], "redacted": bool(meta["redacted"]),
            "version": meta["version"], "supersedes": meta["supersedes"],
            "superseded_by": meta["superseded_by"],
            "author_node": meta["author_node"],
            "source": b["source"], "jurisdiction": b["jurisdiction"],
            "confidence": b["confidence"],
            "evidence_refs": b["evidence_refs"],
            "access_policy": b["access_policy"],
            "retention": b["retention"],
            "created_at": meta["created_at"],
            "envelope": env,
        }

    def retrieve(self, ns: str, query: str, k: int = 3, *,
                 access: str = "public", now: float = None) -> list:
        """Governed retrieval: excludes redacted, superseded, retention-
        expired and above-access chunks; results carry provenance + proof."""
        if access not in ACCESS_LEVELS:
            raise ValidationError(f"unknown access level {access!r}")
        # v0.6.8: ordinary retrieval never reaches a reserved namespace. A
        # draft reflection is reachable only through `hypothesis_retrieval`,
        # marked UNVALIDATED — and that mode does not exist yet, so there is
        # no way in at all. Temporary memory is refused here for the same
        # reason: its evidentiary status has no grammar before Ф2.
        check_namespace_free(ns, op="retrieve")
        now = now if now is not None else time.time()
        raw = self.store.retrieve(ns, query, k=k * 4 or 12)
        out = []
        for r in raw:
            card = self.describe(r["chunk_id"])
            if card is None or card["redacted"] or card["superseded_by"]:
                continue
            if _ACCESS_RANK[card["access_policy"]] > _ACCESS_RANK[access]:
                continue
            ret = card["retention"]
            if ret.get("policy") == "until" and ret.get("until") is not None \
                    and now > float(ret["until"]):
                continue
            out.append({**r,
                        "version": card["version"],
                        "author_node": card["author_node"],
                        "source": card["source"],
                        "confidence": card["confidence"],
                        "evidence_refs": card["evidence_refs"],
                        "access_policy": card["access_policy"]})
            if len(out) >= k:
                break
        return out
