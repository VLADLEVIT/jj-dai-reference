# -*- coding: utf-8 -*-
"""
kernel.smriti — Smriti (स्मृति), the memory & continuity organ. First organ of
the Agent Kernel.

WHAT IT IS: the agent's persistent, portable *self* — the memory that makes an
agent the same agent across restarts and across hosts. Pattern borrowed from
Letta (memory tiers + portable agent state); mechanism replaced with JJ DAI's:
every mutation is witness-gated, and the thinking organ holds a structurally
read-only view. Letta lets the agent self-edit memory directly; here a write
is a witnessed event or it does not happen.

THREE TIERS (Letta's tiering, our binding):

  CORE      — bounded, ALWAYS-in-context labeled blocks (persona, directives,
              current focus). Small and char-limited. This is "who I am right
              now." Edited only through witnessed ops.
  RECALL    — append-only episodic log (what happened). Searchable history.
  ARCHIVAL  — large external knowledge with Merkle-proofed citations. This is
              exactly core.rag_store.RagStore + core.smriti.Smriti (already
              built) — the continuity organ WRAPS them as its archival tier.

CONTINUITY = EVENT SOURCING (the same discipline as registry & containment —
now applied to identity itself):

  * every core/recall mutation is an append-only journal event, each witnessed
    as a first-class MEMORY record.
  * the content rides in a HIDING commitment (memory is private) while the
    clear-text semantic_digest binds the operation and the resulting state:
        "mem:<being_id>:<op_hash>:<state_hash>"  (being_id in the clear so a
    ported bundle is filterable & attributable; provenance itself is hashed).
  * state_hash = H(canonical(identity + core + recall_head + archival_root)),
    deterministic and replay-checkable.

PORTABILITY = SELF-AUTHENTICATING STATE (pull-by-choice for the mind):

  export_portable() emits a bundle {identity, core, recall, archival_root,
  journal, witness records}. A DIFFERENT host can import_portable() and PROVE
  the identity is authentic — re-verifying the origin node's Ed25519-signed
  MEMORY records and replaying the journal to the same state_hash — WITHOUT
  trusting the origin host. Tamper in transit (an edited core block) breaks
  the binding and import refuses. The agent carries itself, cryptographically.

The thinking organ receives ReadOnlyMemory: it can read every tier and audit
the chain, but has no method that mutates — the no-write invariant is
structural (you cannot call a write that does not exist).
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import H_hex, verify as ed_verify         # noqa: E402

GENESIS = "0" * 64


class MemoryError_(RuntimeError):
    pass


class CoreBlockFull(MemoryError_):
    """A core block would exceed its char limit — the trigger for a
    (future) witnessed summarization/eviction flow. Never silently truncate
    identity."""


class PortabilityError(MemoryError_):
    """An imported AgentState failed authentication against its witness
    records — tampered, incomplete, or misattributed. Identity is refused."""


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class CoreBlock:
    label: str
    value: str = ""
    char_limit: int = 2000

    def as_dict(self) -> dict:
        return {"label": self.label, "value": self.value,
                "char_limit": self.char_limit}


@dataclass
class Episode:
    ts: float
    role: str
    text: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class AgentIdentity:
    being_id: str
    created_at: float
    kind: str = "jjdai-agent-state"
    version: str = "1"

    def as_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Read-only view handed to the thinking organ (structural no-write)
# --------------------------------------------------------------------------- #

class ReadOnlyMemory:
    """Everything a thinker may do with memory: read tiers, assemble context,
    audit the chain. Deliberately has NO mutation method."""

    def __init__(self, smriti: "SmritiContinuity"):
        self._s = smriti

    def core_blocks(self) -> dict:
        return {l: b.value for l, b in self._s._core.items()}

    def context_window(self) -> str:
        """The always-in-context CORE tier, rendered — 'who I am right now'."""
        return "\n".join(f"<{l}>\n{b.value}\n</{l}>"
                         for l, b in sorted(self._s._core.items()))

    def recent(self, n: int = 10) -> list:
        return [e.as_dict() for e in self._s._recall[-n:]]

    def recall_archival(self, query: str, k: int = 3) -> dict:
        return self._s.recall_archival(query, k)

    def state_hash(self) -> str:
        return self._s.state_hash()

    def identity(self) -> dict:
        return self._s._identity.as_dict()


# --------------------------------------------------------------------------- #
# The organ
# --------------------------------------------------------------------------- #

class SmritiContinuity:
    """Memory & continuity organ. Writes are witness-gated; reads are free."""

    def __init__(self, identity: AgentIdentity, *, witness=None,
                 journal_path: str = None, archival=None, now_fn=time.time):
        self._identity = identity
        self._witness = witness           # jjdai WitnessChain (write path)
        self._journal_path = journal_path
        self._archival = archival         # core.smriti.Smriti (read-only recall)
        self._now = now_fn
        self._core: dict = {}             # label -> CoreBlock
        self._recall: list = []           # [Episode]
        self._events: list = []           # the log IS the state
        if journal_path and os.path.exists(journal_path):
            from jjdai.durable import read_journal, truncate_torn_tail
            events, report = read_journal(journal_path)
            if report.get("torn_tail"):
                truncate_torn_tail(journal_path)
            for ev in events:
                self._apply(ev)

    # ---- read-only handle for the thinking organ ----
    def readonly(self) -> ReadOnlyMemory:
        return ReadOnlyMemory(self)

    # ------------------------------------------------------------------ #
    # CORE tier — witnessed edits
    # ------------------------------------------------------------------ #
    def core_set(self, label: str, value: str, char_limit: int = 2000) -> dict:
        if len(value) > char_limit:
            raise CoreBlockFull(f"core block {label!r}: {len(value)} > "
                                f"{char_limit} chars")
        return self._emit({"op": "core_set", "t": self._now(), "label": label,
                           "value": value, "char_limit": char_limit})

    def core_append(self, label: str, addition: str) -> dict:
        blk = self._core.get(label)
        limit = blk.char_limit if blk else 2000
        base = (blk.value + "\n") if blk and blk.value else ""
        new_val = base + addition
        if len(new_val) > limit:
            raise CoreBlockFull(f"core block {label!r} would reach "
                                f"{len(new_val)} > {limit} chars — summarize")
        return self._emit({"op": "core_append", "t": self._now(),
                           "label": label, "addition": addition})

    # ------------------------------------------------------------------ #
    # RECALL tier — witnessed append + local search
    # ------------------------------------------------------------------ #
    def recall_add(self, role: str, text: str) -> dict:
        return self._emit({"op": "recall_add", "t": self._now(),
                           "role": role, "text": text})

    def recall_search(self, query: str, k: int = 5) -> list:
        q = set(query.lower().split())
        scored = []
        for e in self._recall:
            s = len(q & set(e.text.lower().split()))
            if s:
                scored.append((s, e))
        scored.sort(key=lambda r: (-r[0], r[1].ts))
        return [e.as_dict() for _, e in scored[:k]]

    # ------------------------------------------------------------------ #
    # ARCHIVAL tier — delegated to the existing Memory Keeper (read-only)
    # ------------------------------------------------------------------ #
    def recall_archival(self, query: str, k: int = 3) -> dict:
        if self._archival is None:
            return {"answer": "[smriti] no archival tier bound",
                    "grounded": False, "citations": []}
        # core.smriti.Smriti.recall(ns, query, k) — ns keyed by being
        return self._archival.recall(self._identity.being_id, query, k)

    # ------------------------------------------------------------------ #
    # State hash + event sourcing
    # ------------------------------------------------------------------ #
    def _recall_head(self) -> str:
        h = GENESIS
        for e in self._recall:
            h = H_hex(canonical({"prev": h, "ep": e.as_dict()}))
        return h

    def _archival_root(self):
        # bound archival tier's merkle root for this being's namespace, if any
        rag = getattr(self._archival, "_rag", None)
        if rag is not None:
            try:
                return rag.merkle_root(self._identity.being_id)
            except Exception:
                return None
        return None

    def state_hash(self) -> str:
        # NOTE: only being_id (not created_at) enters the state — continuity
        # is about *who* + *content*, not birth timestamp; this also lets an
        # auditor reconstruct state from the being_id in the clear digest.
        state = {
            "being_id": self._identity.being_id,
            "core": {l: b.as_dict() for l, b in sorted(self._core.items())},
            "recall_head": self._recall_head(),
            "archival_root": self._archival_root(),
        }
        return H_hex(canonical(state))

    def _emit(self, op: dict) -> dict:
        self._apply(op)
        if self._journal_path:
            from jjdai.durable import durable_append
            durable_append(self._journal_path, op)      # fsynced
        receipt = None
        if self._witness is not None:
            op_hash = H_hex(canonical(op))
            receipt = self._witness.append(
                "MEMORY",
                request={"mem_op": op},              # -> hiding commitment
                provenance={"organ": "smriti",
                            "being_id": self._identity.being_id},
                semantic_digest=(f"mem:{self._identity.being_id}:"
                                 f"{op_hash}:{self.state_hash()}"),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(op["t"])))
        return {"op": op, "witness_receipt": receipt,
                "state_hash": self.state_hash()}

    def _apply(self, op: dict):
        self._events.append(op)
        k = op["op"]
        if k == "core_set":
            self._core[op["label"]] = CoreBlock(op["label"], op["value"],
                                                op["char_limit"])
        elif k == "core_append":
            blk = self._core.get(op["label"]) or CoreBlock(op["label"])
            blk.value = (blk.value + "\n" + op["addition"]) if blk.value \
                else op["addition"]
            self._core[op["label"]] = blk
        elif k == "recall_add":
            self._recall.append(Episode(op["t"], op["role"], op["text"]))
        else:
            raise ValueError(f"unknown memory op {k!r}")

    @property
    def events(self) -> list:
        return list(self._events)

    # ------------------------------------------------------------------ #
    # PORTABILITY — self-authenticating export / import
    # ------------------------------------------------------------------ #
    def export_portable(self) -> dict:
        """Bundle the whole self + the signed MEMORY records that prove it.
        Carryable to another host; verifiable without trusting this one."""
        wit = {"node_id": None, "pubkey": None, "records": []}
        if self._witness is not None:
            prefix = f"mem:{self._identity.being_id}:"
            recs = [r for r in self._witness.records
                    if r.get("kind") == "MEMORY"
                    and str(r.get("semantic_digest", "")).startswith(prefix)]
            wit = {"node_id": self._witness.node_id,
                   "pubkey": self.witness_pubkey_hex(),
                   "records": recs}
        return {
            "identity": self._identity.as_dict(),
            "core": {l: b.as_dict() for l, b in sorted(self._core.items())},
            "recall": [e.as_dict() for e in self._recall],
            "archival_root": self._archival_root(),
            "state_hash": self.state_hash(),
            "journal": list(self._events),
            "witness": wit,
        }

    def witness_pubkey_hex(self):
        sk = getattr(self._witness, "sk", None)
        return sk.public.hex() if sk is not None and hasattr(sk, "public") else None

    @classmethod
    def import_portable(cls, bundle: dict, *, verify: bool = True,
                        pubkey_hex: str = None, archival=None,
                        now_fn=time.time) -> "SmritiContinuity":
        """Reconstruct an agent's self on a fresh host. With verify=True the
        journal is replayed and each op's (op_hash, state_hash) binding is
        checked against the origin's Ed25519-signed MEMORY records — proving
        authenticity without trusting the exporter."""
        ident = AgentIdentity(**bundle["identity"])
        s = cls(ident, archival=archival, now_fn=now_fn)  # no witness: import
        journal = bundle.get("journal", [])

        if verify:
            recs = (bundle.get("witness") or {}).get("records", [])
            pub_hex = pubkey_hex or (bundle.get("witness") or {}).get("pubkey")
            if len(recs) != len(journal):
                raise PortabilityError(
                    f"journal/record count mismatch: {len(journal)} vs {len(recs)}")
            pub = bytes.fromhex(pub_hex) if pub_hex else None
            probe = cls(ident, archival=archival, now_fn=now_fn)
            for i, (op, rec) in enumerate(zip(journal, recs)):
                # 1. self-integrity of the record (this_hash covers the body;
                #    sig covers this_hash). NOTE: filtered MEMORY records are
                #    not prev_hash-adjacent in a mixed chain, so we verify each
                #    record standalone rather than re-chaining across them.
                body = {k: v for k, v in rec.items()
                        if k not in ("this_hash", "sig")}
                if rec.get("this_hash") != H_hex(canonical(body)):
                    raise PortabilityError(f"record {i}: hash mismatch")
                if pub is not None and not ed_verify(
                        pub, rec["this_hash"].encode(),
                        bytes.fromhex(rec["sig"])):
                    raise PortabilityError(f"record {i}: bad signature")
                # 2. the binding: being + op + resulting state must match the
                #    record's clear-text digest (identity attribution included)
                probe._apply(op)
                expected = (f"mem:{ident.being_id}:{H_hex(canonical(op))}:"
                            f"{probe.state_hash()}")
                if rec.get("semantic_digest") != expected:
                    raise PortabilityError(
                        f"record {i}: being/op/state binding broken "
                        "(tamper, misattribution, or forgery)")
            if probe.state_hash() != bundle.get("state_hash"):
                raise PortabilityError("final state_hash mismatch")

        for op in journal:                 # reconstruct (verified) state
            s._apply(op)
        if s.state_hash() != bundle.get("state_hash"):
            raise PortabilityError("reconstructed state_hash mismatch")
        return s


def verify_memory_against_chain(events: list, chain_records: list) -> int:
    """Auditor check mirroring registry/containment: every MEMORY op appears,
    in order, as a MEMORY record whose semantic_digest binds op + state. Uses
    a fresh replayer to recompute state_hash at each step. Returns count."""
    recs = [r for r in chain_records if r.get("kind") == "MEMORY"]
    if len(recs) != len(events):
        raise PortabilityError(
            f"count mismatch: {len(events)} ops vs {len(recs)} records")
    ident = None
    for op in events:                      # identity is implicit in provenance
        break
    # replay via a throwaway organ keyed to the records' being
    def _parse_being(digest: str) -> str:
        # digest = "mem:<being_id>:<op_hash>:<state_hash>"; being_id itself
        # contains a colon (e.g. "being:x"), so strip the fixed prefix and the
        # two trailing hash fields rather than a naive split.
        body = digest[len("mem:"):]
        return body.rsplit(":", 2)[0]

    being = _parse_being(str(recs[0].get("semantic_digest", "mem:being:unknown::")
                             )) if recs else "being:unknown"
    probe = SmritiContinuity(AgentIdentity(being, 0.0))
    for i, (op, rec) in enumerate(zip(events, recs)):
        probe._apply(op)
        expected = f"mem:{being}:{H_hex(canonical(op))}:{probe.state_hash()}"
        if rec.get("semantic_digest") != expected:
            raise PortabilityError(f"binding broken at op {i}")
    return len(events)
