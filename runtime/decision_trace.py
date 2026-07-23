# -*- coding: utf-8 -*-
"""
runtime.decision_trace — the record of one decision's life (v0.5.3)
===================================================================
A DecisionTrace is what POST /v1/tasks returns instead of a bare model
completion: the full, witnessed account of one task's passage through the
Being — every state it entered, every organ that touched it, every piece
of evidence it produced, and the honest name of how it ended.

The happy path:

    RECEIVED -> GROUNDED -> PLANNED -> GENERATED -> VERIFIED
             -> AUTHORIZED -> ACTED -> RECORDED

Terminal branches, each with exact semantics:

    REFUSED       the Being declined honestly (policy, missing panel,
                  failed verification) — a first-class outcome, not an
                  error
    FAILED        an internal fault; the reason is witnessed
    FATE_UNKNOWN  an action's INTENT is witnessed but its OUTCOME is not
                  (crash between the two): the honest system says
                  "I do not know", it never invents an ending
    CONTAINED     Article 25: the executive hand is severed, but memory,
                  recall and deliberation in the trace remain intact —
                  containment stops the hand, not the mind

Tasks whose action needs no executive hand (pure answers) pass through
AUTHORIZED and ACTED with action=None — the states are still visited so
every trace reads the same shape.
"""
from __future__ import annotations

import time

from jjdai.canonical import canonical
from jjdai.crypto import H_hex

# ---- states --------------------------------------------------------------- #

RECEIVED = "RECEIVED"
GROUNDED = "GROUNDED"
PLANNED = "PLANNED"
GENERATED = "GENERATED"
VERIFIED = "VERIFIED"
AUTHORIZED = "AUTHORIZED"
ACTED = "ACTED"
RECORDED = "RECORDED"

REFUSED = "REFUSED"
FAILED = "FAILED"
FATE_UNKNOWN = "FATE_UNKNOWN"
CONTAINED = "CONTAINED"

PIPELINE = (RECEIVED, GROUNDED, PLANNED, GENERATED, VERIFIED,
            AUTHORIZED, ACTED, RECORDED)
TERMINAL = frozenset({RECORDED, REFUSED, FAILED, FATE_UNKNOWN, CONTAINED})
BRANCHES = frozenset({REFUSED, FAILED, FATE_UNKNOWN, CONTAINED})

# every pipeline state may fall into any branch; forward motion is strictly
# one step at a time — no state is ever skipped silently
LEGAL = {s: {PIPELINE[i + 1]} | BRANCHES
         for i, s in enumerate(PIPELINE[:-1])}
LEGAL[RECORDED] = frozenset()
for b in BRANCHES:
    LEGAL[b] = frozenset()


class TraceError(RuntimeError):
    pass


class DecisionTrace:
    """The mutable in-flight record; serializes to the API answer."""

    def __init__(self, task_id: str, task: dict, being_id: str,
                 node_id: str, profile: str):
        self.task_id = task_id
        self.task_hash = H_hex(canonical(task))
        self.being_id = being_id
        self.node_id = node_id
        self.profile = profile
        self.state = RECEIVED
        self.created_at = time.time()
        self.transitions: list = []       # [{from,to,at,witness_index,detail}]
        self.citations: list = []         # grounding evidence (Plane H/Smriti)
        self.plan_hash: str = None
        self.plan_steps: list = []
        self.generator: dict = None       # object_id + provenance model
        self.verifier_panel: dict = None  # selected/rejected/mode
        self.answer: str = None
        self.containment: dict = None     # decision + scope evidence
        self.action: dict = None          # karma receipt (intent/outcome)
        self.outcome_reason: str = None   # for REFUSED/FAILED/FATE_UNKNOWN
        self.witness_first: int = None
        self.witness_last: int = None

    # ---- lifecycle -------------------------------------------------------- #
    def move(self, to: str, *, witness_index: int, detail: dict = None):
        if to not in LEGAL.get(self.state, frozenset()):
            raise TraceError(
                f"illegal transition {self.state} -> {to} for {self.task_id}")
        self.transitions.append({
            "from": self.state, "to": to, "at": time.time(),
            "witness_index": witness_index, "detail": detail or {}})
        self.state = to
        if self.witness_first is None:
            self.witness_first = witness_index
        self.witness_last = witness_index

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL

    # ---- serialization ---------------------------------------------------- #
    def as_dict(self) -> dict:
        return {
            "kind": "DECISION_TRACE",
            "task_id": self.task_id,
            "task_hash": self.task_hash,
            "being_id": self.being_id,
            "node_id": self.node_id,
            "profile": self.profile,
            "state": self.state,
            "terminal": self.terminal,
            "created_at": self.created_at,
            "transitions": self.transitions,
            "citations": self.citations,
            "plan_hash": self.plan_hash,
            "plan_steps": self.plan_steps,
            "generator": self.generator,
            "verifier_panel": self.verifier_panel,
            "answer": self.answer,
            "containment": self.containment,
            "action": self.action,
            "outcome_reason": self.outcome_reason,
            "witness_span": [self.witness_first, self.witness_last],
        }

    def trace_hash(self) -> str:
        return H_hex(canonical(self.as_dict()))

    @classmethod
    def from_journal(cls, entries: list) -> "DecisionTrace":
        """Rebuild a trace from its durable journal entries (recovery)."""
        head = entries[0]
        t = cls(head["task_id"], {"_rehydrated": True}, head["being_id"],
                head["node_id"], head["profile"])
        t.task_hash = head["task_hash"]
        t.created_at = head["at"]
        for e in entries[1:]:
            if e["op"] == "move":
                t.transitions.append({
                    "from": e["from"], "to": e["to"], "at": e["at"],
                    "witness_index": e["witness_index"],
                    "detail": e.get("detail") or {}})
                t.state = e["to"]
                if t.witness_first is None:
                    t.witness_first = e["witness_index"]
                t.witness_last = e["witness_index"]
            elif e["op"] == "enrich":
                for k, v in e["fields"].items():
                    setattr(t, k, v)
        return t
