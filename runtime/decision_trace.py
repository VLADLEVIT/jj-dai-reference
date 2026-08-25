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

#: Domain separator for what a BEING signs about its own decision. A bare
#: hash signed without a domain can be replayed as a signature over any
#: other object that happens to hash the same way.
BEING_DECISION_DOMAIN = b"jjdai/being/decision/v1:"

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
        #: The BEING's own signature over the decision it made (recut5,
        #: audit P0.3). The witness chain is signed by the NODE and stays
        #: that way — INV-9 — but until now the being key signed nothing
        #: at all, so "the being decided this" rested on the node's word
        #: about itself. See `being_commitment` for what is signed.
        self.being_attestation: dict = None
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
            "being_attestation": self.being_attestation,
            "witness_span": [self.witness_first, self.witness_last],
        }

    def content_digest(self) -> str:
        """The DECISION, digested — the one commitment everything uses.

        recut6, audit P0.2. Until now the RECORDED transition carried
        `trace_hash()`, computed BEFORE the transition was appended. The
        transition then changed the trace, so the chain witnessed the hash
        of an object the caller never received: `RECORDED.detail.trace_hash
        != trace.trace_hash()`, reproducibly. A hash of an object must never
        be placed inside that same object, and `trace_hash()` is gone rather
        than left as a trap for the next caller.

        The commitment is taken over a PROJECTION that excludes everything
        self-referential or appended afterwards: transitions, witness span,
        timestamps, the being's attestation (which carries this digest) and
        the state itself (which advances to RECORDED as the record is
        written).

        Transitions are deliberately NOT folded in. Every transition is
        already its own witnessed TASK record, so the chain covers the
        sequence by construction; re-hashing it here would prove nothing
        further while forcing the commitment to change at the instant it is
        written — the very defect being fixed. What the chain cannot cover
        by itself is the CONTENT, and that is what this binds: the task,
        the plan, the evidence cited, the generator and the artifact behind
        it, the panel, the answer, the containment decision, the action
        receipt and the outcome.
        """
        return recompute_commitment(self.as_dict())

    #: The being signs the same content the node witnesses. One commitment,
    #: two signatures meaning different things — authorship and testimony.
    def being_commitment(self) -> str:
        return self.content_digest()

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


def attest_decision(trace: "DecisionTrace", being_sk) -> dict:
    """The being signs its own decision. Returns the attestation dict."""
    commitment = trace.being_commitment()
    return {"being_id": trace.being_id,
            "commitment": commitment,
            "pub": being_sk.public.hex(),
            "sig": being_sk.sign(BEING_DECISION_DOMAIN
                                 + commitment.encode()).hex()}


def verify_decision_attestation(trace_dict: dict) -> tuple:
    """Offline check that the named being signed THIS decision.

    Fail-closed on every path, and in particular on re-attribution: the
    being_id must be the hash of the key that signed, so a genuine
    signature cannot be carried over to another being's trace.
    """
    from jjdai.crypto import canonical_being_id, verify as _verify
    att = (trace_dict or {}).get("being_attestation")
    if not att:
        return False, "no attestation"
    try:
        pub = bytes.fromhex(att["pub"])
        sig = bytes.fromhex(att["sig"])
        commitment = att["commitment"]
    except (KeyError, TypeError, ValueError):
        return False, "malformed attestation"
    if att.get("being_id") != trace_dict.get("being_id"):
        return False, "attestation names another being than the trace"
    if canonical_being_id(pub) != att["being_id"]:
        return False, "being_id does not match the signing key"
    expected = recompute_commitment(trace_dict)
    if commitment != expected:
        return False, "commitment does not open to this decision"
    if not _verify(pub, BEING_DECISION_DOMAIN + commitment.encode(), sig):
        return False, "bad being signature"
    return True, "ok"


def recompute_commitment(trace_dict: dict) -> str:
    """The commitment, recomputed from a SERIALIZED trace.

    The whole point of the projection is that this returns one value for
    the trace the caller received, the trace recovered from the journal
    after a restart, and the content the WitnessChain committed to.
    """
    return H_hex(canonical({
        "kind": "DECISION_CONTENT_COMMITMENT", "v": "1",
        "being_id": trace_dict.get("being_id"),
        "node_id": trace_dict.get("node_id"),
        "profile": trace_dict.get("profile"),
        "task_id": trace_dict.get("task_id"),
        "task_hash": trace_dict.get("task_hash"),
        "citations": trace_dict.get("citations"),
        "plan_hash": trace_dict.get("plan_hash"),
        "plan_steps": trace_dict.get("plan_steps"),
        "generator": trace_dict.get("generator"),
        "verifier_panel": trace_dict.get("verifier_panel"),
        "answer_hash": H_hex((trace_dict.get("answer") or "").encode()),
        "containment": trace_dict.get("containment"),
        "action": trace_dict.get("action"),
        "outcome_reason": trace_dict.get("outcome_reason"),
    }))
