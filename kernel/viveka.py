# -*- coding: utf-8 -*-
"""
kernel.viveka — Viveka (विवेक), the discernment & will organ. Second organ of
the Agent Kernel.

WHAT IT IS: the agent's structured will — an explicit STATE GRAPH the agent
moves through, instead of an opaque autoregressive ramble. Nodes are steps of
discernment or action; edges (static or conditional) are choices; the state
flows through and is checkpointed at every step. Pattern borrowed from
LangGraph (graph + checkpoint/rollback + interrupt); mechanism replaced with
JJ DAI's:

  * every step is a witnessed DELIBERATION record (the will is observable —
    Invariant III: no hidden control channel);
  * ROLLBACK is itself witnessed — you cannot secretly rewind history; the
    Witness shows the true sequence including every counterfactual retry;
  * an EXECUTIVE transition (one that will touch the world through Karma) is
    GATED by the Article-25 governor before it runs — if the Being is
    contained, executive steps are blocked (the hand), while pure discernment
    steps proceed (the mind). This is where Viveka meets containment.

CHECKPOINT / ROLLBACK = event sourcing (the same discipline as registry,
containment, and Smriti — now for the flow of will):

  * each executed node appends a checkpoint {step, node, state, state_hash};
  * the journal is append-only; rollback appends a marker and restores an
    earlier state — history is never deleted, only extended;
  * the witness digest binds the run, step, node and resulting state:
        "viveka:<run_id>:<step>:<node>:<state_hash>"
    state content rides in a hiding commitment (deliberation is private);
  * replaying the journal reproduces the current state and full checkpoint
    list — restart- and audit-safe.

STEP BUDGET: the will is bounded. A graph that loops halts cleanly at
max_steps — no infinite, unwitnessed churn.

Node fn:    f(state: dict) -> dict         (partial updates, merged into state)
Router fn:  f(state: dict) -> str          (name of next node, or END)
"""
from __future__ import annotations

import copy
import json
import os
import sys
import time
from dataclasses import dataclass, field

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from core.identity import entitled_to_witness               # noqa: E402
from jjdai.crypto import H_hex, open_commit                 # noqa: E402

#: The organ's SERIALIZED identity. One row per spelling that may appear in
#: a chain, mapping the digest prefix to the organ name and the committed
#: event field that must go with it. A table rather than three loose
#: constants, because these values are ONE fact and must never be checked
#: independently: a record wearing one spelling in its digest and another in
#: its provenance is not a record about this organ.
ORGAN_BINDINGS = {
    "viveka": {"organ": "viveka", "event_field": "viveka_event"},
}
EMITTED_PREFIX = "viveka"

#: How much a verification actually established, weakest first. The previous
#: return value was a COUNT — "12 records bound" — which said how much was
#: checked and never what was proved. A caller reading an int cannot tell a
#: digest match from an identity-bound chain, so every caller quietly
#: treated the weakest result as the strongest.
DIGEST_BOUND = "DIGEST_BOUND"              # the events produced these digests
ATTRIBUTED = "ATTRIBUTED"                  # + provenance names this being/organ
COMMITMENT_OPENED = "COMMITMENT_OPENED"    # + the committed request opens
IDENTITY_BOUND = "IDENTITY_BOUND"          # + the signer may speak for it
PROOF_LEVELS = (DIGEST_BOUND, ATTRIBUTED, COMMITMENT_OPENED, IDENTITY_BOUND)


class DeliberationProof(tuple):
    """(level, records). A tuple so `== n` comparisons fail loudly rather
    than silently reading as a count."""
    __slots__ = ()

    def __new__(cls, level, records):
        return super().__new__(cls, (level, int(records)))

    @property
    def level(self):
        return self[0]

    @property
    def records(self):
        return self[1]

    def at_least(self, level) -> bool:
        return PROOF_LEVELS.index(self.level) >= PROOF_LEVELS.index(level)

    def __repr__(self):
        return f"DeliberationProof({self.level}, {self.records})"

END = "__END__"
EXECUTIVE_SCOPE = "tools.side_effect"


class VivekaError(RuntimeError):
    pass


@dataclass
class Checkpoint:
    step: int
    node: str
    state: dict
    state_hash: str
    ts: float
    note: str = ""

    def as_dict(self) -> dict:
        return {"step": self.step, "node": self.node, "state": self.state,
                "state_hash": self.state_hash, "ts": self.ts, "note": self.note}


class Viveka:
    """A witnessed, checkpointed, governor-gated state-graph executor."""

    def __init__(self, being_id: str, *, witness=None, journal_path: str = None,
                 governor=None, now_fn=time.time, max_steps: int = 64):
        self.being_id = being_id
        self._witness = witness
        self._journal_path = journal_path
        self._governor = governor
        self._now = now_fn
        self._max_steps = max_steps
        # graph definition
        self._nodes: dict = {}            # name -> (fn, executive)
        self._edges: dict = {}            # name -> next name
        self._cond: dict = {}             # name -> router fn
        self._entry: str = None
        # run state
        self._state: dict = {}
        self._cursor: str = None
        self._step: int = 0
        self._run_id: str = None
        self._checkpoints: list = []      # append-only
        self._events: list = []           # the log IS the flow
        self._status: str = "idle"
        if journal_path and os.path.exists(journal_path):
            with open(journal_path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        self._apply(json.loads(line))

    # ------------------------------------------------------------------ #
    # Graph definition
    # ------------------------------------------------------------------ #
    def add_node(self, name: str, fn, *, executive: bool = False) -> "Viveka":
        if name == END:
            raise VivekaError("END is reserved")
        self._nodes[name] = (fn, executive)
        return self

    def add_edge(self, src: str, dst: str) -> "Viveka":
        self._edges[src] = dst
        return self

    def add_conditional(self, src: str, router) -> "Viveka":
        self._cond[src] = router
        return self

    def set_entry(self, name: str) -> "Viveka":
        self._entry = name
        return self

    # ------------------------------------------------------------------ #
    # Execution
    # ------------------------------------------------------------------ #
    def run(self, initial_state: dict = None) -> dict:
        if initial_state is not None:
            if self._entry is None:
                raise VivekaError("no entry node set")
            self._state = dict(initial_state)
            self._cursor = self._entry
            self._step = 0
            self._run_id = H_hex(canonical(
                {"being": self.being_id, "init": initial_state,
                 "t": self._now()}))[:16]
            self._emit({"ev": "start", "t": self._now(),
                        "run_id": self._run_id, "entry": self._entry,
                        "state": dict(initial_state)})
        return self._drive()

    def resume(self) -> dict:
        if self._cursor is None:
            raise VivekaError("nothing to resume")
        return self._drive()

    def _drive(self) -> dict:
        while self._cursor != END and self._cursor is not None:
            if self._step >= self._max_steps:
                self._status = "budget"
                break
            fn, executive = self._nodes[self._cursor]
            # Article-25 gate: executive transitions need governor permission
            if executive and self._governor is not None and \
                    not self._governor.permits(self.being_id, EXECUTIVE_SCOPE):
                self._emit({"ev": "blocked", "t": self._now(),
                            "run_id": self._run_id, "step": self._step,
                            "node": self._cursor, "scope": EXECUTIVE_SCOPE})
                self._status = "contained"
                return self._result()
            # execute the node
            updates = fn(dict(self._state)) or {}
            if not isinstance(updates, dict):
                raise VivekaError(f"node {self._cursor!r} must return a dict")
            self._state.update(updates)
            self._step += 1
            self._checkpoint(self._cursor)
            # choose the next node
            self._cursor = self._next_node(self._cursor)
        if self._cursor == END:
            self._status = "complete"
        return self._result()

    def _next_node(self, node: str) -> str:
        if node in self._cond:
            nxt = self._cond[node](dict(self._state))
            return nxt
        return self._edges.get(node, END)

    def _result(self) -> dict:
        return {"status": self._status, "state": dict(self._state),
                "steps": self._step, "node": self._cursor,
                "run_id": self._run_id, "state_hash": self.state_hash()}

    # ------------------------------------------------------------------ #
    # Checkpoint / rollback
    # ------------------------------------------------------------------ #
    def _checkpoint(self, node: str, note: str = ""):
        cp = Checkpoint(self._step, node, copy.deepcopy(self._state),
                        self._state_hash_of(self._state), self._now(), note)
        self._emit({"ev": "step", "t": cp.ts, "run_id": self._run_id,
                    "step": cp.step, "node": node,
                    "state": copy.deepcopy(self._state)})

    def rollback_to(self, checkpoint_step: int, *, patch: dict = None) -> dict:
        """Rewind to the state AFTER `checkpoint_step`, optionally patching it
        (a counterfactual retry), and resume from that node's successor. The
        rollback is WITNESSED — the rewind is part of the visible history."""
        target = next((c for c in self._checkpoints
                       if c.step == checkpoint_step), None)
        if target is None:
            raise VivekaError(f"no checkpoint at step {checkpoint_step}")
        new_state = copy.deepcopy(target.state)
        if patch:
            new_state.update(patch)
        self._state = new_state
        self._step = target.step
        self._cursor = self._next_node(target.node)
        self._status = "rolled_back"
        self._emit({"ev": "rollback", "t": self._now(),
                    "run_id": self._run_id, "to_step": checkpoint_step,
                    "patch": patch or {}, "state": copy.deepcopy(new_state)})
        return {"status": self._status, "to_step": checkpoint_step,
                "resume_node": self._cursor, "state_hash": self.state_hash()}

    # ------------------------------------------------------------------ #
    # State hash + event sourcing
    # ------------------------------------------------------------------ #
    @staticmethod
    def _state_hash_of(state: dict) -> str:
        return H_hex(canonical(state))

    def state_hash(self) -> str:
        return self._state_hash_of(self._state)

    def _emit(self, event: dict):
        self._apply(event)
        if self._journal_path:
            with open(self._journal_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, sort_keys=True,
                                   ensure_ascii=False) + "\n")
        if self._witness is not None and event["ev"] in ("step", "rollback",
                                                          "blocked"):
            sh = self._state_hash_of(event.get("state", self._state))
            node = event.get("node", event.get("ev"))
            step = event.get("step", self._step)
            b = ORGAN_BINDINGS[EMITTED_PREFIX]
            self._witness.append(
                "DELIBERATION",
                # hiding commitment. The field name is part of the committed
                # preimage, so it travels with the organ name.
                request={b["event_field"]: event},
                provenance={"organ": b["organ"], "being_id": self.being_id},
                semantic_digest=(f"{EMITTED_PREFIX}:{event['run_id']}"
                                 f":{step}:{node}:{sh}"),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(event["t"])))

    def _apply(self, event: dict):
        self._events.append(event)
        ev = event["ev"]
        if ev == "start":
            self._run_id = event["run_id"]
            self._state = dict(event["state"])
            self._cursor = event["entry"]
            self._step = 0
            self._checkpoints = []
        elif ev == "step":
            self._state = dict(event["state"])
            self._step = event["step"]
            self._checkpoints.append(Checkpoint(
                event["step"], event["node"], copy.deepcopy(event["state"]),
                self._state_hash_of(event["state"]), event["t"]))
        elif ev == "rollback":
            self._state = dict(event["state"])
            self._step = event["to_step"]
        elif ev == "blocked":
            pass
        else:
            raise ValueError(f"unknown viveka event {ev!r}")

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    @property
    def checkpoints(self) -> list:
        return list(self._checkpoints)

    @property
    def events(self) -> list:
        return list(self._events)

    @property
    def status(self) -> str:
        return self._status


def verify_deliberation_against_chain(events: list, chain_records: list,
                                      being_id: str, *, chain=None,
                                      binding=None) -> DeliberationProof:
    """Auditor: every step/rollback/blocked event that would be witnessed
    appears, in order, as a DELIBERATION record that binds BOTH what
    happened and WHOSE deliberation it was. Returns the number of bound
    records.

    Until v0.6.7-recut3 this function accepted `being_id` and never used it.
    It compared one string — the semantic digest — and nothing else. A chain
    signed by a DIFFERENT node, attributed in its provenance to a different
    being through a different organ, carrying a completely unrelated
    request, verified clean against another being's events.

    The digest binds run, step, node and resulting state: WHAT HAPPENED. It
    is silent about WHO, and that silence was being read as attribution —
    the one thing a witness plane exists to make impossible. Every act here
    is an act by a named being, and a record that cannot say whose act it
    was is not evidence of an act at all.

    Three bindings are checked, and a fourth is honestly declined:

      * the digest, as before — run, step, node, resulting state;
      * the ORGAN, resolved from the digest prefix through `ORGAN_BINDINGS`,
        so a record cannot wear one spelling in its digest and another in
        its provenance;
      * the BEING, by recomputing the provenance hash this record would
        carry if it were this being acting through that organ. Provenance is
        hashed into the record, so this needs nothing but the record itself;
      * the committed request is opened ONLY when `chain` is supplied. That
        commitment is HIDING and its salt is held off-chain by the writer,
        so without the writer's chain object there is no honest way to know
        which event was committed — and this function no longer implies
        there is;
      * the SIGNER's entitlement, only when a `binding` is supplied. This is
        the hole the third audit found: provenance checking proves the
        record is INTERNALLY consistent with a claim, not that the chain
        writing it was ever entitled to speak for this being. A chain under
        a foreign key, naming the right being and the right organ, passed.
        A two-signature HostingBinding closes it — the being consented to be
        hosted, the node accepted responsibility.

    Returns a `DeliberationProof` naming the level reached, NOT a count. A
    count answers "how much was checked" and is silent on "what was proved",
    and every caller read the weakest result as the strongest.
    """
    witnessed = [e for e in events if e["ev"] in ("step", "rollback", "blocked")]
    recs = [r for r in chain_records if r.get("kind") == "DELIBERATION"]
    if len(recs) != len(witnessed):
        raise VivekaError(
            f"count mismatch: {len(witnessed)} events vs {len(recs)} records")
    for i, (ev, rec) in enumerate(zip(witnessed, recs)):
        sh = H_hex(canonical(ev.get("state", {})))
        node = ev.get("node", ev.get("ev"))
        step = ev.get("step", 0)
        tail = f":{ev['run_id']}:{step}:{node}:{sh}"
        digest = rec.get("semantic_digest") or ""
        prefix = digest.split(":", 1)[0]
        organ_binding = ORGAN_BINDINGS.get(prefix)
        if organ_binding is None or digest != prefix + tail:
            raise VivekaError(f"binding broken at event {i}")
        want = H_hex(canonical({"organ": organ_binding["organ"],
                                "being_id": being_id}))
        if rec.get("provenance_hash") != want:
            raise VivekaError(
                f"record {i} is not attributable to {being_id!r} acting "
                f"through {organ_binding['organ']!r}: its provenance names "
                f"some "
                f"other being, some other organ, or nothing at all")
        if chain is None:
            continue
        salt = getattr(chain, "_salts", {}).get((rec.get("index"), "request"))
        if salt is None:
            raise VivekaError(
                f"record {i}: opening was asked for and no salt is held for "
                f"it — an unopenable commitment is not evidence")
        if not open_commit(rec.get("request_commitment") or "", salt,
                           canonical({organ_binding["event_field"]: ev})):
            raise VivekaError(
                f"record {i}: the committed request does not open to this "
                f"event under the {organ_binding['event_field']!r} field")
    level = ATTRIBUTED if chain is None else COMMITMENT_OPENED
    if binding is not None:
        if chain is None:
            raise VivekaError(
                "a hosting binding was supplied without the chain it is "
                "supposed to bind — nothing to compare the signer against")
        if not chain.verify_chain():
            raise VivekaError("the chain carrying these records does not "
                              "verify under its own signer")
        if not entitled_to_witness(binding, being_id=being_id,
                                   node_id=chain.node_id):
            raise VivekaError(
                f"chain {chain.node_id!r} is not entitled to witness for "
                f"{being_id!r}: no valid two-signature hosting binding says "
                f"this node hosts this being. Self-consistent provenance is "
                f"a claim, not an entitlement")
        level = IDENTITY_BOUND
    return DeliberationProof(level, len(witnessed))
