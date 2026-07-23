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
from jjdai.crypto import H_hex                              # noqa: E402

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
            self._witness.append(
                "DELIBERATION",
                request={"viveka_event": event},        # hiding commitment
                provenance={"organ": "viveka", "being_id": self.being_id},
                semantic_digest=f"viveka:{event['run_id']}:{step}:{node}:{sh}",
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
                                      being_id: str) -> int:
    """Auditor: every step/rollback/blocked event that would be witnessed
    appears, in order, as a DELIBERATION record whose digest binds run/step/
    node/state. Returns the number of bound records."""
    witnessed = [e for e in events if e["ev"] in ("step", "rollback", "blocked")]
    recs = [r for r in chain_records if r.get("kind") == "DELIBERATION"]
    if len(recs) != len(witnessed):
        raise VivekaError(
            f"count mismatch: {len(witnessed)} events vs {len(recs)} records")
    for i, (ev, rec) in enumerate(zip(witnessed, recs)):
        sh = H_hex(canonical(ev.get("state", {})))
        node = ev.get("node", ev.get("ev"))
        step = ev.get("step", 0)
        expected = f"viveka:{ev['run_id']}:{step}:{node}:{sh}"
        if rec.get("semantic_digest") != expected:
            raise VivekaError(f"binding broken at event {i}")
    return len(witnessed)
