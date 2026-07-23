# -*- coding: utf-8 -*-
"""
runtime.being — the Being Composition Runtime (v0.5.3)
======================================================
Closes the composition gap named by the v0.5.2 audit: JJ DAI had almost
every organ and no organism. This module is the organism — ONE long-lived
runtime that owns

    one identity        (the node's SigningKey — no organ mints its own)
    one witness chain   (the daemon's; every organ writes here or nowhere)
    Smriti              (memory & continuity; grounding + remembering)
    Plane H             (governed knowledge; citations in, proposals out)
    Viveka              (bounded deliberation producing the PLAN)
    Router              (diversity-panel generation + verification)
    Karma               (governed, containment-gated action)
    Containment         (Article 25 — the gate before every hand-move)
    TaskStateMachine    (witnessed lifecycle + durable journal)

and drives every task through the full witnessed cycle:

    RECEIVED -> GROUNDED -> PLANNED -> GENERATED -> VERIFIED
             -> AUTHORIZED -> ACTED -> RECORDED
    branches:  REFUSED / FAILED / FATE_UNKNOWN / CONTAINED

PROFILES (the audit's gate 2 — no implicit self-verification):
  * "production": a ProvenanceManifest per route object and a full
    independent panel are MANDATORY. No provenance, no panel, degraded
    panel => the task is REFUSED. There is no flag to relax this.
  * "dev": the router's labeled legacy path (mode="self") is allowed and
    every such verification is visibly marked in the trace.

CONTAINMENT SEMANTICS (gate 3): a contained Being still GROUNDS, PLANS,
GENERATES and VERIFIES — memory, recall and voice remain whole. The trace
turns CONTAINED only at the AUTHORIZED gate, and only for tasks that need
the executive hand. The hand is severed; the mind is not.

FATE_UNKNOWN (honesty about action): Karma witnesses INTENT before acting
and OUTCOME after. If the runtime dies between the two, recovery finds
the orphaned intent and closes the trace as FATE_UNKNOWN — the system
that does not know says so.
"""
from __future__ import annotations

import os
import threading
import time
import uuid

from jjdai.canonical import canonical
from jjdai.crypto import H_hex
from kernel.smriti import SmritiContinuity, AgentIdentity
from kernel.viveka import Viveka
from kernel.karma import Karma, ActionRefused, KarmaError
from core.plane_h import (GovernedPlaneH, WritePolicy,
                          make_write_proposal)
from core.rag_store import RagStore
from core.router import (Router, RoutingPolicy, RuleClassifier, RouteObject,
                         Query, RefusalError, ChampionRegistry,
                         WitnessChain as RouterWitness)
from runtime.decision_trace import (DecisionTrace, GROUNDED, PLANNED,
                                    GENERATED, VERIFIED, AUTHORIZED, ACTED,
                                    RECORDED, REFUSED, FAILED, CONTAINED)
from runtime.state_machine import TaskStateMachine
from runtime.recovery import recover_traces

EXECUTIVE_SCOPE = "scope:executive"
KNOWLEDGE_NS = "being/knowledge"


class BeingRuntimeError(RuntimeError):
    pass


class BeingRuntime:
    """One Being, one identity, one witness, one lifecycle."""

    def __init__(self, *, sk, chain, being_id: str, governor,
                 workspace: str,
                 profile: str = "production",
                 route_objects: list = None,
                 engines: dict = None,
                 provenance: dict = None,
                 topics: dict = None,
                 panel_k: int = 2,
                 min_independence: float = 0.5,
                 max_per_group: int = 1,
                 journal_dir: str = None,
                 lock=None):
        if profile not in ("production", "dev"):
            raise BeingRuntimeError(f"unknown profile {profile!r}")
        if profile == "production" and not provenance:
            raise BeingRuntimeError(
                "production profile requires a provenance map — a Being "
                "that cannot judge verifier independence must not verify")
        self.sk = sk
        self.chain = chain                       # THE one witness chain
        self.being_id = being_id
        self.governor = governor
        self.profile = profile
        self._lock = lock or threading.Lock()
        # One mind processes one task at a time (v1: strictly serial —
        # concurrent selves are a v0.6+ question, not an accident)
        self._task_serial = threading.RLock()
        jd = journal_dir
        if jd:
            os.makedirs(jd, exist_ok=True)

        # ---- organs, all on the ONE chain ------------------------------- #
        self.smriti = SmritiContinuity(
            AgentIdentity(being_id=being_id, created_at=time.time()),
            witness=chain,
            journal_path=os.path.join(jd, "smriti.jsonl") if jd else None)
        self.plane_h = GovernedPlaneH(
            RagStore(os.path.join(jd, "plane_h.db") if jd else ":memory:"),
            WritePolicy(), witness=chain)
        self.plane_h.policy.grant(KNOWLEDGE_NS, chain.node_id)
        self.karma = Karma(
            being_id, workspace, witness=chain, governor=governor,
            journal_path=os.path.join(jd, "karma.jsonl") if jd else None)
        self.machine = TaskStateMachine(
            chain,
            journal_path=os.path.join(jd, "tasks.jsonl") if jd else None,
            lock=self._lock)

        # ---- router over the SAME chain (adapter, not a second witness) - #
        self.registry = ChampionRegistry()
        self._router_witness = RouterWitness(chain=chain)
        self.topics = dict(topics or {"_generalist": []})
        policy = RoutingPolicy(classifier_rules=self.topics, abac_rules=[])
        self.router = Router(
            policy, RuleClassifier(policy),
            route_objects or [], engines or {}, self.registry,
            self._router_witness,
            provenance=provenance,
            panel_k=panel_k, min_independence=min_independence,
            max_per_group=max_per_group,
            allow_degraded_panel=False)          # never relaxed; see profile
        if profile == "dev" and provenance is None:
            self.router.provenance = None        # labeled mode="self" path

        # ---- recovery of prior lives ------------------------------------ #
        self.traces: dict = {}
        if jd:
            self.traces = recover_traces(
                os.path.join(jd, "tasks.jsonl"),
                karma_journal=os.path.join(jd, "karma.jsonl"),
                machine=self.machine)

    # ------------------------------------------------------------------ #
    #  The lifecycle
    # ------------------------------------------------------------------ #
    def handle_task(self, task: dict) -> DecisionTrace:
        """Drive one task through the full witnessed cycle. Always returns
        a terminal DecisionTrace; exceptions become named branches."""
        with self._task_serial:
            return self._handle_task_serial(task)

    def _handle_task_serial(self, task: dict) -> DecisionTrace:
        task_id = task.get("task_id") or f"task:{uuid.uuid4().hex[:16]}"
        trace = self.machine.open_trace(task_id, task, self.being_id,
                                        self.profile)
        self.traces[task_id] = trace
        try:
            self._ground(trace, task)
            self._plan(trace, task)
            self._generate_and_verify(trace, task)
            self._authorize_and_act(trace, task)
            self._record(trace, task)
        except _Terminal:
            pass                                  # trace already terminal
        except RefusalError as e:
            if not trace.terminal:
                self.machine.enrich(trace, outcome_reason=str(e))
                self.machine.move(trace, REFUSED, detail={"reason": str(e)})
        except ActionRefused as e:
            if not trace.terminal:
                self.machine.enrich(trace, outcome_reason=str(e))
                self.machine.move(trace, CONTAINED,
                                  detail={"reason": str(e)})
        except Exception as e:                    # noqa: BLE001 — named FAILED
            if not trace.terminal:
                self.machine.enrich(trace,
                                    outcome_reason=f"{type(e).__name__}: {e}")
                self.machine.move(trace, FAILED,
                                  detail={"error": f"{type(e).__name__}: "
                                                   f"{str(e)[:300]}"})
        return trace

    # ---- GROUNDED: recall + governed knowledge with citations ----------- #
    def _ground(self, trace: DecisionTrace, task: dict):
        query = task.get("text", "")
        citations = []
        for r in self.plane_h.retrieve(KNOWLEDGE_NS, query, k=3,
                                       access="internal"):
            citations.append({
                "source": "plane_h", "ns": KNOWLEDGE_NS,
                "chunk_id": r["chunk_id"],
                "content_hash": H_hex(r["text"].encode()),
                "ns_root": self.plane_h.store.merkle_root(KNOWLEDGE_NS),
                "author_node": r["author_node"],
                "version": r["version"]})
        for ep in self.smriti.recall_search(query, k=2):
            role = ep["role"] if isinstance(ep, dict) else ep.role
            text = ep["text"] if isinstance(ep, dict) else ep.text
            citations.append({
                "source": "smriti", "role": role,
                "content_hash": H_hex(text.encode())})
        self.smriti.recall_add("task", f"[{trace.task_id}] {query[:400]}")
        self.machine.enrich(trace, citations=citations)
        self.machine.move(trace, GROUNDED,
                          detail={"citations": len(citations)})

    # ---- PLANNED: bounded Viveka deliberation --------------------------- #
    def _plan(self, trace: DecisionTrace, task: dict):
        from kernel.viveka import END
        wants_action = bool(task.get("action"))
        v = Viveka(self.being_id, witness=self.chain,
                   governor=self.governor, max_steps=8)
        v.add_node("frame", lambda s: {**s, "framed": True})
        v.add_node("steps", lambda s: {**s, "steps":
                   ["ground", "generate", "verify"]
                   + (["act"] if s["wants_action"] else []) + ["record"]})
        v.add_node("commit", lambda s: s)
        v.add_edge("frame", "steps")
        v.add_edge("steps", "commit")
        v.add_edge("commit", END)
        v.set_entry("frame")
        res = v.run({"task_id": trace.task_id,
                     "wants_action": wants_action,
                     "citations": len(trace.citations)})
        plan = (res.get("state") or {}).get("steps") or []
        plan_hash = v.state_hash()
        self.machine.enrich(trace, plan_hash=plan_hash, plan_steps=plan)
        self.machine.move(trace, PLANNED,
                          detail={"plan_hash": plan_hash, "steps": plan})

    # ---- GENERATED + VERIFIED: router with diversity panel -------------- #
    def _generate_and_verify(self, trace: DecisionTrace, task: dict):
        res = self.router.route(Query(text=task.get("text", ""),
                                      require_verification=True))
        st = res.per_subtask[0]
        gen_prov = None
        if self.router.provenance:
            gen_prov = self.router.provenance.get(st["object"], {})
        self.machine.enrich(
            trace,
            generator={"object_id": st["object"],
                       "provenance_model":
                           (gen_prov or {}).get("model_id")},
            answer=st["answer"])
        self.machine.move(trace, GENERATED,
                          detail={"object": st["object"]})
        panel = self._last_panel_payload()
        mode = "panel" if self.router.provenance is not None else "self"
        if self.profile == "production" and mode != "panel":
            raise RefusalError(
                "production profile forbids self-verification")
        self.machine.enrich(trace, verifier_panel={
            "mode": mode, "verified": st["verified"],
            **({"selected": panel.get("selected"),
                "rejected": panel.get("rejected")} if panel else {})})
        if not st["verified"]:
            raise RefusalError("verification did not pass")
        self.machine.move(trace, VERIFIED,
                          detail={"mode": mode,
                                  "panel": (panel or {}).get("selected")})

    def _last_panel_payload(self) -> dict | None:
        for v in reversed(self._router_witness._views):
            if v.event_type == "route.panel":
                return v.payload
        return None

    # ---- AUTHORIZED + ACTED: the containment gate then the hand --------- #
    def _authorize_and_act(self, trace: DecisionTrace, task: dict):
        action = task.get("action")
        contained = self.governor.is_contained(self.being_id) \
            if self.governor else False
        decision = {
            "being_id": self.being_id,
            "contained": contained,
            "action_requested": bool(action),
            "executive_permitted": (not action) or not contained}
        self.machine.enrich(trace, containment=decision)
        if action and contained:
            # the mind ran the whole way here; only the HAND is refused
            self.machine.enrich(
                trace, outcome_reason="Article 25: executive hand severed")
            self.machine.move(trace, CONTAINED, detail=decision)
            raise _Terminal()
        self.machine.move(trace, AUTHORIZED, detail=decision)
        receipt = None
        if action:
            kind = action.get("kind")
            if kind == "fs_write":
                result = self.karma.fs_write(action["path"],
                                             action.get("content", ""))
            elif kind == "shell":
                result = self.karma.shell(action["argv"])
            else:
                raise KarmaError(f"unknown action kind {kind!r}")
            receipt = result.as_dict()
        self.machine.enrich(trace, action=receipt)
        self.machine.move(trace, ACTED,
                          detail={"action": bool(receipt),
                                  **({"karma_status": receipt.get("status")}
                                     if receipt else {})})

    # ---- RECORDED: memory + governed knowledge write -------------------- #
    def _record(self, trace: DecisionTrace, task: dict):
        self.smriti.recall_add(
            "outcome", f"[{trace.task_id}] answered; "
                       f"verified={trace.verifier_panel['verified']}")
        if task.get("remember", True) and trace.answer:
            env = make_write_proposal(
                self.sk, op="add", ns=KNOWLEDGE_NS,
                doc_id=f"task/{trace.task_id}",
                text=f"Q: {task.get('text', '')[:400]}\n"
                     f"A: {trace.answer[:800]}",
                source={"type": "being-task", "task_id": trace.task_id},
                access_policy="internal")
            self.plane_h.apply(env, text=env and
                               f"Q: {task.get('text', '')[:400]}\n"
                               f"A: {trace.answer[:800]}")
        self.machine.move(trace, RECORDED,
                          detail={"trace_hash": trace.trace_hash()})

    # ------------------------------------------------------------------ #
    def trace(self, task_id: str) -> DecisionTrace | None:
        return self.traces.get(task_id)


class _Terminal(Exception):
    """Internal control flow: the trace already reached a terminal state
    (e.g. CONTAINED at the authorization gate) — unwind cleanly."""
