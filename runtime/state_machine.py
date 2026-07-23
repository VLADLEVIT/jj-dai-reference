# -*- coding: utf-8 -*-
"""
runtime.state_machine — witnessed decision lifecycle (v0.5.3)
=============================================================
One object owns every state change of every task: each transition is
(1) validated against the legal-transition map, (2) appended to the ONE
witness chain as a TASK record, (3) journaled durably — in that order,
so the chain never lags the journal. A transition that is not witnessed
did not happen; a transition the map forbids raises before anything is
written.

The journal is the recovery substrate: runtime.recovery rebuilds every
trace from it after a restart and resolves in-flight fates honestly.
"""
from __future__ import annotations

import threading
import time

from jjdai.durable import durable_append
from runtime.decision_trace import DecisionTrace, TraceError

TASK_KIND = "TASK"


class TaskStateMachine:
    def __init__(self, chain, *, journal_path: str = None, lock=None):
        self.chain = chain
        self.journal_path = journal_path
        self._lock = lock or threading.Lock()

    def _journal(self, entry: dict):
        if self.journal_path:
            durable_append(self.journal_path, entry)

    def open_trace(self, task_id: str, task: dict, being_id: str,
                   profile: str) -> DecisionTrace:
        trace = DecisionTrace(task_id, task, being_id,
                              self.chain.node_id, profile)
        with self.chain.lock:
            rec = self.chain.append(
                TASK_KIND,
                request={"task": task},
                semantic_digest={"task_id": task_id, "state": "RECEIVED",
                                 "task_hash": trace.task_hash})
        idx = len(self.chain.records) - 1
        trace.transitions.append({"from": None, "to": "RECEIVED",
                                  "at": time.time(), "witness_index": idx,
                                  "detail": {}})
        trace.witness_first = trace.witness_last = idx
        self._journal({"op": "open", "task_id": task_id,
                       "task_hash": trace.task_hash, "being_id": being_id,
                       "node_id": self.chain.node_id, "profile": profile,
                       "at": trace.created_at})
        return trace

    def move(self, trace: DecisionTrace, to: str, *, detail: dict = None,
             response: dict = None):
        """Witness first (under the node lock), then journal, then mutate
        the in-memory trace. An illegal move raises with NOTHING written."""
        from runtime.decision_trace import LEGAL
        if to not in LEGAL.get(trace.state, frozenset()):
            raise TraceError(
                f"illegal transition {trace.state} -> {to} "
                f"for {trace.task_id}")
        with self.chain.lock:
            self.chain.append(
                TASK_KIND,
                request=response or {},
                semantic_digest={"task_id": trace.task_id, "state": to,
                                 "from": trace.state,
                                 **({"detail": detail} if detail else {})})
            idx = len(self.chain.records) - 1
        self._journal({"op": "move", "task_id": trace.task_id,
                       "from": trace.state, "to": to, "at": time.time(),
                       "witness_index": idx, "detail": detail or {}})
        trace.move(to, witness_index=idx, detail=detail)

    def enrich(self, trace: DecisionTrace, **fields):
        """Attach evidence to the trace (citations, plan, panel, receipts)
        and journal it so recovery restores MEANING, not just states."""
        for k, v in fields.items():
            if not hasattr(trace, k):
                raise TraceError(f"unknown trace field {k!r}")
            setattr(trace, k, v)
        self._journal({"op": "enrich", "task_id": trace.task_id,
                       "at": time.time(), "fields": fields})
