# -*- coding: utf-8 -*-
"""
runtime.recovery — restoring MEANING after a restart (v0.5.3)
=============================================================
The audit's gate 4: after a restart the Being must recover not only its
witness chain but the SEMANTIC state of every task — what it was asked,
how far it got, what evidence it gathered, and how it ended.

Recovery reads the durable task journal and rebuilds every DecisionTrace
(states + enrichments). Then it resolves the fates of tasks the crash
caught mid-flight, honestly:

  * a task that died between AUTHORIZED and ACTED **with a Karma INTENT
    that has no OUTCOME** closes as FATE_UNKNOWN — the action may or may
    not have happened in the world; the system that does not know SAYS
    it does not know;
  * any other non-terminal task closes as FAILED
    ("interrupted by restart") — it demonstrably did NOT act, so its
    fate is known: it failed to complete;
  * terminal tasks are restored exactly as they ended.

Every resolution is itself witnessed and journaled — recovery leaves the
same kind of evidence as normal operation.
"""
from __future__ import annotations

import os

from jjdai.durable import read_journal, truncate_torn_tail
from runtime.decision_trace import (DecisionTrace, AUTHORIZED,
                                    FAILED, FATE_UNKNOWN)


def _load_journal(path: str) -> list:
    if not path or not os.path.exists(path):
        return []
    entries, report = read_journal(path)
    if report.get("torn_tail"):
        truncate_torn_tail(path)
    return entries


def _orphaned_intents(karma_journal: str) -> set:
    """Karma intents whose outcome never landed (Karma journal schema:
    ph="intent"/"outcome" keyed by action_hash — kernel/karma.py)."""
    open_intents, closed = set(), set()
    for e in _load_journal(karma_journal):
        aid = e.get("action_hash")
        if aid is None:
            continue
        if e.get("ph") == "intent":
            open_intents.add(aid)
        elif e.get("ph") == "outcome":
            closed.add(aid)
    return open_intents - closed


def recover_traces(tasks_journal: str, *, karma_journal: str = None,
                   machine=None) -> dict:
    """-> {task_id: DecisionTrace}, with in-flight fates resolved."""
    entries = _load_journal(tasks_journal)
    if not entries:
        return {}
    by_task: dict = {}
    for e in entries:
        by_task.setdefault(e["task_id"], []).append(e)
    orphans = _orphaned_intents(karma_journal) if karma_journal else set()

    traces = {}
    for task_id, seq in by_task.items():
        trace = DecisionTrace.from_journal(seq)
        if not trace.terminal:
            # the crash caught this one mid-flight — resolve honestly
            if trace.state == AUTHORIZED and orphans:
                reason = ("restart found a witnessed action INTENT with no "
                          "OUTCOME — the world may or may not contain the "
                          "action; fate honestly unknown")
                target = FATE_UNKNOWN
            else:
                reason = "interrupted by restart before completion"
                target = FAILED
            if machine is not None:
                machine.enrich(trace, outcome_reason=reason)
                machine.move(trace, target, detail={"recovery": True,
                                                    "reason": reason})
            else:                                 # offline analysis path
                trace.outcome_reason = reason
                trace.transitions.append({"from": trace.state, "to": target,
                                          "at": None, "witness_index": None,
                                          "detail": {"recovery": True}})
                trace.state = target
        traces[task_id] = trace
    return traces
