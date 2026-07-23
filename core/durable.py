# -*- coding: utf-8 -*-
"""
core.durable — Durable Governance (v0.3.1.3 #4).

WHAT WAS ACTUALLY BROKEN (found by inspection, not assumed):

  1. NO fsync. Every journal (registry, containment, memory, viveka) and the
     witness log itself appended with plain `open(a)+write`. The bytes sat in
     the OS page cache; a power loss silently ate the last governance events.
     A containment order could be "recorded" and then never have happened.
  2. TORN LINES kill boot. A crash mid-write leaves a half-written JSON line;
     the next start does json.loads(line) -> exception -> the node cannot boot
     at all. Governance state was one bad shutdown away from unreadable.
  3. ANCHOR STATE was ephemeral. WitnessChain._last_anchor_index resets to 0
     on restart, so a restarted node RE-ANCHORS its entire history and the
     "new records since last anchor" logic is meaningless. Worse, LocalAnchor
     kept receipts in MEMORY only — the very receipts that prove the chain was
     not truncated vanished exactly when they were needed (after a restart).

WHAT THIS MODULE PROVIDES:

  durable_append(path, obj)  — append + flush + os.fsync (and fsync the
      DIRECTORY on file creation, or the file's existence itself can be lost).
      Slower and correct beats fast and lying.
  read_journal(path)         — crash-tolerant read: a torn TRAILING line is
      reported and dropped (it is the one write that did not complete); a torn
      line ANYWHERE ELSE is corruption, not a crash, and raises. That
      distinction matters: the tail is recoverable, the middle is an attack or
      a disk fault.
  PersistentAnchor           — anchor receipts on disk. Survives restart,
      keeps last_anchor_index, seq-monotonic, and detects a rewound/rewritten
      chain by comparing counts against the last receipt.
  AnchorScheduler            — periodic anchoring policy (every N records or T
      seconds), so anchoring is a habit, not a hope.
  reconcile_governance()     — the boot gate: verify the witness chain, replay
      every governance journal, prove each journal is bound to the chain
      (registry/containment/memory), and check anchor receipts. Fails closed.
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402,F401
from jjdai.crypto import H_hex                              # noqa: E402,F401
# Low-level durability primitives live in jjdai/ — the witness chain needs them
# too, and the primitive layer must not depend on core/.
from jjdai.durable import (durable_append, read_journal,    # noqa: E402,F401
                           truncate_torn_tail, DurabilityError,
                           JournalCorruption)


# --------------------------------------------------------------------------- #
# Crash-safe append / repair-tolerant read
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# Persistent anchoring
# --------------------------------------------------------------------------- #

class PersistentAnchor:
    """Anchor receipts that survive restart — the whole point of an anchor.

    Each receipt: {seq, node, root, count, ts}. `count` is the chain length at
    anchor time; a later chain claiming FEWER records than the last receipt has
    been truncated or rewritten, and check_consistency() says so."""

    def __init__(self, path: str):
        self.path = path
        self.receipts, _ = read_journal(path) if path else ([], None)

    def submit(self, node: str, root: str, count: int = None) -> dict:
        rec = {"seq": len(self.receipts), "node": node, "root": root,
               "count": count if count is not None else -1, "ts": time.time()}
        self.receipts.append(rec)
        if self.path:
            durable_append(self.path, rec)     # fsynced: receipts must survive
        return rec

    def latest(self):
        return self.receipts[-1] if self.receipts else None

    def last_anchor_index(self) -> int:
        last = self.latest()
        return last["count"] if last and last["count"] >= 0 else 0

    def check_consistency(self, current_count: int) -> dict:
        """A restarted/attacked node must not be shorter than what it anchored."""
        last = self.latest()
        if last is None:
            return {"ok": True, "reason": "no receipts yet"}
        if last["count"] >= 0 and current_count < last["count"]:
            return {"ok": False,
                    "reason": f"chain truncated: {current_count} records now, "
                              f"{last['count']} were anchored at seq "
                              f"{last['seq']}"}
        return {"ok": True, "anchored_count": last["count"],
                "current_count": current_count}


class AnchorScheduler:
    """Anchor on a policy, not on hope: every N new records or T seconds."""

    def __init__(self, chain, anchor: PersistentAnchor, *,
                 every_n: int = 50, every_s: float = 3600.0,
                 now_fn=time.time):
        self.chain = chain
        self.anchor = anchor
        self.every_n = every_n
        self.every_s = every_s
        self._now = now_fn
        self._last_ts = now_fn()
        # restore anchoring position from the persisted receipts (the bug this
        # fixes: WitnessChain._last_anchor_index resets to 0 on restart, so a
        # restarted node re-anchors its whole history)
        self._last_index = anchor.last_anchor_index()

    def due(self) -> bool:
        new = len(self.chain.records) - self._last_index
        return new > 0 and (new >= self.every_n
                            or (self._now() - self._last_ts) >= self.every_s)

    def maybe_anchor(self, force: bool = False) -> dict:
        if not force and not self.due():
            return {"anchored": 0, "due": False}
        new = self.chain.records[self._last_index:]
        if not new:
            return {"anchored": 0, "due": False}
        from jjdai.merkle import merkle_root
        root = merkle_root([r["this_hash"].encode() for r in new])
        receipt = self.anchor.submit(self.chain.node_id, root,
                                     count=len(self.chain.records))
        self._last_index = len(self.chain.records)
        self._last_ts = self._now()
        return {"anchored": len(new), "root": root, "receipt": receipt}


# --------------------------------------------------------------------------- #
# Boot-time reconciliation — fail closed
# --------------------------------------------------------------------------- #

def reconcile_governance(chain, *, registry_journal: str = None,
                         containment_journal: str = None,
                         memory_journal: str = None,
                         anchor: PersistentAnchor = None) -> dict:
    """The governance boot gate. Verifies the witness chain, replays every
    journal, proves each is bound to the chain, and checks anchor receipts.
    Raises DurabilityError on any inconsistency — a node whose governance
    state cannot be reconciled must not serve."""
    report = {"chain_verified": False, "records": len(chain.records)}
    if not chain.verify_chain():
        raise DurabilityError("boot: witness chain failed verification")
    report["chain_verified"] = True

    if registry_journal:
        from core.registry import verify_journal_against_chain as reg_verify
        events, rep = read_journal(registry_journal)
        report["registry"] = {"events": len(events), **rep}
        try:
            report["registry"]["bound"] = reg_verify(events, chain.records)
        except Exception as e:
            raise DurabilityError(f"boot: registry journal/witness mismatch: {e}")

    if containment_journal:
        from core.containment import verify_journal_against_chain as con_verify
        events, rep = read_journal(containment_journal)
        report["containment"] = {"events": len(events), **rep}
        try:
            report["containment"]["bound"] = con_verify(events, chain.records)
        except Exception as e:
            raise DurabilityError(
                f"boot: containment journal/witness mismatch: {e}")

    if memory_journal:
        from kernel.smriti import verify_memory_against_chain as mem_verify
        events, rep = read_journal(memory_journal)
        report["memory"] = {"events": len(events), **rep}
        try:
            report["memory"]["bound"] = mem_verify(events, chain.records)
        except Exception as e:
            raise DurabilityError(f"boot: memory journal/witness mismatch: {e}")

    if anchor is not None:
        cons = anchor.check_consistency(len(chain.records))
        report["anchor"] = cons
        if not cons["ok"]:
            raise DurabilityError(f"boot: {cons['reason']}")
    return report
