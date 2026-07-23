#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Durable Governance acceptance tests (v0.3.1.3 #4).

  U-1   crash-safe append: durable_append fsyncs; bytes are on disk
        immediately after the call returns (no page-cache gamble)
  U-2   TORN TAIL: a journal killed mid-write loads cleanly — the incomplete
        trailing event is reported and dropped, the node still boots
  U-3   MID-FILE corruption is NOT treated as a crash: it raises
        (that is tampering or a disk fault, not an interrupted write)
  U-4   truncate_torn_tail repairs the file atomically so the next append is
        clean; earlier records are untouched
  U-5   CONTAINMENT survives restart: a contained Being is STILL contained
        after the ledger is rebuilt from its journal — and the governor still
        severs executive scopes (the hand stays stopped across a reboot)
  U-6   REGISTRY survives restart: weights/champion reproduce from journal
  U-7   WITNESS survives restart with a torn tail; chain still verifies
  U-8   journal ↔ Witness reconciliation at boot: a good pair reconciles; a
        TAMPERED journal is caught and boot FAILS CLOSED
  U-9   ANCHOR RECEIPTS PERSIST: receipts survive restart (they are the proof
        of non-truncation — losing them exactly at restart was the old bug)
  U-10  no re-anchor storm after restart: anchoring position is restored from
        persisted receipts, so a restarted node anchors only NEW records
  U-11  TRUNCATION DETECTED: a chain shorter than the last receipt's count is
        caught by check_consistency and boot fails closed
  U-12  periodic anchoring policy: due() fires on record count and on elapsed
        time, not before

Run (from the build root):  python3 test_durable.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile


from jjdai.crypto import SigningKey                          # noqa: E402
from jjdai.witness import WitnessChain                       # noqa: E402
from jjdai.durable import (durable_append, read_journal,     # noqa: E402
                           truncate_torn_tail, JournalCorruption)
from core.durable import (PersistentAnchor, AnchorScheduler,  # noqa: E402
                          reconcile_governance, DurabilityError)
from core.registry import ChampionRegistry, Params           # noqa: E402
from core.containment import (ContainmentLedger,             # noqa: E402
                              EXECUTIVE_SCOPES, PROTECTED_SCOPES,
                              CONTAINED)

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_durable():

    WORK = tempfile.mkdtemp(prefix="jjdai_dur_")
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    class Clock:
        def __init__(self, t=1_750_000_000.0): self.t = t
        def __call__(self): return self.t
        def tick(self, s): self.t += s


    def simulate_crash_midwrite(path: str, partial: str):
        """Append a HALF-written line, exactly as a power loss would leave it."""
        with open(path, "a", encoding="utf-8") as f:
            f.write(partial)          # no trailing newline: the write never finished


    # ---- U-1 fsync append ------------------------------------------------------ #
    jp = os.path.join(WORK, "j1.jsonl")
    durable_append(jp, {"ev": "a", "n": 1})
    durable_append(jp, {"ev": "b", "n": 2})
    on_disk = open(jp, encoding="utf-8").read().count("\n")
    events, rep = read_journal(jp)
    check("U-1", on_disk == 2 and len(events) == 2 and not rep["torn_tail"],
          "durable_append fsyncs; both records on disk")

    # ---- U-2 torn tail --------------------------------------------------------- #
    simulate_crash_midwrite(jp, '{"ev": "c", "n": 3')      # killed mid-write
    events2, rep2 = read_journal(jp)
    check("U-2", rep2["torn_tail"] and rep2["dropped"] == 1
          and len(events2) == 2 and events2[-1]["ev"] == "b",
          "torn trailing line reported & dropped; node still boots")

    # ---- U-3 mid-file corruption raises ---------------------------------------- #
    bad = os.path.join(WORK, "bad.jsonl")
    with open(bad, "w", encoding="utf-8") as f:
        f.write('{"ev": "a"}\n')
        f.write('{"ev": BROKEN\n')                          # corrupt, NOT the tail
        f.write('{"ev": "c"}\n')
    raised = False
    try:
        read_journal(bad)
    except JournalCorruption:
        raised = True
    check("U-3", raised,
          "mid-file corruption raises (tampering/disk fault, not a crash)")

    # ---- U-4 repair ------------------------------------------------------------ #
    repaired = truncate_torn_tail(jp)
    after, rep3 = read_journal(jp)
    durable_append(jp, {"ev": "d", "n": 4})
    after2, _ = read_journal(jp)
    check("U-4", repaired and not rep3["torn_tail"] and len(after) == 2
          and len(after2) == 3 and after2[-1]["ev"] == "d",
          "torn tail repaired atomically; next append clean; history intact")

    # ---- U-5 containment survives restart -------------------------------------- #
    clk = Clock()
    sk = SigningKey(b"\xAB" * 32)
    wlog = os.path.join(WORK, "wit.jsonl")
    cjour = os.path.join(WORK, "cont.jsonl")
    chain = WitnessChain(sk, log_path=wlog)
    led = ContainmentLedger("node:A", witness=chain, journal_path=cjour,
                            evidence_resolver=lambda r: True, now_fn=clk)
    BEING = "being:rogue"
    led.contain(BEING, evidence_refs=["e1"], reason="live attempt", topic="cyber",
                initiator="node:A")
    # --- simulated reboot: rebuild the ledger from its journal alone ---
    led2 = ContainmentLedger("node:A", journal_path=cjour,
                             evidence_resolver=lambda r: True, now_fn=clk)
    still_contained = led2.is_contained(BEING) and led2.state(BEING) == CONTAINED
    hand_still_cut = not any(led2.permits(BEING, s) for s in EXECUTIVE_SCOPES)
    mind_still_free = all(led2.permits(BEING, s) for s in PROTECTED_SCOPES)
    check("U-5", still_contained and hand_still_cut and mind_still_free,
          "containment survives reboot: hand still severed, mind still free")

    # ---- U-6 registry survives restart ----------------------------------------- #
    rjour = os.path.join(WORK, "reg.jsonl")
    reg = ChampionRegistry(Params(), witness=chain, journal_path=rjour, now_fn=clk)
    for _ in range(6):
        reg.record("maglev", "ne:alpha", True, margin=0.3)
    w_before = reg.weight("maglev", "ne:alpha")
    snap_before = reg.snapshot_hash()
    reg2 = ChampionRegistry(Params(), journal_path=rjour, now_fn=clk)
    check("U-6", reg2.snapshot_hash() == snap_before
          and abs(reg2.weight("maglev", "ne:alpha") - w_before) < 1e-9
          and reg2.champion("maglev")["object_id"] == "ne:alpha",
          f"registry rebuilt from journal: weight {w_before:.3f} reproduced")

    # ---- U-7 witness survives restart with a torn tail ------------------------- #
    simulate_crash_midwrite(wlog, '{"index": 99, "prev_hash": "de')
    chain2 = WitnessChain(sk, log_path=wlog)
    check("U-7", getattr(chain2, "torn_tail_repaired", False)
          and chain2.verify_chain() and len(chain2.records) == len(chain.records),
          f"witness reloaded past torn tail; {len(chain2.records)} records verify")

    # ---- U-8 journal ↔ witness reconciliation ---------------------------------- #
    report = reconcile_governance(chain2, registry_journal=rjour,
                                  containment_journal=cjour)
    # now tamper the containment journal and boot again
    tampered_j = os.path.join(WORK, "cont_tampered.jsonl")
    evs, _ = read_journal(cjour)
    evs[0] = dict(evs[0], reason="fabricated after the fact")
    with open(tampered_j, "w", encoding="utf-8") as f:
        for e in evs:
            f.write(json.dumps(e, sort_keys=True) + "\n")
    failed_closed = False
    try:
        reconcile_governance(chain2, containment_journal=tampered_j)
    except DurabilityError:
        failed_closed = True
    check("U-8", report["chain_verified"] and report["registry"]["bound"] == 6
          and report["containment"]["bound"] == 1 and failed_closed,
          "good pair reconciles; tampered journal -> boot fails closed")

    # ---- U-9 anchor receipts persist ------------------------------------------- #
    apath = os.path.join(WORK, "anchors.jsonl")
    anc = PersistentAnchor(apath)
    sched = AnchorScheduler(chain2, anc, every_n=1, now_fn=clk)
    r1 = sched.maybe_anchor(force=True)
    anc_reloaded = PersistentAnchor(apath)          # simulated restart
    check("U-9", r1["anchored"] > 0 and len(anc_reloaded.receipts) == 1
          and anc_reloaded.latest()["root"] == r1["root"],
          f"anchor receipt survives restart (root {r1['root'][:10]}…)")

    # ---- U-10 no re-anchor storm after restart --------------------------------- #
    sched_after_reboot = AnchorScheduler(chain2, anc_reloaded, every_n=1,
                                         now_fn=clk)
    nothing_new = sched_after_reboot.maybe_anchor(force=True)
    chain2.append("INFER", request={"x": 1})
    only_new = sched_after_reboot.maybe_anchor(force=True)
    check("U-10", nothing_new["anchored"] == 0 and only_new["anchored"] == 1,
          "restarted node re-anchors nothing; anchors only the 1 new record")

    # ---- U-11 truncation detected ---------------------------------------------- #
    cons_ok = anc_reloaded.check_consistency(len(chain2.records))
    cons_bad = anc_reloaded.check_consistency(1)     # chain claims to be shorter
    boot_refused = False
    try:
        class _Short:
            records = chain2.records[:1]
            def verify_chain(self): return True
        reconcile_governance(_Short(), anchor=anc_reloaded)
    except DurabilityError:
        boot_refused = True
    check("U-11", cons_ok["ok"] and not cons_bad["ok"] and boot_refused,
          "chain shorter than last receipt -> truncation caught, boot fails closed")

    # ---- U-12 periodic policy -------------------------------------------------- #
    clk2 = Clock()
    anc2 = PersistentAnchor(os.path.join(WORK, "a2.jsonl"))
    ch3 = WitnessChain(SigningKey(b"\xCD" * 32))
    s2 = AnchorScheduler(ch3, anc2, every_n=3, every_s=600.0, now_fn=clk2)
    for _ in range(2):
        ch3.append("INFER", request={"n": 1})
    due_at_2 = s2.due()
    ch3.append("INFER", request={"n": 1})
    due_at_3 = s2.due()                       # count policy fires
    s2.maybe_anchor()
    ch3.append("INFER", request={"n": 1})
    due_soon = s2.due()                       # 1 record, 0s elapsed -> not due
    clk2.tick(601)
    due_after_time = s2.due()                 # time policy fires
    check("U-12", (not due_at_2) and due_at_3 and (not due_soon) and due_after_time,
          "anchoring due on record count and on elapsed time, not before")

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nDURABLE GOVERNANCE: {len(results) - failed}/{len(results)} green"
          + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_durable()
