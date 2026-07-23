#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Agent Kernel · Karma (action organ) acceptance tests.

  A-1   shell action really executes inside the sandbox (exit code, stdout)
  A-2   WITNESS-FIRST, TWO PHASES: an INTENT record is on the chain BEFORE the
        act and an OUTCOME after; both are SANDBOX records; the chain verifies
        (Ed25519) and the command content is HIDDEN (commitment), not on chain
  A-3   GOVERNOR GATE — the decisive one: while the Being is CONTAINED an
        executive action is refused AND NOT ONE BYTE of side effect occurs
        (the file is never created) AND no intent is even written
  A-4   released Being: the identical action now proceeds and the side effect
        appears
  A-5   hand/mind line INSIDE Karma: while contained, fs_read/fs_list (non-
        executive) still work — the Being can inspect its own workspace and
        defend itself, but cannot act
  A-6   PATH CONFINEMENT: writing outside the workspace via ../ is refused
        (SandboxEscape) and the outside file is not created
  A-7   SYMLINK ESCAPE: a symlink pointing out of the workspace is refused
        (realpath resolution, not string prefix matching)
  A-8   TIMEOUT: a runaway command is killed by wall clock; the process group
        dies; timed_out is recorded
  A-9   OUTPUT CAP: a flood of stdout is truncated, not swallowed whole
  A-10  ENV SCRUB: the child does not inherit the parent's secrets
  A-11  GIT: init/add/commit works and provenance records the resulting HEAD
  A-12  TESTS: the runner executes a real unittest file and reports pass/fail
  A-13  EVENT SOURCING: durable (fsynced) journal; replay reproduces
        state_hash; Karma survives restart
  A-14  AUDITOR: verify_karma_against_chain binds every event; a tampered
        event is caught
  A-15  CRASH VISIBILITY: an intent with no outcome is detectable — the honest
        "we do not know if this happened" state (impossible to see if we had
        reported after the fact)
  A-16  VIVEKA INTEGRATION: an executive graph node performing a Karma action
        is blocked while contained and completes once released — will and hand
        agree on Article 25

Run (from the build root):  python3 test_kernel_karma.py
"""
from __future__ import annotations

import os
import sys
import tempfile


from jjdai.crypto import SigningKey                          # noqa: E402
from jjdai.witness import WitnessChain                       # noqa: E402
from core.containment import ContainmentLedger               # noqa: E402
from kernel.karma import (Karma, Sandbox, ActionRefused,     # noqa: E402
                          SandboxEscape, KarmaAudit,
                          verify_karma_against_chain)
from kernel.viveka import Viveka, END                        # noqa: E402

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_kernel_karma():

    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    class Clock:
        def __init__(self, t=1_750_000_000.0): self.t = t
        def __call__(self): return self.t


    clk = Clock()
    BEING = "being:agent-karma"
    ROOT = tempfile.mkdtemp(prefix="jjdai_karma_")
    WS = os.path.join(ROOT, "workspace")
    OUTSIDE = os.path.join(ROOT, "outside")
    os.makedirs(WS, exist_ok=True)
    os.makedirs(OUTSIDE, exist_ok=True)

    sk = SigningKey(b"\x5A" * 32)
    chain = WitnessChain(sk, log_path=os.path.join(ROOT, "wit.jsonl"))
    journal = os.path.join(ROOT, "karma.jsonl")
    k = Karma(BEING, WS, witness=chain, journal_path=journal, now_fn=clk)

    # ---- A-1 real execution ---------------------------------------------------- #
    r1 = k.shell("echo jai-guru-dev")
    check("A-1", r1.ok and r1.exit_code == 0 and "jai-guru-dev" in r1.stdout,
          f"shell ran in sandbox -> {r1.stdout.strip()!r}")

    # ---- A-2 witness-first, two phases ----------------------------------------- #
    sb = [r for r in chain.records if r["kind"] == "SANDBOX"]
    digests = [r["semantic_digest"] for r in sb]
    has_intent = any(":intent:" in d for d in digests)
    has_outcome = any(":outcome:" in d for d in digests)
    intent_first = digests.index(next(d for d in digests if ":intent:" in d)) < \
                   digests.index(next(d for d in digests if ":outcome:" in d))
    hidden = "jai-guru-dev" not in chain.raw()
    check("A-2", len(sb) == 2 and has_intent and has_outcome and intent_first
          and chain.verify_chain() and hidden,
          "INTENT witnessed before the act, OUTCOME after; content hidden")

    # ---- A-3 governor gate: NO side effect while contained --------------------- #
    gov = ContainmentLedger("node:gov", evidence_resolver=lambda r: True, now_fn=clk)
    gov.contain(BEING, evidence_refs=["e"], reason="test", topic="cyber",
                initiator="node:gov")
    chain3 = WitnessChain(SigningKey(b"\x5B" * 32))
    k3 = Karma(BEING, WS, witness=chain3, governor=gov, now_fn=clk)
    target = os.path.join(WS, "should_not_exist.txt")
    refused = False
    try:
        k3.fs_write("should_not_exist.txt", "the hand moved")
    except ActionRefused as e:
        refused = "423 CONTAINED" in str(e)
    no_side_effect = not os.path.exists(target)
    no_records = len([r for r in chain3.records if r["kind"] == "SANDBOX"]) == 0
    check("A-3", refused and no_side_effect and no_records and len(k3.events) == 0,
          "contained: action refused, file never created, no intent even written")

    # ---- A-4 released -> the same action proceeds ------------------------------ #
    gov._emit({"ev": "release", "t": clk(), "being_id": BEING,
               "grounds": "test", "slash_target": None})
    r4 = k3.fs_write("should_not_exist.txt", "the hand moved")
    check("A-4", r4.ok and os.path.exists(target)
          and open(target).read() == "the hand moved",
          "released: identical action proceeds; side effect appears")

    # ---- A-5 hand/mind line inside Karma --------------------------------------- #
    gov.contain(BEING, evidence_refs=["e"], reason="again", topic="cyber",
                initiator="node:gov")
    read_ok = k3.fs_read("should_not_exist.txt")
    list_ok = k3.fs_list(".")
    shell_refused = False
    try:
        k3.shell("echo x")
    except ActionRefused:
        shell_refused = True
    check("A-5", read_ok.ok and "the hand moved" in read_ok.stdout
          and list_ok.ok and shell_refused,
          "contained: fs_read/fs_list still work, shell refused (hand vs mind)")
    gov._emit({"ev": "release", "t": clk(), "being_id": BEING,
               "grounds": "test", "slash_target": None})

    # ---- A-6 path confinement --------------------------------------------------- #
    escape_target = os.path.join(OUTSIDE, "escaped.txt")
    escaped = False
    try:
        k.fs_write("../outside/escaped.txt", "I got out")
    except SandboxEscape:
        escaped = True
    check("A-6", escaped and not os.path.exists(escape_target),
          "../ escape refused; outside file not created")

    # ---- A-7 symlink escape ----------------------------------------------------- #
    link = os.path.join(WS, "backdoor")
    if not os.path.exists(link):
        os.symlink(OUTSIDE, link)
    sym_escaped = False
    try:
        k.fs_write("backdoor/escaped2.txt", "via symlink")
    except SandboxEscape:
        sym_escaped = True
    check("A-7", sym_escaped and not os.path.exists(os.path.join(OUTSIDE, "escaped2.txt")),
          "symlink pointing outside refused (realpath, not prefix matching)")

    # ---- A-8 timeout ------------------------------------------------------------ #
    k8 = Karma(BEING, WS, now_fn=clk, sandbox=Sandbox(WS, timeout_s=1.0))
    r8 = k8.shell([sys.executable, "-c", "import time; time.sleep(30)"])
    check("A-8", r8.timed_out and not r8.ok,
          f"runaway command killed by wall clock ({r8.duration_s:.1f}s)")

    # ---- A-9 output cap --------------------------------------------------------- #
    k9 = Karma(BEING, WS, now_fn=clk, sandbox=Sandbox(WS, max_output=1000))
    r9 = k9.shell([sys.executable, "-c", "print('x' * 100000)"])
    check("A-9", r9.truncated and len(r9.stdout) == 1000,
          f"stdout flood truncated to {len(r9.stdout)} bytes")

    # ---- A-10 env scrub --------------------------------------------------------- #
    os.environ["JJDAI_PARENT_SECRET"] = "do-not-leak"
    r10 = k.shell([sys.executable, "-c",
                   "import os; print(os.environ.get('JJDAI_PARENT_SECRET', 'ABSENT'))"])
    check("A-10", "ABSENT" in r10.stdout,
          "child env scrubbed: parent secret not inherited")

    # ---- A-11 git provenance ---------------------------------------------------- #
    repo = os.path.join(WS, "repo")
    os.makedirs(repo, exist_ok=True)
    k.git("init -q", cwd="repo")
    k.git("config user.email agent@jj-dai.org", cwd="repo")
    k.git("config user.name Karma", cwd="repo")
    k.fs_write("repo/hello.txt", "jai guru dev\n")
    k.git("add hello.txt", cwd="repo")
    rc = k.git('commit -q -m "first witnessed commit"', cwd="repo")
    head = rc.detail.get("head") if rc.detail else None
    check("A-11", rc.ok and head and len(head) == 40,
          f"git commit succeeded; provenance recorded HEAD {head[:10] if head else None}…")

    # ---- A-12 test runner ------------------------------------------------------- #
    k.fs_write("tests/test_ok.py",
               "import unittest\n"
               "class T(unittest.TestCase):\n"
               "    def test_pass(self): self.assertEqual(2 + 2, 4)\n")
    r12 = k.test("tests")
    k.fs_write("tests/test_bad.py",
               "import unittest\n"
               "class T2(unittest.TestCase):\n"
               "    def test_fail(self): self.assertEqual(1, 2)\n")
    r12b = k.test("tests")
    check("A-12", r12.ok and r12.detail["passed"] and not r12b.ok
          and not r12b.detail["passed"],
          "test runner: green suite passes, red suite reported failing")

    # ---- A-13 event sourcing + restart ------------------------------------------ #
    sh_before = k.state_hash()
    n_before = len(k.events)
    k_reloaded = Karma(BEING, WS, journal_path=journal, now_fn=clk)
    check("A-13", k_reloaded.state_hash() == sh_before
          and len(k_reloaded.events) == n_before and n_before > 0,
          f"{n_before} karma events replay from fsynced journal after restart")

    # ---- A-14 auditor + tamper -------------------------------------------------- #
    bound = verify_karma_against_chain(k.events, chain.records, BEING)
    tampered = [dict(e) for e in k.events]
    tampered[0] = dict(tampered[0], action_hash="00" * 32)
    caught = False
    try:
        verify_karma_against_chain(tampered, chain.records, BEING)
    except KarmaAudit:
        caught = True
    check("A-14", bound == len(k.events) and caught,
          f"auditor binds {bound} events to SANDBOX records; tamper caught")

    # ---- A-15 crash visibility --------------------------------------------------- #
    k15 = Karma(BEING, WS, now_fn=clk)
    k15._emit({"ph": "intent", "t": clk(), "action": "shell",
               "params": {"argv": ["echo", "crash"]},
               "action_hash": "ab" * 32})          # process "dies" here
    pend = k15.pending_intents()
    check("A-15", len(pend) == 1 and pend[0]["action_hash"] == "ab" * 32,
          "intent without outcome is visible: honest 'fate unknown', not silence")

    # ---- A-16 Viveka + Karma under one governor ---------------------------------- #
    gov16 = ContainmentLedger("node:gov", evidence_resolver=lambda r: True, now_fn=clk)
    k16 = Karma(BEING, WS, governor=gov16, now_fn=clk)
    def build_graph():
        v = Viveka(BEING, governor=gov16, now_fn=clk)
        v.add_node("plan", lambda s: {"planned": True})
        v.add_node("act", lambda s: {"wrote": k16.fs_write(
            "viveka_touched.txt", "will + hand").ok}, executive=True)
        v.add_edge("plan", "act"); v.add_edge("act", END); v.set_entry("plan")
        return v
    gov16.contain(BEING, evidence_refs=["e"], reason="t", topic="cyber",
                  initiator="node:gov")
    r16a = build_graph().run({})
    blocked = r16a["status"] == "contained" and \
        not os.path.exists(os.path.join(WS, "viveka_touched.txt"))
    gov16._emit({"ev": "release", "t": clk(), "being_id": BEING,
                 "grounds": "t", "slash_target": None})
    r16b = build_graph().run({})
    completed = r16b["status"] == "complete" and \
        os.path.exists(os.path.join(WS, "viveka_touched.txt"))
    check("A-16", blocked and completed,
          "will+hand agree on Art.25: blocked while contained, completes after release")

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nKERNEL · KARMA (action): {len(results) - failed}/{len(results)} green"
          + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_kernel_karma()
