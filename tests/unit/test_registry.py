#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — ChampionRegistry §9.9 acceptance tests (iteration I1).

Every check targets one clause of the reputation spine. The clock is frozen
and advanced by hand — decay is tested by moving time, not by sleeping.

  G-1   cold start: no verdicts -> no champion (w_min floor honored)
  G-2   fresh verified work earns weight; best object selected
  G-3   DECAY: an idle ex-champion sinks below an active rival
        ("influence requires continuous fresh verified work")
  G-4   DECAY to prior: long-idle object's R returns to C0, E -> 0
  G-5   SHRINKAGE: a lucky 2/2 newcomer does NOT outrank a 45/50 veteran
  G-6   SUB-LINEARITY + SATURATION: 16x volume -> 2x credit, capped at 1
  G-7   SLASHING: failed challenge halves influence instantly; recovery is
        slow and linear (checked at +15 days: partial, not full)
  G-8   STAKE: below-reference stake gates weight concavely; zero stake = 0
  G-9   CLIP: w never exceeds w_max no matter the evidence mountain
  G-10  SCOPE: personal champion wins inside its scope, invisible outside;
        empty personal scope falls back to global
  G-11  EVENT SOURCING: replay of the journal reproduces snapshot_hash
        exactly; REGISTRY events land on the witness chain; the chain
        verifies; journal<->chain binding passes; a tampered journal is
        caught by the auditor
  G-12  difficulty weighting: hard verified wins outweigh easy ones

Run (from the build root):  python3 test_registry.py
"""
from __future__ import annotations

import os
import sys
import tempfile


from jjdai.crypto import SigningKey                          # noqa: E402
from jjdai.witness import WitnessChain                       # noqa: E402
from core.registry import (ChampionRegistry, Params,         # noqa: E402
                           verify_journal_against_chain,
                           JournalChainMismatch)

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_registry():

    DAY = 86400.0
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    class Clock:
        def __init__(self, t=1_750_000_000.0): self.t = t
        def __call__(self): return self.t
        def tick(self, days): self.t += days * DAY


    clk = Clock()
    P = Params()

    # ---- G-1 cold start --------------------------------------------------------- #
    reg = ChampionRegistry(P, now_fn=clk)
    check("G-1", reg.champion("maglev") is None, "no verdicts -> no champion")

    # ---- G-2 fresh work earns weight -------------------------------------------- #
    for i in range(8):
        reg.record("maglev", "ne:alpha", True, margin=0.30)
        reg.record("maglev", "ne:beta", i % 2 == 0, margin=0.10)   # 50% passer
    ch = reg.champion("maglev")
    w_alpha = reg.weight("maglev", "ne:alpha")
    check("G-2", ch and ch["object_id"] == "ne:alpha" and w_alpha > 0.5,
          f"alpha w={w_alpha:.3f} beats 50%-passer")

    # ---- G-3 decay: idle ex-champion loses to an active rival ------------------- #
    for _ in range(21):                      # beta grinds daily for 3 weeks,
        clk.tick(1)                          # alpha is idle the whole time
        reg.record("maglev", "ne:beta", True, margin=0.25)
    ch3 = reg.champion("maglev")
    check("G-3", ch3["object_id"] == "ne:beta",
          f"idle alpha w={reg.weight('maglev','ne:alpha'):.3f} < "
          f"active beta w={reg.weight('maglev','ne:beta'):.3f}")

    # ---- G-4 decay to prior ------------------------------------------------------ #
    clk.tick(365)
    c4 = reg.components("maglev", "ne:alpha")
    check("G-4", abs(c4["R"] - P.c0) < 0.02 and c4["E"] < 0.05,
          f"after a year idle: R={c4['R']:.3f}→C0, E={c4['E']:.4f}→0")

    # ---- G-5 shrinkage: lucky newcomer vs veteran -------------------------------- #
    reg5 = ChampionRegistry(P, now_fn=clk)
    for i in range(50):
        reg5.record("nuclear", "ne:veteran", i % 10 != 0)   # 45/50 = 90%
    reg5.record("nuclear", "ne:lucky", True)
    reg5.record("nuclear", "ne:lucky", True)                # 2/2 = 100%
    check("G-5", reg5.champion("nuclear")["object_id"] == "ne:veteran",
          f"veteran w={reg5.weight('nuclear','ne:veteran'):.3f} > "
          f"lucky-2/2 w={reg5.weight('nuclear','ne:lucky'):.3f}")

    # ---- G-6 sub-linearity ------------------------------------------------------- #
    reg6 = ChampionRegistry(P, now_fn=clk)
    for _ in range(4):
        reg6.record("t", "ne:small", True)
    for _ in range(64):
        reg6.record("t", "ne:big", True)
    e_small = reg6.components("t", "ne:small")["E"]
    e_big = reg6.components("t", "ne:big")["E"]
    ratio = e_big / e_small
    check("G-6", 1.8 < ratio < 2.2 and e_big == 1.0,
          f"16x volume -> credit ratio {ratio:.2f} (sub-linear), saturates at 1")

    # ---- G-7 slashing + slow recovery -------------------------------------------- #
    reg7 = ChampionRegistry(P, now_fn=clk)
    for _ in range(20):
        reg7.record("cyber", "ne:cheat", True)
    w_before = reg7.weight("cyber", "ne:cheat")
    reg7.slash("ne:cheat", "failed blind challenge")
    w_after = reg7.weight("cyber", "ne:cheat")
    clk.tick(15)
    s_15d = reg7.components("cyber", "ne:cheat")["S"]
    check("G-7", w_after <= w_before * 0.55 and 0.55 < s_15d < 0.95,
          f"w {w_before:.3f}->{w_after:.3f} on slash; S after 15d = {s_15d:.3f} "
          "(recovering, not recovered)")

    # ---- G-8 stake gate ----------------------------------------------------------- #
    reg8 = ChampionRegistry(P, now_fn=clk)
    for _ in range(20):
        reg8.record("s", "ne:poor", True)
        reg8.record("s", "ne:none", True)
    reg8.set_stake("ne:poor", 0.25)          # quarter stake -> g = 0.5
    reg8.set_stake("ne:none", 0.0)
    g_poor = reg8.components("s", "ne:poor")["g"]
    w_none = reg8.weight("s", "ne:none")
    check("G-8", abs(g_poor - 0.5) < 1e-9 and w_none == 0.0,
          f"g(0.25)={g_poor:.2f} (concave), g(0)=0 -> w=0")

    # ---- G-9 clip ------------------------------------------------------------------ #
    reg9 = ChampionRegistry(P, now_fn=clk)
    for _ in range(500):
        reg9.record("c", "ne:titan", True, difficulty=3.0)
    check("G-9", reg9.weight("c", "ne:titan") == P.w_max,
          f"500 hard wins still clip at w_max={P.w_max}")

    # ---- G-10 scope keying --------------------------------------------------------- #
    reg10 = ChampionRegistry(P, now_fn=clk)
    for _ in range(10):
        reg10.record("legal", "ne:global", True)
        reg10.record("legal", "ne:bro", True, margin=0.4, scope="user:bro")
    in_scope = reg10.champion("legal", scope="user:bro")
    outside = reg10.champion("legal")
    fallback = reg10.champion("legal", scope="user:elena")
    check("G-10", in_scope["object_id"] == "ne:bro"
          and outside["object_id"] == "ne:global"
          and fallback["object_id"] == "ne:global" and fallback["scope"] == "global",
          "personal wins in-scope, invisible outside, empty scope falls back")

    # ---- G-11 event sourcing + chain binding --------------------------------------- #
    work = tempfile.mkdtemp(prefix="jjdai_reg_")
    journal = os.path.join(work, "registry.jsonl")
    sk = SigningKey.generate()
    chain = WitnessChain(sk, log_path=os.path.join(work, "wit.jsonl"))
    reg11 = ChampionRegistry(P, witness=chain, journal_path=journal, now_fn=clk)
    reg11.record("maglev", "ne:alpha", True, margin=0.3)
    reg11.record("maglev", "ne:alpha", False, margin=0.1)
    reg11.slash("ne:alpha", "spot-check failed")
    reg11.set_stake("ne:alpha", 0.8)

    replayed = ChampionRegistry.replay(reg11.events, P, now_fn=clk)
    same_snapshot = replayed.snapshot_hash() == reg11.snapshot_hash()
    chain_ok = chain.verify_chain()
    bound = verify_journal_against_chain(reg11.events, chain.records)
    tampered = list(reg11.events)
    tampered[1] = dict(tampered[1], ok=True)          # flip a verdict
    try:
        verify_journal_against_chain(tampered, chain.records)
        caught = False
    except JournalChainMismatch:
        caught = True
    # journal survives restart:
    reg11b = ChampionRegistry(P, journal_path=journal, now_fn=clk)
    persisted = reg11b.snapshot_hash() == reg11.snapshot_hash()
    check("G-11", same_snapshot and chain_ok and bound == 4 and caught and persisted,
          "replay == snapshot; 4 REGISTRY events on verified chain; "
          "tampered journal caught; журнал переживает рестарт")

    # ---- G-12 difficulty weighting -------------------------------------------------- #
    reg12 = ChampionRegistry(P, now_fn=clk)
    for _ in range(5):
        reg12.record("m", "ne:hard", True, difficulty=4.0)
        reg12.record("m", "ne:easy", True, difficulty=1.0)
    check("G-12", reg12.weight("m", "ne:hard") > reg12.weight("m", "ne:easy"),
          f"hard w={reg12.weight('m','ne:hard'):.3f} > "
          f"easy w={reg12.weight('m','ne:easy'):.3f}")

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nREGISTRY §9.9: {len(results) - failed}/{len(results)} green"
          + ("  ✓ reputation spine certified" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_registry()
