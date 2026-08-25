#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_kriya_gate_naming — v0.6.8: one word stops meaning two things
==================================================================
ADR-018 closes open question 10 of ADR-016 rev 2 by splitting a term that
had come to name two unrelated organs:

  Viveka     — cognitive discrimination inside Chitta. Forms distinctions,
               authorizes nothing.
  KriyaGate  — the deterministic, NON-cognitive control of the passage of an
               intention into an executable action: state graph, checkpoint,
               step budget, authority envelope, Article 25.

`kernel/viveka.py` implements the second and is named after the first. The
MODULE rename is Ф2 (roadmap r6.8.3 phase table). What this drop moves is only
what a hash chain freezes — the organ label, the digest prefix and the
committed event field — because those cannot move after genesis.

The interesting half of this is the read path. Every chain written before
this drop carries `viveka:`. The prefix is a LABEL; the binding that matters
is run/step/node/state and it is identical under either name. So the old
prefix stays acceptable on read forever, and the checks below have to prove
that this acceptance did not quietly weaken the binding it verifies.

  KRIYA-1  A live run emits the new serialized values: the digest prefix is
           `kriya_gate:` and the provenance hash is the hash of a record
           naming `kriya_gate` as the organ.
  KRIYA-2  A pre-v0.6.8 chain — real records carrying the legacy prefix —
           still verifies against its own event journal.
  KRIYA-3  Dual acceptance did not become blanket acceptance: a tampered
           binding is still caught under BOTH prefixes, and a foreign
           prefix is not accepted at all.
  KRIYA-4  No emission path re-introduces the old value: the module carries
           no literal `viveka` in an emitted position.
"""
from __future__ import annotations

import io
import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.canonical import canonical                              # noqa: E402
from jjdai.cognitive import (KRIYA_GATE_DIGEST_PREFIX,             # noqa: E402
                             KRIYA_GATE_EVENT_FIELD,
                             KRIYA_GATE_ORGAN,
                             LEGACY_VIVEKA_DIGEST_PREFIX)
from jjdai.crypto import H_hex, SigningKey                         # noqa: E402
from jjdai.witness import LocalAnchor, WitnessChain                # noqa: E402
from kernel.viveka import (ATTRIBUTED, END, Viveka,                # noqa: E402
                           VivekaError,
                           verify_deliberation_against_chain)

BEING = "being:kriya-gate-naming"


def _run(tmp):
    chain = WitnessChain(SigningKey.generate(), anchor=LocalAnchor(),
                         log_path=os.path.join(tmp, "w.jsonl"))
    v = Viveka(BEING, witness=chain,
               journal_path=os.path.join(tmp, "j.jsonl"))
    v.add_node("s1", lambda st: {"n": st["n"] + 1})
    v.add_node("s2", lambda st: {"n": st["n"] * 2})
    v.add_edge("s1", "s2")
    v.add_edge("s2", END)
    v.set_entry("s1")
    v.run({"n": 1})
    return chain, v


def test_live_run_emits_kriya_gate():
    with tempfile.TemporaryDirectory() as tmp:
        chain, v = _run(tmp)
        recs = [r for r in chain.records if r["kind"] == "DELIBERATION"]
        assert recs, "the run witnessed nothing"
        for r in recs:
            d = r["semantic_digest"]
            assert d.startswith(KRIYA_GATE_DIGEST_PREFIX + ":"), d
            assert not d.startswith(LEGACY_VIVEKA_DIGEST_PREFIX + ":"), d
        # provenance is hashed, so the organ label is checked the only way
        # it can honestly be checked: by recomputing the hash the record
        # would carry if the organ were named what we claim.
        expect = H_hex(canonical({"organ": KRIYA_GATE_ORGAN,
                                  "being_id": BEING}))
        assert recs[0]["provenance_hash"] == expect, (
            "the provenance hash does not match a record naming "
            f"{KRIYA_GATE_ORGAN!r} as the organ")
        stale = H_hex(canonical({"organ": "viveka", "being_id": BEING}))
        assert recs[0]["provenance_hash"] != stale
        assert chain.verify_chain()
        # v0.6.8 rebase onto recut9: the verifier returns a
        # DeliberationProof(level, records), not a count. The count alone
        # said how much was CHECKED and nothing about what was PROVED —
        # which is why every caller used to read the weakest result as the
        # strongest. So the level is asserted here too, not just the number.
        proof = verify_deliberation_against_chain(v.events, chain.records,
                                                  BEING)
        assert proof.records == len(recs), proof
        assert proof.at_least(ATTRIBUTED), proof
    print(f"  [PASS] KRIYA-1  {len(recs)} records carry the kriya_gate "
          f"digest and organ; proof level {proof.level}")


def _legacy_chain(tmp):
    """A chain as v0.6.7 would have written it, from a real run's events."""
    with tempfile.TemporaryDirectory() as inner:
        _, v = _run(inner)
        events = v.events
    chain = WitnessChain(SigningKey.generate(), anchor=LocalAnchor(),
                         log_path=os.path.join(tmp, "legacy.jsonl"))
    for ev in events:
        if ev["ev"] not in ("step", "rollback", "blocked"):
            continue
        sh = H_hex(canonical(ev.get("state", {})))
        node = ev.get("node", ev.get("ev"))
        step = ev.get("step", 0)
        chain.append(
            "DELIBERATION",
            request={"viveka_event": ev},
            provenance={"organ": "viveka", "being_id": BEING},
            semantic_digest=(f"{LEGACY_VIVEKA_DIGEST_PREFIX}:{ev['run_id']}:"
                             f"{step}:{node}:{sh}"))
    return chain, events


def test_legacy_chain_still_verifies():
    with tempfile.TemporaryDirectory() as tmp:
        chain, events = _legacy_chain(tmp)
        proof = verify_deliberation_against_chain(events, chain.records,
                                                  BEING)
        bound = proof.records
        assert bound == len([r for r in chain.records
                             if r["kind"] == "DELIBERATION"])
        # the legacy row must still ATTRIBUTE, not merely match digests:
        # keeping the old prefix readable is worth nothing if it downgrades
        # what a pre-v0.6.8 record proves.
        assert proof.at_least(ATTRIBUTED), proof
        assert chain.verify_chain()
    print(f"  [PASS] KRIYA-2  a pre-v0.6.8 chain of {bound} records still "
          f"verifies at {proof.level}")


def test_dual_acceptance_is_not_blanket_acceptance():
    with tempfile.TemporaryDirectory() as tmp:
        # tamper under the LEGACY prefix
        chain, events = _legacy_chain(tmp)
        recs = [r for r in chain.records if r["kind"] == "DELIBERATION"]
        recs[0]["semantic_digest"] = recs[0]["semantic_digest"][:-4] + "dead"
        try:
            verify_deliberation_against_chain(events, chain.records, BEING)
        except VivekaError:
            pass
        else:
            raise AssertionError("a tampered legacy binding passed")

    with tempfile.TemporaryDirectory() as tmp:
        # tamper under the NEW prefix
        chain, v = _run(tmp)
        recs = [r for r in chain.records if r["kind"] == "DELIBERATION"]
        recs[-1]["semantic_digest"] = recs[-1]["semantic_digest"][:-4] + "dead"
        try:
            verify_deliberation_against_chain(v.events, chain.records, BEING)
        except VivekaError:
            pass
        else:
            raise AssertionError("a tampered current binding passed")

    with tempfile.TemporaryDirectory() as tmp:
        # a THIRD prefix is not a third organ
        chain, v = _run(tmp)
        recs = [r for r in chain.records if r["kind"] == "DELIBERATION"]
        recs[0]["semantic_digest"] = "transition_guard" + \
            recs[0]["semantic_digest"][len(KRIYA_GATE_DIGEST_PREFIX):]
        try:
            verify_deliberation_against_chain(v.events, chain.records, BEING)
        except VivekaError:
            pass
        else:
            raise AssertionError("an unknown organ prefix was accepted")
    print("  [PASS] KRIYA-3  tampering caught under both prefixes; a third "
          "prefix is refused")


def test_no_legacy_value_is_emitted():
    src = io.open(os.path.join(_ROOT, "kernel", "viveka.py"),
                  encoding="utf-8").read()
    fossils = ('f"viveka:', "f'viveka:", '"organ": "viveka"',
               '"viveka_event"', "'viveka_event'")
    for f in fossils:
        assert f not in src, (
            f"kernel/viveka.py still emits the legacy serialized value {f!r} "
            f"— the module keeps its FILENAME until Ф2, but what it writes "
            f"into a hash chain moved in v0.6.8")
    assert KRIYA_GATE_EVENT_FIELD == "kriya_gate_event"
    assert "from jjdai.cognitive import" in src, \
        "the organ names are spelled locally instead of imported"
    print("  [PASS] KRIYA-4  no legacy serialized value left in an emitted "
          "position")


if __name__ == "__main__":
    for t in (test_live_run_emits_kriya_gate,
              test_legacy_chain_still_verifies,
              test_dual_acceptance_is_not_blanket_acceptance,
              test_no_legacy_value_is_emitted):
        t()
    print("\nkriya gate naming — 4/4 checks green")
