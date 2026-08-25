#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_deliberation_attribution — v0.6.7-recut3: whose deliberation was it?
==========================================================================
`verify_deliberation_against_chain(events, records, being_id)` took a being
and never used it. It compared one string — the semantic digest — and
nothing else. The audit built a chain signed by a DIFFERENT node, attributed
in its provenance to a different being through a different organ, carrying a
completely unrelated request, and the auditor accepted it as a correct
binding for another being's events.

The digest binds run, step, node and resulting state: WHAT HAPPENED. It is
silent about WHO. Reading that silence as attribution defeats the point of a
witness plane — every act in this system is an act by a named being, and a
record that cannot say whose act it was is not evidence of an act.

What can honestly be checked, and what cannot, differ here, and the split is
part of the design rather than a shortcut: the provenance is HASHED into the
record, so the claim "this being, through this organ" is checkable by
recomputation from the record alone. The request is a HIDING commitment
whose salt is held off-chain by the writer, so which event was committed is
checkable only with the writer's chain in hand — and the function now says
so instead of implying otherwise.

  ATTR-1  an honest run verifies, at both levels: without the chain, and
          with it, where the commitment is actually opened.
  ATTR-2  THE AUDIT'S FORGERY: right digests, wrong being, wrong organ,
          unrelated request, foreign signing key — refused. Fails against
          recut2.
  ATTR-3  each part of the attribution is load-bearing on its own: wrong
          being alone is refused, and wrong organ alone is refused, so the
          check cannot be passing for one reason while claiming two.
  ATTR-4  the organ table binds the digest prefix to the organ name and to
          the committed field together; an unknown prefix is not an organ.
  ATTR-5  opening is refused, not skipped, when the salt is absent, and a
          commitment that opens to a different event is caught — proved by
          mutating a field the semantic digest does NOT cover, because the
          first cut mutated one it did and never reached open_commit.
  ATTR-6  entitlement to witness for a being comes from a two-signature
          hosting binding, never from the record's own claim. Fails against
          recut3.
"""
from __future__ import annotations

import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.canonical import canonical                          # noqa: E402
from jjdai.crypto import H_hex, SigningKey                     # noqa: E402
from jjdai.witness import LocalAnchor, WitnessChain            # noqa: E402
from core.identity import (BeingIdentity, NodeIdentity,        # noqa: E402
                           make_hosting_binding)
from kernel.viveka import (ATTRIBUTED, COMMITMENT_OPENED, END,  # noqa: E402
                           EMITTED_PREFIX, IDENTITY_BOUND,
                           ORGAN_BINDINGS, Viveka, VivekaError,
                           verify_deliberation_against_chain)

#: Canonical identities, not readable placeholders. `being:attribution-real`
#: would have exercised the checks against a string that can never appear in
#: a real chain, and the audit was right to say so: an id that is not a hash
#: of a key cannot be bound to a signer at all, so every identity check
#: would have been vacuous.
_BEING = BeingIdentity(SigningKey.generate())
_OTHER_BEING = BeingIdentity(SigningKey.generate())
BEING = _BEING.being_id
OTHER = _OTHER_BEING.being_id


#: The node that legitimately hosts BEING, and its two-signature binding.
_NODE_SK = SigningKey.generate()
_NODE = NodeIdentity(_NODE_SK)
BINDING = make_hosting_binding(_BEING, _NODE, since_ts=1_750_000_000.0)


def _chain(tmp, name="w.jsonl", *, host=True):
    """`host=True` gives the chain the signing key named in BINDING."""
    sk = _NODE_SK if host else SigningKey.generate()
    return WitnessChain(sk, anchor=LocalAnchor(),
                        log_path=os.path.join(tmp, name))


def _run(tmp):
    chain = _chain(tmp)
    v = Viveka(BEING, witness=chain,
               journal_path=os.path.join(tmp, "j.jsonl"))
    v.add_node("s1", lambda st: {"n": st["n"] + 1})
    v.add_node("s2", lambda st: {"n": st["n"] * 3})
    v.add_edge("s1", "s2")
    v.add_edge("s2", END)
    v.set_entry("s1")
    v.run({"n": 1})
    return chain, v


def _forge(tmp, events, *, organ, being, request, name):
    """A chain as an impostor would write it: correct digests, wrong claims,
    and its own signing key — which the verifier never sees, because it is
    handed records rather than a chain."""
    chain = _chain(tmp, name)
    for ev in events:
        if ev["ev"] not in ("step", "rollback", "blocked"):
            continue
        sh = H_hex(canonical(ev.get("state", {})))
        node = ev.get("node", ev.get("ev"))
        step = ev.get("step", 0)
        chain.append("DELIBERATION", request=request,
                     provenance={"organ": organ, "being_id": being},
                     semantic_digest=(f"{EMITTED_PREFIX}:{ev['run_id']}:"
                                      f"{step}:{node}:{sh}"))
    return chain


def test_honest_run_verifies_at_both_levels():
    with tempfile.TemporaryDirectory() as tmp:
        chain, v = _run(tmp)
        n = len([r for r in chain.records if r["kind"] == "DELIBERATION"])
        assert n >= 2, n
        weak = verify_deliberation_against_chain(v.events, chain.records,
                                                 BEING)
        assert (weak.level, weak.records) == (ATTRIBUTED, n), weak
        opened = verify_deliberation_against_chain(v.events, chain.records,
                                                   BEING, chain=chain)
        assert (opened.level, opened.records) == (COMMITMENT_OPENED, n), opened
        full = verify_deliberation_against_chain(v.events, chain.records,
                                                 BEING, chain=chain,
                                                 binding=BINDING)
        assert full.level == IDENTITY_BOUND, full
        assert full.at_least(COMMITMENT_OPENED)
        assert not opened.at_least(IDENTITY_BOUND), (
            "a weaker result compared as though it were the strongest — the "
            "defect a bare count made invisible")
        assert chain.verify_chain()
    print(f"  [PASS] ATTR-1  {n} records, three distinct proof levels")


def test_the_audit_forgery_is_refused():
    with tempfile.TemporaryDirectory() as tmp:
        _, v = _run(tmp)
        forged = _forge(tmp, v.events, organ="karma", being=OTHER,
                        request={"unrelated": "nothing to do with the event"},
                        name="forged.jsonl")
        assert forged.verify_chain(), \
            "the forgery must be internally well-formed, or this proves less"
        try:
            verify_deliberation_against_chain(v.events, forged.records, BEING)
        except VivekaError as e:
            assert "attributable" in str(e), str(e)
        else:
            raise AssertionError(
                "a chain written by another node, naming another being and "
                "another organ, verified as this being's deliberation")
    print("  [PASS] ATTR-2  the audit's forgery is refused")


def test_each_half_of_the_attribution_is_load_bearing():
    with tempfile.TemporaryDirectory() as tmp:
        chain, v = _run(tmp)
        b = ORGAN_BINDINGS[EMITTED_PREFIX]

        # wrong BEING only — organ correct, request correct
        wrong_being = _forge(tmp, v.events, organ=b["organ"], being=OTHER,
                             request={b["event_field"]: "x"},
                             name="wb.jsonl")
        try:
            verify_deliberation_against_chain(v.events, wrong_being.records,
                                              BEING)
        except VivekaError:
            pass
        else:
            raise AssertionError("another being's records passed")

        # wrong ORGAN only — being correct
        wrong_organ = _forge(tmp, v.events, organ="smriti", being=BEING,
                             request={b["event_field"]: "x"},
                             name="wo.jsonl")
        try:
            verify_deliberation_against_chain(v.events, wrong_organ.records,
                                              BEING)
        except VivekaError:
            pass
        else:
            raise AssertionError(
                "a record attributed to another organ passed — the organ is "
                "not being checked, only the being")

        # and an honest chain still passes, so neither refusal is blanket
        assert verify_deliberation_against_chain(
            v.events, chain.records, BEING).records >= 2
    print("  [PASS] ATTR-3  wrong being and wrong organ each refuse alone")


def test_the_organ_table_is_one_fact():
    for prefix, binding in ORGAN_BINDINGS.items():
        assert binding["organ"] and binding["event_field"], binding
        assert binding["event_field"].startswith(binding["organ"]), (
            "the committed field name and the organ name must move "
            "together; they are one fact about one organ")
    assert EMITTED_PREFIX in ORGAN_BINDINGS

    with tempfile.TemporaryDirectory() as tmp:
        chain, v = _run(tmp)
        recs = [dict(r) for r in chain.records]
        for r in recs:
            if r["kind"] == "DELIBERATION":
                r["semantic_digest"] = "transition_guard" + \
                    r["semantic_digest"][len(EMITTED_PREFIX):]
        try:
            verify_deliberation_against_chain(v.events, recs, BEING)
        except VivekaError:
            pass
        else:
            raise AssertionError("an unknown prefix was accepted as an organ")
    print("  [PASS] ATTR-4  an unknown prefix is not an organ")


def test_opening_is_refused_not_skipped():
    with tempfile.TemporaryDirectory() as tmp:
        chain, v = _run(tmp)
        # salts live off-chain with the writer: a reader who asks to open
        # and cannot must be told, not quietly given a pass
        stripped = _chain(tmp, "s.jsonl")
        stripped.records = [dict(r) for r in chain.records]
        stripped._salts = {}
        try:
            verify_deliberation_against_chain(v.events, stripped.records,
                                              BEING, chain=stripped)
        except VivekaError as e:
            assert "not evidence" in str(e), str(e)
        else:
            raise AssertionError("a missing salt silently passed as opened")

        # the same records without asking to open are fine — the weaker
        # level is available, it is simply not called the stronger one
        assert verify_deliberation_against_chain(
            v.events, stripped.records, BEING).records >= 2

        # A commitment that opens to a DIFFERENT event must be caught HERE,
        # in open_commit, and the mutation has to prove that.
        #
        # The first cut of this check mutated `state`, which is an INPUT TO
        # THE SEMANTIC DIGEST: the digest comparison rejected the event
        # several lines earlier and the opening branch never ran. Verified
        # against the real defect — with `open_commit` replaced by a stub
        # returning True, the check still passed. So the mutation now
        # targets a field that the digest does not cover.
        swapped = [dict(e) for e in v.events]
        witnessed = [e for e in swapped
                     if e["ev"] in ("step", "rollback", "blocked")]
        assert "t" in witnessed[0], witnessed[0].keys()
        witnessed[0]["t"] = witnessed[0]["t"] + 1234.5
        # the digest is unaffected: same run, step, node and state
        assert verify_deliberation_against_chain(
            swapped, chain.records, BEING).level == ATTRIBUTED, (
            "the mutated field reached the semantic digest after all, so "
            "this check would again prove nothing about open_commit")
        try:
            verify_deliberation_against_chain(swapped, chain.records, BEING,
                                              chain=chain)
        except VivekaError as e:
            assert "does not open" in str(e), str(e)
        else:
            raise AssertionError("an event that was never committed passed")
    print("  [PASS] ATTR-5  opening is proved by a mutation outside the "
          "digest")


def test_signer_entitlement_is_not_self_declared():
    """The third audit's finding, stated as a check.

    Provenance checking proves a record is internally consistent with a
    claim. It does not prove the chain that wrote it was ever entitled to
    speak for this being — and a chain under a foreign key, naming the right
    being and the right organ, passed. What was missing is a statement
    signed by BOTH parties: the being consented to be hosted, the node
    accepted responsibility for what it witnesses under that name.
    """
    with tempfile.TemporaryDirectory() as tmp:
        chain, v = _run(tmp)
        # a chain under a FOREIGN key whose records make all the right claims
        foreign = _chain(tmp, "foreign.jsonl", host=False)
        b = ORGAN_BINDINGS[EMITTED_PREFIX]
        for ev in v.events:
            if ev["ev"] not in ("step", "rollback", "blocked"):
                continue
            sh = H_hex(canonical(ev.get("state", {})))
            foreign.append(
                "DELIBERATION", request={b["event_field"]: ev},
                provenance={"organ": b["organ"], "being_id": BEING},
                semantic_digest=(f"{EMITTED_PREFIX}:{ev['run_id']}:"
                                 f"{ev.get('step', 0)}:"
                                 f"{ev.get('node', ev['ev'])}:{sh}"))
        assert foreign.verify_chain(), "the forgery must be well-formed"
        assert foreign.node_id != chain.node_id

        # without a binding it reaches ATTRIBUTED — and that is HONEST: the
        # level claims internal consistency and nothing more
        weak = verify_deliberation_against_chain(v.events, foreign.records,
                                                 BEING)
        assert weak.level == ATTRIBUTED, weak
        assert not weak.at_least(IDENTITY_BOUND)

        # asked for identity, it is refused
        try:
            verify_deliberation_against_chain(v.events, foreign.records,
                                              BEING, chain=foreign,
                                              binding=BINDING)
        except VivekaError as e:
            assert "entitled" in str(e), str(e)
        else:
            raise AssertionError(
                "a chain under a foreign key reached IDENTITY_BOUND by "
                "declaring the right being itself")

        # a binding for ANOTHER being does not launder the right chain
        other_binding = make_hosting_binding(
            _OTHER_BEING, _NODE, since_ts=1_750_000_000.0)
        try:
            verify_deliberation_against_chain(v.events, chain.records, BEING,
                                              chain=chain,
                                              binding=other_binding)
        except VivekaError:
            pass
        else:
            raise AssertionError("a binding for another being was accepted")

        # A binding whose IDS are right but whose SIGNATURES are not must
        # fail. Without this the id comparison carries the whole check and
        # the signature verification is dead code — confirmed against the
        # real thing: with verify_hosting_binding() removed from the
        # entitlement path, every other case here still passed.
        for field in ("being_sig", "node_sig"):
            forged_sig = dict(BINDING)
            forged_sig[field] = "00" * 64
            try:
                verify_deliberation_against_chain(v.events, chain.records,
                                                  BEING, chain=chain,
                                                  binding=forged_sig)
            except VivekaError:
                pass
            else:
                raise AssertionError(
                    f"a binding with an invalid {field} was accepted — the "
                    f"ids matched and nobody checked who signed")

        # a binding re-attributed to another node, with genuine signatures
        moved = dict(BINDING, node_id=_OTHER_BEING.being_id)
        try:
            verify_deliberation_against_chain(v.events, chain.records, BEING,
                                              chain=chain, binding=moved)
        except VivekaError:
            pass
        else:
            raise AssertionError("a re-attributed binding was accepted")

        # and a binding without a chain is refused rather than ignored
        try:
            verify_deliberation_against_chain(v.events, chain.records, BEING,
                                              binding=BINDING)
        except VivekaError as e:
            assert "without the chain" in str(e), str(e)
        else:
            raise AssertionError("a binding with nothing to bind was "
                                 "silently accepted")
    print("  [PASS] ATTR-6  entitlement comes from a two-signature binding, "
          "never from the record's own claim")


if __name__ == "__main__":
    for t in (test_honest_run_verifies_at_both_levels,
              test_the_audit_forgery_is_refused,
              test_each_half_of_the_attribution_is_load_bearing,
              test_the_organ_table_is_one_fact,
              test_opening_is_refused_not_skipped,
              test_signer_entitlement_is_not_self_declared):
        t()
    print("\ndeliberation attribution — 5/5 checks green")
