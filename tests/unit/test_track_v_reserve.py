#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_track_v_reserve — v0.6.8: the names of track V exist and refuse
====================================================================
Cross-cutting track V (Chitta and reflexive cognition, ADR-018 rev 2,
Accepted 22 August 2026) reserves its serialized vocabulary before genesis
testnet-0. Witness records are JCS-canonicalized and hash-chained, and a
cognitive-ledger event becomes a Merkle leaf under a domain separator: a
value that has entered a chain cannot afterwards be added, renamed or
re-domained without breaking every hash after it.

These checks are written against the ROADMAP formulation of the reserve
("declared and forbidden to emit"), not against the implementation — the
project's recurring defect is a check named after a claim that measures
something adjacent to it. Each one fails against v0.6.7.

  TRKV-1  Every declared kind is in the canonical witness enum and NOTHING
          may emit it; the refusal names track V and ADR-018 rather than
          the track IV reserve it sits beside.
  TRKV-2  ONE list, not two: the witness enum folds in the vocabulary
          module's tuple, contains no duplicates, and did not lose the
          track IV reserve while gaining this one.
  TRKV-3  Reserved namespaces refuse at all three doors of Plane H —
          grant, apply and ordinary retrieve — including a sub-path under
          the prefix, against a REAL store, a REAL signed proposal and a
          REAL witness chain.
  TRKV-4  Access classes and key domains refuse; and the track V access
          classes are disjoint from Plane H's ranked ACCESS_LEVELS, which
          are a different thing wearing the same English word.
  TRKV-5  The enums are pinned literally — statuses, KriyaGate outcomes,
          CONTESTED reason codes, the retrieval mode and the two
          commitment domain separators, in exact spelling and order.
  TRKV-6  Leaf domain separators are pinned literally for all fifteen
          kinds, and one is never minted for a kind that is not reserved.
  TRKV-7  OWED is a marker for what Ф2 still owes, not a value: it refuses
          everywhere and never appears in the set of reserved values.
  TRKV-8  No second spelling: no source file outside the vocabulary module
          hardcodes a reserved value as a string literal. That is how the
          key-plane domain names on the r6.7 diagrams (`reflexive`,
          `prediction`) would have drifted into code.
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

from jjdai import cognitive as cog                                  # noqa: E402
from jjdai.cognitive import ReservedValueError                      # noqa: E402
from jjdai.crypto import canonical_node_id, SigningKey              # noqa: E402
from jjdai.witness import (COGNITIVE_KINDS, KINDS,                  # noqa: E402
                           RESERVED_KINDS, RESERVED_TRACK_IV_KINDS,
                           LocalAnchor, WitnessChain)
from core.plane_h import (ACCESS_LEVELS, AuthorizationError,        # noqa: E402
                          GovernedPlaneH, ValidationError,
                          WritePolicy, make_write_proposal)
from core.rag_store import RagStore                                 # noqa: E402


def _chain(tmp):
    return WitnessChain(SigningKey.generate(), anchor=LocalAnchor(),
                        log_path=os.path.join(tmp, "witness.jsonl"))


def test_kinds_declared_and_refused():
    assert len(COGNITIVE_KINDS) == 15, COGNITIVE_KINDS
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        for kind in COGNITIVE_KINDS:
            assert kind in KINDS, f"{kind} missing from the canonical enum"
            assert kind in RESERVED_KINDS, f"{kind} is emittable"
            before = len(c.records)
            try:
                c.append(kind, semantic_digest="ab" * 16)
            except ValueError as e:
                msg = str(e)
                assert "RESERVED" in msg, msg
                assert "ADR-018" in msg, (
                    f"{kind}: the refusal cites the wrong decision — a "
                    f"reader sent to ADR-015 will not find this kind there")
            else:
                raise AssertionError(f"{kind} was emitted before its "
                                     f"semantics exist")
            assert len(c.records) == before, "a refused write still appended"
        assert c.verify_chain()
    print(f"  [PASS] TRKV-1  {len(COGNITIVE_KINDS)} track V kinds declared, "
          f"none emittable")


def test_one_list_not_two():
    assert cog.COGNITIVE_KINDS == COGNITIVE_KINDS, \
        "the witness enum re-declares the vocabulary instead of importing it"
    assert len(set(KINDS)) == len(KINDS), \
        f"duplicate kinds in the canonical enum: {KINDS}"
    for kind in RESERVED_TRACK_IV_KINDS:
        assert kind in RESERVED_KINDS, \
            f"{kind}: the track IV reserve was dropped while adding track V"
    assert set(cog.BY_KIND) == set(COGNITIVE_KINDS)
    print("  [PASS] TRKV-2  one vocabulary, folded into the enum, no "
          "duplicates, track IV intact")


def test_namespaces_refuse_at_every_door():
    sk_auth = SigningKey.generate()
    author = canonical_node_id(sk_auth.public)
    for ns in (cog.NS_REFLECTION_DRAFT,
               cog.NS_REFLECTION_DRAFT.rstrip("/"),      # bare prefix
               cog.NS_REFLECTION_DRAFT + "being-1",      # sub-path
               cog.NS_REFLECTION_VALIDATED,
               cog.NS_SELF_MODEL):
        with tempfile.TemporaryDirectory() as tmp:
            chain = _chain(tmp)
            store = RagStore(os.path.join(tmp, "rag.db"))
            policy = WritePolicy()

            # door 1 — configuration time
            try:
                policy.grant(ns, author)
            except ReservedValueError:
                pass
            else:
                raise AssertionError(f"granted a write on {ns!r}")

            # door 2 — the use site, with a policy that was never asked
            policy._grants.setdefault(ns, {}).setdefault(
                "add", set()).add(author)
            gov = GovernedPlaneH(store, policy, witness=chain,
                                 governor_node=chain.node_id)
            env = make_write_proposal(sk_auth, op="add", ns=ns,
                                      doc_id="d1", text="a reflection")
            try:
                gov.apply(env, "a reflection")
            except ReservedValueError:
                pass
            except AuthorizationError:
                raise AssertionError(
                    f"{ns!r} was refused only by the ACL — a reserve that "
                    f"depends on nobody having granted access is not a "
                    f"reserve")
            else:
                raise AssertionError(f"wrote into {ns!r}")

            # door 3 — ordinary retrieval
            try:
                gov.retrieve(ns, "reflection")
            except ReservedValueError:
                pass
            else:
                raise AssertionError(f"ordinary retrieval reached {ns!r}")

            assert not chain.records, \
                "a refused namespace still produced a witness record"
    print("  [PASS] TRKV-3  reserved namespaces refuse at grant, apply and "
          "retrieve, prefix and sub-path alike")


def test_access_classes_and_key_domains():
    for value in cog.ACCESS_CLASSES:
        try:
            cog.check_access_class(value)
        except ReservedValueError:
            continue
        raise AssertionError(f"access class {value} accepted")
    for value in cog.KEY_DOMAINS:
        try:
            cog.check_key_domain(value)
        except ReservedValueError:
            continue
        raise AssertionError(f"key domain {value} accepted")
    cog.check_access_class("public")          # not ours, not our business
    cog.check_key_domain("node_identity")

    assert not (set(cog.ACCESS_CLASSES) & set(ACCESS_LEVELS)), (
        "the key-plane access classes collide with Plane H's ranked access "
        "levels — one word, two meanings, which is the defect ADR-018 "
        "closed for Viveka")
    with tempfile.TemporaryDirectory() as tmp:
        gov = GovernedPlaneH(RagStore(os.path.join(tmp, "r.db")),
                             WritePolicy())
        try:
            gov.retrieve("aton/boilers", "q", access=cog.ACCESS_REFLEXIVE)
        except ValidationError:
            pass
        else:
            raise AssertionError("Plane H accepted a key-plane access class")
    print("  [PASS] TRKV-4  access classes and key domains refuse; disjoint "
          "from Plane H access levels")


def test_enums_pinned_literally():
    assert cog.PREDICTION_STATUSES == (
        "RESOLVED", "UNRESOLVED_EXTERNAL", "UNRESOLVED_UNOBSERVED",
        "EXPIRED_BY_DESIGN", "CENSORED", "INVALID_OUTCOME_SCHEMA")
    assert cog.PREDICTION_SEALED == "PREDICTION_SEALED"
    assert cog.PREDICTION_SEALED not in cog.PREDICTION_STATUSES, (
        "PREDICTION_SEALED is a lifecycle state, not a resolution status "
        "(ADR-018 rev 2, B-5)")
    assert cog.PREDICTION_SEALED not in cog.COGNITIVE_KINDS
    assert cog.PREDICTION_SEALED not in cog.ACCESS_CLASSES
    assert cog.PREDICTION_SEALED not in cog.KEY_DOMAINS
    assert cog.KRIYA_GATE_OUTCOMES == (
        "ADMITTED", "DENIED", "DEFERRED", "BUDGET_EXHAUSTED",
        "CHECKPOINT_REQUIRED", "AUTHORITY_EXCEEDED", "ARTICLE_25_BLOCKED")
    assert cog.CONTESTED_REASON_CODES == (
        "CONTESTED_EXTERNAL_CHALLENGE", "CONTESTED_INTERNAL_DISCRIMINATION")
    assert cog.CONTESTED_REASON_CODES_VERSION == "1"
    assert cog.HYPOTHESIS_RETRIEVAL == "hypothesis_retrieval"
    assert cog.PREDICTION_COMMITMENT_DOMAIN == "JJDAI:PREDICTION:v1"
    assert cog.INTENTION_COMMITMENT_DOMAIN == "JJDAI:INTENTION:v1"
    assert cog.NAMESPACES == ("cognitive/reflection/draft/",
                              "cognitive/reflection/validated/",
                              "cognitive/self_model/")
    try:
        cog.check_retrieval_mode(cog.HYPOTHESIS_RETRIEVAL)
    except ReservedValueError:
        pass
    else:
        raise AssertionError("the reserved retrieval mode is usable")
    print("  [PASS] TRKV-5  statuses, outcomes, reason codes, namespaces and "
          "domain separators pinned literally")


def test_leaf_domains_pinned():
    assert set(cog.LEAF_DOMAINS) == set(COGNITIVE_KINDS)
    assert cog.LEAF_DOMAINS["REFLECTION"] == "JJDAI:LEDGER:REFLECTION:v1"
    assert cog.LEAF_DOMAINS["SELF_MODEL_SNAPSHOT"] == \
        "JJDAI:LEDGER:SELF_MODEL_SNAPSHOT:v1"
    assert cog.LEAF_DOMAINS["PREDICTION_COMMITMENT"] == \
        "JJDAI:LEDGER:PREDICTION_COMMITMENT:v1"
    assert len(set(cog.LEAF_DOMAINS.values())) == len(COGNITIVE_KINDS), \
        "two kinds share a leaf domain — the tree could not tell them apart"
    for kind, dom in cog.LEAF_DOMAINS.items():
        assert dom == f"JJDAI:LEDGER:{kind}:v1", (kind, dom)
    for absent in ("INFER", "SESSION_OPEN", "NOT_A_KIND"):
        try:
            cog.leaf_domain(absent)
        except ReservedValueError:
            continue
        raise AssertionError(f"minted a leaf domain for {absent!r}")
    print("  [PASS] TRKV-6  fifteen distinct leaf domains, pinned, none "
          "minted on demand")


def test_owed_is_not_a_value():
    for check in (cog.check_access_class, cog.check_key_domain):
        try:
            check(cog.OWED)
        except ReservedValueError as e:
            assert "OWED" in str(e), str(e)
            continue
        raise AssertionError(f"{check.__name__} accepted the OWED marker")
    assert cog.OWED not in cog.ALL_RESERVED_VALUES
    owed = [r.kind for r in cog.RESERVES if r.reason_codes is cog.OWED]
    assert len(owed) == 14, (
        "the count of kinds whose reason codes ADR-018 has NOT fixed "
        f"changed to {len(owed)} — if an enumeration was decided it belongs "
        f"in the ADR first, and if one was invented here it must not be")
    print(f"  [PASS] TRKV-7  OWED refuses as a value; {len(owed)} reason-code "
          f"sets named as owed to Ф2 rather than invented")


def test_no_second_spelling():
    """Every reserved value has exactly one home.

    A serialized value written twice is a value that drifts once. This is
    not hypothetical: the r6.7 diagrams draw the key-plane domains as
    `reflexive` and `prediction` while the reserved values are
    `reflexive_recovery`, `prediction_round`, `prediction_resolution` and
    `round_ephemeral` — recorded as drift to resolve before genesis in
    docs/architecture/README.md. This check keeps the second spelling out
    of the code, where a hash would freeze it.
    """
    # v0.6.8 rebase: there are now TWO vocabularies with two homes, so the
    # check takes a table. Widened rather than left covering only track V —
    # a rule that guards one reserve and not the one beside it is the same
    # gap under a different name.
    from jjdai import custody as cus
    # The one-home rule can only bind tokens that mean one thing. ADR-019
    # also reserves ordinary English words as tool effect classes and node
    # profiles; running this check over them reports six honest files that
    # use one of them in an unrelated sense. They are excluded here for the
    # same reason `jjdai.reserved` excludes them from the value scan, and
    # the exclusion is asserted below rather than assumed.
    ambiguous = set(cus.AMBIGUOUS_TOKENS)
    assert ambiguous and not (set(cus.SCANNABLE_VALUES) & ambiguous)
    homes = ((os.path.join("jjdai", "cognitive.py"), cog.ALL_RESERVED_VALUES),
             (os.path.join("jjdai", "custody.py"),
              tuple(cus.SCANNABLE_VALUES) + tuple(cus.NAMESPACES)))
    offenders = []
    for base, dirs, files in os.walk(_ROOT):
        dirs[:] = [d for d in dirs
                   if d not in ("__pycache__", ".git", "docs", "tests")]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(base, fn), _ROOT)
            src = io.open(os.path.join(base, fn), encoding="utf-8").read()
            for home, values in homes:
                if rel == home:
                    continue
                for value in values:
                    if f'"{value}"' in src or f"'{value}'" in src:
                        offenders.append(f"{rel}: {value!r}")
    assert not offenders, (
        "reserved values hardcoded outside the module that owns them — "
        "import the constant, so there is one place a rename has to "
        "happen:\n  " + "\n  ".join(sorted(offenders)))
    total = len(cog.ALL_RESERVED_VALUES) + len(cus.ALL_RESERVED_VALUES)
    print(f"  [PASS] TRKV-8  {total} reserved values across two "
          f"vocabularies, one home each")


if __name__ == "__main__":
    for t in (test_kinds_declared_and_refused, test_one_list_not_two,
              test_namespaces_refuse_at_every_door,
              test_access_classes_and_key_domains,
              test_enums_pinned_literally, test_leaf_domains_pinned,
              test_owed_is_not_a_value, test_no_second_spelling):
        t()
    print("\ntrack V reserve — 8/8 checks green")
