#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The ADR-019 pre-genesis reserve — deferred verification and custody.

ADR-019 rev 3.1 (Accepted) D12 declares a vocabulary and forbids emitting
any of it: Accepted authorises the RESERVE and nothing in the runtime. The
specification lands in Ф2 and network corroboration in Ф3; a lone production
node still refuses with `no_independent_panel`, now because the machinery is
absent rather than because a document was under discussion.

ADR-019 §4 names the carrier of this reserve — the same drop that carries
the track V reserve — so these checks sit beside TRKV-1…8 and are written
the same way: pinned literally where a value is hash-chained, refusing where
a name could be used before its phase.

  CUST-1  Every declared kind is in the canonical witness enum and NOTHING
          may emit one.
  CUST-2  One list, not two: the enum folds in the vocabulary rather than
          re-declaring it, and track IV and track V survive the fold.
  CUST-3  Reserved namespaces refuse at all three doors of Plane H — grant,
          apply and ordinary retrieve — prefix and sub-path alike.
  CUST-4  The key domain and the access class refuse, and the access class
          stays disjoint from Plane H's ranked access LEVELS.
  CUST-5  The enums are pinned literally: outcomes, custody reason codes,
          replay status and reason, stored status and the effective-status
          projection.
  CUST-6  Leaf domain separators are pinned literally for all eleven kinds,
          distinct from each other and from track V's, and not minted on
          demand.
  CUST-7  The prefixes exist for a reason: no custody outcome collides with
          containment's `CORROBORATED`, and no projection value collides
          with an outcome.
  CUST-8  The ambiguous tokens are declared, refuse by argument, and are
          excluded from the value scan — the named limitation of this
          reserve, asserted rather than left in a comment.
"""
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.plane_h import (ACCESS_LEVELS, AuthorizationError,   # noqa: E402
                          GovernedPlaneH, WritePolicy,
                          make_write_proposal)
from core.rag_store import RagStore                           # noqa: E402
from jjdai import cognitive as cog                            # noqa: E402
from jjdai import custody as cus                              # noqa: E402
from jjdai import reserved as rsv                             # noqa: E402
from jjdai import witness as wit                              # noqa: E402
from jjdai.crypto import canonical_node_id, SigningKey        # noqa: E402


def _chain(tmp):
    return wit.WitnessChain(SigningKey.generate(), anchor=wit.LocalAnchor(),
                            log_path=os.path.join(tmp, "w.jsonl"))


def test_kinds_declared_and_refused():
    """CUST-1"""
    assert len(cus.CUSTODY_KINDS) == 11, cus.CUSTODY_KINDS
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        for kind in cus.CUSTODY_KINDS:
            assert kind in wit.KINDS, f"{kind} not in the canonical enum"
            assert kind in wit.RESERVED_KINDS, kind
            try:
                c.append(kind, semantic_digest="ab" * 16)
                raise AssertionError(f"{kind} was emitted")
            except cog.ReservedValueError as e:
                assert "ADR-019" in str(e), str(e)
        assert not c.records
    print(f"  [PASS] CUST-1  {len(cus.CUSTODY_KINDS)} custody kinds "
          f"declared, none emittable")


def test_one_list_not_two():
    """CUST-2"""
    assert len(wit.KINDS) == len(set(wit.KINDS)), "a kind is declared twice"
    for kind in cus.CUSTODY_KINDS:
        assert wit.KINDS.count(kind) == 1, kind
    # the fold must not have displaced what was there before
    for kind in wit.RESERVED_TRACK_IV_KINDS:
        assert kind in wit.RESERVED_KINDS, kind
    for kind in cog.COGNITIVE_KINDS:
        assert kind in wit.RESERVED_KINDS, kind
    assert set(cus.CUSTODY_KINDS).isdisjoint(cog.COGNITIVE_KINDS)
    print("  [PASS] CUST-2  one enum, three declaration sites, no "
          "duplicates; track IV and track V intact")


def test_namespaces_refuse_at_every_door():
    """CUST-3"""
    sk_auth = SigningKey.generate()
    author = canonical_node_id(sk_auth.public)
    probes = []
    for ns in cus.NAMESPACES:
        probes += [ns, ns.rstrip("/"), ns + "being-1"]
    for ns in probes:
        with tempfile.TemporaryDirectory() as tmp:
            chain = _chain(tmp)
            store = RagStore(os.path.join(tmp, "rag.db"))
            policy = WritePolicy()

            # door 1 — configuration time
            try:
                policy.grant(ns, author)
            except cog.ReservedValueError:
                pass
            else:
                raise AssertionError(f"granted a write on {ns!r}")

            # door 2 — the use site, with a policy that was never asked. If
            # the only thing standing in the way were the ACL, the reserve
            # would depend on nobody having granted access.
            policy._grants.setdefault(ns, {}).setdefault(
                "add", set()).add(author)
            gov = GovernedPlaneH(store, policy, witness=chain,
                                 governor_node=chain.node_id)
            env = make_write_proposal(sk_auth, op="add", ns=ns,
                                      doc_id="d1", text="pending memory")
            try:
                gov.apply(env, "pending memory")
            except cog.ReservedValueError:
                pass
            except AuthorizationError:
                raise AssertionError(
                    f"{ns!r} was refused only by the ACL")
            else:
                raise AssertionError(f"wrote into {ns!r}")

            # door 3 — ordinary retrieval
            try:
                gov.retrieve(ns, "pending")
            except cog.ReservedValueError:
                pass
            else:
                raise AssertionError(f"ordinary retrieval reached {ns!r}")

            assert not chain.records, \
                "a refused namespace still produced a witness record"
    print(f"  [PASS] CUST-3  {len(probes)} custody namespace probes refuse "
          f"at grant, apply and retrieve")


def test_key_domain_and_access_class():
    """CUST-4"""
    for value in cus.KEY_DOMAINS:
        try:
            cus.check_key_domain(value)
            raise AssertionError(f"{value} not refused")
        except cog.ReservedValueError:
            pass
    for value in cus.ACCESS_CLASSES:
        try:
            cus.check_access_class(value)
            raise AssertionError(f"{value} not refused")
        except cog.ReservedValueError:
            pass
    # the same collision track V had to name: Plane H's ACCESS_LEVELS are a
    # RANKED, chunk-level retrieval policy. This is an unranked key-plane
    # class over a whole object. Two things, one English word.
    assert set(cus.ACCESS_CLASSES).isdisjoint(ACCESS_LEVELS)
    assert set(cus.ACCESS_CLASSES).isdisjoint(cog.ACCESS_CLASSES)
    assert set(cus.KEY_DOMAINS).isdisjoint(cog.KEY_DOMAINS)
    print("  [PASS] CUST-4  key domain and access class refuse; disjoint "
          "from Plane H levels and from track V")


def test_enums_pinned_literally():
    """CUST-5"""
    assert cus.CUSTODY_OUTCOMES == (
        "CUSTODY_CORROBORATED", "CUSTODY_DIVERGENT", "CUSTODY_UNVERIFIABLE",
        "CUSTODY_EXPIRED_UNSETTLED")
    assert cus.CUSTODY_REASON_CODES == (
        "PANEL_UNREACHABLE", "PANEL_QUORUM_UNMET", "PANEL_INDEPENDENCE_UNMET")
    # rev 3.1 removed the two replay codes from the custody reasons: D5 and
    # D16 ruled replay is not a condition of corroboration, and the list went
    # on asserting the opposite. Pinned so the split cannot quietly reverse.
    assert cus.REPLAY_STATUSES == ("REPLAY_AVAILABLE", "REPLAY_UNAVAILABLE")
    assert cus.REPLAY_REASON_CODES == ("REPLAY_INPUTS_INCOMPLETE",
                                       "MODEL_REPLACED_BEFORE_SETTLEMENT")
    assert not (set(cus.CUSTODY_REASON_CODES) & set(cus.REPLAY_REASON_CODES))
    assert cus.STORED_STATUSES == ("PENDING_VERIFICATION",)
    assert cus.EFFECTIVE_EVIDENCE_STATUSES == (
        "EVIDENCE_PENDING", "EVIDENCE_CORROBORATED_FOR_USE",
        "EVIDENCE_DIVERGENT", "EVIDENCE_UNVERIFIABLE", "EVIDENCE_EXPIRED")
    assert cus.TRACE_STATES == ("SELF_CHECKED",)
    assert cus.NAMESPACES == ("verification/custody/",
                              "memory/pending_verification/")
    assert cus.KEY_DOMAINS == ("verification_custody",)
    assert cus.ACCESS_CLASSES == ("CUSTODY_PRIVATE",)
    print("  [PASS] CUST-5  outcomes, reason codes, replay split, statuses "
          "and namespaces pinned literally")


def test_leaf_domains_pinned():
    """CUST-6"""
    assert cus.LEAF_DOMAIN_PREFIX == "JJDAI:CUSTODY:"
    domains = cus.LEAF_DOMAINS
    assert len(domains) == len(cus.CUSTODY_KINDS)
    assert len(set(domains.values())) == len(domains), "a domain repeats"
    assert domains["CUSTODY_ENTERED"] == "JJDAI:CUSTODY:CUSTODY_ENTERED:v1"
    assert domains["DEPENDENT_REEVALUATION_SETTLED"] == \
        "JJDAI:CUSTODY:DEPENDENT_REEVALUATION_SETTLED:v1"
    assert not (set(domains.values()) & set(cog.LEAF_DOMAINS.values()))
    try:
        cus.leaf_domain("REFLECTION")          # a track V kind, not ours
        raise AssertionError("a leaf domain was minted on demand")
    except cog.ReservedValueError:
        pass
    print(f"  [PASS] CUST-6  {len(domains)} distinct leaf domains, pinned, "
          f"none minted on demand")


def test_prefixes_prevent_the_third_collision():
    """CUST-7"""
    # `CORROBORATED` is taken by containment; rev 3.1 prefixed the outcomes
    # for that reason and the projection for the same reason one level up.
    assert "CORROBORATED" not in cus.CUSTODY_OUTCOMES
    assert "CORROBORATED" not in cus.EFFECTIVE_EVIDENCE_STATUSES
    for value in cus.CUSTODY_OUTCOMES:
        assert value.startswith("CUSTODY_"), value
    for value in cus.EFFECTIVE_EVIDENCE_STATUSES:
        assert value.startswith("EVIDENCE_"), value
    assert not (set(cus.CUSTODY_OUTCOMES) &
                set(cus.EFFECTIVE_EVIDENCE_STATUSES))
    src = os.path.join(_ROOT, "core", "containment.py")
    if os.path.exists(src):
        import io as _io
        text = _io.open(src, encoding="utf-8").read()
        for value in cus.CUSTODY_OUTCOMES + cus.EFFECTIVE_EVIDENCE_STATUSES:
            assert f'"{value}"' not in text, (
                f"{value} collides with a containment value")
    print("  [PASS] CUST-7  outcomes and projection carry distinct prefixes; "
          "no collision with containment")


def test_ambiguous_tokens_are_declared_and_excluded():
    """CUST-8"""
    assert cus.EFFECT_CLASSES == ("pure", "local_transactional",
                                  "local_nontransactional", "external",
                                  "unknown")
    assert cus.NODE_PROFILES == ("network_member", "local_only")
    for value in cus.EFFECT_CLASSES:
        try:
            cus.check_effect_class(value)
            raise AssertionError(f"{value} not refused by argument")
        except cog.ReservedValueError:
            pass
    for value in cus.NODE_PROFILES:
        try:
            cus.check_node_profile(value)
            raise AssertionError(f"{value} not refused by argument")
        except cog.ReservedValueError:
            pass
    # and the named limitation: they are NOT searched for in a record body,
    # because they are ordinary words. Asserted both ways so neither the
    # exclusion nor the declaration can drift alone.
    assert set(cus.AMBIGUOUS_TOKENS) <= rsv.UNSCANNED_VALUES
    assert not (set(cus.AMBIGUOUS_TOKENS) & rsv.SCANNED_VALUES)
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        c.append("INFER", provenance={"organ": "karma",
                                      "precision": cus.EFFECT_CLASSES[-1]},
                 semantic_digest="ab" * 16)
        assert len(c.records) == 1
    print(f"  [PASS] CUST-8  {len(cus.AMBIGUOUS_TOKENS)} ambiguous tokens "
          f"refuse by argument and are excluded from the value scan")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print(f"\ncustody reserve — {len(tests)}/{len(tests)} checks green")
