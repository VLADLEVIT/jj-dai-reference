#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The ADR-022 vocabulary — release provenance, frozen before first emission.

ADR-022 rev 2.2 (Accepted, 27 Aug 2026) is the sixth pre-genesis window and
the only one whose names are written by the drop that declares them. That
difference is the first thing these checks pin, because the tidy-looking
mistake is to treat it like the other two reserves and refuse everything.

  PROV-1  The seven schema ids are pinned literally, distinct, and the tree
          holds no second spelling of any of them.
  PROV-2  RELEASE_ATTESTED is in the canonical witness enum and is
          EMITTABLE — folded in, not re-declared, and absent from
          RESERVED_KINDS. Track IV, V and VI survive the fold.
  PROV-3  Two separators sign and one does not, and the two functions refuse
          each other's strings.
  PROV-4  The debt events are NOT witness record kinds, and the projection
          is fail-closed: order, terminality and the reference field.
  PROV-5  The two key domains are distinct and neither serves the other's
          function.
  PROV-6  `verification_evidence_hash` is required for a verifier and
          forbidden for a builder — one shape, not "absent or null".
  PROV-7  The scope ladder is ordered and `same-host` does not carry a
          release tag.
  PROV-8  `device_binding: "attested"` refuses until Ф3, and the control
          block is five NUMBERS rather than a name.
  PROV-9  The effect-class split of v0.6.9: `pure` admitted, the other three
          deferred to Ф2, `unknown` fail-closed for a different reason and
          permanently.
"""
import io as _io
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai import cognitive as cog                            # noqa: E402
from jjdai import custody as cus                              # noqa: E402
from jjdai import provenance as prv                           # noqa: E402
from jjdai import witness as wit                              # noqa: E402
from jjdai.crypto import SigningKey                           # noqa: E402


def _chain(tmp):
    return wit.WitnessChain(SigningKey.generate(), anchor=wit.LocalAnchor(),
                            log_path=os.path.join(tmp, "w.jsonl"))


def _refuses(fn, *args):
    try:
        fn(*args)
    except (prv.ProvenanceValueError, cog.ReservedValueError):
        return True
    return False


def test_schemas_are_pinned_and_unique():
    """PROV-1"""
    assert prv.SCHEMA_RELEASE_STATEMENT == "jjdai.release-statement/v1"
    assert prv.SCHEMA_RELEASE_APPROVAL == "jjdai.release-approval/v1"
    assert prv.SCHEMA_RELEASE_ATTESTATION == "jjdai.release-attestation/v1"
    assert prv.SCHEMA_RELEASE_PUBLICATION == "jjdai.release-publication/v1"
    assert prv.SCHEMA_TOOLSET_MANIFEST == "jjdai.toolset-manifest/v2"
    assert prv.SCHEMA_SOURCE_TREE == "jjdai.source-tree/v2"
    assert prv.SCHEMA_REBUILD_EVIDENCE == "jjdai.rebuild-evidence/v1"
    assert prv.SCHEMA_RELEASE_REVOCATION == "jjdai.release-revocation/v1"
    assert len(set(prv.SCHEMAS)) == len(prv.SCHEMAS) == 8
    # the algorithm id travels beside every digest and IS the source-tree
    # schema; two names for it would be two algorithms to a reader.
    assert prv.TREE_DIGEST_ALGO == prv.SCHEMA_SOURCE_TREE
    # No second spelling anywhere in the package: a serialized value written
    # twice is how one value becomes two.
    pkg = os.path.join(_ROOT, "jjdai")
    for name in sorted(os.listdir(pkg)):
        if not name.endswith(".py") or name == "provenance.py":
            continue
        text = _io.open(os.path.join(pkg, name), encoding="utf-8").read()
        for schema in prv.SCHEMAS:
            assert f'"{schema}"' not in text, (
                f"{schema} is spelt again in jjdai/{name}; it belongs to "
                f"jjdai.provenance and is imported from there")
    print("  [PASS] PROV-1  eight schema ids pinned, distinct, spelt once")


def test_release_attested_is_emittable_not_reserved():
    """PROV-2"""
    assert prv.KIND_RELEASE_ATTESTED in wit.KINDS
    # rev 2.4: three more, reserved and emittable together, before first
    # emission — the kinds two debt positions and one false green were
    # waiting on. All four fold into wit.KINDS exactly once.
    assert prv.PROVENANCE_KINDS == (prv.KIND_RELEASE_ATTESTED,
                                    prv.KIND_KEY_ACTIVATED,
                                    prv.KIND_KEY_REVOKED,
                                    prv.KIND_RELEASE_REVOKED)
    for kind in prv.PROVENANCE_KINDS:
        assert wit.KINDS.count(kind) == 1 and kind not in wit.RESERVED_KINDS
    # THE point of this check. Tracks V and VI freeze names nothing may
    # write; window 6 freezes names this drop writes.
    assert prv.KIND_RELEASE_ATTESTED not in wit.RESERVED_KINDS, (
        "RELEASE_ATTESTED must be emittable: the drop that declares it is "
        "the drop that writes it (roadmap r6.9.1, freeze table)")
    # folded, not re-declared
    assert wit.KINDS.count(prv.KIND_RELEASE_ATTESTED) == 1
    src = _io.open(os.path.join(_ROOT, "jjdai", "witness.py"),
                   encoding="utf-8").read()
    assert f'"{prv.KIND_RELEASE_ATTESTED}"' not in src, (
        "the kind is imported, not spelt a second time in the enum")
    # the other three reserves survive the fold
    for kind in (cog.COGNITIVE_KINDS + cus.CUSTODY_KINDS +
                 wit.RESERVED_TRACK_IV_KINDS):
        assert kind in wit.KINDS and kind in wit.RESERVED_KINDS
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        # v0.6.9, closing an audit P0: an emittable kind with no required
        # content is worse than a reserved one, so the four fields of D5.5
        # are mandatory. This line carried only `version` and was a
        # REGRESSION in my own tree that a full run showed as a red I did
        # not reconcile against the printed failures.
        c.append(prv.KIND_RELEASE_ATTESTED, semantic_digest="ab" * 16,
                 provenance={"attestation_hash": "aa" * 32,
                             "statement_hash": "bb" * 32,
                             "version": "v0.6.9",
                             "tree_digest": "cc" * 32})
        assert c.records[-1]["kind"] == prv.KIND_RELEASE_ATTESTED
    assert set(prv.RELEASE_ATTESTED_FIELDS) == {
        "attestation_hash", "statement_hash", "version", "tree_digest"}
    print("  [PASS] PROV-2  RELEASE_ATTESTED folded in and emittable; three "
          "reserves intact")


def test_signing_domains_and_hash_prefix_refuse_each_other():
    """PROV-3"""
    # rev 2.3 adds the rebuild-evidence domain. A SEPARATE domain because it
    # is a separate act: an approval says "I accept this release", the
    # evidence says "I ran the recipe myself and got these bytes", and one
    # signature must never be readable as the other.
    assert prv.SIGNING_DOMAINS == ("JJDAI:RELEASE:APPROVAL:v1",
                                   "JJDAI:TOOLSET:MANIFEST:v1",
                                   "JJDAI:REBUILD:EVIDENCE:v1",
                                   "JJDAI:RELEASE:REVOKE:v1")
    assert prv.HASH_PREFIXES == ("JJDAI:RELEASE:ATTESTATION:v1",
                                 "JJDAI:RELEASE:KEYLIFECYCLE:v1",
                                 "JJDAI:RELEASE:REVOKED:v1")
    assert len(set(prv.SEPARATORS)) == 7
    # Both functions end in an unknown-separator guard, and that guard would
    # refuse a wrong-role string too — for the wrong reason. So the check
    # asserts WHICH refusal fired: a known separator used in the wrong role
    # must be refused BY ROLE, and the message must differ from the one an
    # unminted string gets. Without this the role split could be deleted
    # entirely and this check would still pass, which is the defect that
    # carried ANCH-REQ-1 past its own mutation in v0.6.7-recut2.
    def _why(fn, sep):
        try:
            fn(sep)
        except prv.ProvenanceValueError as exc:
            return str(exc)
        raise AssertionError(f"{fn.__name__}({sep!r}) did not refuse")

    for sep in prv.SIGNING_DOMAINS:
        assert prv.signing_domain(sep) == sep.encode("utf-8") + b"\x00"
        why = _why(prv.hash_prefix, sep)
        assert "SIGNING domain" in why and "unknown" not in why, (
            f"{sep} was refused as an unknown prefix rather than as a "
            f"signing domain: the role split is not what refused it")
    for sep in prv.HASH_PREFIXES:
        assert prv.hash_prefix(sep) == sep.encode("utf-8") + b"\x00"
        why = _why(prv.signing_domain, sep)
        assert "HASH pre-image prefix" in why and "unknown" not in why, (
            f"{sep} stopped being a signing domain in rev 2.2 when the "
            f"redundant statement signature was removed, and must be "
            f"refused by that fact rather than by not being listed")
    assert "unknown" in _why(prv.signing_domain, "JJDAI:RELEASE:MINTED:v1")
    assert "unknown" in _why(prv.hash_prefix, "JJDAI:RELEASE:MINTED:v1")
    roles = {s.value: s.role for s in prv.SEPARATOR_ROLES}
    assert roles == {prv.DOMAIN_RELEASE_APPROVAL: "signing",
                     prv.DOMAIN_TOOLSET_MANIFEST: "signing",
                     prv.DOMAIN_REBUILD_EVIDENCE: "signing",
                     prv.DOMAIN_RELEASE_REVOKE: "signing",
                     prv.PREFIX_RELEASE_ATTESTATION: "hash-prefix",
                     prv.PREFIX_KEY_LIFECYCLE: "hash-prefix",
                     prv.PREFIX_RELEASE_REVOKED: "hash-prefix"}
    print("  [PASS] PROV-3  four signing domains and three hash prefixes refuse "
          "each other's role")


def test_debt_events_project_fail_closed():
    """PROV-4"""
    assert prv.DEBT_EVENTS == ("DEBT_OPENED", "DEBT_CLOSED", "DEBT_CANCELLED")
    # NOT witness kinds: release housekeeping is not a claim to a peer.
    for ev in prv.DEBT_EVENTS:
        assert ev not in wit.KINDS
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        try:
            c.append(prv.DEBT_OPENED, semantic_digest="ab" * 16)
            raise AssertionError("a debt event reached the witness chain")
        except ValueError:
            pass
    o, cl, ca = prv.DEBT_OPENED, prv.DEBT_CLOSED, prv.DEBT_CANCELLED
    assert prv.project_debt([{"event": o}]) == prv.DEBT_OPEN
    assert prv.project_debt(
        [{"event": o}, {"event": cl, "evidence_ref": "tests/x"}]
    ) == prv.DEBT_SETTLED
    assert prv.project_debt(
        [{"event": o}, {"event": ca, "decision_ref": "ADR-022/D2"}]
    ) == prv.DEBT_WITHDRAWN
    # fail-closed on every shape that would let a position be quietly rewritten
    assert _refuses(prv.project_debt, [])
    assert _refuses(prv.project_debt, [{"event": cl, "evidence_ref": "x"}])
    assert _refuses(prv.project_debt, [{"event": o}, {"event": o}])
    assert _refuses(prv.project_debt,
                    [{"event": o}, {"event": cl, "evidence_ref": "x"},
                     {"event": ca, "decision_ref": "y"}])
    # a terminal event without its reference is a deletion with better manners
    assert _refuses(prv.project_debt, [{"event": o}, {"event": cl}])
    assert _refuses(prv.project_debt, [{"event": o}, {"event": ca}])
    assert prv.DEBT_REFERENCE_FIELD == {cl: "evidence_ref",
                                        ca: "decision_ref"}
    print("  [PASS] PROV-4  debt events are ledger-only; projection refuses "
          "reopening, overwriting and unreferenced closure")


def test_key_domains_do_not_serve_each_other():
    """PROV-5"""
    assert prv.KEY_DOMAINS == ("release_signing", "toolset_authorization")
    assert prv.key_domain_for(prv.PURPOSE_RELEASE_PROVENANCE) == \
        prv.KEY_DOMAIN_RELEASE_SIGNING
    assert prv.key_domain_for(prv.PURPOSE_TOOLSET_L2_MUTATION) == \
        prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION
    prv.check_domain_serves(prv.KEY_DOMAIN_RELEASE_SIGNING,
                            prv.PURPOSE_RELEASE_PROVENANCE)
    prv.check_domain_serves(prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
                            prv.PURPOSE_TOOLSET_L2_MUTATION)
    # the crossing that D10 exists to forbid: whoever can cut a build would
    # thereby be able to widen a being's hand.
    assert _refuses(prv.check_domain_serves, prv.KEY_DOMAIN_RELEASE_SIGNING,
                    prv.PURPOSE_TOOLSET_L2_MUTATION)
    assert _refuses(prv.check_domain_serves,
                    prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
                    prv.PURPOSE_RELEASE_PROVENANCE)
    assert _refuses(prv.check_domain_serves, "guardian_sign",
                    prv.PURPOSE_RELEASE_PROVENANCE)
    assert _refuses(prv.key_domain_for, "anything_else")
    # distinct from the domains the other ADRs own
    assert not (set(prv.KEY_DOMAINS) &
                (set(cog.KEY_DOMAINS) | set(cus.KEY_DOMAINS)))
    print("  [PASS] PROV-5  release_signing and toolset_authorization are "
          "distinct and refuse each other's function")


def test_approval_roles_carry_one_evidence_shape():
    """PROV-6"""
    assert prv.APPROVAL_ROLES == ("builder", "verifier")
    assert prv.EVIDENCE_REQUIRED_BY_ROLE[prv.ROLE_VERIFIER] is True
    assert prv.EVIDENCE_REQUIRED_BY_ROLE[prv.ROLE_BUILDER] is False
    assert set(prv.EVIDENCE_REQUIRED_BY_ROLE) == set(prv.APPROVAL_ROLES)
    print("  [PASS] PROV-6  verification evidence required for verifier, "
          "forbidden for builder")


def test_scope_ladder_orders_and_gates_the_release_tag():
    """PROV-7"""
    assert prv.REPRODUCIBILITY_SCOPES == ("same-host", "same-host-class",
                                          "cross-host-class")
    assert prv.scope_rank("same-host") < prv.scope_rank("same-host-class") \
        < prv.scope_rank("cross-host-class")
    assert prv.RELEASE_MIN_SCOPE == "same-host-class"
    prv.check_scope_allows_release("same-host-class")
    prv.check_scope_allows_release("cross-host-class")
    # a rebuild on the machine that built it repeats the machine
    assert _refuses(prv.check_scope_allows_release, "same-host")
    assert _refuses(prv.check_scope_allows_release, "any-host")
    assert _refuses(prv.scope_rank, "any-host")
    print("  [PASS] PROV-7  scope ladder ordered; same-host carries no "
          "release tag")


def test_control_is_numbers_and_attested_is_reserved():
    """PROV-8"""
    assert prv.CONTROL_FIELDS == ("signature_threshold", "distinct_keys",
                                  "distinct_devices", "distinct_principals",
                                  "device_binding")
    # four of the five are counted, not named. `distinct_principals` is the
    # one D2 insists is a NUMBER: two-key drawn as two-person would enter a
    # signed artefact as an independence nobody had.
    prv.check_device_binding(prv.DEVICE_BINDING_ASSERTED)

    def _why(value):
        try:
            prv.check_device_binding(value)
        except prv.ProvenanceValueError as exc:
            return str(exc)
        raise AssertionError(f"device_binding {value!r} was admitted")

    # `attested` is a DECLARED value held back until Ф3, so it must be
    # refused as reserved and not merely as a string nobody listed — the
    # trailing unknown-value guard would refuse it either way, and a check
    # that cannot tell those apart would survive the deletion of the rule.
    why = _why(prv.DEVICE_BINDING_ATTESTED)
    assert "RESERVED" in why and "Ф3" in why and "unknown" not in why
    assert "unknown" in _why("proved")
    assert prv.DEVICE_BINDING_ATTESTED in prv.DEVICE_BINDINGS, (
        "attested is declared and withheld, not undeclared")
    print("  [PASS] PROV-8  control is five fields, four counted; attested "
          "device binding reserved to Ф3")


def test_effect_class_split_of_v069():
    """PROV-9"""
    assert cus.ADMISSIBLE_EFFECT_CLASSES == ("pure",)
    assert cus.DEFERRED_EFFECT_CLASSES == ("local_transactional",
                                           "local_nontransactional",
                                           "external")
    assert cus.EFFECT_CLASS_UNKNOWN == "unknown"
    cus.check_effect_class("pure")                    # admitted by this drop
    for value in cus.DEFERRED_EFFECT_CLASSES:
        assert _refuses(cus.check_effect_class, value)
    assert _refuses(cus.check_effect_class, cus.EFFECT_CLASS_UNKNOWN)
    # the two refusals must not share a reason: `unknown` outlives the phase
    # gate that the deferred three are waiting on.
    try:
        cus.check_effect_class(cus.EFFECT_CLASS_UNKNOWN)
    except cog.ReservedValueError as exc:
        unknown_msg = str(exc)
    try:
        cus.check_effect_class("external")
    except cog.ReservedValueError as exc:
        deferred_msg = str(exc)
    assert "FAIL-CLOSED" in unknown_msg and "Ф2" not in unknown_msg
    assert "Ф2" in deferred_msg
    # `pure` stays out of the body scan: it is an ordinary English word
    assert "pure" in cus.AMBIGUOUS_TOKENS
    print("  [PASS] PROV-9  pure admitted, three classes deferred to Ф2, "
          "unknown fail-closed for its own reason")


if __name__ == "__main__":
    for fn in (test_schemas_are_pinned_and_unique,
               test_release_attested_is_emittable_not_reserved,
               test_signing_domains_and_hash_prefix_refuse_each_other,
               test_debt_events_project_fail_closed,
               test_key_domains_do_not_serve_each_other,
               test_approval_roles_carry_one_evidence_shape,
               test_scope_ladder_orders_and_gates_the_release_tag,
               test_control_is_numbers_and_attested_is_reserved,
               test_effect_class_split_of_v069):
        fn()
