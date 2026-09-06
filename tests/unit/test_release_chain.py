#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The release chain — statement, approval, attestation, publication.

ADR-022 D2, D5, D6. Each check is written against a defect an earlier
revision of the ADR actually had, or against a shortcut this construction
invites, rather than against the code that implements it.

  REL-1   A ReleaseStatement carries no position in the witness sequence,
          names its digest algorithm, and its control block is complete.
  REL-2   `verification_evidence_hash` has ONE shape: required for a
          verifier, forbidden for a builder.
  REL-3   An approval names its release. Carrying it to another statement
          refuses even with a valid signature.
  REL-4   Both roles are required, keys are pairwise distinct and devices
          are pairwise distinct.
  REL-5   The control numbers are COUNTED from the approvals through the
          registry; a recorded number that disagrees refuses. The registry
          — not the approval — says who and where.
  REL-6   Key validity is judged at the ACTUAL position of the
          RELEASE_ATTESTED record: before activation and after revocation
          both refuse, and a historical release stays valid after the key is
          revoked later.
  REL-7   The hashed object stops growing once hashed: `witness_ref` lives
          in the publication, not the attestation, and a swapped reference
          is caught by RESOLUTION.
  REL-8   An unfinished release never reaches the WitnessChain.
  REL-9   The registry refuses two device_id on one physical host, an
          incomplete entry and a duplicate key_id.
  REL-10  The shipped `docs/release_keys.json` is a valid, EMPTY registry —
          no ceremony has been held, so no release can be attested.
  REL-11  Strict schema, and the external facts: tag against version, digest
          against the built tree, acceptance green and against the same
          tree, artefact bytes against the recorded hash.
  REL-12  A publication into an EDITED chain refuses. Integrity-valid means
          the chain verifies, not that one hash matches a value taken from
          the object under examination.
  REL-13  Read-position, verify and append are one atomic step; a record
          landing elsewhere abandons the publication.
  REL-14  A key with no physical binding is not registered, and one public
          key holds one id.
  REL-15  An INCOMPLETE context cannot publish or tag. `internal_only()` is
          for an archival reader; passing it to `publish()` turned every
          external gate off at once and wrote a release of nothing in
          particular.
  REL-16  A key's lifecycle positions must RESOLVE in the chain. A number in
          a JSON file is an assertion, and one that can be edited earlier
          makes a signature valid that was not.
"""
import copy
import io as _io
import json
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai import provenance as prv                           # noqa: E402
from jjdai import release as rel                              # noqa: E402
from jjdai import witness as wit                              # noqa: E402
from jjdai.crypto import SigningKey                           # noqa: E402

_CTX = None  # replaced below; declared here so helpers can see it
_ENV = {"python": "CPython 3.12.3", "locale": "C", "timezone": "UTC",
        "umask": "0022", "network": "disabled-and-checked",
        "network_enforcement": "asserted",
        "source_date_epoch": "1700000000"}

#: Rebuild evidence, minted for real. The fixture used to write `"9a" * 32`
#: into every verifier approval — the audit published a release naming it,
#: found no object behind it, and called the whole construction a proof that
#: a verifier had signed a hash-shaped string. Here the evidence is what the
#: verifier would actually produce: his OWN statement over the same tree.
_EVIDENCE = {}
_EVIDENCE_BY_SH = {}

#: A ledger with nothing open against a release tag. The real one has seven
#: positions open and REL-17 uses it; this is the fixture for every other
#: check, which is about something else and must not be blocked by it.
_PUBLICATION_BLOCKED = {
    "release_debt": {
        "schema": "jjdai.debt-ledger/v1",
        "events": [
            {"seq": 1, "id": "fixture-publication-position",
             "event": "DEBT_OPENED", "blocks": "publication",
             "opened_in": "fixture"}]}}

_CLEAN_LEDGER = {
    "release_debt": {
        "schema": "jjdai.debt-ledger/v1",
        "events": [
            {"seq": 1, "id": "fixture-position", "event": "DEBT_OPENED",
             "blocks": "meaning-of-a-release-tag", "opened_in": "fixture"},
            {"seq": 2, "id": "fixture-position", "event": "DEBT_CLOSED",
             "closed_in": "fixture", "evidence_ref": "fixture"},
        ]}}
_BUILDER = SigningKey(b"\x51" * 32)
_VERIFIER = SigningKey(b"\x52" * 32)

#: Most checks here are about the INTERNAL rules of D5.4. They still need a
#: COMPLETE context, because v0.6.9 forbids publishing with an incomplete
#: one — every absent reader is a gate that silently passes, and
#: `internal_only()` turns all of them off at once. So the fixture supplies
#: facts that AGREE with `_statement()`; the external gates going red have
#: their own subject in REL-11, and the refusal of `internal_only()` has its
#: own in REL-15.



def _full_context(statement=None):
    statement = statement or _statement()
    acceptance = {"schema": rel.ACCEPTANCE_SCHEMA,
                  "suite": rel.ACCEPTANCE_SUITE,
                  "passed": 292, "total": 292, "import_errors": 0,
                  "tree_digest": statement["tree_digest"],
                  "tree_digest_algo": prv.TREE_DIGEST_ALGO,
                  "_raw_hash": statement["acceptance_hash"]}
    by_name = {a["name"]: a for a in statement["artefacts"]}

    def artefact(name):
        return _bytes_for(by_name[name]["sha256"], by_name[name]["length"])

    return rel.ReleaseContext(
        expected_tag=statement["version"],
        tree_digest=statement["tree_digest"],
        acceptance=acceptance,
        build_environment=dict(_ENV),
        artefact_reader=artefact,
        bundle_reader=lambda: _bytes_for(statement["bundle_hash"]),
        recipe_reader=lambda: _bytes_for(statement["recipe_hash"]),
        sbom_reader=lambda: _bytes_for(statement["sbom_hash"]),
        toolset_manifest_reader=lambda: _bytes_for(
            statement["toolset_manifest_hash"]),
        evidence_reader=lambda digest: _EVIDENCE.get(digest),
        debt_reader=lambda: _CLEAN_LEDGER,
        revocation_reader=lambda h: _REVOCATIONS.get(h))


_PREIMAGE = {}
_CTX = None   # bound after the helpers below are defined


def _bytes_for(digest, length=None):
    """Bytes that hash to `digest` — found once and cached.

    The fixture cannot invert sha256, so the statement's hashes are BUILT
    from these bytes instead: `_statement()` reads them from here. The
    search below only runs if a hash is asked for that no fixture minted,
    which is a fixture bug rather than a check failing.
    """
    if digest in _PREIMAGE:
        return _PREIMAGE[digest]
    raise AssertionError(f"no fixture bytes mint {digest}")


def _mint(tag, length=64):
    from jjdai.crypto import H_hex
    body = (tag.encode() * length)[:length]
    digest = H_hex(body)
    _PREIMAGE[digest] = body
    return digest, len(body)


def _registry(*, builder_active=0, verifier_active=1,
              builder_revoked=None, same_device=False):
    doc = {"schema": rel.REGISTRY_SCHEMA,
           "lifecycle_binding": rel.LIFECYCLE_WITNESSED, "keys": [
        {"key_id": "kb", "public": _BUILDER.public.hex(),
         "device_id": "dev-b", "principal_id": "p1", "roles": ["builder"],
         "physical_host": "box-b",
         "physical_host_assertion": "op-1/2026-08-29",
         "activated_at_witness_seq": builder_active,
         "revoked_at_witness_seq": builder_revoked,
         "revocation_reason": "test" if builder_revoked else None},
        {"key_id": "kv", "public": _VERIFIER.public.hex(),
         "device_id": "dev-b" if same_device else "dev-v",
         "principal_id": "p1", "roles": ["verifier"],
         "physical_host": "box-b" if same_device else "box-v",
         "physical_host_assertion": "op-1/2026-08-29",
         "activated_at_witness_seq": verifier_active,
         "revoked_at_witness_seq": None},
    ]}
    return rel.load_registry(doc)


def _statement(**over):
    doc = {
        "schema": prv.SCHEMA_RELEASE_STATEMENT,
        "version": "v0.6.9",
        "tree_digest": "ab" * 32,
        "tree_digest_algo": prv.TREE_DIGEST_ALGO,
        "artefacts": [dict(zip(("sha256", "length"),
                               _mint("artefact")),
                           name="jjdai-0.6.9.tar.gz")],
        "bundle_hash": _mint("bundle")[0],
        "toolset_manifest_hash": _mint("manifest")[0],
        "sbom_hash": _mint("sbom")[0],
        "acceptance_hash": _mint("acceptance")[0],
        "recipe_hash": _mint("recipe")[0],
        "build_environment": dict(_ENV),
        "reproducibility_scope": prv.SCOPE_SAME_HOST_CLASS,
        "control": {"signature_threshold": 2, "distinct_keys": 2,
                    "distinct_devices": 2, "distinct_principals": 1,
                    "device_binding": prv.DEVICE_BINDING_ASSERTED},
    }
    doc.update(over)
    _register_evidence(doc)
    return doc


#: Who ran what, and where. Two runs, two hosts of one class — the fixture
#: for `same-host-class`, which is the minimum a release tag stands on.
_RUN_BUILDER, _RUN_VERIFIER = "run-b-2026-09-05", "run-v-2026-09-05"
_HOST_CLASS = "linux-x86_64"


def _evidence_doc(statement, **over):
    """A real `jjdai.rebuild-evidence/v1`, signed by the verifier's key.

    rev 2.3. The fixture used to hand back `canonical(statement)` — the
    PRIMARY statement, offered as proof that the primary statement had been
    independently rebuilt. The audit of recut2 found exactly that and was
    right: the comparison passed because it compared a document with
    itself.
    """
    doc = {
        "schema": prv.SCHEMA_REBUILD_EVIDENCE,
        "statement_hash": rel.statement_hash(statement),
        "build_run_id": _RUN_VERIFIER,
        "key_id": "kv",
        "device_id": "dev-v",
        "principal_id": "p1",
        "host_class": _HOST_CLASS,
        "build_environment": dict(_ENV),
        "tree_digest": statement["tree_digest"],
        "tree_digest_algo": statement["tree_digest_algo"],
        "artefacts": copy.deepcopy(statement["artefacts"]),
        "bundle_hash": statement["bundle_hash"],
        "recipe_hash": statement["recipe_hash"],
    }
    sk = over.pop("_sk", None) or _VERIFIER
    doc.update(over)
    doc["signature"] = sk.sign(rel.evidence_signing_bytes(doc)).hex()
    return doc


def _register_evidence(statement, **over):
    """Mint the evidence object and make it addressable by its hash."""
    from jjdai.canonical import canonical
    from jjdai.crypto import H_hex
    sk = over.pop("_sk", None)
    doc = _evidence_doc(statement, **(dict(over, _sk=sk) if sk else over))
    raw = canonical(doc)
    digest = H_hex(raw)
    _EVIDENCE[digest] = raw
    if not over:
        _EVIDENCE_BY_SH[rel.statement_hash(statement)] = digest
    return digest


def _approval(sk, key_id, role, sh, *, device=None, principal="p1", **over):
    body = {"schema": prv.SCHEMA_RELEASE_APPROVAL,
            "statement_hash": sh, "key_id": key_id,
            "principal_id": principal,
            "device_id": device or ("dev-b" if role == "builder" else "dev-v"),
            "role": role,
            "build_run_id": (_RUN_BUILDER if role == "builder"
                             else _RUN_VERIFIER),
            "host_class": _HOST_CLASS}
    if role == prv.ROLE_VERIFIER:
        # Addressed by statement_hash: an approval names the rebuild of the
        # statement it approves, and nothing else resolves.
        body["verification_evidence_hash"] = _EVIDENCE_BY_SH.get(sh, "9a" * 32)
    body.update(over)
    body["signature"] = sk.sign(rel.approval_signing_bytes(body)).hex()
    return body


def _attestation(statement=None, approvals=None):
    statement = statement or _statement()
    sh = rel.statement_hash(statement)
    if approvals is None:
        approvals = [_approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh),
                     _approval(_VERIFIER, "kv", prv.ROLE_VERIFIER, sh)]
    return {"schema": prv.SCHEMA_RELEASE_ATTESTATION,
            "statement": statement, "statement_hash": sh,
            "approvals": approvals}


_CTX_CACHE = []


def _ctx():
    if not _CTX_CACHE:
        _CTX_CACHE.append(_full_context())
    return _CTX_CACHE[0]


#: Every fixture chain opens with the two keys' activation records — rev
#: 2.4 makes activation a WITNESSED fact, and a key signs nothing before its
#: KEY_ACTIVATED record exists. So the first release of a fixture node sits
#: at index 2, and "nothing was written" means "still exactly two".
ACTIVATIONS = 2
_REVOCATIONS = {}


def _activate(chain, key_id, public_hex):
    return chain.append(prv.KIND_KEY_ACTIVATED,
                        semantic_digest=rel.key_lifecycle_digest(
                            key_id, "activated", public_hex))


def _chain(tmp, *, activate=True):
    chain = wit.WitnessChain(SigningKey.generate(), anchor=wit.LocalAnchor(),
                             log_path=os.path.join(tmp, "w.jsonl"))
    if activate:
        _activate(chain, "kb", _BUILDER.public.hex())
        _activate(chain, "kv", _VERIFIER.public.hex())
    return chain


def _code(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except rel.ReleaseError as exc:
        return exc.code
    except Exception as exc:                                   # noqa: BLE001
        return type(exc).__name__
    return None


def test_statement_has_no_position_and_names_its_algorithm():
    """REL-1"""
    rel.validate_statement(_statement())
    # the defect D5.2 forbids: a position inside the signed body could be
    # pointed back into the validity window of a revoked key
    for field in ("witness_seq", "witness_ref"):
        assert _code(rel.validate_statement,
                     _statement(**{field: 7})) == rel.REL_BAD_SCHEMA
    assert _code(rel.validate_statement,
                 _statement(tree_digest_algo="sha256")) == rel.REL_BAD_SCHEMA
    for field in rel.STATEMENT_FIELDS:
        broken = _statement()
        del broken[field]
        assert _code(rel.validate_statement, broken) == rel.REL_BAD_SCHEMA, \
            field
    # a scope below same-host-class carries no release tag
    assert _code(rel.validate_statement,
                 _statement(reproducibility_scope=prv.SCOPE_SAME_HOST))
    # every control field is present, and `attested` binding is Ф3
    for field in prv.CONTROL_FIELDS:
        broken = _statement()
        del broken["control"][field]
        assert _code(rel.validate_statement, broken) == rel.REL_BAD_SCHEMA
    print("  [PASS] REL-1  statement carries no witness position, names its "
          "digest algorithm, control block complete")


def test_evidence_hash_has_one_shape():
    """REL-2"""
    sh = rel.statement_hash(_statement())
    rel.validate_approval(_approval(_VERIFIER, "kv", prv.ROLE_VERIFIER, sh))
    rel.validate_approval(_approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh))
    bare = _approval(_VERIFIER, "kv", prv.ROLE_VERIFIER, sh)
    del bare["verification_evidence_hash"]
    assert _code(rel.validate_approval, bare) == rel.REL_EVIDENCE_SHAPE
    bare["verification_evidence_hash"] = None
    assert _code(rel.validate_approval, bare) == rel.REL_EVIDENCE_SHAPE
    loaded = _approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh,
                       verification_evidence_hash="9a" * 32)
    assert _code(rel.validate_approval, loaded) == rel.REL_EVIDENCE_SHAPE, (
        "a builder carrying rebuild evidence is how a builder becomes a "
        "verifier without rebuilding anything")
    print("  [PASS] REL-2  verification evidence required for verifier, "
          "forbidden for builder — one shape, not 'absent or null'")


def test_an_approval_names_its_release():
    """REL-3"""
    reg = _registry()
    other = _statement(version="v0.6.10")
    sh_other = rel.statement_hash(other)
    ctx = _ctx()
    # a perfectly valid signature over an approval for ANOTHER release.
    # The attestation still carries THIS statement, so the tag gate agrees
    # and the refusal below is the approval binding and nothing else.
    att = _attestation(approvals=[
        _approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh_other),
        _approval(_VERIFIER, "kv", prv.ROLE_VERIFIER,
                  rel.statement_hash(_statement()))])
    assert _code(rel.verify_attestation, att, registry=reg, context=_ctx(),
                 witness_seq=ACTIVATIONS) == rel.REL_STATEMENT_MISMATCH
    # and the attestation's own recorded hash must match its statement
    att = _attestation()
    att["statement_hash"] = "00" * 32
    assert _code(rel.verify_attestation, att, registry=reg, context=_ctx(),
                 witness_seq=ACTIVATIONS) == rel.REL_STATEMENT_MISMATCH
    print("  [PASS] REL-3  an approval is bound to one statement and cannot "
          "be carried to another")


def test_both_roles_distinct_keys_distinct_devices():
    """REL-4"""
    reg = _registry()
    st = _statement()
    sh = rel.statement_hash(st)
    rel.verify_attestation(_attestation(st), registry=reg, context=_ctx(), witness_seq=ACTIVATIONS)
    # two builders: no signature of the act of verification
    both_builders = _attestation(
        _statement(control=dict(st["control"])),
        [_approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh),
         _approval(_VERIFIER, "kv", prv.ROLE_BUILDER, sh, device="dev-v")])
    assert _code(rel.verify_attestation, both_builders, registry=reg, context=_ctx(),
                 witness_seq=ACTIVATIONS) in (rel.REL_ROLE_MISSING,
                                    rel.REL_ROLE_NOT_PERMITTED)
    # one key signing twice is one signature counted twice
    twice = _attestation(st, [_approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh),
                              _approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh)])
    assert _code(rel.verify_attestation, twice, registry=reg, context=_ctx(),
                 witness_seq=ACTIVATIONS) in (rel.REL_KEY_REUSED, rel.REL_ROLE_MISSING)
    # two keys on ONE machine close nothing that one key on it does not
    reg_same = _registry(same_device=True)
    att = _attestation(st, [_approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh),
                            _approval(_VERIFIER, "kv", prv.ROLE_VERIFIER, sh,
                                      device="dev-b")])
    assert _code(rel.verify_attestation, att, registry=reg_same, context=_ctx(),
                 witness_seq=ACTIVATIONS) == rel.REL_DEVICE_REUSED
    print("  [PASS] REL-4  both roles required; keys and devices pairwise "
          "distinct")


def test_control_numbers_are_counted_not_asserted():
    """REL-5"""
    reg = _registry()
    st = _statement()
    sh = rel.statement_hash(st)
    counted = rel.verify_attestation(_attestation(st), registry=reg, context=_ctx(),
                                     witness_seq=ACTIVATIONS)
    assert counted["distinct_keys"] == 2 and counted["distinct_devices"] == 2
    assert counted["distinct_principals"] == 1
    # the defect D2 exists to prevent: two-key drawn as two-person
    lying = _statement(control=dict(st["control"], distinct_principals=2))
    lying_sh = rel.statement_hash(lying)
    att = _attestation(lying, [
        _approval(_BUILDER, "kb", prv.ROLE_BUILDER, lying_sh),
        _approval(_VERIFIER, "kv", prv.ROLE_VERIFIER, lying_sh)])
    assert _code(rel.verify_attestation, att, registry=reg, context=_ctx(),
                 witness_seq=ACTIVATIONS) == rel.REL_CONTROL_MISMATCH
    # and the registry, not the approval, says who and where
    att = _attestation(st, [
        _approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh, principal="someone"),
        _approval(_VERIFIER, "kv", prv.ROLE_VERIFIER, sh)])
    assert _code(rel.verify_attestation, att, registry=reg, context=_ctx(),
                 witness_seq=ACTIVATIONS) == rel.REL_CONTROL_MISMATCH
    print("  [PASS] REL-5  control numbers derived from the registry; a "
          "recorded number that disagrees refuses")


def test_key_validity_is_judged_at_the_actual_position():
    """REL-6"""
    st = _statement()
    att = _attestation(st)
    # before activation
    assert _code(rel.verify_attestation, att,
                 registry=_registry(builder_active=5), context=_ctx(),
                 witness_seq=ACTIVATIONS) == rel.REL_KEY_NOT_ACTIVE
    # after revocation
    assert _code(rel.verify_attestation, att,
                 registry=_registry(builder_revoked=3), context=_ctx(),
                 witness_seq=7) == rel.REL_KEY_REVOKED
    # a release recorded BEFORE the revocation stays valid: historical
    # attestations are not re-signed, and a key revoked later does not make
    # the whole of its history quietly worthless
    rel.verify_attestation(att, registry=_registry(builder_revoked=9), context=_ctx(),
                           witness_seq=4)
    # a key registered for one role may not act in the other
    sh = rel.statement_hash(st)
    swapped = _attestation(st, [
        _approval(_BUILDER, "kb", prv.ROLE_VERIFIER, sh),
        _approval(_VERIFIER, "kv", prv.ROLE_BUILDER, sh, device="dev-v")])
    assert _code(rel.verify_attestation, swapped, registry=_registry(), context=_ctx(),
                 witness_seq=ACTIVATIONS) == rel.REL_ROLE_NOT_PERMITTED
    print("  [PASS] REL-6  validity read at the record's real position; a "
          "later revocation does not void an earlier release")


def test_witness_ref_is_outside_the_hash_and_resolved():
    """REL-7"""
    reg = _registry()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        att = _attestation()
        before = rel.attestation_hash(att)
        pub = rel.publish(att, chain=chain, registry=reg, context=_ctx())
        # THE property: hashing does not change what was hashed
        assert rel.attestation_hash(pub["attestation"]) == before
        assert "witness_ref" not in pub["attestation"]
        rel.verify_publication(pub, chain=chain, registry=reg, context=_ctx())
        # a swapped reference is caught by resolution, because nothing signs it
        chain.append("INFER", semantic_digest="cd" * 16)
        swapped = copy.deepcopy(pub)
        swapped["witness_ref"] = {"index": len(chain.records) - 1,
                                  "this_hash": chain.records[-1]["this_hash"]}
        assert _code(rel.verify_publication, swapped, chain=chain,
                     registry=reg, context=_ctx()) == rel.REL_WITNESS_UNRESOLVED
        gone = copy.deepcopy(pub)
        gone["witness_ref"] = {"index": 999, "this_hash": "x"}
        assert _code(rel.verify_publication, gone, chain=chain,
                     registry=reg, context=_ctx()) == rel.REL_WITNESS_UNRESOLVED
        wrong_hash = copy.deepcopy(pub)
        wrong_hash["witness_ref"]["this_hash"] = "00" * 32
        assert _code(rel.verify_publication, wrong_hash, chain=chain,
                     registry=reg, context=_ctx()) == rel.REL_WITNESS_UNRESOLVED
        # THE case the second guard exists for, and the only one that proves
        # it: TWO real releases in one chain, and the reference carried from
        # one to the other WITH the pre-image that record actually committed
        # to. The hash check passes here — the pre-image is genuine — so if
        # the attestation is not compared with it, the swap goes through.
        # a genuinely different release: its own context, because the tag
        # and tree gates now compare against real facts
        second = _statement(version="v0.6.10", tree_digest="99" * 32)
        ctx2 = _full_context(second)
        sh2 = rel.statement_hash(second)
        att2 = _attestation(second, [
            _approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh2),
            _approval(_VERIFIER, "kv", prv.ROLE_VERIFIER, sh2)])
        pub2 = rel.publish(att2, chain=chain, registry=reg, context=ctx2)
        carried = copy.deepcopy(pub)
        carried["witness_ref"] = copy.deepcopy(pub2["witness_ref"])
        assert _code(rel.verify_publication, carried, chain=chain,
                     registry=reg, context=_ctx()) == rel.REL_WITNESS_UNRESOLVED, (
            "a publication pointed at ANOTHER release's record, carrying "
            "that record's genuine pre-image, was accepted")
    print("  [PASS] REL-7  the hashed object stops growing; a swapped "
          "witness_ref is caught by resolution")


def test_an_unfinished_release_never_reaches_the_chain():
    """REL-8"""
    reg = _registry()
    st = _statement()
    sh = rel.statement_hash(st)
    broken = [
        ("one role only", _attestation(
            st, [_approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh)])),
        ("verifier with no evidence", None),
        ("unknown key", _attestation(st, [
            _approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh),
            _approval(_VERIFIER, "ghost", prv.ROLE_VERIFIER, sh)])),
    ]
    bare = _approval(_VERIFIER, "kv", prv.ROLE_VERIFIER, sh)
    del bare["verification_evidence_hash"]
    broken[1] = ("verifier with no evidence", _attestation(
        st, [_approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh), bare]))
    for label, att in broken:
        with tempfile.TemporaryDirectory() as tmp:
            chain = _chain(tmp)
            assert _code(rel.publish, att, chain=chain, registry=reg, context=_ctx()), label
            assert len(chain.records) == ACTIVATIONS, (
                f"{label}: an unfinished release reached the chain. Because "
                f"it cannot, no TTL and no revocation are needed for a "
                f"device that died before the second signature")
    print("  [PASS] REL-8  three unfinished releases refused with an empty "
          "chain behind them")


def test_registry_refuses_what_would_make_the_count_a_fiction():
    """REL-9"""
    base = {"schema": rel.REGISTRY_SCHEMA, "lifecycle_binding": rel.LIFECYCLE_WITNESSED, "keys": [
        {"key_id": "k1", "public": "aa" * 32, "device_id": "d1",
         "principal_id": "p1", "roles": ["builder"],
         "activated_at_witness_seq": 0, "physical_host": "box-1",
         "physical_host_assertion": "op-1"},
        {"key_id": "k2", "public": "bb" * 32, "device_id": "d2",
         "principal_id": "p2", "roles": ["verifier"],
         "activated_at_witness_seq": 0, "physical_host": "box-1",
         "physical_host_assertion": "op-1"}]}
    assert _code(rel.load_registry, base) == rel.REL_DEVICE_SHARED_HOST, (
        "two VMs on one box are ONE device; registering them separately "
        "makes distinct_devices read as two while being one")
    twice = copy.deepcopy(base)
    twice["keys"][1]["physical_host"] = "box-2"
    twice["keys"][1]["key_id"] = "k1"
    assert _code(rel.load_registry, twice) == rel.REL_REGISTRY_INVALID
    incomplete = copy.deepcopy(base)
    incomplete["keys"] = [dict(base["keys"][0])]
    del incomplete["keys"][0]["principal_id"]
    assert _code(rel.load_registry, incomplete) == rel.REL_REGISTRY_INVALID
    bad_role = copy.deepcopy(base)
    bad_role["keys"] = [dict(base["keys"][0], roles=["publisher"])]
    assert _code(rel.load_registry, bad_role) == rel.REL_REGISTRY_INVALID
    assert _code(rel.load_registry, {"schema": "other"}) == \
        rel.REL_REGISTRY_INVALID
    print("  [PASS] REL-9  registry refuses a shared host, a duplicate key, "
          "an incomplete entry and an unknown role")


def test_shipped_registry_is_valid_and_empty():
    """REL-10"""
    path = os.path.join(_ROOT, rel.REGISTRY_FILE)
    keys = rel.load_registry(path)
    assert keys == {}, (
        "this tree ships no release keys: two keys on two physical devices "
        "are a Ф0 gate item and a ceremony, not something a build produces")
    doc = json.load(_io.open(path, encoding="utf-8"))
    assert doc["schema"] == rel.REGISTRY_SCHEMA
    assert "note" in doc and "ceremony" in doc["note"]
    # with an empty registry nothing can be attested — the honest state
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        assert _code(rel.publish, _attestation(), chain=chain,
                     registry=keys, context=_ctx()) == rel.REL_UNKNOWN_KEY
        assert len(chain.records) == ACTIVATIONS
    print("  [PASS] REL-10  the shipped registry is valid and empty; no "
          "release can be attested until the ceremony is held")




def test_strict_schema_and_external_facts():
    """REL-11"""
    reg = _registry()
    # digest-shaped holes: the first cut asked only that these be non-empty
    for field in rel.STATEMENT_HEX_FIELDS:
        assert _code(rel.validate_statement,
                     _statement(**{field: "x"})) == rel.REL_BAD_SCHEMA, field
    assert _code(rel.validate_statement,
                 _statement(artefacts=["not-an-artefact"])) == \
        rel.REL_BAD_SCHEMA
    assert _code(rel.validate_statement,
                 _statement(build_environment={"anything": True})) == \
        rel.REL_BAD_SCHEMA
    # a counter that renders as two and compares as neither
    lying = _statement(control={"signature_threshold": "2",
                                "distinct_keys": "2", "distinct_devices": "2",
                                "distinct_principals": "1",
                                "device_binding": prv.DEVICE_BINDING_ASSERTED})
    assert _code(rel.validate_statement, lying) == rel.REL_BAD_SCHEMA

    # a context is REQUIRED: the weaker check must be asked for by name
    att = _attestation()
    assert _code(rel.verify_attestation, att, registry=reg, witness_seq=ACTIVATIONS,
                 context=None) == rel.REL_BAD_SCHEMA

    st = _statement()
    ok_ctx = _full_context(st)
    rel.verify_attestation(_attestation(st), registry=reg, witness_seq=ACTIVATIONS,
                           context=ok_ctx)
    assert _code(rel.verify_attestation, _attestation(st), registry=reg,
                 witness_seq=ACTIVATIONS,
                 context=ok_ctx._replace(expected_tag="v0.6.10")) == \
        rel.REL_TAG_MISMATCH
    assert _code(rel.verify_attestation, _attestation(st), registry=reg,
                 witness_seq=ACTIVATIONS,
                 context=ok_ctx._replace(tree_digest="99" * 32)) == \
        rel.REL_TREE_MISMATCH
    # a hash pointing at a RED run is a hash of a red run
    green = ok_ctx.acceptance
    red = dict(green, passed=254, total=255)
    assert _code(rel.verify_attestation, _attestation(st), registry=reg,
                 witness_seq=ACTIVATIONS, context=ok_ctx._replace(acceptance=red)) == \
        rel.REL_ACCEPTANCE_INVALID
    green_other_tree = dict(green, tree_digest="77" * 32)
    assert _code(rel.verify_attestation, _attestation(st), registry=reg,
                 witness_seq=ACTIVATIONS,
                 context=ok_ctx._replace(acceptance=green_other_tree)) == \
        rel.REL_ACCEPTANCE_INVALID
    # artefact bytes must be the bytes
    # and the shapes the audit walked straight through
    for broken in (dict(green, import_errors=1),
                   dict(green, schema="other"),
                   dict(green, suite="live"),
                   {k: v for k, v in green.items() if k != "tree_digest"},
                   {k: v for k, v in green.items()
                    if k != "tree_digest_algo"}):
        assert _code(rel.verify_attestation, _attestation(st), registry=reg,
                     witness_seq=ACTIVATIONS,
                     context=ok_ctx._replace(acceptance=broken)) == \
            rel.REL_ACCEPTANCE_INVALID, broken
    # NOT rejected, and deliberately: a 1/1 run with no import errors
    # against this tree IS green. A floor on the count would be a magic
    # number, and the audit's object failed on `import_errors`, not on size.
    rel.verify_attestation(_attestation(st), registry=reg, witness_seq=ACTIVATIONS,
                           context=ok_ctx._replace(
                               acceptance=dict(green, passed=1, total=1)))
    # the environment table must be whole AND agree with what was measured
    holed_env = {k: v for k, v in _ENV.items() if k != "source_date_epoch"}
    holed = _statement(build_environment=holed_env)
    assert _code(rel.validate_statement, holed) is None
    # The refusal must be the HOLE and not the disagreement that follows
    # from it: measured against the same incomplete table the comparison
    # finds no drift, so a check that accepts either message would survive
    # deleting the completeness rule. Asserted by wording.
    try:
        rel.verify_attestation(
            _attestation(holed), registry=reg, witness_seq=ACTIVATIONS,
            context=_full_context(holed)._replace(
                build_environment=dict(holed_env)))
        raise AssertionError("a build_environment with a hole was accepted")
    except rel.ReleaseError as exc:
        assert exc.code == rel.REL_ENVIRONMENT_MISMATCH
        assert "omits" in str(exc) and "source_date_epoch" in str(exc), (
            f"refused for the wrong reason: {exc}")
    assert _code(rel.verify_attestation, _attestation(st), registry=reg,
                 witness_seq=ACTIVATIONS,
                 context=ok_ctx._replace(
                     build_environment=dict(_ENV, locale="en_US.UTF-8"))) == \
        rel.REL_ENVIRONMENT_MISMATCH
    # a length that does not match the bytes, beside a correct digest
    art = st["artefacts"][0]
    assert _code(rel.verify_attestation,
                 _attestation(_statement(artefacts=[dict(art,
                                                         length=999999)])),
                 registry=reg, witness_seq=ACTIVATIONS,
                 context=ok_ctx) == rel.REL_ARTEFACT_MISMATCH
    # and evidence named by a token rather than a digest
    sh = rel.statement_hash(st)
    assert _code(rel.verify_attestation, _attestation(st, [
        _approval(_BUILDER, "kb", prv.ROLE_BUILDER, sh),
        _approval(_VERIFIER, "kv", prv.ROLE_VERIFIER, sh,
                  verification_evidence_hash="x")]),
                 registry=reg, witness_seq=ACTIVATIONS,
                 context=ok_ctx) == rel.REL_BAD_SCHEMA
    bad_bytes = ok_ctx._replace(artefact_reader=lambda name: b"other")
    assert _code(rel.verify_attestation, _attestation(st), registry=reg,
                 witness_seq=ACTIVATIONS, context=bad_bytes) == rel.REL_ARTEFACT_MISMATCH
    print("  [PASS] REL-11 strict schema; tag, tree, acceptance and artefact "
          "bytes are checked against facts outside the statement")


def test_publication_requires_an_intact_chain():
    """REL-12"""
    reg = _registry()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        pub = rel.publish(_attestation(), chain=chain, registry=reg,
                          context=_ctx())
        rel.verify_publication(pub, chain=chain, registry=reg, context=_ctx())
        # the audit's probe: edit a signed field after publication
        chain.records[0]["timestamp"] = "2000-01-01T00:00:00Z"
        assert chain.verify_chain() is False
        assert _code(rel.verify_publication, pub, chain=chain, registry=reg,
                     context=_ctx()) == rel.REL_WITNESS_UNRESOLVED, (
            "a reference into an edited chain resolved as valid; "
            "integrity-valid means the CHAIN verifies, not that one field "
            "matches a value taken from the object being checked")
    print("  [PASS] REL-12 a publication into an edited chain refuses; the "
          "chain is verified cryptographically, not by one hash compare")


def test_publish_is_atomic_against_a_concurrent_append():
    """REL-13"""
    reg = _registry(builder_active=0)
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        seen = {}
        real_verify = rel.verify_attestation

        def racing(att, *, registry, witness_seq, context):
            # A concurrent writer lands between reading the position and the
            # append. `WitnessChain.lock` is an RLock, so a same-thread
            # writer gets through the hold — which is exactly the shape the
            # audit used.
            seen["verified_for"] = witness_seq
            if "raced" not in seen:
                seen["raced"] = True
                chain.append("INFER", semantic_digest="cd" * 16)
            return real_verify(att, registry=registry,
                               witness_seq=witness_seq, context=context)

        rel.verify_attestation = racing
        try:
            code = _code(rel.publish, _attestation(), chain=chain,
                         registry=reg, context=_ctx())
        finally:
            rel.verify_attestation = real_verify
        assert code == rel.REL_WITNESS_UNRESOLVED, (
            f"publish accepted a record at an index other than the one it "
            f"verified for (verified for {seen.get('verified_for')})")
        # THE assertion this check was missing, and the reason it was green
        # for the wrong reason: the error code alone says the function
        # RETURNED a refusal, not that nothing was written. An append-only
        # store has no undo, so "abandoned" after the record lands is a word
        # about a record that exists forever.
        kinds = [r["kind"] for r in chain.records]
        assert prv.KIND_RELEASE_ATTESTED not in kinds, (
            f"the refusal was reported and the release record persisted "
            f"anyway: {kinds}")
        # and the chain is still sound after the refusal
        assert chain.verify_chain() is True
        assert [r["index"] for r in chain.records] == \
            list(range(len(chain.records)))
    # the same property under REAL threads, which is where the defect lived:
    # `append` never took the lock it was documented to hold, so two writers
    # both took index 0 and the chain failed to verify.
    import threading
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        errors = []

        def writer(n):
            try:
                chain.append("INFER", semantic_digest=("%02x" % n) * 16)
            except Exception as exc:                           # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,))
                   for i in range(12)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert not errors, errors
        assert [r["index"] for r in chain.records] == \
            list(range(ACTIVATIONS + 12)), (
            "two writers took one index: the lock is documented as guarding "
            "append and must actually be held across next_index, signing, "
            "persist and the in-memory append")
        assert chain.verify_chain() is True
    print("  [PASS] REL-13 verify and append are one atomic step, nothing "
          "is written on refusal, and concurrent appends keep the chain "
          "sound")


def test_registry_requires_physical_binding_and_one_key_per_public():
    """REL-14"""
    entry = {"key_id": "k1", "public": "aa" * 32, "device_id": "d1",
             "principal_id": "p1", "roles": ["builder"],
             "activated_at_witness_seq": 0}
    # neither hardware binding nor an asserted host: the rule used to hold
    # only where an operator had bothered to fill the field in
    assert _code(rel.load_registry,
                 {"schema": rel.REGISTRY_SCHEMA, "lifecycle_binding": rel.LIFECYCLE_WITNESSED, "keys": [dict(entry)]}) == \
        rel.REL_REGISTRY_INVALID
    assert _code(rel.load_registry, {"schema": rel.REGISTRY_SCHEMA, "lifecycle_binding": rel.LIFECYCLE_WITNESSED, "keys": [
        dict(entry, physical_host="box-1")]}) == rel.REL_REGISTRY_INVALID
    rel.load_registry({"schema": rel.REGISTRY_SCHEMA, "lifecycle_binding": rel.LIFECYCLE_WITNESSED, "keys": [
        dict(entry, physical_host="box-1", physical_host_assertion="op-1")]})
    rel.load_registry({"schema": rel.REGISTRY_SCHEMA, "lifecycle_binding": rel.LIFECYCLE_WITNESSED, "keys": [
        dict(entry, hardware_binding="tpm-quote-1")]})
    # two ids over one key are one key wearing two names
    twins = {"schema": rel.REGISTRY_SCHEMA, "lifecycle_binding": rel.LIFECYCLE_WITNESSED, "keys": [
        dict(entry, physical_host="b1", physical_host_assertion="op"),
        dict(entry, key_id="k2", device_id="d2", physical_host="b2",
             physical_host_assertion="op", roles=["verifier"])]}
    assert _code(rel.load_registry, twins) == rel.REL_REGISTRY_INVALID
    print("  [PASS] REL-14 a key without a physical binding is not "
          "registered; one public key holds one id")


def test_an_incomplete_context_cannot_publish_or_tag():
    """REL-15"""
    reg = _registry()
    bare = rel.ReleaseContext.internal_only()
    assert len(bare.missing()) == len(rel.ReleaseContext._fields)
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        assert _code(rel.publish, _attestation(), chain=chain, registry=reg,
                     context=bare) == rel.REL_CONTEXT_INCOMPLETE
        assert len(chain.records) == ACTIVATIONS, (
            "a release was written with no tag, tree, acceptance, bundle, "
            "recipe, SBOM, manifest or artefact ever compared")
        # one absent reader is enough: each is a gate that silently passes
        for field in rel.ReleaseContext._fields:
            holed = _ctx()._replace(**{field: None})
            assert _code(rel.publish, _attestation(), chain=chain,
                         registry=reg,
                         context=holed) == rel.REL_CONTEXT_INCOMPLETE, field
        assert len(chain.records) == ACTIVATIONS
        pub = rel.publish(_attestation(), chain=chain, registry=reg,
                          context=_ctx())
        assert _code(rel.check_release_tag, "v0.6.9", pub, chain=chain,
                     registry=reg,
                     context=bare) == rel.REL_CONTEXT_INCOMPLETE
    print("  [PASS] REL-15 an incomplete context publishes nothing and tags "
          "nothing")


def test_key_lifecycle_positions_resolve_in_the_chain():
    """REL-16 · third version, ADR-022 rev 2.4

    The first version appended six INFER records and accepted one of them
    as a key activation, under a docstring promising to read the record's
    pre-image. The second said honestly what it could prove — a position
    not past the end of the chain — because KEY_ACTIVATED did not exist and
    a build does not reopen a frozen reserve. rev 2.4 reopened it before
    first emission. This version checks what the first one claimed.
    """
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)            # KEY_ACTIVATED kb @0, kv @1
        rel.check_lifecycle_witnessed(_registry(), chain=chain)

        # 1. THE ORIGINAL FALSE GREEN, replayed against the real check: six
        #    INFER records, a registry pointing activation at one of them
        for _ in range(6):
            chain.append("INFER", semantic_digest="ab" * 16)
        assert _code(rel.check_lifecycle_witnessed,
                     _registry(builder_active=5),
                     chain=chain) == rel.REL_LIFECYCLE_UNWITNESSED
        # 2. a position past the end, and a position at nothing
        assert _code(rel.check_lifecycle_witnessed,
                     _registry(builder_revoked=99),
                     chain=chain) == rel.REL_LIFECYCLE_UNWITNESSED
        # 3. the RIGHT kind naming the WRONG key: kv's activation record
        #    offered as kb's. A lifecycle record witnesses one key's one
        #    transition, and the digest names both.
        assert _code(rel.check_lifecycle_witnessed,
                     _registry(builder_active=1),
                     chain=chain) == rel.REL_LIFECYCLE_UNWITNESSED
        # 4. the right key, the wrong transition: an activation record where
        #    the registry claims a revocation
        assert _code(rel.check_lifecycle_witnessed,
                     _registry(builder_revoked=0),
                     chain=chain) == rel.REL_LIFECYCLE_UNWITNESSED
        # 4b. the RIGHT digest on the WRONG kind: an INFER record carrying
        #     exactly kb's activation digest. The digest names the key; the
        #     kind says what happened to it, and a record that is not a
        #     lifecycle record witnesses no lifecycle whatever it hashes
        chain.append("INFER", semantic_digest=rel.key_lifecycle_digest(
            "kb", "activated", _BUILDER.public.hex()))
        assert _code(rel.check_lifecycle_witnessed,
                     _registry(builder_active=len(chain.records) - 1),
                     chain=chain) == rel.REL_LIFECYCLE_UNWITNESSED
        # 5. a real revocation resolves — and then the key is dead at and
        #    after it, so a publication at a later position refuses
        chain.append(prv.KIND_KEY_REVOKED,
                     semantic_digest=rel.key_lifecycle_digest(
                         "kb", "revoked", _BUILDER.public.hex()))
        revoked_at = len(chain.records) - 1
        rel.check_lifecycle_witnessed(_registry(builder_revoked=revoked_at),
                                      chain=chain)
        assert _code(rel.publish, _attestation(), chain=chain,
                     registry=_registry(builder_revoked=revoked_at),
                     context=_ctx()) == rel.REL_KEY_REVOKED
        # 6. COMPLETENESS. The audit of recut6 wrote that same KEY_REVOKED
        #    and handed the check a registry still saying revoked=None —
        #    and it passed, because it verified only the positions the
        #    registry chose to present. A registry does not get to forget
        #    a transition the chain remembers.
        assert _code(rel.check_lifecycle_witnessed, _registry(),
                     chain=chain) == rel.REL_LIFECYCLE_HIDDEN
        assert _code(rel.publish, _attestation(), chain=chain,
                     registry=_registry(), context=_ctx()) == \
            rel.REL_LIFECYCLE_HIDDEN
        # nor present a LATER transition in place of the first
        chain.append(prv.KIND_KEY_REVOKED,
                     semantic_digest=rel.key_lifecycle_digest(
                         "kb", "revoked", _BUILDER.public.hex()))
        assert _code(rel.check_lifecycle_witnessed,
                     _registry(builder_revoked=revoked_at + 1),
                     chain=chain) == rel.REL_LIFECYCLE_HIDDEN
        assert rel.lifecycle_projection(chain, _registry()["kb"]) == \
            {"activated": [0], "revoked": [revoked_at, revoked_at + 1]}

    # AND A RELEASE BEFORE THE REVOCATION STAYS VALID: history is not
    # re-signed, the key acts from activation up to its revocation position
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        st = _statement()
        early = rel.publish(_attestation(st), chain=chain,
                            registry=_registry(), context=_full_context(st))
        chain.append(prv.KIND_KEY_REVOKED,
                     semantic_digest=rel.key_lifecycle_digest(
                         "kb", "revoked", _BUILDER.public.hex()))
        after = len(chain.records) - 1
        rel.verify_publication(early, chain=chain,
                               registry=_registry(builder_revoked=after),
                               context=_full_context(st))
        assert _code(rel.publish, _attestation(), chain=chain,
                     registry=_registry(builder_revoked=after),
                     context=_ctx()) == rel.REL_KEY_REVOKED

    # THE RECORD KIND IS A BINDING. A bare KEY_ACTIVATED with no digest is a
    # position with nothing at it, and the chain refuses to write one.
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp, activate=False)
        try:
            chain.append(prv.KIND_KEY_ACTIVATED)
            raise AssertionError("a bare lifecycle record was written")
        except ValueError as e:
            assert "semantic_digest" in str(e)
        # and "64-hex" means the ALPHABET, not the length: `"z" * 64` was a
        # digest to the first cut of the guard
        try:
            chain.append(prv.KIND_KEY_ACTIVATED, semantic_digest="z" * 64)
            raise AssertionError("a non-hex lifecycle digest was written")
        except ValueError as e:
            assert "semantic_digest" in str(e)
        assert len(chain.records) == 0
        # and position 0 on an empty chain is no longer a convention:
        # activation is witnessed BEFORE the key signs anything
        assert _code(rel.check_lifecycle_witnessed, _registry(),
                     chain=chain) == rel.REL_LIFECYCLE_UNWITNESSED

    # THE CLAIM IS NOW REQUIRED, not merely permitted: a registry that says
    # `asserted` where it could be checked is refused, and the shipped one
    # says `witnessed`
    assert _code(rel.load_registry,
                 {"schema": rel.REGISTRY_SCHEMA, "lifecycle_binding": rel.LIFECYCLE_WITNESSED, "keys": [],
                  "lifecycle_binding": rel.LIFECYCLE_ASSERTED}) == \
        rel.REL_LIFECYCLE_BINDING
    shipped = json.load(_io.open(os.path.join(_ROOT, "docs",
                                              "release_keys.json"),
                                 encoding="utf-8"))
    assert shipped["lifecycle_binding"] == rel.LIFECYCLE_WITNESSED
    # the kinds are in the vocabulary — the line REL-16 v2 kept as a signal
    # for exactly this moment
    assert prv.KIND_KEY_ACTIVATED in wit.KINDS
    assert prv.KIND_KEY_REVOKED in wit.KINDS
    assert prv.KIND_KEY_ACTIVATED not in wit.RESERVED_KINDS
    # and the debt is CLOSED in the ledger, by an event with a reference
    status = json.load(_io.open(os.path.join(_ROOT, "docs",
                                             "architecture_status.json"),
                                encoding="utf-8"))
    assert rel.LIFECYCLE_DEBT not in prv.open_debt(status)
    print("  [PASS] REL-16 a lifecycle position resolves to a KEY_ACTIVATED "
          "or KEY_REVOKED record naming this key and this transition")


def test_a_release_is_revoked_by_name():
    """REL-23 · ADR-022 D6, closed by rev 2.4

    Where the moment of a key's compromise is unknown, voiding the key's
    whole history would take down releases that were sound. The release is
    named instead, forward: a signed RevocationStatement, then a
    RELEASE_REVOKED record binding the release by statement hash. The
    attestation stays intact and the record stays where it was; what changes
    is a later, signed fact about it. An earlier cut of this tree carried a
    `release_is_revoked` that read a field nothing writes; it was removed
    and owed, and this is the debt paid.
    """
    reg = _registry()
    st = _statement()
    from jjdai.canonical import canonical
    from jjdai.crypto import H_hex
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        ctx = _full_context(st)
        pub = rel.publish(_attestation(st), chain=chain, registry=reg,
                          context=ctx)
        rel.verify_publication(pub, chain=chain, registry=reg, context=ctx)
        sh = rel.statement_hash(st)

        # an unregistered key cannot revoke; nothing is written
        before = len(chain.records)
        assert _code(rel.revoke_release, sh, key_id="nobody", reason="x",
                     signing_key=_BUILDER, chain=chain,
                     registry=reg) == rel.REL_UNKNOWN_KEY
        assert len(chain.records) == before

        # a body signed by the WRONG private key under a registered key_id
        # is refused BEFORE the append — the audit of recut6 passed the
        # verifier's key with key_id="kb" and an invalid revocation stood
        # in the append-only chain forever, blocking the release
        before = len(chain.records)
        assert _code(rel.revoke_release, sh, key_id="kb", reason="x",
                     signing_key=_VERIFIER, chain=chain,
                     registry=reg) == rel.REL_BAD_SIGNATURE
        assert len(chain.records) == before, "nothing is written on refusal"

        # the release-signing authority revokes, by name
        body = rel.revoke_release(sh, key_id="kb", reason="compromise "
                                  "window unknown; this release only",
                                  signing_key=_BUILDER, chain=chain,
                                  registry=reg)
        _REVOCATIONS[H_hex(canonical(body))] = canonical(body)
        assert chain.records[-1]["kind"] == prv.KIND_RELEASE_REVOKED
        assert chain.records[-1]["semantic_digest"] == \
            rel.revocation_digest(sh)

        # 1. the publication now verifies as REVOKED, on both paths
        assert _code(rel.verify_publication, pub, chain=chain, registry=reg,
                     context=ctx) == rel.REL_REVOKED
        assert _code(rel.check_release_tag, "v0.6.9", pub, chain=chain,
                     registry=reg, context=ctx) == rel.REL_REVOKED
        assert _code(rel.toolset_authorizer, pub, chain=chain, registry=reg,
                     context=ctx) == rel.REL_REVOKED
        # 2. the attestation itself is untouched — revocation is an event
        #    after the fact, not an edit of it
        rel.verify_attestation(pub["attestation"], registry=reg,
                               context=ctx, witness_seq=pub["witness_ref"]
                               ["index"])
        # 3. a revocation whose body cannot be read is NOT thereby lifted
        assert _code(rel.verify_publication, pub, chain=chain, registry=reg,
                     context=ctx._replace(revocation_reader=None)) == \
            rel.REL_REVOKED_UNRESOLVED
        assert _code(rel.verify_publication, pub, chain=chain, registry=reg,
                     context=ctx._replace(
                         revocation_reader=lambda h: b"{}")) == \
            rel.REL_REVOKED_UNRESOLVED
        # 4. a forged body under the right hash does not verify: the
        #    signature is over the domain, by the registered key
        forged = dict(body, reason="lifted")
        forged["signature"] = _VERIFIER.sign(
            rel.revocation_signing_bytes(forged)).hex()
        assert _code(rel.verify_publication, pub, chain=chain, registry=reg,
                     context=ctx._replace(
                         revocation_reader=lambda h: canonical(forged))) == \
            rel.REL_REVOKED_UNRESOLVED
        # 5. another release on the same chain is unaffected — the
        #    revocation names ONE statement
        other = _statement(version="v0.6.9+1")
        opub = rel.publish(_attestation(other), chain=chain, registry=reg,
                           context=_full_context(other))
        # 6. a record whose body binds correctly but is signed by a key
        #    other than the one it names is not a revocation: written past
        #    revoke_release() straight into the chain, it must still refuse
        #    — and refuse as UNRESOLVED, never lift
        osh = rel.statement_hash(other)
        rogue = {"schema": prv.SCHEMA_RELEASE_REVOCATION,
                 "statement_hash": osh, "key_id": "kb", "reason": "rogue"}
        rogue["signature"] = _VERIFIER.sign(
            rel.revocation_signing_bytes(rogue)).hex()
        chain.append(prv.KIND_RELEASE_REVOKED, provenance=rogue,
                     semantic_digest=rel.revocation_digest(osh))
        _REVOCATIONS[H_hex(canonical(rogue))] = canonical(rogue)
        assert _code(rel.verify_publication, opub, chain=chain,
                     registry=reg, context=_full_context(other)) == \
            rel.REL_REVOKED_UNRESOLVED
        # 7. THREE VALUES, ONE RELEASE. A properly signed revocation of
        #    release B, bound under a record whose digest names release A:
        #    the audit of recut6 had A verify as revoked on B's signature.
        third = _statement(version="v0.6.9+2")
        tpub = rel.publish(_attestation(third), chain=chain, registry=reg,
                           context=_full_context(third))
        tsh = rel.statement_hash(third)
        of_b = {"schema": prv.SCHEMA_RELEASE_REVOCATION,
                "statement_hash": "bb" * 32, "key_id": "kb",
                "reason": "a different release entirely"}
        of_b["signature"] = _BUILDER.sign(
            rel.revocation_signing_bytes(of_b)).hex()
        chain.append(prv.KIND_RELEASE_REVOKED, provenance=of_b,
                     semantic_digest=rel.revocation_digest(tsh))
        _REVOCATIONS[H_hex(canonical(of_b))] = canonical(of_b)
        assert _code(rel.verify_publication, tpub, chain=chain,
                     registry=reg, context=_full_context(third)) == \
            rel.REL_REVOKED_UNRESOLVED
    # the debt is closed in the ledger, and the placeholder that stood for
    # it in code is gone
    assert not hasattr(rel, "RELEASE_REVOKED_OWED")
    status = json.load(_io.open(os.path.join(_ROOT, "docs",
                                             "architecture_status.json"),
                                encoding="utf-8"))
    assert "release-revocation-by-name" not in prv.open_debt(status)
    print("  [PASS] REL-23 a release is revoked by name with a signed "
          "statement and a witness record; the attestation stays intact")


def test_rebuild_evidence_resolves_to_this_build():
    """REL-17

    `verification_evidence_hash` was checked for SHAPE and nothing else, so
    the audit published a release whose verifier named `9a9a…9a` — an
    address with no object behind it. What that proved was that a verifier
    had signed a hash-shaped string; what it must prove is that an
    independent rebuild EXISTS and produced this build.
    """
    reg = _registry()
    honest = _statement()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        rel.publish(_attestation(honest), chain=chain, registry=reg,
                    context=_full_context(honest))

    # 1. an address with nothing behind it
    st = _statement()
    sh = rel.statement_hash(st)
    named_nothing = _attestation(st, [
        _approval(_BUILDER, "kb", "builder", sh),
        _approval(_VERIFIER, "kv", "verifier", sh,
                  verification_evidence_hash="9a" * 32)])
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        assert _code(rel.publish, named_nothing, chain=chain, registry=reg,
                     context=_full_context(st)) == rel.REL_EVIDENCE_UNRESOLVED
        assert len(chain.records) == ACTIVATIONS

    # 2. bytes that are not the bytes the approval names
    from jjdai.crypto import H_hex
    st = _statement()
    sh = rel.statement_hash(st)
    lying = _attestation(st, [
        _approval(_BUILDER, "kb", "builder", sh),
        _approval(_VERIFIER, "kv", "verifier", sh,
                  verification_evidence_hash="7c" * 32)])
    ctx = _full_context(st)
    ctx = ctx._replace(evidence_reader=lambda d: b"some other object")
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        assert _code(rel.publish, lying, chain=chain, registry=reg,
                     context=ctx) == rel.REL_EVIDENCE_UNRESOLVED

    # 3. evidence that resolves and is not a release statement
    st = _statement()
    sh = rel.statement_hash(st)
    raw = b"a note saying the rebuild went fine"
    _EVIDENCE[H_hex(raw)] = raw
    prose = _attestation(st, [
        _approval(_BUILDER, "kb", "builder", sh),
        _approval(_VERIFIER, "kv", "verifier", sh,
                  verification_evidence_hash=H_hex(raw))])
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        assert _code(rel.publish, prose, chain=chain, registry=reg,
                     context=_full_context(st)) == rel.REL_EVIDENCE_DIVERGENT

    # 4. THE ONE THE WHOLE CONSTRUCTION EXISTS FOR: a rebuild that resolves,
    #    verifies, was somebody else's act — and produced a different
    #    artefact. Two runs of one recipe over one tree that disagree are
    #    the finding, not a detail.
    st = _statement()
    sh = rel.statement_hash(st)
    digest = _register_evidence(st, bundle_hash=_mint("other-bundle")[0])
    att = _attestation(st, [
        _approval(_BUILDER, "kb", "builder", sh),
        _approval(_VERIFIER, "kv", "verifier", sh,
                  verification_evidence_hash=digest)])
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        assert _code(rel.publish, att, chain=chain, registry=reg,
                     context=_full_context(st)) == rel.REL_EVIDENCE_DIVERGENT

    # the reader is a required fact, not an optional one: absent, publishing
    # refuses on the context rather than skipping the gate
    holed = _full_context(honest)._replace(evidence_reader=None)
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        assert _code(rel.publish, _attestation(honest), chain=chain,
                     registry=reg,
                     context=holed) == rel.REL_CONTEXT_INCOMPLETE
    print("  [PASS] REL-17 named rebuild evidence must resolve, validate "
          "and agree with the build it approves")


def test_rebuild_evidence_is_somebody_elses_act():
    """REL-20 · ADR-022 rev 2.3

    The defect this closes was mine. recut2 required the evidence to
    resolve and to be a `ReleaseStatement` agreeing with this one, and the
    audit handed it THE PRIMARY STATEMENT: identical to itself in every
    compared field, so the comparison passed trivially. Resolvability had
    been proved and independence had not — the same substitution this drop
    keeps finding, committed by the fix for the previous round of it.

    rev 2.3 gives the rebuild its own schema and its own signature, so the
    object cannot be the statement, cannot be signed by the builder, and
    cannot describe the run the builder already approved.
    """
    reg = _registry()
    from jjdai.canonical import canonical
    from jjdai.crypto import H_hex

    def _publish_with(evidence_digest, statement):
        sh = rel.statement_hash(statement)
        att = _attestation(statement, [
            _approval(_BUILDER, "kb", "builder", sh),
            _approval(_VERIFIER, "kv", "verifier", sh,
                      verification_evidence_hash=evidence_digest)])
        with tempfile.TemporaryDirectory() as tmp:
            chain = _chain(tmp)
            return _code(rel.publish, att, chain=chain, registry=reg,
                         context=_full_context(statement))

    # 1. THE AUDIT'S OWN PROBE: the release statement offered as evidence
    #    about itself. A `ReleaseStatement` cannot declare the rebuild
    #    schema, so this is refused by construction rather than by a
    #    comparison that happens to notice.
    st = _statement()
    raw = canonical(st)
    _EVIDENCE[H_hex(raw)] = raw
    assert _publish_with(H_hex(raw), st) == rel.REL_EVIDENCE_NOT_INDEPENDENT

    # 2. signed by the BUILDER: one principal performing both roles under
    #    two names, which is what the two-key control exists to prevent
    st = _statement()
    digest = _register_evidence(st, _sk=_BUILDER)
    assert _publish_with(digest, st) == rel.REL_BAD_SIGNATURE
    st = _statement()
    digest = _register_evidence(st, key_id="kb", device_id="dev-b",
                                _sk=_BUILDER)
    assert _publish_with(digest, st) == rel.REL_EVIDENCE_NOT_INDEPENDENT

    # 3. the SAME RUN the builder approved. Two signatures over one build
    #    are one build, whatever the key count says.
    st = _statement()
    digest = _register_evidence(st, build_run_id=_RUN_BUILDER)
    assert _publish_with(digest, st) == rel.REL_EVIDENCE_NOT_INDEPENDENT

    # 4. an unsigned or tampered object does not pass on shape alone
    st = _statement()
    doc = _evidence_doc(st)
    doc["tree_digest"] = "ff" * 32          # after signing
    raw = canonical(doc)
    _EVIDENCE[H_hex(raw)] = raw
    assert _publish_with(H_hex(raw), st) == rel.REL_BAD_SIGNATURE

    # 5. and the honest object publishes
    st = _statement()
    assert _publish_with(_EVIDENCE_BY_SH[rel.statement_hash(st)], st) is None
    print("  [PASS] REL-20 rebuild evidence is a separate signed act by the "
          "verifier over a different run, or it is not evidence")


def test_reproducibility_scope_is_derived_from_the_two_runs():
    """REL-21 · ADR-022 rev 2.3

    `reproducibility_scope` was a value the statement said about itself and
    nothing compared it with anything: the audit of recut2 placed a tag
    claiming `cross-host-class` with no fact about either host anywhere in
    the release. A scope that cannot go down is not a measurement.
    """
    reg = _registry()

    def _publish(scope, *, builder_host, verifier_host, verifier_run=None):
        st = _statement(reproducibility_scope=scope)
        sh = rel.statement_hash(st)
        # the evidence describes the verifier's run, so it moves with it —
        # otherwise the evidence gate fires first and the scope is never
        # reached, which would make this check about something else
        digest = _register_evidence(
            st, host_class=verifier_host,
            build_run_id=verifier_run or _RUN_VERIFIER)
        att = _attestation(st, [
            _approval(_BUILDER, "kb", "builder", sh, host_class=builder_host),
            _approval(_VERIFIER, "kv", "verifier", sh,
                      host_class=verifier_host,
                      build_run_id=verifier_run or _RUN_VERIFIER,
                      verification_evidence_hash=digest)])
        with tempfile.TemporaryDirectory() as tmp:
            chain = _chain(tmp)
            return _code(rel.publish, att, chain=chain, registry=reg,
                         context=_full_context(st))

    # THE AUDIT'S PROBE: the stronger claim with nothing behind it
    assert _publish(prv.SCOPE_CROSS_HOST_CLASS,
                    builder_host=_HOST_CLASS,
                    verifier_host=_HOST_CLASS) == rel.REL_SCOPE_MISMATCH
    # two classes genuinely differing DO carry the stronger scope — but the
    # evidence must describe that run, so it refuses here on the evidence
    # rather than on the scope, which is the correct next gate
    assert _publish(prv.SCOPE_SAME_HOST_CLASS,
                    builder_host=_HOST_CLASS,
                    verifier_host="macos-arm64") == rel.REL_SCOPE_MISMATCH
    # one run signed twice is `same-host`, and `same-host` carries no tag.
    # It is refused one gate earlier, by the evidence: a rebuild that names
    # the run the builder already approved is not a rebuild.
    assert _publish(prv.SCOPE_SAME_HOST_CLASS,
                    builder_host=_HOST_CLASS, verifier_host=_HOST_CLASS,
                    verifier_run=_RUN_BUILDER) == \
        rel.REL_EVIDENCE_NOT_INDEPENDENT
    assert prv.derive_scope(
        {"build_run_id": "r1", "host_class": "a"},
        {"build_run_id": "r1", "host_class": "b"}) == prv.SCOPE_SAME_HOST
    # and the honest pair publishes
    assert _publish(prv.SCOPE_SAME_HOST_CLASS, builder_host=_HOST_CLASS,
                    verifier_host=_HOST_CLASS) is None
    # an approval that names neither run nor host is not an approval
    st = _statement()
    sh = rel.statement_hash(st)
    for hole in ("build_run_id", "host_class"):
        bad = _approval(_BUILDER, "kb", "builder", sh, **{hole: ""})
        assert _code(rel.validate_approval, bad) == rel.REL_BAD_SCHEMA
    print("  [PASS] REL-21 the reproducibility scope is computed from the "
          "two runs and compared, never believed")


def test_a_permitting_callback_is_a_boundary():
    """REL-22 · the audit of recut3, blockers 1 and 2

    Two ways the authorizer permitted more than had been verified. It
    called `verify_publication` with whatever context it was given, and a
    context with `evidence_reader=None` skipped the evidence check — so a
    publication whose rebuild evidence did not exist yielded a callback
    answering 0. And it kept a reference to the statement dict, so editing
    `toolset_manifest_hash` in the publication AFTER the callback was built
    changed what the callback permitted: a permission no longer describing
    the object that had been verified.
    """
    reg = _registry()
    st = _statement()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        # the context reads its facts from a COPY of the statement, so that
        # the mutation in step 3 below reaches only the dict the callback
        # was given — which is the thing under test — and not the facts the
        # verifier compares it with
        ctx = _full_context(copy.deepcopy(st))
        pub = rel.publish(_attestation(st), chain=chain, registry=reg,
                          context=ctx)

        # 1. no reader, no permission — refused on the context, not skipped
        holed = ctx._replace(evidence_reader=None)
        assert _code(rel.toolset_authorizer, pub, chain=chain, registry=reg,
                     context=holed) == rel.REL_CONTEXT_INCOMPLETE
        # and even a diagnostic verification no longer passes an approval
        # whose evidence it cannot read
        assert _code(rel.verify_publication, pub, chain=chain, registry=reg,
                     context=holed) == rel.REL_EVIDENCE_UNRESOLVED

        # 2. a CONSUMED publication meets the publication boundary of the
        #    ledger, exactly as a produced one does
        assert _code(rel.toolset_authorizer, pub, chain=chain, registry=reg,
                     context=ctx._replace(
                         debt_reader=lambda: _PUBLICATION_BLOCKED)) == \
            rel.REL_DEBT_OPEN

        # 3. the permission is captured as VALUES at creation
        authorize = rel.toolset_authorizer(pub, chain=chain, registry=reg,
                                           context=ctx)
        original = st["toolset_manifest_hash"]
        forged = "cc" * 32
        pub["attestation"]["statement"]["toolset_manifest_hash"] = forged
        assert authorize(original) == pub["witness_ref"]["index"]
        assert _code(authorize, forged) == rel.REL_TOOLSET_AUTHZ_UNRESOLVED
        # the edited publication itself no longer verifies — which is the
        # point: the callback must keep describing what DID verify
        assert _code(rel.verify_publication, pub, chain=chain, registry=reg,
                     context=ctx) is not None
    print("  [PASS] REL-22 an authorizer needs the full context, meets the "
          "publication boundary, and permits what was verified — not what "
          "the dict says later")


def test_permission_and_publication_track_the_live_chain():
    """REL-24 · the audit of recut6, findings 4 and 5

    Two ways time was judged once and trusted thereafter. An authorizer
    built before a revocation kept permitting after it, because currency
    was judged at creation and only the stored hash compared at use. And
    `publish()` ran the lifecycle and revocation checks BEFORE taking the
    chain lock, so a RELEASE_REVOKED slid in between and a publication came
    back whose immediate verification said revoked.
    """
    reg = _registry()
    st = _statement()
    from jjdai.canonical import canonical
    from jjdai.crypto import H_hex
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        ctx = _full_context(st)
        pub = rel.publish(_attestation(st), chain=chain, registry=reg,
                          context=ctx)
        authorize = rel.toolset_authorizer(pub, chain=chain, registry=reg,
                                           context=ctx)
        assert authorize(st["toolset_manifest_hash"]) == \
            pub["witness_ref"]["index"]

        # 1. revoke AFTER the callback exists: the old callback must refuse
        body = rel.revoke_release(rel.statement_hash(st), key_id="kb",
                                  reason="after the fact",
                                  signing_key=_BUILDER, chain=chain,
                                  registry=reg)
        _REVOCATIONS[H_hex(canonical(body))] = canonical(body)
        assert _code(authorize, st["toolset_manifest_hash"]) == \
            rel.REL_REVOKED
        # and it is still immune to the caller's dict — recut4's property
        # was not traded away for this one
        pub["attestation"]["statement"]["toolset_manifest_hash"] = "cc" * 32
        assert _code(authorize, "cc" * 32) == rel.REL_REVOKED

    # 2. publish() judges lifecycle and revocation UNDER THE HOLD it writes
    #    under. Proved by observing the lock from inside the checks: an
    #    RLock reports whether the calling thread owns it.
    st = _statement()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        held = {}
        real_life, real_rev = rel.check_lifecycle_witnessed, \
            rel._check_not_revoked

        def _spy_life(keys, *, chain):
            held["lifecycle"] = chain.lock._is_owned()
            return real_life(keys, chain=chain)

        def _spy_rev(statement, *, chain, registry, context):
            held["revocation"] = chain.lock._is_owned()
            return real_rev(statement, chain=chain, registry=registry,
                            context=context)

        rel.check_lifecycle_witnessed = _spy_life
        rel._check_not_revoked = _spy_rev
        try:
            rel.publish(_attestation(st), chain=chain, registry=reg,
                        context=_full_context(st))
        finally:
            rel.check_lifecycle_witnessed = real_life
            rel._check_not_revoked = real_rev
        assert held == {"lifecycle": True, "revocation": True}, held

        # 3. and revoke_release() judges the key at the position the record
        #    actually takes — the append lands exactly where validity was
        #    judged, under the same hold
        seen = {}
        real_valid = rel.key_valid_at

        def _spy_valid(key, seq):
            seen["judged_at"] = seq
            seen["held"] = chain.lock._is_owned()
            return real_valid(key, seq)

        rel.key_valid_at = _spy_valid
        try:
            rel.revoke_release(rel.statement_hash(st), key_id="kb",
                               reason="r", signing_key=_BUILDER,
                               chain=chain, registry=reg)
        finally:
            rel.key_valid_at = real_valid
        assert seen == {"judged_at": chain.records[-1]["index"],
                        "held": True}, seen
    # 4. A REVOKED KEY CANNOT REVOKE. The audit of recut7 wrote a
    #    KEY_REVOKED for kb and then handed revoke_release() a registry
    #    still saying revoked=None: key_valid_at read the stale registry
    #    and the append went through. The registry is checked against the
    #    chain's own projection first, under the hold, and nothing is
    #    written.
    st = _statement()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        chain.append(prv.KIND_KEY_REVOKED,
                     semantic_digest=rel.key_lifecycle_digest(
                         "kb", "revoked", _BUILDER.public.hex()))
        before = len(chain.records)
        log_before = os.path.getsize(os.path.join(tmp, "w.jsonl"))
        assert _code(rel.revoke_release, rel.statement_hash(st),
                     key_id="kb", reason="r", signing_key=_BUILDER,
                     chain=chain, registry=_registry()) == \
            rel.REL_LIFECYCLE_HIDDEN
        # and with the revocation declared, the same call refuses on the
        # key being dead at the position — either way, nothing written
        assert _code(rel.revoke_release, rel.statement_hash(st),
                     key_id="kb", reason="r", signing_key=_BUILDER,
                     chain=chain,
                     registry=_registry(builder_revoked=before - 1)) == \
            rel.REL_KEY_REVOKED
        # an unwitnessed activation refuses the same way
        assert _code(rel.revoke_release, rel.statement_hash(st),
                     key_id="kb", reason="r", signing_key=_BUILDER,
                     chain=chain,
                     registry=_registry(builder_active=1)) == \
            rel.REL_LIFECYCLE_UNWITNESSED
        assert len(chain.records) == before
        assert os.path.getsize(os.path.join(tmp, "w.jsonl")) == log_before

    # 5. NOTHING IS WRITTEN INTO A CHAIN THAT DOES NOT VERIFY. The audit of
    #    recut7 broke an earlier record's signature, saw verify_chain() go
    #    False, and publish() appended anyway — refused one record too late
    #    for an append-only history. Integrity is a precondition of the
    #    write, judged under the same hold.
    st = _statement()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        chain.records[0]["signature"] = "00" * 64
        assert not chain.verify_chain()
        before = len(chain.records)
        log_before = os.path.getsize(os.path.join(tmp, "w.jsonl"))
        assert _code(rel.publish, _attestation(st), chain=chain,
                     registry=reg, context=_full_context(st)) == \
            rel.REL_WITNESS_UNRESOLVED
        assert _code(rel.revoke_release, rel.statement_hash(st),
                     key_id="kb", reason="r", signing_key=_BUILDER,
                     chain=chain, registry=reg) == rel.REL_WITNESS_UNRESOLVED
        assert len(chain.records) == before
        assert os.path.getsize(os.path.join(tmp, "w.jsonl")) == log_before
    print("  [PASS] REL-24 a permission is re-judged against the live chain "
          "on every use; publish and revoke judge under the hold they write "
          "under, and write nothing into a chain that does not verify or "
          "under a key the chain has revoked")


def test_the_gates_read_the_debt_ledger():
    """REL-18

    The ledger has carried `blocks` on every position since D14 and no code
    read it, so the audit tagged a release with four positions open under
    `meaning-of-a-release-tag` — the one thing D13 forbids outright. A
    ledger that governs documentation and not the boundary it names is a
    table, not a control.
    """
    reg = _registry()
    real = json.load(_io.open(os.path.join(_ROOT, "docs",
                                           "architecture_status.json"),
                              encoding="utf-8"))
    st = _statement()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        ctx = _full_context(st)._replace(debt_reader=lambda: real)
        # PUBLICATION IS ITS OWN BOUNDARY. recut3 moved the lifecycle
        # position onto it — a RELEASE_ATTESTED built on editable positions
        # was serving as L2 authorization time while the tag was refused —
        # and recut6 CLOSED that position with witnessed lifecycle records.
        # So the real ledger now lets a publication through and still
        # refuses the tag: two boundaries, one ledger, read separately.
        assert _code(rel.publish, _attestation(st), chain=chain,
                     registry=reg,
                     context=ctx._replace(
                         debt_reader=lambda: _PUBLICATION_BLOCKED)) == \
            rel.REL_DEBT_OPEN
        assert len(chain.records) == ACTIVATIONS
        pub = rel.publish(_attestation(st), chain=chain, registry=reg,
                          context=ctx)
        code = _code(rel.check_release_tag, "v0.6.9", pub, chain=chain,
                     registry=reg, context=ctx)
        assert code == rel.REL_DEBT_OPEN, code
        blocking = [p for p in prv.open_debt(real)
                    if any(e.get("id") == p
                           and e.get("blocks") == prv.BLOCKS_RELEASE_TAG
                           for e in real["release_debt"]["events"])]
        assert len(blocking) >= 4, blocking

        # ONE projection, and an unknown boundary refuses rather than
        # quietly blocking nothing — which is what a misspelt `blocks`
        # would do now that a gate depends on the spelling.
        bad = {"release_debt": {"schema": "jjdai.debt-ledger/v1", "events": [
            {"seq": 1, "id": "x", "event": "DEBT_OPENED",
             "blocks": "meaning-of-a-realease-tag", "opened_in": "typo"}]}}
        assert _code(rel.check_release_tag, "v0.6.9", pub, chain=chain,
                     registry=reg,
                     context=ctx._replace(debt_reader=lambda: bad)) == \
            rel.REL_DEBT_OPEN
        # and the ledger is a required fact: absent, the tag refuses on the
        # context. An absent reader is a gate that silently passes.
        assert _code(rel.check_release_tag, "v0.6.9", pub, chain=chain,
                     registry=reg,
                     context=ctx._replace(debt_reader=None)) == \
            rel.REL_CONTEXT_INCOMPLETE
    print("  [PASS] REL-18 publication and tag gates project the debt "
          "ledger and refuse an open position on their own boundary")


def test_toolset_authorization_is_resolved_from_the_release():
    """REL-19

    D10 keeps `release_signing` and `toolset_authorization` apart so that
    whoever can cut a build cannot thereby widen a being's hand. The link is
    `toolset_manifest_hash` INSIDE the statement, and it is also the only
    honest answer to "authorized when?" — recut1 let the manifest answer
    that about itself, which a signature makes immutable rather than true.
    """
    reg = _registry()
    st = _statement()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        ctx = _full_context(st)
        chain.append("INFER", semantic_digest="ab" * 16)
        pub = rel.publish(_attestation(st), chain=chain, registry=reg,
                          context=ctx)
        authorize = rel.toolset_authorizer(pub, chain=chain, registry=reg,
                                           context=ctx)
        # the position is the RELEASE_ATTESTED record's actual index
        assert authorize(st["toolset_manifest_hash"]) == \
            pub["witness_ref"]["index"] == ACTIVATIONS + 1
        # a release authorizes the manifest it NAMES, never one nearby
        assert _code(authorize, "cc" * 32) == rel.REL_TOOLSET_AUTHZ_UNRESOLVED
    print("  [PASS] REL-19 a toolset manifest is authorized at the position "
          "where the release naming it was attested")


if __name__ == "__main__":
    for fn in (test_statement_has_no_position_and_names_its_algorithm,
               test_evidence_hash_has_one_shape,
               test_an_approval_names_its_release,
               test_both_roles_distinct_keys_distinct_devices,
               test_control_numbers_are_counted_not_asserted,
               test_key_validity_is_judged_at_the_actual_position,
               test_witness_ref_is_outside_the_hash_and_resolved,
               test_an_unfinished_release_never_reaches_the_chain,
               test_registry_refuses_what_would_make_the_count_a_fiction,
               test_shipped_registry_is_valid_and_empty,
               test_strict_schema_and_external_facts,
               test_publication_requires_an_intact_chain,
               test_publish_is_atomic_against_a_concurrent_append,
               test_registry_requires_physical_binding_and_one_key_per_public,
               test_an_incomplete_context_cannot_publish_or_tag,
               test_key_lifecycle_positions_resolve_in_the_chain,
               test_rebuild_evidence_resolves_to_this_build,
               test_rebuild_evidence_is_somebody_elses_act,
               test_reproducibility_scope_is_derived_from_the_two_runs,
               test_a_permitting_callback_is_a_boundary,
               test_a_release_is_revoked_by_name,
               test_permission_and_publication_track_the_live_chain,
               test_the_gates_read_the_debt_ledger,
               test_toolset_authorization_is_resolved_from_the_release):
        fn()
