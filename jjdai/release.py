# -*- coding: utf-8 -*-
"""
jjdai.release — the four release objects and the key registry
=============================================================
ADR-022 D2, D5, D6. One evidential chain: which tree, by which recipe, into
which artefacts, checked by whom and by what independent act. It breaks the
same way at every link, so it is built as one module rather than as four
half-related ones.

THREE THINGS THIS FILE IS ARRANGED AROUND, EACH OF WHICH WAS A DEFECT IN AN
EARLIER REVISION OF THE ADR AND IS THEREFORE EASY TO REINTRODUCE.

**The hashed object must stop growing once it is hashed.** rev 2.1 kept
`witness_ref` inside the envelope the hash was taken over, so adding the
reference changed the bytes and therefore the hash, and the witness record
ended up bound to the previous version of the object. `ReleaseAttestation`
is immutable and hashed; `ReleasePublication` is a SECOND object that
carries the attestation byte for byte plus the reference. Substitution of
`witness_ref` is caught by RESOLUTION, not by a signature: the record
carries `attestation_hash` and `statement_hash`, so the reference must
resolve, name a `RELEASE_ATTESTED`, carry the same hashes and be
integrity-valid — the rule ADR-018 rev 2 already applies to `evidence_refs`.

**There is no self-declared position.** Key validity is judged at the ACTUAL
sequence position of the `RELEASE_ATTESTED` record. A position inside the
signed body could be pointed backwards into the validity window of a revoked
key, so the body does not have one (D5.2: "Поля позиции в витнесс-
последовательности нет").

**The control block is COUNTED, never asserted.** `distinct_keys`,
`distinct_devices` and `distinct_principals` are derived from the valid
approvals through the registry and compared with what the statement records;
a disagreement refuses. Two-key drawn as two-person would enter a signed
artefact as an independence nobody had — the same defect as a panel
simulated by one engine, in another place.
"""
from __future__ import annotations

import copy
from collections import namedtuple

import json

from .canonical import canonical
from .crypto import H_hex, verify
from . import provenance as prv

REGISTRY_FILE = "docs/release_keys.json"
REGISTRY_SCHEMA = "jjdai.release-keys/v1"

#: Refusal codes. Every one of them is a fail-closed path in D5.4 or D6.
REL_BAD_SCHEMA = "REL_BAD_SCHEMA"
REL_STATEMENT_MISMATCH = "REL_STATEMENT_MISMATCH"
REL_ROLE_MISSING = "REL_ROLE_MISSING"
REL_EVIDENCE_SHAPE = "REL_EVIDENCE_SHAPE"
REL_KEY_REUSED = "REL_KEY_REUSED"
REL_DEVICE_REUSED = "REL_DEVICE_REUSED"
REL_UNKNOWN_KEY = "REL_UNKNOWN_KEY"
REL_KEY_NOT_ACTIVE = "REL_KEY_NOT_ACTIVE"
REL_KEY_REVOKED = "REL_KEY_REVOKED"
REL_ROLE_NOT_PERMITTED = "REL_ROLE_NOT_PERMITTED"
REL_BAD_SIGNATURE = "REL_BAD_SIGNATURE"
REL_CONTROL_MISMATCH = "REL_CONTROL_MISMATCH"
REL_SCOPE_TOO_LOW = "REL_SCOPE_TOO_LOW"
REL_TAG_MISMATCH = "REL_TAG_MISMATCH"
REL_WITNESS_UNRESOLVED = "REL_WITNESS_UNRESOLVED"
REL_REGISTRY_INVALID = "REL_REGISTRY_INVALID"
REL_DEVICE_SHARED_HOST = "REL_DEVICE_SHARED_HOST"
REL_TREE_MISMATCH = "REL_TREE_MISMATCH"
REL_ACCEPTANCE_INVALID = "REL_ACCEPTANCE_INVALID"
REL_ARTEFACT_MISMATCH = "REL_ARTEFACT_MISMATCH"
REL_CONTEXT_INCOMPLETE = "REL_CONTEXT_INCOMPLETE"
REL_LIFECYCLE_UNWITNESSED = "REL_LIFECYCLE_UNWITNESSED"
REL_RELEASE_REVOKED = "REL_RELEASE_REVOKED"
REL_ENVIRONMENT_MISMATCH = "REL_ENVIRONMENT_MISMATCH"
REL_EVIDENCE_UNRESOLVED = "REL_EVIDENCE_UNRESOLVED"
REL_EVIDENCE_DIVERGENT = "REL_EVIDENCE_DIVERGENT"
REL_DEBT_OPEN = "REL_DEBT_OPEN"
REL_LIFECYCLE_BINDING = "REL_LIFECYCLE_BINDING"
REL_TOOLSET_AUTHZ_UNRESOLVED = "REL_TOOLSET_AUTHZ_UNRESOLVED"
REL_EVIDENCE_NOT_INDEPENDENT = "REL_EVIDENCE_NOT_INDEPENDENT"
REL_SCOPE_MISMATCH = "REL_SCOPE_MISMATCH"
REL_REVOKED = "REL_REVOKED"
REL_REVOKED_UNRESOLVED = "REL_REVOKED_UNRESOLVED"
REL_LIFECYCLE_HIDDEN = "REL_LIFECYCLE_HIDDEN"


class ReleaseError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code, message):
    return ReleaseError(code, message)


# --------------------------------------------------------------------------- #
# D6 · the key registry
# --------------------------------------------------------------------------- #

KEY_FIELDS = ("key_id", "public", "device_id", "principal_id", "roles",
              "activated_at_witness_seq")

RegisteredKey = namedtuple(
    "RegisteredKey",
    "key_id public device_id principal_id roles activated revoked reason")


def load_registry(path_or_doc) -> dict:
    """Read `docs/release_keys.json` and refuse anything malformed.

    Append-only in discipline; this reader does not enforce append-only
    across time — git history does — but it does enforce that every entry is
    complete, that `key_id` is unique, and that two `device_id` values are
    not declared on one physical host. A device that is two virtual machines
    on one box is ONE device (D6), and letting it register twice would make
    `distinct_devices` a fiction while reading as two.
    """
    if isinstance(path_or_doc, str):
        try:
            with open(path_or_doc, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            raise _fail(REL_REGISTRY_INVALID,
                        f"release key registry unreadable: {e}") from None
    else:
        doc = path_or_doc
    if not isinstance(doc, dict) or doc.get("schema") != REGISTRY_SCHEMA:
        raise _fail(REL_REGISTRY_INVALID,
                    f"release key registry must declare schema "
                    f"{REGISTRY_SCHEMA!r}")
    # WHAT THE POSITIONS IN THIS FILE ARE. `activated_at_witness_seq` is a
    # number in a JSON file, and until a record kind exists that says "this
    # key became active here", a number in a file is an ASSERTION. The audit
    # of recut1 found the opposite claimed: a function named
    # `check_lifecycle_witnessed` that resolved an index and looked no
    # further, and a check that appended six INFER records and read one of
    # them as the activation of a key. So the registry DECLARES which of the
    # two it is, in a field, the way `device_binding` declares it for
    # devices — half a control is announced as half (ADR-022 D2's rule,
    # applied where the same defect appeared).
    #
    # `witnessed` refuses: it needs KEY_ACTIVATED / KEY_REVOKED in the
    # witness vocabulary, window 6 of the pre-genesis reserve does not hold
    # them, and reopening a frozen reserve is an ADR decision and not a
    # build's. The gap is the debt position `release-key-lifecycle-
    # witnessing`, which blocks the meaning of a release tag.
    # rev 2.4 inverts the previous rule. `asserted` was the only honest
    # value while no record kind could witness a key's lifecycle; now
    # KEY_ACTIVATED and KEY_REVOKED exist, `check_lifecycle_witnessed` reads
    # their pre-images, and a registry that still says `asserted` is asking
    # to be believed where it could be checked. Refused.
    binding = doc.get("lifecycle_binding")
    if binding != LIFECYCLE_WITNESSED:
        raise _fail(
            REL_LIFECYCLE_BINDING,
            f"the registry declares lifecycle_binding={binding!r}; since "
            f"ADR-022 rev 2.4 every position must resolve to a "
            f"{KEY_ACTIVATED} / {KEY_REVOKED} record naming the key and the "
            f"transition, and the registry must say {LIFECYCLE_WITNESSED!r}. "
            f"An asserted position where a witnessed one is possible is a "
            f"number in a file asking to be trusted")
    keys = {}
    hosts = {}
    publics = {}
    for entry in doc.get("keys") or []:
        for field in KEY_FIELDS:
            if entry.get(field) in (None, "", []):
                raise _fail(REL_REGISTRY_INVALID,
                            f"registry entry omits {field!r}: an incomplete "
                            f"key cannot be counted, and the control block "
                            f"is counted from this file")
        kid = entry["key_id"]
        if kid in keys:
            raise _fail(REL_REGISTRY_INVALID,
                        f"key_id {kid!r} registered twice; the registry is "
                        f"append-only and a key is registered once, then "
                        f"revoked forward")
        # Physical separateness is DECLARED or the key is not registered.
        # The first cut only compared `physical_host` when an operator
        # bothered to fill it in, so two VMs registered as two devices with
        # the field simply absent counted as two — the rule held exactly
        # where it was not needed. One of the two must be present:
        # `hardware_binding` (a real attestation, Ф3) or
        # `physical_host_assertion` naming who asserts it and under which
        # statement, which is what `device_binding: "asserted"` means.
        host = entry.get("physical_host")
        assertion = entry.get("physical_host_assertion")
        if not entry.get("hardware_binding") and not (host and assertion):
            raise _fail(
                REL_REGISTRY_INVALID,
                f"key {entry['key_id']!r} declares neither a hardware "
                f"binding nor a physical_host with a "
                f"physical_host_assertion. distinct_devices is a count of "
                f"PHYSICAL machines; without one of the two it counts "
                f"whatever the file lists, which is what the operator "
                f"wanted it to say (ADR-022 D6).")
        if host:
            other = hosts.get(host)
            if other and other != entry["device_id"]:
                raise _fail(
                    REL_DEVICE_SHARED_HOST,
                    f"device_id {entry['device_id']!r} and {other!r} both "
                    f"declare physical host {host!r}. Two virtual machines "
                    f"on one box are ONE device (ADR-022 D6); registering "
                    f"them separately would make distinct_devices read as "
                    f"two while being one.")
            hosts[host] = entry["device_id"]
        bad_role = [r for r in entry["roles"] if r not in prv.APPROVAL_ROLES]
        if bad_role:
            raise _fail(REL_REGISTRY_INVALID,
                        f"key {kid!r} declares unknown role(s) {bad_role}")
        if entry["public"] in publics:
            raise _fail(
                REL_REGISTRY_INVALID,
                f"key {kid!r} shares a public key with {publics[entry['public']]!r}. "
                f"Two ids over one key are one key wearing two names, and "
                f"distinct_keys would count it twice.")
        publics[entry["public"]] = kid
        keys[kid] = RegisteredKey(
            kid, entry["public"], entry["device_id"], entry["principal_id"],
            tuple(entry["roles"]), int(entry["activated_at_witness_seq"]),
            entry.get("revoked_at_witness_seq"),
            entry.get("revocation_reason"))
    return keys


def key_valid_at(key: RegisteredKey, witness_seq: int) -> None:
    """Was this key active at the position the release record actually took?

    Not "is it active now". A historical attestation is not re-signed after
    a revocation (D6): its signature holds if the key was active at the
    sequence position of ITS `RELEASE_ATTESTED` record. Where the moment of
    compromise is known the revocation carries that position and everything
    signed after it loses validity by itself; where it is not, affected
    releases are revoked BY NAME, forward, rather than the whole history of
    the key going quietly worthless.
    """
    if witness_seq < key.activated:
        raise _fail(
            REL_KEY_NOT_ACTIVE,
            f"key {key.key_id!r} activates at witness position "
            f"{key.activated} and this release records at {witness_seq}: a "
            f"key acts from its declared position, never retroactively")
    if key.revoked is not None and witness_seq >= int(key.revoked):
        raise _fail(
            REL_KEY_REVOKED,
            f"key {key.key_id!r} was revoked at witness position "
            f"{key.revoked} ({key.reason or 'no reason recorded'}) and this "
            f"release records at {witness_seq}")


# --------------------------------------------------------------------------- #
# D5 · the four objects
# --------------------------------------------------------------------------- #

#: Fields that must be a 64-character lowercase hex digest. The first cut
#: asked only that they be non-empty, so `tree_digest: "x"` was a valid
#: statement — a digest-shaped hole in the one field the whole chain is
#: about.
STATEMENT_HEX_FIELDS = ("tree_digest", "bundle_hash", "toolset_manifest_hash",
                        "sbom_hash", "acceptance_hash", "recipe_hash")

ARTEFACT_FIELDS = ("name", "sha256", "length")

BUILD_ENV_FIELDS = ("python", "locale", "timezone", "umask", "network")

STATEMENT_FIELDS = ("schema", "version", "tree_digest", "tree_digest_algo",
                    "artefacts", "bundle_hash", "toolset_manifest_hash",
                    "sbom_hash", "acceptance_hash", "recipe_hash",
                    "build_environment", "reproducibility_scope", "control")

#: rev 2.3 adds `build_run_id` and `host_class` to EVERY approval.
#: Without them "two independent builds" is a statement about the
#: number of signatures rather than the number of builds — two
#: signatures over one run counted as the control.
APPROVAL_FIELDS = ("schema", "statement_hash", "key_id", "principal_id",
                   "build_run_id", "host_class",
                   "device_id", "role")


def _hex64(value, what: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or \
            any(c not in "0123456789abcdef" for c in value.lower()):
        raise _fail(REL_BAD_SCHEMA,
                    f"{what} is not a sha256: a hash has a fixed width, and "
                    f"a short string in its place is a digest-shaped hole")
    return value.lower()


def statement_hash(statement) -> str:
    """sha256 over the JCS canonicalization of the statement.

    No domain prefix: this hash addresses an object, and the one string that
    prefixes a hash pre-image in ADR-022 is the attestation's. Adding a
    second would invent a separator that no reserve declares.
    """
    return H_hex(canonical(statement))


def approval_signing_bytes(approval) -> bytes:
    body = {k: v for k, v in approval.items() if k != "signature"}
    return prv.signing_domain(prv.DOMAIN_RELEASE_APPROVAL) + canonical(body)


def attestation_hash(attestation) -> str:
    """`sha256("JJDAI:RELEASE:ATTESTATION:v1\\0" ‖ JCS(ReleaseAttestation))`.

    `hash_prefix()` is used rather than `signing_domain()` and the two
    refuse each other's strings, so this can never quietly become a
    signature. rev 2.2 removed the redundant statement signature; the
    attestation is addressed by this hash and covered by the approvals
    inside it.
    """
    return H_hex(prv.hash_prefix(prv.PREFIX_RELEASE_ATTESTATION) +
                 canonical(attestation))


def validate_statement(statement) -> dict:
    if not isinstance(statement, dict) or \
            statement.get("schema") != prv.SCHEMA_RELEASE_STATEMENT:
        raise _fail(REL_BAD_SCHEMA,
                    f"statement must declare {prv.SCHEMA_RELEASE_STATEMENT!r}")
    for field in STATEMENT_FIELDS:
        if statement.get(field) in (None, "", [], {}):
            raise _fail(REL_BAD_SCHEMA, f"statement omits {field!r}")
    if "witness_seq" in statement or "witness_ref" in statement:
        raise _fail(
            REL_BAD_SCHEMA,
            "a ReleaseStatement carries NO position in the witness sequence "
            "(ADR-022 D5.2). A self-declared position could be pointed back "
            "into the validity window of a revoked key; the actual position "
            "of the RELEASE_ATTESTED record is what counts.")
    if statement["tree_digest_algo"] != prv.TREE_DIGEST_ALGO:
        raise _fail(REL_BAD_SCHEMA,
                    f"tree_digest_algo must be {prv.TREE_DIGEST_ALGO!r}; a "
                    f"digest without the name of the algorithm that made it "
                    f"compares to nothing")
    for field in STATEMENT_HEX_FIELDS:
        _hex64(statement[field], f"statement field {field!r}")
    artefacts = statement["artefacts"]
    if not isinstance(artefacts, list) or not artefacts:
        raise _fail(REL_BAD_SCHEMA, "artefacts must be a non-empty list")
    for art in artefacts:
        if not isinstance(art, dict):
            raise _fail(REL_BAD_SCHEMA,
                        f"artefact {art!r} is not an object; a list of "
                        f"strings names files and says nothing about them")
        for field in ARTEFACT_FIELDS:
            if art.get(field) in (None, ""):
                raise _fail(REL_BAD_SCHEMA,
                            f"artefact omits {field!r}")
        _hex64(art["sha256"], f"artefact {art['name']!r} sha256")
        if not isinstance(art["length"], int) or art["length"] <= 0:
            raise _fail(REL_BAD_SCHEMA,
                        f"artefact {art['name']!r} length must be a "
                        f"positive integer")
    env = statement["build_environment"]
    if not isinstance(env, dict):
        raise _fail(REL_BAD_SCHEMA, "build_environment must be an object")
    for field in BUILD_ENV_FIELDS:
        if not env.get(field):
            raise _fail(
                REL_BAD_SCHEMA,
                f"build_environment omits {field!r}; the D3 table is the "
                f"statement of what was pinned, and a table with holes "
                f"pins nothing there")
    prv.check_scope_allows_release(statement["reproducibility_scope"])
    control = statement["control"]
    for field in prv.CONTROL_FIELDS:
        if field not in control:
            raise _fail(REL_BAD_SCHEMA, f"control block omits {field!r}")
    # Counters are NUMBERS. `"2"` is a string that renders as two and
    # compares as neither — the exact shape D2 refuses when it says the
    # control is described in numbers rather than asserted.
    for field in ("signature_threshold", "distinct_keys", "distinct_devices",
                  "distinct_principals"):
        value = control[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise _fail(REL_BAD_SCHEMA,
                        f"control.{field} must be a positive integer, not "
                        f"{value!r}")
    prv.check_device_binding(control["device_binding"])
    return statement


def validate_approval(approval) -> dict:
    if not isinstance(approval, dict) or \
            approval.get("schema") != prv.SCHEMA_RELEASE_APPROVAL:
        raise _fail(REL_BAD_SCHEMA,
                    f"approval must declare {prv.SCHEMA_RELEASE_APPROVAL!r}")
    for field in APPROVAL_FIELDS:
        if not approval.get(field):
            raise _fail(REL_BAD_SCHEMA, f"approval omits {field!r}")
    role = approval["role"]
    if role not in prv.APPROVAL_ROLES:
        raise _fail(REL_ROLE_NOT_PERMITTED,
                    f"unknown approval role {role!r}")
    # ONE shape of the field, not "absent or null" (D5.3). Without this the
    # builder role is rewritten as verifier under a valid signature, with an
    # arbitrary rebuild evidence — rewriting exactly the proof the whole
    # construction exists to produce.
    has = "verification_evidence_hash" in approval
    needs = prv.EVIDENCE_REQUIRED_BY_ROLE[role]
    if needs and not approval.get("verification_evidence_hash"):
        raise _fail(REL_EVIDENCE_SHAPE,
                    "role 'verifier' requires verification_evidence_hash: an "
                    "approval that claims an independent rebuild without "
                    "naming its evidence is the claim without the rebuild")
    if needs:
        # A digest, not a token. `"x"` was accepted, which is an approval
        # naming evidence that cannot be looked up — the shape of a citation
        # without a citation.
        _hex64(approval["verification_evidence_hash"],
               "verification_evidence_hash")
    if not needs and has:
        raise _fail(REL_EVIDENCE_SHAPE,
                    "role 'builder' must NOT carry verification_evidence_"
                    "hash; the field present on a builder is how a builder "
                    "becomes a verifier without rebuilding anything")
    return approval


class ReleaseContext(namedtuple(
        "ReleaseContext",
        "expected_tag tree_digest acceptance build_environment "
        "artefact_reader bundle_reader recipe_reader sbom_reader "
        "toolset_manifest_reader evidence_reader debt_reader "
        "revocation_reader")):
    """The FACTS a statement is checked against, from outside the statement.

    Without these, verification proves that a signed document agrees with
    itself. That is worth having and it is not what D5.4 asks for: the tag
    must equal the version, the digest must equal the tree that was built,
    the acceptance hash must point at a GREEN run, and every artefact,
    bundle, recipe, SBOM and toolset manifest hash must match real bytes.

    `internal_only()` exists so that a caller who genuinely has no external
    facts — a fixture, a reader inspecting an archived object — says so
    deliberately, rather than getting the weaker check by omission. Passing
    nothing is not allowed: an argument with a permissive default is how the
    weaker answer becomes the usual one.
    """

    @classmethod
    def internal_only(cls):
        """For an ARCHIVAL reader with no access to the release's world.

        Useful and dangerous in the same breath, so `publish()` and
        `check_release_tag()` refuse it outright. The audit passed this
        straight into `publish()` and got a RELEASE_ATTESTED record written
        with no tag, tree, acceptance, bundle, recipe, SBOM, manifest or
        artefact ever compared — a signed release of nothing in particular.
        An inspector may verify internal consistency; a release may not be
        MADE that way.
        """
        return cls(None, None, None, None, None, None, None, None, None,
                   None, None, None)

    def missing(self) -> list:
        """Facts this context cannot supply. Empty means complete."""
        return sorted(f for f in self._fields if getattr(self, f) is None)

    def require_complete(self, what: str) -> None:
        gaps = self.missing()
        if gaps:
            raise _fail(
                REL_CONTEXT_INCOMPLETE,
                f"{what} requires a COMPLETE verification context; these "
                f"facts are absent: {gaps}. Each absent reader is a gate "
                f"that silently passes, and `internal_only()` turns every "
                f"one of them off at once — it exists for an archival "
                f"reader, never for making a release.")


#: What a recorded run must BE before it can stand behind a release. The
#: first cut asked only `passed == total`, and the audit walked an object
#: reading `{"passed": 1, "total": 1, "import_errors": 1}` with no tree
#: digest straight through: one check that passed, one import that never
#: ran, and nothing saying which tree it ran against.
ACCEPTANCE_SCHEMA = "jjdai.acceptance_result/v4"
ACCEPTANCE_SUITE = "hermetic"


def _check_acceptance(statement, acceptance) -> None:
    if acceptance is None:
        raise _fail(REL_ACCEPTANCE_INVALID,
                    "no recorded run supplied; a release is cut on a green "
                    "run and 'no run' is not a green one")
    if H_hex(canonical(acceptance)) != statement["acceptance_hash"] and \
            acceptance.get("_raw_hash") != statement["acceptance_hash"]:
        raise _fail(REL_ACCEPTANCE_INVALID,
                    "acceptance_hash does not address the recorded run "
                    "supplied as evidence")
    if acceptance.get("schema") != ACCEPTANCE_SCHEMA:
        raise _fail(REL_ACCEPTANCE_INVALID,
                    f"the recorded run declares schema "
                    f"{acceptance.get('schema')!r}, not {ACCEPTANCE_SCHEMA!r}")
    if acceptance.get("suite") != ACCEPTANCE_SUITE:
        raise _fail(
            REL_ACCEPTANCE_INVALID,
            f"the run is of suite {acceptance.get('suite')!r}. A release "
            f"stands on the HERMETIC suite: the live groups are evidence "
            f"about a host, and a host is not the tree")
    if acceptance.get("import_errors"):
        raise _fail(
            REL_ACCEPTANCE_INVALID,
            f"{acceptance['import_errors']} import error(s) in the recorded "
            f"run. A module that never imported ran no checks, so the "
            f"passed/total pair is a count of what happened to load")
    passed, total = acceptance.get("passed"), acceptance.get("total")
    if not isinstance(total, int) or total <= 0 or passed != total:
        raise _fail(
            REL_ACCEPTANCE_INVALID,
            f"the recorded run is {passed}/{total} — a hash pointing at a "
            f"red or empty run is a hash of a red or empty run")
    if acceptance.get("tree_digest") != statement["tree_digest"]:
        raise _fail(
            REL_ACCEPTANCE_INVALID,
            "the recorded run does not name THIS tree. An absent digest is "
            "not a match: it is a run that cannot say what it ran against")
    if acceptance.get("tree_digest_algo") != prv.TREE_DIGEST_ALGO:
        raise _fail(REL_ACCEPTANCE_INVALID,
                    "the recorded run states a digest without naming the "
                    "algorithm that made it")


def _check_environment(statement, actual) -> None:
    """The D3 table, compared against what was MEASURED.

    `environment_matches()` existed and no verifier called it — the same
    "validator beside the boundary" shape the audit has now found three
    times in this drop. Imported lazily so `jjdai.release` does not depend
    on the build module at import time.
    """
    from .build_env import ENV_FIELDS, environment_matches
    recorded = statement["build_environment"]
    absent = [f for f in ENV_FIELDS if not recorded.get(f)]
    if absent:
        raise _fail(
            REL_ENVIRONMENT_MISMATCH,
            f"build_environment omits {absent}. D3 fixes the whole table, "
            f"and a table with holes pins nothing there — `source_date_epoch` "
            f"could be deleted and the statement still validated")
    if actual is None:
        raise _fail(REL_ENVIRONMENT_MISMATCH,
                    "no measured build environment supplied to compare the "
                    "recorded table against")
    drift = environment_matches(recorded, actual)
    if drift:
        raise _fail(
            REL_ENVIRONMENT_MISMATCH,
            f"the recorded build environment differs from the measured one "
            f"in {drift}. A build that ran under another locale or another "
            f"clock cannot present itself as the same build")


def _check_bytes(reader, name, want, what, *, length=None):
    if reader is None:
        return
    try:
        data = reader(name) if name is not None else reader()
    except Exception as e:                                     # noqa: BLE001
        raise _fail(REL_ARTEFACT_MISMATCH,
                    f"{what} could not be read: {e}") from None
    got = H_hex(data)
    if got != want:
        raise _fail(REL_ARTEFACT_MISMATCH,
                    f"{what} hashes {got}, the statement records {want}")
    # The length is a SECOND fact and must be checked as one. A statement
    # recording 999999 bytes beside a correct digest passed, and a reader
    # who trusts the number without fetching the bytes is misled by a signed
    # artefact — which is the only kind of reader this field exists for.
    if length is not None and len(data) != length:
        raise _fail(REL_ARTEFACT_MISMATCH,
                    f"{what} is {len(data)} bytes, the statement records "
                    f"{length}")


def verify_attestation(attestation, *, registry, witness_seq, context) -> dict:
    """Every rule of D5.4, each fail-closed. Returns the counted control.

    `witness_seq` is the ACTUAL position of the `RELEASE_ATTESTED` record —
    supplied by the caller from the resolved record, never read out of the
    signed body. `context` carries the external facts; see `ReleaseContext`.
    """
    if not isinstance(attestation, dict) or \
            attestation.get("schema") != prv.SCHEMA_RELEASE_ATTESTATION:
        raise _fail(REL_BAD_SCHEMA,
                    f"attestation must declare "
                    f"{prv.SCHEMA_RELEASE_ATTESTATION!r}")
    statement = validate_statement(attestation.get("statement"))
    want = statement_hash(statement)
    if attestation.get("statement_hash") != want:
        raise _fail(REL_STATEMENT_MISMATCH,
                    f"attestation records statement_hash "
                    f"{attestation.get('statement_hash')!r}, the statement "
                    f"hashes {want}")
    approvals = attestation.get("approvals") or []
    keys, devices, principals, roles = set(), set(), set(), set()
    for signed in approvals:
        approval = validate_approval(signed)
        if approval["statement_hash"] != want:
            raise _fail(
                REL_STATEMENT_MISMATCH,
                f"approval by {approval['key_id']!r} names another release; "
                f"the statement_hash inside an approval is what stops it "
                f"being carried to a different one")
        key = registry.get(approval["key_id"])
        if key is None:
            raise _fail(REL_UNKNOWN_KEY,
                        f"key {approval['key_id']!r} is not in the registry")
        key_valid_at(key, witness_seq)
        if approval["role"] not in key.roles:
            raise _fail(REL_ROLE_NOT_PERMITTED,
                        f"key {key.key_id!r} is registered for {list(key.roles)} "
                        f"and this approval claims {approval['role']!r}")
        # The registry is the source of truth for who and where. An approval
        # may claim any principal and device it likes; what is counted is
        # what the registry records for the key that actually signed.
        if approval["device_id"] != key.device_id or \
                approval["principal_id"] != key.principal_id:
            raise _fail(
                REL_CONTROL_MISMATCH,
                f"approval by {key.key_id!r} claims device "
                f"{approval['device_id']!r} / principal "
                f"{approval['principal_id']!r}; the registry records "
                f"{key.device_id!r} / {key.principal_id!r}. Ownership is "
                f"declared in ONE place, under history, not repeated per "
                f"record where it can drift.")
        try:
            sig = bytes.fromhex(signed.get("signature") or "")
            public = bytes.fromhex(key.public)
        except (ValueError, TypeError):
            raise _fail(REL_BAD_SIGNATURE,
                        f"approval by {key.key_id!r}: signature or key is "
                        f"not hex") from None
        if not verify(public, approval_signing_bytes(signed), sig):
            raise _fail(REL_BAD_SIGNATURE,
                        f"approval by {key.key_id!r} does not verify under "
                        f"{prv.DOMAIN_RELEASE_APPROVAL}")
        if key.key_id in keys:
            raise _fail(REL_KEY_REUSED,
                        f"key {key.key_id!r} approved twice; two signatures "
                        f"by one key are one signature counted twice")
        if key.device_id in devices:
            raise _fail(
                REL_DEVICE_REUSED,
                f"device {key.device_id!r} carries two approvals. Two keys "
                f"on one machine close nothing that one key on it does not: "
                f"a compromised workstation holds both.")
        keys.add(key.key_id)
        devices.add(key.device_id)
        principals.add(key.principal_id)
        roles.add(approval["role"])

    for role in prv.APPROVAL_ROLES:
        if role not in roles:
            raise _fail(
                REL_ROLE_MISSING,
                f"no approval of role {role!r}. One of the two signatures "
                f"must be the signature of the ACT OF VERIFICATION, or the "
                f"control is two signatures over one person's word "
                f"(ADR-022 D2).")

    counted = {"signature_threshold": len(approvals),
               "distinct_keys": len(keys),
               "distinct_devices": len(devices),
               "distinct_principals": len(principals),
               "device_binding": statement["control"]["device_binding"]}
    recorded = statement["control"]
    for field in ("signature_threshold", "distinct_keys", "distinct_devices",
                  "distinct_principals"):
        if int(recorded[field]) != counted[field]:
            raise _fail(
                REL_CONTROL_MISMATCH,
                f"control records {field}={recorded[field]} and the "
                f"approvals count {counted[field]}. The numbers are DERIVED "
                f"from valid approvals through the registry; a recorded "
                f"number that disagrees is an independence nobody had.")
    if counted["distinct_keys"] < 2 or counted["distinct_devices"] < 2:
        raise _fail(REL_CONTROL_MISMATCH,
                    "two signatures by two distinct keys on two distinct "
                    "devices is the floor and is never lowered to one "
                    "(ADR-022 D2, D6)")
    _check_external(statement, context, approvals, registry)
    return counted


def _check_external(statement, context, approvals=(), registry=None) -> None:
    """The half of D5.4 that compares the statement with the world."""
    if context is None:
        raise _fail(
            REL_BAD_SCHEMA,
            "a verification context is required; pass "
            "ReleaseContext.internal_only() to state deliberately that no "
            "external fact is available, because a permissive default is "
            "how the weaker check becomes the usual one")
    if context.expected_tag is not None and \
            context.expected_tag != statement["version"]:
        raise _fail(
            REL_TAG_MISMATCH,
            f"the tag is {context.expected_tag!r} and the statement says "
            f"{statement['version']!r}. A release whose tag and version "
            f"disagree is two releases to anyone resolving either one.")
    if context.tree_digest is not None and \
            context.tree_digest != statement["tree_digest"]:
        raise _fail(
            REL_TREE_MISMATCH,
            f"the built tree hashes {context.tree_digest}, the statement "
            f"records {statement['tree_digest']}. This is the first link of "
            f"the chain; broken here, nothing downstream means anything.")
    _check_acceptance(statement, context.acceptance)
    _check_environment(statement, context.build_environment)
    for art in statement["artefacts"]:
        _check_bytes(context.artefact_reader, art["name"], art["sha256"],
                     f"artefact {art['name']!r}", length=art["length"])
    _check_bytes(context.bundle_reader, None, statement["bundle_hash"],
                 "release bundle")
    _check_bytes(context.recipe_reader, None, statement["recipe_hash"],
                 "build recipe")
    _check_bytes(context.sbom_reader, None, statement["sbom_hash"], "SBOM")
    _check_bytes(context.toolset_manifest_reader, None,
                 statement["toolset_manifest_hash"], "toolset manifest")
    _check_rebuild_evidence(statement, context, approvals, registry)
    _check_scope(statement, approvals)


#: The fields an independent rebuild REPRODUCES. A second builder on a host
#: of the same class runs the same recipe over the same tree and gets the
#: same artefacts; that, and not the whole document, is what
#: `reproducibility_scope` promises. Comparing the entire statement would
#: refuse a verifier for holding a different `control` block — which every
#: verifier does, because the control counts approvals that include his own.
REBUILD_REPRODUCES = ("version", "tree_digest", "tree_digest_algo",
                      "artefacts", "bundle_hash", "recipe_hash", "sbom_hash",
                      "toolset_manifest_hash")


def _check_scope(statement, approvals) -> None:
    """`reproducibility_scope` is DERIVED and compared, never believed.

    rev 2.3. The audit of recut2 placed a release tag claiming
    `cross-host-class` while nothing anywhere in the release said what
    either host was: the code accepted the stronger proof, and the evidence
    did not offer it. Now the two approvals carry `host_class` and
    `build_run_id`, the scope follows from them, and the recorded value must
    equal the computed one.
    """
    by_role = {}
    for approval in approvals:
        by_role[approval.get("role")] = approval
    builder = by_role.get(prv.ROLE_BUILDER)
    verifier = by_role.get(prv.ROLE_VERIFIER)
    if not builder or not verifier:
        return                       # role coverage has its own refusal
    derived = prv.derive_scope(builder, verifier)
    if statement["reproducibility_scope"] != derived:
        raise _fail(
            REL_SCOPE_MISMATCH,
            f"the statement records reproducibility_scope "
            f"{statement['reproducibility_scope']!r} and the two approvals "
            f"describe {derived!r} (builder {builder['host_class']!r} run "
            f"{builder['build_run_id']!r}, verifier {verifier['host_class']!r} "
            f"run {verifier['build_run_id']!r}). A scope that cannot go down "
            f"is not a measurement")


#: The outputs an independent rebuild REPRODUCES. Reproducibility is the
#: claim that two runs of one recipe over one tree produce the same bytes,
#: so these four are what the evidence and the statement must agree on.
REBUILD_REPRODUCES = ("tree_digest", "tree_digest_algo", "artefacts",
                      "bundle_hash", "recipe_hash")

EVIDENCE_FIELDS = ("schema", "statement_hash", "build_run_id", "key_id",
                   "device_id", "principal_id", "host_class",
                   "build_environment", "tree_digest", "tree_digest_algo",
                   "artefacts", "bundle_hash", "recipe_hash", "signature")


def evidence_signing_bytes(evidence) -> bytes:
    body = {k: v for k, v in evidence.items() if k != "signature"}
    return prv.signing_domain(prv.DOMAIN_REBUILD_EVIDENCE) + canonical(body)


def _check_rebuild_evidence(statement, context, approvals, registry) -> None:
    """A named rebuild must resolve, be SOMEONE ELSE'S, and agree.

    Three defects deep, and each fix exposed the next. First the field was
    checked for shape, so `9a9a…9a` published — an address with no object.
    Then the object was required to resolve and to be a `ReleaseStatement`
    agreeing with this one, and the audit of recut2 handed it THE PRIMARY
    STATEMENT: identical to itself in every field, so the comparison passed
    trivially. Resolvability had been proved; independence had not.

    rev 2.3 gives the evidence its own schema and its own signature. The
    object cannot be the statement, cannot be signed by the builder, and
    cannot describe the same run — and it must still agree, byte for byte,
    on everything a rebuild reproduces.
    """
    for approval in approvals:
        digest = approval.get("verification_evidence_hash")
        if not digest:
            continue
        if context.evidence_reader is None:
            # NOT a skip. This line was `continue`, and the audit of recut3
            # built a permitting authorization callback from a publication
            # whose evidence did not exist, by handing verification a
            # context with no reader: absent reader, absent check, present
            # permission. An approval names evidence; a verifier who cannot
            # read it has not verified the approval.
            raise _fail(
                REL_EVIDENCE_UNRESOLVED,
                f"the approval of {approval['key_id']!r} names rebuild "
                f"evidence and the context has no evidence reader. An "
                f"absent reader is a gate that silently passes")
        try:
            raw = context.evidence_reader(digest)
        except Exception as e:                                 # noqa: BLE001
            raise _fail(
                REL_EVIDENCE_UNRESOLVED,
                f"the rebuild evidence named by {approval['key_id']!r} "
                f"({digest[:12]}…) could not be read: {e}. A verifier's "
                f"approval is the signature of an ACT; evidence that does "
                f"not resolve leaves the signature over nothing") from None
        if not raw:
            raise _fail(
                REL_EVIDENCE_UNRESOLVED,
                f"the rebuild evidence named by {approval['key_id']!r} "
                f"({digest[:12]}…) resolves to no bytes")
        got = H_hex(raw)
        if got != digest:
            raise _fail(
                REL_EVIDENCE_UNRESOLVED,
                f"the evidence supplied for {approval['key_id']!r} hashes "
                f"{got}, the approval names {digest}")
        try:
            evidence = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise _fail(
                REL_EVIDENCE_DIVERGENT,
                f"the rebuild evidence of {approval['key_id']!r} is not a "
                f"readable document; it must be a "
                f"{prv.SCHEMA_REBUILD_EVIDENCE}") from None
        _check_one_evidence(statement, evidence, approval, approvals,
                            registry, context)


def _check_one_evidence(statement, evidence, approval, approvals, registry,
                        context) -> None:
    if not isinstance(evidence, dict) or \
            evidence.get("schema") != prv.SCHEMA_REBUILD_EVIDENCE:
        # THE ONE THAT CLOSES SELF-EVIDENCE. A `ReleaseStatement` cannot
        # declare this schema, so the primary object can no longer be
        # offered as the proof that it was independently rebuilt.
        raise _fail(
            REL_EVIDENCE_NOT_INDEPENDENT,
            f"the evidence declares schema {evidence.get('schema')!r}; a "
            f"rebuild is witnessed by a {prv.SCHEMA_REBUILD_EVIDENCE}, and "
            f"the release statement is not evidence about itself")
    missing = [f for f in EVIDENCE_FIELDS if not evidence.get(f)]
    if missing:
        raise _fail(REL_BAD_SCHEMA,
                    f"rebuild evidence omits {missing}")
    want = statement_hash(statement)
    if evidence["statement_hash"] != want:
        raise _fail(
            REL_STATEMENT_MISMATCH,
            f"the rebuild evidence names statement {evidence['statement_hash']!r}"
            f" and this release hashes {want}")

    # WHOSE ACT IT WAS. The evidence must belong to the approval that names
    # it, and be signed by that key — a rebuild signed by the builder is the
    # builder performing both roles under two names.
    for field in ("key_id", "device_id", "principal_id"):
        if evidence[field] != approval[field]:
            raise _fail(
                REL_EVIDENCE_NOT_INDEPENDENT,
                f"the rebuild evidence records {field}={evidence[field]!r} "
                f"and the approval naming it records {approval[field]!r}. "
                f"The evidence is the act of the verifier who signs for it")
    key = registry.get(evidence["key_id"]) if registry else None
    if key is None:
        raise _fail(REL_UNKNOWN_KEY,
                    f"rebuild evidence signed by {evidence['key_id']!r}, "
                    f"which is not in the registry")
    try:
        sig = bytes.fromhex(evidence.get("signature") or "")
        public = bytes.fromhex(key.public)
    except (ValueError, TypeError):
        raise _fail(REL_BAD_SIGNATURE,
                    "rebuild evidence signature or key is not hex") from None
    if not verify(public, evidence_signing_bytes(evidence), sig):
        raise _fail(
            REL_BAD_SIGNATURE,
            f"the rebuild evidence of {key.key_id!r} does not verify under "
            f"{prv.DOMAIN_REBUILD_EVIDENCE}")

    # A DIFFERENT RUN. Same id means one build signed twice, which is the
    # control D2 describes in numbers being satisfied by arithmetic.
    for other in approvals:
        if other.get("role") == prv.ROLE_BUILDER and \
                other.get("build_run_id") == evidence["build_run_id"]:
            raise _fail(
                REL_EVIDENCE_NOT_INDEPENDENT,
                f"the rebuild evidence carries build_run_id "
                f"{evidence['build_run_id']!r}, the same run the builder "
                f"approved. One run repeated is the machine repeated")
    if evidence["build_run_id"] != approval["build_run_id"] or \
            evidence["host_class"] != approval["host_class"]:
        raise _fail(
            REL_EVIDENCE_NOT_INDEPENDENT,
            "the rebuild evidence and the approval that names it describe "
            "different runs or different host classes; the approval is the "
            "signature OF this act, not a signature beside it")

    # AND IT MUST AGREE. This is the reproducibility claim itself.
    for field in REBUILD_REPRODUCES:
        if canonical(evidence[field]) != canonical(statement[field]):
            raise _fail(
                REL_EVIDENCE_DIVERGENT,
                f"the independent rebuild by {approval['key_id']!r} "
                f"produced a different {field}. Two runs of one recipe over "
                f"one tree that disagree are the finding, not a detail")
    _check_environment(statement, evidence["build_environment"])


# --------------------------------------------------------------------------- #
# D5.5 · the order, and the publication
# --------------------------------------------------------------------------- #

def toolset_authorizer(publication, *, chain, registry, context,
                       node_public: bytes = None):
    """A resolver of toolset authorization POSITIONS, from a verified release.

    D10 keeps `release_signing` and `toolset_authorization` apart so that
    whoever can cut a build cannot thereby widen a being's hand. The link
    between them is `toolset_manifest_hash` inside the `ReleaseStatement`:
    the release NAMES which manifest it carries without sanctioning it.

    That name is also the only honest answer to "authorized when?". The
    manifest cannot say — it would be dating itself — and the loader cannot
    know, holding no chain. So the party holding both resolves the
    publication, checks it names this manifest, and answers with the actual
    index of its `RELEASE_ATTESTED` record.
    """
    # A PERMITTING CALLBACK IS A BOUNDARY, and it gets the boundary's
    # checks. `verify_publication` alone is diagnostic: with a partial
    # context it skips whatever it cannot read, which is the right thing for
    # a diagnosis and the wrong thing for a permission. The audit of recut3
    # built an authorizer from a publication whose rebuild evidence did not
    # exist, simply by passing `evidence_reader=None`, and it answered 0.
    context.require_complete("resolving toolset authorization")
    # A CONSUMED publication is judged by the same ledger as a produced one.
    # `publish()` refusing on `publication` debt protects the node that
    # publishes; a node that IMPORTS a publication built elsewhere must
    # refuse on the same boundary, or the debt blocks only the honest path.
    _check_debt(context, prv.BLOCKS_PUBLICATION,
                "consuming a publication for toolset authorization")
    verify_publication(publication, chain=chain, registry=registry,
                       context=context, node_public=node_public)
    # VALUES, captured now — and the object SNAPSHOTTED. recut4 captured
    # `expected` and `index` so that editing the caller's dict afterwards
    # could not move the permission. The audit of recut6 found the other
    # half: a revocation AFTER the callback was built did not move it
    # either, because currency was judged once, at creation. So the
    # publication is copied here, beyond the caller's reach, and re-verified
    # against the LIVE chain on every use: the identity of what was
    # permitted is immutable, the fact that it is still permitted is not.
    snapshot = copy.deepcopy(publication)
    expected = str(snapshot["attestation"]["statement"]
                   ["toolset_manifest_hash"])
    index = int(snapshot["witness_ref"]["index"])

    def authorize(manifest_hash: str) -> int:
        verify_publication(snapshot, chain=chain, registry=registry,
                           context=context, node_public=node_public)
        if expected != manifest_hash:
            raise _fail(
                REL_TOOLSET_AUTHZ_UNRESOLVED,
                f"this manifest hashes {manifest_hash}, and the release at "
                f"witness position {index} carries {expected}. A manifest "
                f"is authorized by the release that NAMES it, never by one "
                f"that happens to be nearby")
        return index

    return authorize


def _check_debt(context, boundary: str, what: str) -> None:
    """The ledger is the source of truth for the boundary it NAMES.

    `architecture_status.json :: release_debt` carries `blocks` on every
    position — `publication`, `meaning-of-a-release-tag`,
    `byte-exactness-of-the-tree`, `phase-0-gate` — and until this recut no
    code read it. The audit tagged a release with four positions open under
    `meaning-of-a-release-tag`, which is exactly the one prohibition D13
    states: presenting an unclosed drop as a release. A ledger that governs
    documentation and not the boundary it names is a table, not a control.

    The projection is `provenance.load_debt_ledger`, the one that already
    refuses a history not starting with DEBT_OPENED and a terminal event
    without its reference — not a second scan written here, because two
    implementations of one projection disagree the moment one is fixed.
    """
    if context is None or context.debt_reader is None:
        raise _fail(
            REL_DEBT_OPEN,
            f"{what} requires the debt ledger; without it the gate passes "
            f"silently, which is how the ledger became a table")
    try:
        status = context.debt_reader()
        states = prv.load_debt_ledger(status)
        blocks = {e["id"]: e.get("blocks")
                  for e in status["release_debt"]["events"]}
    except Exception as e:                                     # noqa: BLE001
        raise _fail(REL_DEBT_OPEN,
                    f"the debt ledger could not be projected: {e}") from None
    open_here = sorted(pos for pos, state in states.items()
                       if state == prv.DEBT_OPEN
                       and blocks.get(pos) == boundary)
    if open_here:
        raise _fail(
            REL_DEBT_OPEN,
            f"{what} is refused: {len(open_here)} debt position(s) open "
            f"under {boundary!r} — {', '.join(open_here)}. A position is "
            f"closed by an event with an evidence_ref, never by cutting "
            f"anyway (ADR-022 D13, D14)")


def release_provenance(attestation) -> dict:
    """The four fields D5.5 step 4 puts in the record.

    The chain stores only `provenance_hash` — the witness keeps the hash and
    the pre-image stays with whoever holds the object, which is the same
    discipline as every other record here. So the publication carries the
    pre-image and verification RECOMPUTES the hash rather than reading
    fields out of a record that does not hold them.
    """
    statement = attestation["statement"]
    return {"attestation_hash": attestation_hash(attestation),
            "statement_hash": attestation["statement_hash"],
            "version": statement["version"],
            "tree_digest": statement["tree_digest"]}


def _chain_is_sound_or_refuse(chain, node_public: bytes = None) -> None:
    """A write into a chain that does not verify is a write into rubble.

    The audit of recut7 broke the signature of an earlier record, saw
    `verify_chain()` go False, and called `publish()`: it appended. The
    next verification refused, correctly — and one record too late for an
    append-only history, which cannot take the record back. Integrity is a
    PRECONDITION of writing, checked under the same hold as the write; the
    verifier's check after the fact is the second line, not the first.
    """
    if not chain.verify_chain(node_public):
        raise _fail(
            REL_WITNESS_UNRESOLVED,
            "the witness chain does not verify — hashes, links or node "
            "signatures are broken — and nothing is written into it. A "
            "record appended to a chain that cannot be trusted would be the "
            "one true record in a history nobody can read")


def publish(attestation, *, chain, registry, context) -> dict:
    """Steps 3–5 of D5.5, in order, or nothing at all.

    An unfinished release does not reach the WitnessChain (O-9). Everything
    that could refuse has refused before `append` is called, so a failed
    attempt leaves a local record with a reason code and no witness entry to
    retract — which is why neither a TTL nor a revocation is needed for a
    device that died before the second signature.
    """
    # ATOMIC. Reading the position, verifying against it and appending must
    # happen under one hold of the chain lock. Without it a concurrent
    # append lands between the read and the write, the record takes a
    # different index, and the release is published as valid at one position
    # and then verified as INVALID at its real one — the audit produced
    # exactly that with a concurrent INFER and a key revoked at index 1.
    # `WitnessChain.lock` is an RLock, so the nested append is fine.
    context.require_complete("publishing a release")
    _check_debt(context, prv.BLOCKS_PUBLICATION, "publishing a release")
    with chain.lock:
        # UNDER THE HOLD, not before it. recut6 ran the lifecycle and
        # revocation checks and THEN took the lock; the audit slid a
        # RELEASE_REVOKED in between, and publish() returned a publication
        # at position 4 whose immediate verification said revoked at 3. The
        # state a release is judged against and the state it is written
        # into must be one state, and the lock is what makes them one.
        _chain_is_sound_or_refuse(chain)
        check_lifecycle_witnessed(registry, chain=chain)
        _check_not_revoked(attestation["statement"], chain=chain,
                           registry=registry, context=context)
        seq = chain.next_index()  # the position the record WILL take
        verify_attestation(attestation, registry=registry,
                           witness_seq=seq, context=context)
        digest = attestation_hash(attestation)
        provenance = release_provenance(attestation)
        # The position is re-read INSIDE the same hold rather than compared
        # afterwards. The earlier shape verified for `seq`, appended, and
        # raised if the index differed — but by then the RELEASE_ATTESTED
        # record was already in the chain and on disk, so "abandoned" was
        # a word about a record that exists forever. An append-only store
        # has no undo; the only place to refuse is BEFORE the write.
        actual = chain.next_index()
        if actual != seq:
            raise _fail(
                REL_WITNESS_UNRESOLVED,
                f"the chain moved from {seq} to {actual} between reading "
                f"the position and writing: the approvals were verified "
                f"against key validity at {seq}. Nothing is written — a "
                f"release abandoned after the record lands is not abandoned")
        record = chain.append(prv.KIND_RELEASE_ATTESTED,
                              semantic_digest=digest, provenance=provenance)
    statement = attestation["statement"]
    return {"schema": prv.SCHEMA_RELEASE_PUBLICATION,
            "attestation": attestation,
            "witness_ref": {"index": record["index"],
                            "this_hash": record["this_hash"],
                            "provenance": provenance}}


def verify_publication(publication, *, chain, registry, context,
                       node_public: bytes = None) -> dict:
    """Resolve `witness_ref` and check the attestation at ITS position.

    Substitution of the reference is caught by RESOLUTION rather than by a
    signature — the reference is outside the hashed object by construction,
    so nothing signs it. It must resolve, name a `RELEASE_ATTESTED`, carry
    the same two hashes, and be integrity-valid. Same rule ADR-018 rev 2
    applies to `evidence_refs`.
    """
    if publication.get("schema") != prv.SCHEMA_RELEASE_PUBLICATION:
        raise _fail(REL_BAD_SCHEMA,
                    f"publication must declare "
                    f"{prv.SCHEMA_RELEASE_PUBLICATION!r}")
    # Both paths, not one. recut1 had this check written and called from
    # nowhere; a verifier who skips it reads a registry whose revocation
    # position may sit in a future the chain never reaches, which is the
    # same key silently valid for every release he is about to accept.
    check_lifecycle_witnessed(registry, chain=chain)
    _check_not_revoked(publication["attestation"]["statement"], chain=chain,
                       registry=registry, context=context)
    attestation = publication.get("attestation")
    ref = publication.get("witness_ref") or {}
    # INTEGRITY-VALID, in the ADR's own words, means the chain verifies —
    # not that one field matches a value taken from the same object being
    # checked. The audit edited a signed `timestamp` after publication:
    # `verify_chain()` went False and `verify_publication()` still accepted,
    # because the only hash it compared came out of the reference it was
    # asked to trust.
    if not chain.verify_chain(node_public):
        raise _fail(
            REL_WITNESS_UNRESOLVED,
            "the witness chain does not verify: hashes, links or node "
            "signatures are broken. A reference into a chain that has been "
            "edited resolves to nothing trustworthy, whatever it points at.")
    try:
        record = chain.records[int(ref.get("index"))]
    except (TypeError, ValueError, IndexError):
        raise _fail(REL_WITNESS_UNRESOLVED,
                    "witness_ref does not resolve in this chain") from None
    if record.get("kind") != prv.KIND_RELEASE_ATTESTED:
        raise _fail(REL_WITNESS_UNRESOLVED,
                    f"witness_ref names a {record.get('kind')!r} record")
    if record.get("this_hash") != ref.get("this_hash"):
        raise _fail(REL_WITNESS_UNRESOLVED,
                    "witness_ref names a record whose hash has changed")
    # The record holds `provenance_hash`, not the fields. So the pre-image
    # travels in the reference and is checked BOTH ways: it must hash to
    # what the record committed to, and it must describe THIS attestation.
    # Either check alone is bypassable — the first by supplying a matching
    # pre-image for some other record, the second by supplying a pre-image
    # the record never committed to.
    claimed = ref.get("provenance")
    if not isinstance(claimed, dict):
        raise _fail(REL_WITNESS_UNRESOLVED,
                    "witness_ref carries no provenance pre-image; the record "
                    "commits to a hash and the fields must come with it")
    if H_hex(canonical(claimed)) != record.get("provenance_hash"):
        raise _fail(REL_WITNESS_UNRESOLVED,
                    "the provenance pre-image does not hash to what the "
                    "record committed to")
    if claimed != release_provenance(attestation):
        raise _fail(
            REL_WITNESS_UNRESOLVED,
            "the record commits to a different attestation. Because "
            "witness_ref is outside the hashed object, a swapped reference "
            "is caught here and only here.")
    return verify_attestation(attestation, registry=registry,
                              witness_seq=int(ref["index"]),
                              context=context)


# --------------------------------------------------------------------------- #
# D13 · what each tag asserts, and what it refuses to
# --------------------------------------------------------------------------- #

TAG_PREFLIGHT = "preflight"
TAG_RELEASE = "release"

REL_TAG_FORBIDDEN = "REL_TAG_FORBIDDEN"

#: The four things D13 forbids outright. Named as data so a refusal cites
#: the prohibition rather than paraphrasing it, and so a reader can see the
#: whole list without reading the function.
TAG_PROHIBITIONS = (
    "an unclosed drop presented as a release",
    "two-key presented as two-person",
    "a digest printed without the name of its algorithm",
    "a release tag on a same-host rebuild",
)


def preflight_annotation(*, version: str, tree_digest: str,
                         tree_digest_algo: str, acceptance: str) -> str:
    """The annotation of `vX.Y.Z-preflight`.

    It names a commit and asserts NOTHING about provenance. The wording
    says so in the tag itself rather than in a document beside it, because
    a caveat that travels separately from the object it qualifies does not
    travel.
    """
    if not tree_digest_algo:
        raise _fail(REL_TAG_FORBIDDEN,
                    "a digest without the name of its algorithm is "
                    "forbidden in a tag annotation (ADR-022 D13)")
    return "\n".join([
        f"JJ DAI {version} preflight — NOT a release.",
        "",
        "Names a commit; asserts nothing about provenance. SBOM present as",
        "an inventory, but the build is not reproducible here and the",
        "artefacts are not signed. Does not consume the version number.",
        "",
        f"tree_digest      {tree_digest}",
        f"tree_digest_algo {tree_digest_algo}",
        f"acceptance       {acceptance}",
    ])


def release_annotation(publication, *, chain, registry, context,
                       node_public: bytes = None) -> str:
    """The annotation of a release tag, carrying D13's list verbatim.

    Every line here is a fact a reader can resolve: the attestation by its
    hash, the record by its reference, the tree by its digest AND the name
    of the algorithm that produced it, and the control as NUMBERS. A tag
    that says "two-person approved" where two keys were held by one person
    would put an independence nobody had into the most quoted artefact of
    the release.
    """
    # COUNTED HERE, from the verified path. The numbers used to arrive as
    # an argument, and the audit of recut2 printed an annotation claiming 99
    # keys, 99 principals and `device_binding: attested` — an independence
    # nobody had, in the most quoted artefact of the release, produced by
    # the one function whose whole subject is that the control is numbers
    # rather than a name.
    counted = verify_publication(publication, chain=chain, registry=registry,
                                 context=context, node_public=node_public)
    attestation = publication["attestation"]
    statement = attestation["statement"]
    ref = publication["witness_ref"]
    if counted["distinct_principals"] < 2 and \
            statement["control"]["device_binding"] != \
            prv.DEVICE_BINDING_ASSERTED:
        raise _fail(REL_TAG_FORBIDDEN,
                    "device_binding must be 'asserted' while separateness "
                    "is an operator's word (ADR-022 D2)")
    prv.check_scope_allows_release(statement["reproducibility_scope"])
    return "\n".join([
        f"JJ DAI {statement['version']}",
        "",
        f"attestation_hash   {attestation_hash(attestation)}",
        f"witness_ref        index={ref['index']} "
        f"this_hash={ref['this_hash']}",
        f"statement_hash     {attestation['statement_hash']}",
        f"tree_digest        {statement['tree_digest']}",
        f"tree_digest_algo   {statement['tree_digest_algo']}",
        f"reproducibility    {statement['reproducibility_scope']}",
        "control            " + json.dumps(counted, sort_keys=True),
    ])


def check_release_tag(tag_name: str, publication, *, chain, registry,
                      context, node_public: bytes = None) -> dict:
    """Everything a release tag asserts, verified before it is placed.

    `tag name == ReleaseStatement.version` is checked HERE as well as in the
    context, because the tag is the name a reader resolves by: a tag and a
    version that disagree are two releases to anyone holding either one.
    """
    context.require_complete("placing a release tag")
    _check_debt(context, prv.BLOCKS_RELEASE_TAG, "placing a release tag")
    counted = verify_publication(publication, chain=chain, registry=registry,
                                 context=context, node_public=node_public)
    statement = publication["attestation"]["statement"]
    if tag_name != statement["version"]:
        raise _fail(REL_TAG_MISMATCH,
                    f"tag {tag_name!r} against version "
                    f"{statement['version']!r}")
    if tag_name.endswith("-" + TAG_PREFLIGHT):
        raise _fail(REL_TAG_FORBIDDEN,
                    "a preflight tag asserts nothing about provenance and "
                    "must not carry a release attestation; presenting an "
                    "unclosed drop as a release is the first prohibition of "
                    "D13")
    return counted


# --------------------------------------------------------------------------- #
# D6 · the key lifecycle, resolved in the chain rather than declared in JSON
# --------------------------------------------------------------------------- #

KEY_ACTIVATED = "KEY_ACTIVATED"
KEY_REVOKED = "KEY_REVOKED"
RELEASE_REVOKED = "RELEASE_REVOKED"


LIFECYCLE_ASSERTED = "asserted"
LIFECYCLE_WITNESSED = "witnessed"

#: The debt position that stands where the witnessed lifecycle would be.
LIFECYCLE_DEBT = "release-key-lifecycle-witnessing"


def key_lifecycle_digest(key_id: str, transition: str, public_hex: str) -> str:
    """The semantic_digest a KEY_ACTIVATED / KEY_REVOKED record binds.

    Names the key by id AND by public key, and the transition by word, so
    that a position cannot be satisfied by the other transition of the same
    key, nor by the same transition of a key that later reused the id.
    """
    if transition not in ("activated", "revoked"):
        raise ValueError(transition)
    return H_hex(prv.hash_prefix(prv.PREFIX_KEY_LIFECYCLE)
                 + canonical({"key_id": key_id, "transition": transition,
                              "public": public_hex}))


def lifecycle_projection(chain, key) -> dict:
    """What the CHAIN says about a key: every transition, by position.

    The registry is checked against this, not the other way round. The
    audit of recut6 wrote a KEY_REVOKED record for a key and handed
    `check_lifecycle_witnessed` a registry still saying `revoked: None` —
    and it passed, because it verified only the positions the registry chose
    to present. A chain that proves the correctness of the reference shown
    and nothing about the ones withheld proves the wrong thing: the whole
    point of witnessing a revocation is that a registry cannot forget it.
    """
    found = {"activated": [], "revoked": []}
    for record in chain.records:
        kind = record.get("kind")
        if kind == prv.KIND_KEY_ACTIVATED:
            transition = "activated"
        elif kind == prv.KIND_KEY_REVOKED:
            transition = "revoked"
        else:
            continue
        want = key_lifecycle_digest(key.key_id, transition, key.public)
        if record.get("semantic_digest") == want:
            found[transition].append(int(record["index"]))
    return found


def check_lifecycle_witnessed(keys, *, chain) -> None:
    """Every declared position resolves to a record that NAMES the transition.

    Third version of this function, and the first that does what its name
    says. recut1 promised to read the record's pre-image and threw the
    record away; recut2 said so honestly and checked only that the position
    was not past the end of the chain, because KEY_ACTIVATED did not exist
    in the witness vocabulary and a build does not reopen a frozen reserve.
    ADR-022 rev 2.4 reopened it, before first emission, with the two kinds —
    and now the record at the position must be of the right kind and carry
    `key_lifecycle_digest(key_id, transition, public)` as its semantic
    digest. A registry cannot move a key's activation by editing a digit:
    the digit points at a record, and the record names the key.

    Position 0 on an empty chain is no longer a convention: activation is
    witnessed BEFORE the key signs anything, so the first release of a
    node sits after its keys' activation records.
    """
    for key in keys.values():
        for position, kind, transition in (
                (key.activated, prv.KIND_KEY_ACTIVATED, "activated"),
                (key.revoked, prv.KIND_KEY_REVOKED, "revoked")):
            if position is None:
                continue
            try:
                record = chain.records[int(position)]
            except (TypeError, ValueError, IndexError):
                raise _fail(
                    REL_LIFECYCLE_UNWITNESSED,
                    f"key {key.key_id!r} declares {kind} at witness position "
                    f"{position!r} and no record sits there. A position that "
                    f"resolves to nothing is a number in a file, and a "
                    f"number in a file is an assertion") from None
            if record.get("kind") != kind:
                raise _fail(
                    REL_LIFECYCLE_UNWITNESSED,
                    f"key {key.key_id!r} declares {kind} at {position}, and "
                    f"the record there is a {record.get('kind')!r}. Six INFER "
                    f"records do not witness an activation, whatever index "
                    f"they happen to occupy")
            want = key_lifecycle_digest(key.key_id, transition, key.public)
            if record.get("semantic_digest") != want:
                raise _fail(
                    REL_LIFECYCLE_UNWITNESSED,
                    f"the {kind} record at {position} does not name key "
                    f"{key.key_id!r} with this public key and this "
                    f"transition. A lifecycle record witnesses ONE key's ONE "
                    f"transition, and this one witnesses something else")
        # COMPLETENESS, not only correctness. Whatever the chain holds about
        # this key, the registry must show — the first activation and the
        # first revocation, at those positions. A revocation the chain
        # witnessed and the registry omits is a key kept alive by silence.
        chain_says = lifecycle_projection(chain, key)
        for transition, declared in (("activated", key.activated),
                                     ("revoked", key.revoked)):
            positions = chain_says[transition]
            first = positions[0] if positions else None
            if declared is None and first is not None:
                raise _fail(
                    REL_LIFECYCLE_HIDDEN,
                    f"the chain witnesses key {key.key_id!r} {transition} "
                    f"at position {first} and the registry declares no "
                    f"{transition} at all. A registry does not get to "
                    f"forget a transition the chain remembers")
            if declared is not None and first is not None \
                    and int(declared) != first:
                raise _fail(
                    REL_LIFECYCLE_HIDDEN,
                    f"key {key.key_id!r} was first {transition} at position "
                    f"{first} and the registry declares {declared}. The "
                    f"earliest witnessed transition is the one that counts; "
                    f"a later one cannot be presented in its place")


def revocation_digest(statement_hash: str) -> str:
    """What a RELEASE_REVOKED record binds: the release, by statement hash."""
    return H_hex(prv.hash_prefix(prv.PREFIX_RELEASE_REVOKED)
                 + canonical({"statement_hash": statement_hash}))


REVOCATION_FIELDS = ("schema", "statement_hash", "key_id", "reason",
                     "signature")


def revocation_signing_bytes(revocation) -> bytes:
    body = {k: v for k, v in revocation.items() if k != "signature"}
    return prv.signing_domain(prv.DOMAIN_RELEASE_REVOKE) + canonical(body)


def revoke_release(statement_hash: str, *, key_id: str, reason: str,
                   signing_key, chain, registry) -> dict:
    """Revoke a release BY NAME: a signed statement, then a witness record.

    ADR-022 D6, closed by rev 2.4. Where the moment of a key's compromise is
    unknown, voiding the key's whole history would take down releases that
    were sound; the release is named instead, forward, and its record stays
    in the chain — a revocation is an event after the fact, not an edit of
    it. The signature is checked here under the registry key BEFORE the
    record is written, so the chain never carries a revocation nobody was
    entitled to make.
    """
    if not reason or not isinstance(reason, str):
        raise _fail(REL_BAD_SCHEMA, "a revocation names its reason")
    key = registry.get(key_id)
    if key is None:
        raise _fail(REL_UNKNOWN_KEY, f"revoking key {key_id!r} is not registered")
    body = {"schema": prv.SCHEMA_RELEASE_REVOCATION,
            "statement_hash": statement_hash, "key_id": key_id,
            "reason": reason}
    body["signature"] = signing_key.sign(revocation_signing_bytes(body)).hex()
    # VERIFIED UNDER THE REGISTRY, not trusted because we just signed it.
    # The audit of recut6 passed the verifier's private key with
    # `key_id="kb"`: the body was signed, by the wrong key, and appended —
    # an invalid revocation in an append-only chain, which the fail-closed
    # rule below then honoured as a revocation. The docstring promised this
    # check; the body did not contain it.
    try:
        ok = verify(bytes.fromhex(key.public), revocation_signing_bytes(body),
                    bytes.fromhex(body["signature"]))
    except (ValueError, TypeError):
        ok = False
    if not ok:
        raise _fail(
            REL_BAD_SIGNATURE,
            f"the revocation does not verify under the registered public "
            f"key of {key_id!r}. Nothing is written: the chain is "
            f"append-only, and a revocation nobody was entitled to make "
            f"would stand in it forever")
    # ONE STATE. The position validity is judged at must be the position
    # the record takes; between a `next_index()` read and an `append` an
    # unrelated write can move it, and a key revoked in that gap would
    # revoke under a dead key. Same discipline as `publish`.
    with chain.lock:
        # THE SAME PRECONDITIONS AS A PUBLICATION. The audit of recut7
        # revoked a release with a key the chain had already witnessed as
        # revoked, by handing this function a registry that still said
        # `revoked: None` — `key_valid_at` reads the registry's fields, and
        # the registry was stale. So the chain is checked to be sound, the
        # registry is checked against the chain's own lifecycle projection
        # (a hidden revocation refuses), and only then is the key judged at
        # the position the record will take. One state, one hold.
        _chain_is_sound_or_refuse(chain)
        check_lifecycle_witnessed({key_id: key}, chain=chain)
        seq = chain.next_index()
        key_valid_at(key, seq)
        record = chain.append(prv.KIND_RELEASE_REVOKED, provenance=body,
                              semantic_digest=revocation_digest(
                                  statement_hash))
        assert record["index"] == seq
    return body


def _check_not_revoked(statement, *, chain, registry, context) -> None:
    """A revoked release verifies as REVOKED — never as a release.

    The scan is by recomputed digest, so it needs no body; the body is read
    only when a record is found, through `revocation_reader`, and a record
    whose body cannot be read or does not verify still REFUSES: an
    unverifiable revocation is treated as a revocation, because the
    alternative is a chain where the way to un-revoke a release is to lose
    its statement.
    """
    want = revocation_digest(statement_hash(statement))
    for record in chain.records:
        if record.get("kind") != prv.KIND_RELEASE_REVOKED or \
                record.get("semantic_digest") != want:
            continue
        index = record.get("index")
        if context is None or context.revocation_reader is None:
            raise _fail(
                REL_REVOKED_UNRESOLVED,
                f"witness record {index} revokes this release and the "
                f"context has no revocation reader; a revocation that cannot "
                f"be read is not thereby lifted")
        try:
            raw = context.revocation_reader(record.get("provenance_hash"))
            body = json.loads(raw.decode("utf-8"))
        except Exception as e:                                 # noqa: BLE001
            raise _fail(REL_REVOKED_UNRESOLVED,
                        f"the revocation at {index} could not be read: "
                        f"{e}") from None
        if H_hex(canonical(body)) != record.get("provenance_hash") or \
                body.get("schema") != prv.SCHEMA_RELEASE_REVOCATION or \
                any(not body.get(f) for f in REVOCATION_FIELDS):
            raise _fail(REL_REVOKED_UNRESOLVED,
                        f"the revocation body at {index} is not the one the "
                        f"record binds, or is not a release revocation")
        # THREE VALUES, ONE RELEASE. The record was found by the digest of
        # THIS statement; the body must name this statement too, and the
        # record's digest must be the digest OF the body's target. The audit
        # of recut6 bound a signed revocation of release B under the record
        # digest of release A, and A verified as revoked on B's signature.
        target = statement_hash(statement)
        if body["statement_hash"] != target or \
                revocation_digest(body["statement_hash"]) != want:
            raise _fail(
                REL_REVOKED_UNRESOLVED,
                f"the revocation at {index} is bound to this release by its "
                f"record and names {body['statement_hash'][:12]}… in its "
                f"signed body. A signature over one release is not a "
                f"revocation of another, and a record that says otherwise "
                f"is unresolved, not honoured")
        key = registry.get(body["key_id"]) if registry else None
        if key is None:
            raise _fail(REL_REVOKED_UNRESOLVED,
                        f"the revocation at {index} names key "
                        f"{body['key_id']!r}, which is not registered")
        try:
            ok = verify(bytes.fromhex(key.public),
                        revocation_signing_bytes(body),
                        bytes.fromhex(body["signature"]))
        except (ValueError, TypeError):
            ok = False
        if not ok:
            raise _fail(REL_REVOKED_UNRESOLVED,
                        f"the revocation at {index} does not verify under "
                        f"{body['key_id']!r}")
        key_valid_at(key, int(index))
        raise _fail(
            REL_REVOKED,
            f"this release was revoked by name at witness position {index} "
            f"by {body['key_id']!r}: {body['reason']}. The attestation is "
            f"intact and the record is where it was; what changed is a "
            f"later, signed fact about it")


#: The constant that stood here in recut1–recut5 said named revocation was
#: OWED. rev 2.4 delivered it; the ledger records the closure.
RELEASE_REVOKED_DELIVERED = "ADR-022 rev 2.4"
