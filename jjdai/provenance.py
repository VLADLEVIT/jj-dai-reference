# -*- coding: utf-8 -*-
"""
jjdai.provenance — the ADR-022 vocabulary, frozen before its first emission
===========================================================================
ADR-022 rev 2.2 (Accepted, 27 Aug 2026) names one concern: **the provenance
of executable code**. Which tree, by which recipe, into which artefacts,
checked by whom and by what independent act. The chain breaks the same way
at every link, so its vocabulary lives in one module rather than being spelt
where each consumer happens to need it.

HOW THIS RESERVE DIFFERS FROM THE OTHER TWO, AND WHY THAT IS NOT A LAPSE.
`jjdai.cognitive` (ADR-018) and `jjdai.custody` (ADR-019) freeze names that
NOTHING may emit: their semantics land in Ф2–Ф3, so every one of those kinds
refuses at the door of the witness chain. This module freezes names that
**this drop emits**. The roadmap draws the line explicitly (r6.9.1, the
freeze table): tracks V and VI freeze names in Ф0 and schemas in Ф2, because
they emit nothing until then; window 6 freezes **names AND schemas whole**,
before the first emission in v0.6.9, because a signature covers a canonical
encoding and changing that encoding after the first emission is a migration
rather than a clarification.

So `RELEASE_ATTESTED` enters the canonical witness enum as an EMITTABLE kind
and deliberately not as a reserved one. Putting it in `RESERVED_KINDS` would
be the tidy-looking mistake: the drop that declares it is the drop that
writes it.

TWO SEPARATORS ARE SIGNING DOMAINS AND ONE IS NOT, AND THE DIFFERENCE IS
ENFORCED HERE RATHER THAN DESCRIBED.  `JJDAI:RELEASE:APPROVAL:v1` and
`JJDAI:TOOLSET:MANIFEST:v1` are the domains under which bytes are SIGNED.
`JJDAI:RELEASE:ATTESTATION:v1` is the pre-image prefix of a HASH and, since
rev 2.2 removed the redundant statement signature, is not a signing domain
at all. All three are the same shape of string, which is precisely why a
function that accepted any of them for any purpose would turn the
distinction into prose. `signing_domain()` refuses the hash prefix by name
and `hash_prefix()` refuses the two signing domains; both fail closed.

TWO KEY DOMAINS, TWO FUNCTIONS, AND NO KEY THAT DOES BOTH (D10).
`release_signing` says a bundle came from a recipe and went out with a
release. `toolset_authorization` sanctions an L2 mutation — the reach of a
being's hand widens. One key on both roles would mean that whoever can cut a
build can thereby extend a being's authority. The two are bound only by
`toolset_manifest_hash` inside the `ReleaseStatement`: a release NAMES the
manifest it carries and does not sanction it by carrying it.
"""
from __future__ import annotations

from collections import namedtuple


class ProvenanceValueError(ValueError):
    """A release-provenance value was used outside its declared role.

    ValueError for the same reason `ReservedValueError` is one: the witness
    chain already refuses with ValueError and a caller that catches one
    should catch both.
    """


# --------------------------------------------------------------------------- #
# Schemas — frozen whole, not by name only
# --------------------------------------------------------------------------- #
#
# Six ids. `jjdai.source-tree/v2` is the odd one out: it names a DIGEST
# ALGORITHM rather than a document shape, and it is written beside every
# digest it produces (D11). A digest without the name of the algorithm that
# made it compares to nothing — two algorithms give strings that look alike
# and mean different things.

SCHEMA_RELEASE_STATEMENT = "jjdai.release-statement/v1"
SCHEMA_RELEASE_APPROVAL = "jjdai.release-approval/v1"
SCHEMA_RELEASE_ATTESTATION = "jjdai.release-attestation/v1"
SCHEMA_RELEASE_PUBLICATION = "jjdai.release-publication/v1"
SCHEMA_TOOLSET_MANIFEST = "jjdai.toolset-manifest/v2"
SCHEMA_SOURCE_TREE = "jjdai.source-tree/v2"
#: rev 2.3. The schema of the object `verification_evidence_hash`
#: addresses. Until rev 2.3 the ADR named the hash and never said what
#: it pointed AT, so the implementation chose `ReleaseStatement` — and
#: the audit of recut2 showed the primary statement serving as evidence
#: about itself. A distinct schema makes that impossible by construction.
SCHEMA_REBUILD_EVIDENCE = "jjdai.rebuild-evidence/v1"
#: rev 2.4. The signed body behind a RELEASE_REVOKED record.
SCHEMA_RELEASE_REVOCATION = "jjdai.release-revocation/v1"

SCHEMAS = (SCHEMA_RELEASE_STATEMENT, SCHEMA_RELEASE_APPROVAL,
           SCHEMA_RELEASE_ATTESTATION, SCHEMA_RELEASE_PUBLICATION,
           SCHEMA_TOOLSET_MANIFEST, SCHEMA_SOURCE_TREE,
           SCHEMA_REBUILD_EVIDENCE, SCHEMA_RELEASE_REVOCATION)

#: The algorithm identifier that travels beside a tree digest, everywhere it
#: is written: `hermetic.json`, `ReleaseStatement`, the tag annotation.
TREE_DIGEST_ALGO = SCHEMA_SOURCE_TREE


# --------------------------------------------------------------------------- #
# Domain separators — two roles, one shape
# --------------------------------------------------------------------------- #

DOMAIN_RELEASE_APPROVAL = "JJDAI:RELEASE:APPROVAL:v1"
#: rev 2.3. The domain a RebuildEvidence is signed under. A separate
#: domain because it is a separate ACT: the approval says "I accept
#: this release", the evidence says "I ran the recipe myself and got
#: these bytes", and one signature must not be readable as the other.
DOMAIN_REBUILD_EVIDENCE = "JJDAI:REBUILD:EVIDENCE:v1"
#: rev 2.4. The domain a RevocationStatement is signed under. Revoking a
#: release by name is an act of the release-signing authority, and it gets
#: its own domain for the reason every other act does: an approval must not
#: be replayable as a revocation, nor the reverse.
DOMAIN_RELEASE_REVOKE = "JJDAI:RELEASE:REVOKE:v1"
DOMAIN_TOOLSET_MANIFEST = "JJDAI:TOOLSET:MANIFEST:v1"
PREFIX_RELEASE_ATTESTATION = "JJDAI:RELEASE:ATTESTATION:v1"
#: rev 2.4. Pre-image prefixes of the two lifecycle records. A KEY_ACTIVATED
#: or KEY_REVOKED record binds `H(prefix ‖ JCS({key_id, transition,
#: public}))` as its semantic_digest, so a registry position resolves to a
#: record that NAMES the key and the transition — the property
#: `check_lifecycle_witnessed` promised in recut1 and could not deliver
#: until the kinds existed.
PREFIX_KEY_LIFECYCLE = "JJDAI:RELEASE:KEYLIFECYCLE:v1"
#: rev 2.4. A RELEASE_REVOKED record binds `H(prefix ‖ JCS({statement_hash}))`
#: so that any reader can find the revocations of a release by recomputing,
#: without a body; the AUTHORITY for the revocation is a signed
#: RevocationStatement whose hash is the record's provenance_hash.
PREFIX_RELEASE_REVOKED = "JJDAI:RELEASE:REVOKED:v1"

#: Strings under which bytes are SIGNED.
SIGNING_DOMAINS = (DOMAIN_RELEASE_APPROVAL, DOMAIN_TOOLSET_MANIFEST,
                   DOMAIN_REBUILD_EVIDENCE, DOMAIN_RELEASE_REVOKE)

#: Strings that prefix a HASH pre-image. Not signing domains.
HASH_PREFIXES = (PREFIX_RELEASE_ATTESTATION, PREFIX_KEY_LIFECYCLE,
                 PREFIX_RELEASE_REVOKED)

SEPARATORS = SIGNING_DOMAINS + HASH_PREFIXES

_NUL = b"\x00"


def signing_domain(separator: str) -> bytes:
    """Return the byte prefix for signing under `separator`.

    Refuses a hash pre-image prefix. The refusal is the point: rev 2.1 spoke
    of "the bytes signed by the statement signature" for a field that was
    not in the envelope and whose signer was never named, and rev 2.2
    removed that signature. Letting the attestation prefix through here
    would let that signature back in by accident.
    """
    if separator in HASH_PREFIXES:
        raise ProvenanceValueError(
            f"{separator!r} is a HASH pre-image prefix, not a signing "
            f"domain (ADR-022 D5.1). Nothing signs under it: the "
            f"attestation is addressed by its hash and covered by the "
            f"approvals inside it. Signing under a hash prefix would "
            f"re-introduce the redundant statement signature rev 2.2 "
            f"removed.")
    if separator not in SIGNING_DOMAINS:
        raise ProvenanceValueError(
            f"unknown signing domain {separator!r}; ADR-022 declares "
            f"exactly {list(SIGNING_DOMAINS)}. Minting a separator on "
            f"demand is how one domain silently becomes two.")
    return separator.encode("utf-8") + _NUL


def hash_prefix(separator: str) -> bytes:
    """Return the byte prefix for a hash pre-image under `separator`.

    Refuses a signing domain, so that domain separation of hashes and domain
    separation of signatures cannot be collapsed into one habit.
    """
    if separator in SIGNING_DOMAINS:
        raise ProvenanceValueError(
            f"{separator!r} is a SIGNING domain, not a hash pre-image "
            f"prefix (ADR-022 D5.1). Hashing under a signature domain makes "
            f"a digest that looks like it was signed and was not.")
    if separator not in HASH_PREFIXES:
        raise ProvenanceValueError(
            f"unknown hash pre-image prefix {separator!r}; ADR-022 declares "
            f"exactly {list(HASH_PREFIXES)}.")
    return separator.encode("utf-8") + _NUL


# --------------------------------------------------------------------------- #
# Witness record kind — one, and it is emittable
# --------------------------------------------------------------------------- #

#: Written only after every mandatory approval is in, both roles are present
#: and every 5.4 check has passed (D5.5). An unfinished release never reaches
#: the chain, which is why neither a TTL nor a revocation is needed for a
#: device that died before the second signature: a failed attempt is kept
#: locally with a reason code and no witness record exists to retract.
KIND_RELEASE_ATTESTED = "RELEASE_ATTESTED"

#: `jjdai.witness` folds this into its canonical enum. One list, not two —
#: the same discipline the track V and track VI reserves follow.
#: rev 2.4. The three kinds window 6 did not hold, reserved and EMITTABLE
#: from this revision, before first emission. Two positions of the debt
#: ledger stood exactly here — `release-key-lifecycle-witnessing` and
#: `release-revocation-by-name` — and recut1's false REL-16 stood here too:
#: a check that asserted a witnessed lifecycle no record kind could witness.
KIND_KEY_ACTIVATED = "KEY_ACTIVATED"
KIND_KEY_REVOKED = "KEY_REVOKED"
KIND_RELEASE_REVOKED = "RELEASE_REVOKED"
LIFECYCLE_KINDS = (KIND_KEY_ACTIVATED, KIND_KEY_REVOKED)
PROVENANCE_KINDS = (KIND_RELEASE_ATTESTED, KIND_KEY_ACTIVATED,
                    KIND_KEY_REVOKED, KIND_RELEASE_REVOKED)

#: The fields a RELEASE_ATTESTED record carries (D5.5 step 4). Declared as
#: data so a check can assert the set instead of trusting a call site.
RELEASE_ATTESTED_FIELDS = ("attestation_hash", "statement_hash", "version",
                           "tree_digest")


# --------------------------------------------------------------------------- #
# Debt ledger — events, NOT witness records
# --------------------------------------------------------------------------- #
#
# D14. A debt position is a PROJECTION over append-only events, the same
# construction as the effective evidence status in track VI. The events live
# in `docs/architecture_status.json`, which is the single source of truth;
# the surfaces render only positions whose projection is `open`.
#
# These are deliberately NOT witness record kinds. Release debt is a fact
# about this repository's own housekeeping, not a claim one node makes to
# another, and putting it in the shared enum would invite exactly that
# reading. Offering one of these to `witness.append()` is an unknown kind.

DEBT_OPENED = "DEBT_OPENED"
DEBT_CLOSED = "DEBT_CLOSED"
DEBT_CANCELLED = "DEBT_CANCELLED"

DEBT_EVENTS = (DEBT_OPENED, DEBT_CLOSED, DEBT_CANCELLED)

#: The projection a position's event history collapses to.
DEBT_OPEN = "open"
DEBT_SETTLED = "closed"
DEBT_WITHDRAWN = "cancelled"
DEBT_PROJECTIONS = (DEBT_OPEN, DEBT_SETTLED, DEBT_WITHDRAWN)

#: WHAT a position blocks. The values were already in the ledger and read by
#: nobody: the audit of recut1 placed a release tag with four positions open
#: under `meaning-of-a-release-tag`, because `check_release_tag` never
#: opened the file. They are named here so the gate and the ledger use one
#: spelling — a boundary compared by a string literal typed twice is a
#: boundary that stops matching after the first rename.
BLOCKS_PUBLICATION = "publication"
BLOCKS_RELEASE_TAG = "meaning-of-a-release-tag"
BLOCKS_TREE_EXACTNESS = "byte-exactness-of-the-tree"
BLOCKS_PHASE_0_GATE = "phase-0-gate"
BLOCKS_OUTSIDE_CONTRIBUTION = "acceptance-of-outside-contribution"
DEBT_BOUNDARIES = (BLOCKS_PUBLICATION, BLOCKS_RELEASE_TAG,
                   BLOCKS_TREE_EXACTNESS, BLOCKS_PHASE_0_GATE,
                   BLOCKS_OUTSIDE_CONTRIBUTION)

#: A terminal event must cite WHY it is terminal, and the two cite different
#: things: a cancelled position points at the decision that removed it, a
#: closed one at the check that discharged it. The pairing is enforced rather
#: than documented — an unreferenced closure is indistinguishable from a
#: quiet deletion, which is the whole thing D14 forbids.
DEBT_REFERENCE_FIELD = {
    DEBT_CLOSED: "evidence_ref",
    DEBT_CANCELLED: "decision_ref",
}

_TERMINAL = {DEBT_CLOSED: DEBT_SETTLED, DEBT_CANCELLED: DEBT_WITHDRAWN}


def load_debt_ledger(status_doc) -> dict:
    """Every position's projection, computed by ONE function.

    SBOM-3 used to scan the events itself and take the last one it saw,
    which is a projection only by accident: it never checked that a history
    starts with `DEBT_OPENED`, that nothing follows a terminal event, or
    that a terminal event carries its reference. Two implementations of one
    projection disagree the moment one of them is fixed, so there is one.
    """
    ledger = status_doc["release_debt"]
    if ledger.get("schema") != "jjdai.debt-ledger/v1":
        raise ProvenanceValueError("release_debt: unexpected schema")
    by_id = {}
    for event in ledger["events"]:
        # The boundary is now READ by `release._check_debt`, so a misspelt
        # one no longer costs a wrong word in a document — it costs a gate
        # that finds nothing open and passes. Refused at the source.
        if event.get("event") == DEBT_OPENED and \
                event.get("blocks") not in DEBT_BOUNDARIES:
            raise ProvenanceValueError(
                "debt position %r opens against boundary %r, which is not "
                "one of %s. An unknown boundary blocks nothing and reads as "
                "though it blocks something"
                % (event.get("id"), event.get("blocks"),
                   list(DEBT_BOUNDARIES)))
        by_id.setdefault(event["id"], []).append(event)
    out = {}
    for position, events in by_id.items():
        events.sort(key=lambda e: e["seq"])
        out[position] = project_debt(events)
    return out


def open_debt(status_doc) -> list:
    """The positions a surface may render — `open`, and nothing else."""
    return sorted(k for k, v in load_debt_ledger(status_doc).items()
                  if v == DEBT_OPEN)


def project_debt(events) -> str:
    """Collapse one position's event history into its current state.

    Fail-closed and order-sensitive: a history that does not begin with
    `DEBT_OPENED` is refused rather than assumed open, and an event after a
    terminal one is refused rather than silently winning. A position is never
    deleted, so "no events" is not a state — it is an absent position, and
    the caller asked about something that does not exist.
    """
    seq = list(events)
    if not seq:
        raise ProvenanceValueError(
            "a debt position with no events does not exist; D14 removes a "
            "position never, so an empty history is a lookup error rather "
            "than a state")
    state = None
    for i, ev in enumerate(seq):
        # A bare string cannot carry a reference, so accepting one is
        # accepting a closure with no evidence and a cancellation with no
        # decision — exactly what D14 forbids, arriving through the shape of
        # the argument rather than through its content. The first cut took
        # either form and only checked the reference when the event happened
        # to be a mapping, so `["DEBT_OPENED", "DEBT_CLOSED"]` closed a debt
        # silently. One shape only.
        if not isinstance(ev, dict):
            raise ProvenanceValueError(
                f"debt event {ev!r} is not an object; every event carries at "
                f"least its own kind, and the terminal ones carry the "
                f"reference that makes them distinguishable from a deletion "
                f"(ADR-022 D14)")
        kind = ev.get("event")
        if kind not in DEBT_EVENTS:
            raise ProvenanceValueError(
                f"unknown debt event {kind!r}; ADR-022 D14 declares exactly "
                f"{list(DEBT_EVENTS)}")
        if i == 0:
            if kind != DEBT_OPENED:
                raise ProvenanceValueError(
                    f"a debt history begins with {DEBT_OPENED}, not "
                    f"{kind!r}: a position that was closed before it was "
                    f"opened is a rendering of events that never happened")
            state = DEBT_OPEN
            continue
        if state is not DEBT_OPEN:
            raise ProvenanceValueError(
                f"event {kind!r} follows a terminal event; the history "
                f"inside a position is immutable, so a later event cannot "
                f"overwrite the one that settled it")
        if kind == DEBT_OPENED:
            raise ProvenanceValueError(
                "a position is opened once; re-opening would make the "
                "projection depend on which OPENED a reader stopped at")
        state = _TERMINAL[kind]
        field = DEBT_REFERENCE_FIELD[kind]
        if not ev.get(field):
            raise ProvenanceValueError(
                f"{kind} requires {field!r}: a cancelled position leaves "
                f"the decision that removed it and a closed one leaves "
                f"the check that discharged it. Without the reference a "
                f"terminal event is a deletion with better manners")
    return state


# --------------------------------------------------------------------------- #
# Key domains — ADR-017 use domains, one per function
# --------------------------------------------------------------------------- #

KEY_DOMAIN_RELEASE_SIGNING = "release_signing"
KEY_DOMAIN_TOOLSET_AUTHORIZATION = "toolset_authorization"

KEY_DOMAINS = (KEY_DOMAIN_RELEASE_SIGNING, KEY_DOMAIN_TOOLSET_AUTHORIZATION)

#: What a key of each domain is for, in the terms D10 uses. Purposes are
#: named separately from domains so that the cross-use check compares two
#: vocabularies rather than a string against itself.
PURPOSE_RELEASE_PROVENANCE = "release_provenance"
PURPOSE_TOOLSET_L2_MUTATION = "toolset_l2_mutation"

PURPOSES = (PURPOSE_RELEASE_PROVENANCE, PURPOSE_TOOLSET_L2_MUTATION)

_DOMAIN_FOR_PURPOSE = {
    PURPOSE_RELEASE_PROVENANCE: KEY_DOMAIN_RELEASE_SIGNING,
    PURPOSE_TOOLSET_L2_MUTATION: KEY_DOMAIN_TOOLSET_AUTHORIZATION,
}


def key_domain_for(purpose: str) -> str:
    """The one ADR-017 use domain that may serve `purpose`."""
    try:
        return _DOMAIN_FOR_PURPOSE[purpose]
    except KeyError:
        raise ProvenanceValueError(
            f"unknown purpose {purpose!r}; ADR-022 D10 names exactly "
            f"{list(PURPOSES)}") from None


def check_domain_serves(domain: str, purpose: str) -> None:
    """Refuse a key domain used for the other domain's function.

    The refusal names the consequence rather than the rule, because the rule
    reads like bookkeeping and the consequence does not: one key on both
    roles means whoever can cut a build can thereby widen a being's hand.
    """
    if domain not in KEY_DOMAINS:
        raise ProvenanceValueError(
            f"unknown key domain {domain!r}; ADR-022 declares exactly "
            f"{list(KEY_DOMAINS)}")
    wanted = key_domain_for(purpose)
    if domain != wanted:
        raise ProvenanceValueError(
            f"key domain {domain!r} may not serve {purpose!r}: that is "
            f"{wanted!r}'s function (ADR-022 D10). Release provenance and "
            f"the right to change a being's hand are separate powers, and "
            f"one key holding both collapses them.")


# --------------------------------------------------------------------------- #
# Approval roles and the reproducibility scope ladder
# --------------------------------------------------------------------------- #

ROLE_BUILDER = "builder"
ROLE_VERIFIER = "verifier"
APPROVAL_ROLES = (ROLE_BUILDER, ROLE_VERIFIER)

#: `verification_evidence_hash` is REQUIRED for a verifier and FORBIDDEN for
#: a builder — one shape of the field, not "absent or null" (D5.3). Without
#: this the builder role is rewritten as verifier under a valid signature,
#: which rewrites the one piece of evidence the whole construction exists to
#: produce.
EVIDENCE_REQUIRED_BY_ROLE = {ROLE_BUILDER: False, ROLE_VERIFIER: True}

SCOPE_SAME_HOST = "same-host"
SCOPE_SAME_HOST_CLASS = "same-host-class"
SCOPE_CROSS_HOST_CLASS = "cross-host-class"

#: Ascending. `same-host` is diagnostic only: a rebuild on the machine that
#: built it repeats the machine, not the recipe.
REPRODUCIBILITY_SCOPES = (SCOPE_SAME_HOST, SCOPE_SAME_HOST_CLASS,
                          SCOPE_CROSS_HOST_CLASS)

RELEASE_MIN_SCOPE = SCOPE_SAME_HOST_CLASS


def scope_rank(scope: str) -> int:
    try:
        return REPRODUCIBILITY_SCOPES.index(scope)
    except ValueError:
        raise ProvenanceValueError(
            f"unknown reproducibility scope {scope!r}; ADR-022 D3 declares "
            f"exactly {list(REPRODUCIBILITY_SCOPES)}") from None


def derive_scope(builder, verifier) -> str:
    """The scope two runs ACHIEVED, computed from what each declared.

    rev 2.3. `reproducibility_scope` was a value the statement said about
    itself and nothing compared it with anything: the audit placed a tag
    claiming `cross-host-class` with no fact about either host anywhere in
    the release. A scope that cannot go down is not a measurement.

    `host_class` and `build_run_id` are DECLARATIONS, signed by whoever ran
    the build — the same standing as `device_binding: "asserted"`. They do
    not prove there were two machines; they make the claim of two machines
    signed, comparable and refutable, which is what the field was missing.
    """
    if builder.get("build_run_id") and \
            builder["build_run_id"] == verifier.get("build_run_id"):
        # One run signed twice. Not two builds, whatever the key count says.
        return SCOPE_SAME_HOST
    if builder.get("host_class") == verifier.get("host_class"):
        return SCOPE_SAME_HOST_CLASS
    return SCOPE_CROSS_HOST_CLASS


def check_scope_allows_release(scope: str) -> None:
    """Refuse a release tag on a scope below `same-host-class` (D13)."""
    if scope_rank(scope) < scope_rank(RELEASE_MIN_SCOPE):
        raise ProvenanceValueError(
            f"reproducibility scope {scope!r} is below "
            f"{RELEASE_MIN_SCOPE!r} and does not carry a release tag "
            f"(ADR-022 D3, D13). A rebuild on the same machine repeats the "
            f"machine; it is preflight and diagnosis, not independence.")


# --------------------------------------------------------------------------- #
# Control block, device binding, interim authorization
# --------------------------------------------------------------------------- #

#: The five numbers of D2. Named as data so a check can assert the shape:
#: the control is DESCRIBED IN NUMBERS computed from valid approvals against
#: the key registry, never asserted in prose. `distinct_principals` is a
#: number and not a name for exactly this reason.
CONTROL_FIELDS = ("signature_threshold", "distinct_keys", "distinct_devices",
                  "distinct_principals", "device_binding")

DEVICE_BINDING_ASSERTED = "asserted"
DEVICE_BINDING_ATTESTED = "attested"
DEVICE_BINDINGS = (DEVICE_BINDING_ASSERTED, DEVICE_BINDING_ATTESTED)


def check_device_binding(value: str) -> None:
    """`attested` is reserved for Ф3 and refuses until attestation exists.

    Saying `attested` before there is hardware attestation to say it with
    would put an independence into a signed artefact that nobody measured —
    the same defect as a panel simulated by one engine, in a different
    place.
    """
    if value == DEVICE_BINDING_ATTESTED:
        raise ProvenanceValueError(
            f"device_binding {value!r} is RESERVED until hardware "
            f"attestation profiles land in Ф3 (ADR-022 §16). Until then the "
            f"separateness of two devices is an operator's assertion, and "
            f"the artefact says so with {DEVICE_BINDING_ASSERTED!r}.")
    if value != DEVICE_BINDING_ASSERTED:
        raise ProvenanceValueError(
            f"unknown device_binding {value!r}; ADR-022 D2 declares exactly "
            f"{list(DEVICE_BINDINGS)}")


#: The interim authorization form and the condition that ends it (D10). Both
#: live in the signed manifest so the temporariness is machine-readable: a
#: manifest still carrying the interim form after the Gauntlet capability is
#: registered refuses to load. A temporary form does not outlive its own
#: justification quietly, and a CHANGELOG sentence is not a mechanism.
AUTHORIZATION_FORM_INTERIM = "operator_signature_interim"
SUNSET_CONDITION_GAUNTLET = "profile_gauntlet_available"

AUTHORIZATION_FORMS = (AUTHORIZATION_FORM_INTERIM,)


Separator = namedtuple("Separator", "value role")

#: Every separator with its role, for a check that asserts the split as data
#: rather than re-listing it.
SEPARATOR_ROLES = (
    Separator(DOMAIN_RELEASE_APPROVAL, "signing"),
    Separator(DOMAIN_REBUILD_EVIDENCE, "signing"),
    Separator(DOMAIN_TOOLSET_MANIFEST, "signing"),
    Separator(PREFIX_RELEASE_ATTESTATION, "hash-prefix"),
    Separator(PREFIX_KEY_LIFECYCLE, "hash-prefix"),
    Separator(PREFIX_RELEASE_REVOKED, "hash-prefix"),
    Separator(DOMAIN_RELEASE_REVOKE, "signing"),
)

#: Everything this module freezes, for drift checks and for reporting. Not a
#: refusal list: unlike the track V and VI reserves, these names are emitted
#: by the drop that declares them.
ALL_PROVENANCE_VALUES = (SCHEMAS + SEPARATORS + PROVENANCE_KINDS +
                         DEBT_EVENTS + KEY_DOMAINS + APPROVAL_ROLES +
                         REPRODUCIBILITY_SCOPES + DEVICE_BINDINGS +
                         AUTHORIZATION_FORMS + (SUNSET_CONDITION_GAUNTLET,))
