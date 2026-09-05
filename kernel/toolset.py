# -*- coding: utf-8 -*-
"""
kernel.toolset — manifest v2, recipes, materialization
======================================================
ADR-022 D7 and D8.

**Source tree holds recipes, never binaries.** `deploy/wasm-toolset/recipe/
<tool>.json` names the upstream by commit and source archive sha256, the
build environment by digest, the build command verbatim, and the expected
sha256 of the output. The built `.wasm` travels in the release bundle,
signed with the release; a production node receives the signed bundle,
checks hashes and executes. It does not compile and does not reach upstream
— otherwise every node grows a compiler and a supply-chain surface of its
own, and one provenance problem is solved by creating a second.

**Two files, and only one of them is trusted.** `toolset-manifest.json`
(`jjdai.toolset-manifest/v2`) is immutable and signed: which tools, which
effect class, which expected hashes, which authorization form.
`toolset-materialization.json` is local and unsigned: what is actually on
this node. The loader hashes the REAL BYTES of a module and compares them
with the MANIFEST. Trusting the materialization's hash would mean the
signed manifest is bypassed by editing an unsigned file, so a disagreement
between the two is a refusal and never an auto-reinstall.

**The temporariness is machine-readable.** By ADR-015 adding an executable
tool is an L2 mutation and belongs to the Profile Gauntlet, which does not
exist until Ф3. Until then the signed manifest sanctions the mutation under
`authorization_form: "operator_signature_interim"` with
`sunset_condition: "profile_gauntlet_available"`. From the moment the
Gauntlet capability is registered a manifest still carrying the interim form
refuses to load. A temporary form does not outlive its justification
quietly, and a sentence in a CHANGELOG is not a mechanism.
"""
from __future__ import annotations

import json
import os

from jjdai import provenance as prv
from jjdai.canonical import canonical
from jjdai.custody import check_effect_class
from jjdai.crypto import H_hex, verify
from kernel import wasm_pure as wp

#: Refusal codes for the manifest layer. Distinct from the per-tool codes in
#: `kernel.isolation` and from the boundary codes in `kernel.wasm_pure`: a
#: manifest defect, a drifted module and an over-reaching import are three
#: different facts and an operator should never have to guess which is meant.
MANIFEST_BAD_SCHEMA = "MANIFEST_BAD_SCHEMA"
MANIFEST_NO_RESOLVER = "MANIFEST_NO_RESOLVER"
MANIFEST_UNKNOWN_KEY = "MANIFEST_UNKNOWN_KEY"
MANIFEST_KEY_REVOKED = "MANIFEST_KEY_REVOKED"
MANIFEST_BAD_SIGNATURE = "MANIFEST_BAD_SIGNATURE"
MANIFEST_UNSIGNED = "MANIFEST_UNSIGNED"
MANIFEST_SUNSET = "MANIFEST_SUNSET_REACHED"
MANIFEST_NO_EFFECT_CLASS = "MANIFEST_NO_EFFECT_CLASS"
MANIFEST_NO_RECIPE = "MANIFEST_NO_RECIPE"
MANIFEST_AUTHZ_UNRESOLVED = "MANIFEST_AUTHZ_UNRESOLVED"
RECIPE_INCOMPLETE = "RECIPE_INCOMPLETE"
RECIPE_PLACEHOLDER = "RECIPE_PLACEHOLDER"
MATERIALIZATION_DRIFT = "MATERIALIZATION_DRIFT"


class ToolsetError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code, message):
    return ToolsetError(code, message)


# --------------------------------------------------------------------------- #
# Recipes
# --------------------------------------------------------------------------- #
#
# The recipe format is deliberately NOT one of the six schema ids frozen by
# window 6. Those six are protocol objects: they are signed, hashed into
# other objects, or written into append-only records, so their canonical
# encoding is fixed before the first emission. A recipe is a BUILD INPUT.
# Only its `recipe_hash` crosses into a signed artefact, and a hash does not
# care what the format calls itself. Reserving a name that never enters the
# vocabulary would make the reserve list mean two different things at once.

RECIPE_FORMAT = "jjdai.toolset-recipe/v1"

RECIPE_FIELDS = ("format", "tool", "effect_class", "upstream_url",
                 "upstream_commit", "source_sha256", "build_image_digest",
                 "build_command", "expected_sha256", "reproducible")

#: Fields that must be a 64-character hex digest. The first cut required
#: only that they be non-empty, so `"source_sha256": "x"` read as a full
#: recipe — a pin-shaped hole. A hash is a fixed width or it is prose.
RECIPE_HEX_FIELDS = ("source_sha256", "expected_sha256")

#: An upstream commit is a full 40-character git object name. An abbreviated
#: one is ambiguous by construction and gets longer as a repository grows.
RECIPE_COMMIT_FIELD = "upstream_commit"

#: A recipe that has not been filled in must refuse LOUDLY rather than pass
#: as a pin. A placeholder that validates is worse than a missing file: the
#: missing file is noticed.
PLACEHOLDER = "__OWED_ON_BUILD_HOST__"


def load_recipe(path: str) -> dict:
    """Read and validate one recipe. Fail-closed on every incompleteness."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise _fail(RECIPE_INCOMPLETE,
                    f"recipe {path!r} unreadable: {e}") from None
    if doc.get("format") != RECIPE_FORMAT:
        raise _fail(RECIPE_INCOMPLETE,
                    f"recipe {path!r} is not {RECIPE_FORMAT}")
    for field in RECIPE_FIELDS:
        if not doc.get(field):
            raise _fail(RECIPE_INCOMPLETE,
                        f"recipe {path!r} omits {field!r}; a recipe with a "
                        f"gap builds something nobody can re-derive")
    if doc.get("reproducible") is not True:
        raise _fail(
            RECIPE_INCOMPLETE,
            f"recipe {path!r} does not declare `reproducible: true`. "
            f"ADR-022 D7 admits no `reproducible: false` in a production "
            f"toolset: an instrument that does not repeat goes to the "
            f"quarantine class, outside the decision path, and does not "
            f"close T-TOOLSET.")
    check_effect_class(doc.get("effect_class"))
    for field, value in doc.items():
        if value == PLACEHOLDER:
            raise _fail(
                RECIPE_PLACEHOLDER,
                f"recipe {path!r} still carries the placeholder in {field!r}. "
                f"The pins are filled on a build host with the toolchain and "
                f"upstream access; until then this recipe builds nothing and "
                f"says so, rather than validating with a hash-shaped string "
                f"that pins nothing (ADR-022 O-3).")
    for field in RECIPE_HEX_FIELDS:
        value = doc[field]
        if len(value) != 64 or any(c not in "0123456789abcdef"
                                   for c in value.lower()):
            raise _fail(RECIPE_INCOMPLETE,
                        f"recipe {path!r}: {field!r} is not a sha256 — a "
                        f"hash has a fixed width, and a short string in its "
                        f"place is a pin-shaped hole")
    commit = doc[RECIPE_COMMIT_FIELD]
    if len(commit) != 40 or any(c not in "0123456789abcdef"
                                for c in commit.lower()):
        raise _fail(RECIPE_INCOMPLETE,
                    f"recipe {path!r}: {RECIPE_COMMIT_FIELD!r} must be a "
                    f"full 40-character object name; an abbreviation is "
                    f"ambiguous by construction and grows more so")
    return doc


def recipe_hash(path: str) -> str:
    """sha256 over the recipe's raw bytes — what the manifest pins.

    Raw bytes, not a re-serialization: the manifest names the file that was
    read, and a re-encoding would let two different files carry one hash.
    """
    with open(path, "rb") as f:
        return H_hex(f.read())


# --------------------------------------------------------------------------- #
# Manifest v2
# --------------------------------------------------------------------------- #

TOOL_FIELDS = ("module", "sha256", "effect_class", "recipe_hash", "limits")


MANIFEST_FILE = "toolset-manifest.json"


def signing_bytes(doc) -> bytes:
    """The bytes a toolset manifest is signed over.

    Domain separator, NUL, then the JCS canonicalization of the document
    with only the SIGNATURE VALUE removed. The signer's identity — `key_id`,
    `key_domain`, `domain` — lives in a `signer` block that IS inside the
    signed bytes.

    The first cut excluded the whole `signature` object, which held the
    identity as well, so the same bytes verified under any `key_id` that
    carried the same public key: the audit swapped the id for another
    registered one and the manifest was accepted. Only the value a signature
    cannot cover — itself — is excluded; everything the verifier decides
    with is covered.
    """
    body = {k: v for k, v in doc.items() if k != "signature"}
    return prv.signing_domain(prv.DOMAIN_TOOLSET_MANIFEST) + canonical(body)


def manifest_address(raw: bytes) -> str:
    """THE address of a toolset manifest: sha256 of the file's real bytes.

    There was briefly a second one. `ReleaseStatement.toolset_manifest_hash`
    is written by the assembler as sha256 of the FILE, while this module
    handed the authorizer sha256 of JCS(parsed document) — for any formatted
    JSON those are different digests, so the two sides addressed different
    objects and the authorization could never have matched a real manifest.
    Two identities for one thing is the defect; there is one now, and it is
    the bytes, because the bytes are what shipped.
    """
    return H_hex(raw)


def validate_manifest(doc, *, resolver, gauntlet_available: bool = False,
                      authorization=None, raw: bytes = None):
    """Validate and VERIFY a `jjdai.toolset-manifest/v2` document.

    `resolver(key_id)` returns the registered key or None. It is a required
    argument with no default, and passing None refuses:

    The first cut of this function checked that a signature was PRESENT and
    under the right domain, and said in its own docstring that verification
    was impossible without a Key Plane. The audit took the sentence at its
    word and fed it `{"key_id": "nonexistent", "signature":
    "not-a-signature"}`, which loaded. That is the exact defect this file
    warns about elsewhere: absence of a checker is not permission. A
    manifest is what sanctions an L2 mutation — the widening of a being's
    hand — so with no way to resolve the signing key the right answer is
    that the profile is UNAVAILABLE, not that an object shaped like a signed
    one is accepted.
    """
    if resolver is None:
        raise _fail(
            MANIFEST_NO_RESOLVER,
            "no release-key resolver: the toolset manifest sanctions an L2 "
            "mutation and cannot be accepted unverified. Until a key "
            "registry exists on this node the wasm profile is unavailable, "
            "which is the honest state — an object that looks signed is not "
            "a signature (ADR-022 D8, D10).")
    if not isinstance(doc, dict) or \
            doc.get("schema") != prv.SCHEMA_TOOLSET_MANIFEST:
        raise _fail(MANIFEST_BAD_SCHEMA,
                    f"toolset manifest must declare schema "
                    f"{prv.SCHEMA_TOOLSET_MANIFEST!r}; v1 is not loaded, "
                    f"because v1 has no effect class and the hand cannot be "
                    f"limited in custody without one (ADR-022 D9)")

    form = doc.get("authorization_form")
    if form not in prv.AUTHORIZATION_FORMS:
        raise _fail(MANIFEST_UNSIGNED,
                    f"unknown authorization_form {form!r}; ADR-022 D10 "
                    f"declares {list(prv.AUTHORIZATION_FORMS)}")
    if doc.get("sunset_condition") != prv.SUNSET_CONDITION_GAUNTLET:
        raise _fail(MANIFEST_UNSIGNED,
                    f"an interim authorization must name the condition that "
                    f"ends it: {prv.SUNSET_CONDITION_GAUNTLET!r}")
    if form == prv.AUTHORIZATION_FORM_INTERIM and gauntlet_available:
        raise _fail(
            MANIFEST_SUNSET,
            f"the Profile Gauntlet capability is registered, so a manifest "
            f"still carrying {form!r} refuses to load (ADR-022 D10). Adding "
            f"an executable tool is an L2 mutation; the interim operator "
            f"signature stood in for a Gauntlet that did not exist, and it "
            f"does not outlive its own justification.")

    signer = doc.get("signer")
    sig = doc.get("signature")
    if not isinstance(signer, dict) or not signer.get("key_id"):
        raise _fail(MANIFEST_UNSIGNED,
                    "toolset manifest carries no `signer` block. The "
                    "signer's identity must sit INSIDE the signed bytes: "
                    "with it beside them, one public key registered under "
                    "two ids verifies as either.")
    if not isinstance(sig, str) or not sig:
        raise _fail(MANIFEST_UNSIGNED,
                    "toolset manifest carries no signature; the manifest is "
                    "what sanctions an L2 mutation, and an unsigned "
                    "sanction is none")
    # The domain must be the TOOLSET one. Signing a manifest under the
    # release domain would mean whoever can cut a build can widen the hand.
    domain = signer.get("domain")
    if domain != prv.DOMAIN_TOOLSET_MANIFEST:
        raise _fail(
            MANIFEST_UNSIGNED,
            f"toolset manifest signed under {domain!r}; it must be "
            f"{prv.DOMAIN_TOOLSET_MANIFEST!r} (ADR-022 D10). Release "
            f"provenance and the right to change a being's hand are separate "
            f"powers and do not share a domain.")
    prv.signing_domain(domain)      # refuses a hash prefix used as a domain
    prv.check_domain_serves(signer.get("key_domain"),
                            prv.PURPOSE_TOOLSET_L2_MUTATION)

    key = resolver(signer["key_id"])
    if not key:
        raise _fail(MANIFEST_UNKNOWN_KEY,
                    f"signing key {signer['key_id']!r} is not in the registry")
    # HISTORICAL validity, not current-only (ADR-022 D10, and the same rule
    # `jjdai.release.key_valid_at` applies to release keys). The first cut
    # read a boolean `revoked`, so revoking a key today invalidated every
    # manifest it ever signed — a node would go dark on a rotation rather
    # than on a compromise. The manifest declares WHEN it was authorized;
    # the registry says when the key was active; validity is the comparison
    # of the two.
    #
    # WHERE THE POSITION COMES FROM. Not from here. The first cut read
    # `authorized_at_witness_seq` out of the signed manifest, falling back to
    # an integer the caller passed, and no caller passed one — so the
    # manifest declared its own authorization time and the signature made
    # that time immutable rather than true. A key valid on [0, 10) signed a
    # manifest claiming position 0 and it loaded, which is the same
    # backdating ADR-022 rev 2.1 removed from `ReleaseStatement`: whoever
    # holds a once-valid key can date a widening of a being's hand into the
    # window where it was valid.
    #
    # `authorization` is a callable supplied by a party that HOLDS the
    # chain — `jjdai.release.toolset_authorizer` builds one from a verified
    # ReleasePublication. It answers with the actual index of the
    # RELEASE_ATTESTED record of the release whose `toolset_manifest_hash`
    # is this manifest. The release names which manifest it carries; the
    # chain says where that release was attested; the two together are the
    # authorization time, and neither of them is the manifest's own word.
    declared = signer.get("authorized_at_witness_seq")
    authorized = None
    if authorization is not None:
        if raw is None:
            raise _fail(
                MANIFEST_AUTHZ_UNRESOLVED,
                "authorization was supplied without the manifest's raw "
                "bytes. The release names this manifest by the sha256 of "
                "the FILE; recomputing an address from the parsed document "
                "would ask the authorizer about an object the release never "
                "named")
        # THE BYTES AND THE DOCUMENT ARE ONE OBJECT, or this refuses. The
        # signature is checked over `doc` and the authorization over `raw`;
        # the audit of recut3 signed document B, authorized bytes A, and
        # loaded. The file loader never produces that pair, because it
        # parses the bytes it hands over — this is the seam of the direct
        # API, and it is closed here rather than documented.
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise _fail(MANIFEST_BAD_SCHEMA,
                        "raw manifest bytes are not a JSON document") from None
        if canonical(parsed) != canonical(doc):
            raise _fail(
                MANIFEST_AUTHZ_UNRESOLVED,
                "the raw bytes and the document passed beside them are two "
                "different manifests. The signature would be checked over "
                "one and the authorization resolved for the other")
        authorized = int(authorization(manifest_address(raw)))
        if declared is not None and int(declared) != authorized:
            raise _fail(
                MANIFEST_AUTHZ_UNRESOLVED,
                f"the manifest declares authorized_at_witness_seq="
                f"{declared!r}; the release carrying this manifest was "
                f"attested at {authorized}. A manifest does not name its "
                f"own position — that is the whole of the backdating "
                f"defect, arriving through a field instead of an argument")
    activated = key.get("activated_at_witness_seq")
    revoked = key.get("revoked_at_witness_seq")
    if activated is not None or revoked is not None:
        if not isinstance(authorized, int):
            raise _fail(
                MANIFEST_AUTHZ_UNRESOLVED,
                "the registry records a key lifecycle and no RESOLVED "
                "authorization position was supplied. Without one there is "
                "nothing to judge historical validity AT, and the position "
                "may not be taken from the manifest that is being judged: "
                "pass `authorization=` from a party holding the chain")
        if activated is not None and authorized < int(activated):
            raise _fail(MANIFEST_KEY_REVOKED,
                        f"key {signer['key_id']!r} activates at {activated} "
                        f"and this manifest claims {authorized}: a key acts "
                        f"from its declared position, never retroactively")
        if revoked is not None and authorized >= int(revoked):
            raise _fail(
                MANIFEST_KEY_REVOKED,
                f"key {signer['key_id']!r} was revoked at {revoked} and this "
                f"manifest was authorized at {authorized}")
    elif key.get("revoked"):
        # A registry that carries no lifecycle can only answer the weaker
        # question. Named rather than silently treated as the same thing.
        raise _fail(MANIFEST_KEY_REVOKED,
                    f"signing key {signer['key_id']!r} is revoked and the "
                    f"registry records no positions, so historical validity "
                    f"cannot be judged; the weaker current-only answer "
                    f"applies")
    if key.get("key_domain") != prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION:
        raise _fail(
            MANIFEST_UNKNOWN_KEY,
            f"key {signer['key_id']!r} is registered for "
            f"{key.get('key_domain')!r}, not "
            f"{prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION!r}. The manifest may "
            f"claim any domain it likes; what counts is the domain the "
            f"REGISTRY records for the key that actually signed.")
    try:
        raw = bytes.fromhex(sig)
        public = bytes.fromhex(key["public"])
    except (ValueError, TypeError, KeyError):
        raise _fail(MANIFEST_BAD_SIGNATURE,
                    "signature or public key is not hex") from None
    if not verify(public, signing_bytes(doc), raw):
        raise _fail(MANIFEST_BAD_SIGNATURE,
                    "toolset manifest signature does not verify over the "
                    "canonical body under "
                    f"{prv.DOMAIN_TOOLSET_MANIFEST}")

    tools = doc.get("tools")
    if not isinstance(tools, dict):
        raise _fail(MANIFEST_BAD_SCHEMA, "manifest declares no tools mapping")
    for tool, entry in sorted(tools.items()):
        if not isinstance(entry, dict):
            raise _fail(MANIFEST_BAD_SCHEMA,
                        f"tool {tool!r} is not an object")
        for field in TOOL_FIELDS:
            if not entry.get(field):
                if field == "effect_class":
                    raise _fail(
                        MANIFEST_NO_EFFECT_CLASS,
                        f"tool {tool!r} declares no effect_class. Without "
                        f"one the restriction of the hand in custody is "
                        f"unenforceable, because 'locally reversible' has "
                        f"nothing to be told apart from (ADR-022 D9).")
                if field == "recipe_hash":
                    raise _fail(
                        MANIFEST_NO_RECIPE,
                        f"tool {tool!r} pins no recipe_hash: a module whose "
                        f"recipe is unnamed is a binary of unknown origin "
                        f"wearing a hash (ADR-022 D7).")
                raise _fail(MANIFEST_BAD_SCHEMA,
                            f"tool {tool!r} omits {field!r}")
        # `unknown` refuses closed; the classes above `pure` refuse until
        # their reversal machinery exists in Ф2. Both come from one checker
        # so the manifest cannot admit a class the runtime cannot enforce.
        check_effect_class(entry["effect_class"])
        wp.check_limits_declared(entry["limits"])
    return doc


def load_verified_manifest(path: str, *, resolver,
                           gauntlet_available: bool = False,
                           authorization=None) -> dict:
    """THE door. Everything downstream — availability, capabilities, module
    resolution, execution — goes through this and not around it.

    The audit found the validator sitting BESIDE the door rather than being
    it: `kernel.isolation` read `toolset.json` itself and never called
    validation, so a manifest with no signature, no authorization form, no
    sunset, no recipe hash and no limits reported `available = (True, "")`
    and executed. Checks that exercise a helper the runtime never calls
    prove the helper, not the boundary.
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise _fail(MANIFEST_BAD_SCHEMA,
                    f"toolset manifest at {path!r} unreadable: {e}") from None
    # The RAW bytes travel with the document. The loader already hashes real
    # bytes for modules for the same reason: what shipped is what is
    # addressed, and re-serialising is how the two sides drift apart.
    return validate_manifest(doc, resolver=resolver,
                             gauntlet_available=gauntlet_available,
                             authorization=authorization, raw=raw)


# --------------------------------------------------------------------------- #
# Materialization — a record of state, never a source of truth
# --------------------------------------------------------------------------- #

MATERIALIZATION_FILE = "toolset-materialization.json"


def check_module_against_manifest(tool: str, entry: dict,
                                  module_bytes: bytes) -> None:
    """The loader's duty (D8): hash the real bytes, then check the boundary.

    Order matters. The digest is checked first so that a drifted module is
    reported as drift rather than as whatever its imports happen to be; only
    a module that IS the pinned one is then asked whether it stays inside its
    declared effect class.
    """
    got = H_hex(module_bytes)
    want = (entry.get("sha256") or "").lower()
    if got != want:
        raise _fail(MATERIALIZATION_DRIFT,
                    f"module for {tool!r} hashes {got}, manifest pins "
                    f"{want} — refused. The materialization file is not "
                    f"consulted: trusting its hash would let an unsigned "
                    f"file overrule a signed manifest.")
    if entry.get("effect_class") == "pure":
        wp.check_pure_imports(module_bytes)
