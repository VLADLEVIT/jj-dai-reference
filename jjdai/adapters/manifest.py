"""jjdai/adapters/manifest.py — model profiles and ModelArtifactManifest.

TWO OBJECTS, DELIBERATELY DIFFERENT IN KIND
-------------------------------------------
A **model-family profile** is written for humans: a declarative description
of a family — tokenizer, chat template, architecture id, attention type, MoE
routing, supported precisions, required operators. Convenient to read, easy
to edit, and therefore NOT a cryptographic object of truth.

A **ModelArtifactManifest** is written for the network. The chain is:

    profile document
        → validation against a VERSIONED schema
        → JCS canonicalization
        → ModelArtifactManifest
        → hash + signature + witness record

That is what turns the provenance hash of SEC-02/SEC-03 in the ASIC spec
from "the hash of one file" into a complete, open chain of origin for the
executable artifact: which checkpoint, which tokenizer and chat template,
which architecture/config hash, which quantization and conversion toolchain,
which profile version, which backend/driver/runtime versions, which weight
adapters, from what source and under what licence, against which golden
tensors and traces.

WHY VALIDATION IS STRICT AND UNKNOWN KEYS ARE REFUSED
-----------------------------------------------------
A silently ignored field is a claim nobody checks. If a profile can carry
`precision: fp8` on a build that has never heard of fp8, the document says
one thing and the run does another, and the manifest signs the disagreement.
Refusing unknown keys keeps the signature meaningful.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")))
from jjdai.canonical import canonical                          # noqa: E402
from jjdai.crypto import H_hex                                 # noqa: E402
from jjdai.adapters.errors import ManifestError, ProfileError  # noqa: E402

#: Bumped when the profile schema changes shape. Carried inside every
#: manifest so a document signed under v1 stays interpretable under v2.
PROFILE_SCHEMA_VERSION = "1"
MANIFEST_SCHEMA_VERSION = "1"

PROFILE_REQUIRED = ("schema", "family", "architecture", "tokenizer",
                    "chat_template", "attention", "precisions")
PROFILE_OPTIONAL = ("moe_routing", "required_operators", "context_window",
                    "notes", "aliases")
PRECISIONS = ("fp32", "fp16", "bf16", "fp8", "int8", "int4", "nf4")
ATTENTION = ("mha", "mqa", "gqa", "mla", "sliding_window")


def validate_profile(doc: dict) -> dict:
    """Validate a model-family profile against the versioned schema."""
    if not isinstance(doc, dict):
        raise ProfileError("profile must be a mapping")
    schema = doc.get("schema")
    if schema != f"jjdai.model-profile/v{PROFILE_SCHEMA_VERSION}":
        raise ProfileError(
            f"unknown profile schema {schema!r}; this build reads "
            f"jjdai.model-profile/v{PROFILE_SCHEMA_VERSION}")
    missing = [k for k in PROFILE_REQUIRED if k not in doc]
    if missing:
        raise ProfileError(f"profile is missing required key(s): {missing}")
    unknown = [k for k in doc
               if k not in PROFILE_REQUIRED + PROFILE_OPTIONAL]
    if unknown:
        raise ProfileError(
            f"profile carries unknown key(s) {unknown}: a field this build "
            f"ignores is a claim nobody checks, and the manifest would sign "
            f"the disagreement")
    if doc["attention"] not in ATTENTION:
        raise ProfileError(f"unknown attention type {doc['attention']!r}; "
                           f"known: {list(ATTENTION)}")
    if not isinstance(doc["precisions"], list) or not doc["precisions"]:
        raise ProfileError("precisions must be a non-empty list")
    bad = [p for p in doc["precisions"] if p not in PRECISIONS]
    if bad:
        raise ProfileError(f"unknown precision(s) {bad}; known: "
                           f"{list(PRECISIONS)}")
    return doc


def load_profile(path: str) -> dict:
    """Read and validate a profile document (JSON; stdlib-only by design)."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as e:
        raise ProfileError(f"cannot read profile {path!r}: {e}") from e
    except json.JSONDecodeError as e:
        raise ProfileError(f"profile {path!r} is not valid JSON: {e}") from e
    return validate_profile(doc)


def profile_hash(doc: dict) -> str:
    """Hash of the CANONICALIZED profile — the stable identity of the
    document, independent of key order or whitespace."""
    return H_hex(canonical(validate_profile(doc)))


def build_manifest(*, profile: dict, checkpoint_hash: str,
                   backend: str, backend_version: str,
                   runtime_version: str = "",
                   protocol_version: str = "1",
                   quantization: dict = None,
                   conversion_toolchain: dict = None,
                   weight_adapters: list = None,
                   source: str = "", licenses: list = None,
                   golden: dict = None) -> dict:
    """Assemble a ModelArtifactManifest body. Canonical, hashable, signable.

    The body carries no timestamp and no node identity: those belong to the
    witness record that wraps it. The manifest describes the ARTIFACT, so
    two nodes holding the same artifact must produce byte-identical bodies —
    otherwise the hash stops being a shared name for the same thing.
    """
    prof = validate_profile(profile)
    if not checkpoint_hash:
        raise ManifestError("checkpoint_hash is required: a manifest without "
                            "the artifact it describes proves nothing")
    body = {
        "schema": f"jjdai.model-artifact/v{MANIFEST_SCHEMA_VERSION}",
        "family": prof["family"],
        "profile_hash": profile_hash(prof),
        "profile_schema": prof["schema"],
        "architecture": prof["architecture"],
        "tokenizer": prof["tokenizer"],
        "chat_template": prof["chat_template"],
        "checkpoint_hash": checkpoint_hash,
        "quantization": quantization or {},
        "conversion_toolchain": conversion_toolchain or {},
        "backend": backend,
        "backend_version": backend_version,
        "runtime_version": runtime_version,
        "protocol_version": protocol_version,
        "weight_adapters": sorted(weight_adapters or []),
        "source": source,
        "licenses": sorted(licenses or []),
        "golden": golden or {},
    }
    return body


def manifest_hash(body: dict) -> str:
    return H_hex(canonical(body))


def sign_manifest(body: dict, sk) -> dict:
    """Wrap a manifest body in a signed envelope.

    Signature is over the canonicalized BODY, never over a rendering of it:
    the same artifact described by two nodes must verify against the same
    bytes regardless of how either serialized it for display.
    """
    digest = manifest_hash(body)
    return {"body": body, "manifest_hash": digest,
            "sig": sk.sign(canonical(body)).hex(),
            "pubkey": sk.public.hex()}


def verify_manifest(envelope: dict) -> dict:
    """Check that an envelope's hash and signature match its body."""
    from jjdai.crypto import verify
    body = envelope.get("body")
    if not isinstance(body, dict):
        raise ManifestError("envelope carries no body")
    digest = manifest_hash(body)
    if envelope.get("manifest_hash") != digest:
        raise ManifestError(
            f"manifest_hash does not match the body it claims to describe "
            f"(declared {envelope.get('manifest_hash')!r}, computed "
            f"{digest!r})")
    try:
        ok = verify(bytes.fromhex(envelope["pubkey"]),
                    canonical(body),
                    bytes.fromhex(envelope["sig"]))
    except (KeyError, ValueError) as e:
        raise ManifestError(f"malformed signature envelope: {e}") from e
    if not ok:
        raise ManifestError("manifest signature does not verify")
    return body


def profiles_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "models")


def load_family(name: str) -> dict:
    """Load an in-tree model-family profile by name."""
    return load_profile(os.path.join(profiles_dir(), f"{name}.json"))


def available_families() -> list:
    d = profiles_dir()
    if not os.path.isdir(d):
        return []
    return sorted(f[:-5] for f in os.listdir(d) if f.endswith(".json"))
