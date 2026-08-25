# -*- coding: utf-8 -*-
"""
core.attestation — Weight attestation + signed DeploymentManifest (v0.5.1)
==========================================================================
Closes the dev-5 audit item "manifest ids are declared, not attested".

Before this module a SubstrateManifest named a content address that nothing
ever checked against real bytes, and ProvenanceManifest let the caller
override operator/jurisdiction with a bare string. Now:

    measure_artifact        — streamed SHA-256 over the actual weight file
    WeightAttestation       — the operator's SIGNED binding
                              manifest_id <-> measured artifact hash
    DeploymentManifest      — the operator's SIGNED description of THIS
                              deployment: node, operator domain,
                              jurisdiction, engine fingerprint, and the
                              full set of attested substrates/adapters
    AttestationStore        — durable journal, fail-closed on reload

Strictness ladder (honest by construction):
  * If a substrate_id is a TRUE content address ("sha256:" + 64 hex), the
    attestation REQUIRES the measured hash to equal it — the manifest and
    the artifact become one fact.
  * If it is a symbolic id (dev/test fixtures like "sha256:base-A"), the
    attestation still pins the measured hash, so any later swap of the
    artifact is detectable; the binding id<->bytes rests on the operator's
    signature alone and is labeled "declared" rather than "content".

WHAT THIS DOES NOT PROVE (stated plainly): without TEE/secure-boot
attestation there is no proof that the ENGINE process actually loaded the
measured bytes into memory. Weight attestation proves the operator
measured the artifact it claims to serve, signed that measurement, and can
be slashed against it. Runtime attestation is the roadmap seam.
"""
from __future__ import annotations

import hashlib
import os
import time

from jjdai.canonical import canonical
from jjdai.crypto import H_hex, SigningKey, verify, canonical_node_id
from jjdai.durable import durable_append, read_journal

WEIGHTS_DOMAIN = b"jjdai/attest/weights/v1:"
DEPLOY_DOMAIN = b"jjdai/attest/deployment/v1:"

_CHUNK = 1 << 20      # 1 MiB read chunks — weights never fit in RAM twice


class AttestationError(RuntimeError):
    pass


def _is_content_address(any_id: str) -> bool:
    if not (isinstance(any_id, str) and any_id.startswith("sha256:")):
        return False
    h = any_id[7:]
    return len(h) == 64 and all(c in "0123456789abcdef" for c in h)


# --------------------------------------------------------------------------- #
#  Measurement
# --------------------------------------------------------------------------- #

def measure_artifact(path: str) -> dict:
    """Streamed SHA-256 measurement of a weight artifact on disk."""
    if not os.path.isfile(path):
        raise AttestationError(f"artifact not found: {path!r}")
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return {"artifact_hash": "sha256:" + h.hexdigest(),
            "size_bytes": size,
            "measured_at": time.time()}


# --------------------------------------------------------------------------- #
#  Weight attestation
# --------------------------------------------------------------------------- #

def _nonblank(value) -> bool:
    """Identity is a non-empty string; None, "" and "  " are one absence."""
    return isinstance(value, str) and bool(value.strip())


def make_weight_attestation(sk: SigningKey, *, manifest_id: str,
                            measurement: dict = None,
                            artifact_path: str = None,
                            engine_fingerprint: str = None) -> dict:
    """The attester's signed binding manifest_id <-> measured bytes.
    Supply either a prior `measurement` or an `artifact_path` to measure
    now. If manifest_id is a TRUE content address, a mismatching
    measurement refuses the attestation outright (fail closed at the
    source — an operator cannot even sign the contradiction)."""
    if measurement is None:
        if artifact_path is None:
            raise AttestationError("need measurement or artifact_path")
        measurement = measure_artifact(artifact_path)
    # recut9: an attestation says WHICH ENGINE measured these bytes. Signing
    # one that names no engine produces a fact nobody can attribute, and a
    # later comparison against it can only succeed by treating absence as
    # agreement — which is the fail-open the seventh audit found.
    if not _nonblank(engine_fingerprint):
        raise AttestationError(
            "a weight attestation must name the engine that measured the "
            "artifact; an absent fingerprint is not 'unspecified', it is a "
            "measurement nobody can attribute")
    binding = "declared"
    if _is_content_address(manifest_id):
        if measurement["artifact_hash"] != manifest_id:
            raise AttestationError(
                f"artifact measures {measurement['artifact_hash']} but the "
                f"manifest id claims {manifest_id} — refusing to sign a "
                "false content binding")
        binding = "content"
    body = {
        "kind": "WEIGHT_ATTESTATION",
        "manifest_id": manifest_id,
        "artifact_hash": measurement["artifact_hash"],
        "size_bytes": measurement["size_bytes"],
        "binding": binding,               # "content" | "declared"
        "engine_fingerprint": engine_fingerprint,
        "attester_node": canonical_node_id(sk.public),
        "measured_at": measurement["measured_at"],
    }
    sig = sk.sign(WEIGHTS_DOMAIN + canonical(body))
    return {"body": body, "pub": sk.public.hex(), "sig": sig.hex()}


def verify_weight_attestation(env: dict, *, manifest_id: str = None,
                              expected_hash: str = None) -> tuple:
    """-> (ok, reason). Offline."""
    try:
        body, pub, sig = env["body"], bytes.fromhex(env["pub"]), bytes.fromhex(env["sig"])
    except (KeyError, TypeError, ValueError):
        return False, "malformed envelope"
    if body.get("kind") != "WEIGHT_ATTESTATION":
        return False, "wrong kind"
    if canonical_node_id(pub) != body.get("attester_node"):
        return False, "attester_node does not match public key"
    if not verify(pub, WEIGHTS_DOMAIN + canonical(body), sig):
        return False, "bad signature"
    if body.get("binding") not in ("content", "declared"):
        return False, "unknown binding class"
    if _is_content_address(body.get("manifest_id", "")):
        if body["binding"] != "content" \
                or body.get("artifact_hash") != body["manifest_id"]:
            return False, ("content-addressed manifest id must carry a "
                           "matching content binding")
    if manifest_id is not None and body.get("manifest_id") != manifest_id:
        return False, "attests a different manifest"
    if expected_hash is not None and body.get("artifact_hash") != expected_hash:
        return False, "attests a different artifact"
    return True, "ok"


# --------------------------------------------------------------------------- #
#  Deployment manifest
# --------------------------------------------------------------------------- #

def make_deployment_manifest(sk: SigningKey, *, node_id: str,
                             operator_domain: str, jurisdiction: str,
                             engine_fingerprint: str,
                             substrate_attestations: dict,
                             adapter_ids: list = None,
                             base_url: str = None) -> dict:
    """The operator's SIGNED description of one running deployment.
    substrate_attestations: {substrate_id: WeightAttestation envelope}.
    Every embedded attestation is verified before signing; a deployment
    manifest can never carry an attestation its own signer would reject.
    The signer must BE the node it describes — a deployment manifest is a
    first-person statement, not gossip."""
    if canonical_node_id(sk.public) != node_id:
        raise AttestationError(
            "deployment manifest must be signed by the node it describes")
    if not _nonblank(engine_fingerprint):
        raise AttestationError(
            "a deployment manifest must name the engine it runs")
    attested = {}
    for sid, att in sorted((substrate_attestations or {}).items()):
        ok, why = verify_weight_attestation(att, manifest_id=sid)
        if not ok:
            raise AttestationError(
                f"refusing to embed invalid attestation for {sid!r}: {why}")
        # recut8: an attestation may be perfectly signed and still belong to
        # a DIFFERENT deployment. A manifest that embeds one is internally
        # contradictory — it says "this node, this engine" over evidence
        # produced by another node or another engine — and the honest place
        # to stop that is before it is signed, not after.
        ab = att["body"]
        if ab.get("attester_node") != node_id:
            raise AttestationError(
                f"refusing to embed attestation for {sid!r} attested by "
                f"{ab.get('attester_node')!r}: a deployment manifest is a "
                f"first-person statement and {node_id!r} cannot vouch for "
                "someone else's measurement")
        if ab.get("engine_fingerprint") != engine_fingerprint:
            raise AttestationError(
                f"refusing to embed attestation for {sid!r} taken under "
                f"engine {ab.get('engine_fingerprint')!r} in a deployment "
                f"that declares {engine_fingerprint!r}")
        attested[sid] = att
    body = {
        "kind": "DEPLOYMENT_MANIFEST",
        "node_id": node_id,
        "operator_domain": operator_domain,
        "jurisdiction": jurisdiction,
        "engine_fingerprint": engine_fingerprint,
        "substrates": {sid: {"attestation_hash": H_hex(canonical(att)),
                             "artifact_hash": att["body"]["artifact_hash"],
                             "binding": att["body"]["binding"]}
                       for sid, att in attested.items()},
        "adapter_ids": sorted(adapter_ids or []),
        "base_url": base_url,
        "created_at": time.time(),
    }
    sig = sk.sign(DEPLOY_DOMAIN + canonical(body))
    return {"body": body, "pub": sk.public.hex(), "sig": sig.hex(),
            "attestations": attested}


def verify_deployment_manifest(env: dict, *, node_id: str = None) -> tuple:
    """-> (ok, reason). Verifies the envelope AND every embedded
    attestation AND their hash binding into the signed body."""
    try:
        body, pub, sig = env["body"], bytes.fromhex(env["pub"]), bytes.fromhex(env["sig"])
    except (KeyError, TypeError, ValueError):
        return False, "malformed envelope"
    if body.get("kind") != "DEPLOYMENT_MANIFEST":
        return False, "wrong kind"
    if not _nonblank(body.get("engine_fingerprint")):
        return False, "names no engine fingerprint"
    if not _nonblank(body.get("node_id")):
        return False, "names no node"
    if canonical_node_id(pub) != body.get("node_id"):
        return False, "node_id does not match public key"
    if node_id is not None and body.get("node_id") != node_id:
        return False, "describes a different node"
    if not verify(pub, DEPLOY_DOMAIN + canonical(body), sig):
        return False, "bad signature"
    atts = env.get("attestations") or {}
    for sid, ref in (body.get("substrates") or {}).items():
        att = atts.get(sid)
        if att is None:
            return False, f"attestation for {sid!r} missing from the bundle"
        if H_hex(canonical(att)) != ref.get("attestation_hash"):
            return False, f"attestation for {sid!r} does not match the signed hash"
        ok, why = verify_weight_attestation(
            att, manifest_id=sid, expected_hash=ref.get("artifact_hash"))
        if not ok:
            return False, f"attestation for {sid!r} invalid: {why}"
        # recut8: the bundle must be internally CONSISTENT, not merely
        # composed of individually valid parts. Signatures that each verify
        # while describing different nodes or different engines are a
        # contradiction, and a verifier that reports "ok" on one is telling
        # a reader something untrue.
        ab = att["body"]
        if ab.get("attester_node") != body.get("node_id"):
            return False, (f"attestation for {sid!r} was signed by "
                           f"{ab.get('attester_node')!r}, not by the node "
                           f"this deployment describes")
        if ab.get("engine_fingerprint") != body.get("engine_fingerprint"):
            return False, (f"attestation for {sid!r} was taken under engine "
                           f"{ab.get('engine_fingerprint')!r} while the "
                           f"deployment declares "
                           f"{body.get('engine_fingerprint')!r}")
    return True, "ok"


# --------------------------------------------------------------------------- #
#  Durable store
# --------------------------------------------------------------------------- #

class AttestationStore:
    """Durable journal of weight attestations and deployment manifests.
    FAIL CLOSED on reload — every persisted envelope is re-verified."""

    def __init__(self, path: str = None):
        self.path = path
        self._weights: dict = {}      # manifest_id -> env
        self._deployments: dict = {}  # node_id -> env
        if path and os.path.exists(path):
            entries, _ = read_journal(path)
            for e in entries:
                if e.get("kind") == "WEIGHT_ATTESTATION_REC":
                    ok, why = verify_weight_attestation(e["env"])
                    if not ok:
                        raise AttestationError(
                            f"attestation journal integrity failure: {why}")
                    self._weights[e["env"]["body"]["manifest_id"]] = e["env"]
                elif e.get("kind") == "DEPLOYMENT_MANIFEST_REC":
                    ok, why = verify_deployment_manifest(e["env"])
                    if not ok:
                        raise AttestationError(
                            f"deployment journal integrity failure: {why}")
                    self._deployments[e["env"]["body"]["node_id"]] = e["env"]

    def _persist(self, kind: str, env: dict):
        if self.path:
            durable_append(self.path, {"kind": kind, "env": env})

    def hold_weight(self, env: dict) -> str:
        ok, why = verify_weight_attestation(env)
        if not ok:
            raise AttestationError(f"attestation rejected: {why}")
        mid = env["body"]["manifest_id"]
        held = self._weights.get(mid)
        if held is not None:
            if held["body"]["artifact_hash"] != env["body"]["artifact_hash"]:
                raise AttestationError(
                    f"{mid!r} already attested with hash "
                    f"{held['body']['artifact_hash']} — a differing "
                    "re-attestation is a governance event, not an update")
            return mid
        self._weights[mid] = env
        self._persist("WEIGHT_ATTESTATION_REC", env)
        return mid

    def hold_deployment(self, env: dict) -> str:
        ok, why = verify_deployment_manifest(env)
        if not ok:
            raise AttestationError(f"deployment manifest rejected: {why}")
        nid = env["body"]["node_id"]
        self._deployments[nid] = env
        self._persist("DEPLOYMENT_MANIFEST_REC", env)
        return nid

    def weight(self, manifest_id: str) -> dict | None:
        return self._weights.get(manifest_id)

    def deployment(self, node_id: str) -> dict | None:
        return self._deployments.get(node_id)
