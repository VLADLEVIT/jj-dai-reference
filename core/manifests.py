# -*- coding: utf-8 -*-
"""
core.manifests — Signed substrate / adapter / provenance manifests (v0.5, P1)
=============================================================================
The identity layer for MODELS, mirroring what core.identity gives nodes:
every substrate and adapter that can touch a decision is described by a
signed, content-addressed manifest, and every routable model resolves to a
ProvenanceManifest — the input to diversity-constrained verifier selection
(core.diversity).

    SubstrateManifest  — frozen base weights: content address, lineage
                         (base family, training-data families), architecture
                         family, profile, operator domain, jurisdiction.
    AdapterManifest    — a specialization bound to a substrate compat tag:
                         task domain, its own data families, acceptance
                         evidence reference.
    ProvenanceManifest — the composed identity of a running model
                         (substrate + adapters), DERIVED, not asserted:
                         lineage/architecture come from the substrate
                         manifest, data families are the union.

All envelopes are JCS-canonical, Ed25519-signed with domain separation,
offline-verifiable. The registry is durable (JSONL), verifies before
holding, refuses conflicting re-registration of the same id (manifests are
immutable — supersession is a NEW id), and can enforce a publisher ACL
(fail closed when enabled).
"""
from __future__ import annotations

import os
import time

from jjdai.canonical import canonical
from jjdai.crypto import H_hex, SigningKey, verify, node_id, canonical_node_id
from jjdai.durable import durable_append, read_journal

SUBSTRATE_DOMAIN = b"jjdai/manifest/substrate/v1:"
ADAPTER_DOMAIN = b"jjdai/manifest/adapter/v1:"

PROFILES = ("A", "B")


class ManifestError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
#  Construction
# --------------------------------------------------------------------------- #

def make_substrate_manifest(sk: SigningKey, *, substrate_id: str, name: str,
                            version: str, base_family: str,
                            architecture_family: str,
                            training_data_families: list,
                            profile: str = "B",
                            operator_domain: str = "jj-dai.org",
                            jurisdiction: str = "UA",
                            license_id: str = "AGPL-3.0-only",
                            params_b: float = None,
                            quantization: str = None) -> dict:
    if profile not in PROFILES:
        raise ManifestError(f"unknown profile {profile!r}")
    if not substrate_id.startswith("sha256:"):
        raise ManifestError("substrate_id must be content-addressed (sha256:…)")
    body = {
        "kind": "SUBSTRATE_MANIFEST",
        "substrate_id": substrate_id,
        "name": name, "version": version,
        "frozen": True,                       # substrates are frozen, always
        "lineage": {
            "base_family": base_family,
            "training_data_families": sorted(set(training_data_families)),
        },
        "architecture_family": architecture_family,
        "profile": profile,
        "params_b": params_b,
        "quantization": quantization,
        "operator_domain": operator_domain,
        "jurisdiction": jurisdiction,
        "license": license_id,
        "publisher_node": canonical_node_id(sk.public),
        "created_at": time.time(),
    }
    sig = sk.sign(SUBSTRATE_DOMAIN + canonical(body))
    return {"body": body, "pub": sk.public.hex(), "sig": sig.hex()}


def make_adapter_manifest(sk: SigningKey, *, adapter_id: str,
                          base_compat_tag: str, task_domain: str,
                          training_data_families: list,
                          acceptance_ref: str = None,
                          operator_domain: str = "jj-dai.org",
                          jurisdiction: str = "UA") -> dict:
    if not adapter_id.startswith("sha256:"):
        raise ManifestError("adapter_id must be content-addressed (sha256:…)")
    body = {
        "kind": "ADAPTER_MANIFEST",
        "adapter_id": adapter_id,
        "base_compat_tag": base_compat_tag,
        "task_domain": task_domain,
        "training_data_families": sorted(set(training_data_families)),
        "acceptance_ref": acceptance_ref,
        "operator_domain": operator_domain,
        "jurisdiction": jurisdiction,
        "publisher_node": canonical_node_id(sk.public),
        "created_at": time.time(),
    }
    sig = sk.sign(ADAPTER_DOMAIN + canonical(body))
    return {"body": body, "pub": sk.public.hex(), "sig": sig.hex()}


def verify_manifest(env: dict) -> tuple:
    """Offline verification for either manifest kind."""
    try:
        body, pub, sig = env["body"], bytes.fromhex(env["pub"]), bytes.fromhex(env["sig"])
    except (KeyError, TypeError, ValueError):
        return False, "malformed envelope"
    kind = body.get("kind")
    if kind == "SUBSTRATE_MANIFEST":
        domain = SUBSTRATE_DOMAIN
        if body.get("frozen") is not True:
            return False, "substrate manifests must declare frozen=true"
        if body.get("profile") not in PROFILES:
            return False, "unknown profile"
    elif kind == "ADAPTER_MANIFEST":
        domain = ADAPTER_DOMAIN
    else:
        return False, "unknown kind"
    if canonical_node_id(pub) != body.get("publisher_node"):
        return False, "publisher_node does not match public key"
    if not verify(pub, domain + canonical(body), sig):
        return False, "bad signature"
    return True, "ok"


def manifest_digest(env: dict) -> str:
    """Stable content digest of a manifest envelope (for referencing)."""
    return H_hex(canonical(env["body"]))


# --------------------------------------------------------------------------- #
#  Registry
# --------------------------------------------------------------------------- #

class ManifestRegistry:
    """Durable manifest store. Verifies before holding; ids are immutable
    (conflicting re-registration is refused — supersession is a new id);
    optional publisher ACL fails closed when enabled."""

    def __init__(self, path: str = None, allowed_publishers: set = None):
        self.path = path
        self.allowed = set(allowed_publishers) if allowed_publishers else None
        self._subs: dict = {}      # substrate_id -> env
        self._adps: dict = {}      # adapter_id -> env
        if path and os.path.exists(path):
            entries, _ = read_journal(path)
            for e in entries:
                env = e["env"]
                # FAIL CLOSED on reload: re-verify every manifest signature
                # (and ACL, if enabled) exactly as at registration.
                ok, reason = verify_manifest(env)
                if not ok:
                    raise ManifestError(
                        f"manifest journal integrity failure on reload: {reason}")
                b = env["body"]
                if self.allowed is not None \
                        and b["publisher_node"] not in self.allowed:
                    raise ManifestError(
                        "manifest journal integrity failure on reload: "
                        "publisher not in admission list")
                if b["kind"] == "SUBSTRATE_MANIFEST":
                    self._subs[b["substrate_id"]] = env
                else:
                    self._adps[b["adapter_id"]] = env

    def register(self, env: dict) -> str:
        ok, reason = verify_manifest(env)
        if not ok:
            raise ManifestError(f"manifest rejected: {reason}")
        b = env["body"]
        publisher = b["publisher_node"]
        if self.allowed is not None and publisher not in self.allowed:
            raise ManifestError(
                f"publisher {publisher[:16]}… not in the admission list "
                "(registry fails closed)")
        table, key = ((self._subs, b["substrate_id"])
                      if b["kind"] == "SUBSTRATE_MANIFEST"
                      else (self._adps, b["adapter_id"]))
        if key in table:
            if manifest_digest(table[key]) == manifest_digest(env):
                return key                       # idempotent
            raise ManifestError(
                f"{key} already registered with different content — "
                "manifests are immutable; publish a NEW id to supersede")
        table[key] = env
        if self.path:
            durable_append(self.path, {"kind": "MANIFEST", "env": env})
        return key

    def substrate(self, substrate_id: str) -> dict | None:
        return self._subs.get(substrate_id)

    def adapter(self, adapter_id: str) -> dict | None:
        return self._adps.get(adapter_id)

    # ---- provenance composition ------------------------------------------ #
    def provenance(self, *, model_id: str, substrate_id: str,
                   adapter_ids: list = None,
                   operator_domain: str = None,
                   jurisdiction: str = None,
                   deployment: dict = None) -> dict:
        """Compose the ProvenanceManifest of a RUNNING model. Lineage and
        architecture are DERIVED from registered manifests, not asserted by
        the caller; data families are the union across substrate+adapters.

        v0.5.1: `deployment` — a signed DeploymentManifest envelope. When
        given it is VERIFIED and becomes the source of operator_domain /
        jurisdiction, and the provenance records whether this substrate's
        weights are attested ("content" / "declared") in that deployment.
        Bare-string overrides remain possible but are labeled
        deployment_source="asserted" — a verifier can tell signed facts
        from claims."""
        sub = self.substrate(substrate_id)
        if sub is None:
            raise ManifestError(f"unknown substrate {substrate_id!r}")
        sb = sub["body"]
        families = set(sb["lineage"]["training_data_families"])
        adapters = []
        for aid in adapter_ids or []:
            a = self.adapter(aid)
            if a is None:
                raise ManifestError(f"unknown adapter {aid!r}")
            ab = a["body"]
            if ab["base_compat_tag"] != substrate_id:
                raise ManifestError(
                    f"adapter {aid!r} is bound to {ab['base_compat_tag']!r}, "
                    f"not {substrate_id!r}")
            families |= set(ab["training_data_families"])
            adapters.append(aid)
        deployment_source = "substrate-default"
        attestation = None
        if deployment is not None:
            from core.attestation import verify_deployment_manifest
            ok, why = verify_deployment_manifest(deployment)
            if not ok:
                raise ManifestError(f"deployment manifest invalid: {why}")
            db = deployment["body"]
            operator_domain = db["operator_domain"]
            jurisdiction = db["jurisdiction"]
            deployment_source = "signed-deployment"
            ref = (db.get("substrates") or {}).get(substrate_id)
            attestation = ({"artifact_hash": ref["artifact_hash"],
                            "binding": ref["binding"]}
                           if ref else None)
        elif operator_domain is not None or jurisdiction is not None:
            deployment_source = "asserted"
        return {
            "kind": "PROVENANCE_MANIFEST",
            "model_id": model_id,
            "substrate_id": substrate_id,
            "adapter_ids": sorted(adapters),
            "base_family": sb["lineage"]["base_family"],
            "architecture_family": sb["architecture_family"],
            "training_data_families": sorted(families),
            "operator_domain": operator_domain or sb["operator_domain"],
            "jurisdiction": jurisdiction or sb["jurisdiction"],
            "deployment_source": deployment_source,
            "weight_attestation": attestation,
        }
