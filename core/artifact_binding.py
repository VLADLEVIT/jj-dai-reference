# -*- coding: utf-8 -*-
"""
core.artifact_binding — which weights actually answered (v0.6.7-recut5.1)
=========================================================================
recut5 put `model_artifact_manifest_hash` into the DecisionTrace and had
`production` refuse when it was empty. The fifth audit showed that this was
still a false green, for four reasons at once, and it was worth writing all
four down because each is a different way to fake provenance:

  1. the seat read the manifest out of the DRIVER (`attestation_manifest()`),
     and exactly one driver implements it — the reference `hash` backend.
     Every real backend returned `unknown` / `attested: False`, so the field
     was empty precisely on the hosts where it matters;
  2. the seat called `validate_manifest_body()` — a SCHEMA check. Nothing
     verified the manifest's SIGNATURE. A well-formed manifest anybody could
     write passed;
  3. the gate tested "is this string non-empty". A test fixture handing over
     `"0" * 64` with `attested: False` satisfied `production`;
  4. it ran after generation, so a node whose provenance was unprovable
     served, thought, and only then refused — per task, forever.

So the binding is built ONCE, at boot, from an operator-supplied signed
envelope, and it is a CHAIN rather than a field:

    signed ModelArtifactManifest      (verify_manifest: schema + hash + sig)
        → checkpoint_hash  ==  a verified WeightAttestation.artifact_hash
        → engine_fingerprint  ==  the DeploymentManifest's fingerprint
        → backend  ==  the driver actually loaded
        → quantization read FROM the verified body, never asserted

Every link is checked, any break refuses, and the result is FROZEN: a seat
cannot edit what it reports about the weights behind it. `verified` is set
by this module and nowhere else, so a fixture that wants to look bound has
to produce a genuinely signed chain — which is the point.
"""
from __future__ import annotations

from dataclasses import dataclass

from jjdai.canonical import canonical
from jjdai.crypto import H_hex
from jjdai.adapters.manifest import verify_manifest
from core.attestation import (verify_deployment_manifest,
                              verify_weight_attestation)

UNKNOWN = "unknown"


class ArtifactBindingError(RuntimeError):
    """The chain from decision to weights is broken. Always fail-closed.

    Carries `manifest_verified` so a caller can record WHICH link failed.
    recut7 introduced the flag and then threw the fact away: the daemon
    called `unbound()` without it, so `manifest_verified` was true only
    when `verified` already was, and the distinction it existed to draw
    never appeared (sixth audit, non-blocking).
    """

    def __init__(self, message, *, manifest_verified: bool = False):
        super().__init__(message)
        self.manifest_verified = bool(manifest_verified)


@dataclass(frozen=True)
class ArtifactRefs:
    """What a seat may say about the artifact behind it. Immutable."""

    #: The WHOLE chain held: manifest signature, measured weights, and a
    #: signed deployment that carries them. Only this admits production.
    verified: bool
    reason: str
    #: The manifest alone verified. Recorded because "the description is
    #: genuine but nothing measured it" is a real and different state from
    #: "nothing verified at all" — and because recut6 conflated them,
    #: returning verified=True for exactly that case (audit, recut7).
    manifest_verified: bool = False
    engine_fingerprint: str = None
    determinism_level: str = None
    model_artifact_manifest_hash: str = None
    deployment_manifest_hash: str = None
    checkpoint_hash: str = None
    quantization: str = UNKNOWN
    attested: bool = False

    def as_trace_fields(self) -> dict:
        """The subset that goes into a DecisionTrace generator block."""
        return {
            "engine_fingerprint": self.engine_fingerprint,
            "determinism_level": self.determinism_level,
            "model_artifact_manifest_hash": self.model_artifact_manifest_hash,
            "deployment_manifest_hash": self.deployment_manifest_hash,
            "checkpoint_hash": self.checkpoint_hash,
            "quantization": self.quantization,
            "attested": self.attested,
            "manifest_verified": self.manifest_verified,
            "artifact_verified": self.verified,
        }


def _nonblank(value) -> bool:
    """An identity is a non-empty string. `None`, `""` and `"  "` are not
    three shades of unspecified — they are the same absence."""
    return isinstance(value, str) and bool(value.strip())


def _identity(obj, attr: str, message: str) -> str:
    value = getattr(obj, attr, None)
    if not _nonblank(value):
        raise ArtifactBindingError(message, manifest_verified=True)
    return value


def unbound(reason: str, *, engine=None, manifest_verified: bool = False,
            deployment_manifest_hash: str = None) -> ArtifactRefs:
    """An honest 'I cannot name my weights', with the reason kept.

    `unknown` is a VALUE here, not an absence: a node that says it does not
    know is telling the truth, and `production` refuses it. What is
    forbidden is inventing a precision, which is what the hardcoded `int4`
    of recut4 did.
    """
    return ArtifactRefs(
        verified=False, reason=reason, manifest_verified=manifest_verified,
        engine_fingerprint=getattr(engine, "fingerprint", None),
        determinism_level=getattr(engine, "determinism_level", None),
        deployment_manifest_hash=deployment_manifest_hash)


def deployment_hash(deployment: dict) -> str:
    return H_hex(canonical(deployment["body"])) if deployment else None


def _quantization_of(body: dict) -> str:
    q = body.get("quantization")
    if isinstance(q, dict):
        return q.get("scheme") or q.get("precision") or UNKNOWN
    if isinstance(q, str) and q:
        return q
    return UNKNOWN


def bind_artifact(*, manifest_envelope: dict, engine,
                  weight_attestations: dict = None,
                  deployment: dict = None) -> ArtifactRefs:
    """Verify the WHOLE chain, or raise. Never returns a partial binding.

    recut7, sixth audit. recut6 built four of the five links and left the
    fifth unchecked, which is worse than not having it: `VERT-10` asserted
    a guarantee the code did not provide. Specifically the binder read
    `engine_fingerprint` out of the DeploymentManifest and hashed its body
    without ever calling `verify_deployment_manifest()`, so a manifest with
    a zeroed signature or an empty `substrates` map bound clean; and
    `require_attestation=False` returned `verified=True, attested=False`
    while the docstring claimed production would refuse it — production
    reads only `verified`, so it did not.

    Both are gone. There is no partial mode and no flag that relaxes the
    chain: a deployment is REQUIRED, its signature is checked, the weight
    attestations are taken FROM the verified bundle, and the checkpoint the
    ModelArtifactManifest names must actually appear among the substrates
    that deployment signed for. `verified` means all of it.
    """
    if not isinstance(manifest_envelope, dict):
        raise ArtifactBindingError(
            "no model artifact manifest supplied: a decision that cannot "
            "name the weights that produced it is unprovable, whatever the "
            "trace says")

    body = verify_manifest(manifest_envelope)     # schema + hash + signature

    # ---- the engine must NAME ITSELF before anything can match it ----- #
    # recut9, seventh audit. Every comparison below used to be guarded by
    # truthiness — `if dep_fp and fp and dep_fp != fp` — so when both sides
    # were empty no mismatch arose and the whole chain came back
    # `verified=True`. recut8's own CHANGELOG had already written the rule
    # down ("`engine_fingerprint: None` is not 'unspecified', it is a
    # measurement nobody can say which engine produced") while the code
    # kept treating absence as agreement. An unnamed identity is not a
    # weak match, it is no identity, and it is refused here rather than
    # compared.
    backend = _identity(engine, "backend",
                        "the loaded engine states no backend: a driver that "
                        "cannot say what it is cannot be matched against a "
                        "manifest that names one")
    fp = _identity(engine, "fingerprint",
                   "the loaded engine states no fingerprint: without one, "
                   "nothing distinguishes these weights from any others")

    if body["backend"] != backend:
        raise ArtifactBindingError(
            f"manifest describes backend {body['backend']!r} but this node "
            f"runs {backend!r} — the manifest belongs to another deployment",
            manifest_verified=True)

    # ---- the deployment, VERIFIED (recut7) ---------------------------- #
    if not isinstance(deployment, dict):
        raise ArtifactBindingError(
            "no deployment manifest supplied: a signed description of "
            "weights is not evidence that this node holds them, and the "
            "deployment is the only signed statement that says which "
            "measured artifacts this node actually serves",
            manifest_verified=True)
    ok, why = verify_deployment_manifest(deployment)
    if not ok:
        raise ArtifactBindingError(
            f"deployment manifest does not verify: {why}",
            manifest_verified=True)
    dep_body = deployment["body"]
    dep_hash = deployment_hash(deployment)

    dep_fp = dep_body.get("engine_fingerprint")
    if not _nonblank(dep_fp):
        raise ArtifactBindingError(
            "the deployment manifest names no engine fingerprint",
            manifest_verified=True)
    if dep_fp != fp:
        raise ArtifactBindingError(
            f"deployment manifest attests engine {dep_fp!r} while the "
            f"loaded driver reports {fp!r}", manifest_verified=True)

    # ---- the checkpoint must be IN what the deployment signed for ----- #
    checkpoint = body.get("checkpoint_hash")
    substrates = dep_body.get("substrates") or {}
    named = [sid for sid, ref in substrates.items()
             if ref.get("artifact_hash") == checkpoint]
    if not named:
        raise ArtifactBindingError(
            f"the deployment manifest signs for {sorted(substrates)} and "
            f"none of them measures the checkpoint this manifest names "
            f"({checkpoint}); a deployment that does not carry these "
            "weights cannot vouch for them", manifest_verified=True)

    # ---- attestations come FROM the verified bundle -------------------- #
    # verify_deployment_manifest already checked each embedded attestation
    # against the hash the signed body commits to, so this set is the one
    # the operator signed. An externally supplied set is not trusted beside
    # it — it must be byte-identical, or it is a second, unsigned opinion.
    embedded = deployment.get("attestations") or {}
    for sid in named:
        if sid not in embedded:
            raise ArtifactBindingError(
                f"the deployment names substrate {sid!r} but its bundle "
                "carries no attestation for it", manifest_verified=True)
    # ---- the attestation must be about THIS engine (recut8) ----------- #
    # recut6 checked this and the recut7 rewrite dropped it, which is how a
    # validly signed but semantically contradictory chain bound clean:
    # running engine fp-running, deployment fp-running, attestation
    # fp-different. `verify_deployment_manifest` now refuses that bundle
    # offline, and `make_deployment_manifest` refuses to build one — this
    # third check is against the engine actually LOADED here, which neither
    # of those can see.
    for sid in named:
        ab = embedded[sid]["body"]
        att_fp = ab.get("engine_fingerprint")
        if not _nonblank(att_fp):
            raise ArtifactBindingError(
                f"the weight attestation for {sid!r} names no engine: a "
                "measurement nobody can attribute to an engine is not "
                "provenance", manifest_verified=True)
        if att_fp != fp:
            raise ArtifactBindingError(
                f"the weight attestation for {sid!r} was taken under engine "
                f"{att_fp!r} and this node runs {fp!r}: measured bytes and "
                "the engine that measured them are one statement, not two",
                manifest_verified=True)
        if ab.get("attester_node") != dep_body.get("node_id"):
            raise ArtifactBindingError(
                f"the attestation for {sid!r} was signed by "
                f"{ab.get('attester_node')!r} while the deployment "
                f"describes {dep_body.get('node_id')!r}",
                manifest_verified=True)

    if weight_attestations:
        for sid, env in weight_attestations.items():
            if sid not in embedded:
                raise ArtifactBindingError(
                    f"weight attestation for {sid!r} was supplied outside "
                    "the signed deployment, which does not carry it",
                    manifest_verified=True)
            if canonical(env) != canonical(embedded[sid]):
                raise ArtifactBindingError(
                    f"the supplied attestation for {sid!r} differs byte for "
                    "byte from the one the deployment signed",
                    manifest_verified=True)

    quant = _quantization_of(body)
    if quant == UNKNOWN:
        raise ArtifactBindingError(
            "the verified manifest states no quantization; a binding that "
            "cannot say how the weights are represented is incomplete, and "
            "guessing is what recut4 did", manifest_verified=True)

    return ArtifactRefs(
        verified=True, reason="ok", manifest_verified=True,
        engine_fingerprint=fp,
        determinism_level=getattr(engine, "determinism_level", None),
        model_artifact_manifest_hash=manifest_envelope.get("manifest_hash"),
        deployment_manifest_hash=dep_hash,
        checkpoint_hash=checkpoint,
        quantization=quant,
        attested=True)
