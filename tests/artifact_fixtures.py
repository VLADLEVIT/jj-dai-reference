# -*- coding: utf-8 -*-
"""
tests.artifact_fixtures — a REAL signed artifact chain for fixtures
===================================================================
Not a stub. recut5's lifecycle fixtures handed `production` a
`model_artifact_manifest_hash` of `"0" * 64` with `attested: False`, and
the gate accepted it — the fifth audit found the gate this way, by reading
what the fixture got away with.

The lesson is not "write a better stub". A fixture that can satisfy a
security gate by asserting a shape proves that the gate checks shapes. So
this builds the genuine article: a real profile document, a real file whose
bytes are measured, a real `WeightAttestation` over those bytes, a real
`DeploymentManifest`, and a `ModelArtifactManifest` signed with a real key.
`core.artifact_binding.bind_artifact` then verifies all of it exactly as it
does in production. If the chain is broken anywhere, the fixture fails —
which is the property we want out of a fixture in the first place.
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from core.artifact_binding import bind_artifact                # noqa: E402
from core.attestation import (make_deployment_manifest,        # noqa: E402
                              make_weight_attestation,
                              measure_artifact)
from jjdai.adapters.manifest import (build_manifest,           # noqa: E402
                                     sign_manifest)
from dataclasses import dataclass                               # noqa: E402
from jjdai.crypto import (SigningKey,                          # noqa: E402
                          canonical_node_id)

@dataclass(frozen=True)
class ArtifactFixture:
    envelope: dict
    attestations: dict
    deployment: dict
    path: str
    substrate_id: str


#: Minimal valid model-family profile. Kept here rather than loaded from
#: jjdai/adapters/models/ so a fixture does not silently depend on which
#: families happen to ship.
PROFILE = {
    "schema": "jjdai.model-profile/v1",
    "family": "fixture-family",
    "architecture": "fixture-arch",
    "tokenizer": "fixture-tokenizer",
    "chat_template": "fixture-template",
    "attention": "gqa",
    "precisions": ["int8"],
}


def signed_artifact(tmpdir, *, backend="hash", fingerprint="fp-fixture",
                    quantization="int8", weights=b"fixture weights v1",
                    name="weights.bin"):
    """-> ArtifactFixture(envelope, attestations, deployment, path, id).

    `path` and `substrate_id` matter: a Node given `--attest-artifact`
    MEASURES the file itself and signs its own attestation, so a harness
    that passes them exercises the real deployment path instead of handing
    the node a pre-made answer.
    """
    sk = SigningKey.generate()
    path = os.path.join(tmpdir, name)
    with open(path, "wb") as fh:
        fh.write(weights)
    measurement = measure_artifact(path)
    substrate_id = measurement["artifact_hash"]        # content-addressed

    att = make_weight_attestation(
        sk, manifest_id=substrate_id, measurement=measurement,
        engine_fingerprint=fingerprint)
    # A deployment manifest is a FIRST-PERSON statement: its signer must be
    # the node it describes. The fixture honours that rather than working
    # around it — the rule is the reason the manifest means anything.
    deployment = make_deployment_manifest(
        sk, node_id=canonical_node_id(sk.public),
        operator_domain="fixture.example",
        jurisdiction="UA", engine_fingerprint=fingerprint,
        substrate_attestations={substrate_id: att}, adapter_ids=[])
    body = build_manifest(
        profile=PROFILE, checkpoint_hash=substrate_id, backend=backend,
        backend_version="fixture-1", runtime_version="fixture-1",
        quantization={"scheme": quantization},
        source="fixture", licenses=["AGPL-3.0-only"])
    return ArtifactFixture(sign_manifest(body, sk), {substrate_id: att},
                           deployment, path, substrate_id)


def bound_refs(tmpdir, engine, **kw):
    """Verified ArtifactRefs for `engine`, through the real binder."""
    fx = signed_artifact(tmpdir,
                         backend=getattr(engine, "backend", "hash"),
                         fingerprint=getattr(engine, "fingerprint",
                                             "fp-fixture"), **kw)
    return bind_artifact(manifest_envelope=fx.envelope, engine=engine,
                         weight_attestations=fx.attestations,
                         deployment=fx.deployment)
