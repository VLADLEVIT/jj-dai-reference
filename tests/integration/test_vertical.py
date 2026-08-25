#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_vertical — v0.6.7: one path, one engine, one identity
===========================================================
Three ways of making this node think used to exist, and none of them went
through the whole organism:

  /v1/messages            the real engine, no DecisionTrace, no Karma
  /v1/tasks               the full BeingRuntime — on THREE synthetic
                          engines built by `core.router._mk_node`, a helper
                          declared inside the router's own acceptance-test
                          section, one of them with `noise=0.05`
  live_engine_acceptance  both, but around the daemon, mTLS and attestation

The middle row was the dangerous one. Weight attestation and /capabilities
described the real configured backend while the signed DecisionTrace that
entered the witness chain came from a test fixture: the node witnessed the
work of an engine that was never attested and is not a model.

The fixtures are gone. What replaces them is not a cleverer panel — it is
an honest refusal, because one engine is one place and one place is not a
panel (ADR-019 D1).

  VERT-1  the Being thinks with the node's REAL backend: the seat carries
          the backend's own fingerprint and determinism level, and no
          reference fixture is reachable from the daemon at all.
  VERT-2  the verifier role is declared from what the driver IMPLEMENTS,
          never assumed; a backend without `score` gets no verifier role
          and no substitute verdict is manufactured.
  VERT-3  a lone node in `production` REFUSES, and the refusal carries a
          reason CODE plus a digest — never free text, which the witness
          plane rejects outright.
  VERT-4  the labelled path completes end to end on the real engine and
          says `mode: "self"` in the trace rather than naming a panel.
  VERT-5  the Being has its OWN canonical identity from its OWN key, and
          `being:<node_id[:16]>` is gone.
  VERT-6  a hosting binding is what entitles this node to witness for this
          being, and readiness degrades honestly without one.
"""
from __future__ import annotations

import io
import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import readiness as R                                          # noqa: E402
from core.identity import (BeingIdentity, IdentityError,       # noqa: E402
                           NodeIdentity,
                           make_hosting_binding)
from daemon import Node, _BeingEngineSeat                      # noqa: E402
from jjdai.adapters.registry import (BackendConfig,            # noqa: E402
                                     create as create_backend,
                                     load_builtin)
from jjdai.crypto import SigningKey                            # noqa: E402
from runtime.being import OUTCOME_CODES, OUTCOME_NO_PANEL      # noqa: E402

load_builtin()

PROV = {"m:self": {"model_id": "m:self", "base_family": "fam-S",
                   "architecture_family": "arch-s",
                   "training_data_families": ["ds-s"],
                   "operator_domain": "self.example", "jurisdiction": "UA"}}


def _engine(fp="fp:hash-ref"):
    return create_backend("hash", BackendConfig(
        fingerprint=fp, determinism_level="reproducible"))


def _node(tmp, profile, *, engine=None, provenance=None, tag="n",
          being_identity=None, identity=None, bind=True, artifact=True):
    """A node for the vertical checks.

    `bind` is the recut5 knob: production now demands a persistent being,
    a persistent node and a valid hosting binding between the two, so the
    harness must supply what a real deployment supplies. Passing
    bind=False reproduces the pre-recut5 situation on purpose.
    """
    if bind:
        being_identity = being_identity or BeingIdentity(SigningKey.generate())
        identity = identity or NodeIdentity(SigningKey.generate())
    engine = engine if engine is not None else _engine()
    manifest, substrates, artifacts = None, ["sha256:base-A"], None
    if artifact and profile == "production":
        # recut6: production is a BOOT gate on the artifact chain, so the
        # harness supplies what an operator supplies — a signed manifest
        # AND the weights themselves, which the node measures for itself.
        sys.path.insert(0, os.path.join(_ROOT, "tests"))
        from artifact_fixtures import signed_artifact
        fx = signed_artifact(tmp, backend=engine.backend,
                             fingerprint=engine.fingerprint,
                             name=f"{tag}-weights.bin")
        manifest = fx.envelope
        substrates = [fx.substrate_id]
        artifacts = {fx.substrate_id: fx.path}
    return Node(name="vert", profile="A", substrates=substrates,
                adapters={}, engine=engine,
                model_artifact_manifest=manifest,
                attest_artifacts=artifacts,
                log_path=os.path.join(tmp, f"{tag}.jsonl"),
                being_identity=being_identity, identity=identity,
                being_profile=profile, being_provenance=provenance,
                being_workspace=os.path.join(tmp, f"{tag}-ws"),
                being_journal_dir=os.path.join(tmp, f"{tag}-j"))


def test_the_being_thinks_with_the_real_backend():
    with tempfile.TemporaryDirectory() as tmp:
        eng = _engine("fp:the-real-one")
        n = _node(tmp, "dev", engine=eng)
        seat = n.being.router.nodes["n-self"]
        assert isinstance(seat, _BeingEngineSeat), type(seat)
        desc = seat.describe()
        fps = {e.engine_fingerprint for e in desc.engines}
        assert fps == {"fp:the-real-one"}, (
            f"the seat describes something other than the configured "
            f"backend: {fps}")
        assert {e.determinism_level for e in desc.engines} == {"reproducible"}
        assert desc.attributes["backend"] == "hash"

    # and the fixture is not reachable from the daemon any more
    src = io.open(os.path.join(_ROOT, "node", "daemon.py"),
                  encoding="utf-8").read()
    # No CALL to the fixture helper. The comment that explains why it left
    # is allowed to name it — a check that forbids the word would forbid
    # writing down the reason, and the reason is the valuable part.
    calls = [ln for ln in src.splitlines()
             if "_mk_node" in ln and not ln.lstrip().startswith("#")]
    assert not calls, (
        "VERT-1: node/daemon.py still CALLS the router's acceptance-test "
        f"helper; attestation would describe one engine while the signed "
        f"trace came from another: {calls}")
    print("  [PASS] VERT-1  the seat is the configured backend, fixtures gone")


def test_verifier_role_is_implemented_not_assumed():
    with tempfile.TemporaryDirectory() as tmp:
        n = _node(tmp, "dev")
        roles = {e.role for e in n.being.router.nodes["n-self"].describe().engines}
        assert roles == {"generator", "verifier"}, roles

        # a backend that does NOT implement score gets no verifier role
        eng = _engine()

        class _NoScore:
            backend = "no-score"
            fingerprint = "fp:no-score"
            determinism_level = "attested"

            def capabilities(self):
                caps = eng.capabilities()
                caps = dict(caps)
                caps["implemented"] = dict(caps["implemented"])
                caps["implemented"]["execution"] = ["generate"]
                return caps

        seat = _BeingEngineSeat(type("N", (), {"engine": _NoScore()})(),
                                "n-self", "sha256:base-A")
        roles2 = {e.role for e in seat.describe().engines}
        assert roles2 == {"generator"}, (
            f"a backend with no forced-continuation scoring was given a "
            f"verifier role anyway: {roles2}")
    print("  [PASS] VERT-2  the verifier role is read from the driver")


def test_a_lone_production_node_refuses_in_a_reason_code():
    with tempfile.TemporaryDirectory() as tmp:
        n = _node(tmp, "production", provenance=PROV, tag="p")
        tr = n.being.handle_task({"text": "verify this on your own",
                                  "action": {"kind": "fs_write",
                                             "path": "x.txt",
                                             "content": "no"}})
        assert tr.state == "REFUSED", (tr.state, tr.outcome_reason)
        assert "independent" in (tr.outcome_reason or ""), tr.outcome_reason
        last = [t for t in tr.transitions if t["to"] == "REFUSED"][-1]
        detail = last["detail"]
        assert detail["reason_code"] == OUTCOME_NO_PANEL, detail
        assert detail["reason_code"] in OUTCOME_CODES
        assert detail["reason_codes_version"] == "1"
        assert len(detail["detail_hash"]) == 64
        # the prose must NOT be there: the witness plane refuses free text,
        # so a refusal carrying it does not record at all — it raises.
        assert "reason" not in detail and "error" not in detail, detail
        assert n.chain.verify_chain(), "the refusal broke the chain"
        # the action did not happen
        assert not os.path.exists(os.path.join(tmp, "p-ws", "x.txt"))
    print("  [PASS] VERT-3  a lone production node refuses, in a code the "
          "network can read")


def test_the_labelled_path_completes_and_says_so():
    with tempfile.TemporaryDirectory() as tmp:
        n = _node(tmp, "dev", tag="d")
        tr = n.being.handle_task({"text": "write the milestone",
                                  "action": {"kind": "fs_write",
                                             "path": "m.txt",
                                             "content": "alive"}})
        assert tr.state == "RECORDED", (tr.state, tr.outcome_reason)
        assert tr.verifier_panel["mode"] == "self", tr.verifier_panel
        assert "selected" not in tr.verifier_panel, (
            "a self-verified trace listed panel members")
        assert tr.generator["object_id"] == "m:self"
        assert io.open(os.path.join(tmp, "d-ws", "m.txt")).read() == "alive"
        assert n.chain.verify_chain()
    print("  [PASS] VERT-4  the labelled path completes on the real engine "
          "and admits mode=self")


def test_the_being_has_its_own_identity():
    with tempfile.TemporaryDirectory() as tmp:
        n = _node(tmp, "dev", tag="i", bind=False)
        assert n.being_id.startswith("being:")
        assert len(n.being_id) == len("being:") + 64, n.being_id
        assert n.being_id[len("being:"):] != n.chain.node_id[len("node:"):16], (
            "the being id is still a slice of the node id")
        assert n.being_ephemeral is True, (
            "a node with no being keystore must SAY its being is ephemeral")

        # with a keystore the identity is stable across restarts
        ks = os.path.join(tmp, "being.keystore")
        one = BeingIdentity.load_or_create(ks, "pass")
        two = BeingIdentity.load_or_create(ks, "pass")
        assert one.being_id == two.being_id, "the being did not survive"
        n2 = Node(name="v", profile="A", substrates=["sha256:base-A"],
                  adapters={}, engine=_engine(),
                  log_path=os.path.join(tmp, "i2.jsonl"),
                  being_identity=one, being_profile="dev",
                  being_workspace=os.path.join(tmp, "i2-ws"),
                  being_journal_dir=os.path.join(tmp, "i2-j"))
        assert n2.being_id == one.being_id
        assert n2.being_ephemeral is False

    src = io.open(os.path.join(_ROOT, "node", "daemon.py"),
                  encoding="utf-8").read()
    assert 'f"being:{self.chain.node_id[:16]}"' not in src, \
        "VERT-5: the being is still minted out of the node id"
    print("  [PASS] VERT-5  the being carries a canonical id from its own key")


def test_binding_is_what_entitles_the_node():
    being = BeingIdentity(SigningKey.generate())
    node = NodeIdentity(SigningKey.generate())
    other = NodeIdentity(SigningKey.generate())
    binding = make_hosting_binding(being, node, since_ts=1_750_000_000.0)

    base = {"identity_loaded": True}
    assert R.evaluate_identity(dict(base, being_ephemeral=True))["state"] \
        == R.DEGRADED
    unbound = R.evaluate_identity(dict(base, being_ephemeral=False))
    assert unbound["state"] == R.DEGRADED, unbound
    assert "hosting binding" in unbound["reason"], unbound["reason"]
    bound = R.evaluate_identity(dict(base, being_ephemeral=False,
                                     being_bound=True))
    assert bound["state"] == R.READY, bound

    from core.identity import entitled_to_witness
    assert entitled_to_witness(binding, being_id=being.being_id,
                               node_id=node.node_id)
    assert not entitled_to_witness(binding, being_id=being.being_id,
                                   node_id=other.node_id)
    assert not entitled_to_witness(None, being_id=being.being_id,
                                   node_id=node.node_id)
    print("  [PASS] VERT-6  entitlement comes from the binding; readiness "
          "degrades honestly without one")


def test_the_daemon_enforces_the_binding_it_reports():
    """VERT-7 (recut5, audit P0.2).

    VERT-6 above proved the HELPER and nothing else, and that is exactly
    how the defect stayed green: `entitled_to_witness` was correct, tested
    and never called on the runtime path. Readiness reported
    `being_bound = bool(hosting_binding)`, so `{"garbage": true}` read
    READY, and a `being_id` naming one being while the keystore held
    another's key was never compared. This checks the ENFORCEMENT.
    """
    with tempfile.TemporaryDirectory() as tmp:
        being = BeingIdentity(SigningKey.generate())
        stranger = BeingIdentity(SigningKey.generate())
        node = NodeIdentity(SigningKey.generate())
        other = NodeIdentity(SigningKey.generate())

        def build(**kw):
            base = dict(name="vert", profile="A",
                        substrates=["sha256:base-A"], adapters={},
                        engine=_engine(), being_profile="dev",
                        being_workspace=os.path.join(tmp, "e-ws"),
                        being_journal_dir=os.path.join(tmp, "e-j"))
            base.update(kw)
            return Node(**base)

        # a) garbage binding is refused, not reported as bound
        try:
            build(log_path=os.path.join(tmp, "a.jsonl"),
                  being_identity=being, identity=node,
                  hosting_binding={"garbage": True})
            raise AssertionError(
                "VERT-7: a node accepted a hosting binding that does not "
                "verify — the shape that made bool() look like a check")
        except IdentityError as e:
            assert "does not verify" in str(e), e

        # b) a VALID binding between two other parties is not an
        #    entitlement for these
        try:
            build(log_path=os.path.join(tmp, "b.jsonl"),
                  being_identity=being, identity=node,
                  hosting_binding=make_hosting_binding(stranger, other,
                                                       since_ts=1.0))
            raise AssertionError(
                "VERT-7: a node accepted a binding naming another being on "
                "another node")
        except IdentityError as e:
            assert "not an entitlement" in str(e), e

        # c) a supplied being_id that the keystore does not derive
        try:
            build(log_path=os.path.join(tmp, "c.jsonl"),
                  being_identity=being, identity=node,
                  being_id=stranger.being_id)
            raise AssertionError(
                "VERT-7: a node carried a being_id its own key does not "
                "derive — an id that is not the hash of the key that signs "
                "for it is a label, not an identity")
        except IdentityError as e:
            assert "derives" in str(e), e

        # d) production refuses an ephemeral being outright
        try:
            build(log_path=os.path.join(tmp, "d.jsonl"),
                  being_profile="production", being_provenance=PROV)
            raise AssertionError(
                "VERT-7: production started with an ephemeral being")
        except IdentityError as e:
            assert "PERSISTENT being" in str(e), e

        # e) the honest path: bound, and readiness says so from the
        #    VERIFIED predicate rather than from truthiness
        n = build(log_path=os.path.join(tmp, "e.jsonl"),
                  being_identity=being, identity=node)
        assert n.hosting_binding and n.being_id == being.being_id
        snap = n.readiness_snapshot()
        assert snap["being_bound"] is True, snap
        n.hosting_binding = {"garbage": True}
        assert n.readiness_snapshot()["being_bound"] is False, (
            "VERT-7: readiness still reports boundness by truthiness")
    print("  [PASS] VERT-7  the daemon ENFORCES the binding, and readiness "
          "reports a verified entitlement rather than a non-empty dict")


def test_a_restart_may_not_change_the_being():
    """VERT-8 (recut5, audit P0.1).

    The journal is the being's history. A boot that mints a fresh key and
    then loads that history is not continuity — it is two lives merged,
    and every signature in it verifies, which is why nothing caught it.
    """
    from runtime.recovery import BeingContinuityError, journal_being_ids
    with tempfile.TemporaryDirectory() as tmp:
        ks = os.path.join(tmp, "being.keystore")
        being = BeingIdentity.load_or_create(ks, "pass")
        node = NodeIdentity(SigningKey.generate())
        jd = os.path.join(tmp, "j")

        def boot(bid, tag):
            return Node(name="vert", profile="A",
                        substrates=["sha256:base-A"], adapters={},
                        engine=_engine(),
                        log_path=os.path.join(tmp, f"{tag}.jsonl"),
                        being_identity=bid, identity=node,
                        being_profile="dev",
                        being_workspace=os.path.join(tmp, "ws"),
                        being_journal_dir=jd)

        n1 = boot(being, "r1")
        tr = n1.being.handle_task({"text": "remember me"})
        assert tr.state == "RECORDED", (tr.state, tr.outcome_reason)
        assert journal_being_ids(os.path.join(jd, "tasks.jsonl")) == \
            {being.being_id}

        # same keystore -> the same being, and its history returns
        again = BeingIdentity.load_or_create(ks, "pass")
        assert again.being_id == being.being_id
        n2 = boot(again, "r2")
        assert n2.being_id == being.being_id, "the being did not survive"
        assert tr.task_id in n2.being.traces, (
            "VERT-8: the being's own history did not come back")

        # a different key over the same journal is a refusal
        try:
            boot(BeingIdentity(SigningKey.generate()), "r3")
            raise AssertionError(
                "VERT-8: a fresh being inherited another being's journal — "
                "this is the P0.1 defect: continuity that is really a merge")
        except BeingContinuityError as e:
            assert "another being" in str(e), e
    print("  [PASS] VERT-8  a being's history is its own: the same key gets "
          "it back, a different key is refused")


def test_the_being_signs_what_it_authored():
    """VERT-9 (recut5, audit P0.3).

    The being keystore existed since recut4 and signed the manifest and
    the hosting binding — that is, statements ABOUT the being made at
    boot. Everything the being actually said still went out under the
    node key, including its knowledge proposals. The witness chain stays
    node-signed (INV-9); authorship does not.
    """
    from core.plane_h import make_write_proposal, verify_write_proposal
    from runtime.decision_trace import verify_decision_attestation
    with tempfile.TemporaryDirectory() as tmp:
        being = BeingIdentity(SigningKey.generate())
        n = _node(tmp, "dev", tag="s", being_identity=being)
        tr = n.being.handle_task({"text": "say something worth signing"})
        assert tr.state == "RECORDED", (tr.state, tr.outcome_reason)

        att = tr.being_attestation
        assert att, "VERT-9: the being signed nothing about its own decision"
        assert att["being_id"] == being.being_id
        ok, why = verify_decision_attestation(tr.as_dict())
        assert ok, why

        # the witness chain is still the NODE's, and still verifies
        assert n.chain.verify_chain(), "the node's chain must stay its own"
        assert att["pub"] != n.chain.pubkey_hex if hasattr(
            n.chain, "pubkey_hex") else True

        # re-attribution fails: a genuine signature on another being's trace
        d = tr.as_dict()
        d["being_id"] = "being:" + "0" * 64
        assert not verify_decision_attestation(d)[0], (
            "VERT-9: an attestation was accepted on a trace naming another "
            "being")
        d = tr.as_dict()
        d["answer"] = (d["answer"] or "") + " and one more thing"
        ok2, why2 = verify_decision_attestation(d)
        assert not ok2, (
            "VERT-9: the commitment did not cover the answer — a signature "
            "over a decision that can change underneath it proves nothing")

        # a Being-authored knowledge proposal carries the BEING signature
        env = make_write_proposal(SigningKey.generate(), being_sk=being.sk,
                                  op="add", ns="being/knowledge",
                                  doc_id="d/1", text="hello")
        ok3, why3 = verify_write_proposal(env, text="hello")
        assert ok3, why3
        assert env["body"]["author_being"] == being.being_id
        stripped = {k: v for k, v in env.items() if k != "being_sig"}
        assert not verify_write_proposal(stripped, text="hello")[0], (
            "VERT-9: a proposal naming an authoring being was accepted "
            "without that being's signature")
        # and a runtime built DIRECTLY cannot hold one being's id with
        # another's key — the Node derives it, but nothing stopped a
        # caller from assembling the pair by hand (recut6).
        from runtime.being import BeingRuntime, BeingRuntimeError
        from jjdai.witness import WitnessChain
        sk = SigningKey.generate()
        mismatched = True
        try:
            BeingRuntime(sk=sk, being_sk=SigningKey.generate(),
                         chain=WitnessChain(sk),
                         being_id=being.being_id, governor=None,
                         workspace=tmp, profile="dev")
        except BeingRuntimeError as e:
            mismatched, why9 = False, str(e)
        assert not mismatched, (
            "VERT-9: a runtime accepted one being's id with another's key — "
            "everything it signed would be attributed to a name it cannot "
            "hold")
        assert "does not match the being key" in why9, why9
    print("  [PASS] VERT-9  the being signs what it authored, under an id "
          "its own key derives; the chain stays the node's")


def test_the_trace_names_the_artifact_that_produced_it():
    """VERT-10 (recut6, rewritten after the fifth audit).

    recut5's version asserted that the FIELDS were present and that the
    reference backend honestly said `unknown`. Both were true and neither
    was the gate: `production` tested "is this string non-empty", nothing
    verified the manifest SIGNATURE, and the seat asked the driver — which
    only the reference backend implements. So this pins the CHAIN.
    """
    from core.artifact_binding import ArtifactBindingError, bind_artifact
    sys.path.insert(0, os.path.join(_ROOT, "tests"))
    from artifact_fixtures import signed_artifact

    with tempfile.TemporaryDirectory() as tmp:
        eng = _engine("fp-bind")
        fx = signed_artifact(tmp, backend="hash", fingerprint="fp-bind")
        envelope, atts, deployment = fx.envelope, fx.attestations, fx.deployment

        refs = bind_artifact(manifest_envelope=envelope, engine=eng,
                             weight_attestations=atts, deployment=deployment)
        assert refs.verified and refs.attested, refs
        assert refs.quantization == "int8", refs
        assert refs.model_artifact_manifest_hash == envelope["manifest_hash"]

        # a) the SIGNATURE is checked, not just the shape.
        #    The assertion is OUTSIDE the try on purpose: the first cut had
        #    `raise AssertionError(...)` inside a `except Exception` whose
        #    body asserted the word "signature" appeared — and the
        #    AssertionError's own text contained it, so the check passed by
        #    catching itself. Found by mutation, which is the only reason
        #    mutations are run.
        forged = {"body": dict(envelope["body"]),
                  "manifest_hash": envelope["manifest_hash"],
                  "sig": "00" * 64, "pubkey": envelope["pubkey"]}
        bound, why = True, ""
        try:
            bind_artifact(manifest_envelope=forged, engine=eng,
                          weight_attestations=atts, deployment=deployment)
        except Exception as e:                      # noqa: BLE001
            bound, why = False, str(e).lower()
        assert not bound, (
            "VERT-10: a manifest with a bad signature bound — recut5 called "
            "validate_manifest_body() and never verify_manifest()")
        assert "signature" in why, why

        # b) a manifest describing weights this node has NOT measured
        other = signed_artifact(tmp, backend="hash", fingerprint="fp-bind",
                                weights=b"different weights",
                                name="other.bin").envelope
        try:
            bind_artifact(manifest_envelope=other, engine=eng,
                          weight_attestations=atts, deployment=deployment)
            raise AssertionError(
                "VERT-10: a manifest bound to a checkpoint no attestation "
                "on this node measures")
        except ArtifactBindingError as e:
            assert "measures the checkpoint" in str(e), e

        # c) NO deployment at all is not a binding. recut6 allowed this
        #    through `require_attestation=False` and still returned
        #    verified=True — the flag is gone; there is no partial mode.
        bound, why = True, ""
        try:
            bind_artifact(manifest_envelope=envelope, engine=eng,
                          weight_attestations=None, deployment=None)
        except ArtifactBindingError as e:
            bound, why = False, str(e)
        assert not bound, (
            "VERT-10: a signed description of weights was accepted as "
            "evidence that those weights are here")
        assert "deployment manifest" in why, why

        # c2) the deployment's SIGNATURE is checked. recut6 hashed its body
        #     and read a field out of it without ever verifying it, so a
        #     zeroed signature bound clean.
        import copy
        tampered = copy.deepcopy(deployment)
        tampered["sig"] = "00" * 64
        bound, why = True, ""
        try:
            bind_artifact(manifest_envelope=envelope, engine=eng,
                          weight_attestations=atts, deployment=tampered)
        except ArtifactBindingError as e:
            bound, why = False, str(e)
        assert not bound, (
            "VERT-10: a deployment manifest with a forged signature bound")
        assert "does not verify" in why, why

        # c3) a VALIDLY signed deployment that does not carry this
        #     checkpoint cannot vouch for it
        other_fx = signed_artifact(tmp, backend="hash",
                                   fingerprint="fp-bind",
                                   weights=b"unrelated weights",
                                   name="unrelated.bin")
        bound, why = True, ""
        try:
            bind_artifact(manifest_envelope=envelope, engine=eng,
                          weight_attestations=None,
                          deployment=other_fx.deployment)
        except ArtifactBindingError as e:
            bound, why = False, str(e)
        assert not bound, (
            "VERT-10: a deployment signing for OTHER weights vouched for "
            "these")
        assert "measures the checkpoint" in why, why

        # c4) an attestation supplied outside the signed deployment is a
        #     second, unsigned opinion — not evidence
        bound, why = True, ""
        try:
            bind_artifact(manifest_envelope=envelope, engine=eng,
                          weight_attestations=other_fx.attestations,
                          deployment=deployment)
        except ArtifactBindingError as e:
            bound, why = False, str(e)
        assert not bound, (
            "VERT-10: an attestation the signed deployment does not carry "
            "was accepted alongside it")
        assert "outside the signed deployment" in why, why

        # c5) a bundle whose parts each verify but CONTRADICT each other.
        #     recut6 checked the attestation's engine against the running
        #     one; the recut7 rewrite dropped it, and a chain reading
        #     running=fp-bind / deployment=fp-bind / attestation=fp-other
        #     bound clean. Forged by hand here on purpose: since recut8
        #     `make_deployment_manifest` REFUSES to build one, so the only
        #     way such a bundle reaches a verifier is from an adversary or
        #     an older builder — which is exactly who it must be checked
        #     against.
        from core.attestation import (DEPLOY_DOMAIN, AttestationError,
                                      make_deployment_manifest,
                                      make_weight_attestation,
                                      measure_artifact,
                                      verify_deployment_manifest)
        from jjdai.canonical import canonical as _canon
        from jjdai.crypto import canonical_node_id

        wpath = os.path.join(tmp, "contradict.bin")
        io.open(wpath, "wb").write(b"contradictory weights")
        meas = measure_artifact(wpath)
        sid = meas["artifact_hash"]
        opsk = SigningKey.generate()
        node_id = canonical_node_id(opsk.public)

        def forge(att):
            """A deployment bundle assembled WITHOUT the recut8 guard."""
            body = {"kind": "DEPLOYMENT_MANIFEST", "node_id": node_id,
                    "operator_domain": "forge.example", "jurisdiction": "UA",
                    "engine_fingerprint": "fp-bind",
                    "substrates": {sid: {
                        "attestation_hash": __import__(
                            "jjdai.crypto", fromlist=["H_hex"]).H_hex(
                                _canon(att)),
                        "artifact_hash": att["body"]["artifact_hash"],
                        "binding": att["body"]["binding"]}},
                    "adapter_ids": [], "base_url": None,
                    "created_at": 1_750_000_000.0}
            return {"body": body, "pub": opsk.public.hex(),
                    "sig": opsk.sign(DEPLOY_DOMAIN + _canon(body)).hex(),
                    "attestations": {sid: att}}

        # a manifest for THESE weights, so the checkpoint-membership check
        # is satisfied and the contradiction is the only thing left to
        # catch — otherwise the earlier gate carries the assertion.
        from artifact_fixtures import PROFILE as _PROFILE
        from jjdai.adapters.manifest import (build_manifest as _build,
                                             sign_manifest as _sign)
        forged_manifest = _sign(_build(
            profile=_PROFILE, checkpoint_hash=sid, backend="hash",
            backend_version="forge-1", runtime_version="forge-1",
            quantization={"scheme": "int8"}), opsk)

        wrong_engine = make_weight_attestation(
            opsk, manifest_id=sid, measurement=meas,
            engine_fingerprint="fp-other")
        stranger = SigningKey.generate()
        wrong_node = make_weight_attestation(
            stranger, manifest_id=sid, measurement=meas,
            engine_fingerprint="fp-bind")

        # level 1: the builder refuses to create the contradiction at all
        for att, needle in ((wrong_engine, "taken under engine"),
                            (wrong_node, "cannot vouch")):
            built, why = True, ""
            try:
                make_deployment_manifest(
                    opsk, node_id=node_id, operator_domain="forge.example",
                    jurisdiction="UA", engine_fingerprint="fp-bind",
                    substrate_attestations={sid: att}, adapter_ids=[])
            except AttestationError as e:
                built, why = False, str(e)
            assert not built, (
                "VERT-10: a deployment manifest was BUILT over an "
                "attestation from another engine or another node")
            assert needle in why, why

        # level 2: the offline verifier refuses the forged bundle
        for att, needle in ((wrong_engine, "taken under engine"),
                            (wrong_node, "not by the node")):
            ok, why = verify_deployment_manifest(forge(att))
            assert not ok, (
                "VERT-10: a bundle whose parts each verify but describe "
                "different engines or nodes was reported ok — each "
                "signature being valid is not the same as the bundle being "
                "consistent")
            assert needle in why, why

        # level 3: the binder refuses it on its own. This layer is
        # UNREACHABLE while levels 1 and 2 hold, so asserting it through
        # the normal path would prove nothing about it — the level-2
        # failure would carry the assertion, which is this project's
        # recurring defect. The verifier is stubbed out for the length of
        # this block instead, the same technique that exposed ATTR-5, so
        # the third layer is the only thing left to catch the
        # contradiction. It exists because the link that vanished in
        # recut7 was one nobody was checking twice.
        import core.artifact_binding as _ab
        _real = _ab.verify_deployment_manifest
        _ab.verify_deployment_manifest = lambda env, **kw: (True, "ok")
        try:
            for att, needle in ((wrong_engine, "and this node runs"),
                                (wrong_node, "while the deployment "
                                             "describes")):
                bound, why = True, ""
                try:
                    _ab.bind_artifact(manifest_envelope=forged_manifest,
                                      engine=eng, weight_attestations=None,
                                      deployment=forge(att))
                except ArtifactBindingError as e:
                    bound, why = False, str(e)
                assert not bound, (
                    "VERT-10: with the verifier stubbed, the binder "
                    "accepted a self-contradictory chain — the layer that "
                    "vanished in recut7 is missing again")
                assert needle in why, why
        finally:
            _ab.verify_deployment_manifest = _real

        # c6) AN UNNAMED IDENTITY IS NOT A MATCH (recut9, seventh audit).
        #     Every comparison above used to be guarded by truthiness — `if
        #     dep_fp and fp and dep_fp != fp` — so when both sides were
        #     empty no mismatch arose and the chain returned verified=True.
        #     recut8's own CHANGELOG had already written the rule down
        #     while the code kept treating absence as agreement.
        class _Unnamed:
            determinism_level = "reproducible"

            def __init__(self, backend, fingerprint):
                self.backend, self.fingerprint = backend, fingerprint

        for label, blank_engine, needle in (
                ("blank runtime fingerprint", _Unnamed("hash", ""),
                 "states no fingerprint"),
                ("whitespace fingerprint", _Unnamed("hash", "   "),
                 "states no fingerprint"),
                ("missing runtime backend", _Unnamed("", "fp-bind"),
                 "states no backend")):
            bound, why = True, ""
            try:
                bind_artifact(manifest_envelope=envelope, engine=blank_engine,
                              weight_attestations=None, deployment=deployment)
            except ArtifactBindingError as e:
                bound, why = False, str(e)
            assert not bound, (
                f"VERT-10: {label} — an engine that cannot name itself was "
                "treated as matching whatever it was compared against")
            assert needle in why, why

        # and the contradiction cannot be SIGNED into existence either
        for fpv in ("", "   ", None):
            signed, why = True, ""
            try:
                make_weight_attestation(opsk, manifest_id=sid,
                                        measurement=meas,
                                        engine_fingerprint=fpv)
            except AttestationError as e:
                signed, why = False, str(e)
            assert not signed, (
                f"VERT-10: a weight attestation naming no engine ({fpv!r}) "
                "was signed — a measurement nobody can attribute")
            assert "name the engine" in why, why

        # d2) `manifest_verified` must MEAN something apart from
        #     `verified`. recut7 introduced the flag and then discarded the
        #     fact at the daemon boundary, so it was true only when
        #     `verified` already was (sixth audit, non-blocking).
        broken = True
        try:
            bind_artifact(manifest_envelope=envelope, engine=eng,
                          weight_attestations=None, deployment=None)
        except ArtifactBindingError as e:
            broken = False
            assert e.manifest_verified is True, (
                "VERT-10: a failure AFTER the manifest verified does not "
                "record that it did — the flag is a copy of `verified`")
        assert not broken

        # e) an unbound node says so, and `production` refuses at BOOT
        n = _node(tmp, "dev", engine=eng, tag="ab")
        assert n.artifact_refs.verified is False, n.artifact_refs
        assert n.capabilities()["quantization"] == "unknown"
        seat = n.being.router.nodes["n-self"]
        assert {e.quantization for e in seat.describe().engines} == {"unknown"}
        try:
            _node(tmp, "production", engine=eng, provenance=PROV, tag="ab2",
                  artifact=False)
            raise AssertionError(
                "VERT-10: production started with no verified artifact "
                "binding — the check must be a boot gate, not a per-task "
                "refusal after the node has already been serving")
        except ArtifactBindingError as e:
            assert "verified model artifact binding" in str(e), e

        src = io.open(os.path.join(_ROOT, "node", "daemon.py"),
                      encoding="utf-8").read()
        hard = [ln for ln in src.splitlines()
                if '"int4"' in ln and not ln.lstrip().startswith("#")]
        assert not hard, f"VERT-10: a precision is still hardcoded: {hard}"
    print("  [PASS] VERT-10  the artifact binding is a verified CHAIN — "
          "manifest signature, DEPLOYMENT signature, the checkpoint "
          "present among the substrates that deployment signed for, "
          "attestations taken from the signed bundle, engine agreement — "
          "and an unverified one refuses the boot")


def test_the_witnessed_commitment_is_the_trace_you_get():
    """VERT-11 (recut6, audit P0.2).

    The RECORDED transition used to carry `trace_hash()`, computed before
    the transition was appended — so the chain committed to an object the
    caller never received, reproducibly. A hash of an object must never sit
    inside that object.
    """
    from runtime.decision_trace import recompute_commitment
    with tempfile.TemporaryDirectory() as tmp:
        jd = os.path.join(tmp, "c-j")
        being = BeingIdentity(SigningKey.generate())
        node = NodeIdentity(SigningKey.generate())

        def boot(tag):
            return Node(name="vert", profile="A",
                        substrates=["sha256:base-A"], adapters={},
                        engine=_engine(), log_path=os.path.join(tmp,
                                                                f"{tag}.jsonl"),
                        being_identity=being, identity=node,
                        being_profile="dev",
                        being_workspace=os.path.join(tmp, "c-ws"),
                        being_journal_dir=jd)

        n = boot("c1")
        tr = n.being.handle_task({"text": "commit to what you actually did",
                                  "action": {"kind": "fs_write",
                                             "path": "c.txt",
                                             "content": "done"}})
        assert tr.state == "RECORDED", (tr.state, tr.outcome_reason)

        witnessed = tr.transitions[-1]["detail"]["content_commitment"]
        assert witnessed == recompute_commitment(tr.as_dict()), (
            "VERT-11: the chain committed to something other than the trace "
            "the caller received — this is the recut5 defect")

        # and again after a restart, from the journal
        n2 = boot("c2")
        recovered = n2.being.traces[tr.task_id]
        assert recompute_commitment(recovered.as_dict()) == witnessed, (
            "VERT-11: the recovered trace does not open to the witnessed "
            "commitment")

        # negatives: the commitment must cover what the decision WAS
        # Each mutated value must DIFFER from what the trace already holds,
        # or the "mutation" is a no-op and the check passes for the wrong
        # reason — the EVID-5 defect of recut3, caught here on first run
        # because `citations` is legitimately empty on a first task.
        for field, value in (("answer", "something else"),
                             ("action", {"ok": False}),
                             ("outcome_reason", "rewritten"),
                             ("citations", [{"chunk_id": "forged"}]),
                             ("plan_hash", "f" * 64),
                             ("being_id", "being:" + "0" * 64)):
            d = tr.as_dict()
            assert d.get(field) != value, (
                f"VERT-11: the mutation of {field!r} is a no-op")
            d[field] = value
            assert recompute_commitment(d) != witnessed, (
                f"VERT-11: the commitment does not cover {field!r}")
        d = tr.as_dict()
        d["generator"] = dict(d["generator"] or {},
                              model_artifact_manifest_hash="f" * 64)
        assert recompute_commitment(d) != witnessed, (
            "VERT-11: the commitment does not cover which weights answered")

        # the transition sequence is covered by the CHAIN, not by the hash —
        # every transition points at a record that states that state
        for trn in tr.transitions:
            rec = n.chain.records[trn["witness_index"]]
            assert rec["semantic_digest"]["state"] == trn["to"], (
                "VERT-11: a transition does not match the record it names")
        assert n.chain.verify_chain()

        src = io.open(os.path.join(_ROOT, "runtime", "decision_trace.py"),
                      encoding="utf-8").read()
        assert "def trace_hash" not in src, (
            "VERT-11: trace_hash() is back — it is a trap, not an API")
    print("  [PASS] VERT-11  the witnessed commitment opens to the trace the "
          "caller gets and to the one recovered after a restart")


if __name__ == "__main__":
    for t in (test_the_being_thinks_with_the_real_backend,
              test_verifier_role_is_implemented_not_assumed,
              test_a_lone_production_node_refuses_in_a_reason_code,
              test_the_labelled_path_completes_and_says_so,
              test_the_being_has_its_own_identity,
              test_binding_is_what_entitles_the_node,
              test_the_daemon_enforces_the_binding_it_reports,
              test_a_restart_may_not_change_the_being,
              test_the_being_signs_what_it_authored,
              test_the_trace_names_the_artifact_that_produced_it,
              test_the_witnessed_commitment_is_the_trace_you_get):
        t()
    print("\nvertical — 11/11 checks green")