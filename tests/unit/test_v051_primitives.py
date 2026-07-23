#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.5.1 unit acceptance — attestation · anchoring · explicit generator
=====================================================================
Weight attestation:
  A-1  measurement is streamed sha256; content-addressed ids REQUIRE a
       matching artifact (a false binding cannot even be signed)
  A-2  attestation envelopes verify offline; tampers rejected
  A-3  DeploymentManifest: first-person only, embedded attestations
       verified and hash-bound; tampers rejected
  A-4  AttestationStore: differing re-attestation refused as a governance
       event; fail-closed reload
Provenance integration:
  P-1  provenance(deployment=...) derives operator/jurisdiction from the
       SIGNED deployment and surfaces the weight attestation; bare-string
       overrides labeled "asserted"
External anchoring:
  N-1  AnchorLog: durable, fail-closed reload on malformed entries
  N-2  scheduler ratchet: bookkeeping-only growth is skipped; substantive
       growth anchors once through EVERY backend and witnesses ONE
       ANCHOR_EXTERNAL record
  N-3  PeerQuorumAnchor reports pending without a receipt, recorded with
Diversity:
  G-1  generator_provenance is honored EXPLICITLY: a generator absent
       from the candidate pool still excludes its clones (the dev-5 hole)
"""
from __future__ import annotations

import copy
import hashlib
import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai.crypto import SigningKey                                # noqa: E402
from jjdai.witness import WitnessChain                             # noqa: E402
from core.attestation import (measure_artifact,                    # noqa: E402
                              make_weight_attestation,
                              verify_weight_attestation,
                              make_deployment_manifest,
                              verify_deployment_manifest,
                              AttestationStore, AttestationError)
from core.anchoring import (AnchorLog, AnchorScheduler,            # noqa: E402
                            LocalFileAnchor, PeerQuorumAnchor,
                            AnchorError)
from core.manifests import (ManifestRegistry,                      # noqa: E402
                            make_substrate_manifest)
from core.diversity import select_verifiers                        # noqa: E402


def _weights(tmp, name, data: bytes):
    p = os.path.join(tmp, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def test_weight_attestation():
    sk = SigningKey.generate()
    with tempfile.TemporaryDirectory() as tmp:
        data = os.urandom(3 * (1 << 20) + 137)      # >3 chunks, odd tail
        path = _weights(tmp, "base.gguf", data)

        # ---- A-1 ----
        m = measure_artifact(path)
        assert m["artifact_hash"] == "sha256:" + hashlib.sha256(data).hexdigest()
        assert m["size_bytes"] == len(data)
        cid = m["artifact_hash"]                     # true content address
        att = make_weight_attestation(sk, manifest_id=cid,
                                      artifact_path=path)
        assert att["body"]["binding"] == "content"
        other = _weights(tmp, "other.gguf", os.urandom(1024))
        try:
            make_weight_attestation(sk, manifest_id=cid, artifact_path=other)
            assert False, "A-1: a false content binding must be unsignable"
        except AttestationError:
            pass
        sym = make_weight_attestation(sk, manifest_id="sha256:base-A",
                                      artifact_path=path)
        assert sym["body"]["binding"] == "declared", \
            "A-1: symbolic ids are honest about their binding class"
        print("  [PASS] A-1  streamed measurement; content ids enforced at "
              "signing; symbolic ids labeled declared")

        # ---- A-2 ----
        assert verify_weight_attestation(att, manifest_id=cid) == (True, "ok")
        for name, mut in {
            "hash swap": lambda e: e["body"].update(
                artifact_hash="sha256:" + "0" * 64),
            "id swap": lambda e: e["body"].update(
                manifest_id="sha256:" + "1" * 64),
            "binding lie": lambda e: e["body"].update(binding="content")
                if e["body"]["binding"] != "content"
                else e["body"].update(binding="declared"),
            "foreign key": lambda e: e.update(
                pub=SigningKey.generate().public.hex()),
        }.items():
            bad = copy.deepcopy(att)
            mut(bad)
            ok, _ = verify_weight_attestation(bad)
            assert not ok, f"A-2: tamper not caught: {name}"
        print("  [PASS] A-2  offline verification; 4 tamper classes caught")

        # ---- A-3 ----
        nid = att["body"]["attester_node"]
        dep = make_deployment_manifest(
            sk, node_id=nid, operator_domain="aton.energy",
            jurisdiction="UA", engine_fingerprint="fp-x",
            substrate_attestations={cid: att},
            adapter_ids=["sha256:adp-1"])
        assert verify_deployment_manifest(dep, node_id=nid) == (True, "ok")
        stranger = SigningKey.generate()
        try:
            make_deployment_manifest(
                stranger, node_id=nid, operator_domain="x", jurisdiction="UA",
                engine_fingerprint="fp", substrate_attestations={cid: att})
            assert False, "A-3: deployment manifests are first-person only"
        except AttestationError:
            pass
        bad = copy.deepcopy(dep)
        bad["attestations"][cid]["body"]["size_bytes"] += 1
        ok, why = verify_deployment_manifest(bad)
        assert not ok, "A-3: mutated embedded attestation must be caught"
        bad2 = copy.deepcopy(dep)
        bad2["body"]["jurisdiction"] = "KY"
        ok, _ = verify_deployment_manifest(bad2)
        assert not ok, "A-3: body tamper must break the signature"
        print("  [PASS] A-3  deployment manifest: first-person, hash-bound "
              "attestations, tampers caught")

        # ---- A-4 ----
        store_path = os.path.join(tmp, "attest.jsonl")
        st = AttestationStore(store_path)
        st.hold_weight(att)
        st.hold_weight(att)                          # idempotent
        conflicting = make_weight_attestation(
            sk, manifest_id="sha256:base-A", artifact_path=other)
        st.hold_weight(sym)
        try:
            st.hold_weight(conflicting)
            assert False, "A-4: differing re-attestation is a governance event"
        except AttestationError:
            pass
        st.hold_deployment(dep)
        st2 = AttestationStore(store_path)
        assert st2.weight(cid) and st2.deployment(nid), "A-4: reload holds"
        import json as _json
        with open(store_path) as f:
            lines = f.read().strip().split("\n")
        forged = _json.loads(lines[0])
        forged["env"]["body"]["artifact_hash"] = "sha256:" + "f" * 64
        with open(store_path, "w") as f:
            f.write(_json.dumps(forged) + "\n")
        try:
            AttestationStore(store_path)
            assert False, "A-4: forged journal must refuse the boot"
        except AttestationError:
            pass
        print("  [PASS] A-4  store: idempotent, conflict-refusing, "
              "fail-closed reload")

        # ---- P-1 ----
        reg = ManifestRegistry()
        sub_env = make_substrate_manifest(
            sk, substrate_id=cid, name="base", version="1",
            base_family="fam-X", architecture_family="arch-X",
            training_data_families=["dsX"])
        reg.register(sub_env)
        prov = reg.provenance(model_id="m:1", substrate_id=cid,
                              deployment=dep)
        assert prov["operator_domain"] == "aton.energy" \
            and prov["deployment_source"] == "signed-deployment" \
            and prov["weight_attestation"]["binding"] == "content", prov
        prov2 = reg.provenance(model_id="m:2", substrate_id=cid,
                               operator_domain="claimed.example")
        assert prov2["deployment_source"] == "asserted", \
            "P-1: bare-string overrides must be labeled as claims"
        print("  [PASS] P-1  provenance derives from the SIGNED deployment; "
              "bare claims labeled")


class _CountingBackend:
    name = "counting"

    def __init__(self):
        self.calls = []

    def submit(self, node_id, root, count):
        self.calls.append((root, count))
        return {"backend": self.name, "node": node_id, "root": root,
                "count": count, "status": "recorded", "ts": 0.0}


def test_anchoring():
    sk = SigningKey.generate()
    with tempfile.TemporaryDirectory() as tmp:
        # ---- N-1 ----
        log_path = os.path.join(tmp, "anchors.jsonl")
        log = AnchorLog(log_path)
        log.add(LocalFileAnchor().submit("node:x", "ab" * 32, 3))
        log2 = AnchorLog(log_path)
        assert len(log2.receipts) == 1 and log2.latest("local")
        with open(log_path, "a") as f:
            f.write('{"kind":"ANCHOR_RECEIPT","receipt":{"bad":true}}\n')
        try:
            AnchorLog(log_path)
            assert False, "N-1: malformed journal must refuse the boot"
        except AnchorError:
            pass
        print("  [PASS] N-1  anchor log durable + fail-closed reload")

        # ---- N-2 ----
        ch = WitnessChain(sk)
        be = _CountingBackend()
        sched = AnchorScheduler(ch, [be, LocalFileAnchor()],
                                AnchorLog(os.path.join(tmp, "a2.jsonl")))
        for i in range(3):
            ch.append("INFER", semantic_digest={"i": i})
        r1 = sched.anchor_now()
        assert r1.get("anchored") and len(r1["receipts"]) == 2 \
            and ch.records[-1]["kind"] == "ANCHOR_EXTERNAL", r1
        r2 = sched.anchor_now()
        assert r2.get("skipped") == "not-substantive", \
            f"N-2: anchor-only growth must not re-anchor: {r2}"
        ch.append("INFER", semantic_digest={"i": 99})
        r3 = sched.anchor_now()
        assert r3.get("anchored") and len(be.calls) == 2, \
            "N-2: substantive growth anchors again"
        assert ch.verify_chain(), "N-2: chain stays valid through anchoring"
        print("  [PASS] N-2  ratchet: skip bookkeeping, anchor substance, "
              "one ANCHOR_EXTERNAL per round")

        # ---- N-3 ----
        receipts = {}
        pq = PeerQuorumAnchor(lambda c, r: receipts.get(c))
        rec = pq.submit("node:x", "cd" * 32, 7)
        assert rec["status"] == "pending"
        receipts[7] = {"k": 2, "acks": []}
        rec2 = pq.submit("node:x", "cd" * 32, 7)
        assert rec2["status"] == "recorded" and rec2["k"] == 2
        print("  [PASS] N-3  peer-quorum backend: pending without receipt, "
              "recorded with")


def _prov(mid, fam):
    return {"model_id": mid, "base_family": fam,
            "architecture_family": f"arch-{fam}",
            "training_data_families": [f"ds-{fam}"],
            "operator_domain": f"{mid}.example", "jurisdiction": "UA"}


def test_explicit_generator_provenance():
    gen = _prov("m:gen", "fam-G")
    clone = _prov("m:clone", "fam-G")                # same family as generator
    clone["operator_domain"] = gen["operator_domain"]
    clone["training_data_families"] = gen["training_data_families"]
    clone["architecture_family"] = gen["architecture_family"]
    indep = _prov("m:indep", "fam-Z")
    # the generator is NOT in the candidate pool — the dev-5 hole
    res_hole = select_verifiers(
        [{"provenance": clone, "reputation": 0.9},
         {"provenance": indep, "reputation": 0.5}], k=1,
        min_independence=0.5, exclude_model="m:gen")
    assert res_hole["selected"][0]["provenance"]["model_id"] == "m:clone", \
        "G-1 precondition: without the explicit manifest the clone slips in"
    res = select_verifiers(
        [{"provenance": clone, "reputation": 0.9},
         {"provenance": indep, "reputation": 0.5}], k=1,
        min_independence=0.5, generator_provenance=gen)
    ids = [c["provenance"]["model_id"] for c in res["selected"]]
    assert ids == ["m:indep"], f"G-1: {ids}"
    reasons = {r["model_id"]: r["reason"] for r in res["rejected"]}
    assert "m:clone" in reasons, "G-1: the clone must be rejected by name"
    print("  [PASS] G-1  explicit generator_provenance closes the "
          "absent-generator hole; clone rejected, independent selected")


if __name__ == "__main__":
    test_weight_attestation()
    test_anchoring()
    test_explicit_generator_provenance()
    print("\nV0.5.1 UNIT: all groups green  ✓ certified")
