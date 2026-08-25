#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_vertical_live — v0.6.7-recut6 LIVE vertical on a target host
=================================================================
The hermetic vertical (VERT-1…11) runs against the reference `hash` backend
and against genuinely signed fixture artifacts. That proves the WIRING and
the CHAIN. It cannot prove either against a real model, and the recut5
version of this file could not prove anything at all: it set
`BackendConfig.endpoint`, a field that does not exist on a `__slots__`
object whose URL field is `url`, so it raised AttributeError before the
first check. A live test that cannot start is not evidence. It was named as
un-run in the recut5 CHANGELOG, and the fifth audit found the crash — which
is a better outcome than a green badge would have been.

Two things changed after that audit:

  * `--engine-url`, through the real daemon, instead of a field that does
    not exist;
  * the node under test is a REAL DAEMON spawned over mTLS, not a `Node`
    built inside this process. Constructing the object in-process skips
    precisely what a live test exists to cover: argv, both keystores, TLS,
    the boot gates and a restart.

Requirements on the host, every one refused loudly if absent:

    JJDAI_LIVE_BACKEND=dwarfstar|sglang|vllm|llama_cpp|mlx
    JJDAI_LIVE_URL=http://127.0.0.1:8080
    JJDAI_LIVE_MANIFEST=/path/signed-model-artifact.json
    JJDAI_LIVE_WEIGHTS=/path/checkpoint       (the node measures it itself)

    python3 scripts/run_acceptance.py live

ON THE MANIFEST. No shipped driver implements `attestation_manifest()`
except the reference backend, and recut6 stopped asking drivers for
provenance for that reason: the ModelArtifactManifest is an OPERATOR
artifact, signed out of band and passed with `--model-artifact-manifest`.
This test therefore needs one for the model on the host. Producing it is a
deployment step; a manifest this file signed for itself would prove only
that this file can sign things.

  LV-1  the daemon serves the real engine over mTLS
  LV-2  the artifact chain verifies on the real model — a real quantization,
        not `unknown`
  LV-3  one backend, one description: trace and /capabilities agree
  LV-4  the decision is being-signed; the chain stays node-signed (INV-9)
  LV-5  the witnessed commitment opens to the trace the caller received
  LV-6  restart continuity over mTLS: same being, same history, same
        commitment
  LV-7  one seat is still not a panel, and the refusal names independence
"""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "node"))

from runtime.decision_trace import (                           # noqa: E402
    recompute_commitment, verify_decision_attestation)

DAEMON = os.path.join(_ROOT, "node", "daemon.py")
GEN_CERTS = os.path.join(_ROOT, "scripts", "gen_dev_certs.py")
PORT = int(os.environ.get("JJDAI_LIVE_PORT", "8711"))

PROVENANCE = {
    "m:self": {"model_id": "m:self", "base_family": "fam-live",
               "architecture_family": "arch-live",
               "training_data_families": ["ds-live"],
               "operator_domain": "self.example", "jurisdiction": "UA"},
}


def _env(name: str, why: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(
            f"{name} is unset. This file is evidence about a TARGET HOST "
            f"with a real model and must not pass on a machine that has "
            f"none. {why}")
    return v


def _ctx(ca, cert, key):
    c = ssl.create_default_context(cafile=ca)
    c.check_hostname = False
    c.load_cert_chain(cert, key)
    return c


def _req(ctx, url, payload=None, timeout=120):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, json.loads(r.read().decode())


def _wait(ctx, base, tries=120):
    for _ in range(tries):
        try:
            code, caps = _req(ctx, base + "/capabilities")
            if code == 200:
                return caps
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"{base} never came up — read the daemon's stderr")


def test_vertical_live():
    backend = _env("JJDAI_LIVE_BACKEND", "The driver this host runs.")
    url = _env("JJDAI_LIVE_URL", "The backend's base URL.")
    manifest = _env("JJDAI_LIVE_MANIFEST",
                    "A SIGNED ModelArtifactManifest for the model on this "
                    "host; it is a deployment artifact, not something a "
                    "test may fabricate.")
    weights = _env("JJDAI_LIVE_WEIGHTS",
                   "The checkpoint file, so the node measures it and signs "
                   "its own weight attestation.")
    with open(manifest, encoding="utf-8") as fh:
        checkpoint = json.load(fh)["body"]["checkpoint_hash"]

    env = dict(os.environ)
    env["JJDAI_KEYSTORE_PASSPHRASE"] = "live-node-pass"
    env["JJDAI_BEING_PASSPHRASE"] = "live-being-pass"
    procs = {}
    with tempfile.TemporaryDirectory() as tmp:
        certdir = os.path.join(tmp, "certs")
        r = subprocess.run([sys.executable, GEN_CERTS, "--out", certdir,
                            "live-a", "client"],
                           capture_output=True, text=True, timeout=180)
        assert r.returncode == 0, r.stderr[:400]
        prov_path = os.path.join(tmp, "prov.json")
        with open(prov_path, "w", encoding="utf-8") as fh:
            json.dump(PROVENANCE, fh)
        base = f"https://127.0.0.1:{PORT}"

        def spawn(profile="dev"):
            args = [sys.executable, DAEMON, "--port", str(PORT),
                    "--name", "live-a", "--fingerprint", "fp-live",
                    "--engine", backend, "--engine-url", url,
                    "--substrates", json.dumps([checkpoint]),
                    "--substrate-artifacts",
                    json.dumps({checkpoint: weights}),
                    "--model-artifact-manifest", manifest,
                    "--log", os.path.join(tmp, "a.jsonl"),
                    "--node-keystore", os.path.join(tmp, "a.keystore"),
                    "--being-keystore", os.path.join(tmp, "a.being.keystore"),
                    "--being-profile", profile,
                    "--being-workspace", os.path.join(tmp, "ws"),
                    "--being-journals", os.path.join(tmp, "being"),
                    "--tls-cert", os.path.join(certdir, "live-a.crt"),
                    "--tls-key", os.path.join(certdir, "live-a.key"),
                    "--tls-ca", os.path.join(certdir, "ca.crt"),
                    "--tls-require-client-cert"]
            if profile == "production":
                args += ["--being-provenance", prov_path]
            return subprocess.Popen(args, env=env)

        ctx = _ctx(os.path.join(certdir, "ca.crt"),
                   os.path.join(certdir, "client.crt"),
                   os.path.join(certdir, "client.key"))
        try:
            procs["a"] = spawn("dev")
            caps = _wait(ctx, base)

            assert caps["backend"] == backend, caps
            assert caps["engine_fingerprint"], caps
            print(f"  [PASS] LV-1  the daemon serves the live {backend} "
                  f"backend over mTLS")

            assert caps["quantization"] != "unknown", (
                "LV-2: the node booted without a verified artifact binding "
                "— on a target host that is a deployment defect, not an "
                "honest 'unknown'")
            print(f"  [PASS] LV-2  artifact chain verified on the real "
                  f"model: quantization={caps['quantization']!r}")

            code, resp = _req(ctx, base + "/v1/tasks", {
                "task": {"text": "say something on real weights"}})
            assert code == 200, resp
            tr = resp["trace"]
            assert tr["state"] == "RECORDED", tr.get("outcome_reason")
            g = tr["generator"]
            assert g["artifact_verified"] is True, g
            assert g["quantization"] == caps["quantization"], (
                "LV-3: the trace and /capabilities describe the same "
                "backend differently")
            assert g["checkpoint_hash"] == checkpoint, g
            print("  [PASS] LV-3  one backend, one description, both paths")

            ok, why = verify_decision_attestation(tr)
            assert ok, f"LV-4: {why}"
            code, ch = _req(ctx, base + "/witness/chain")
            from jjdai.witness import WitnessChain as _WC
            probe = _WC.__new__(_WC)
            probe.records = ch["records"]
            assert probe.verify_chain(bytes.fromhex(ch["pubkey"])), (
                "LV-4: the node's chain must verify under the NODE key")
            print("  [PASS] LV-4  the being signed the decision; the chain "
                  "stays the node's and verifies offline")

            witnessed = tr["transitions"][-1]["detail"]["content_commitment"]
            assert witnessed == recompute_commitment(tr), (
                "LV-5: the chain committed to something other than the "
                "trace the caller received")
            print("  [PASS] LV-5  the witnessed commitment opens to the "
                  "trace that was returned")

            being_before, task_id = caps["being_id"], tr["task_id"]
            procs["a"].terminate(); procs["a"].wait(timeout=30)
            procs["a"] = spawn("dev")
            caps2 = _wait(ctx, base)
            assert caps2["being_id"] == being_before, (
                f"LV-6: the restart changed the being: {being_before} -> "
                f"{caps2['being_id']}")
            code, again = _req(ctx, base + f"/v1/tasks/{task_id}")
            assert code == 200 and again["trace"]["state"] == "RECORDED"
            assert recompute_commitment(again["trace"]) == witnessed, (
                "LV-6: the recovered trace does not open to the witnessed "
                "commitment")
            print("  [PASS] LV-6  continuity on a real model across an "
                  "mTLS restart: same being, same history, same commitment")

            procs["a"].terminate(); procs["a"].wait(timeout=30)
            procs["a"] = spawn("production")
            _wait(ctx, base)
            code, refused = _req(ctx, base + "/v1/tasks", {
                "task": {"text": "verify yourself alone"}})
            t7 = refused["trace"]
            assert t7["state"] == "REFUSED", t7["state"]
            detail = t7["transitions"][-1]["detail"]
            assert detail["reason_code"] == "no_independent_panel", detail
            assert "reason" not in detail, (
                "LV-7: free text reached the witness plane")
            print("  [PASS] LV-7  one seat is not a panel, and the refusal "
                  "names independence rather than the model")
        finally:
            for p in procs.values():
                p.terminate()

    print("\nVERTICAL LIVE: all gates green  ✓ certified")


if __name__ == "__main__":
    test_vertical_live()
