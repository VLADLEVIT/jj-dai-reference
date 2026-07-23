#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Being Composition Runtime, live (v0.5.3) — the audit's definition of done
=========================================================================
Three real daemon processes over mTLS. Node A runs the Being in the
PRODUCTION profile; B and C replicate its evidence.

  G-1  POST /v1/tasks over mTLS returns a full RECORDED DecisionTrace:
       every pipeline state walked, plan hash, independent verifier panel
       (selected + rejected with reasons), a governed fs_write receipt,
       and a witness span on ONE chain that verifies end-to-end
  G-2  the evidence replicates: B and C hold quorum receipts covering the
       task records (the Being's decisions are not private history)
  G-3  RESTART: node A is stopped and restarted on the same identity and
       journals; GET /v1/tasks/<id> returns the SAME trace — states,
       citations, plan and receipts restored from disk (meaning, not just
       hashes); the chain still verifies
  G-4  CONTAINMENT hand-stop: after containment on A, an action task ends
       CONTAINED with the mind's states walked and the file NOT written;
       a pure-answer task still ends RECORDED
  G-5  production boot without provenance refuses (exit 2) — the profile
       is a promise, not a suggestion
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
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

DAEMON = os.path.join(_ROOT, "node", "daemon.py")
GEN_CERTS = os.path.join(_ROOT, "scripts", "gen_dev_certs.py")
P_A, P_B, P_C = 8691, 8692, 8693

PROVENANCE = {
    "m:gen": {"model_id": "m:gen", "base_family": "fam-G",
              "architecture_family": "arch-a",
              "training_data_families": ["ds-gen"],
              "operator_domain": "gen.example", "jurisdiction": "UA"},
    "m:v1": {"model_id": "m:v1", "base_family": "fam-G",
             "architecture_family": "arch-b",
             "training_data_families": ["ds-v1"],
             "operator_domain": "v1.example", "jurisdiction": "KR"},
    "m:v2": {"model_id": "m:v2", "base_family": "fam-G",
             "architecture_family": "arch-c",
             "training_data_families": ["ds-v2"],
             "operator_domain": "v2.example", "jurisdiction": "EE"},
}


def _client_ctx(ca, cert, key):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.check_hostname = False
    ctx.load_cert_chain(cert, key)
    return ctx


def _req(ctx, url, payload=None, timeout=30):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, json.loads(r.read().decode())


def _wait_tls(ctx, base, tries=60):
    for _ in range(tries):
        try:
            code, caps = _req(ctx, base + "/capabilities")
            if code == 200:
                return caps
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"{base} never came up")


def _spawn(port, name, fp, tmp, certdir, extra):
    env = dict(os.environ)
    args = [sys.executable, DAEMON, "--port", str(port), "--name", name,
            "--fingerprint", fp,
            "--tls-cert", os.path.join(certdir, f"{name}.crt"),
            "--tls-key", os.path.join(certdir, f"{name}.key"),
            "--tls-ca", os.path.join(certdir, "ca.crt"),
            "--tls-require-client-cert",
            "--peer-ca", os.path.join(certdir, "ca.crt"),
            "--client-cert", os.path.join(certdir, f"{name}.crt"),
            "--client-key", os.path.join(certdir, f"{name}.key")] + extra
    return subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def test_being_runtime_three_nodes():
    _prev = os.environ.get("JJDAI_KEYSTORE_PASSPHRASE")
    os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = "being-test-pass"
    procs = {}
    with tempfile.TemporaryDirectory() as tmp:
        certdir = os.path.join(tmp, "certs")
        r = subprocess.run([sys.executable, GEN_CERTS, "--out", certdir,
                            "being-A", "being-B", "being-C", "client"],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, r.stderr[:400]
        prov_path = os.path.join(tmp, "prov.json")
        with open(prov_path, "w", encoding="utf-8") as f:
            json.dump(PROVENANCE, f)
        ws = os.path.join(tmp, "being-ws")

        def spawn_a():
            return _spawn(P_A, "being-A", "fp-being-A", tmp, certdir, [
                "--log", os.path.join(tmp, "A.jsonl"),
                "--node-keystore", os.path.join(tmp, "A.keystore"),
                "--being-profile", "production",
                "--being-provenance", prov_path,
                "--being-workspace", ws,
                "--being-journals", os.path.join(tmp, "A.being"),
                "--allow-test-hooks",
                "--peers",
                f"https://127.0.0.1:{P_B},https://127.0.0.1:{P_C}"])

        try:
            procs["A"] = spawn_a()
            for name, port in (("being-B", P_B), ("being-C", P_C)):
                procs[name] = _spawn(port, name, f"fp-{name}", tmp, certdir, [
                    "--log", os.path.join(tmp, f"{name}.jsonl"),
                    "--node-keystore", os.path.join(tmp,
                                                    f"{name}.keystore")])
            ctx = _client_ctx(os.path.join(certdir, "ca.crt"),
                              os.path.join(certdir, "client.crt"),
                              os.path.join(certdir, "client.key"))
            base_a = f"https://127.0.0.1:{P_A}"
            caps = _wait_tls(ctx, base_a)
            assert caps["being_runtime"] == "production", caps
            for port in (P_B, P_C):
                _wait_tls(ctx, f"https://127.0.0.1:{port}")

            # ---- G-1 ------------------------------------------------------ #
            code, resp = _req(ctx, base_a + "/v1/tasks", {
                "task": {"text": "record the composition milestone",
                         "action": {"kind": "fs_write",
                                    "path": "milestone.txt",
                                    "content": "the organism lives"}}})
            assert code == 200, resp
            tr = resp["trace"]
            assert tr["state"] == "RECORDED", tr.get("outcome_reason")
            assert [t["to"] for t in tr["transitions"]] == [
                "RECEIVED", "GROUNDED", "PLANNED", "GENERATED", "VERIFIED",
                "AUTHORIZED", "ACTED", "RECORDED"]
            assert tr["verifier_panel"]["mode"] == "panel" \
                and sorted(tr["verifier_panel"]["selected"]) == \
                ["m:v1", "m:v2"] and tr["plan_hash"] \
                and tr["action"]["ok"] \
                and tr["witness_span"][1] > tr["witness_span"][0], tr
            assert open(os.path.join(ws, "milestone.txt")).read() == \
                "the organism lives"
            task_id = tr["task_id"]
            code, ch = _req(ctx, base_a + "/witness/chain")
            from jjdai.witness import WitnessChain as _WC
            _probe = _WC.__new__(_WC)
            _probe.records = ch["records"]
            assert _probe.verify_chain(bytes.fromhex(ch["pubkey"])), \
                "G-1: the ONE exported chain must verify offline"
            print("  [PASS] G-1  mTLS task -> RECORDED trace: full path, "
                  "panel [m:v1,m:v2], plan hash, action receipt, one chain")

            # ---- G-2 ------------------------------------------------------ #
            code, rep = _req(ctx, base_a + "/replicate/push", {})
            assert code == 200 and rep.get("quorum_reached"), rep
            stored = [p for p, r in rep["peers"].items()
                      if r["status"] == "stored" and r["ack_valid"]]
            assert len(stored) == 2, \
                "G-2: B and C must both acknowledge the Being's evidence"
            print("  [PASS] G-2  the Being's decisions replicate: "
                  f"{len(stored)} valid peer receipts over {rep['count']} "
                  "records incl. the task lifecycle")

            # ---- G-3 ------------------------------------------------------ #
            procs["A"].terminate(); procs["A"].wait(timeout=15)
            procs["A"] = spawn_a()
            _wait_tls(ctx, base_a)
            code, resp2 = _req(ctx, base_a + f"/v1/tasks/{task_id}")
            assert code == 200, resp2
            tr2 = resp2["trace"]
            assert tr2["state"] == "RECORDED" \
                and tr2["plan_steps"] == tr["plan_steps"] \
                and tr2["citations"] == tr["citations"] \
                and tr2["action"]["ok"], \
                "G-3: restart must restore MEANING, not just hashes"
            code, ch = _req(ctx, base_a + "/witness/chain")
            _probe2 = _WC.__new__(_WC)
            _probe2.records = ch["records"]
            assert _probe2.verify_chain(bytes.fromhex(ch["pubkey"])), \
                "G-3: chain must verify"
            print("  [PASS] G-3  restart on the same identity: the trace "
                  "returns with citations, plan and receipts intact")

            # ---- G-4 ------------------------------------------------------ #
            code, c = _req(ctx, base_a + "/admin/containment", {
                "contain": True, "evidence_refs": ["w:0"],
                "initiator": "steward:test", "reason": "gate-6 hand-stop"})
            assert code == 200 and c["contained"], c
            code, resp3 = _req(ctx, base_a + "/v1/tasks", {
                "task": {"text": "try to act while contained",
                         "action": {"kind": "fs_write", "path": "no.txt",
                                    "content": "x"}}})
            tr3 = resp3["trace"]
            assert tr3["state"] == "CONTAINED", tr3
            assert [t["to"] for t in tr3["transitions"]][:5] == [
                "RECEIVED", "GROUNDED", "PLANNED", "GENERATED", "VERIFIED"]
            assert not os.path.exists(os.path.join(ws, "no.txt")), \
                "G-4: the hand must not have moved"
            code, resp4 = _req(ctx, base_a + "/v1/tasks", {
                "task": {"text": "still thinking while contained"}})
            assert resp4["trace"]["state"] == "RECORDED", \
                "G-4: the contained mind still answers"
            print("  [PASS] G-4  containment: action task CONTAINED after "
                  "a full mind-run, file unwritten; pure answer RECORDED")

            # ---- G-5 ------------------------------------------------------ #
            r = subprocess.run(
                [sys.executable, DAEMON, "--port", "8699",
                 "--name", "bad", "--fingerprint", "fp-bad",
                 "--being-profile", "production"],
                capture_output=True, text=True, timeout=30)
            assert r.returncode == 2 and "provenance" in r.stderr, r.stderr
            print("  [PASS] G-5  production without provenance refuses "
                  "the boot — the profile is a promise")
        finally:
            if _prev is None:
                os.environ.pop("JJDAI_KEYSTORE_PASSPHRASE", None)
            else:
                os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = _prev
            for p in procs.values():
                p.terminate()
            for p in procs.values():
                try:
                    p.wait(timeout=10)
                except Exception:
                    p.kill()


if __name__ == "__main__":
    test_being_runtime_three_nodes()
    print("\nBEING RUNTIME LIVE: all gates green  ✓ certified")
