#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Being Composition Runtime, live (v0.5.3) — the audit's definition of done
=========================================================================
Three real daemon processes over mTLS. B and C replicate A's evidence.

REWRITTEN for the vertical (v0.6.7). Until the vertical, node A ran the
Being in the PRODUCTION profile and every task reached RECORDED — but only
because the daemon built THREE synthetic engines with the router's own
test helper, so the "independent verifier panel" was three copies of a
fixture. With the real backend wired in there is ONE engine, one seat, and
a lone node has no independent panel at all.

So this file now pins BOTH truths, which is what the old version could not
distinguish: the organism works end to end on the real engine (`dev`, with
the trace saying `mode: "self"` out loud), and a lone node in `production`
REFUSES rather than manufacturing a panel out of one engine.

  G-1  POST /v1/tasks over mTLS returns a full RECORDED DecisionTrace on
       the REAL configured backend: every pipeline state walked, plan hash,
       a governed fs_write receipt, and a witness span on ONE chain that
       verifies end-to-end
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
  G-6  a lone node in `production`, with a well-formed provenance manifest
       and one real engine, REFUSES the task and says why in a reason CODE
       the network can read. Fails against recut3, where three fixtures
       made a panel appear out of nothing
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

#: One seat, because the node has one engine. The vertical removed the
#: three fixtures; a provenance map naming objects that no longer exist
#: would describe a router that is not there.
PROVENANCE = {
    "m:self": {"model_id": "m:self", "base_family": "fam-G",
               "architecture_family": "arch-a",
               "training_data_families": ["ds-gen"],
               "operator_domain": "self.example", "jurisdiction": "UA"},
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
    _prev_being = os.environ.get("JJDAI_BEING_PASSPHRASE")
    os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = "being-test-pass"
    os.environ["JJDAI_BEING_PASSPHRASE"] = "being-key-pass"
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
                # dev, deliberately: this node has ONE real engine, so it
                # has no independent panel and `production` would refuse
                # (G-6). `dev` is the labelled path — the trace carries
                # mode="self" — and it is what lets G-1..G-4 exercise the
                # organism on a real backend instead of on fixtures.
                "--being-profile", "dev",
                # deliberately NO --being-provenance: `dev` takes the
                # labelled mode="self" path only when there is no
                # provenance map to judge independence against. Given one,
                # it demands a panel exactly like production — which on a
                # one-seat node is the refusal G-6 pins.

                "--being-workspace", ws,
                "--being-journals", os.path.join(tmp, "A.being"),
                # recut5 (audit P0.1): the keystore is what makes G-3 a
                # continuity check at all. Without it every restart minted
                # a fresh being:<hash> and then served the PREVIOUS being's
                # traces out of this journal — the test passed because it
                # only compared the trace, never the being.
                "--being-keystore", os.path.join(tmp, "A.being.keystore"),
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
            assert caps["being_runtime"] == "dev", caps
            # the being now has a CANONICAL identity of its own, derived
            # from a key, rather than `being:` plus a slice of the node id
            assert caps["being_id"].startswith("being:"), caps["being_id"]
            assert len(caps["being_id"]) == len("being:") + 64, \
                f"not a canonical being id: {caps['being_id']}"
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
            # The panel is `self` and the trace SAYS so. That is the whole
            # point of the labelled path: a node with one engine does not
            # get an independent panel, and the record admits it instead of
            # naming two fixtures that were copies of the first.
            assert tr["verifier_panel"]["mode"] == "self", tr["verifier_panel"]
            assert tr["verifier_panel"]["verified"] is True
            assert "selected" not in tr["verifier_panel"], (
                "a self-verified trace listed panel members — the shape that "
                "made three copies of one fixture look like independence")
            assert tr["generator"]["object_id"] == "m:self", tr["generator"]
            assert tr["plan_hash"] \
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
            print("  [PASS] G-1  mTLS task -> RECORDED on the REAL backend: "
                  "full path, labelled self-verification, action receipt, "
                  "one chain")

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
            code, caps1 = _req(ctx, base_a + "/capabilities")
            being_before = caps1["being_id"]
            assert being_before.startswith("being:") \
                and len(being_before) == len("being:") + 64, being_before
            procs["A"].terminate(); procs["A"].wait(timeout=15)
            procs["A"] = spawn_a()
            _wait_tls(ctx, base_a)
            code, caps2 = _req(ctx, base_a + "/capabilities")
            assert caps2["being_id"] == being_before, (
                "G-3: the restart changed the BEING. Returning the same "
                "trace is not continuity if a different mind is answering "
                f"for it: {being_before} -> {caps2['being_id']}")
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
            print("  [PASS] G-3  restart over mTLS on the same NODE and "
                  "BEING keystores: the being id is unchanged and the "
                  "trace returns with citations, plan and receipts intact")

            # ---- G-4 ------------------------------------------------------ #
            code, c = _req(ctx, base_a + "/admin/containment", {
                "contain": True, "evidence_refs": ["w:0"],
                "initiator": "guardian:test", "reason": "gate-6 hand-stop"})
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

            # ---- G-6 ------------------------------------------------------ #
            # A lone node in production, given everything it could possibly
            # need EXCEPT a second independent place to verify from.
            # recut6: production is a BOOT gate on the artifact chain, so
            # this node gets what an operator gives one — a signed manifest
            # and the weights, which it measures for itself.
            sys.path.insert(0, os.path.join(_ROOT, "tests"))
            from artifact_fixtures import signed_artifact
            fx = signed_artifact(tmp, backend="hash", fingerprint="fp-being-D")
            man_path = os.path.join(tmp, "model-artifact.json")
            with open(man_path, "w", encoding="utf-8") as fh:
                json.dump(fx.envelope, fh)
            P_D = 8698
            procs["D"] = _spawn(P_D, "being-B", "fp-being-D", tmp, certdir, [
                "--log", os.path.join(tmp, "D.jsonl"),
                "--node-keystore", os.path.join(tmp, "D.keystore"),
                "--being-profile", "production",
                "--being-provenance", prov_path,
                "--substrates", json.dumps([fx.substrate_id]),
                "--substrate-artifacts", json.dumps({fx.substrate_id:
                                                     fx.path}),
                "--model-artifact-manifest", man_path,
                # recut5: production now demands a persistent being and a
                # hosting binding before it will witness under a name.
                "--being-keystore", os.path.join(tmp, "D.being.keystore"),
                "--being-workspace", os.path.join(tmp, "D-ws"),
                "--being-journals", os.path.join(tmp, "D.being")])
            base_d = f"https://127.0.0.1:{P_D}"
            caps_d = _wait_tls(ctx, base_d)
            assert caps_d["being_runtime"] == "production", caps_d
            code6, resp6 = _req(ctx, base_d + "/v1/tasks", {
                "task": {"text": "verify something on your own"}})
            tr6 = resp6.get("trace", {})
            assert tr6.get("state") == "REFUSED", (code6, tr6.get("state"),
                                                   tr6.get("outcome_reason"))
            reason = tr6.get("outcome_reason") or ""
            assert "independent" in reason, reason
            # the CODE is what the network reads; the prose stays local
            last = [t for t in tr6["transitions"] if t["to"] == "REFUSED"][-1]
            assert last["detail"]["reason_code"] == "no_independent_panel", \
                last["detail"]
            assert "reason" not in last["detail"], (
                "free text went into a transition detail again — the witness "
                "plane refuses it and the refusal would not record at all")
            print("  [PASS] G-6  a lone production node refuses and names "
                  "the missing independence in a reason code")
        finally:
            if _prev is None:
                os.environ.pop("JJDAI_KEYSTORE_PASSPHRASE", None)
            else:
                os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = _prev
            if _prev_being is None:
                os.environ.pop("JJDAI_BEING_PASSPHRASE", None)
            else:
                os.environ["JJDAI_BEING_PASSPHRASE"] = _prev_being
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
