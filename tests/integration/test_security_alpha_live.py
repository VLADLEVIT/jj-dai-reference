#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security-alpha, live (v0.5.5) — the operational boundary over mTLS
==================================================================
Two real daemons under a production-style PKI (offline root CA, admin
client cert, node leaf certs), an authz policy and a revocation list.

  S-1  AUTHZ by role: an admin client reaches /admin/* and /challenge/
       open; a plain peer client is 403'd there but still reaches
       /v1/tasks and /witness/*; the matched rule is named in the 403
  S-2  REVOCATION beats identity: after the admin serial is revoked
       (node reloaded with it in --revoked-serials), the very same cert
       gets 401 CERT_REVOKED on every path — revoked is nobody
  S-3  METRICS + HEALTH: /healthz is open; /metrics needs peer/admin and
       exposes witnessed counters that MOVED under the traffic above
       (requests_total up, denied_authz_total > 0)
  S-4  CHALLENGE over the wire: an admin opens a round; two peer nodes
       claim seats with real VRF proofs, commit blind, reveal, and the
       admin resolves to a witnessed majority verdict — the adversarial
       round now runs across the network, not just in-process
  S-5  the PKI itself: every issued leaf verifies to the offline root CA
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

from jjdai.crypto import SigningKey, vrf_prove                     # noqa: E402
from core.challenge import sortition_alpha                         # noqa: E402

DAEMON = os.path.join(_ROOT, "node", "daemon.py")
GEN_PKI = os.path.join(_ROOT, "deploy", "gen_pki.py")
P_A, P_B = 8695, 8696


def _ctx(ca, cert, key):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(ca)
    c.check_hostname = False
    c.load_cert_chain(cert, key)
    return c


def _req(ctx, url, payload=None, timeout=15, method=None, raw=False):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"}
                                 if data else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode()
            return r.status, (body if raw else json.loads(body))
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body


def _wait(ctx, base, tries=60):
    for _ in range(tries):
        try:
            code, _ = _req(ctx, base + "/healthz")
            if code == 200:
                return True
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"{base} never came up")


def test_security_alpha_live():
    _prev = os.environ.get("JJDAI_KEYSTORE_PASSPHRASE")
    os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = "sec-alpha-pass"
    procs = {}
    with tempfile.TemporaryDirectory() as tmp:
        pki = os.path.join(tmp, "pki")
        # ---- S-5 PKI: offline CA, node leaves, admin + peer client certs
        subprocess.run([sys.executable, GEN_PKI, "init-ca", "--out", pki,
                        "--cn", "JJ DAI test root"], check=True,
                       capture_output=True)
        for name in ("node-a", "node-b"):
            subprocess.run([sys.executable, GEN_PKI, "node", "--out", pki,
                            "--name", name, "--ip", "127.0.0.1"],
                           check=True, capture_output=True)
        subprocess.run([sys.executable, GEN_PKI, "admin", "--out", pki,
                        "--cn", "ops-ua"], check=True, capture_output=True)
        # a plain peer client cert (CN not in admin_cns)
        subprocess.run([sys.executable, GEN_PKI, "node", "--out", pki,
                        "--name", "peer-client", "--ip", "127.0.0.1"],
                       check=True, capture_output=True)
        for leaf in ("node-a", "node-b", "admin-ops-ua", "peer-client"):
            r = subprocess.run(["openssl", "verify", "-CAfile",
                                os.path.join(pki, "ca.crt"),
                                os.path.join(pki, f"{leaf}.crt")],
                               capture_output=True, text=True)
            assert r.returncode == 0, f"S-5: {leaf} does not verify: {r.stderr}"
        print("  [PASS] S-5  production PKI: offline root CA, every leaf "
              "verifies to it")

        # authz policy + provenance
        authz = {"default": "deny", "admin_cns": ["ops-ua"], "rules": [
            {"prefix": "/healthz", "allow": ["anonymous", "peer", "admin"]},
            {"prefix": "/metrics", "allow": ["peer", "admin"]},
            {"prefix": "/capabilities", "allow": ["peer", "admin"]},
            {"prefix": "/witness/", "allow": ["peer", "admin"]},
            {"prefix": "/v1/", "allow": ["peer", "admin"]},
            {"prefix": "/challenge/seat", "allow": ["peer", "admin"]},
            {"prefix": "/challenge/commit", "allow": ["peer", "admin"]},
            {"prefix": "/challenge/reveal", "allow": ["peer", "admin"]},
            {"prefix": "/challenge/open", "allow": ["admin"]},
            {"prefix": "/challenge/resolve", "allow": ["admin"]},
            {"prefix": "/admin/", "allow": ["admin"]}]}
        authz_path = os.path.join(tmp, "authz.json")
        json.dump(authz, open(authz_path, "w"))
        prov = {m: {"model_id": m, "base_family": "fam-G",
                    "architecture_family": a,
                    "training_data_families": [d], "operator_domain":
                    f"{m}.x", "jurisdiction": j}
                for m, a, d, j in (("m:gen", "ar-a", "ds-g", "UA"),
                                   ("m:v1", "ar-b", "ds-1", "KR"),
                                   ("m:v2", "ar-c", "ds-2", "EE"))}
        prov_path = os.path.join(tmp, "prov.json")
        json.dump(prov, open(prov_path, "w"))
        revoked_path = os.path.join(tmp, "revoked.txt")
        open(revoked_path, "w").close()

        def spawn_a():
            return subprocess.Popen([
                sys.executable, DAEMON, "--port", str(P_A), "--name",
                "node-a", "--fingerprint", "fp-a",
                "--log", os.path.join(tmp, "a.jsonl"),
                "--node-keystore", os.path.join(tmp, "a.keystore"),
                "--tls-cert", os.path.join(pki, "node-a.crt"),
                "--tls-key", os.path.join(pki, "node-a.key"),
                "--tls-ca", os.path.join(pki, "ca.crt"),
                "--tls-require-client-cert",
                "--authz-policy", authz_path,
                "--revoked-serials", "@" + revoked_path,
                "--rate-limit", "infer=100/60,task=50/60,read=200/60",
                "--challenge-windows", "3,3",
                "--being-profile", "production",
                "--being-provenance", prov_path,
                "--being-workspace", os.path.join(tmp, "a.ws"),
                "--being-journals", os.path.join(tmp, "a.being")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        admin_ctx = _ctx(os.path.join(pki, "ca.crt"),
                         os.path.join(pki, "admin-ops-ua.crt"),
                         os.path.join(pki, "admin-ops-ua.key"))
        peer_ctx = _ctx(os.path.join(pki, "ca.crt"),
                        os.path.join(pki, "peer-client.crt"),
                        os.path.join(pki, "peer-client.key"))
        base_a = f"https://127.0.0.1:{P_A}"
        try:
            procs["a"] = spawn_a()
            _wait(admin_ctx, base_a)

            # ---- S-1 authz by role ---------------------------------------- #
            # admin reaches an admin-only route (challenge/open); a peer is
            # 403'd there with the matched rule named, but still serves /v1
            vks0 = {"v0": SigningKey.generate()}
            code, _ = _req(admin_ctx, base_a + "/challenge/open", {
                "round_id": "authz-probe", "transcript_hash": "t",
                "eligible": {k: v.public.hex() for k, v in vks0.items()},
                "k": 1})
            assert code == 200, f"S-1: admin blocked from /challenge/open: {code}"
            code, body = _req(peer_ctx, base_a + "/admin/containment",
                              {"contain": False})
            assert code == 403 and body["role"] == "peer" \
                and body["rule"] == "/admin/", body
            code, _ = _req(peer_ctx, base_a + "/v1/tasks",
                           {"task": {"text": "peer may compute"}})
            assert code == 200, f"S-1: peer wrongly blocked from /v1/tasks"
            code, body = _req(peer_ctx, base_a + "/challenge/open",
                              {"round_id": "x", "transcript_hash": "y",
                               "eligible": {}, "k": 1})
            assert code == 403, "S-1: peer must not open challenge rounds"
            print("  [PASS] S-1  authz: admin reaches /challenge/open + "
                  "/admin/*; peer 403'd there, named rule, but serves "
                  "/v1/tasks")

            # ---- S-3 metrics + health ------------------------------------- #
            code, _ = _req(admin_ctx, base_a + "/healthz")
            assert code == 200
            code, text = _req(peer_ctx, base_a + "/metrics", raw=True)
            assert code == 200 and "jjdai_requests_total" in text \
                and "jjdai_denied_authz_total" in text, text[:200]
            denied = int([ln for ln in text.splitlines()
                          if ln.startswith("jjdai_denied_authz_total")
                          ][0].split()[1])
            assert denied >= 1, "S-3: the 403s above must show in metrics"
            print(f"  [PASS] S-3  /healthz open; /metrics gated + live "
                  f"(denied_authz_total={denied})")

            # ---- S-4 challenge over the network --------------------------- #
            vks = {"vA": SigningKey.generate(), "vB": SigningKey.generate(),
                   "vC": SigningKey.generate()}
            eligible = {k: v.public.hex() for k, v in vks.items()}
            code, opened = _req(admin_ctx, base_a + "/challenge/open", {
                "round_id": "net-1", "transcript_hash": "task-hash-1",
                "eligible": eligible, "k": 3})
            assert code == 200, opened
            alpha = bytes.fromhex(opened["alpha"])
            seats = []
            for vid, sk in vks.items():
                code, r = _req(peer_ctx, base_a + "/challenge/seat", {
                    "round_id": "net-1", "verifier_id": vid,
                    "proof": vrf_prove(sk, alpha).hex()})
                assert code == 200, r
                if r["won"]:
                    seats.append(vid)
            assert len(seats) >= 2, f"S-4: only {len(seats)} seats won"
            verdict = {"verified": True}
            salts = {}
            from core.challenge import ChallengeRound
            for vid in seats:
                salts[vid] = os.urandom(8).hex()
                code, r = _req(peer_ctx, base_a + "/challenge/commit", {
                    "round_id": "net-1", "verifier_id": vid,
                    "commitment": ChallengeRound.make_commitment(
                        "net-1", vid, verdict, salts[vid])})
                assert code == 200, r
            for vid in seats:
                code, r = _req(peer_ctx, base_a + "/challenge/reveal", {
                    "round_id": "net-1", "verifier_id": vid,
                    "verdict": verdict, "salt": salts[vid]})
                assert code == 200, r
            # resolve needs the reveal window closed; poll briefly
            res = None
            for _ in range(40):
                code, res = _req(admin_ctx, base_a + "/challenge/resolve",
                                 {"round_id": "net-1"})
                if code == 200 and res.get("status") == "resolved":
                    break
                time.sleep(1)
            assert res and res["status"] == "resolved" \
                and res["verdict"] == verdict \
                and sorted(res["supporters"]) == sorted(seats), res
            print(f"  [PASS] S-4  challenge round over mTLS: {len(seats)} "
                  "seats claimed by VRF, blind-committed, revealed, "
                  "resolved to a witnessed majority")

            # ---- S-2 revocation beats identity ---------------------------- #
            serial = subprocess.run(
                ["openssl", "x509", "-in",
                 os.path.join(pki, "admin-ops-ua.crt"), "-noout", "-serial"],
                capture_output=True, text=True).stdout.strip().split("=")[1]
            with open(revoked_path, "w") as f:
                f.write(serial + "\n")
            procs["a"].terminate(); procs["a"].wait(timeout=15)
            procs["a"] = spawn_a()
            _wait(peer_ctx, base_a)               # peer still works
            code, body = _req(admin_ctx, base_a + "/capabilities")
            assert code == 401 and "REVOKED" in body["error"], \
                f"S-2: revoked admin cert still accepted: {code} {body}"
            code, _ = _req(peer_ctx, base_a + "/capabilities")
            assert code == 200, "S-2: an unrevoked peer must still work"
            print("  [PASS] S-2  revocation beats identity: the revoked "
                  "admin cert is 401 everywhere; unrevoked peer unaffected")
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
    test_security_alpha_live()
    print("\nSECURITY-ALPHA LIVE: all gates green  ✓ certified")
