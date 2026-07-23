#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TLS/mTLS · weight attestation · external anchoring (v0.5.1) — live
==================================================================
  T-1  a TLS node serves HTTPS: verified with the pinned dev CA;
       an UNPINNED client (empty trust store) is refused; plain HTTP
       against the TLS port fails
  T-2  mTLS: a client WITHOUT a certificate is refused at the handshake;
       with a CA-signed client certificate the same request succeeds
       (fail closed, then open only to the admitted)
  T-3  replication runs over TLS end-to-end: two HTTPS nodes exchange
       roots, acks, consistency and segments through the mTLS channel
  W-1  attestation boot gate: a CONTENT-ADDRESSED substrate whose
       artifact bytes mismatch refuses the boot (exit 2); with matching
       bytes the node boots, witnesses an ATTESTATION record and serves
       the signed DeploymentManifest at GET /attestation (offline-verified)
  W-2  --require-attestation refuses to boot with an unattested substrate
  N-1  external anchoring: POST /witness/anchor runs local + peer-quorum +
       ots backends; the mock OTS calendar receives the 32-byte root and
       its proof bytes are held in CUSTODY (status pending-attestation);
       receipts are durable and served at GET /witness/anchors; the
       ANCHOR_EXTERNAL record is on the chain and the ratchet skips an
       idle re-anchor
"""
from __future__ import annotations

import hashlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.attestation import verify_deployment_manifest            # noqa: E402
from smoke_two_nodes import jii, spawn                             # noqa: E402

P_TLS, P_TLS2, P_CAL, P_ATT = 8671, 8672, 8673, 8674
DAEMON = os.path.join(_ROOT, "node", "daemon.py")
GENCERTS = os.path.join(_ROOT, "scripts", "gen_dev_certs.py")


# ---- TLS-aware mini client ------------------------------------------------ #

def _ctx(ca=None, cert=None, key=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca:
        c.load_verify_locations(ca)
    else:
        c.check_hostname = False        # empty trust store, still verifying
    if cert:
        c.load_cert_chain(cert, key)
    return c


def _get(url, ctx=None, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:
        return r.status, json.loads(r.read().decode())


def _post(url, obj, ctx=None, timeout=10):
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, json.loads(r.read().decode())


def _wait_https(base, ctx, tries=60):
    for _ in range(tries):
        try:
            return _get(base + "/capabilities", ctx=ctx)[1]
        except OSError:
            time.sleep(0.15)
    raise AssertionError(f"node at {base} did not come up over TLS")


# ---- mock OpenTimestamps calendar ---------------------------------------- #

class _Calendar(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        if self.path != "/digest":
            self.send_response(404)
            self.end_headers()
            return
        n = int(self.headers.get("Content-Length", 0))
        digest = self.rfile.read(n)
        _Calendar.received.append(digest)
        # a fake pending-attestation proof deterministically derived from
        # the digest — enough to prove custody round-trips exactly
        proof = b"\x00OTS-PENDING\x01" + hashlib.sha256(digest).digest()
        self.send_response(200)
        self.send_header("Content-Length", str(len(proof)))
        self.end_headers()
        self.wfile.write(proof)

    def log_message(self, *a):
        pass


def test_tls_attest_anchor_live():
    _prev_pass = os.environ.get("JJDAI_KEYSTORE_PASSPHRASE")
    os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = "tls-test-pass"
    procs = []
    cal_srv = ThreadingHTTPServer(("127.0.0.1", P_CAL), _Calendar)
    threading.Thread(target=cal_srv.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            # ---- certs ---------------------------------------------------- #
            certs = os.path.join(tmp, "certs")
            r = subprocess.run([sys.executable, GENCERTS, "--out", certs,
                                "node-a", "node-b", "client-x"],
                               capture_output=True, text=True)
            assert r.returncode == 0, r.stderr
            ca = os.path.join(certs, "ca.crt")

            # ---- weight artifact + content-addressed substrate ------------ #
            weights = os.path.join(tmp, "base.gguf")
            data = os.urandom((1 << 20) + 333)
            with open(weights, "wb") as f:
                f.write(data)
            cid = "sha256:" + hashlib.sha256(data).hexdigest()

            tls_common = lambda name: [
                "--tls-cert", os.path.join(certs, f"{name}.crt"),
                "--tls-key", os.path.join(certs, f"{name}.key"),
                "--tls-ca", ca, "--tls-require-client-cert",
                "--peer-ca", ca,
                "--client-cert", os.path.join(certs, f"{name}.crt"),
                "--client-key", os.path.join(certs, f"{name}.key")]

            base_a = f"https://127.0.0.1:{P_TLS}"
            base_b = f"https://127.0.0.1:{P_TLS2}"
            procs.append(spawn(P_TLS, "tls-A", "fp-tls-A", [
                "--log", os.path.join(tmp, "tls-A.jsonl"),
                "--node-keystore", os.path.join(tmp, "tls-A.keystore"),
                "--substrates", json.dumps([cid]),
                "--substrate-artifacts", json.dumps({cid: weights}),
                "--require-attestation",
                "--anchor-backends", "local,peer-quorum,ots",
                "--ots-calendar", f"http://127.0.0.1:{P_CAL}",
                "--peers", base_b, "--quorum", "1",
            ] + tls_common("node-a")))
            procs.append(spawn(P_TLS2, "tls-B", "fp-tls-B", [
                "--log", os.path.join(tmp, "tls-B.jsonl"),
                "--node-keystore", os.path.join(tmp, "tls-B.keystore"),
                "--peers", base_a, "--quorum", "1",
            ] + tls_common("node-b")))

            mtls = _ctx(ca, os.path.join(certs, "client-x.crt"),
                        os.path.join(certs, "client-x.key"))
            caps = _wait_https(base_a, mtls)
            _wait_https(base_b, mtls)

            # ---- T-1 ------------------------------------------------------ #
            assert caps["attested_substrates"] == [cid]
            unpinned = _ctx()          # empty trust store
            try:
                _get(base_a + "/capabilities", ctx=unpinned)
                assert False, "T-1: unpinned client must refuse the server"
            except (ssl.SSLError, OSError):
                pass
            try:
                _get(f"http://127.0.0.1:{P_TLS}/capabilities")
                assert False, "T-1: plain HTTP must fail against a TLS port"
            except OSError:
                pass
            print("  [PASS] T-1  HTTPS with pinned dev CA; unpinned and "
                  "plaintext refused")

            # ---- T-2 ------------------------------------------------------ #
            no_client_cert = _ctx(ca)
            try:
                _get(base_a + "/capabilities", ctx=no_client_cert)
                assert False, "T-2: mTLS must refuse a certless client"
            except (ssl.SSLError, OSError):
                pass
            code, _ = _get(base_a + "/capabilities", ctx=mtls)
            assert code == 200
            print("  [PASS] T-2  mTLS: certless handshake refused; "
                  "CA-signed client admitted")

            # ---- W-1 ------------------------------------------------------ #
            code, att = _get(base_a + "/attestation", ctx=mtls)
            assert code == 200
            dep = att["deployment"]
            ok, why = verify_deployment_manifest(dep)
            assert ok, f"W-1: served deployment manifest invalid: {why}"
            assert dep["body"]["substrates"][cid]["binding"] == "content"
            code, chain = _get(base_a + "/witness/chain", ctx=mtls)
            kinds = [r["kind"] for r in chain["records"]]
            assert "ATTESTATION" in kinds, \
                "W-1: the attestation must be witnessed on-chain"
            print("  [PASS] W-1  content-bound attestation witnessed and "
                  "served; manifest verifies offline")

            # tampered artifact refuses the boot (exit 2)
            bad_weights = os.path.join(tmp, "tampered.gguf")
            with open(bad_weights, "wb") as f:
                f.write(data + b"\x00")
            r = subprocess.run(
                [sys.executable, DAEMON, "--port", str(P_ATT),
                 "--name", "att-bad", "--fingerprint", "fp-bad",
                 "--substrates", json.dumps([cid]),
                 "--substrate-artifacts", json.dumps({cid: bad_weights})],
                capture_output=True, text=True, timeout=30)
            assert r.returncode == 2 and "refusing" in r.stderr.lower(), \
                f"W-1: tampered artifact must refuse the boot: {r.stderr[:200]}"
            print("  [PASS] W-1b content-addressed mismatch refuses the boot")

            # ---- W-2 ------------------------------------------------------ #
            r = subprocess.run(
                [sys.executable, DAEMON, "--port", str(P_ATT),
                 "--name", "att-none", "--fingerprint", "fp-none",
                 "--substrates", json.dumps([cid]),
                 "--require-attestation"],
                capture_output=True, text=True, timeout=30)
            assert r.returncode == 2 and "attestation" in r.stderr.lower(), \
                f"W-2: {r.stderr[:200]}"
            print("  [PASS] W-2  --require-attestation refuses unattested "
                  "substrates")

            # ---- T-3 replication over TLS -------------------------------- #
            for i in range(2):
                code, _ = _post(base_a + "/v1/messages",
                                jii(caps, prompt=f"tls ping {i}"), ctx=mtls)
                assert code == 200
            code, push = _post(base_a + "/replicate/push", {}, ctx=mtls)
            assert code == 200 and push["quorum_reached"] and push["anchored"], \
                f"T-3: quorum over TLS failed: {push}"
            assert push["peers"][base_b]["status"] == "stored"
            assert push["peers"][base_b].get("segments_pushed", 0) >= 1, \
                "T-3: segments must flow through the mTLS channel too"
            print("  [PASS] T-3  roots, acks and segments replicated over "
                  "mTLS; quorum anchored")

            # ---- N-1 external anchoring ---------------------------------- #
            code, anc = _post(base_a + "/witness/anchor", {}, ctx=mtls)
            assert code == 200 and anc.get("anchored"), anc
            by_backend = {r["backend"]: r for r in anc["receipts"]}
            assert by_backend["local"]["status"] == "recorded"
            assert by_backend["peer-quorum"]["status"] in ("recorded",
                                                           "pending")
            ots = by_backend["ots-calendar"]
            assert ots["status"] == "pending-attestation" and ots["proof_hex"]
            assert _Calendar.received, "N-1: calendar never saw the digest"
            sent = _Calendar.received[-1]
            assert sent.hex() == anc["root"], \
                "N-1: the calendar must receive the exact 32-byte root"
            expected = b"\x00OTS-PENDING\x01" + hashlib.sha256(sent).digest()
            assert bytes.fromhex(ots["proof_hex"]) == expected, \
                "N-1: custody must hold the calendar's exact proof bytes"
            code, held = _get(base_a + "/witness/anchors", ctx=mtls)
            assert len(held["receipts"]) >= 3 and "ots-calendar" in \
                held["backends"], held
            code, chain = _get(base_a + "/witness/chain", ctx=mtls)
            assert chain["records"][-1]["kind"] == "ANCHOR_EXTERNAL"
            code, anc2 = _post(base_a + "/witness/anchor", {}, ctx=mtls)
            assert anc2.get("skipped") == "not-substantive", \
                f"N-1: idle re-anchor must be skipped: {anc2}"
            print("  [PASS] N-1  local+peer-quorum+ots anchored; proof "
                  "custody exact; durable receipts; ratchet skips idle")
        finally:
            cal_srv.shutdown()
            if _prev_pass is None:
                os.environ.pop("JJDAI_KEYSTORE_PASSPHRASE", None)
            else:
                os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = _prev_pass
            for pr in procs:
                pr.terminate()
            for pr in procs:
                try:
                    pr.wait(timeout=10)
                except Exception:
                    pr.kill()


if __name__ == "__main__":
    test_tls_attest_anchor_live()
    print("\nTLS + ATTESTATION + ANCHORING: all groups green  ✓ certified")
