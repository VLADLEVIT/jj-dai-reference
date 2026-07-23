#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Monero anchoring, live (v0.5.2) — daemon + mock monero-wallet-rpc
=================================================================
  M-1  the daemon anchors through the xmr backend: the wallet-rpc
       receives a `transfer` whose SINGLE destination is one piconero to
       the address derived from the ANCHORED ROOT (independently
       re-derived by the test); the receipt holds tx_hash + tx_key in
       custody with status pending-confirmation and the derivation tag
  M-2  the receipt binds OFFLINE: verify_receipt_binding(root, receipt)
       passes for the anchored root and refuses a different root
  M-3  receipts are durable (GET /witness/anchors after the round) and
       one ANCHOR_EXTERNAL record summarizes the round on-chain
  M-4  DEFENSE IN DEPTH: with the wallet-rpc DOWN the xmr receipt is
       status=failed (named, durable) while the local backend still
       records — one dead anchor never silences the round
  M-5  the daemon refuses to boot with the xmr backend and no
       --xmr-wallet-rpc (fail closed on configuration)
"""
from __future__ import annotations

import json
import os
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

from core.anchoring_xmr import (xmr_address_from_root,             # noqa: E402
                                verify_receipt_binding)
from smoke_two_nodes import get, post, wait_up, jii, spawn         # noqa: E402

P_NODE, P_RPC = 8681, 8682
DAEMON = os.path.join(_ROOT, "node", "daemon.py")


class _WalletRpc(BaseHTTPRequestHandler):
    """Mock monero-wallet-rpc: validates the transfer shape and answers
    like the real thing (tx_hash/tx_key/fee)."""
    transfers = []

    def do_POST(self):
        if self.path != "/json_rpc":
            self.send_response(404)
            self.end_headers()
            return
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n).decode())
        if req.get("method") != "transfer":
            body = {"jsonrpc": "2.0", "id": req.get("id"),
                    "error": {"code": -32601, "message": "unknown method"}}
        else:
            _WalletRpc.transfers.append(req["params"])
            fake = os.urandom(32).hex()
            body = {"jsonrpc": "2.0", "id": req.get("id"),
                    "result": {"tx_hash": fake,
                               "tx_key": os.urandom(32).hex(),
                               "fee": 30720000, "amount":
                                   req["params"]["destinations"][0]["amount"]}}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def test_xmr_anchor_live():
    _prev = os.environ.get("JJDAI_KEYSTORE_PASSPHRASE")
    os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = "xmr-test-pass"
    base = f"http://127.0.0.1:{P_NODE}"
    rpc_srv = ThreadingHTTPServer(("127.0.0.1", P_RPC), _WalletRpc)
    threading.Thread(target=rpc_srv.serve_forever, daemon=True).start()
    procs = []
    with tempfile.TemporaryDirectory() as tmp:
        try:
            procs.append(spawn(P_NODE, "xmr-A", "fp-xmr-A", [
                "--log", os.path.join(tmp, "xmr-A.jsonl"),
                "--node-keystore", os.path.join(tmp, "xmr-A.keystore"),
                "--anchor-backends", "local,xmr",
                "--xmr-wallet-rpc", f"http://127.0.0.1:{P_RPC}",
                "--xmr-network", "stagenet"]))
            caps = wait_up(base)
            for i in range(2):
                code, _ = post(base + "/v1/messages",
                               jii(caps, prompt=f"xmr ping {i}"))
                assert code == 200

            # ---- M-1 ------------------------------------------------------ #
            code, anc = post(base + "/witness/anchor", {})
            assert code == 200 and anc.get("anchored"), anc
            xr = next(r for r in anc["receipts"] if r["backend"] == "xmr")
            assert xr["status"] == "pending-confirmation" \
                and xr["tx_hash"] and xr["tx_key"] \
                and xr["derivation"] == "jjdai-xmr-spendkey-v1" \
                and xr["network"] == "stagenet", xr
            assert len(_WalletRpc.transfers) == 1
            sent = _WalletRpc.transfers[0]["destinations"]
            assert len(sent) == 1 and sent[0]["amount"] == 1, \
                "M-1: exactly one piconero to exactly one destination"
            expect = xmr_address_from_root(anc["root"], "stagenet")
            assert sent[0]["address"] == expect == xr["address"], \
                "M-1: the wallet must be paid at the ROOT-derived address"
            print("  [PASS] M-1  transfer = 1 piconero to the root-derived "
                  "stagenet address; custody holds tx_hash/tx_key")

            # ---- M-2 ------------------------------------------------------ #
            assert verify_receipt_binding(anc["root"], xr) == (True, "ok")
            ok, _ = verify_receipt_binding("ab" * 32, xr)
            assert not ok, "M-2: a foreign root must not bind"
            print("  [PASS] M-2  offline binding: anchored root ok, foreign "
                  "root refused")

            # ---- M-3 ------------------------------------------------------ #
            code, held = get(base + "/witness/anchors")
            assert any(r["backend"] == "xmr" for r in held["receipts"]) \
                and "xmr" in held["backends"], held
            code, chain = get(base + "/witness/chain")
            assert chain["records"][-1]["kind"] == "ANCHOR_EXTERNAL"
            summary = chain["records"][-1]["semantic_digest"]
            assert {"backend": "xmr", "status": "pending-confirmation"} in \
                summary["backends"], summary
            print("  [PASS] M-3  durable receipt served; ANCHOR_EXTERNAL "
                  "summarizes the xmr round on-chain")

            # ---- M-4 ------------------------------------------------------ #
            rpc_srv.shutdown()
            rpc_srv.server_close()      # release the port: refuse, not hang
            time.sleep(0.2)
            post(base + "/v1/messages", jii(caps, prompt="xmr after down"))
            code, anc2 = post(base + "/witness/anchor", {})
            assert code == 200 and anc2.get("anchored"), anc2
            by = {r["backend"]: r for r in anc2["receipts"]}
            assert by["xmr"]["status"] == "failed" and by["xmr"]["detail"], \
                f"M-4: a dead wallet-rpc must yield a NAMED failure: {by}"
            assert by["local"]["status"] == "recorded", \
                "M-4: the local backend must still record the round"
            print("  [PASS] M-4  wallet-rpc down: xmr fails NAMED and "
                  "durable; the round still completes")

            # ---- M-5 ------------------------------------------------------ #
            r = subprocess.run(
                [sys.executable, DAEMON, "--port", "8683",
                 "--name", "xmr-bad", "--fingerprint", "fp-bad",
                 "--anchor-backends", "xmr"],
                capture_output=True, text=True, timeout=30)
            assert r.returncode == 2 and "xmr-wallet-rpc" in r.stderr, \
                f"M-5: {r.stderr[:200]}"
            print("  [PASS] M-5  xmr backend without wallet-rpc URL refuses "
                  "the boot")
        finally:
            try:
                rpc_srv.shutdown()
                rpc_srv.server_close()
            except Exception:
                pass
            if _prev is None:
                os.environ.pop("JJDAI_KEYSTORE_PASSPHRASE", None)
            else:
                os.environ["JJDAI_KEYSTORE_PASSPHRASE"] = _prev
            for pr in procs:
                pr.terminate()
            for pr in procs:
                try:
                    pr.wait(timeout=10)
                except Exception:
                    pr.kill()


if __name__ == "__main__":
    test_xmr_anchor_live()
    print("\nXMR ANCHOR LIVE: all groups green  ✓ certified")
