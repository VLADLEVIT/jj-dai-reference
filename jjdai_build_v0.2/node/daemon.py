#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Tier-1 Node Daemon (v0.1)
==================================
The first LIVE certification target for the NECS conformance suite: a stdlib
HTTP server exposing the /v1/messages JII envelope (NECS C1), backed by the
REAL jjdai primitive layer — Ed25519-signed WitnessChain, RFC 8785 JCS
canonicalization, hiding commitments H(salt‖x).

Whitepaper §13 step 1: "2 nodes (Xeon + RTX 6000): memory integrity, base +
RAG + prompting + tools, no fine-tuning." This daemon is that node's trust
shell. The inference engine is a SEAM: `HashEngine` (deterministic reference)
runs today; a DwarfStar `/v1` adapter (Profile B) plugs into the same three
methods without touching the envelope or witness logic.

Endpoints
---------
GET  /capabilities       NECS capability descriptor (+ witness pubkey)
POST /v1/messages        JII request -> JII response  (C1 semantics:
                         400 BAD_ENVELOPE · 404 SUBSTRATE_UNKNOWN ·
                         404 ADAPTER_UNKNOWN · 422 PROVENANCE_MISMATCH ·
                         503 WITNESS_UNAVAILABLE — fail-closed, NO output)
GET  /witness/chain      full chain export (bodies only — salts never leave)
GET  /witness/head       {head, count, node_id}
POST /witness/anchor     batch-anchor new records; returns Merkle root receipt
POST /admin/witness      TEST HOOK (only with --allow-test-hooks):
                         {"up": false} simulates witness failure

Run
---
    python3 daemon.py --port 8471 --fingerprint fp-node-A
    python3 daemon.py --port 8472 --fingerprint fp-node-B --profile A \
        --adapters '{"sha256:adp-good":"sha256:base-A","sha256:adp-bad":"sha256:base-OTHER"}'

Certification: node/smoke_two_nodes.py (remote R-C1..R-C3 suite).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import H_hex, SigningKey, node_id         # noqa: E402
from jjdai.witness import WitnessChain, LocalAnchor         # noqa: E402

JII_REQUIRED = ("substrate_id", "adapter_ids", "sampling", "request_id", "nonce")


def semantic_digest(text: str) -> str:
    """8-dim char-class histogram — the harness's cheap embedding stand-in.
    Consensus (C3.6) compares THIS, never hiding commitments."""
    buckets = [0] * 8
    for ch in text:
        buckets[ord(ch) % 8] += 1
    return ",".join(str(b) for b in buckets)


# --------------------------------------------------------------------------- #
# Engine seam
# --------------------------------------------------------------------------- #

class HashEngine:
    """Deterministic reference engine (Profile B). Same input -> same bytes,
    so the node can honestly declare determinism_level='reproducible'.

    PRODUCTION SEAM: replace with DwarfStarEngine — an adapter that forwards
    `messages`+`sampling` to the local DwarfStar /v1 endpoint and declares
    determinism_level='attested'. The daemon's envelope/witness logic does
    not change."""

    determinism_level = "reproducible"
    backend = "cpu"

    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint

    def generate(self, messages: list, sampling: dict) -> str:
        prompt = canonical(messages).decode()
        return "out:" + H_hex((prompt + self.fingerprint).encode())[:24]


# --------------------------------------------------------------------------- #
# Node
# --------------------------------------------------------------------------- #

class Node:
    def __init__(self, *, name: str, profile: str, substrates: list,
                 adapters: dict, engine: HashEngine, log_path: str = None,
                 allow_test_hooks: bool = False):
        self.name = name
        self.profile = profile
        self.substrates = list(substrates)
        self.adapters = dict(adapters)          # adapter_id -> base_compat_tag
        self.engine = engine
        self.sk = SigningKey.generate()
        self.chain = WitnessChain(self.sk, anchor=LocalAnchor(),
                                  log_path=log_path)
        self.witness_up = True                  # test hook flips this
        self.allow_test_hooks = allow_test_hooks
        self._lock = threading.Lock()

    # ---- capability descriptor (NECS C1.2) ----
    def capabilities(self) -> dict:
        return {
            "engine": "jjdai-tier1-daemon", "engine_version": "0.1",
            "backend": self.engine.backend, "profile": self.profile,
            "substrates": self.substrates, "adapters": list(self.adapters),
            "max_context": 65536,
            "determinism_level": self.engine.determinism_level,
            "engine_fingerprint": self.engine.fingerprint,
            "witness": {
                "sig_alg": "ed25519",
                "node_id": self.chain.node_id,
                "pubkey": self.sk.public.hex(),
                "anchor": "local",
            },
        }

    # ---- JII handler (NECS C1.3–C1.8) ----
    def handle(self, request: dict) -> tuple[int, dict]:
        for field in JII_REQUIRED:
            if field not in request:
                return 400, {"error": "400 BAD_ENVELOPE", "missing": field}
        if request["substrate_id"] not in self.substrates:
            return 404, {"error": "404 SUBSTRATE_UNKNOWN"}
        for aid in request["adapter_ids"]:
            if aid not in self.adapters:
                return 404, {"error": "404 ADAPTER_UNKNOWN"}
            if self.adapters[aid] != request["substrate_id"]:
                return 422, {"error": "422 PROVENANCE_MISMATCH"}
        # C1.8 / C3 — FAIL CLOSED: no witness, no inference, NO output field.
        if not self.witness_up:
            return 503, {"error": "503 WITNESS_UNAVAILABLE"}

        sampling = dict(request["sampling"])    # never silently mutated (C1.7)
        text = self.engine.generate(request["messages"], sampling)
        output = {"role": "assistant", "content": text}
        provenance = {
            "substrate_id": request["substrate_id"],
            "adapter_ids": request["adapter_ids"],
            "engine_fingerprint": self.engine.fingerprint,
            "determinism_level": self.engine.determinism_level,
            "sampling": sampling,
            "hardware_class": self.engine.backend,
        }
        with self._lock:                        # one chain, serialized appends
            receipt = self.chain.append(
                "INFER",
                request=request,                # -> hiding commitment only
                response=output,                # -> hiding commitment only
                provenance=provenance,
                semantic_digest=semantic_digest(text),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
        return 200, {
            "request_id": request["request_id"],
            "nonce": request["nonce"],
            "champion_context": request.get("champion_context"),
            "output": output,
            "provenance": provenance,
            "witness_receipt": receipt,
        }

    # ---- witness export (bodies only — salts stay local, off-chain) ----
    def chain_export(self) -> dict:
        with self._lock:
            return {"node_id": self.chain.node_id,
                    "pubkey": self.sk.public.hex(),
                    "head": self.chain.head_hash(),
                    "records": list(self.chain.records)}

    def anchor(self) -> dict:
        with self._lock:
            return self.chain.anchor_root()


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #

def make_handler(node: Node):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, obj: dict):
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n) if n else b"{}"
            try:
                return json.loads(raw.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None

        def do_GET(self):
            if self.path == "/capabilities":
                return self._send(200, node.capabilities())
            if self.path == "/witness/chain":
                return self._send(200, node.chain_export())
            if self.path == "/witness/head":
                exp = node.chain_export()
                return self._send(200, {"node_id": exp["node_id"],
                                        "head": exp["head"],
                                        "count": len(exp["records"])})
            return self._send(404, {"error": "404 NOT_FOUND"})

        def do_POST(self):
            if self.path == "/v1/messages":
                req = self._read_json()
                if req is None:
                    return self._send(400, {"error": "400 BAD_ENVELOPE",
                                            "missing": "valid-json-body"})
                code, resp = node.handle(req)
                return self._send(code, resp)
            if self.path == "/witness/anchor":
                return self._send(200, node.anchor())
            if self.path == "/admin/witness":
                if not node.allow_test_hooks:
                    return self._send(403, {"error": "403 TEST_HOOKS_DISABLED"})
                req = self._read_json() or {}
                node.witness_up = bool(req.get("up", True))
                return self._send(200, {"witness_up": node.witness_up})
            return self._send(404, {"error": "404 NOT_FOUND"})

        def log_message(self, fmt, *args):     # quiet by default
            if os.environ.get("JJDAI_DAEMON_VERBOSE"):
                sys.stderr.write("[%s] %s\n" % (node.name, fmt % args))

    return Handler


def main(argv=None):
    ap = argparse.ArgumentParser(description="JJ DAI Tier-1 node daemon")
    ap.add_argument("--port", type=int, default=8471)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--name", default="tier1-node")
    ap.add_argument("--profile", choices=("A", "B"), default="B")
    ap.add_argument("--substrates", default='["sha256:base-A"]',
                    help="JSON list of served substrate ids")
    ap.add_argument("--adapters", default="{}",
                    help='JSON map adapter_id -> base_compat_tag (Profile A)')
    ap.add_argument("--fingerprint", default="fp-tier1-0001")
    ap.add_argument("--log", default=None, help="JSONL witness persistence path")
    ap.add_argument("--allow-test-hooks", action="store_true",
                    help="enable /admin/witness (NEVER in production)")
    args = ap.parse_args(argv)

    node = Node(name=args.name, profile=args.profile,
                substrates=json.loads(args.substrates),
                adapters=json.loads(args.adapters),
                engine=HashEngine(args.fingerprint),
                log_path=args.log, allow_test_hooks=args.allow_test_hooks)
    srv = ThreadingHTTPServer((args.host, args.port), make_handler(node))
    print(f"[{args.name}] node_id={node.chain.node_id[:16]}…  "
          f"profile={args.profile}  http://{args.host}:{args.port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
