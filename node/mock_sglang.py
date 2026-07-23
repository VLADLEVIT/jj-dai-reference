#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Mock SGLang Server (CI contract, v0.1)
===============================================
A stdlib, deterministic stand-in for an SGLang server, implementing exactly
the API subset that engine_sglang.py binds to:

    GET  /health
    GET  /get_model_info
    POST /generate     (text, sampling_params, lora_path,
                        return_logprob, logprob_start_len, top_logprobs_num)

Purpose: the SGLang adapter and the whole Tier-2 daemon path must be
CERTIFIABLE in CI — no GPU, no network, no third-party wheels. This mock is
the executable contract; when a real SGLang version changes a field, this
file is where the divergence is captured and the adapter re-pinned.

Model: a deterministic language model over a small vocabulary — token
distribution at each step is derived from sha256(context ‖ token ‖ lora),
mirroring the router's ReferenceEngine. Deterministic => the adapter can be
declared 'reproducible' in CI, and teacher-forcing verification has real
teeth: a forged token genuinely falls outside the nucleus.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VOCAB = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta",
         "eta", "theta", "iota", "kappa", "lam", "mu"]


def _weight(context: str, token: str, lora: str) -> float:
    h = hashlib.sha256(f"{lora}|{context}|{token}".encode()).digest()
    return 1.0 + int.from_bytes(h[:4], "big") / 2**32 * 9.0   # in [1,10)


def _dist(context: str, lora: str) -> dict:
    w = {t: _weight(context, t, lora) for t in VOCAB}
    z = sum(w.values())
    return {t: v / z for t, v in w.items()}


def _nucleus(dist: dict, sp: dict) -> list:
    ordered = sorted(dist.items(), key=lambda kv: (-kv[1], kv[0]))
    k = sp.get("top_k", -1)
    if k and k > 0:
        ordered = ordered[:k]
    if sp.get("temperature", 0.0) <= 0.0:
        return ordered[:1]
    out, acc = [], 0.0
    for t, p in ordered:
        out.append((t, p))
        acc += p
        if acc >= sp.get("top_p", 1.0):
            break
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    model_path = "mock/frozen-base-A"
    lora_paths = ["adp-good"]

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        if self.path == "/get_model_info":
            return self._send(200, {"model_path": self.model_path,
                                    "is_generation": True,
                                    "lora_paths": self.lora_paths})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/generate":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n).decode())
        text = req.get("text", "")
        sp = req.get("sampling_params", {})
        lora = req.get("lora_path", "")
        words = text.split()

        # ---- teacher-forcing path: score the forced continuation --------- #
        if req.get("return_logprob"):
            start = req.get("logprob_start_len", len(words))
            kk = req.get("top_logprobs_num", 16)
            input_top, in_lp = [], []
            for pos in range(start, len(words)):
                ctx = " ".join(words[:pos])
                dist = _dist(ctx, lora)
                ordered = sorted(dist.items(), key=lambda kv: (-kv[1], kv[0]))[:kk]
                input_top.append([[math.log(p), t] for t, p in ordered])
                tok = words[pos]
                in_lp.append([math.log(dist.get(tok, 1e-12)), tok])
            return self._send(200, {
                "text": "",
                "meta_info": {"input_top_logprobs": input_top,
                              "input_token_logprobs": in_lp,
                              "prompt_tokens": start,
                              "completion_tokens": 0},
            })

        # ---- generation path: deterministic nucleus decode --------------- #
        out, ctx_words = [], list(words)
        for _ in range(min(sp.get("max_new_tokens", 8), 32)):
            nuc = _nucleus(_dist(" ".join(ctx_words), lora), sp)
            # deterministic pick inside the nucleus (hash-seeded index)
            seed = hashlib.sha256((" ".join(ctx_words) + lora).encode()).digest()
            tok = nuc[int.from_bytes(seed[4:8], "big") % len(nuc)][0]
            out.append(tok)
            ctx_words.append(tok)
        return self._send(200, {
            "text": " ".join(out),
            "meta_info": {"prompt_tokens": len(words),
                          "completion_tokens": len(out),
                          "finish_reason": "length"},
        })

    def log_message(self, fmt, *args):
        pass


def main(port: int = 30000):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[mock-sglang] http://127.0.0.1:{port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 30000)
