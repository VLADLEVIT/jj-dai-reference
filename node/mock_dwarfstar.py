#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Mock DwarfStar Server (CI contract, v0.1)
==================================================
Stdlib, deterministic stand-in for a DwarfStar (ds4) server. This file IS the
wire contract engine_dwarfstar.py is certified against — when the real ds4
build differs, capture the divergence HERE first, then re-pin the adapter.

Serves BOTH dialects the adapter can auto-probe (pick with argv[2]):

  oai:  GET  /v1/models                 {data:[{id: "ds4-flash"}]}
        POST /v1/chat/completions       {model, messages, temperature, top_p,
                                         max_tokens}
                                        -> {choices:[{message:{role,content}}]}
  gen:  GET  /v1/model                  {model: "ds4-flash"}
        POST /v1/generate               {prompt, temperature, top_p, top_k,
                                         n_predict, logprobs?, logprob_start?}
                                        -> {content} | {top_logprobs} (forced)
  both: GET  /health                    {status: "ok"}

Model: same deterministic hash-derived distribution as mock_sglang — so the
adapter can be declared 'reproducible' in CI and teacher-forcing (gen dialect
with logprobs) has real teeth.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VOCAB = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta",
         "eta", "theta", "iota", "kappa", "lam", "mu"]
MODEL = "ds4-flash"


def _dist(context: str) -> dict:
    w = {}
    for t in VOCAB:
        h = hashlib.sha256(f"ds4|{context}|{t}".encode()).digest()
        w[t] = 1.0 + int.from_bytes(h[:4], "big") / 2**32 * 9.0
    z = sum(w.values())
    return {t: v / z for t, v in w.items()}


def _nucleus(dist: dict, temp: float, top_p: float, top_k: int) -> list:
    ordered = sorted(dist.items(), key=lambda kv: (-kv[1], kv[0]))
    if top_k and top_k > 0:
        ordered = ordered[:top_k]
    if temp <= 0.0:
        return ordered[:1]
    out, acc = [], 0.0
    for t, p in ordered:
        out.append((t, p))
        acc += p
        if acc >= top_p:
            break
    return out


def _decode(prompt: str, temp: float, top_p: float, top_k: int, n: int) -> str:
    ctx = prompt.split()
    out = []
    for _ in range(min(n, 32)):
        nuc = _nucleus(_dist(" ".join(ctx)), temp, top_p, top_k)
        seed = hashlib.sha256((" ".join(ctx) + "ds4").encode()).digest()
        tok = nuc[int.from_bytes(seed[4:8], "big") % len(nuc)][0]
        out.append(tok)
        ctx.append(tok)
    return " ".join(out)


def make_handler(dialect: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"status": "ok"})
            if dialect == "oai" and self.path == "/v1/models":
                return self._send(200, {"data": [{"id": MODEL}]})
            if dialect == "gen" and self.path == "/v1/model":
                return self._send(200, {"model": MODEL})
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n).decode())
            if dialect == "oai" and self.path == "/v1/chat/completions":
                prompt = "\n".join(f"{m['role']}: {m['content']}"
                                   for m in req.get("messages", [])) \
                         + "\nassistant:"
                text = _decode(prompt, req.get("temperature", 0.0),
                               req.get("top_p", 1.0), 0,
                               req.get("max_tokens", 8))
                return self._send(200, {"choices": [
                    {"message": {"role": "assistant", "content": text}}]})
            if dialect == "gen" and self.path == "/v1/generate":
                prompt = req.get("prompt", "")
                words = prompt.split()
                if req.get("logprobs"):            # forced-continuation score
                    start = req.get("logprob_start", len(words))
                    kk = req["logprobs"]
                    top = []
                    for pos in range(start, len(words)):
                        d = _dist(" ".join(words[:pos]))
                        ordered = sorted(d.items(),
                                         key=lambda kv: (-kv[1], kv[0]))[:kk]
                        top.append([[math.log(p), t] for t, p in ordered])
                    return self._send(200, {"content": "",
                                            "top_logprobs": top})
                text = _decode(prompt, req.get("temperature", 0.0),
                               req.get("top_p", 1.0), req.get("top_k", 0),
                               req.get("n_predict", 8))
                return self._send(200, {"content": text})
            return self._send(404, {"error": "not found"})

        def log_message(self, fmt, *args):
            pass

    return Handler


def main(port: int = 31000, dialect: str = "oai"):
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(dialect))
    print(f"[mock-dwarfstar:{dialect}] http://127.0.0.1:{port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 31000,
         sys.argv[2] if len(sys.argv) > 2 else "oai")
