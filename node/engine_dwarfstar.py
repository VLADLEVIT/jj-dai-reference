#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — DwarfStar Engine Adapter (Tier-1, v0.1)
================================================
Binds the node daemon's engine seam onto a local DwarfStar (ds4) server —
the Tier-1 substrate (RTX 6000 / Apple Silicon class, whitepaper §13 step 1).

NECS placement (spec section "DwarfStar → Profile B / B-spec"): DwarfStar
serves a FROZEN base (or an offline-merged baked substrate, B-spec). It has
no hot LoRA slot — so this adapter is PROFILE B BY CONSTRUCTION: it refuses
adapter_ids outright. Specialization on a DwarfStar node lives in context
space (system prompts, Smriti/RAG) and, later, activation space (steering
vectors) — never weight space at request time.

Trust boundary — same rule as SGLang: DwarfStar is wrapped, never trusted.
The JII envelope, Ed25519 witness chain, and fail-closed logic all stay in
the daemon. This adapter only translates the NECS verb:

    generate(messages, sampling, adapter_ids=())  -> text     (generator role)

Verifier role: DwarfStar is the ATTESTED FAST GENERATOR in the locked
generator/verifier asymmetry (decision #5). Per-token teacher-forcing needs
top-k logprobs on a forced continuation; if the deployed ds4 build exposes
them, set `supports_logprobs=True` and `score()` activates (same nucleus-
reachability logic as the SGLang adapter). Otherwise score() raises and the
daemon fails closed on /v1/score — verification is then done by a PEER
verifier node (CPU reproducible), which is the intended §9 topology anyway.

Wire contract — pinned to mock_dwarfstar.py (the executable contract):
this adapter auto-probes TWO dialects, because ds4 builds differ:

  dialect "oai"  : POST /v1/chat/completions
                   {model, messages, temperature, top_p, max_tokens}
                   -> {choices:[{message:{content}}]}
                   identity: GET /v1/models -> {data:[{id}]}
  dialect "gen"  : POST /v1/generate
                   {prompt, temperature, top_p, top_k, n_predict}
                   -> {content | text}
                   identity: GET /v1/model -> {model|id}
  health         : GET /health (fallback: the identity endpoint itself)

!!! RE-PIN BEFORE PRODUCTION: validate field names against the deployed
ds4 build (github.com/VLADLEVIT/jjdai-logic1-ds4) and capture any divergence
in mock_dwarfstar.py first — the mock is where contract drift must surface,
not production.

FINGERPRINT SEAM: pass the model file's content hash (e.g. sha256 of the
ds4-flash weights file) as `fingerprint`, so provenance names the actual
frozen substrate, not a label.
"""
from __future__ import annotations

import json
import math
import urllib.error
import urllib.request


class DwarfStarError(RuntimeError):
    """Server unreachable / malformed reply / unsupported role — the daemon
    maps this to 503 (fail-closed: no engine, no inference)."""


class DwarfStarEngine:
    """NECS engine seam bound to a DwarfStar /v1 server. Profile B strict."""

    profile = "B"
    backend = "dwarfstar"

    def __init__(self, base_url: str, *, fingerprint: str,
                 model: str = "ds4-flash", timeout: float = 60.0,
                 determinism_level: str = "attested",
                 dialect: str = "auto", supports_logprobs: bool = False):
        self.base_url = base_url.rstrip("/")
        self.fingerprint = fingerprint
        self.model = model
        self.timeout = timeout
        self.determinism_level = determinism_level
        self.supports_logprobs = supports_logprobs
        self._dialect = None if dialect == "auto" else dialect

    # ------------------------------------------------------------------ #
    # HTTP plumbing (stdlib only)
    # ------------------------------------------------------------------ #
    def _post(self, path: str, obj: dict) -> dict:
        data = json.dumps(obj).encode()
        req = urllib.request.Request(self.base_url + path, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            raise DwarfStarError(f"dwarfstar {path}: {e}") from e

    def _get(self, path: str) -> dict:
        try:
            with urllib.request.urlopen(self.base_url + path,
                                        timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            raise DwarfStarError(f"dwarfstar {path}: {e}") from e

    # ------------------------------------------------------------------ #
    # Dialect probe / health / identity
    # ------------------------------------------------------------------ #
    def dialect(self) -> str:
        if self._dialect:
            return self._dialect
        try:
            self._get("/v1/models")
            self._dialect = "oai"
        except DwarfStarError:
            self._get("/v1/model")          # raises if neither -> engine down
            self._dialect = "gen"
        return self._dialect

    def healthy(self) -> bool:
        try:
            self._get("/health")
            return True
        except DwarfStarError:
            try:
                self.dialect()
                return True
            except DwarfStarError:
                return False

    def probe(self) -> dict:
        """Model identity as the server reports it (surfaces into
        capabilities and, in production, cross-checked against the
        content-addressed substrate manifest — NECS C2)."""
        if self.dialect() == "oai":
            data = self._get("/v1/models").get("data", [])
            return {"model_path": data[0]["id"] if data else "unknown",
                    "dialect": "oai"}
        info = self._get("/v1/model")
        return {"model_path": info.get("model", info.get("id", "unknown")),
                "dialect": "gen"}

    # ------------------------------------------------------------------ #
    # NECS verb: generate
    # ------------------------------------------------------------------ #
    @staticmethod
    def _prompt(messages: list) -> str:
        # Reference template for the "gen" dialect. PRODUCTION: use the
        # model's own chat template.
        return "\n".join(f"{m['role']}: {m['content']}" for m in messages) \
               + "\nassistant:"

    def generate(self, messages: list, sampling: dict,
                 adapter_ids: list = ()) -> str:
        if adapter_ids:
            # Profile B by construction — never silently ignore an adapter
            # request (that would be a silent capability downgrade).
            raise DwarfStarError(
                "DwarfStar node is Profile B: hot adapters are not served "
                f"(got {list(adapter_ids)!r}). Route Profile A traffic to a "
                "Tier-2 node, or bake the adapter offline (B-spec).")
        if self.dialect() == "oai":
            resp = self._post("/v1/chat/completions", {
                "model": self.model,
                "messages": messages,
                "temperature": sampling.get("temperature", 0.0),
                "top_p": sampling.get("top_p", 1.0),
                "max_tokens": sampling.get("max_tokens", 256),
            })
            try:
                return resp["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError) as e:
                raise DwarfStarError(
                    f"malformed /v1/chat/completions reply: {list(resp)}") from e
        resp = self._post("/v1/generate", {
            "prompt": self._prompt(messages),
            "temperature": sampling.get("temperature", 0.0),
            "top_p": sampling.get("top_p", 1.0),
            "top_k": sampling.get("top_k", 0),
            "n_predict": sampling.get("max_tokens", 256),
        })
        text = resp.get("content", resp.get("text"))
        if text is None:
            raise DwarfStarError(f"malformed /v1/generate reply: {list(resp)}")
        return text

    # ------------------------------------------------------------------ #
    # NECS verb: score (only if the ds4 build exposes forced logprobs)
    # ------------------------------------------------------------------ #
    def score(self, messages: list, tokens: list, sampling: dict,
              adapter_ids: list = ()) -> dict:
        if adapter_ids:
            raise DwarfStarError("Profile B: no adapters (see generate()).")
        if not self.supports_logprobs:
            raise DwarfStarError(
                "this DwarfStar build exposes no forced-continuation "
                "logprobs; verifier role unavailable — use a peer verifier "
                "node (/v1/score on a Tier-2 or CPU-reproducible node).")
        # Same reachability logic as the SGLang adapter, over the "gen"
        # dialect's logprob extension (mock contract: prompt + forced text,
        # n_predict=0, logprobs=k -> {top_logprobs: [[[lp, tok], ...], ...]}).
        prompt = self._prompt(messages)
        resp = self._post("/v1/generate", {
            "prompt": prompt + " " + " ".join(tokens),
            "n_predict": 0,
            "logprobs": 16,
            "logprob_start": len(prompt.split()),   # TOKENIZER SEAM
        })
        top = resp.get("top_logprobs")
        if top is None or len(top) < len(tokens):
            raise DwarfStarError("server returned no/short top_logprobs")
        temp = sampling.get("temperature", 0.0)
        top_p = sampling.get("top_p", 1.0)
        top_k = sampling.get("top_k", 0)
        reachable, min_margin = [], 1.0
        for pos, tok in enumerate(tokens):
            probs = {t: math.exp(lp) for lp, t in top[pos]}
            z = sum(probs.values()) or 1.0
            probs = {t: p / z for t, p in probs.items()}
            ordered = sorted(probs.items(), key=lambda kv: (-kv[1], kv[0]))
            if top_k and top_k > 0:
                ordered = ordered[:top_k]
            if temp <= 0.0:
                nucleus = ordered[:1]
            else:
                nucleus, acc = [], 0.0
                for t, p in ordered:
                    nucleus.append((t, p))
                    acc += p
                    if acc >= top_p:
                        break
            ok = tok in [t for t, _ in nucleus]
            reachable.append(ok)
            if ok:
                min_margin = min(min_margin,
                                 probs[tok] - nucleus[-1][1] + 1e-12)
        all_ok = all(reachable) and len(reachable) == len(tokens)
        return {"ok": all_ok, "reachable": reachable,
                "min_margin": round(min_margin if all_ok else 0.0, 6),
                "verifier_fp": self.fingerprint,
                "determinism": self.determinism_level,
                "note": "" if all_ok else
                        f"unreachable token at pos {reachable.index(False)}"}
