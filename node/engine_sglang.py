#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — SGLang Engine Adapter (Tier-2, v0.1)
=============================================
Binds the node daemon's engine seam onto a live SGLang server — the Tier-2
substrate (1×H200 / MI300X, Profile A: hot-swappable LoRA on one frozen base).

Trust boundary
--------------
SGLang is a THIRD-PARTY engine: it is never trusted, only wrapped. The JII
envelope, the Ed25519 witness chain, fail-closed semantics, and adapter
provenance checks (NECS C2) all live in the daemon, OUTSIDE this adapter.
The adapter only translates two NECS verbs onto SGLang's native HTTP API:

  generate(messages, sampling, adapter_ids)  -> text          (generator role)
  score(messages, tokens, sampling)          -> verdict        (verifier role)

Generator/verifier asymmetry (locked design decision #5): a GPU generator is
'attested' (kernels are not bit-deterministic); verification is TEACHER-
FORCING — replay the candidate tokens through the model and check each token
was REACHABLE under the committed sampling params (inside the top-p nucleus /
top-k cut), not bit-equal. That is what `score` implements, via SGLang's
`return_logprob` + `top_logprobs_num` on the forced continuation.

Data-parallel federation (§9): each Tier-2 node runs its OWN full SGLang
replica behind its OWN daemon+witness. Nodes cross-verify each other by
calling each other's /v1/score. No tensor sharding — sharded halves cannot
independently attest; replicas can.

API mapping (pinned to the SGLang native server API, sglang >= 0.4):
  GET  /health, /get_model_info
  POST /generate  {text, sampling_params{temperature,top_p,top_k,
                   max_new_tokens}, lora_path, return_logprob,
                   logprob_start_len, top_logprobs_num}
       -> {text, meta_info{input_top_logprobs, output_token_logprobs, ...}}
Validate the field mapping against your deployed SGLang version before
production — the mock server (mock_sglang.py) is the executable contract this
adapter is certified against.

PRODUCTION SEAMS (marked, not hidden):
  * TOKENIZER BOUNDARY — this reference adapter tokenizes at whitespace level
    so the verification MECHANICS are provable end-to-end today. The real
    binding must align with the model's tokenizer (send input_ids, or use the
    server's /tokenize) so `logprob_start_len` lands exactly on the prompt/
    completion boundary.
  * FINGERPRINT — engine_fingerprint should become a content hash of
    (model weights manifest + engine build + kernel config), not a label.
"""
from __future__ import annotations

import json
import math
import urllib.error
import urllib.request


class SGLangError(RuntimeError):
    """Raised when the SGLang server is unreachable or replies malformed —
    the daemon maps this to 503 (fail-closed: no engine, no inference)."""


class SGLangEngine:
    """NECS engine seam bound to an SGLang server.

    determinism_level:
      'attested'      — GPU generator (default; real Tier-2 hardware)
      'reproducible'  — only when the backing server is bit-deterministic
                        (e.g. the CI mock, or a CPU verifier build)
    """

    def __init__(self, base_url: str, *, fingerprint: str,
                 adapter_paths: dict = None, timeout: float = 60.0,
                 determinism_level: str = "attested",
                 backend: str = "gpu-sglang"):
        self.base_url = base_url.rstrip("/")
        self.fingerprint = fingerprint
        # adapter_id (content address) -> lora_path name loaded in SGLang.
        # The daemon has ALREADY enforced base_compat_tag (C2) before we
        # are called; this is only the id->path translation.
        self.adapter_paths = dict(adapter_paths or {})
        self.timeout = timeout
        self.determinism_level = determinism_level
        self.backend = backend

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
            raise SGLangError(f"sglang {path}: {e}") from e

    def _get(self, path: str) -> dict:
        try:
            with urllib.request.urlopen(self.base_url + path,
                                        timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            raise SGLangError(f"sglang {path}: {e}") from e

    # ------------------------------------------------------------------ #
    # Health / identity
    # ------------------------------------------------------------------ #
    def probe(self) -> dict:
        """Model identity of the backing server (surfaces into capabilities)."""
        info = self._get("/get_model_info")
        return {"model_path": info.get("model_path", "unknown"),
                "served_loras": info.get("lora_paths", list(self.adapter_paths.values()))}

    def healthy(self) -> bool:
        try:
            self._get("/health")
            return True
        except SGLangError:
            return False

    # ------------------------------------------------------------------ #
    # NECS verb: generate  (generator role)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _prompt(messages: list) -> str:
        # Reference chat template: role-tagged lines. PRODUCTION: use the
        # model's own chat template (server-side apply, or tokenizer config).
        return "\n".join(f"{m['role']}: {m['content']}" for m in messages) \
               + "\nassistant:"

    @staticmethod
    def _map_sampling(sampling: dict) -> dict:
        return {
            "temperature": sampling.get("temperature", 0.0),
            "top_p": sampling.get("top_p", 1.0),
            "top_k": sampling.get("top_k", 0) or -1,   # sglang: -1 = off
            "max_new_tokens": sampling.get("max_tokens", 256),
        }

    def generate(self, messages: list, sampling: dict,
                 adapter_ids: list = ()) -> str:
        body = {
            "text": self._prompt(messages),
            "sampling_params": self._map_sampling(sampling),
        }
        if adapter_ids:
            # Single-adapter dispatch in v0.1 (composition is a NECS open item)
            body["lora_path"] = self.adapter_paths.get(
                adapter_ids[0], adapter_ids[0])
        resp = self._post("/generate", body)
        if "text" not in resp:
            raise SGLangError(f"malformed /generate reply: {list(resp)}")
        return resp["text"]

    # ------------------------------------------------------------------ #
    # NECS verb: score  (verifier role — teacher-forcing reachability)
    # ------------------------------------------------------------------ #
    def score(self, messages: list, tokens: list, sampling: dict,
              adapter_ids: list = ()) -> dict:
        """Replay `tokens` through the model under the COMMITTED sampling
        params and check, position by position, that each token was inside
        the sampler's reachable set (top-p nucleus after the top-k cut).

        Returns a router-compatible verdict:
          {ok, reachable: [bool], min_margin, verifier_fp, determinism, note}
        min_margin = the smallest probability margin by which a token stayed
        inside the nucleus — low margins flag borderline claims for audit.
        """
        prompt = self._prompt(messages)
        forced = prompt + " " + " ".join(tokens)
        prompt_len = len(prompt.split())            # TOKENIZER SEAM (see header)
        body = {
            "text": forced,
            "sampling_params": {"max_new_tokens": 0},
            "return_logprob": True,
            "logprob_start_len": prompt_len,
            "top_logprobs_num": 16,
        }
        if adapter_ids:
            body["lora_path"] = self.adapter_paths.get(
                adapter_ids[0], adapter_ids[0])
        resp = self._post("/generate", body)
        top = (resp.get("meta_info") or {}).get("input_top_logprobs")
        if top is None or len(top) < len(tokens):
            raise SGLangError("server returned no/short input_top_logprobs")

        temp = sampling.get("temperature", 0.0)
        top_p = sampling.get("top_p", 1.0)
        top_k = sampling.get("top_k", 0)
        reachable, min_margin = [], 1.0

        for pos, tok in enumerate(tokens):
            cands = top[pos]                        # [[logprob, token], ...]
            probs = {t: math.exp(lp) for lp, t in cands}
            z = sum(probs.values()) or 1.0
            probs = {t: p / z for t, p in probs.items()}
            ordered = sorted(probs.items(), key=lambda kv: (-kv[1], kv[0]))
            if top_k and top_k > 0:
                ordered = ordered[:top_k]
            if temp <= 0.0:
                nucleus = ordered[:1]               # greedy: only argmax
            else:
                nucleus, acc = [], 0.0
                for t, p in ordered:
                    nucleus.append((t, p))
                    acc += p
                    if acc >= top_p:
                        break
            names = [t for t, _ in nucleus]
            ok = tok in names
            reachable.append(ok)
            if ok:
                floor = nucleus[-1][1]
                min_margin = min(min_margin, probs[tok] - floor + 1e-12)
        all_ok = all(reachable) and len(reachable) == len(tokens)
        return {
            "ok": all_ok,
            "reachable": reachable,
            "min_margin": round(min_margin if all_ok else 0.0, 6),
            "verifier_fp": self.fingerprint,
            "determinism": self.determinism_level,
            "note": "" if all_ok else
                    f"unreachable token at pos {reachable.index(False)}",
        }
