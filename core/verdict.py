# -*- coding: utf-8 -*-
"""
core.verdict — Full Verdict Binding (v0.3.1.2 #2).

THE PROBLEM: a verdict from /v1/score was a bare dict {ok, reachable,
min_margin, ...}. The cross-verify loop re-audited that the verifier WROTE a
record, but the verdict itself was not a signed, self-contained commitment. A
verdict could be lifted and replayed against a different request; `ok` and
`min_margin` were the verifier's word, bound to nothing.

THE FIX: a verdict becomes a SEALED ENVELOPE that binds the verifier's
identity, the exact scoring context, and a one-time nonce, under the
verifier's Ed25519 signature:

  context_hash = H(canonical({
      substrate_id, adapter_ids, messages, sampling, tokens, request_id, nonce
  }))                                   # the WHOLE thing that was scored

  sealed = {ok, reachable, min_margin, verifier_fp, determinism,
            verifier_node_id, context_hash, nonce,
            sig = Ed25519(verifier_key, canonical(body_without_sig))}

Guarantees this buys:
  * PEER IDENTITY PINNING — verifier_node_id must equal HASH(pubkey); the
    signature must verify under that key. A verdict cannot be attributed to a
    verifier who did not sign it.
  * CONTEXT BINDING — the verdict is welded to the exact (request, tokens)
    it judged; lift it onto any other request and context_hash mismatches.
  * REPLAY / NONCE PROTECTION — a NonceRegistry rejects a (verifier, nonce)
    seen before; the same sealed verdict cannot be counted twice.
  * FORGED ok / min_margin REJECTION — because ok and min_margin are inside
    the signed body, flipping either invalidates the signature. (The
    cross-verify re-audit still independently recomputes reachability from the
    signed chain record; binding makes tampering detectable even before that.)
  * UNIQUE-NodeID QUORUM — count_quorum() counts DISTINCT verifier_node_ids
    only, so one verifier answering N times (or a sybil reusing a key) cannot
    manufacture consensus.

This module SEALS (verifier side) and OPENS/VERIFIES (consumer side). It does
not trust; it checks.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import (canonical_node_id, canonical_being_id, H_hex, node_id as _hash_pub,      # noqa: E402
                          verify as ed_verify)
from jjdai.schema import VerdictEnvelope, ValidationError    # noqa: E402

SIGNED_FIELDS = ("ok", "reachable", "min_margin", "verifier_fp",
                 "determinism", "verifier_node_id", "context_hash", "nonce")


class VerdictError(RuntimeError):
    pass


def scoring_context_hash(request: dict) -> str:
    """Canonical hash over the WHOLE scored context. Anything that could
    change the verdict is inside it; nothing that couldn't is."""
    ctx = {
        "substrate_id": request.get("substrate_id"),
        "adapter_ids": request.get("adapter_ids", []),
        "messages": request.get("messages", []),
        "sampling": request.get("sampling", {}),
        "tokens": request.get("tokens", []),
        "request_id": request.get("request_id"),
        "nonce": request.get("nonce"),
    }
    return H_hex(canonical(ctx))


def seal_verdict(raw_verdict: dict, *, request: dict, verifier_sk,
                 verifier_node_id: str = None) -> dict:
    """Verifier side: wrap a raw score result into a signed, context-bound,
    schema-valid VerdictEnvelope. The canonical verifier_node_id is derived
    from the verifier key itself via crypto.canonical_node_id() — the single
    identity derivation shared by NodeIdentity, WitnessChain and the network
    layer — so it always matches open()'s identity-pinning check."""
    verifier_nid = canonical_node_id(verifier_sk.public)
    body = {
        "ok": bool(raw_verdict["ok"]),
        "reachable": list(raw_verdict.get("reachable", [])),
        "min_margin": float(raw_verdict.get("min_margin", 0.0)),
        "verifier_fp": str(raw_verdict.get("verifier_fp", "")),
        "determinism": raw_verdict.get("determinism", "attested"),
        "verifier_node_id": verifier_nid,
        "context_hash": scoring_context_hash(request),
        "nonce": request["nonce"],
    }
    if raw_verdict.get("note"):
        body["note"] = raw_verdict["note"][:512]
    body["sig"] = verifier_sk.sign(canonical(
        {k: body[k] for k in SIGNED_FIELDS})).hex()
    return VerdictEnvelope.validate(body, "VerdictEnvelope")


def open_verdict(envelope: dict, *, request: dict, verifier_pubkey_hex: str,
                 nonces: "NonceRegistry" = None) -> dict:
    """Consumer side: validate schema, pin identity, verify signature, check
    context binding and replay. Returns the trusted envelope or raises."""
    try:
        env = VerdictEnvelope.validate(envelope, "VerdictEnvelope")
    except ValidationError as e:
        raise VerdictError(f"malformed verdict: {e}") from e

    for f in ("verifier_node_id", "context_hash", "nonce", "sig"):
        if not env.get(f):
            raise VerdictError(f"unbound verdict: missing {f} "
                               "(v0.3.1.2 requires full binding)")

    # identity pinning: node_id must be the hash of the presented pubkey
    pub = bytes.fromhex(verifier_pubkey_hex)
    if env["verifier_node_id"] != canonical_node_id(pub):
        raise VerdictError("verifier_node_id does not match presented pubkey")

    # signature over the signed body (ok/min_margin/etc. are INSIDE it)
    if not ed_verify(pub, canonical({k: env[k] for k in SIGNED_FIELDS}),
                     bytes.fromhex(env["sig"])):
        raise VerdictError("bad verifier signature (forged ok/min_margin or "
                           "wrong key)")

    # context binding: welded to the exact request+tokens scored
    if env["context_hash"] != scoring_context_hash(request):
        raise VerdictError("context_hash mismatch — verdict lifted onto a "
                           "different request")
    if env["nonce"] != request.get("nonce"):
        raise VerdictError("nonce mismatch between verdict and request")

    # replay protection
    if nonces is not None:
        nonces.use(env["verifier_node_id"], env["nonce"])   # raises on reuse
    return env


class NonceRegistry:
    """One-time (verifier_node_id, nonce) ledger. Rejects replays."""

    def __init__(self):
        self._seen: set = set()

    def use(self, verifier_node_id: str, nonce: str):
        key = (verifier_node_id, nonce)
        if key in self._seen:
            raise VerdictError(f"replay: verdict nonce {nonce!r} from "
                               f"{verifier_node_id} already counted")
        self._seen.add(key)

    def seen(self, verifier_node_id: str, nonce: str) -> bool:
        return (verifier_node_id, nonce) in self._seen


def count_quorum(envelopes: list) -> dict:
    """Consensus over sealed, already-opened verdicts, counting DISTINCT
    verifier_node_ids only (unique-NodeID quorum — one verifier answering many
    times cannot fake agreement). Returns pass/fail tallies and the min margin
    among passing verifiers."""
    by_node = {}
    for env in envelopes:
        by_node[env["verifier_node_id"]] = env      # last wins per node
    passes = [e for e in by_node.values() if e["ok"]]
    fails = [e for e in by_node.values() if not e["ok"]]
    margin = min((e["min_margin"] for e in passes), default=0.0)
    return {"distinct_verifiers": len(by_node),
            "pass": len(passes), "fail": len(fails),
            "min_margin": margin,
            "passed": len(passes) > 0 and len(fails) == 0}
