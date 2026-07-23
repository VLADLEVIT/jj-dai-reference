# -*- coding: utf-8 -*-
"""
core.crossverify — the peer cross-verification loop (closes iteration I1).

WHAT IT DOES: a generator node produces an output; a PEER verifier node scores
it (teacher-forcing reachability, /v1/score); the peer's verdict — once
independently re-audited — is fed into the §9.9 ChampionRegistry. This is the
loop that turns *certified* nodes into *reputation-earning* nodes.

THE TRUST RULE (why this is not a thin RPC wrapper): a verdict is a CLAIM.
JJ DAI never takes a claim on faith — "truth is discovered, not decreed." So
the loop does NOT trust the peer's JSON reply. It:

  1. asks the peer to /v1/score the (messages, tokens) under committed sampling;
  2. FETCHES the peer's witness chain and re-verifies, OFFLINE with the peer's
     published Ed25519 key, that the verifier record the peer claims to have
     written actually exists, is signed, and its semantic_digest matches the
     verdict it returned (chain_verifier); only then
  3. records the verdict into the registry — attributed to the GENERATOR's
     object (topic champion), with margin = the verifier's min_margin.

  A peer that returns "ok" but did not (or wrote a different record) fails the
  re-audit and its verdict is DISCARDED — never reaching the registry. A peer
  that lies about reachability is caught the same way the smoke suite catches
  a forged token: the verifier record is signed, so its content is nailed down.

ANTI-SELF-DEALING: a node cannot verify its own generation into reputation —
`peer_verifier_url` must differ from the generator, and the recorded verdict
carries both ids so the witness shows who attested whom (independence is
auditable). Optional `min_verifiers` requires N independent peers to agree
before the registry is credited (default 1 for the pilot).

This module is transport-light: it takes an injectable `http_post`/`http_get`
(the tests pass in-process fakes; production passes urllib). It touches the
registry through the same `record()` the router uses — one code path.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import H_hex, verify as ed_verify         # noqa: E402

GENESIS = "0" * 64


class CrossVerifyError(RuntimeError):
    pass


def _rechain_and_find(export: dict, receipt_index: int) -> dict:
    """Re-verify the peer's chain offline (JCS re-hash + Ed25519 on every
    record) and return the record at `receipt_index`. Raises if the chain
    is broken or the index is absent — a peer cannot fabricate a receipt for
    a record it never signed."""
    pub = bytes.fromhex(export["pubkey"])
    prev = GENESIS
    found = None
    for i, rec in enumerate(export["records"]):
        if rec["index"] != i or rec["prev_hash"] != prev:
            raise CrossVerifyError(f"peer chain broken at index {i}")
        body = {k: v for k, v in rec.items() if k not in ("this_hash", "sig")}
        if rec["this_hash"] != H_hex(canonical(body)):
            raise CrossVerifyError(f"peer record {i} hash mismatch")
        if not ed_verify(pub, rec["this_hash"].encode(),
                         bytes.fromhex(rec["sig"])):
            raise CrossVerifyError(f"peer record {i} bad signature")
        if i == receipt_index:
            found = rec
        prev = rec["this_hash"]
    if prev != export["head"] and export["records"]:
        raise CrossVerifyError("peer head mismatch")
    if found is None:
        raise CrossVerifyError(f"receipt index {receipt_index} not on peer chain")
    return found


class CrossVerifier:
    """Orchestrates generator → peer verifier → registry, with re-audit."""

    def __init__(self, registry, *, http_post, http_get,
                 min_verifiers: int = 1, open_verdict=None, nonces=None):
        self._reg = registry
        self._post = http_post          # (url, obj) -> (status, json)
        self._get = http_get            # (url) -> (status, json)
        self._min = min_verifiers
        # FULL VERDICT BINDING hooks (v0.3.1.2): if provided, every peer
        # verdict is opened/verified as a sealed envelope before it counts.
        self._open = open_verdict
        if nonces is None and open_verdict is not None:
            from core.verdict import NonceRegistry
            nonces = NonceRegistry()
        self._nonces = nonces

    def verify_and_record(self, *, topic: str, generator_id: str,
                          generator_url: str, verifier_urls: list,
                          jii_request: dict, output_tokens: list,
                          scope: str = "global") -> dict:
        """Have each peer in `verifier_urls` score the output, re-audit each
        peer's signed verdict, and (on agreement of >= min_verifiers) record
        the verdict for the generator's champion. Returns a full trace."""
        peers = [u for u in verifier_urls if u != generator_url]
        if not peers:
            raise CrossVerifyError(
                "no independent verifier (a node cannot verify its own work "
                "into reputation)")

        audited = []
        for url in peers:
            score_req = dict(jii_request)
            score_req["tokens"] = list(output_tokens)
            status, reply = self._post(url + "/v1/score", score_req)
            if status != 200 or "verdict" not in reply:
                audited.append({"verifier": url, "ok": None,
                                "discarded": f"score status {status}"})
                continue
            verdict = reply["verdict"]
            receipt = reply.get("witness_receipt") or {}
            # FULL VERDICT BINDING (v0.3.1.2): open the sealed envelope FIRST —
            # pin the verifier identity, verify the signature over ok/margin,
            # check context binding to THIS request, and reject replays. Only a
            # verdict that survives this is even considered.
            if self._open is not None:
                try:
                    _, caps = self._get(url + "/capabilities")
                    vpub = (caps.get("witness") or {}).get("pubkey")
                    verdict = self._open(verdict, request=score_req,
                                         verifier_pubkey_hex=vpub,
                                         nonces=self._nonces)
                except Exception as e:
                    audited.append({"verifier": url, "ok": None,
                                    "discarded": f"verdict binding failed: {e}"})
                    continue
            # RE-AUDIT: fetch the peer chain and prove the verifier record
            # exists, is signed, and binds the reachability it reported.
            try:
                _, export = self._get(url + "/witness/chain")
                rec = _rechain_and_find(export, receipt.get("index", -1))
                expected_digest = self._digest(verdict["reachable"])
                if rec.get("semantic_digest") != expected_digest:
                    raise CrossVerifyError(
                        "verifier record does not bind the returned verdict")
            except CrossVerifyError as e:
                audited.append({"verifier": url, "ok": None,
                                "discarded": f"re-audit failed: {e}"})
                continue
            audited.append({"verifier": url, "ok": bool(verdict["ok"]),
                            "min_margin": verdict.get("min_margin", 0.0),
                            "verifier_node": export["node_id"]})

        # independence: distinct, successfully re-audited peers
        good = [a for a in audited if a["ok"] is not None]
        agree_pass = [a for a in good if a["ok"] is True]
        recorded = None
        if len(good) >= self._min:
            # consensus verdict: pass only if a quorum of re-audited peers pass
            passed = len(agree_pass) >= self._min
            margin = (min(a["min_margin"] for a in agree_pass)
                      if agree_pass else 0.0)
            recorded = self._reg.record(
                topic, generator_id, passed, margin=margin, scope=scope)
        return {"topic": topic, "generator": generator_id,
                "verifiers_tried": len(peers), "audited": audited,
                "quorum": self._min, "recorded": recorded is not None,
                "registry_receipt": recorded}

    @staticmethod
    def _digest(reachable) -> str:
        """Mirror of daemon.handle_score's semantic_digest for the verifier
        record: semantic_digest(json.dumps(verdict['reachable']))."""
        buckets = [0] * 8
        for ch in json.dumps(reachable):
            buckets[ord(ch) % 8] += 1
        return ",".join(str(b) for b in buckets)
