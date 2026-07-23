# -*- coding: utf-8 -*-
"""
core.challenge — the adversarial verification round (v0.5.4)
============================================================
The audit's v0.6.1: verification must survive adversarial verifiers.
This module gives verdicts four properties they did not have before:

  UNBIASABLE SEATS  Panel seats are won by VRF sortition (RFC 9381
    ECVRF, jjdai.crypto): beta = VRF(sk_verifier, alpha) where alpha is
    bound to the TRANSCRIPT being judged and the round id. Nobody — not
    the challenger, not the verifier, not a colluding majority — can
    grind a different seat assignment: the VRF's full uniqueness means
    each key has exactly one beta per alpha, and the threshold rule is
    public arithmetic over it. A forged seat claim fails vrf_verify.

  BLIND VERDICTS  Verdicts are COMMITTED (hash + salt, witnessed)
    before any verdict is REVEALED. A verifier cannot wait to see the
    majority and side with it: by the time reveals open, every opinion
    is already sealed on the chain.

  NAMED SILENCE  Deadlines are part of the protocol. A seat that never
    commits, or commits and never reveals, resolves as ABSTAINED — a
    witnessed, reputation-relevant fact, not a quiet nothing.

  FRAUD THAT CONVICTS ITSELF  A reveal that does not match its own
    commitment is packaged as a durable, self-contained FRAUD PROOF:
    the witnessed commitment record, the mismatching reveal, both
    verifiable offline by anyone with the chain. Fraud slashes via the
    registry and excludes the verdict.

Scope, stated honestly: this is the in-process reference protocol over
the one witness chain — the same seam discipline as the rest of the
kernel. Verifiers here are keyholders driven by the caller; the network
transport (peers claiming seats over mTLS) rides on IFF + crossverify
and lands with the security-alpha. The protocol object, the evidence
formats and the sortition math are what this module fixes.
"""
from __future__ import annotations

import time

from jjdai.canonical import canonical
from jjdai.crypto import H_hex, vrf_verify
from jjdai.durable import durable_append

CHALLENGE_KIND = "CHALLENGE"
SORTITION_DOMAIN = b"jjdai:challenge:sortition:v1:"


class ChallengeError(RuntimeError):
    pass


def sortition_alpha(round_id: str, transcript_hash: str) -> bytes:
    """The VRF input for one round: domain-separated and TRANSCRIPT-BOUND,
    so a verifier's selection cannot be reused across rounds or targets."""
    return SORTITION_DOMAIN + canonical({"round_id": round_id,
                                         "transcript_hash": transcript_hash})


def is_selected(beta: bytes, k: int, n: int) -> bool:
    """Public threshold rule: a seat is won iff the first 8 bytes of beta,
    read big-endian, fall under k/n of the 64-bit space. In expectation k
    of n eligible verifiers win; the actual set is nobody's choice."""
    if not (0 < k <= n):
        raise ChallengeError(f"threshold needs 0 < k <= n, got k={k} n={n}")
    return int.from_bytes(beta[:8], "big") < (k * (1 << 64)) // n


class ChallengeRound:
    """One adversarial verification round on the ONE witness chain."""

    def __init__(self, chain, *, registry=None, fraud_log_path: str = None,
                 commit_window: float = 30.0, reveal_window: float = 30.0,
                 now_fn=time.time):
        self.chain = chain
        self.registry = registry
        self.fraud_log_path = fraud_log_path
        self.commit_window = float(commit_window)
        self.reveal_window = float(reveal_window)
        self._now = now_fn
        self.rounds: dict = {}

    # ------------------------------------------------------------------ #
    def _witness(self, digest: dict, request: dict = None) -> int:
        with self.chain.lock:
            self.chain.append(CHALLENGE_KIND, request=request or {},
                              semantic_digest=digest)
            return len(self.chain.records) - 1

    # ------------------------------------------------------------------ #
    def open(self, round_id: str, transcript_hash: str,
             eligible: dict, k: int) -> dict:
        """eligible: {verifier_id: vrf_pubkey_hex}. Witnesses the round
        parameters BEFORE any seat is claimed: alpha is fixed publicly, so
        selection cannot be quietly re-parameterized after the fact."""
        if round_id in self.rounds:
            raise ChallengeError(f"round {round_id!r} already open")
        if not eligible:
            raise ChallengeError("no eligible verifiers")
        if not (0 < k <= len(eligible)):
            raise ChallengeError("need 0 < k <= len(eligible)")
        t = self._now()
        rnd = {
            "round_id": round_id,
            "transcript_hash": transcript_hash,
            "alpha": sortition_alpha(round_id, transcript_hash).hex(),
            "eligible": dict(eligible),
            "k": k,
            "opened_at": t,
            "commit_deadline": t + self.commit_window,
            "reveal_deadline": t + self.commit_window + self.reveal_window,
            "seats": {},        # verifier -> {"beta":, "proof":}
            "commits": {},      # verifier -> {"commitment":, "index":}
            "reveals": {},      # verifier -> {"verdict":, "salt":}
            "frauds": [],
            "resolved": None,
        }
        self.rounds[round_id] = rnd
        self._witness({"phase": "open", "round_id": round_id,
                       "transcript_hash": transcript_hash,
                       "alpha_hash": H_hex(bytes.fromhex(rnd["alpha"])),
                       "eligible": sorted(eligible), "k": k,
                       "commit_deadline": rnd["commit_deadline"],
                       "reveal_deadline": rnd["reveal_deadline"]})
        return rnd

    # ------------------------------------------------------------------ #
    def claim_seat(self, round_id: str, verifier_id: str,
                   vrf_proof_hex: str) -> bool:
        """A verifier proves selection: vrf_verify against the ROUND alpha
        and the verifier's REGISTERED key. Forged proofs and unregistered
        keys fail closed; losing betas are refused (and witnessed, so a
        verifier cannot shop for a round where its loss goes unrecorded)."""
        rnd = self._round(round_id)
        if verifier_id not in rnd["eligible"]:
            raise ChallengeError(f"{verifier_id!r} is not eligible")
        if verifier_id in rnd["seats"]:
            return True
        alpha = bytes.fromhex(rnd["alpha"])
        try:
            beta = vrf_verify(bytes.fromhex(rnd["eligible"][verifier_id]),
                              alpha, bytes.fromhex(vrf_proof_hex))
        except ValueError as e:
            self._witness({"phase": "seat_refused", "round_id": round_id,
                           "verifier": verifier_id,
                           "reason": f"vrf: {e}"})
            raise ChallengeError(f"seat claim refused: {e}")
        won = is_selected(beta, rnd["k"], len(rnd["eligible"]))
        self._witness({"phase": "seat", "round_id": round_id,
                       "verifier": verifier_id, "won": won,
                       "beta_hash": H_hex(beta)})
        if won:
            rnd["seats"][verifier_id] = {"beta": beta.hex(),
                                         "proof": vrf_proof_hex}
        return won

    # ------------------------------------------------------------------ #
    def commit(self, round_id: str, verifier_id: str,
               commitment_hex: str) -> int:
        """Seal a verdict before anyone shows theirs. One commitment per
        seat — a second one is refused AND witnessed (attempted verdict
        replacement is itself evidence)."""
        rnd = self._round(round_id)
        if verifier_id not in rnd["seats"]:
            raise ChallengeError(f"{verifier_id!r} holds no seat")
        if self._now() > rnd["commit_deadline"]:
            raise ChallengeError("commit window closed")
        if verifier_id in rnd["commits"]:
            self._witness({"phase": "double_commit_refused",
                           "round_id": round_id, "verifier": verifier_id})
            raise ChallengeError("verdict already committed — "
                                 "commitments are not replaceable")
        idx = self._witness({"phase": "commit", "round_id": round_id,
                             "verifier": verifier_id,
                             "commitment": commitment_hex})
        rnd["commits"][verifier_id] = {"commitment": commitment_hex,
                                       "index": idx}
        return idx

    @staticmethod
    def make_commitment(round_id: str, verifier_id: str, verdict: dict,
                        salt_hex: str) -> str:
        return H_hex(canonical({"round_id": round_id,
                                "verifier": verifier_id,
                                "verdict": verdict, "salt": salt_hex}))

    # ------------------------------------------------------------------ #
    def reveal(self, round_id: str, verifier_id: str, verdict: dict,
               salt_hex: str) -> dict:
        """Open the sealed verdict. A reveal that does not hash to its own
        commitment becomes a durable fraud proof — verifiable offline from
        the chain alone — and slashes via the registry."""
        rnd = self._round(round_id)
        com = rnd["commits"].get(verifier_id)
        if com is None:
            raise ChallengeError(f"{verifier_id!r} committed nothing")
        now = self._now()
        if now > rnd["reveal_deadline"]:
            self._witness({"phase": "late_reveal_refused",
                           "round_id": round_id, "verifier": verifier_id})
            raise ChallengeError("reveal window closed — seat resolves as "
                                 "ABSTAINED")
        expect = self.make_commitment(round_id, verifier_id, verdict,
                                      salt_hex)
        if expect != com["commitment"]:
            fraud = {
                "kind": "CHALLENGE_FRAUD",
                "type": "commit-reveal-mismatch",
                "round_id": round_id,
                "verifier": verifier_id,
                "commit_witness_index": com["index"],
                "committed": com["commitment"],
                "revealed_verdict": verdict,
                "revealed_salt": salt_hex,
                "recomputed": expect,
                "t": now,
            }
            rnd["frauds"].append(fraud)
            if self.fraud_log_path:
                durable_append(self.fraud_log_path, fraud)
            self._witness({"phase": "fraud", **{k: v for k, v in
                           fraud.items() if k != "kind"}})
            if self.registry is not None and \
                    hasattr(self.registry, "slash"):
                self.registry.slash(verifier_id,
                                    reason="challenge commit-reveal fraud")
            raise ChallengeError("reveal does not match the sealed "
                                 "commitment — fraud proof recorded")
        rnd["reveals"][verifier_id] = {"verdict": verdict, "salt": salt_hex}
        self._witness({"phase": "reveal", "round_id": round_id,
                       "verifier": verifier_id, "verdict": verdict})
        return verdict

    # ------------------------------------------------------------------ #
    def resolve(self, round_id: str) -> dict:
        """After the reveal deadline: tally honestly. Majority of VALID
        reveals decides; frauds are excluded; silence is ABSTAINED; zero
        valid reveals resolve as UNRESOLVED — never an invented verdict."""
        rnd = self._round(round_id)
        if rnd["resolved"] is not None:
            return rnd["resolved"]
        if self._now() < rnd["reveal_deadline"]:
            raise ChallengeError("reveal window still open")
        fraudsters = {f["verifier"] for f in rnd["frauds"]}
        valid = {v: r["verdict"] for v, r in rnd["reveals"].items()
                 if v not in fraudsters}
        abstained = sorted(set(rnd["seats"]) - set(valid) - fraudsters)
        votes: dict = {}
        for v, verdict in valid.items():
            key = H_hex(canonical(verdict))
            votes.setdefault(key, {"verdict": verdict, "voters": []})
            votes[key]["voters"].append(v)
        if votes:
            best = max(votes.values(), key=lambda x: (len(x["voters"]),
                                                      sorted(x["voters"])))
            outcome = {"status": "resolved", "verdict": best["verdict"],
                       "supporters": sorted(best["voters"]),
                       "unanimous": len(votes) == 1}
        else:
            outcome = {"status": "unresolved",
                       "reason": "no valid reveals — the round refuses to "
                                 "invent a verdict"}
        summary = {
            **outcome,
            "round_id": round_id,
            "seats": sorted(rnd["seats"]),
            "revealed": sorted(valid),
            "abstained": abstained,
            "frauds": [{"verifier": f["verifier"], "type": f["type"]}
                       for f in rnd["frauds"]],
        }
        rnd["resolved"] = summary
        self._witness({"phase": "resolve", **summary})
        if self.registry is not None and hasattr(self.registry, "abstain"):
            for v in abstained:
                self.registry.abstain(v)
        return summary

    # ------------------------------------------------------------------ #
    def _round(self, round_id: str) -> dict:
        rnd = self.rounds.get(round_id)
        if rnd is None:
            raise ChallengeError(f"unknown round {round_id!r}")
        return rnd


def verify_fraud_proof(fraud: dict, chain_records: list) -> tuple:
    """OFFLINE fraud verification: anyone holding the chain can convict.
    Checks (1) the witnessed commitment record exists at the named index
    with the named commitment in its digest, and (2) the revealed verdict
    + salt genuinely hash to a DIFFERENT value. No trust in the accuser."""
    if fraud.get("type") != "commit-reveal-mismatch":
        return False, f"unknown fraud type {fraud.get('type')!r}"
    idx = fraud.get("commit_witness_index")
    if not isinstance(idx, int) or not (0 <= idx < len(chain_records)):
        return False, "commit witness index out of range"
    rec = chain_records[idx]
    dg = rec.get("semantic_digest") or {}
    if rec.get("kind") != CHALLENGE_KIND or dg.get("phase") != "commit" \
            or dg.get("round_id") != fraud["round_id"] \
            or dg.get("verifier") != fraud["verifier"] \
            or dg.get("commitment") != fraud["committed"]:
        return False, "witnessed commitment does not match the accusation"
    recomputed = ChallengeRound.make_commitment(
        fraud["round_id"], fraud["verifier"],
        fraud["revealed_verdict"], fraud["revealed_salt"])
    if recomputed == fraud["committed"]:
        return False, "reveal actually matches the commitment — no fraud"
    return True, "fraud confirmed: sealed one verdict, revealed another"
