#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.5.4 unit acceptance — the adversarial challenge round
========================================================
  V-RFC  ECVRF-EDWARDS25519-SHA512-TAI reproduces ALL THREE RFC 9381
         B.3 vectors (pi AND beta, byte-for-byte); tampered proofs,
         wrong alpha, wrong key and small-order keys fail closed
  V-MS   naive m-of-n multisig: threshold met/unmet, duplicates never
         double-count, outsiders never count, bad sigs ignored
  C-SORT sortition is transcript-bound, deterministic, verifiable and
         unbiasable: same round -> same seats; different transcript ->
         (statistically) different seats; a proof from another round is
         refused; expected seat count tracks k/n
  C-RND  full round: seats -> blind commits -> reveals -> majority
         resolution, every phase witnessed on the ONE chain
  C-FRD  a mismatched reveal becomes a durable fraud proof that anyone
         can verify OFFLINE from the chain; the fraudster is slashed and
         excluded; tampered accusations are themselves refused
  C-ABS  silence resolves as ABSTAINED at the deadline; late reveals
         are refused; double commits are refused and witnessed; zero
         valid reveals resolve UNRESOLVED — never an invented verdict
"""
from __future__ import annotations

import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai.crypto import (SigningKey, vrf_prove, vrf_verify,          # noqa: E402
                          multisig_verify)
from jjdai.witness import WitnessChain                                # noqa: E402
from jjdai.durable import read_journal                                # noqa: E402
from core.challenge import (ChallengeRound, ChallengeError,           # noqa: E402
                            sortition_alpha, is_selected,
                            verify_fraud_proof)

RFC_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "",
     "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f"
     "26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab12"
     "68a1b0db10836d9826a528ca76567805",
     "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff"
     "66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "72",
     "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593"
     "3bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926d"
     "a3ef39226bbc355bdc9850112c8f4b02",
     "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb"
     "5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "af82",
     "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80"
     "96bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a"
     "2d41b00b05081ed0f58ee5e31b3a970e",
     "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45"
     "2118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"),
]


def test_vrf_rfc9381():
    for i, (sk_hex, alpha_hex, pi_exp, beta_exp) in enumerate(RFC_VECTORS,
                                                              16):
        sk = SigningKey(bytes.fromhex(sk_hex))
        alpha = bytes.fromhex(alpha_hex)
        pi = vrf_prove(sk, alpha)
        assert pi.hex() == pi_exp, f"V-RFC ex{i}: pi drifted"
        assert vrf_verify(sk.public, alpha, pi).hex() == beta_exp, \
            f"V-RFC ex{i}: beta drifted"
    sk = SigningKey(bytes.fromhex(RFC_VECTORS[0][0]))
    pi = vrf_prove(sk, b"target")
    for attack, args in (
            ("tampered proof", (sk.public, b"target",
                                pi[:40] + bytes([pi[40] ^ 1]) + pi[41:])),
            ("wrong alpha", (sk.public, b"other", pi)),
            ("wrong key", (SigningKey.generate().public, b"target", pi)),
            ("small-order key", (bytes(32), b"target", pi))):
        try:
            vrf_verify(*args)
            assert False, f"V-RFC: {attack} accepted"
        except ValueError:
            pass
    print("  [PASS] V-RFC  all three RFC 9381 B.3 vectors byte-for-byte; "
          "tamper/wrong-alpha/wrong-key/small-order fail closed")


def test_multisig():
    ks = [SigningKey.generate() for _ in range(3)]
    msg = b"steward ballot"
    pol = {"m": 2, "pubkeys": [k.public.hex() for k in ks]}
    two = [(ks[0].public.hex(), ks[0].sign(msg).hex()),
           (ks[1].public.hex(), ks[1].sign(msg).hex())]
    assert multisig_verify(pol, msg, two)
    assert not multisig_verify(pol, msg, two[:1]), "V-MS: 1 < m"
    assert not multisig_verify(pol, msg, two[:1] * 5), \
        "V-MS: duplicates must not double-count"
    out = SigningKey.generate()
    assert not multisig_verify(pol, msg, two[:1] + [
        (out.public.hex(), out.sign(msg).hex())]), "V-MS: outsider counted"
    assert not multisig_verify(pol, msg, two[:1] + [
        (ks[1].public.hex(), ks[1].sign(b"other").hex())]), \
        "V-MS: a signature over another message counted"
    print("  [PASS] V-MS   m-of-n: threshold, dedupe, outsider and "
          "wrong-message signatures all handled")


def _mk_round(now, **kw):
    sk = SigningKey.generate()
    chain = WitnessChain(sk)
    clock = {"t": now}
    cr = ChallengeRound(chain, now_fn=lambda: clock["t"], **kw)
    return cr, chain, clock


def _verifiers(n):
    return {f"v{i}": SigningKey.generate() for i in range(n)}


def _claim_all(cr, rid, keys, alpha):
    seats = {}
    for vid, sk in keys.items():
        won = cr.claim_seat(rid, vid, vrf_prove(sk, alpha).hex())
        if won:
            seats[vid] = sk
    return seats


def test_sortition():
    keys = _verifiers(40)
    eligible = {v: k.public.hex() for v, k in keys.items()}
    cr, _c, _clk = _mk_round(1000.0)
    rnd = cr.open("r1", "th-A", eligible, k=10)
    alpha = bytes.fromhex(rnd["alpha"])
    seats = set(_claim_all(cr, "r1", keys, alpha))
    cr2, _c2, _clk2 = _mk_round(2000.0)
    rnd2 = cr2.open("r1", "th-A", eligible, k=10)
    seats_again = set(_claim_all(cr2, "r1", keys,
                                 bytes.fromhex(rnd2["alpha"])))
    assert seats == seats_again, "C-SORT: same round must give same seats"
    cr3, _c3, _clk3 = _mk_round(3000.0)
    rnd3 = cr3.open("r2", "th-B", eligible, k=10)
    seats_b = set(_claim_all(cr3, "r2", keys, bytes.fromhex(rnd3["alpha"])))
    assert seats != seats_b, \
        "C-SORT: a different transcript must reshuffle the panel"
    assert 2 <= len(seats) <= 22, \
        f"C-SORT: {len(seats)} seats for k=10/n=40 is implausible"
    # a proof ground against ANOTHER round's alpha is refused (use a
    # verifier withOUT a seat: seated ones early-return before verifying)
    unseated = sorted(set(keys) - seats)
    assert unseated, "all 40 won seats?! statistically impossible"
    v0 = unseated[0]
    foreign = vrf_prove(keys[v0], sortition_alpha("r2", "th-B")).hex()
    try:
        cr.claim_seat("r1", v0, foreign)
        assert False, "C-SORT: foreign-round proof accepted"
    except ChallengeError:
        pass
    assert is_selected(bytes(32), 1, 2) and \
        not is_selected(b"\xff" * 32, 1, 2)
    print(f"  [PASS] C-SORT deterministic ({len(seats)} seats), "
          "transcript-bound, foreign proofs refused, threshold sane")


def test_full_round_and_fraud():
    keys = _verifiers(12)
    eligible = {v: k.public.hex() for v, k in keys.items()}
    with tempfile.TemporaryDirectory() as tmp:
        fraud_log = os.path.join(tmp, "fraud.jsonl")

        class _Reg:
            slashed = []
            def slash(self, oid, reason, **kw):
                self.slashed.append((oid, reason))
        reg = _Reg()
        cr, chain, clk = _mk_round(0.0, registry=reg,
                                   fraud_log_path=fraud_log,
                                   commit_window=30, reveal_window=30)
        rnd = cr.open("r9", "th-task-42", eligible, k=6)
        seats = _claim_all(cr, "r9", keys, bytes.fromhex(rnd["alpha"]))
        assert len(seats) >= 3, f"only {len(seats)} seats; rerun-worthy"
        order = sorted(seats)
        honest, fraudster, silent = order[:-2], order[-2], order[-1]
        verdict = {"verified": True, "margin": 0.42}
        salts = {}
        for v in order:
            salts[v] = os.urandom(16).hex()
            vd = verdict if v != fraudster else {"verified": False}
            cr.commit("r9", v, cr.make_commitment("r9", v, vd, salts[v]))
        clk["t"] = 40.0                       # commit window closed
        for v in honest:
            cr.reveal("r9", v, verdict, salts[v])
        # ---- fraud: sealed {verified: False}, reveals {verified: True}
        try:
            cr.reveal("r9", fraudster, verdict, salts[fraudster])
            assert False, "C-FRD: mismatched reveal accepted"
        except ChallengeError:
            pass
        assert reg.slashed and reg.slashed[0][0] == fraudster
        frauds, _rep = read_journal(fraud_log)
        assert len(frauds) == 1
        ok, why = verify_fraud_proof(frauds[0], chain.records)
        assert ok, f"C-FRD: offline verification failed: {why}"
        tampered = dict(frauds[0], committed="ab" * 32)
        ok, _ = verify_fraud_proof(tampered, chain.records)
        assert not ok, "C-FRD: tampered accusation accepted"
        honest_claim = dict(frauds[0],
                            revealed_verdict={"verified": False})
        ok, why = verify_fraud_proof(honest_claim, chain.records)
        assert not ok and "no fraud" in why, \
            "C-FRD: an honest reveal framed as fraud"
        # ---- resolve: majority of valid reveals; silence = ABSTAINED
        clk["t"] = 70.0
        res = cr.resolve("r9")
        assert res["status"] == "resolved" and res["verdict"] == verdict
        assert sorted(res["supporters"]) == sorted(honest)
        assert silent in res["abstained"] and \
            res["frauds"][0]["verifier"] == fraudster
        phases = [r["semantic_digest"].get("phase") for r in chain.records
                  if r["kind"] == "CHALLENGE"]
        for ph in ("open", "seat", "commit", "reveal", "fraud", "resolve"):
            assert ph in phases, f"C-RND: phase {ph} never witnessed"
        assert chain.verify_chain()
        print("  [PASS] C-RND  seats -> blind commits -> reveals -> "
              "majority; every phase witnessed; chain verifies")
        print("  [PASS] C-FRD  fraud slashed + durable + offline-"
              "verifiable; tampered and false accusations refused")


def test_deadlines_and_refusals():
    keys = _verifiers(10)
    eligible = {v: k.public.hex() for v, k in keys.items()}
    cr, chain, clk = _mk_round(0.0, commit_window=10, reveal_window=10)
    rnd = cr.open("rt", "th-T", eligible, k=8)
    seats = _claim_all(cr, "rt", keys, bytes.fromhex(rnd["alpha"]))
    assert seats, "no seats won; rerun-worthy"
    v = sorted(seats)[0]
    salt = os.urandom(16).hex()
    verdict = {"verified": True}
    cr.commit("rt", v, cr.make_commitment("rt", v, verdict, salt))
    try:
        cr.commit("rt", v, cr.make_commitment("rt", v,
                                              {"verified": False}, salt))
        assert False, "C-ABS: double commit accepted"
    except ChallengeError:
        pass
    clk["t"] = 25.0                            # both windows closed
    try:
        cr.reveal("rt", v, verdict, salt)
        assert False, "C-ABS: late reveal accepted"
    except ChallengeError:
        pass
    res = cr.resolve("rt")
    assert res["status"] == "unresolved" and v in res["abstained"], res
    phases = [r["semantic_digest"].get("phase") for r in chain.records
              if r["kind"] == "CHALLENGE"]
    assert "double_commit_refused" in phases \
        and "late_reveal_refused" in phases
    print("  [PASS] C-ABS  double commit + late reveal refused AND "
          "witnessed; silence -> ABSTAINED; zero reveals -> UNRESOLVED")


if __name__ == "__main__":
    test_vrf_rfc9381()
    test_multisig()
    test_sortition()
    test_full_round_and_fraud()
    test_deadlines_and_refusals()
    print("\nCHALLENGE ROUND UNIT: all groups green  ✓ certified")
