#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reserved values are refused as VALUES, not only as arguments — v0.6.8 P0-1.

The audit against the first v0.6.8 cut showed the reserve was bypassable:
an ordinary INFER record carried six reserved tokens in its body and the
chain stayed validly signed, because only function ARGUMENTS were checked.
What a later reader trusts is the value in the record, so a reserve that
guards parameter names guards nothing.

Every check below is written from that finding and each was verified red
against the pre-fix behaviour (the scan removed, or narrowed back to whole
strings, or narrowed back to `semantic_digest` alone).

  RSV-1  The audit's own reproduction: each of the six tokens it smuggled
         through an ordinary record is now refused, and the record is not
         written — refused, not recorded-and-warned.
  RSV-2  Both vocabularies, all scannable tokens: no reserved value of
         either ADR reaches the chain through `semantic_digest`.
  RSV-3  Segments and keys, not only whole strings. A digest is routinely a
         colon-compound, and a mapping key is as good a place to write a
         name as a value.
  RSV-4  `provenance` and `entanglement` are covered too — provenance is the
         field the deliberation verifier recomputes and the one the audit's
         reproduction actually used.
  RSV-5  The line is where it is claimed to be: `request` and `response` are
         NOT scanned, because they enter the chain as hiding commitments
         over caller data. Asserted so the exclusion is a decision on the
         record rather than an omission.
  RSV-6  Ordinary records still pass. A reserve that refuses honest work is
         a different defect, not a stricter one.
  RSV-7  The refusal names the ADR that owes the semantics, and the
         ambiguous tokens are excluded from the scan on purpose.
"""
import io
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai import cognitive as cog                            # noqa: E402
from jjdai import custody as cus                              # noqa: E402
from jjdai import reserved as rsv                             # noqa: E402
from jjdai.crypto import SigningKey                           # noqa: E402
from jjdai.witness import WitnessChain, LocalAnchor           # noqa: E402

DIGEST = "ab" * 16


def _chain(tmp, name="w.jsonl"):
    return WitnessChain(SigningKey.generate(), anchor=LocalAnchor(),
                        log_path=os.path.join(tmp, name))


def _refused(chain, **kw):
    n = len(chain.records)
    try:
        chain.append("INFER", **kw)
    except rsv.ReservedValueError:
        assert len(chain.records) == n, "refused but the record was written"
        return True
    return False


def test_audit_reproduction_now_refuses():
    """RSV-1"""
    smuggled = (cog.KRIYA_GATE_OUTCOMES[0],
                cog.PREDICTION_STATUSES[0],
                cog.CONTESTED_REASON_CODES[0],
                cog.PREDICTION_SEALED,
                cog.PREDICTION_COMMITMENT_DOMAIN,
                cog.HYPOTHESIS_RETRIEVAL)
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        for value in smuggled:
            assert _refused(c, provenance={"organ": "karma",
                                           "outcome": value},
                            request={"x": value}, semantic_digest=DIGEST), (
                f"{value!r} still reaches an ordinary record")
        assert not c.records, "nothing should have been written"
    print(f"  [PASS] RSV-1  the audit's {len(smuggled)} smuggled tokens are "
          f"refused and nothing is written")


def test_both_vocabularies_refused_in_the_digest():
    """RSV-2"""
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        for value in sorted(rsv.SCANNED_VALUES):
            assert _refused(c, semantic_digest=value), value
    print(f"  [PASS] RSV-2  {len(rsv.SCANNED_VALUES)} scannable tokens of "
          f"both ADRs refuse in semantic_digest")


def test_segments_and_keys():
    """RSV-3"""
    token = cus.SELF_CHECKED
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        # one segment of a colon-compound digest
        assert _refused(c, semantic_digest=f"state:{token}:{DIGEST}")
        # a mapping key
        assert _refused(c, provenance={token: 1}, semantic_digest=DIGEST)
        # a value nested in a list under a mapping
        assert _refused(c, provenance={"organ": ["karma", token]},
                        semantic_digest=DIGEST)
        # and a path BELOW a reserved namespace, not only the prefix itself
        deep = cog.NS_SELF_MODEL + "v3"
        assert _refused(c, semantic_digest=deep), deep
    print("  [PASS] RSV-3  segments, keys, nested values and sub-paths of a "
          "reserved namespace all refuse")


def test_provenance_and_entanglement_are_covered():
    """RSV-4"""
    token = cog.KRIYA_GATE_OUTCOMES[0]
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        assert _refused(c, provenance={"organ": "karma", "outcome": token},
                        semantic_digest=DIGEST)
        assert _refused(c, provenance={"organ": "karma"},
                        entanglement={"peer_root": token},
                        semantic_digest=DIGEST)
    assert "provenance" in rsv.SCANNED_FIELDS
    assert "entanglement" in rsv.SCANNED_FIELDS
    print("  [PASS] RSV-4  provenance and entanglement are scanned, not only "
          "the digest")


def test_request_and_response_are_deliberately_not_scanned():
    """RSV-5"""
    token = cog.PREDICTION_STATUSES[0]
    assert "request" not in rsv.SCANNED_FIELDS
    assert "response" not in rsv.SCANNED_FIELDS
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        rec = c.append("INFER", request={"task": f"was it {token}?"},
                       response={"answer": token},
                       provenance={"organ": "karma"},
                       semantic_digest=DIGEST)
        assert rec["index"] == 0
        body = c.records[0]
        # the point of the exclusion: no reserved value crossed to a peer.
        # What is in the chain is a commitment, and it is not the token.
        assert body["request_commitment"] != token
        blob = io.StringIO()
        blob.write(str(body))
        assert token not in blob.getvalue(), (
            "a commitment leaked its preimage into the record")
    print("  [PASS] RSV-5  request/response excluded on purpose; the token "
          "does not reach the record body")


def test_honest_records_still_pass():
    """RSV-6"""
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        for i in range(3):
            c.append("INFER", request={"t": "ordinary work"},
                     provenance={"organ": "karma", "step": i},
                     semantic_digest=f"route:{i}:{DIGEST}")
        # and an ambiguous token in its ordinary sense is not obstructed
        c.append("INFER", provenance={"organ": "karma",
                                      "quantization": cus.EFFECT_CLASSES[-1]},
                 semantic_digest=DIGEST)
        assert len(c.records) == 4
        assert c.verify_chain()
    print("  [PASS] RSV-6  four ordinary records written, chain verifies; an "
          "ambiguous token in its own sense is not obstructed")


def test_refusal_names_the_owner_and_the_exclusion_holds():
    """RSV-7"""
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        try:
            c.append("INFER", semantic_digest=cus.SELF_CHECKED)
            raise AssertionError("not refused")
        except rsv.ReservedValueError as e:
            assert "ADR-019" in str(e), str(e)
        try:
            c.append("INFER", semantic_digest=cog.PREDICTION_SEALED)
            raise AssertionError("not refused")
        except rsv.ReservedValueError as e:
            assert "ADR-018" in str(e), str(e)
    assert rsv.UNSCANNED_VALUES == frozenset(cus.AMBIGUOUS_TOKENS)
    assert not (rsv.UNSCANNED_VALUES & rsv.SCANNED_VALUES), (
        "a token cannot be both scanned for and excluded from the scan")
    print(f"  [PASS] RSV-7  refusals name the owning ADR; "
          f"{len(rsv.UNSCANNED_VALUES)} ambiguous tokens excluded, disjoint")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
    print(f"\nreserved values — {len(tests)}/{len(tests)} checks green")
