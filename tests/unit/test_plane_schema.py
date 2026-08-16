#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_plane_schema — v0.6.5 acceptance for what may cross into the plane
=======================================================================
The witness plane is append-only, replicated and undeletable. That is what
makes it evidence, and it is also what makes it an ideal dead-drop: anything
writable there is readable by every peer, forever. So the plane takes a
VOCABULARY — enum tokens, integers, hex digests — and refuses everything
else, fail closed.

Two honest notes about scope, because the constraint is narrower than it
first appears. `request` and `response` already entered the chain as hiding
COMMITMENTS and `provenance` as a hash, so being-chosen bytes never reached a
peer even before this drop. `semantic_digest` is the one field placed in the
hashed body verbatim, and it is the one this guard closes. What remains after
it is a metadata channel — record counts, kinds, timing — which is bounded
and not addressed here.

  W-1  PROSE REFUSED: free text offered to the plane is rejected, and the
       rejection names the remedy (pass H(x), not x).
  W-2  VOCABULARY ACCEPTED: enum tokens, integers, floats, hex digests and
       the fixed numeric histogram all pass.
  W-3  STRUCTURE ALLOWED, LEAVES CONSTRAINED: nested node-authored mappings
       are fine; a prose leaf anywhere inside is not.
  W-4  BOUNDED WRITE: depth and value count are capped.
  W-5  RESERVED KINDS EXIST BUT CANNOT BE EMITTED: the names are in the
       canonical enum before genesis; emitting one refuses.
  W-6  RESERVED FIELDS REFUSE, AND ARE ABSENT FROM THE RECORD: the names
       enter the canonical shape before genesis, but nothing may populate
       them until their grammar exists. (The first cut of this drop let
       both through unchecked — free text on an ordinary INFER record —
       which re-opened the channel the vocabulary had just closed. Written
       to fail against that version.)
  W-7  REASONS ARE CODES: the challenge round and the rate limiter put
       codes in the plane, never sentences.
"""
from __future__ import annotations

import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import SigningKey                                  # noqa: E402
from jjdai.witness import (IR_SCHEMA_VERSION, KINDS, PlaneSchemaError,  # noqa: E402
                           RESERVED_KINDS, WitnessChain,
                           check_plane_value)


def _chain(tmp):
    return WitnessChain(SigningKey.generate(),
                        log_path=os.path.join(tmp, "witness.jsonl"))


def test_prose_is_refused():
    for bad in ("no valid reveals — the round refuses to invent a verdict",
                "systematic over-budget traffic; one record per offender",
                "hello world",
                "user said: meet me at the bridge"):
        try:
            check_plane_value("semantic_digest", bad)
        except PlaneSchemaError as e:
            assert "H(x)" in str(e), str(e)
            continue
        raise AssertionError(f"prose accepted into the plane: {bad!r}")

    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        before = len(c.records)
        try:
            c.append("INFER", semantic_digest="a sentence about something")
        except PlaneSchemaError:
            pass
        else:
            raise AssertionError("chain accepted prose")
        assert len(c.records) == before, "a refused write still appended"


def test_vocabulary_is_accepted():
    ok = ["karma:being:test:" + "ab" * 32,
          "mem:being:0001:" + "cd" * 32,
          "13,11,5,9,8,9,5,6",
          "vrf_invalid", "seat_refused", "infer",
          42, 3.5, True,
          "cert:node-a.testnet:0A1B",
          "ip:127.0.0.1"]
    for good in ok:
        check_plane_value("semantic_digest", good)


def test_structure_allowed_leaves_constrained():
    check_plane_value("semantic_digest", {
        "deployment_hash": "ab" * 32,
        "substrates": {"sha256:base-A": {"artifact_hash": "cd" * 32,
                                         "binding": "profile_b"}}})
    try:
        check_plane_value("semantic_digest", {
            "substrates": {"sha256:base-A": {"note": "looks fine to me"}}})
    except PlaneSchemaError as e:
        assert "substrates" in str(e), str(e)
    else:
        raise AssertionError("prose hidden inside structure was accepted")


def test_write_is_bounded():
    deep = cur = {}
    for _ in range(8):
        cur["k"] = {}
        cur = cur["k"]
    try:
        check_plane_value("semantic_digest", deep)
    except PlaneSchemaError as e:
        assert "nesting" in str(e) or "values" in str(e), str(e)
    else:
        raise AssertionError("unbounded nesting accepted")

    wide = {f"k{i}": i for i in range(500)}
    try:
        check_plane_value("semantic_digest", wide)
    except PlaneSchemaError:
        pass
    else:
        raise AssertionError("unbounded width accepted")


def test_reserved_kinds_declared_but_not_emittable():
    for kind in RESERVED_KINDS:
        assert kind in KINDS, f"{kind} missing from the canonical enum"
    assert IR_SCHEMA_VERSION == "1"
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        for kind in RESERVED_KINDS:
            try:
                c.append(kind, semantic_digest="x" * 16)
            except ValueError as e:
                assert "RESERVED" in str(e), str(e)
                continue
            raise AssertionError(f"{kind} was emitted before its semantics "
                                 f"exist")


def test_reserved_fields_are_omitted_when_absent():
    with tempfile.TemporaryDirectory() as tmp:
        c = _chain(tmp)
        c.append("INFER", semantic_digest="ab" * 32)
        body = c.records[-1]
        assert "session_id" not in body, body
        assert "ir_schema_version" not in body, body

        # populating a reserved field refuses — including, above all, with
        # the free text that a constrained semantic_digest can no longer
        # carry, which is what makes this a security check and not tidiness
        for kw in ({"session_id": "sess:" + "0a" * 8},
                   {"session_id": "FREE TEXT: meet me at the bridge"},
                   {"ir_schema_version": IR_SCHEMA_VERSION},
                   {"ir_schema_version": "FREE TEXT TOO"}):
            before = len(c.records)
            try:
                c.append("INFER", semantic_digest="cd" * 32, **kw)
            except ValueError as e:
                assert "RESERVED" in str(e), str(e)
            else:
                raise AssertionError(f"reserved field populated: {kw}")
            assert len(c.records) == before, "a refused write still appended"
        assert c.verify_chain()


def test_reasons_are_codes():
    import core.challenge as ch
    src = open(ch.__file__, encoding="utf-8").read()
    assert "REASON_CODES_VERSION" in src, "no versioned code enumeration"
    for code in ch.REASON_CODES:
        check_plane_value("reason_code", code)
    # the sentences must be gone from anything the plane sees
    assert '"reason": f"vrf: {e}"' not in src, "free-text reason still emitted"
    daemon_src = open(os.path.join(_ROOT, "node", "daemon.py"),
                      encoding="utf-8").read()
    assert '"note": "systematic over-budget traffic' not in daemon_src, \
        "free-text note still emitted into the plane"


if __name__ == "__main__":
    tests = [test_prose_is_refused,
             test_vocabulary_is_accepted,
             test_structure_allowed_leaves_constrained,
             test_write_is_bounded,
             test_reserved_kinds_declared_but_not_emittable,
             test_reserved_fields_are_omitted_when_absent,
             test_reasons_are_codes]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\nplane schema — {len(tests)}/{len(tests)} checks green")
