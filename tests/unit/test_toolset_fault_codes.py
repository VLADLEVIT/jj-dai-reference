#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Isolation toolset fault codes (v0.6.6) — "broken" was one word for two events
=============================================================================
A module that is ABSENT is an operations fact: someone shipped a manifest
without its artifact, and on this build — which contains no compiled wasm
modules at all — it is the expected state of a fresh node. A module whose
digest has DRIFTED from its pin is a security fact: the artifact under the
pin is not the artifact that was pinned. Merging them into one alert
guarantees the rare one is read as the common one.

  T-1  a declared module that is absent  -> MODULE_MISSING
  T-2  a module whose bytes changed      -> DIGEST_DRIFT
  T-3  a manifest entry with no pin      -> UNPINNED (a defect, not tampering)
  T-4  a tool not in the manifest        -> NOT_PERMITTED
  T-5  the security codes are named as such, and capabilities carries them
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import H_hex                                # noqa: E402
from kernel import isolation as ISO                           # noqa: E402


def _fixture():
    """A toolset directory with one good, one drifted, one missing and one
    unpinned entry."""
    root = tempfile.mkdtemp(prefix="jjdai-toolset-")
    tools = os.path.join(root, "tools")
    os.makedirs(tools)
    good = os.path.join(tools, "good.wasm")
    with open(good, "wb") as f:
        f.write(b"\0asm\x01\0\0\0GOOD")
    drift = os.path.join(tools, "drift.wasm")
    with open(drift, "wb") as f:
        f.write(b"\0asm\x01\0\0\0ORIGINAL")
    pinned_drift = H_hex(open(drift, "rb").read())
    with open(drift, "wb") as f:                 # replaced after pinning
        f.write(b"\0asm\x01\0\0\0REPLACED")
    unpinned = os.path.join(tools, "unpinned.wasm")
    with open(unpinned, "wb") as f:
        f.write(b"\0asm\x01\0\0\0NOPIN")
    manifest = {
        "schema": ISO.TOOLSET_SCHEMA,
        "tools": {
            "good": {"module": "good.wasm",
                     "sha256": H_hex(open(good, "rb").read())},
            "drift": {"module": "drift.wasm", "sha256": pinned_drift},
            "ghost": {"module": "ghost.wasm", "sha256": "00" * 32},
            "unpinned": {"module": "unpinned.wasm"},
        },
    }
    # The manifest lives INSIDE the toolset directory — the profile derives
    # its path from tools_dir and takes no separate argument, so the fixture
    # must mirror the real deployment layout rather than invent one.
    mpath = os.path.join(tools, "toolset.json")
    with open(mpath, "w") as f:
        json.dump(manifest, f)
    return root, tools, mpath


def test_toolset_fault_codes():
    passed = 0
    root, tools, mpath = _fixture()
    prof = ISO.WasmWasiProfile(root, tools_dir=tools)
    assert prof.manifest_path() == mpath, prof.manifest_path()
    rep = prof.toolset_report()

    assert rep["good"]["ok"] is True and rep["good"]["code"] == ISO.TOOL_OK
    print("  [PASS] T-0 a correctly pinned module is executable")
    passed += 1

    assert rep["ghost"]["code"] == ISO.TOOL_MODULE_MISSING, rep["ghost"]
    print("  [PASS] T-1 absent module -> MODULE_MISSING (operations)")
    passed += 1

    assert rep["drift"]["code"] == ISO.TOOL_DIGEST_DRIFT, rep["drift"]
    print("  [PASS] T-2 replaced module -> DIGEST_DRIFT (security)")
    passed += 1

    assert rep["unpinned"]["code"] == ISO.TOOL_UNPINNED, rep["unpinned"]
    assert rep["unpinned"]["code"] != ISO.TOOL_DIGEST_DRIFT, (
        "a missing pin must not masquerade as tampering")
    print("  [PASS] T-3 unpinned entry -> UNPINNED, distinct from drift")
    passed += 1

    try:
        prof._module_for("not-declared")
        raise AssertionError("undeclared tool must be refused")
    except Exception as e:
        assert getattr(e, "code", None) == ISO.TOOL_NOT_PERMITTED, e
    print("  [PASS] T-4 undeclared tool -> NOT_PERMITTED")
    passed += 1

    assert ISO.TOOL_DIGEST_DRIFT in ISO.TOOL_SECURITY_CODES
    assert ISO.TOOL_MODULE_MISSING not in ISO.TOOL_SECURITY_CODES
    caps = prof.capabilities()
    assert caps["toolset_codes"]["drift"] == ISO.TOOL_DIGEST_DRIFT, caps
    assert "good" not in caps["toolset_codes"], "healthy tools carry no code"
    assert caps["toolset_ready"] == ["good"], caps["toolset_ready"]
    # Availability depends on the HOST runtime as well as the tools, and the
    # v0.6.4 audit required that a refusal name the right cause. On a host
    # without wasmtime the profile is unavailable for a host reason and must
    # say so — it must NOT report a tool fault it does not have, and the
    # per-tool codes stay correct either way.
    if caps["runtime_path"]:
        assert caps["available"] is True, "one good tool keeps the profile up"
    else:
        assert caps["available"] is False
        assert "runtime" in caps["unavailable_reason"], caps
        assert "digest" not in caps["unavailable_reason"], caps
    print("  [PASS] T-5 security codes named apart; capabilities carries them")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_toolset_fault_codes()
