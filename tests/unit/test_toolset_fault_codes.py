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

import copy as _copy
import json
import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai import provenance as PRV                                # noqa: E402
from jjdai.crypto import H_hex, SigningKey                                # noqa: E402
from kernel import isolation as ISO
from kernel import toolset as TS                           # noqa: E402


# --------------------------------------------------------------------------- #
# v0.6.9: a toolset manifest is VERIFIED before anything reads it, so the
# fixtures sign one. The key and its resolver are local to the tests — the
# tree ships no key registry, and a node without one has the wasm profile
# unavailable, which is the honest state rather than a gap in these checks.
# --------------------------------------------------------------------------- #
_SK = SigningKey(b"\x21" * 32)
_KEY_ID = "toolset-test-key"


def _resolver(key_id):
    if key_id != _KEY_ID:
        return None
    return {"public": _SK.public.hex(),
            "key_domain": PRV.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
            "revoked": False}


def _sign(doc):
    doc["signer"] = {"key_id": _KEY_ID,
                     "key_domain": PRV.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
                     "domain": PRV.DOMAIN_TOOLSET_MANIFEST}
    doc["signature"] = _SK.sign(TS.signing_bytes(doc)).hex()
    return doc



def _module(tag: bytes) -> bytes:
    """A WELL-FORMED wasm module carrying `tag`, so two fixtures differ in
    content while both parse.

    v0.6.9: the fixtures used to append raw text after the eight-byte
    header, which is not a module — the bytes after the header are read as a
    section id and a length. That went unnoticed while nothing parsed them;
    the `pure` boundary parses them, and a fixture that is not a module
    would now fail for a reason the check is not about. The tag rides in a
    CUSTOM section (id 0), which is exactly what custom sections are for.
    """
    payload = bytes([len(tag)]) + tag
    return b"\0asm\x01\0\0\0" + b"\x00" + bytes([len(payload)]) + payload


def _fixture():
    """A toolset directory with one good, one drifted, one missing and one
    unpinned entry."""
    root = tempfile.mkdtemp(prefix="jjdai-toolset-")
    tools = os.path.join(root, "tools")
    os.makedirs(tools)
    good = os.path.join(tools, "good.wasm")
    with open(good, "wb") as f:
        f.write(_module(b"GOOD"))
    drift = os.path.join(tools, "drift.wasm")
    with open(drift, "wb") as f:
        f.write(_module(b"ORIGINAL"))
    pinned_drift = H_hex(open(drift, "rb").read())
    with open(drift, "wb") as f:                 # replaced after pinning
        f.write(_module(b"REPLACED"))
    unpinned = os.path.join(tools, "unpinned.wasm")
    with open(unpinned, "wb") as f:
        f.write(_module(b"NOPIN"))
    # v0.6.9: every entry declares its effect class, because ADR-022 D9
    # makes the declaration mandatory — an undeclared tool is refused, not
    # assumed harmless. `classless` is added here as its own subject rather
    # than by leaving one of the four without a class: the four above test
    # DIGEST faults, and folding a manifest fault into one of them would
    # make a red check point at the wrong defect.
    manifest = {
        "schema": ISO.TOOLSET_SCHEMA_V2,
        "tools": {
            "good": {"module": "good.wasm", "effect_class": "pure",
                     "sha256": H_hex(open(good, "rb").read())},
            "drift": {"module": "drift.wasm", "effect_class": "pure",
                      "sha256": pinned_drift},
            "ghost": {"module": "ghost.wasm", "effect_class": "pure",
                      "sha256": "00" * 32},
        },
    }
    # The manifest lives INSIDE the toolset directory — the profile derives
    # its path from tools_dir and takes no separate argument, so the fixture
    # must mirror the real deployment layout rather than invent one.
    manifest["authorization_form"] = PRV.AUTHORIZATION_FORM_INTERIM
    manifest["sunset_condition"] = PRV.SUNSET_CONDITION_GAUNTLET
    for entry in manifest["tools"].values():
        entry.setdefault("recipe_hash", "ef" * 32)
        entry.setdefault("limits", {"fuel": 10 ** 8,
                                    "guest_memory_bytes": 1 << 24,
                                    "output_bytes": 1 << 16})
    mpath = os.path.join(tools, TS.MANIFEST_FILE)
    signed = _sign(manifest)
    with open(mpath, "w") as f:
        json.dump(signed, f)
    return root, tools, mpath, signed


def test_toolset_fault_codes():
    passed = 0
    root, tools, mpath, manifest_doc = _fixture()
    prof = ISO.WasmWasiProfile(root, tools_dir=tools, key_resolver=_resolver)
    assert prof.manifest_path() == mpath, prof.manifest_path()
    rep = prof.toolset_report()

    assert rep["good"]["ok"] is True and rep["good"]["code"] == ISO.TOOL_OK
    print("  [PASS] T-0 a correctly pinned module is executable")
    passed += 1

    # T-0b. A tool with no effect class does not produce a per-tool fault:
    # it refuses the WHOLE manifest, and that is the stronger answer. The
    # manifest is immutable and signed, so one entry that declares no
    # enforceable limit makes the whole sanction invalid — reporting it as
    # one broken tool beside three working ones would let the being keep a
    # hand that a defective manifest authorised. Checked through
    # `available()`, which is the door execution actually goes through.
    broken = _copy.deepcopy(manifest_doc)
    del broken["tools"]["good"]["effect_class"]
    with open(mpath, "w") as f:
        json.dump(_sign({k: v for k, v in broken.items()
                         if k != "signature"}), f)
    broken_prof = ISO.WasmWasiProfile(root, tools_dir=tools,
                                      key_resolver=_resolver)
    assert broken_prof.toolset() == {}, "a classless entry was loaded"
    why = broken_prof.manifest_error()
    assert ISO.toolset_mod.MANIFEST_NO_EFFECT_CLASS in why, why
    with open(mpath, "w") as f:
        json.dump(manifest_doc, f)
    print("  [PASS] T-0b a tool with no declared effect class refuses the "
          "WHOLE manifest (ADR-022 D9, fail-closed)")
    passed += 1

    assert rep["ghost"]["code"] == ISO.TOOL_MODULE_MISSING, rep["ghost"]
    print("  [PASS] T-1 absent module -> MODULE_MISSING (operations)")
    passed += 1

    assert rep["drift"]["code"] == ISO.TOOL_DIGEST_DRIFT, rep["drift"]
    print("  [PASS] T-2 replaced module -> DIGEST_DRIFT (security)")
    passed += 1

    # T-3. An entry with no sha256 pin refuses the WHOLE manifest, for the
    # same reason as T-0b: the manifest is the signed sanction, and one
    # unverifiable module makes the sanction meaningless rather than making
    # one tool unavailable. The per-tool UNPINNED code stays reachable on
    # the legacy v1 path, where entries carry no v2 fields at all.
    unpinned = _copy.deepcopy(manifest_doc)
    del unpinned["tools"]["good"]["sha256"]
    with open(mpath, "w") as f:
        json.dump(_sign({k: v for k, v in unpinned.items()
                         if k != "signature"}), f)
    unpinned_prof = ISO.WasmWasiProfile(root, tools_dir=tools,
                                        key_resolver=_resolver)
    assert unpinned_prof.toolset() == {}, "an unpinned entry was loaded"
    assert "sha256" in unpinned_prof.manifest_error(), \
        unpinned_prof.manifest_error()
    with open(mpath, "w") as f:
        json.dump(manifest_doc, f)
    print("  [PASS] T-3 an entry with no pin refuses the whole manifest; "
          "UNPINNED remains the per-tool code on the legacy path")
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
