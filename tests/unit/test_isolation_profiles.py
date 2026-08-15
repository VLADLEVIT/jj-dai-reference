#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_isolation_profiles — v0.6.4 acceptance for the Karma isolation seam
=======================================================================
  I-1  SEAM: the reference profile is a named profile and stays the default;
       Karma reports which boundary it is acting inside.
  I-2  FAIL CLOSED: a declared profile whose runtime is absent REFUSES the
       action. It never falls back to the reference profile.
  I-3  REFUSAL IS WITNESSED: the refusal in I-2 emits an outcome record
       carrying the refusal class and the profile — both paths are witnessed,
       the difference between them is whether the hand moved.
  I-4  FIXED TOOLSET: a tool absent from the manifest is refused even when
       the runtime IS present.
  I-5  DIGEST PINNING: a tool whose module does not hash to the pinned digest
       is refused (a mismatch is a refusal, not a warning).
  I-6  ARGV MAPPING: with runtime and manifest present, argv is mapped onto
       the wasm runtime with the workspace preopened and nothing else.
  I-7  PATH CONFINEMENT INHERITED: the stronger profile does not relax any
       baseline guarantee — an escape is still an escape.
  I-8  DECLARATION: profile_status reports readiness honestly, and the
       reserved microvm name is never reported available.
  I-9  DECLARED READINESS == EXECUTABLE READINESS: a manifest naming a
       module that is missing, or one that has drifted from its pinned
       digest, is never reported ready — and one broken entry does not take
       the whole boundary dark. (Written to fail against the first cut of
       this drop, where available() checked only that a manifest existed.)
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import H_hex                                     # noqa: E402
from kernel.isolation import (WasmWasiProfile, profile_status,     # noqa: E402
                              resolve_profile)
from kernel.karma import (Karma, ProfileUnavailable, Sandbox,      # noqa: E402
                          SandboxEscape, ToolNotPermitted)

BEING = "being:isolation-test"


def _toolset(dirpath: str, tools: dict):
    with open(os.path.join(dirpath, "toolset.json"), "w", encoding="utf-8") as f:
        json.dump({"schema": "jjdai.toolset/v1", "tools": tools}, f)


def _fake_wasmtime(dirpath: str) -> str:
    """A stand-in for the runtime binary: echoes the argv it was handed.

    The seam is what this build ships; the runtime is a host requirement.
    Testing the mapping against a shim keeps acceptance hermetic and
    deterministic on a machine that has no wasmtime.
    """
    path = os.path.join(dirpath, "wasmtime")
    with open(path, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP
             | stat.S_IXOTH)
    return path


def test_reference_is_a_named_profile():
    with tempfile.TemporaryDirectory() as ws:
        sb = Sandbox(ws)
        assert sb.NAME == "reference", sb.NAME
        ok, reason = sb.available()
        assert ok and reason == "", (ok, reason)
        cap = sb.capabilities()
        assert cap["arbitrary_argv"] is True, cap
        assert cap["execution"] == "os-process", cap

        k = Karma(BEING, ws)
        assert k.profile_name == "reference", k.profile_name
        assert k.isolation()["profile"] == "reference"
        # the default seat is unchanged: the baseline still executes
        r = k.shell([sys.executable, "-c", "print('alive')"])
        assert r.ok and "alive" in r.stdout, r.as_dict()


def test_missing_runtime_fails_closed():
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        _toolset(tools, {"noop": {"module": "noop.wasm", "sha256": "00" * 32}})
        prof = WasmWasiProfile(ws, tools_dir=tools,
                               wasmtime="jjdai-absent-runtime")
        ok, reason = prof.available()
        assert not ok and "not found" in reason, (ok, reason)

        k = Karma(BEING, ws, profile=prof)
        assert k.profile_name == "wasm-wasi", k.profile_name
        try:
            k.shell(["noop"])
        except ProfileUnavailable:
            pass
        else:
            raise AssertionError("missing runtime did not refuse the action")

        # and critically: it did NOT quietly execute in the reference fence
        assert not os.path.exists(os.path.join(ws, "noop")), \
            "action appears to have run despite an unavailable profile"


def test_refusal_is_witnessed():
    class Recorder:
        def __init__(self):
            self.records = []

        def append(self, kind, **kw):
            self.records.append((kind, kw))

    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        _toolset(tools, {"noop": {"module": "noop.wasm", "sha256": "00" * 32}})
        w = Recorder()
        k = Karma(BEING, ws, witness=w,
                  profile=WasmWasiProfile(ws, tools_dir=tools,
                                          wasmtime="jjdai-absent-runtime"))
        try:
            k.shell(["noop"])
        except ProfileUnavailable:
            pass

        phases = [r[1]["request"]["karma_event"]["ph"] for r in w.records]
        assert phases == ["intent", "outcome"], phases
        outcome = w.records[-1][1]["request"]["karma_event"]
        assert outcome["ok"] is False, outcome
        assert outcome["refusal_class"] == "ProfileUnavailable", outcome
        assert outcome["isolation_profile"] == "wasm-wasi", outcome
        prov = w.records[-1][1]["provenance"]
        assert prov["isolation_profile"] == "wasm-wasi", prov


def test_tool_outside_the_fixed_set_is_refused():
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        rt = _fake_wasmtime(tools)
        mod = os.path.join(tools, "noop.wasm")
        with open(mod, "wb") as f:
            f.write(b"\0asm\x01\0\0\0")
        _toolset(tools, {"noop": {"module": "noop.wasm",
                                  "sha256": H_hex(open(mod, "rb").read())}})
        prof = WasmWasiProfile(ws, tools_dir=tools, wasmtime=rt)
        assert prof.available()[0], prof.available()

        k = Karma(BEING, ws, profile=prof)
        for forbidden in (["/bin/sh", "-c", "echo hi"], ["curl"], ["noop2"]):
            try:
                k.shell(forbidden)
            except ToolNotPermitted:
                continue
            raise AssertionError(
                f"arbitrary execution accepted in wasm profile: {forbidden}")


def test_digest_mismatch_is_refused():
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        rt = _fake_wasmtime(tools)
        mod = os.path.join(tools, "noop.wasm")
        with open(mod, "wb") as f:
            f.write(b"\0asm\x01\0\0\0")
        _toolset(tools, {"noop": {"module": "noop.wasm", "sha256": "ab" * 32}})
        prof = WasmWasiProfile(ws, tools_dir=tools, wasmtime=rt)
        k = Karma(BEING, ws, profile=prof)
        try:
            k.shell(["noop"])
        except ToolNotPermitted as e:
            assert "digest" in str(e), str(e)
        else:
            raise AssertionError("module with a wrong digest was executed")


def test_argv_is_mapped_onto_the_runtime():
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        rt = _fake_wasmtime(tools)
        mod = os.path.join(tools, "noop.wasm")
        with open(mod, "wb") as f:
            f.write(b"\0asm\x01\0\0\0")
        _toolset(tools, {"noop": {"module": "noop.wasm",
                                  "sha256": H_hex(open(mod, "rb").read())}})
        prof = WasmWasiProfile(ws, tools_dir=tools, wasmtime=rt)

        argv = prof.wasm_argv(["noop", "alpha"], prof.root)
        assert argv[0] == rt and argv[1] == "run", argv
        assert argv[2] == "--dir", argv
        assert argv[3] == f"{prof.root}::/work", argv
        assert argv[4] == mod and argv[5] == "--" and argv[6] == "alpha", argv
        # exactly one directory is preopened — nothing else is reachable
        assert argv.count("--dir") == 1, argv

        r = prof.run(["noop", "alpha"])
        assert r.ok, r.as_dict()
        assert "alpha" in r.stdout and "/work" in r.stdout, r.stdout


def test_path_confinement_is_inherited():
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        rt = _fake_wasmtime(tools)
        _toolset(tools, {"noop": {"module": "noop.wasm", "sha256": "00" * 32}})
        prof = WasmWasiProfile(ws, tools_dir=tools, wasmtime=rt)
        try:
            prof.resolve("../../etc/passwd")
        except SandboxEscape:
            pass
        else:
            raise AssertionError("stronger profile relaxed path confinement")


def test_declaration_is_honest():
    st = profile_status(["reference", "wasm-wasi"])
    assert st["reference"]["available"] is True, st["reference"]
    assert "microvm" in st, sorted(st)
    assert st["microvm"]["available"] is False, st["microvm"]

    try:
        resolve_profile("microvm", tempfile.gettempdir())
    except ProfileUnavailable:
        pass
    else:
        raise AssertionError("reserved profile resolved instead of refusing")

    try:
        resolve_profile("nonesuch", tempfile.gettempdir())
    except ProfileUnavailable:
        pass
    else:
        raise AssertionError("unknown profile resolved instead of refusing")


def test_declared_readiness_equals_executable_readiness():
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        rt = _fake_wasmtime(tools)

        # a) a manifest naming a GHOST module must not report ready
        _toolset(tools, {"ghost": {"module": "missing.wasm",
                                   "sha256": "00" * 32}})
        prof = WasmWasiProfile(ws, tools_dir=tools, wasmtime=rt)
        ok, reason = prof.available()
        assert not ok, "a ghost module was advertised as ready"
        assert "ghost" in reason, reason
        cap = prof.capabilities()
        assert cap["available"] is False, cap
        assert cap["toolset_ready"] == [], cap
        assert "ghost" in cap["toolset_broken"], cap
        # and the promise the declaration makes is kept: what is declared
        # unready is exactly what refuses at execution
        try:
            prof.run(["ghost"])
        except ProfileUnavailable:
            pass
        else:
            raise AssertionError("ghost module executed")

        # b) a DRIFTED digest is likewise not ready, and refuses precisely
        real = os.path.join(tools, "real.wasm")
        with open(real, "wb") as f:
            f.write(b"\0asm\x01\0\0\0")
        _toolset(tools, {"drift": {"module": "real.wasm",
                                   "sha256": "cd" * 32}})
        prof = WasmWasiProfile(ws, tools_dir=tools, wasmtime=rt)
        assert prof.available()[0] is False, prof.available()
        try:
            prof.run(["drift"])
        except ToolNotPermitted as e:
            assert "digest" in str(e), str(e)
        else:
            raise AssertionError("drifted module executed")

        # c) one broken entry must NOT darken a boundary that still works
        good = H_hex(open(real, "rb").read())
        _toolset(tools, {"drift": {"module": "real.wasm", "sha256": "cd" * 32},
                         "good": {"module": "real.wasm", "sha256": good}})
        prof = WasmWasiProfile(ws, tools_dir=tools, wasmtime=rt)
        ok, reason = prof.available()
        assert ok, f"one bad entry took the whole profile down: {reason}"
        cap = prof.capabilities()
        assert cap["toolset_ready"] == ["good"], cap
        assert list(cap["toolset_broken"]) == ["drift"], cap
        assert cap["manifest_signed"] is False, "unsigned manifest overclaimed"
        assert len(cap["toolset_hash"]) == 64, cap["toolset_hash"]
        assert prof.run(["good"]).ok


if __name__ == "__main__":
    tests = [test_reference_is_a_named_profile,
             test_missing_runtime_fails_closed,
             test_refusal_is_witnessed,
             test_tool_outside_the_fixed_set_is_refused,
             test_digest_mismatch_is_refused,
             test_argv_is_mapped_onto_the_runtime,
             test_path_confinement_is_inherited,
             test_declaration_is_honest,
             test_declared_readiness_equals_executable_readiness]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\nisolation profiles — {len(tests)}/{len(tests)} checks green")
