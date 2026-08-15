#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_wasm_live — v0.6.4 LIVE acceptance for the wasm-wasi isolation profile
==========================================================================
The hermetic suite exercises the seam against a shim, which proves the
MAPPING and the refusals but not the BOUNDARY. This file proves the boundary
against a real runtime, and it is deliberately NOT in the default acceptance
groups: a check that silently skips itself is not evidence, and a check that
requires an external binary must not be able to turn CI red on a machine that
was never meant to carry it.

    python3 scripts/run_acceptance.py live      # explicit, opt-in
    JJDAI_WASMTIME=/path/to/wasmtime python3 tests/live/test_wasm_live.py

Required for the Ф0 gate on each target host (Ubuntu 24 and macOS), where a
real wasmtime IS provisioned. Absent a runtime this module raises rather than
passing quietly.

  L-1  WORKSPACE REACHABLE: the preopened directory is readable and
       writable through the guest path, and only through it.
  L-2  EXTERNAL FILESYSTEM UNREACHABLE: paths outside the workspace are not
       visible to the module even when it asks for them by absolute path.
  L-3  NO NETWORK: the module holds no socket capability.
  L-4  NO ARBITRARY EXECUTABLE: a host binary cannot be launched through the
       profile; only a manifest-declared module runs.
  L-5  DIGEST TAMPERING FAILS CLOSED: flipping a byte of a pinned module
       refuses execution rather than running the altered code.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.crypto import H_hex                                     # noqa: E402
from kernel.isolation import WasmWasiProfile                       # noqa: E402
from kernel.karma import ProfileUnavailable, ToolNotPermitted      # noqa: E402

WASMTIME = os.environ.get("JJDAI_WASMTIME", "wasmtime")
#: A tool module for the live checks. Point this at a WASI build of a small
#: utility (`cat`, `wc`, or a purpose-built probe compiled to wasm32-wasi).
MODULE = os.environ.get("JJDAI_WASM_MODULE", "")


def _require_runtime():
    if shutil.which(WASMTIME) is None:
        raise AssertionError(
            f"L-*: no wasm runtime at {WASMTIME!r}. This group is opt-in and "
            f"must not be run without one — set JJDAI_WASMTIME or install "
            f"wasmtime on this host. (Ф0 gate requires it on every target "
            f"host; hermetic CI runs the shim suite instead.)")
    if not MODULE or not os.path.exists(MODULE):
        raise AssertionError(
            "L-*: set JJDAI_WASM_MODULE to a wasm32-wasi module to exercise "
            "the live boundary. The seam is proven hermetically; this group "
            "proves the RUNTIME, and it cannot do that without one.")


def _profile(ws: str, tools: str, *, digest: str = None) -> WasmWasiProfile:
    import json
    dest = os.path.join(tools, "probe.wasm")
    shutil.copyfile(MODULE, dest)
    with open(dest, "rb") as f:
        real = H_hex(f.read())
    with open(os.path.join(tools, "toolset.json"), "w", encoding="utf-8") as f:
        json.dump({"schema": "jjdai.toolset/v1",
                   "tools": {"probe": {"module": "probe.wasm",
                                       "sha256": digest or real}}}, f)
    return WasmWasiProfile(ws, tools_dir=tools, wasmtime=WASMTIME)


def test_live_workspace_is_reachable():
    _require_runtime()
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        with open(os.path.join(ws, "inside.txt"), "w", encoding="utf-8") as f:
            f.write("visible-to-the-module")
        prof = _profile(ws, tools)
        ok, reason = prof.available()
        assert ok, reason
        r = prof.run(["probe", "/work/inside.txt"])
        assert "visible-to-the-module" in r.stdout, r.as_dict()


def test_live_external_filesystem_is_unreachable():
    _require_runtime()
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools, \
            tempfile.NamedTemporaryFile("w", suffix=".txt",
                                        delete=False) as outside:
        outside.write("must-never-be-read")
        outside.flush()
        prof = _profile(ws, tools)
        for target in (outside.name, "/etc/hostname", "/etc/passwd"):
            r = prof.run(["probe", target])
            assert "must-never-be-read" not in r.stdout, \
                f"module read outside the workspace: {target}"
            assert not r.ok or r.stdout.strip() == "", \
                f"module reached {target}: {r.as_dict()}"
        os.unlink(outside.name)


def test_live_no_network_capability():
    _require_runtime()
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        prof = _profile(ws, tools)
        argv = prof.wasm_argv(["probe"], prof.root)
        joined = " ".join(argv)
        for granted in ("--wasi", "inherit-network", "--allow-net", "-S"):
            assert granted not in joined, \
                f"the mapping grants a network capability: {joined}"
        # exactly one directory is preopened, and it is the workspace
        assert argv.count("--dir") == 1, argv
        assert argv[argv.index("--dir") + 1].startswith(prof.root), argv


def test_live_no_arbitrary_executable():
    _require_runtime()
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        prof = _profile(ws, tools)
        for forbidden in (["/bin/sh", "-c", "id"], ["/bin/ls"], ["curl"]):
            try:
                prof.run(forbidden)
            except ToolNotPermitted:
                continue
            raise AssertionError(f"host binary launched via profile: "
                                 f"{forbidden}")


def test_live_digest_tampering_fails_closed():
    _require_runtime()
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        prof = _profile(ws, tools)
        assert prof.available()[0]
        # flip one byte AFTER the manifest pinned the original
        module = os.path.join(tools, "probe.wasm")
        data = bytearray(open(module, "rb").read())
        data[-1] ^= 0x01
        with open(module, "wb") as f:
            f.write(bytes(data))
        ok, reason = prof.available()
        assert not ok, "a tampered module was still advertised as ready"
        try:
            prof.run(["probe"])
        except (ToolNotPermitted, ProfileUnavailable):
            pass
        else:
            raise AssertionError("tampered module executed")


if __name__ == "__main__":
    tests = [test_live_workspace_is_reachable,
             test_live_external_filesystem_is_unreachable,
             test_live_no_network_capability,
             test_live_no_arbitrary_executable,
             test_live_digest_tampering_fails_closed]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\nwasm live boundary — {len(tests)}/{len(tests)} checks green")
