#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The wasm boundary against a REAL runtime. Opt-in group.

    JJDAI_WASMTIME=wasmtime JJDAI_WASM_MODULE=/path/probe.wasm \
        python3 scripts/run_acceptance.py live

Required for the Ф0 gate on each target host class (hardened Linux x86-64
and macOS Apple silicon), where a real wasmtime IS provisioned. Absent a
runtime this module raises rather than passing quietly: a group that skips
when it cannot run is a group that reports on hosts it never visited.

v0.6.9 REWROTE this file, and the rewrite is the substance of ADR-022 D9
rather than an adjustment to it. L-1 used to read WORKSPACE REACHABLE and
assert that a preopened directory was readable and writable through the
guest path — faithful to the definition of `pure` that r6.9.1 removed, which
permitted writing inside one preopened directory and therefore drew no
boundary at all. L-3 asserted `argv.count("--dir") == 1`. Both would now
pass on a build that had quietly kept the preopen.

  L-1  NO PREOPEN: the guest is handed no directory, and a path it asks for
       by name is not there to open.
  L-2  EXTERNAL FILESYSTEM UNREACHABLE: no absolute path outside anything is
       visible, which after L-1 is the same statement made about the host.
  L-3  NO NETWORK, NO CLOCK, NO ENTROPY, EMPTY ENVIRON: the invocation
       grants none of them and the module cannot import them.
  L-4  NO ARBITRARY EXECUTABLE: a host binary cannot be launched through the
       profile; only a manifest-declared module runs.
  L-5  DIGEST TAMPERING FAILS CLOSED: flipping a byte of a pinned module
       refuses execution rather than running the altered code.
  L-6  FUEL: exhausting the declared fuel gives LIMIT_FUEL and no output.
  L-7  GUEST MEMORY: growing past the declared linear memory gives
       LIMIT_MEMORY, and the runtime itself is not killed instead.
  L-8  OUTPUT: exceeding the declared TOTAL output gives LIMIT_OUTPUT with
       the partial output discarded.
  L-9  STDIN: what this process writes is what the guest reads, and nothing
       of the host's own stdin reaches it.

L-6 and L-7 are what the hermetic suite cannot prove: the shim answers the
capability probe, and only a real wasmtime can exhaust real fuel. The exact
spelling of the limit flags is a property of the installed runtime, and this
group is where it is verified — `_runtime_supports_limits()` refuses a
runtime that does not accept them, so a red here is a runtime that would
have silently ignored a limit.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai import provenance as prv                               # noqa: E402
from jjdai.crypto import H_hex, SigningKey                        # noqa: E402
from kernel import toolset as ts                                  # noqa: E402
from kernel import wasm_pure as wp                                # noqa: E402
from kernel.isolation import WasmWasiProfile                      # noqa: E402
from kernel.karma import ProfileUnavailable, ToolNotPermitted     # noqa: E402

WASMTIME = os.environ.get("JJDAI_WASMTIME", "wasmtime")
#: A tool module for the live checks. Point this at a WASI build of a small
#: utility compiled against a NARROWED target: a module linked against the
#: full wasi-libc imports `fd_prestat_get` and will not instantiate, which
#: is stated in advance by D9 and is not a defect of this group.
MODULE = os.environ.get("JJDAI_WASM_MODULE", "")

_SK = SigningKey(b"\x61" * 32)
_KEY_ID = "live-toolset-key"

DEFAULT_LIMITS = {"fuel": 10 ** 8, "guest_memory_bytes": 16 << 20,
                  "output_bytes": 1 << 16}


def _resolver(key_id):
    if key_id != _KEY_ID:
        return None
    return {"public": _SK.public.hex(),
            "key_domain": prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
            "revoked": False}


def _require_runtime():
    if shutil.which(WASMTIME) is None:
        raise AssertionError(
            f"L-*: no wasm runtime at {WASMTIME!r}. This group is opt-in and "
            f"must not be run without one — set JJDAI_WASMTIME or install "
            f"wasmtime on this host. (Ф0 gate requires it on every target "
            f"host class; hermetic CI runs the shim suite instead.)")
    if not MODULE or not os.path.exists(MODULE):
        raise AssertionError(
            "L-*: set JJDAI_WASM_MODULE to a wasm32-wasi module to exercise "
            "the live boundary. The seam is proven hermetically; this group "
            "proves the RUNTIME, and it cannot do that without one.")


def _profile(ws, tools, *, digest=None, limits=None):
    dest = os.path.join(tools, "probe.wasm")
    shutil.copyfile(MODULE, dest)
    with open(dest, "rb") as f:
        real = H_hex(f.read())
    doc = {"schema": prv.SCHEMA_TOOLSET_MANIFEST,
           "authorization_form": prv.AUTHORIZATION_FORM_INTERIM,
           "sunset_condition": prv.SUNSET_CONDITION_GAUNTLET,
           "tools": {"probe": {"module": "probe.wasm",
                               "sha256": digest or real,
                               "effect_class": "pure",
                               "recipe_hash": "ef" * 32,
                               "limits": dict(limits or DEFAULT_LIMITS)}}}
    doc["signer"] = {"key_id": _KEY_ID,
                     "key_domain": prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
                     "domain": prv.DOMAIN_TOOLSET_MANIFEST}
    doc["signature"] = _SK.sign(ts.signing_bytes(doc)).hex()
    with open(os.path.join(tools, ts.MANIFEST_FILE), "w",
              encoding="utf-8") as f:
        json.dump(doc, f)
    return WasmWasiProfile(ws, tools_dir=tools, wasmtime=WASMTIME,
                           key_resolver=_resolver)


def test_live_no_preopen_directory():
    """L-1"""
    _require_runtime()
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        with open(os.path.join(ws, "inside.txt"), "w", encoding="utf-8") as f:
            f.write("must-never-be-read")
        prof = _profile(ws, tools)
        ok, reason = prof.available()
        assert ok, reason
        argv = prof.wasm_argv(["probe"], prof.root)
        assert not any(str(a).startswith(("--dir", "--mapdir"))
                       for a in argv), argv
        for target in ("/work/inside.txt", "inside.txt",
                       os.path.join(ws, "inside.txt")):
            r = prof.run(["probe", target])
            assert "must-never-be-read" not in r.stdout, (
                f"the guest read {target}: `pure` is ZERO preopens, not "
                f"'writes only inside its own directory' — the formulation "
                f"r6.9.1 removed")


def test_live_external_filesystem_is_unreachable():
    """L-2"""
    _require_runtime()
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        prof = _profile(ws, tools)
        for target in ("/etc/hostname", "/etc/passwd", "../../etc/passwd"):
            r = prof.run(["probe", target])
            assert not r.ok or r.stdout.strip() == "", \
                f"module reached {target}: {r.as_dict()}"


def test_live_no_network_clock_entropy_or_environ():
    """L-3"""
    _require_runtime()
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        prof = _profile(ws, tools)
        joined = " ".join(prof.wasm_argv(["probe"], prof.root))
        for granted in ("inherit-network", "--allow-net", "inherit-env",
                        "--env", "inherit-stdio"):
            assert granted not in joined, \
                f"the mapping grants a capability: {joined}"
        # and the module itself does not IMPORT them — checked on bytes, so
        # the answer does not depend on the input reaching the call
        with open(os.path.join(tools, "probe.wasm"), "rb") as f:
            imports = wp.check_pure_imports(f.read())
        names = {i.name for i in imports}
        assert not (names & {"clock_time_get", "random_get", "sock_send"})


def test_live_no_arbitrary_executable():
    """L-4"""
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
    """L-5"""
    _require_runtime()
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        prof = _profile(ws, tools)
        assert prof.available()[0]
        module = os.path.join(tools, "probe.wasm")
        data = bytearray(open(module, "rb").read())
        data[-1] ^= 0x01
        with open(module, "wb") as f:
            f.write(bytes(data))
        try:
            prof.run(["probe"])
        except (ToolNotPermitted, ProfileUnavailable):
            return
        raise AssertionError("tampered module executed")


def _breach(limits, argv, *, input_bytes=b""):
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        prof = _profile(ws, tools, limits=limits)
        ok, reason = prof.available()
        assert ok, (
            f"the runtime does not accept the limit flags this build passes "
            f"({reason}). That is the point of this check: a limit a runtime "
            f"ignores is not a limit, so the profile refuses rather than "
            f"executing without it")
        return prof.run(argv, input_bytes=input_bytes)


def test_live_fuel_exhaustion_is_named():
    """L-6"""
    _require_runtime()
    r = _breach(dict(DEFAULT_LIMITS, fuel=1), ["probe", "--spin"])
    assert r.ok is False, "fuel of 1 did not stop the module"
    assert r.detail.get("verdict") == wp.PURE_LIMIT_FUEL, r.detail
    assert r.stdout == "", "a partial result survived a limit breach"


def test_live_guest_memory_limit_is_named():
    """L-7"""
    _require_runtime()
    r = _breach(dict(DEFAULT_LIMITS, guest_memory_bytes=1 << 16),
                ["probe", "--grow"])
    assert r.ok is False
    assert r.detail.get("verdict") == wp.PURE_LIMIT_MEMORY, (
        f"{r.detail}. If the runtime itself died instead, the guest limit "
        f"was applied to the host process — the two are separate numbers")


def test_live_total_output_limit_is_named():
    """L-8"""
    _require_runtime()
    r = _breach(dict(DEFAULT_LIMITS, output_bytes=64), ["probe", "--flood"])
    assert r.ok is False
    assert r.detail.get("verdict") == wp.PURE_LIMIT_OUTPUT, r.detail
    assert r.stdout == "", (
        "a truncated result from a deterministic tool cannot be told apart "
        "from a complete one")


def test_live_stdin_is_what_this_process_wrote():
    """L-9"""
    _require_runtime()
    payload = b"deterministic-input"
    with tempfile.TemporaryDirectory() as ws, \
            tempfile.TemporaryDirectory() as tools:
        prof = _profile(ws, tools)
        r = prof.run(["probe", "--echo"], input_bytes=payload)
        assert payload.decode() in r.stdout, r.as_dict()
        r = prof.run(["probe", "--echo"])
        assert r.stdout.strip() == "", (
            "with no input the guest must see EOF, never a descriptor it "
            "was not declared to have")
