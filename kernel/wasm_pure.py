# -*- coding: utf-8 -*-
"""
kernel.wasm_pure — the `pure` effect class as a boundary, not a description
===========================================================================
ADR-022 D9. `pure` used to be a sentence in the roadmap: "no writes outside
one preopen directory". That formulation says writing INSIDE the directory
is allowed, so it was never a boundary at all; r6.9.1 replaced it and this
module is what makes the replacement executable.

A tool is `pure` when every one of these holds. Violating any one refuses
INSTANTIATION — not the call:

* zero preopen directories, neither read nor write;
* an allowlist of WASI imports checked when the module is linked: read
  stdin, write stdout and stderr, exit. An import outside the list is a
  link failure, not a trap at the moment it is reached;
* clocks and entropy denied — `clock_time_get` and `random_get` are outside
  the allowlist and named here so a refusal cites the clause rather than a
  generic "not permitted";
* `environ` empty, `argv` fixed, locale fixed;
* fuel, memory and output-size limits whose breach gives a deterministic
  refusal with a reason code, never a truncated output.

WHY THE IMPORT CHECK IS OURS AND NOT THE RUNTIME'S. A refusal that happens
when execution reaches a forbidden call is a refusal that depends on the
input reaching that call. Two runs of the same module then differ in whether
the boundary held, which is the opposite of what a deterministic tool is
for. So the imports are read out of the module bytes BEFORE the runtime is
invoked, by the parser below: same answer every time, on any host, with or
without wasmtime installed. The runtime's own sandboxing stays in place
underneath as defence in depth; it is not what this boundary rests on.

CONSEQUENCE, STATED IN ADVANCE (D9, O-3). A module linked against the full
`wasi-libc` imports more than this allowlist — `fd_prestat_get` and
`fd_prestat_dir_name` alone are enough, since libc enumerates preopens at
startup and there are none to enumerate. Such a module does not instantiate.
The starter set must be built against a narrowed target, and a tool that
cannot be is not in the set. Whether all four starter tools can be built
that way AND reproduce byte for byte is ADR-022's open question O-3, and it
is answered on a host with a real toolchain, not asserted here.
"""
from __future__ import annotations

import struct
from collections import namedtuple

WASM_MAGIC = b"\x00asm"
WASM_VERSION = 1

#: Refusal codes. They sit beside the toolset codes in `kernel.isolation`
#: and are kept distinct from them: "this module asks for more than `pure`
#: allows" is a different fact from "this module drifted from its pin", and
#: an operator reading one should never have to guess it meant the other.
PURE_NOT_WASM = "NOT_WASM"
PURE_MALFORMED = "MALFORMED_MODULE"
PURE_IMPORT_DENIED = "IMPORT_DENIED"
PURE_PREOPEN_PRESENT = "PREOPEN_PRESENT"
PURE_LIMIT_FUEL = "LIMIT_FUEL"
PURE_LIMIT_MEMORY = "LIMIT_MEMORY"
PURE_LIMIT_OUTPUT = "LIMIT_OUTPUT"

WASI_MODULE = "wasi_snapshot_preview1"

#: Exactly what D9 names: read stdin, write stdout and stderr, exit.
PURE_IMPORT_ALLOWLIST = frozenset({
    (WASI_MODULE, "fd_read"),
    (WASI_MODULE, "fd_write"),
    (WASI_MODULE, "proc_exit"),
})

#: Denied by the allowlist like everything else, but named so the refusal
#: can say WHICH clause of D9 it is. A tool that reads the clock or draws
#: entropy is not deterministic, and a non-deterministic tool cannot be
#: replayed by a panel — which is the whole reason the hand is deterministic.
PURE_DENIED_BY_NAME = {
    "clock_time_get": "clocks are denied: a tool that reads time is not "
                      "replayable, and a panel corroborates by replaying",
    "clock_res_get": "clocks are denied: see clock_time_get",
    "random_get": "entropy is denied: a tool that draws randomness gives a "
                  "different answer to the same question",
    "sock_accept": "the network is denied outright",
    "sock_recv": "the network is denied outright",
    "sock_send": "the network is denied outright",
    "path_open": "there are zero preopen directories, so no path can be "
                 "opened: `pure` is not 'writes only inside its own "
                 "directory', which is the formulation r6.9.1 removed",
    "fd_prestat_get": "there are zero preopen directories to enumerate; a "
                      "module that asks was linked against full wasi-libc "
                      "and must be rebuilt against a narrowed target (O-3)",
    "fd_prestat_dir_name": "see fd_prestat_get",
}


class PureBoundaryError(ValueError):
    """A module or an invocation fails the `pure` boundary."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> PureBoundaryError:
    return PureBoundaryError(code, message)


# --------------------------------------------------------------------------- #
# A minimal reader for the one section that matters
# --------------------------------------------------------------------------- #
#
# Only the import section is parsed. Everything else is skipped by its
# declared length. This is deliberately not a wasm validator: the runtime
# validates, and re-implementing that here would be a second, weaker
# validator whose disagreements with the real one nobody would notice.

Import = namedtuple("Import", "module name kind")

_IMPORT_SECTION = 2
_KINDS = {0x00: "func", 0x01: "table", 0x02: "memory", 0x03: "global"}


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    """Read one unsigned LEB128. Returns (value, next_pos)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise _fail(PURE_MALFORMED,
                        "module truncated inside a LEB128 integer")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise _fail(PURE_MALFORMED, "LEB128 integer too wide to be a "
                                        "length in a well-formed module")


def _name(data: bytes, pos: int) -> tuple[str, int]:
    length, pos = _uleb(data, pos)
    end = pos + length
    if end > len(data):
        raise _fail(PURE_MALFORMED, "module truncated inside a name")
    try:
        return data[pos:end].decode("utf-8"), end
    except UnicodeDecodeError:
        raise _fail(PURE_MALFORMED,
                    "import name is not valid UTF-8") from None


def parse_imports(data: bytes) -> tuple:
    """Every import a module declares, in declaration order.

    Fail-closed on anything it cannot read: a module whose import section
    cannot be parsed is refused rather than treated as importing nothing.
    An unparseable module that reads as `pure` is the worst outcome
    available here.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise _fail(PURE_NOT_WASM, "module bytes expected")
    if len(data) < 8 or bytes(data[:4]) != WASM_MAGIC:
        raise _fail(PURE_NOT_WASM,
                    "not a WebAssembly module: magic header absent")
    version = struct.unpack_from("<I", data, 4)[0]
    if version != WASM_VERSION:
        raise _fail(PURE_NOT_WASM,
                    f"unsupported wasm binary version {version}")
    pos = 8
    imports = []
    while pos < len(data):
        section_id = data[pos]
        pos += 1
        size, pos = _uleb(data, pos)
        end = pos + size
        if end > len(data):
            raise _fail(PURE_MALFORMED,
                        f"section {section_id} declares {size} bytes and the "
                        f"module ends before them")
        if section_id == _IMPORT_SECTION:
            count, p = _uleb(data, pos)
            for _ in range(count):
                mod, p = _name(data, p)
                nm, p = _name(data, p)
                if p >= end:
                    raise _fail(PURE_MALFORMED,
                                "import section ends inside an entry")
                kind = _KINDS.get(data[p], "unknown")
                imports.append(Import(mod, nm, kind))
                p = _skip_descriptor(data, p, end)
        pos = end
    return tuple(imports)


def _skip_descriptor(data: bytes, pos: int, end: int) -> int:
    """Step over one import descriptor. Kind byte, then its payload."""
    if pos >= len(data):
        raise _fail(PURE_MALFORMED, "module ends inside an import descriptor")
    kind = data[pos]
    pos += 1
    if kind == 0x00:                       # func: type index
        _, pos = _uleb(data, pos)
    elif kind == 0x01:                     # table: elem type + limits
        if pos + 1 > len(data):
            raise _fail(PURE_MALFORMED,
                        "module ends inside a table descriptor")
        pos += 1
        pos = _skip_limits(data, pos)
    elif kind == 0x02:                     # memory: limits
        pos = _skip_limits(data, pos)
    elif kind == 0x03:                     # global: valtype + mutability
        if pos + 2 > len(data):
            raise _fail(PURE_MALFORMED,
                        "module ends inside a global descriptor")
        pos += 2
    else:
        raise _fail(PURE_MALFORMED,
                    f"unknown import descriptor kind 0x{kind:02x}")
    if pos > end:
        raise _fail(PURE_MALFORMED, "import descriptor runs past its section")
    return pos


def _skip_limits(data: bytes, pos: int) -> int:
    if pos >= len(data):
        raise _fail(PURE_MALFORMED, "module ends inside a limits descriptor")
    flags = data[pos]
    pos += 1
    _, pos = _uleb(data, pos)              # minimum
    if flags & 0x01:
        _, pos = _uleb(data, pos)          # maximum
    return pos


# --------------------------------------------------------------------------- #
# The boundary itself
# --------------------------------------------------------------------------- #

def check_pure_imports(data: bytes) -> tuple:
    """Refuse a module importing anything outside the `pure` allowlist.

    Returns the parsed imports on success, so a caller can record what was
    actually linked rather than what it assumed.
    """
    imports = parse_imports(data)
    for imp in imports:
        if (imp.module, imp.name) in PURE_IMPORT_ALLOWLIST:
            # The allowlist names FUNCTIONS. A memory, table or global
            # imported under one of those names is a different kind of thing
            # entirely and must not ride in on the name — the audit found
            # `wasi_snapshot_preview1.fd_read` importable as a memory.
            if imp.kind != "func":
                raise _fail(
                    PURE_IMPORT_DENIED,
                    f"{imp.module}.{imp.name} is allowlisted as a FUNCTION "
                    f"and this module imports it as a {imp.kind}. A name is "
                    f"not a permission: an imported memory or table is host "
                    f"state the guest did not have.")
            continue
        why = PURE_DENIED_BY_NAME.get(imp.name)
        detail = f" — {why}" if why else ""
        raise _fail(
            PURE_IMPORT_DENIED,
            f"module imports {imp.module}.{imp.name} ({imp.kind}), which is "
            f"outside the `pure` allowlist{detail}. The allowlist is checked "
            f"at instantiation, not at the call: a boundary that only holds "
            f"when execution happens to reach the forbidden call is a "
            f"boundary that depends on the input (ADR-022 D9).")
    return imports


#: Limits, and the code each breach reports. Values are the manifest's to
#: set per tool; the pairing of breach to code lives here so that exceeding
#: a limit can never be answered with a truncated output — a truncated
#: output is a WRONG ANSWER that looks like an answer.
Limits = namedtuple("Limits",
                    "fuel guest_memory_bytes host_memory_bytes output_bytes")

LIMIT_CODES = {"fuel": PURE_LIMIT_FUEL,
               "guest_memory_bytes": PURE_LIMIT_MEMORY,
               "host_memory_bytes": PURE_LIMIT_MEMORY,
               "output_bytes": PURE_LIMIT_OUTPUT}

#: The guest limit and the host limit are TWO numbers and the first cut used
#: one for both: the per-tool `memory_bytes` was applied as `RLIMIT_AS` over
#: the whole wasmtime process. A guest cap small enough to be meaningful
#: then killed the runtime before the guest started, and the refusal named
#: the guest's limit for the host's death. The guest number bounds the
#: linear memory the module may grow; the host number bounds the process
#: that runs it, and must be larger than the guest's by whatever the runtime
#: itself needs.
GUEST_HOST_HEADROOM = 256 * 1024 * 1024

#: A declared output limit is the authority for its tool, so it needs its
#: own ceiling: the parent buffers up to the cap, and an unbounded number in
#: a manifest would move the denial-of-service from the guest to the
#: governor. Named here rather than left to the flood budget, which is a
#: backstop and not a policy.
MAX_DECLARED_OUTPUT = 8 * 1024 * 1024


def check_limits_declared(limits) -> Limits:
    """Every limit is a positive integer; absence refuses.

    A missing limit is not "unlimited by default": that reading is how a
    fail-open arrives dressed as an omission.
    """
    if not isinstance(limits, dict):
        raise _fail(PURE_MALFORMED, "limits must be declared as a mapping")
    limits = dict(limits)
    # A manifest may declare the host bound or leave it to be derived; what
    # it may NOT do is let one number serve both roles.
    if "host_memory_bytes" not in limits and "guest_memory_bytes" in limits:
        limits["host_memory_bytes"] = (int(limits["guest_memory_bytes"]) +
                                       GUEST_HOST_HEADROOM)
    values = {}
    for field in Limits._fields:
        value = limits.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise _fail(
                PURE_MALFORMED,
                f"limit {field!r} must be a positive integer; a missing "
                f"limit is not 'unlimited by default' (ADR-022 D9)")
        values[field] = value
    if values["output_bytes"] > MAX_DECLARED_OUTPUT:
        raise _fail(
            PURE_MALFORMED,
            f"output_bytes {values['output_bytes']} exceeds the ceiling "
            f"{MAX_DECLARED_OUTPUT}: the parent buffers up to the declared "
            f"limit, so an unbounded one moves the flood from the guest to "
            f"the governor")
    if values["host_memory_bytes"] <= values["guest_memory_bytes"]:
        raise _fail(
            PURE_MALFORMED,
            f"host_memory_bytes ({values['host_memory_bytes']}) must exceed "
            f"guest_memory_bytes ({values['guest_memory_bytes']}): the "
            f"runtime needs room above whatever the guest may grow to, and "
            f"one number for both kills the runtime and calls it a guest "
            f"limit")
    return Limits(**values)


def breach_code(field: str) -> str:
    try:
        return LIMIT_CODES[field]
    except KeyError:
        raise _fail(PURE_MALFORMED, f"unknown limit {field!r}") from None


def check_no_preopens(argv) -> None:
    """Refuse an invocation that would hand the guest a directory.

    Checked on the assembled command rather than on intent, because the
    preopen that mattered — the one r6.9.1 removed from the definition —
    arrived as a flag on exactly this line.
    """
    tokens = [str(a) for a in argv]
    for tok in tokens:
        if tok in ("--dir", "--mapdir") or tok.startswith("--dir=") \
                or tok.startswith("--mapdir="):
            raise _fail(
                PURE_PREOPEN_PRESENT,
                f"invocation carries {tok!r}: `pure` means ZERO preopen "
                f"directories, neither read nor write. The earlier "
                f"formulation allowed writes inside one preopened directory "
                f"and was therefore not a boundary (roadmap r6.9.1).")
