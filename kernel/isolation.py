"""kernel/isolation.py — the isolation-profile seam (build v0.6.4).

Karma has always executed actions in ONE way: a real OS process, fenced from
the outside by path confinement, rlimits, an environment scrub and a wall
clock. That fence is honest but it is a DENY-LIST: the child holds the full
system-call surface of the kernel and we subtract from it. Anything we did
not think to subtract remains.

This module introduces the seam so a node can execute inside a DIFFERENT
boundary without Karma's governance, witnessing or provenance changing at
all. Three profiles are foreseen; two exist here.

  reference   — the v0.6.3 sandbox, unchanged. Process-level confinement.
                Arbitrary argv. The baseline every node can run.

  wasm-wasi   — execution inside a WebAssembly module under WASI. The module
                cannot EXPRESS a system call it was not granted: no
                filesystem beyond the directories the host preopens, no
                sockets, no fork, no exec. An ALLOW-LIST boundary enforced by
                the runtime rather than subtracted from the kernel.

                Consequence, stated plainly: arbitrary shell does not exist
                here. The profile executes a FIXED SET OF PRECOMPILED TOOLS,
                each pinned by digest in a plain manifest — the digest is
                verified on every execution, but the manifest itself is NOT
                signed in this build, and nothing yet witnesses the act of
                adding a tool. A narrower action surface is the point of the
                profile, not a shortcoming of the implementation.

                What is still owed, named here rather than implied: by
                ADR-015 adding an executable tool is an L2 capability
                mutation and belongs in a Profile Gauntlet. Until that gate
                exists, the toolset digest travels in capabilities and in
                Karma's provenance, so a change to what the being's hand can
                reach is at least VISIBLE even though it is not yet governed.

  microvm     — not implemented. Reserved so the registry does not have to
                change shape when it lands.

FAIL CLOSED. If a profile is declared and its runtime is not present on this
host, the action is REFUSED — never silently downgraded to a weaker profile.
A downgrade would let a node believe it is acting inside a boundary it is not
inside, and the witness plane cannot save it: by INV-9 the witness observes
and does not intervene, so a record written after the fact restores nothing.
The node instead DECLARES the unavailability in its capabilities, so work
that needs the profile is never routed to it. Both paths — refusal and
execution — are witnessed by Karma exactly as before.

DEPENDENCY POSTURE. wasmtime is invoked as a SYSTEM BINARY through the
existing sandbox, not as a Python binding: the codebase stays stdlib-only and
the runtime becomes a declared host requirement that enters the SBOM through
the ordinary supply-chain stream.
"""
from __future__ import annotations

import json
import os
import shutil
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.crypto import H_hex                                    # noqa: E402
from kernel.karma import (ActionResult, ProfileUnavailable,        # noqa: E402
                          Sandbox, ToolNotPermitted)

TOOLSET_SCHEMA = "jjdai.toolset/v1"
DEFAULT_WASMTIME = "wasmtime"

#: Why a declared tool is not executable. Added in v0.6.6 because "broken"
#: was one word for two different events with two different owners: a module
#: that is absent is an OPERATIONS fact (someone shipped the manifest without
#: the artifact), while a module whose digest has drifted from its pin is a
#: SECURITY fact (the artifact under the pin is not the artifact that was
#: pinned). Merging them into one alert guarantees that the second is read as
#: the first, because the first is common and the second is rare.
TOOL_OK = "OK"
TOOL_NOT_PERMITTED = "NOT_PERMITTED"        # not in the fixed toolset
TOOL_OUTSIDE_ROOT = "OUTSIDE_ROOT"          # path escapes the toolset dir
TOOL_MODULE_MISSING = "MODULE_MISSING"      # declared, artifact absent
TOOL_UNPINNED = "UNPINNED"                  # manifest entry carries no digest
TOOL_DIGEST_DRIFT = "DIGEST_DRIFT"          # artifact != pinned digest

#: Codes that must never be reported as routine operational noise.
TOOL_SECURITY_CODES = (TOOL_DIGEST_DRIFT, TOOL_OUTSIDE_ROOT)


def _fail(cls, code: str, msg: str):
    """Raise-ready exception carrying a machine-readable cause."""
    e = cls(msg)
    e.code = code
    return e


class WasmWasiProfile(Sandbox):
    """Capability-scoped execution: a fixed toolset of precompiled modules.

    Path confinement, rlimits, the environment scrub and the streaming output
    cap are INHERITED unchanged from the reference sandbox — this profile
    narrows what may execute, it does not relax anything the baseline already
    enforces. Defence in depth: the wasm runtime is itself launched inside the
    reference fence.
    """

    NAME = "wasm-wasi"

    def __init__(self, root: str, *, tools_dir: str = None,
                 wasmtime: str = DEFAULT_WASMTIME, guest_dir: str = "/work",
                 **kw):
        super().__init__(root, **kw)
        self.tools_dir = os.path.realpath(
            tools_dir or os.path.join(os.path.dirname(__file__), "..",
                                      "deploy", "wasm-toolset"))
        self.wasmtime = wasmtime
        self.guest_dir = guest_dir

    # ---- the fixed toolset ---- #
    def manifest_path(self) -> str:
        return os.path.join(self.tools_dir, "toolset.json")

    def toolset(self) -> dict:
        """{tool_name: {module, sha256}} or {} when unreadable.

        Unreadable is not an error here — availability reports it, and every
        execution path re-checks. A profile that cannot name its tools simply
        has none, and every action against it is refused.
        """
        try:
            with open(self.manifest_path(), encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}
        if doc.get("schema") != TOOLSET_SCHEMA:
            return {}
        tools = doc.get("tools")
        return tools if isinstance(tools, dict) else {}

    def toolset_status(self) -> dict:
        """{tool: (ok, reason)} — per-tool EXECUTABLE readiness.

        Declared readiness must equal executable readiness. Reporting a
        profile ready because a manifest exists, while a module it names is
        missing or has drifted from its digest, hands the network a promise
        the node cannot keep: work is routed here on the strength of the
        declaration and then refused at execution. Preventing exactly that
        is what the declaration is for.
        """
        out = {}
        for tool in sorted(self.toolset()):
            try:
                self._module_for(tool)
            except (ToolNotPermitted, ProfileUnavailable) as e:
                out[tool] = (False, str(e))
            else:
                out[tool] = (True, "")
        return out

    def toolset_report(self) -> dict:
        """{tool: {"ok", "code", "reason"}} — readiness WITH its cause.

        toolset_status() is kept unchanged beside this: it is what the v0.6.4
        readiness logic and its checks were written against, and changing a
        return shape to add a field is how a build acquires a regression it
        did not need.
        """
        out = {}
        for tool in sorted(self.toolset()):
            try:
                self._module_for(tool)
            except (ToolNotPermitted, ProfileUnavailable) as e:
                out[tool] = {"ok": False,
                             "code": getattr(e, "code", "UNKNOWN"),
                             "reason": str(e)}
            else:
                out[tool] = {"ok": True, "code": TOOL_OK, "reason": ""}
        return out

    def toolset_hash(self) -> str:
        """A digest over the RESOLVED toolset (names + pinned digests).

        Travels in capabilities and in Karma's provenance so a change to
        what the being's hand can reach is visible in the record, pending
        the L2 gate that will make it governed."""
        items = sorted((t, (e or {}).get("sha256", ""))
                       for t, e in self.toolset().items())
        return H_hex(json.dumps(items, sort_keys=True,
                                separators=(",", ":")).encode())

    def _runtime_ready(self) -> tuple[bool, str]:
        """Host-level facts only: is there a runtime, and a manifest to read.

        Kept apart from available() so a refusal names the RIGHT cause. A
        missing runtime is a host condition; a bad tool is a tool condition;
        collapsing them would report "profile unavailable" for what is
        really "that module drifted from its digest".
        """
        if shutil.which(self.wasmtime) is None:
            return False, (f"wasm runtime {self.wasmtime!r} not found on this "
                           f"host — profile {self.NAME!r} cannot execute")
        if not os.path.exists(self.manifest_path()):
            return False, (f"toolset manifest missing at "
                           f"{self.manifest_path()!r}")
        if not self.toolset():
            return False, (f"toolset manifest at {self.manifest_path()!r} is "
                           f"empty or not schema {TOOLSET_SCHEMA}")
        return True, ""

    def available(self) -> tuple[bool, str]:
        ok, reason = self._runtime_ready()
        if not ok:
            return False, reason
        # Readiness is PER TOOL, and the profile is ready when at least one
        # declared tool can actually run. Two failure modes are being kept
        # apart deliberately: a manifest naming a ghost module must not let
        # the node advertise a capability it cannot honour (the audit
        # finding), and one drifted entry must not take the whole boundary
        # dark (the obvious over-correction). The router reads
        # toolset_ready, not the profile flag alone.
        status = self.toolset_status()
        ready = [t for t, (ok, _) in status.items() if ok]
        if not ready:
            broken = {t: why for t, (ok, why) in status.items() if not ok}
            first = sorted(broken)[0]
            return False, (f"no declared tool is executable — "
                           f"{len(broken)} broken, e.g. {first!r}: "
                           f"{broken[first]}")
        return True, ""

    def capabilities(self) -> dict:
        ok, reason = self.available()
        status = self.toolset_status()
        return {"profile": self.NAME, "execution": "wasm-wasi",
                "arbitrary_argv": False, "available": ok,
                "unavailable_reason": reason,
                "runtime": self.wasmtime,
                "runtime_path": shutil.which(self.wasmtime),
                "toolset": sorted(self.toolset()),
                "toolset_ready": sorted(t for t, (o, _) in status.items() if o),
                "toolset_broken": {t: why for t, (o, why) in status.items()
                                   if not o},
                "toolset_codes": {t: r["code"] for t, r
                                  in self.toolset_report().items()
                                  if not r["ok"]},
                "toolset_hash": self.toolset_hash(),
                "manifest_signed": False,
                "fail_closed": True}

    # ---- module resolution, pinned by digest ---- #
    def _module_for(self, tool: str) -> str:
        entry = self.toolset().get(tool)
        if not isinstance(entry, dict):
            raise _fail(ToolNotPermitted, TOOL_NOT_PERMITTED,
                f"tool {tool!r} is not in the fixed toolset of profile "
                f"{self.NAME!r} — refused (arbitrary execution does not "
                f"exist in this profile)")
        module = os.path.realpath(os.path.join(self.tools_dir,
                                               entry.get("module", "")))
        tools_root = self.tools_dir + os.sep
        if not module.startswith(tools_root):
            raise _fail(ToolNotPermitted, TOOL_OUTSIDE_ROOT,
                f"module for tool {tool!r} resolves outside the toolset "
                f"directory — refused")
        if not os.path.exists(module):
            raise _fail(ProfileUnavailable, TOOL_MODULE_MISSING,
                f"module for tool {tool!r} declared but missing at "
                f"{module!r} — refused")
        want = (entry.get("sha256") or "").lower()
        with open(module, "rb") as f:
            got = H_hex(f.read())
        if not want:
            # A manifest entry with no pin is a MANIFEST DEFECT, not evidence
            # of tampering. Both refuse execution; only one of them should
            # wake anybody up at 3am.
            raise _fail(ToolNotPermitted, TOOL_UNPINNED,
                f"manifest entry for tool {tool!r} carries no sha256 pin — "
                f"refused (an unpinned module is an unverifiable module)")
        if got != want:
            raise _fail(ToolNotPermitted, TOOL_DIGEST_DRIFT,
                f"module digest mismatch for tool {tool!r}: manifest pins "
                f"{want}, module hashes {got} — refused")
        return module

    def wasm_argv(self, argv: list, workdir: str) -> list:
        """The command handed to the reference fence. Split out so the
        mapping is testable without a runtime present."""
        module = self._module_for(argv[0])
        return [self.wasmtime, "run",
                "--dir", f"{workdir}::{self.guest_dir}",
                module, "--", *[str(a) for a in argv[1:]]]

    def run(self, argv: list, *, cwd: str = None) -> ActionResult:
        if not argv:
            raise ToolNotPermitted("empty argv — refused")
        ok, reason = self._runtime_ready()
        if not ok:
            raise ProfileUnavailable(reason)
        # tool resolution happens inside wasm_argv and raises the precise
        # refusal — not permitted, missing module, or digest drift
        workdir = self.resolve(cwd) if cwd else self.root
        return super().run(self.wasm_argv(argv, workdir), cwd=cwd)


#: Registry. microvm is named but deliberately absent — declaring a profile
#: we cannot enforce would be exactly the silent downgrade this module exists
#: to prevent.
PROFILES = {Sandbox.NAME: Sandbox, WasmWasiProfile.NAME: WasmWasiProfile}
RESERVED = ("microvm",)


def resolve_profile(name: str, root: str, **kw) -> Sandbox:
    """Construct a profile by name. Unknown or reserved-but-unimplemented
    names raise rather than falling back to the baseline."""
    if name in RESERVED:
        raise ProfileUnavailable(
            f"isolation profile {name!r} is reserved but not implemented in "
            f"this build — refused rather than downgraded")
    cls = PROFILES.get(name)
    if cls is None:
        raise ProfileUnavailable(
            f"unknown isolation profile {name!r}; known: "
            f"{sorted(PROFILES)} (reserved: {list(RESERVED)})")
    return cls(root, **kw)


def profile_status(profiles: list = None, root: str = None) -> dict:
    """What the node DECLARES about its isolation surface.

    Used by capabilities/readiness so the network never routes an action to a
    node that cannot execute it inside the required boundary. Declaring the
    inability is the honest form of a fallback: refuse the work, do not do
    the work in a weaker box.
    """
    import tempfile
    base = root or tempfile.gettempdir()
    out = {}
    for name in (profiles or sorted(PROFILES)):
        try:
            p = resolve_profile(name, base)
        except ProfileUnavailable as e:
            out[name] = {"profile": name, "available": False,
                         "unavailable_reason": str(e)}
            continue
        out[name] = p.capabilities()
    for name in RESERVED:
        out.setdefault(name, {"profile": name, "available": False,
                              "unavailable_reason": "reserved, not "
                                                    "implemented in this build"})
    return out
