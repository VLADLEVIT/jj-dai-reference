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
                each pinned by digest in a SIGNED manifest (v0.6.9,
                `jjdai.toolset-manifest/v2`): the digest is verified on
                every execution, the manifest's signature under the
                `toolset_authorization` domain is verified at the door, and
                the position it was authorized at is resolved from the
                release that names it, never declared by the manifest. What
                is not yet true is stated where it is owed: the act of
                adding a tool is not witnessed by its own record kind until
                the Profile Gauntlet of Ф3. A narrower action surface is the
                point of the profile, not a shortcoming of the
                implementation.

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
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.crypto import H_hex                                    # noqa: E402
from jjdai import provenance                                      # noqa: E402
from jjdai.custody import check_effect_class                      # noqa: E402
from kernel import toolset as toolset_mod                         # noqa: E402
from kernel import wasm_pure                                      # noqa: E402
from kernel.wasm_pure import (PureBoundaryError, breach_code,     # noqa: E402
                              check_limits_declared,
                              check_no_preopens, check_pure_imports)
from kernel.karma import (ActionResult, ProfileUnavailable,        # noqa: E402
                          Sandbox, ToolNotPermitted)

TOOLSET_SCHEMA = "jjdai.toolset/v1"

#: v0.6.9: the manifest the drop moves to. v1 is still read so a node
#: mid-upgrade reports honestly rather than going dark, but a v1 entry
#: carries no effect class and therefore cannot be executed — see
#: `_module_for`, which refuses it by the absence rather than by the
#: schema version. Refusing by version would say "old file"; refusing
#: by absence says what is actually missing.
TOOLSET_SCHEMA_V2 = provenance.SCHEMA_TOOLSET_MANIFEST
TOOLSET_SCHEMAS = (TOOLSET_SCHEMA, TOOLSET_SCHEMA_V2)

#: The pre-v0.6.9 filename, read only as a fallback. See
#: `manifest_path`.
LEGACY_MANIFEST_FILE = "toolset.json"

#: How the per-tool limits are handed to the runtime. Kept as data so the
#: spelling is in one place and can be probed rather than assumed; wasmtime
#: has moved these flags between releases, and a flag this build guesses
#: wrong is a limit that silently is not applied.
RUNTIME_LIMIT_FLAGS = {
    "fuel": lambda n: ["-W", f"fuel={int(n)}"],
    "memory": lambda n: ["-W", f"max-memory-size={int(n)}"],
}

#: How a runtime reports each breach. wasmtime raises a distinct
#: `OutOfFuel` trap for fuel exhaustion and a memory-growth failure for the
#: linear-memory cap; both must be told apart from an ordinary module error
#: and from a host failure, because D9 requires the breach of a limit to be
#: a NAMED refusal and not an exit code. Matched on the runtime's own text
#: because the CLI gives no machine-readable channel for it — recorded as a
#: seam rather than pretended away, and the `live` group is what proves the
#: strings on a real wasmtime.
RUNTIME_BREACH_MARKERS = (
    ("all fuel consumed", wasm_pure.PURE_LIMIT_FUEL),
    ("out of fuel", wasm_pure.PURE_LIMIT_FUEL),
    ("outoffuel", wasm_pure.PURE_LIMIT_FUEL),
    ("memory minimum size", wasm_pure.PURE_LIMIT_MEMORY),
    ("failed to grow memory", wasm_pure.PURE_LIMIT_MEMORY),
    ("exceeds memory limits", wasm_pure.PURE_LIMIT_MEMORY),
    ("max-memory-size", wasm_pure.PURE_LIMIT_MEMORY),
)


def classify_runtime_breach(stderr: str) -> str:
    """Which declared limit, if any, the runtime says was breached."""
    low = (stderr or "").lower()
    for marker, code in RUNTIME_BREACH_MARKERS:
        if marker in low:
            return code
    return ""

#: What must appear in `wasmtime run --help` for the flags above to mean
#: anything on this host.
RUNTIME_LIMIT_PROBE = {"fuel": "fuel", "memory": "max-memory-size"}
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
TOOL_NO_EFFECT_CLASS = "NO_EFFECT_CLASS"    # v0.6.9: manifest entry
                                            # declares no effect class
                                            # (ADR-022 D9, fail-closed)

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
                 key_resolver=None, gauntlet_available: bool = False,
                 toolset_authorization=None, **kw):
        super().__init__(root, **kw)
        # v0.6.9 (ADR-022 D8/D10). Without a resolver for the signing key
        # the manifest cannot be verified, and an unverified manifest does
        # not sanction an L2 mutation — so the profile is UNAVAILABLE rather
        # than permissive. That is today's honest state on every node: this
        # tree ships no key registry, and no compiled modules either.
        self.key_resolver = key_resolver
        self.gauntlet_available = gauntlet_available
        # WHO SAYS WHEN THE MANIFEST WAS AUTHORIZED. Resolved by a party
        # holding the chain and a verified ReleasePublication —
        # `jjdai.release.toolset_authorizer` builds one. None means the node
        # has no release to resolve against, and for a registry that records
        # a key lifecycle the manifest then REFUSES: the audit of recut2
        # found the authorizer built and never handed to the door it guards,
        # which is the third time in this drop a checker stood beside the
        # boundary instead of being it.
        self.toolset_authorization = toolset_authorization
        self._manifest_error = ""
        self._limit_flags_ok = None
        self.tools_dir = os.path.realpath(
            tools_dir or os.path.join(os.path.dirname(__file__), "..",
                                      "deploy", "wasm-toolset"))
        self.wasmtime = wasmtime
        self.guest_dir = guest_dir

    # ---- the fixed toolset ---- #
    def manifest_path(self) -> str:
        """The one filename. ADR-022 D8 names `toolset-manifest.json`; the
        v0.6.4 tree called it `toolset.json`, and two names for the object
        that sanctions the hand is one name too many. The old name is read
        as a FALLBACK so an un-migrated node reports its state instead of
        going dark, and `toolset()` refuses it by the absence of the v2
        fields rather than by its filename."""
        primary = os.path.join(self.tools_dir, toolset_mod.MANIFEST_FILE)
        if os.path.exists(primary):
            return primary
        legacy = os.path.join(self.tools_dir, LEGACY_MANIFEST_FILE)
        return legacy if os.path.exists(legacy) else primary

    def toolset(self) -> dict:
        """{tool_name: entry} from the VERIFIED manifest, or {}.

        v0.6.9: this used to read and parse the file itself and never call
        the validator, so a manifest with no signature, no authorization
        form, no sunset, no recipe hash and no limits produced
        `available = (True, "")` and executed. The validator was beside the
        door instead of being it. Now there is one door
        (`kernel.toolset.load_verified_manifest`) and everything —
        availability, capabilities, module resolution, execution — arrives
        through it.

        Unreadable or unverifiable is still not an exception here:
        availability reports the reason, and every execution path re-checks.
        A profile that cannot verify its manifest has no tools, and every
        action against it is refused.
        """
        try:
            doc = toolset_mod.load_verified_manifest(
                self.manifest_path(), resolver=self.key_resolver,
                gauntlet_available=self.gauntlet_available,
                authorization=self.toolset_authorization)
        except toolset_mod.ToolsetError as e:
            self._manifest_error = f"{e.code}: {e}"
            return {}
        except (ValueError, TypeError) as e:
            # provenance / custody refusals travel as ValueError; a manifest
            # that trips one of them is as unloadable as a malformed one and
            # must not be reported as merely absent.
            self._manifest_error = f"MANIFEST_REFUSED: {e}"
            return {}
        self._manifest_error = ""
        return doc["tools"]

    def manifest_error(self) -> str:
        """Why the manifest did not load, or "" — public because readiness,
        capabilities and the operator all need the CAUSE and not just the
        absence. A profile with no tools because its manifest failed
        verification — unsigned, unauthorized at a resolvable position,
        or refused for any other reason the door reports — is
        a different situation from one whose manifest is simply not there.
        """
        self.toolset()
        return self._manifest_error

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
        ok, why = self._runtime_supports_limits()
        if not ok:
            return False, why
        if not os.path.exists(self.manifest_path()):
            return False, (f"toolset manifest missing at "
                           f"{self.manifest_path()!r}")
        if not self.toolset():
            why = self._manifest_error or (
                f"empty or not schema {TOOLSET_SCHEMA_V2}")
            return False, (f"toolset manifest at {self.manifest_path()!r} "
                           f"is not usable — {why}")
        return True, ""

    def _runtime_supports_limits(self) -> tuple[bool, str]:
        """Does THIS wasmtime accept the flags that carry the limits?

        Asked once and cached. A runtime that does not accept them makes the
        profile unavailable rather than running without them: a limit passed
        to a binary that ignores it is not a limit, and D9 requires the
        breach of one to be a named refusal. Probed by `--help` rather than
        by version, because a version string says what was released and the
        help text says what this build takes.
        """
        if self._limit_flags_ok is not None:
            return self._limit_flags_ok
        try:
            probe = subprocess.run([self.wasmtime, "run", "--help"],
                                   capture_output=True, text=True, timeout=20)
            text = (probe.stdout or "") + (probe.stderr or "")
        except (OSError, subprocess.SubprocessError) as e:
            self._limit_flags_ok = (False, f"wasm runtime probe failed: {e}")
            return self._limit_flags_ok
        missing = [name for name in RUNTIME_LIMIT_FLAGS
                   if RUNTIME_LIMIT_PROBE[name] not in text]
        if missing:
            self._limit_flags_ok = (
                False,
                f"wasm runtime {self.wasmtime!r} does not accept the "
                f"{missing} limit option(s) this build passes; the profile "
                f"is unavailable rather than executing without them — a "
                f"limit a runtime ignores is not a limit (ADR-022 D9)")
        else:
            self._limit_flags_ok = (True, "")
        return self._limit_flags_ok

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
                # COMPUTED, not declared. It was hardcoded `False` even
                # after a signature verified, so the one capability a reader
                # would use to tell a signed toolset from an unsigned one
                # said the same thing in both cases.
                "manifest_signed": bool(self.toolset()) and
                                   not self._manifest_error,
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
        # v0.6.9 (ADR-022 D9). The module IS the pinned one; now ask whether
        # it stays inside the effect class the manifest declares for it. The
        # order is deliberate: a drifted module is reported as drift, not as
        # whatever its imports happen to be. A tool with no declared class
        # is refused rather than assumed harmless — `unknown` is fail-closed
        # and `check_effect_class` is the one door for that.
        declared = (entry.get("effect_class") or "").strip()
        if not declared:
            raise _fail(ToolNotPermitted, TOOL_NO_EFFECT_CLASS,
                f"tool {tool!r} declares no effect_class — refused. Without "
                f"one the limit on the hand in custody has nothing to be "
                f"told apart from, so an undeclared tool is not a permissive "
                f"default, it is a refusal (ADR-022 D9)")
        check_effect_class(declared)
        if declared == "pure":
            with open(module, "rb") as f:
                data = f.read()
            try:
                check_pure_imports(data)
            except PureBoundaryError as e:
                # Re-raised as a TOOL fault carrying the boundary's own code.
                # `toolset_report()` catches ToolNotPermitted and
                # ProfileUnavailable; letting a PureBoundaryError through
                # would take the whole report down instead of marking one
                # tool unavailable — the readiness rule this codebase has
                # already been bitten by twice. The code is kept as the
                # boundary spelled it (IMPORT_DENIED / MALFORMED_MODULE /
                # NOT_WASM) because "this module reaches past `pure`" and
                # "this module is not a module" are different facts.
                raise _fail(ToolNotPermitted, e.code,
                    f"tool {tool!r} declares effect_class 'pure' and its "
                    f"module does not hold to it: {e}") from None
        return module

    def wasm_argv(self, argv: list, workdir: str, limits=None) -> list:
        """The command handed to the reference fence. Split out so the
        mapping is testable without a runtime present.

        v0.6.9 (ADR-022 D9): ZERO preopen directories. The earlier form
        passed `--dir {workdir}::{guest_dir}`, which meant the guest could
        write inside that directory — so `pure` described a boundary it did
        not draw. `workdir` is kept in the signature because the fence below
        still runs the process somewhere; it is no longer handed to the
        guest. The assembled command is checked rather than trusted, because
        the preopen that mattered arrived as a flag on exactly this line.
        """
        module = self._module_for(argv[0])
        limits = limits or self.limits_for(argv[0])
        # Fuel and guest memory are the RUNTIME's to enforce; the process
        # rlimit below them bounds the host, not the guest, and the two are
        # not the same number. The flag spelling is declared as data rather
        # than inlined, and `_runtime_supports_limits()` refuses a runtime
        # that does not accept it — an unrecognised flag would otherwise be
        # passed, ignored or fatal depending on the wasmtime build, and the
        # limit would be enforced on some hosts and not others. Which
        # spelling a given wasmtime accepts is verified on the target host
        # by the `live` group, not asserted here.
        cmd = [self.wasmtime, "run",
               *RUNTIME_LIMIT_FLAGS["fuel"](limits.fuel),
               *RUNTIME_LIMIT_FLAGS["memory"](limits.guest_memory_bytes),
               module, "--", *[str(a) for a in argv[1:]]]
        check_no_preopens(cmd)
        del workdir
        return cmd

    def limits_for(self, tool: str):
        """The per-tool limits from the VERIFIED manifest.

        Not defaults, not the process-wide sandbox numbers: `pure` means the
        limits the signed manifest declares for THIS tool, and a manifest
        entry without them does not load at all.
        """
        entry = self.toolset().get(tool) or {}
        return check_limits_declared(entry.get("limits"))

    def run(self, argv: list, *, cwd: str = None,
            input_bytes: bytes = b"", **_kw) -> ActionResult:
        if not argv:
            raise ToolNotPermitted("empty argv — refused")
        ok, reason = self._runtime_ready()
        if not ok:
            raise ProfileUnavailable(reason)
        # tool resolution happens inside wasm_argv and raises the precise
        # refusal — not permitted, missing module, or digest drift
        workdir = self.resolve(cwd) if cwd else self.root
        # The command is assembled FIRST, because `_module_for` inside it is
        # what refuses an unknown tool. Reading limits before that would
        # answer "noop2" with "its limits are not a mapping" instead of "it
        # is not in the fixed toolset" — a refusal naming the wrong cause,
        # which this file already keeps three separate code families to
        # avoid.
        cmd = self.wasm_argv(argv, workdir)
        limits = self.limits_for(argv[0])
        r = super().run(cmd, cwd=cwd, input_bytes=input_bytes,
                        max_output=limits.output_bytes,
                        mem_bytes=limits.host_memory_bytes)
        # v0.6.9 (ADR-022 D9). Exceeding a limit gives a DETERMINISTIC
        # REFUSAL with a reason code, never a truncated output. The baseline
        # sandbox caps what it buffers and returns the prefix with
        # `truncated=True`, which for a general shell is a reasonable
        # answer and for a deterministic tool is a WRONG ANSWER THAT LOOKS
        # LIKE AN ANSWER — the caller cannot tell a complete result from the
        # first N bytes of a different one. So the prefix is discarded here
        # rather than returned.
        # Fuel and guest memory are breached INSIDE the runtime, so their
        # verdict comes from what the runtime said. Without this the two of
        # them returned an ordinary non-zero exit and `verdict: None` — two
        # of D9's three limits enforced in name only.
        breach = classify_runtime_breach(r.stderr)
        if breach:
            return ActionResult(
                "shell", False, r.exit_code, "", "", r.duration_s,
                truncated=False, timed_out=r.timed_out,
                detail={"verdict": breach, "limits": limits._asdict(),
                        "reason": (f"tool {argv[0]!r} exhausted a declared "
                                   f"limit inside the runtime; the partial "
                                   f"output is discarded for the same "
                                   f"reason as an output breach"),
                        "runtime_said": r.stderr[:400]})
        emitted = (r.detail or {}).get("bytes_emitted", {})
        # TOTAL output, not the larger stream. The first cut took
        # `max(out, err)`, so 40 bytes on each channel passed a 64-byte
        # limit — a cap on each half is not a cap on the whole.
        over = int(emitted.get("out", 0)) + int(emitted.get("err", 0))
        if r.truncated or over > limits.output_bytes:
            code = breach_code("output_bytes")
            return ActionResult(
                "shell", False, r.exit_code, "", "", r.duration_s,
                truncated=False, timed_out=r.timed_out,
                detail={"verdict": code, "limit": limits.output_bytes,
                        "bytes_emitted": emitted,
                        "reason": (f"tool {argv[0]!r} exceeded its declared "
                                   f"output limit; the partial output is "
                                   f"DISCARDED because a truncated result "
                                   f"from a deterministic tool cannot be "
                                   f"told apart from a complete one")})
        return r


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
