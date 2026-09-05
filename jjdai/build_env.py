# -*- coding: utf-8 -*-
"""
jjdai.build_env — the pinned build environment and the backend hash gate
========================================================================
ADR-022 D3 and D4.

**D4, and why the pin does not live in `pyproject.toml`.** PEP 517 gives
`[build-system].requires` no place for a hash. `setuptools==80.9.0` is a
version pin, and a version pin resolves to whatever an index serves under
that name — which is a promise about a label, not about bytes. So the wheel
of the backend is placed under `vendor/build-backend/`, pinned by sha256 in
a file of its own, and the build script verifies the hash **before
installing**, refusing closed on any mismatch. The environment is then
prepared with the FULL set of build dependencies installed hash-locked, and
only then does the build run with `--no-build-isolation`.

The caveat is stated here rather than left to be discovered:
`--no-build-isolation` cleans nothing by itself. It moves the responsibility
to the caller. What makes the environment clean is the preparation step
above in full, not the flag.

**D3, and the one input that cannot be pinned by pinning.** Everything in
the table below is fixed by name and hash except the clock, and the clock is
fixed by derivation: `SOURCE_DATE_EPOCH` is the COMMITTER time of the tagged
commit, obtained by `git log -1 --pretty=%ct <rev>` and by no other route.
Author time is the wrong field — a rebase or a cherry-pick keeps it while
the tree moves on, so two different trees would carry one timestamp.

The build is not asserted reproducible. It is REBUILT, in a second clean
environment, and the two results compared byte for byte; that comparison is
the `verifier` approval of D5.3. A build that says it is reproducible and
was never rebuilt is a claim about a property nobody measured.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import sys
import subprocess

from . import provenance as prv

PINS_FILE = "vendor/build-backend/PINS.json"
PINS_SCHEMA = "jjdai.build-pins/v1"

#: Same discipline as the toolset recipes: an unfilled pin refuses LOUDLY.
#: A placeholder that validates is worse than a missing file, because the
#: missing file is noticed.
PLACEHOLDER = "__OWED_ON_BUILD_HOST__"

#: Fixed by D3. Written into the `ReleaseStatement.build_environment` table
#: and compared there, so a build that quietly ran under another locale
#: cannot present itself as the same build.
LOCALE = "C"
TIMEZONE = "UTC"
UMASK = 0o022

#: What a prepared environment declares. `network` is the only entry that is
#: a MEASUREMENT rather than a setting: D3 says "disabled and checked", and
#: an unchecked claim of no network is the thing it is guarding against.
ENV_FIELDS = ("python", "locale", "timezone", "umask", "network",
              "network_enforcement",
              "source_date_epoch")

NETWORK_DISABLED = "disabled-and-checked"

#: WHAT THE NETWORK FIELD IS WORTH. A process cannot deny its own egress.
#: Everything reachable from inside this module is a PROBE, and a probe
#: answers about the endpoints it names — recut1 named two, and a host that
#: blocked 1.1.1.1:53 and pypi.org:443 while reaching everything else
#: recorded `disabled-and-checked`. So the measurement is widened and, more
#: importantly, stops being the whole claim: `network_enforcement` says who
#: is asserting the denial and by what mechanism, in the vocabulary D2 uses
#: for `device_binding`. Every value here begins with `asserted` because
#: every value here is an assertion; real enforcement is a namespace, a
#: firewall or an air gap, and the debt position is
#: `build-egress-enforcement`.
NETWORK_ENFORCEMENT_ASSERTED = "asserted"
NETWORK_ENFORCEMENT_ENV = "JJDAI_BUILD_EGRESS_MECHANISM"

#: Endpoints the probe tries. Two of them were a hole; five with three
#: distinct networks and a DNS name is a wider net and still a net.
NETWORK_PROBES = (("1.1.1.1", 53), ("8.8.8.8", 53), ("9.9.9.9", 53),
                  ("pypi.org", 443), ("files.pythonhosted.org", 443),
                  ("github.com", 443))

BUILD_ENV_NOT_CLEAN = "BUILD_ENV_NOT_CLEAN"
BUILD_ENV_NOT_EPHEMERAL = "BUILD_ENV_NOT_EPHEMERAL"

#: Where a prepared build environment lives. One directory, removed and
#: recreated per build: D3 asks for a CLEAN environment, and an environment
#: that survives a build carries whatever the last one left in it.
VENV_DIRNAME = ".build-venv"

BUILD_PIN_MISSING = "BUILD_PIN_MISSING"
BUILD_PIN_MISMATCH = "BUILD_PIN_MISMATCH"
BUILD_ENV_DIRTY = "BUILD_ENV_DIRTY"
BUILD_NETWORK_REACHABLE = "BUILD_NETWORK_REACHABLE"
BUILD_EPOCH_UNAVAILABLE = "BUILD_EPOCH_UNAVAILABLE"


class BuildEnvError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code, message):
    return BuildEnvError(code, message)


# --------------------------------------------------------------------------- #
# D4 · the backend pin
# --------------------------------------------------------------------------- #

PIN_FIELDS = ("name", "version", "sha256", "filename")


def load_pins(root: str) -> dict:
    """Read `vendor/build-backend/PINS.json`.

    Fail-closed on absence: a missing pin file is not "use whatever is
    installed". That reading is how a build backend of unknown provenance
    gets in through an omission rather than a decision.
    """
    path = os.path.join(root, *PINS_FILE.split("/"))
    try:
        with io.open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise _fail(BUILD_PIN_MISSING,
                    f"{PINS_FILE} unreadable: {e}. A build without pinned "
                    f"backend bytes is a build whose output is a function of "
                    f"what an index served that day (ADR-022 D4).") from None
    if doc.get("schema") != PINS_SCHEMA:
        raise _fail(BUILD_PIN_MISSING,
                    f"{PINS_FILE} must declare schema {PINS_SCHEMA!r}")
    pins = doc.get("wheels")
    if not isinstance(pins, list) or not pins:
        raise _fail(BUILD_PIN_MISSING,
                    f"{PINS_FILE} pins no wheels; the backend AND all of its "
                    f"dependencies are pinned, not the backend alone")
    out = {}
    for pin in pins:
        for field in PIN_FIELDS:
            if not pin.get(field):
                raise _fail(BUILD_PIN_MISSING,
                            f"{PINS_FILE}: a pin omits {field!r}")
        digest = pin["sha256"]
        if digest == PLACEHOLDER:
            raise _fail(
                BUILD_PIN_MISSING,
                f"{PINS_FILE}: {pin['name']} still carries the placeholder. "
                f"The digests are taken on a build host with index access "
                f"and the wheels are committed beside them; until then the "
                f"build refuses rather than validating a hash-shaped string "
                f"that pins nothing (ADR-022 D4).")
        if len(digest) != 64 or any(c not in "0123456789abcdef"
                                    for c in digest.lower()):
            raise _fail(BUILD_PIN_MISMATCH,
                        f"{PINS_FILE}: {pin['name']} sha256 is not a "
                        f"sha256 — a short string in a pin is a pin-shaped "
                        f"hole")
        out[pin["filename"]] = pin
    return out


def verify_pinned_wheels(root: str) -> dict:
    """Hash every vendored wheel BEFORE anything installs it.

    Order is the whole point: verifying after installation verifies a
    decision already taken. Returns the pins that were checked; raises on
    the first that is absent or differs.
    """
    pins = load_pins(root)
    vendor = os.path.join(root, "vendor", "build-backend")
    for filename, pin in sorted(pins.items()):
        path = os.path.join(vendor, filename)
        if not os.path.exists(path):
            raise _fail(
                BUILD_PIN_MISSING,
                f"{filename} is pinned and not present in vendor/"
                f"build-backend/. The wheel is vendored deliberately: "
                f"fetching it at build time would put the index back in the "
                f"dependency chain that the pin exists to remove.")
        with open(path, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        if got != pin["sha256"].lower():
            raise _fail(
                BUILD_PIN_MISMATCH,
                f"{filename} hashes {got}, the pin records "
                f"{pin['sha256']}. Refused before installation, not after.")
    return pins


# --------------------------------------------------------------------------- #
# D3 · the environment
# --------------------------------------------------------------------------- #

def source_date_epoch(root: str, rev: str = "HEAD") -> str:
    """The COMMITTER time of the tagged commit, verbatim.

    `%ct`, not `%at`. Author time survives a rebase or a cherry-pick while
    the tree underneath moves, so two different trees would carry one
    timestamp and the archives would look identical where they are not. The
    route is named here because "the commit's time" has two answers and a
    build that picks either is not reproducible across the people building
    it.
    """
    proc = subprocess.run(("git", "log", "-1", "--pretty=%ct", rev),
                          cwd=root, capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip().isdigit():
        raise _fail(BUILD_EPOCH_UNAVAILABLE,
                    f"cannot read committer time of {rev!r}: "
                    f"{(proc.stderr or '').strip() or 'not a git tree'}")
    return proc.stdout.strip()


def network_is_unreachable(probes=NETWORK_PROBES,
                           timeout: float = 1.0) -> bool:
    """Measure, do not assume — and do not mistake the measurement for proof.

    True means every named endpoint refused. It does not mean there is no
    egress: nothing executed inside the build can establish that, which is
    why the table also carries `network_enforcement` and why the gap is in
    the ledger rather than in a comment.
    """
    for host, port in probes:
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            return False
        except OSError:
            continue
    return True


def assert_network_disabled() -> None:
    if not network_is_unreachable():
        raise _fail(
            BUILD_NETWORK_REACHABLE,
            "the network is reachable from the build environment. D3 "
            "requires it disabled and CHECKED: an unchecked claim of no "
            "network is exactly what the requirement guards against, "
            "because a build that can reach an index can resolve something "
            "nobody pinned.")


def describe(root: str, rev: str = "HEAD", *, check_network: bool = True):
    """The `build_environment` table, filled from measurement.

    Every value here also appears in the `ReleaseStatement`, so a build that
    ran under another locale or another clock cannot present itself as the
    same build: the table is inside what the approvals sign.
    """
    import platform
    if check_network:
        assert_network_disabled()
    mechanism = os.environ.get(NETWORK_ENFORCEMENT_ENV, "").strip()
    enforcement = NETWORK_ENFORCEMENT_ASSERTED
    if mechanism:
        # Still `asserted`, with the mechanism named. A host that says
        # `netns:none` has told a reader what to go and check; it has not
        # proved anything to this process, and the prefix says so.
        enforcement = f"{NETWORK_ENFORCEMENT_ASSERTED}:{mechanism}"
    return {"python": f"{platform.python_implementation()} "
                      f"{platform.python_version()}",
            "locale": LOCALE,
            "timezone": TIMEZONE,
            "umask": f"{UMASK:04o}",
            "network": NETWORK_DISABLED,
            "network_enforcement": enforcement,
            "source_date_epoch": source_date_epoch(root, rev)}


def venv_python(venv_dir: str) -> str:
    """The interpreter inside a prepared environment, per platform."""
    win = os.path.join(venv_dir, "Scripts", "python.exe")
    return win if os.path.exists(win) else os.path.join(venv_dir, "bin",
                                                        "python")


def assert_ephemeral_prefix(venv_dir: str) -> None:
    """Refuse to prepare anything into an interpreter that is already live.

    recut1's `--prepare` ran `pip install --force-reinstall` into the
    CURRENT interpreter. That is not a clean environment by any reading: it
    keeps every unrelated distribution already installed, it leaves the
    build hook able to import code that was never pinned, and it cannot
    prove the full set of build inputs because it never controlled the set.
    """
    target = os.path.abspath(venv_dir)
    for live in {os.path.abspath(sys.prefix), os.path.abspath(sys.base_prefix)}:
        if target == live or live.startswith(target + os.sep):
            raise _fail(
                BUILD_ENV_NOT_EPHEMERAL,
                f"{target!r} is the running interpreter's own prefix. A "
                f"build environment is created for the build and destroyed "
                f"after it; installing into the ambient one prepares "
                f"nothing and proves less")


def installed_distributions(venv_dir: str) -> set:
    """Every distribution present under a prepared prefix, by name."""
    names = set()
    lib = os.path.join(venv_dir, "lib")
    roots = []
    if os.path.isdir(lib):
        for entry in sorted(os.listdir(lib)):
            roots.append(os.path.join(lib, entry, "site-packages"))
    roots.append(os.path.join(venv_dir, "Lib", "site-packages"))
    for site in roots:
        if not os.path.isdir(site):
            continue
        for entry in os.listdir(site):
            if entry.endswith((".dist-info", ".egg-info")):
                base = entry.rsplit(".", 1)[0]
                names.add(base.split("-")[0].lower().replace("_", "-"))
    return names


def assert_no_extraneous(venv_dir: str, expected) -> set:
    """The prepared set is EXACTLY the pinned set, or the build refuses.

    Without this the environment is "the pins, plus whatever else was
    there", and "whatever else was there" is precisely the input D3 exists
    to remove: an unpinned distribution that a build hook can import is a
    build input nobody hashed.
    """
    want = {str(n).lower().replace("_", "-") for n in expected}
    have = installed_distributions(venv_dir)
    extra = sorted(have - want)
    missing = sorted(want - have)
    if extra or missing:
        raise _fail(
            BUILD_ENV_NOT_CLEAN,
            f"the prepared environment is not the pinned set: "
            f"extraneous={extra}, missing={missing}. A build environment "
            f"that holds anything the pins do not name is a build whose "
            f"inputs are not the ones that were verified")
    return have


def build_command(sdist_path: str = None, python: str = "python") -> list:
    """The build invocation, as data so a check can assert its shape.

    Two properties D3 fixes and this returns rather than describes: the
    wheel is built FROM THE ALREADY-CHECKED SDIST and not in parallel from
    the tree, and isolation is off because the environment was prepared
    hash-locked beforehand — the flag alone cleans nothing.
    """
    if sdist_path is None:
        return [python, "-m", "build", "--sdist", "--no-isolation",
                "--outdir", "dist"]
    return [python, "-m", "build", "--wheel", "--no-isolation",
            "--outdir", "dist", sdist_path]


#: What a release statement's build_environment must agree with. Named so
#: the release verifier and the builder read ONE list.
def environment_matches(recorded: dict, actual: dict) -> list:
    """Fields where a recorded environment differs from the measured one."""
    return sorted(f for f in ENV_FIELDS
                  if str(recorded.get(f)) != str(actual.get(f)))


REPRODUCIBILITY_SCOPES = prv.REPRODUCIBILITY_SCOPES
