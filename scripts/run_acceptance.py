#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/run_acceptance.py — stdlib acceptance runner (v0.4.1)
=============================================================
Follows the pytest protocol: IMPORT each tests/**/test_*.py (imports must be
side-effect-free), COLLECT test_* functions, RUN them, report. Use this where
pytest is unavailable.

    python3 scripts/run_acceptance.py                  # the five hermetic groups
    python3 scripts/run_acceptance.py unit adversarial # chosen groups
    python3 scripts/run_acceptance.py live             # opt-in, needs a real host

**This runner and `pytest tests/` do NOT collect the same set.** The claim that
they did stood in this docstring through v0.6.8 and was false in one direction:
the runner's default is the five HERMETIC groups, `tests/live` is a sixth that
needs a real wasm runtime and a real model, and a bare `pytest tests/` used to
collect it and fail on a host that has neither. `pytest` now honours the same
exclusion through `--ignore` in `pyproject.toml`, so the two agree on the
DEFAULT set — and the sentence claiming they agree on ALL functions is gone,
because selecting `live` in either tool changes what runs.
"""
from __future__ import annotations

import importlib.util
import hashlib
import platform
import json
import os
import sys
import time
import traceback

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GROUPS = ("unit", "integration", "conformance", "adversarial", "compatibility")
#: Opt-in groups: never collected by default, selectable by name.
#: "live" needs a real wasm runtime on the host and is required by the
#: Ф0 gate on each target host — a check that skips itself quietly is
#: not evidence, so it stays out of the hermetic default instead.
OPT_IN = ("live",)

for _p in (ROOT, os.path.join(ROOT, "node"), os.path.join(ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def collect(groups):
    for group in groups:
        gdir = os.path.join(ROOT, "tests", group)
        if not os.path.isdir(gdir):
            continue
        for fname in sorted(os.listdir(gdir)):
            if fname.startswith("test_") and fname.endswith(".py"):
                yield group, os.path.join(gdir, fname)


def load(path, group):
    modname = f"tests.{group}.{os.path.splitext(os.path.basename(path))[0]}"
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)          # must be side-effect-free
    return mod


#: Groups that existed under another name. Typing a retired name must say so:
#: silently running everything looks like a pass for a group that is gone.
RETIRED = {"legacy": "compatibility"}


def main(argv):
    known = GROUPS + OPT_IN
    unknown = [g for g in argv if g not in known]
    if unknown:
        for g in unknown:
            hint = RETIRED.get(g)
            print(f"unknown group {g!r}" +
                  (f" — renamed to {hint!r} in v0.6.7" if hint else
                   f"; known groups: {', '.join(known)}"), file=sys.stderr)
        return 2
    groups = [g for g in argv if g in known] or list(GROUPS)
    total = failed = errors = 0
    t0 = time.time()
    for group, path in collect(groups):
        rel = os.path.relpath(path, ROOT)
        try:
            mod = load(path, group)
        except Exception:
            print(f"\nIMPORT ERROR  {rel}")
            traceback.print_exc()
            errors += 1
            continue
        fns = [(k, v) for k, v in sorted(vars(mod).items())
               if k.startswith("test_") and callable(v)]
        for name, fn in fns:
            total += 1
            try:
                fn()
                print(f"  PASS  {rel}::{name}")
            except AssertionError as e:
                failed += 1
                print(f"  FAIL  {rel}::{name}  {e}")
            except Exception:
                failed += 1
                print(f"  ERROR {rel}::{name}")
                traceback.print_exc()
    dt = time.time() - t0
    print(f"\nacceptance: {total - failed}/{total} passed, "
          f"{errors} import error(s), {dt:.1f}s")
    # Record what happened — including a failing run. The artefact is
    # evidence of a RUN, not a claim of success; the generator decides what a
    # given result licenses. Recording only green runs would leave the last
    # green one standing after a red one, which is worse than nothing.
    try:
        write_result(total - failed, total, groups, errors, dt)
    except OSError:
        pass
    return 1 if (failed or errors) else 0



# --------------------------------------------------------------------- #
# The acceptance RESULT artefact (v0.6.7 recut)
#
# The badge used to come from `gen_architecture_docs` counting `def test_*`
# declarations, so README said "145/145 green" whether or not anything had
# run, and said it identically on a machine where a check errored. A count of
# functions is not a result.
#
# This writes what actually happened. The generator reads it and REFUSES to
# emit a badge without it, so a green badge now implies a green run.
#: Evidence is keyed by SUITE. One file per suite, because a single
#: artefact cannot simultaneously be evidence of a hermetic run, of the wasm
#: live group, and of a run on a particular target host — and until recut3
#: every invocation wrote the same path, so `run_acceptance.py live`
#: silently destroyed the hermetic result it had nothing to say about.
EVIDENCE_DIR = os.path.join(ROOT, "docs", "evidence")
DEFAULT_SUITE = "hermetic"


def _suite_name(groups) -> str:
    """The suite a set of groups constitutes.

    The default groups are one suite; every opt-in group is its own, because
    what it proves and where it can run are both different.
    """
    chosen = sorted(set(groups))
    opt = [g for g in chosen if g in OPT_IN]
    if not opt:
        return DEFAULT_SUITE
    if chosen == opt:
        return "live-" + "-".join(opt)
    return "mixed-" + "-".join(chosen)


def result_path(suite: str = DEFAULT_SUITE) -> str:
    return os.path.join(EVIDENCE_DIR, f"{suite}.json")


#: Kept as a name because readers import it; it is the hermetic suite.
RESULT_PATH = result_path(DEFAULT_SUITE)


#: Directories that hold no shipped artefact at all.
#: `.typeset` is the scratch directory scripts/typeset_roadmap.py builds
#: the roadmap PDF through. Build scratch belongs outside the digest for
#: the same reason __pycache__ does: it is not shipped, and whether it
#: happens to exist when a run is recorded must not be able to decide
#: whether a later clean unpack reads the same tree.
_DIGEST_SKIP_DIRS = ("__pycache__", ".git", ".pytest_cache", ".typeset",
                     "build", "dist",
                     ".eggs", ".mypy_cache", ".ruff_cache", "node_modules",
                     ".idea", ".vscode")

#: The ONLY files excluded by content: the ones this run and its generator
#: produce. Everything else in the tree is hashed, whatever its extension.
#:
#: An EXCLUSION list, deliberately, because v0.6.7-recut2 shipped an
#: INCLUSION list — `.py` only — and the audit walked straight through it:
#: granting anonymous access to /v1/tasks in `deploy/authz.testnet.json`
#: left the digest unchanged and the badge green. An inclusion list silently
#: loses every file type nobody thought of; an exclusion list fails loudly,
#: because a new kind of file is covered by default and only a deliberate
#: line removes it.
#:
#: The excluded surfaces are not left unverified: `check_docs_drift` proves
#: each of them regenerates from `docs/architecture_status.json`, which IS
#: hashed. They are excluded because they carry the badge itself — hashing
#: them would let writing a result invalidate the run that result describes,
#: and the pair could never converge.
#: `docs/acceptance_result.json` was removed from this list in the v0.6.8
#: remediation: the artefact moved to `docs/evidence/<suite>.json` in
#: v0.6.7-recut3 and nothing has written that path since. A stale entry in an
#: EXCLUSION list is the worst place for one — it silently un-hashes any file
#: that later takes the name, and it reads to an auditor as a deliberate
#: exemption rather than as a leftover.
_DIGEST_SKIP_FILES = ("README.md",)
_DIGEST_SKIP_PREFIXES = ("docs/evidence/",
                         "docs/JJDAI_Code_Architecture_Map_v",
                         "docs/site/JJDAI_Architecture_Status_v")


def _digest_skip(rel: str) -> bool:
    return (rel in _DIGEST_SKIP_FILES
            or rel.startswith(_DIGEST_SKIP_PREFIXES))


def digest_files(root: str = None) -> list:
    """Every shipped file the digest covers, as sorted relative paths.

    Exposed so a check can assert that named release-relevant files are
    actually inside it. A digest nobody can enumerate is a digest nobody can
    audit.
    """
    root = ROOT if root is None else root
    out = []
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _DIGEST_SKIP_DIRS)
        for n in sorted(names):
            rel = os.path.relpath(os.path.join(base, n),
                                  root).replace(os.sep, "/")
            if not _digest_skip(rel):
                out.append(rel)
    return sorted(out)


def source_digest(root: str = None) -> str:
    """A content address of the TREE the run executed against.

    Counts alone were never evidence about code: `total` moves only when the
    NUMBER of checks moves, so a defect introduced without adding or
    removing a test function left the recorded result matching and the badge
    green about a tree that no longer existed.

    Since recut3 this covers the shipped tree and not merely its Python:
    authz policy, systemd and launchd units, shell scripts, the wasm toolset
    manifest, model profiles, Prometheus rules, pyproject, the licences, CI
    workflows, the ADRs and the roadmap. Those are release-relevant, and a
    change to any of them is a change to what the run proved.
    """
    root = ROOT if root is None else root
    h = hashlib.sha256()
    for rel in digest_files(root):
        with open(os.path.join(root, *rel.split("/")), "rb") as fh:
            body = fh.read()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(hashlib.sha256(body).hexdigest().encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def write_result(passed: int, total: int, groups, errors: int,
                 duration_s: float) -> dict:
    """Record a completed run, into the file of the suite it ran.

    Content-addressed so a hand-edited file is detectable: the digest covers
    the counts, the SOURCE TREE and the host this ran on — not the timestamp.

    The host matters because an opt-in group's result is a claim about a
    machine: "the wasm live group passed" is only true of a host that has
    wasmtime. `engine` is declared and left null unless the caller names one
    through JJDAI_EVIDENCE_ENGINE, which is honest about what the runner can
    know by itself.
    """
    suite = _suite_name(groups)
    body = {"schema": "jjdai.acceptance_result/v4",
            "suite": suite,
            # WHAT PRODUCED THIS RUN. Added in /v4 because ENTRY-3 reads
            # green on a host with no pytest: it falls back to asserting
            # configuration when it cannot run the collector, which is the
            # correct behaviour for a suite that must run on a bare
            # interpreter — but the artefact said nothing about WHICH of the
            # two modes had happened. An audit round read the fallback as an
            # exercised probe, and nothing in the evidence could correct it.
            # A green number whose provenance is unrecorded is the shape of
            # defect this file exists to prevent.
            "collector": _collector(),
            "version": _version(),
            "passed": int(passed), "total": int(total),
            "import_errors": int(errors),
            "groups": sorted(groups),
            "python": platform.python_version(),
            "host": {"system": platform.system(),
                     "release": platform.release(),
                     "machine": platform.machine(),
                     "node": platform.node()},
            "engine": os.environ.get("JJDAI_EVIDENCE_ENGINE") or None,
            "tree_digest": source_digest(),
            "duration_s": round(float(duration_s), 1)}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    body["digest"] = hashlib.sha256(payload.encode()).hexdigest()
    body["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    with open(result_path(suite), "w", encoding="utf-8") as fh:
        json.dump(body, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return body


def _collector():
    """The stdlib runner is always the producer; pytest is a second one.

    Recorded as a FACT ABOUT THE RUN, never as a requirement: this runner
    has to work where pytest is absent, which is the whole reason it exists.
    What must not happen is a host without pytest whose artefact reads as if
    an entrypoint-parity claim had been exercised on it.
    """
    info = {"runner": "scripts/run_acceptance.py", "pytest": None}
    try:
        import pytest  # noqa: F401
        info["pytest"] = getattr(pytest, "__version__", "unknown")
    except Exception:
        pass
    info["entrypoint_probe_mode"] = ("collection" if info["pytest"]
                                     else "configuration-only")
    return info


def read_result(suite: str = DEFAULT_SUITE):
    """The recorded run of ONE suite, or None. Refuses a file whose digest
    does not match its own body."""
    try:
        with open(result_path(suite), encoding="utf-8") as fh:
            body = json.load(fh)
    except (OSError, ValueError):
        return None
    claimed = body.pop("digest", None)
    body.pop("completed_at", None)
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    if hashlib.sha256(payload.encode()).hexdigest() != claimed:
        return None
    body["digest"] = claimed
    return body


def _version() -> str:
    try:
        with open(os.path.join(ROOT, "docs", "architecture_status.json"),
                  encoding="utf-8") as fh:
            return json.load(fh).get("version", "")
    except (OSError, ValueError):
        return ""


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
