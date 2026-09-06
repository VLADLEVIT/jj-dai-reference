#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build the release artefacts under the pinned environment of ADR-022 D3/D4.

    python3 scripts/build_release.py --prepare      # hash-lock the env
    python3 scripts/build_release.py --build        # sdist, then wheel FROM it
    python3 scripts/build_release.py --compare DIR  # byte-compare a rebuild

Order is load-bearing at three points and each of them was a defect
somewhere before it was a rule here.

1. **Hashes are checked BEFORE installation.** Verifying afterwards verifies
   a decision already taken.
2. **The wheel is built from the already-checked sdist**, not in parallel
   from the tree. Two independent paths from one tree produce two artefacts
   that nobody has compared.
3. **`--no-build-isolation` is used only after the environment is prepared
   hash-locked.** The flag itself cleans nothing; it moves the
   responsibility to the caller, and the preparation step is that
   responsibility being met.

The script does not claim the build is reproducible. It builds, and
`--compare` is what a second builder runs on another machine of the same
class; the comparison is the evidence behind the `verifier` approval of
D5.3. A build asserting reproducibility that was never rebuilt is a claim
about a property nobody measured.
"""
from __future__ import annotations

import filecmp
import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from jjdai import build_env as be                              # noqa: E402
from jjdai import source_tree as st                            # noqa: E402

VENDOR = os.path.join(ROOT, "vendor", "build-backend")


def prepare(rev: str = "HEAD", *, venv_dir: str = None) -> dict:
    """A ONE-SHOT environment holding exactly the pinned set, and nothing else.

    The first cut ran `pip install --force-reinstall` into the current
    interpreter and called that preparation. It created no environment,
    removed no extraneous package, isolated the build hook from nothing and
    could not state the full set of build inputs — the audit said so and it
    was right. What D3 asks for is an environment that did not exist before
    the build: created here, populated hash-locked from `vendor/`, checked
    to be the pinned set exactly, and removed by the caller afterwards.

    The wheels are installed BY THE OUTER interpreter with `--prefix`, and
    the venv is made `--without-pip`, so no bootstrap distribution lands in
    it that the pins do not name. `pip` and `setuptools` seeded by
    `ensurepip` would each be an unpinned build input sitting exactly where
    a build hook can import them.
    """
    pins = be.verify_pinned_wheels(ROOT)
    print(f"  pins verified: {len(pins)} wheel(s)")
    env = be.describe(ROOT, rev)
    print(f"  environment: {env}")

    target = os.path.abspath(venv_dir or os.path.join(ROOT, be.VENV_DIRNAME))
    be.assert_ephemeral_prefix(target)
    if os.path.isdir(target):
        shutil.rmtree(target)
    _run([sys.executable, "-m", "venv", "--without-pip", target])
    wheels = [os.path.join(VENDOR, name) for name in sorted(pins)]
    cmd = [sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
           "--prefix", target, *wheels]
    print("  " + " ".join(cmd))
    _run(cmd)
    be.assert_no_extraneous(target, [p["name"] for p in pins.values()])
    print(f"  prepared: {target}")
    return {"environment": env, "python": be.venv_python(target),
            "venv": target}


#: The only variables a build inherits. Everything else is dropped: a
#: build input nobody pinned is a build input, whether it arrives as a wheel
#: or as a search path. PATH is kept because the interpreter must be
#: executable; HOME because tooling writes caches under it and refuses
#: without one.
ENV_ALLOWLIST = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR",
                 "SYSTEMROOT")

#: Named individually so a reader sees WHAT was excluded rather than
#: trusting that an allowlist is complete. These are the ones that change
#: what code runs rather than where it writes.
ENV_REFUSED = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PIP_",
               "SETUPTOOLS_", "CFLAGS", "CXXFLAGS", "LDFLAGS", "CC", "CXX",
               "MAKEFLAGS", "SOURCE_DATE_EPOCH")


def _clean_environment() -> dict:
    return {k: v for k, v in os.environ.items() if k in ENV_ALLOWLIST}


def _run(cmd, *, extra=None, **kw):
    """EVERY child process of this script starts from the allowlist.

    recut3 cleaned the environment of the two build processes and left
    `python -m venv` and `pip install --prefix` inheriting the shell: the
    audit's diagnostic `PYTHONPATH` and `PIP_CONFIG_FILE` reached both. An
    unpinned search path or an installer configuration that shapes the
    environment BEFORE the clean build runs inside it is the same input
    arriving one step earlier. So there is one way to start a process here,
    and `subprocess.run` is not called anywhere else in this file — BLD-9
    counts.
    """
    env = _clean_environment()
    env.update(extra or {})
    return subprocess.run(cmd, env=env, check=True, **kw)


def build(rev: str = "HEAD", *, python: str = None) -> list:
    """sdist first, then the wheel FROM that sdist. Never in parallel.

    `python` is the interpreter of the environment `prepare()` made. It has
    no default that reaches for the ambient one: building with the outer
    interpreter after preparing an inner one would leave the preparation as
    decoration.
    """
    if python is None:
        raise SystemExit(
            "build() needs the interpreter prepare() created; building with "
            "the ambient interpreter is the defect prepare() was rewritten "
            "to remove")
    st.assert_clean(ROOT)
    env = be.describe(ROOT, rev)
    # BUILT FROM AN ALLOWLIST, not inherited. `dict(os.environ, …)` handed
    # both build processes whatever the ambient shell held — an external
    # `PYTHONPATH=/attacker/build-hooks` reached `python -m build` itself
    # and could replace the very frontend the pins verify. A one-shot venv
    # that inherits the ambient interpreter's search path is one-shot in the
    # filesystem only.
    extra = dict(SOURCE_DATE_EPOCH=env["source_date_epoch"],
                 LC_ALL=be.LOCALE, LANG=be.LOCALE, TZ=be.TIMEZONE,
                 PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1")
    os.umask(be.UMASK)
    _run(be.build_command(python=python), cwd=ROOT, extra=extra)
    dist = os.path.join(ROOT, "dist")
    sdists = sorted(f for f in os.listdir(dist) if f.endswith(".tar.gz"))
    if len(sdists) != 1:
        raise SystemExit(f"expected exactly one sdist in dist/, found "
                         f"{sdists}. Two sdists mean two candidate sources "
                         f"and the wheel would be built from whichever "
                         f"sorted first.")
    sdist = os.path.join(dist, sdists[0])
    _run(be.build_command(sdist, python=python), cwd=ROOT, extra=extra)
    return sorted(os.listdir(dist))


def compare(other: str) -> int:
    """Byte-compare this dist/ against an independent rebuild's.

    Names every difference rather than stopping at the first: a rebuild that
    differs in three files and reports one sends the reader looking for a
    cause that explains only part of what happened.
    """
    mine = os.path.join(ROOT, "dist")
    names = sorted(set(os.listdir(mine)) | set(os.listdir(other)))
    differences = []
    for name in names:
        a, b = os.path.join(mine, name), os.path.join(other, name)
        if not os.path.exists(a) or not os.path.exists(b):
            differences.append(f"{name}: present in only one build")
        elif not filecmp.cmp(a, b, shallow=False):
            differences.append(f"{name}: differs byte for byte")
    for line in differences:
        print(f"  ✗ {line}")
    if differences:
        print(f"REBUILD DIFFERS in {len(differences)} artefact(s). This is "
              f"not a warning: `reproducible: false` does not exist in "
              f"production (ADR-022 D3). An artefact that does not repeat "
              f"goes to the quarantine class, outside the decision path.")
        return 1
    print(f"  rebuild matches byte for byte across {len(names)} artefact(s)")
    return 0


def main(argv) -> int:
    rev = "HEAD"
    if "--prepare" in argv:
        prepare(rev)
        return 0
    if "--build" in argv:
        # One invocation prepares and builds. Splitting them across two
        # processes was how the ambient interpreter got used for the build
        # after a `--prepare` that had installed into it anyway; now the
        # environment is created here and the interpreter that builds is
        # the one that was just checked to hold exactly the pinned set.
        prepared = prepare(rev)
        try:
            for name in build(rev, python=prepared["python"]):
                print(f"  built {name}")
        finally:
            shutil.rmtree(prepared["venv"], ignore_errors=True)
        return 0
    if "--compare" in argv:
        return compare(argv[argv.index("--compare") + 1])
    print(__doc__)
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (be.BuildEnvError, st.SourceTreeError) as exc:
        print(f"REFUSED [{exc.code}] {exc}")
        raise SystemExit(1) from None
