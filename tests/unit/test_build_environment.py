#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The pinned build environment and the backend hash gate.

ADR-022 D3, D4. The gap this closes is narrow and easy to describe: PEP 517
gives `[build-system].requires` no place for a hash, so `setuptools==80.9.0`
promises a LABEL and not bytes. Everything below is about closing that
outside `pyproject.toml` without pretending the flag `--no-build-isolation`
does it by itself.

  BLD-1  Pins live OUTSIDE pyproject, cover the backend AND its
         dependencies, and an unfilled pin refuses loudly.
  BLD-2  The version in `pyproject.toml` and the version in the pin file
         agree — two places naming one backend must not drift.
  BLD-3  Hashes are checked BEFORE installation, and a mismatch refuses.
  BLD-4  `SOURCE_DATE_EPOCH` is the COMMITTER time, by the named route.
  BLD-5  The network is MEASURED, not assumed.
  BLD-6  The wheel is built from the already-checked sdist, and isolation is
         off only because the environment was prepared.
  BLD-7  The environment table is complete and is compared field by field
         against what a statement records.
"""
import io as _io
import json
import os
import subprocess
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai import build_env as be                              # noqa: E402


def _code(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except be.BuildEnvError as exc:
        return exc.code
    except Exception as exc:                                   # noqa: BLE001
        return type(exc).__name__
    return None


def _pins_doc(**over):
    doc = {"schema": be.PINS_SCHEMA, "wheels": [
        {"name": "setuptools", "version": "80.9.0",
         "filename": "setuptools-80.9.0-py3-none-any.whl",
         "sha256": "ab" * 32}]}
    doc.update(over)
    return doc


def _tree(tmp, doc, wheels=None):
    root = os.path.join(tmp, "t")
    vendor = os.path.join(root, "vendor", "build-backend")
    os.makedirs(vendor, exist_ok=True)
    if doc is not None:
        _io.open(os.path.join(vendor, "PINS.json"), "w",
                 encoding="utf-8", newline="\n").write(json.dumps(doc))
    for name, body in (wheels or {}).items():
        with open(os.path.join(vendor, name), "wb") as f:
            f.write(body)
    return root


def test_pins_live_outside_pyproject_and_refuse_unfilled():
    """BLD-1"""
    pyproject = _io.open(os.path.join(_ROOT, "pyproject.toml"),
                         encoding="utf-8").read()
    build_system = pyproject.split("[project]")[0]
    # A digest may be MENTIONED in the comment that explains where the real
    # pin lives; what must not appear is a `sha256 = ...` key, which every
    # frontend ignores — PEP 517 has no field for it, so writing one there
    # is a pin that does not pin while looking like one that does.
    assert "sha256 =" not in build_system and "sha256=" not in build_system
    assert be.PINS_FILE in pyproject, (
        "pyproject must point at where the real pin lives, or a reader "
        "finds a version pin and concludes that is all there is")
    pins_path = os.path.join(_ROOT, *be.PINS_FILE.split("/"))
    doc = json.load(_io.open(pins_path, encoding="utf-8"))
    names = {w["name"] for w in doc["wheels"]}
    assert "setuptools" in names
    assert len(names) > 1, (
        "D4 pins the backend AND all of its dependencies; pinning the "
        "backend alone leaves the rest resolving from an index")
    # the shipped file is unfilled and says so by refusing
    assert _code(be.load_pins, _ROOT) == be.BUILD_PIN_MISSING
    with tempfile.TemporaryDirectory() as tmp:
        assert _code(be.load_pins, _tree(tmp, None)) == be.BUILD_PIN_MISSING
        assert _code(be.load_pins,
                     _tree(tmp, _pins_doc(wheels=[]))) == be.BUILD_PIN_MISSING
        short = _pins_doc()
        short["wheels"][0]["sha256"] = "x"
        assert _code(be.load_pins, _tree(tmp, short)) == be.BUILD_PIN_MISMATCH
    print("  [PASS] BLD-1  pins live outside pyproject, cover the "
          "dependencies, and an unfilled pin refuses")


def test_pyproject_and_pin_file_name_one_version():
    """BLD-2"""
    pyproject = _io.open(os.path.join(_ROOT, "pyproject.toml"),
                         encoding="utf-8").read()
    doc = json.load(_io.open(os.path.join(_ROOT, *be.PINS_FILE.split("/")),
                             encoding="utf-8"))
    backend = [w for w in doc["wheels"] if w["name"] == "setuptools"][0]
    assert f'setuptools=={backend["version"]}' in pyproject, (
        f"pyproject and {be.PINS_FILE} name different setuptools versions. "
        f"Two places describing one backend drift, and the build would "
        f"verify one wheel and ask the frontend for another")
    assert backend["version"] in backend["filename"], (
        "the pinned filename does not carry the pinned version")
    print("  [PASS] BLD-2  pyproject and the pin file name one backend "
          "version")


def test_hashes_are_checked_before_installation():
    """BLD-3"""
    with tempfile.TemporaryDirectory() as tmp:
        good = b"wheel bytes"
        import hashlib
        digest = hashlib.sha256(good).hexdigest()
        doc = _pins_doc()
        doc["wheels"][0]["sha256"] = digest
        name = doc["wheels"][0]["filename"]
        root = _tree(tmp, doc, {name: good})
        assert be.verify_pinned_wheels(root)
        # a wheel that differs refuses — and refuses BEFORE any install step
        with open(os.path.join(root, "vendor", "build-backend", name),
                  "wb") as f:
            f.write(b"other bytes")
        assert _code(be.verify_pinned_wheels, root) == be.BUILD_PIN_MISMATCH
        # a pinned wheel that is absent refuses too: fetching it at build
        # time would put the index back in the chain the pin removes
        os.remove(os.path.join(root, "vendor", "build-backend", name))
        assert _code(be.verify_pinned_wheels, root) == be.BUILD_PIN_MISSING
    # the ordering is a property of the script, asserted on its source
    src = _io.open(os.path.join(_ROOT, "scripts", "build_release.py"),
                   encoding="utf-8").read()
    verify_at = src.index("verify_pinned_wheels")
    install_at = src.index('"install"')
    assert verify_at < install_at, (
        "installation happens before verification; verifying afterwards "
        "verifies a decision already taken")
    print("  [PASS] BLD-3  every pinned wheel is hashed before anything "
          "installs it")


def test_source_date_epoch_is_committer_time():
    """BLD-4"""
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "r")
        os.makedirs(root)
        for cmd in (["git", "init", "-q"],
                    ["git", "config", "user.email", "t@t"],
                    ["git", "config", "user.name", "t"]):
            subprocess.run(cmd, cwd=root, check=True)
        _io.open(os.path.join(root, "a.txt"), "w").write("a\n")
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        env = dict(os.environ, GIT_AUTHOR_DATE="1000000000 +0000",
                   GIT_COMMITTER_DATE="2000000000 +0000")
        subprocess.run(["git", "commit", "-qm", "t"], cwd=root, env=env,
                       check=True)
        got = be.source_date_epoch(root)
        assert got == "2000000000", (
            f"got {got}: author time survives a rebase or a cherry-pick "
            f"while the tree moves on, so two different trees would carry "
            f"one timestamp. D3 names the committer time")
        assert "%ct" in _io.open(
            os.path.join(_ROOT, "jjdai", "build_env.py"),
            encoding="utf-8").read()
    assert _code(be.source_date_epoch, tempfile.gettempdir()) == \
        be.BUILD_EPOCH_UNAVAILABLE
    print("  [PASS] BLD-4  SOURCE_DATE_EPOCH is the committer time by the "
          "named route; a non-git tree refuses")


def test_network_is_measured():
    """BLD-5"""
    assert be.NETWORK_DISABLED == "disabled-and-checked"
    real = be.network_is_unreachable
    try:
        be.network_is_unreachable = lambda *a, **k: False
        assert _code(be.assert_network_disabled) == \
            be.BUILD_NETWORK_REACHABLE
        be.network_is_unreachable = lambda *a, **k: True
        be.assert_network_disabled()
    finally:
        be.network_is_unreachable = real
    # `describe` refuses to fill the table while the network is up: the
    # table is inside what the approvals sign, so a value of
    # "disabled-and-checked" written on a connected host would be a signed
    # statement of something nobody measured
    try:
        be.network_is_unreachable = lambda *a, **k: False
        assert _code(be.describe, _ROOT) == be.BUILD_NETWORK_REACHABLE
    finally:
        be.network_is_unreachable = real
    print("  [PASS] BLD-5  the network is probed, and the table cannot be "
          "filled while it answers")


def test_wheel_comes_from_the_checked_sdist():
    """BLD-6"""
    sdist_cmd = be.build_command()
    wheel_cmd = be.build_command("dist/x.tar.gz")
    assert "--sdist" in sdist_cmd and "--wheel" not in sdist_cmd
    assert "--wheel" in wheel_cmd and wheel_cmd[-1] == "dist/x.tar.gz", (
        "the wheel must be built FROM the sdist; two independent paths from "
        "one tree produce two artefacts nobody has compared")
    for cmd in (sdist_cmd, wheel_cmd):
        assert "--no-isolation" in cmd
    src = _io.open(os.path.join(_ROOT, "scripts", "build_release.py"),
                   encoding="utf-8").read()
    assert "cleans nothing" in src, (
        "the caveat must be written where the flag is used: "
        "--no-build-isolation moves the responsibility to the caller and "
        "does not meet it")
    assert src.index("def prepare") < src.index("def build")
    print("  [PASS] BLD-6  sdist first, wheel from it, isolation off only "
          "after a prepared environment")


def test_environment_table_is_complete_and_compared():
    """BLD-7"""
    assert be.ENV_FIELDS == ("python", "locale", "timezone", "umask",
                             "network", "network_enforcement",
                             "source_date_epoch")
    assert (be.LOCALE, be.TIMEZONE, be.UMASK) == ("C", "UTC", 0o022)
    recorded = {"python": "CPython 3.12.3", "locale": "C", "timezone": "UTC",
                "umask": "0022", "network": be.NETWORK_DISABLED,
                "network_enforcement": be.NETWORK_ENFORCEMENT_ASSERTED,
                "source_date_epoch": "1700000000"}
    assert be.environment_matches(recorded, dict(recorded)) == []
    drifted = dict(recorded, locale="en_US.UTF-8", umask="0002")
    assert be.environment_matches(recorded, drifted) == ["locale", "umask"], (
        "every differing field must be named: reporting one of three sends "
        "the reader after a cause that explains part of what happened")
    # a missing field counts as a difference rather than as agreement
    assert "source_date_epoch" in be.environment_matches(
        recorded, {k: v for k, v in recorded.items()
                   if k != "source_date_epoch"})
    print("  [PASS] BLD-7  the environment table is complete and compared "
          "field by field")


def test_the_prepared_environment_is_ephemeral_and_exactly_the_pins():
    """BLD-8

    `--prepare` ran `pip install --force-reinstall` into the CURRENT
    interpreter and called that a clean environment. It created nothing,
    removed nothing, isolated the build hook from nothing, and could not
    state the full set of build inputs because it never controlled the set.
    """
    # 1. the ambient interpreter is refused as a target
    assert _code(be.assert_ephemeral_prefix, sys.prefix) == \
        be.BUILD_ENV_NOT_EPHEMERAL
    assert _code(be.assert_ephemeral_prefix, sys.base_prefix) == \
        be.BUILD_ENV_NOT_EPHEMERAL

    with tempfile.TemporaryDirectory() as tmp:
        be.assert_ephemeral_prefix(tmp)
        site = os.path.join(tmp, "lib", "python3.12", "site-packages")
        os.makedirs(os.path.join(site, "build-1.2.2.post1.dist-info"))
        os.makedirs(os.path.join(site, "setuptools-80.9.0.dist-info"))
        assert be.assert_no_extraneous(tmp, ["build", "setuptools"]) == \
            {"build", "setuptools"}
        # 2. anything the pins do not name is a build input nobody hashed —
        #    including the two `ensurepip` would seed, which is why the venv
        #    is made --without-pip and populated from outside
        os.makedirs(os.path.join(site, "pip-24.0.dist-info"))
        assert _code(be.assert_no_extraneous, tmp,
                     ["build", "setuptools"]) == be.BUILD_ENV_NOT_CLEAN
        # 3. and a pin that did not arrive counts as a difference too: an
        #    environment missing a build input is not the verified one
        assert _code(be.assert_no_extraneous, tmp,
                     ["build", "setuptools", "pip", "wheel"]) == \
            be.BUILD_ENV_NOT_CLEAN

    # 4. the network claim is widened AND downgraded. Two endpoints were a
    #    hole; six are a wider net and still a net, so the table says who is
    #    asserting the denial rather than presenting a probe as proof.
    assert len(be.NETWORK_PROBES) >= 6
    assert len({host for host, _ in be.NETWORK_PROBES}) >= 6
    assert "network_enforcement" in be.ENV_FIELDS
    real_epoch = be.source_date_epoch
    be.source_date_epoch = lambda *a, **k: "1700000000"
    was = os.environ.get(be.NETWORK_ENFORCEMENT_ENV)
    try:
        os.environ.pop(be.NETWORK_ENFORCEMENT_ENV, None)
        assert be.describe(_ROOT, check_network=False)["network_enforcement"] \
            == be.NETWORK_ENFORCEMENT_ASSERTED
        # a host that names its mechanism has told a reader where to go and
        # look; it has not proved anything to this process, and the prefix
        # is what keeps the two apart
        os.environ[be.NETWORK_ENFORCEMENT_ENV] = "netns:none"
        named = be.describe(_ROOT, check_network=False)["network_enforcement"]
        assert named == "asserted:netns:none"
        assert named.startswith(be.NETWORK_ENFORCEMENT_ASSERTED)
    finally:
        be.source_date_epoch = real_epoch
        os.environ.pop(be.NETWORK_ENFORCEMENT_ENV, None)
        if was is not None:
            os.environ[be.NETWORK_ENFORCEMENT_ENV] = was

    src = _io.open(os.path.join(_ROOT, "scripts", "build_release.py"),
                   encoding="utf-8").read()
    # the FLAG, not the word: the docstring names the old behaviour on
    # purpose, and a check that cannot tell prose from an argument would
    # force the history out of the file to stay green
    assert '"--force-reinstall"' not in src, (
        "reinstalling into the live interpreter is what this check exists "
        "to keep out of the tree")
    assert "--without-pip" in src and "--prefix" in src
    assert "shutil.rmtree" in src, "one-shot means removed, not reused"
    # 5. building with the ambient interpreter after preparing an inner one
    #    would leave the preparation as decoration
    sys.path.insert(0, os.path.join(_ROOT, "scripts"))
    import build_release as br
    try:
        br.build()
        raise AssertionError("build() ran without a prepared interpreter")
    except SystemExit as exc:
        assert "prepare()" in str(exc)
    print("  [PASS] BLD-8  the build environment is created for the build, "
          "holds exactly the pinned set, and is refused otherwise")


def test_the_build_environment_is_built_not_inherited():
    """BLD-9 · the audit of recut2, P0-6

    The one-shot venv was real and still porous: `child = dict(os.environ,
    …)` handed both build processes whatever the ambient shell held. An
    external `PYTHONPATH=/attacker/build-hooks` reached `python -m build`
    itself and could replace the frontend the pins verify. A venv that
    inherits the ambient search path is one-shot in the filesystem only.
    """
    sys.path.insert(0, os.path.join(_ROOT, "scripts"))
    import build_release as br

    was = {k: os.environ.get(k) for k in ("PYTHONPATH", "PIP_INDEX_URL",
                                          "CFLAGS", "PATH")}
    try:
        os.environ["PYTHONPATH"] = "/attacker/build-hooks"
        os.environ["PIP_INDEX_URL"] = "https://attacker.example/simple"
        os.environ["CFLAGS"] = "-fplugin=/attacker/plugin.so"
        clean = br._clean_environment()
        for banned in ("PYTHONPATH", "PIP_INDEX_URL", "CFLAGS"):
            assert banned not in clean, banned
        assert "PATH" in clean, (
            "the interpreter must still be executable; an allowlist that "
            "keeps nothing is a build that cannot run")
    finally:
        for k, v in was.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # the refusals are NAMED, not merely absent from a list: a reader can
    # see WHAT was excluded rather than trust that an allowlist is complete
    for name in ("PYTHONPATH", "PYTHONHOME", "PIP_", "SETUPTOOLS_", "CFLAGS"):
        assert name in br.ENV_REFUSED
    src = _io.open(os.path.join(_ROOT, "scripts", "build_release.py"),
                   encoding="utf-8").read()
    # the ASSIGNMENT, not the word: the comment names the old behaviour on
    # purpose, and a check that cannot tell prose from code would force the
    # history out of the file to stay green
    assert "child = dict(os.environ" not in src, (
        "inheriting the ambient environment is the defect this check exists "
        "to keep out of the tree")
    assert "_clean_environment()" in src
    # ONE WAY TO START A PROCESS, and it is the clean one. recut3 cleaned
    # the two build processes and left `python -m venv` and `pip install
    # --prefix` inheriting the shell — the environment was shaped by an
    # unpinned search path one step before the clean build ran inside it.
    assert src.count("subprocess.run(") == 1, (
        "every child process must go through _run(); a second call site is "
        "a second inheritance")
    seen = {}
    real = br.subprocess.run

    def _spy(cmd, **kw):
        seen["env"] = kw.get("env")
        return None

    was_pp = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = "/attacker/build-hooks"
    os.environ["PIP_CONFIG_FILE"] = "/attacker/pip.conf"
    br.subprocess.run = _spy
    try:
        br._run(["true"], extra={"SOURCE_DATE_EPOCH": "1"})
    finally:
        br.subprocess.run = real
        os.environ.pop("PIP_CONFIG_FILE", None)
        if was_pp is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = was_pp
    assert seen["env"] is not None and "PYTHONPATH" not in seen["env"]
    assert "PIP_CONFIG_FILE" not in seen["env"]
    assert seen["env"]["SOURCE_DATE_EPOCH"] == "1"
    print("  [PASS] BLD-9  the child environment is built from an allowlist, "
          "not inherited from whatever shell ran the build")


if __name__ == "__main__":
    for fn in (test_pins_live_outside_pyproject_and_refuse_unfilled,
               test_pyproject_and_pin_file_name_one_version,
               test_hashes_are_checked_before_installation,
               test_source_date_epoch_is_committer_time,
               test_network_is_measured,
               test_wheel_comes_from_the_checked_sdist,
               test_environment_table_is_complete_and_compared,
               test_the_prepared_environment_is_ephemeral_and_exactly_the_pins,
               test_the_build_environment_is_built_not_inherited):
        fn()
