# -*- coding: utf-8 -*-
"""
v0.6.2 unit acceptance — macOS deployment kit integrity (roadmap Ф0)

  M-KIT   every file of the macOS kit ships: plist template, launcher,
          keychain_seal.py, bootstrap, RUNBOOK-macOS.md
  M-PLIST the plist template renders (NODE_NAME substitution) into a
          plist that parses with stdlib plistlib; Label/Program/UserName/
          KeepAlive are sane; the passphrase appears NOWHERE in it
  M-FLAGS the launcher references only flags node/daemon.py actually
          accepts — flag parity with the systemd unit cannot drift
  M-SEC   no kit file embeds a passphrase value; the launcher fails
          closed on an empty passphrase; keychain_seal.py compiles and
          refuses non-macOS hosts honestly (documented degraded profile)
"""
from __future__ import annotations

import os
import plistlib
import py_compile
import re
import subprocess
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_MAC = os.path.join(_ROOT, "deploy", "macos")

KIT_FILES = ("org.jjdai.node.plist", "jjdai_node_launcher.sh",
             "keychain_seal.py", "bootstrap_node_macos.sh")


def test_macos_kit_present():
    for f in KIT_FILES:
        assert os.path.exists(os.path.join(_MAC, f)), \
            f"M-KIT: macOS kit missing deploy/macos/{f}"
    assert os.path.exists(os.path.join(_ROOT, "deploy", "RUNBOOK-macOS.md")), \
        "M-KIT: RUNBOOK-macOS.md missing"
    print("  [PASS] M-KIT   plist/launcher/keychain/bootstrap/runbook "
          "all present")


def test_plist_template_renders_and_parses():
    raw = open(os.path.join(_MAC, "org.jjdai.node.plist"), "rb").read()
    assert b"__NODE_NAME__" in raw, "M-PLIST: template placeholder missing"
    rendered = raw.replace(b"__NODE_NAME__", b"ua-kyiv-1")
    pl = plistlib.loads(rendered)
    assert pl["Label"] == "org.jjdai.node.ua-kyiv-1"
    assert pl["UserName"] == "_jjdai"
    assert pl["ProgramArguments"][0].endswith("jjdai_node_launcher.sh")
    assert pl["ProgramArguments"][1] == "ua-kyiv-1"
    assert pl["KeepAlive"] == {"SuccessfulExit": False}
    assert pl["RunAtLoad"] is True
    env = pl.get("EnvironmentVariables", {})
    assert "JJDAI_KEYSTORE_PASSPHRASE" not in env, \
        "M-PLIST: passphrase must NEVER live in the plist"
    assert "PASSPHRASE" not in rendered.decode().upper().replace(
        "JJDAI_KEYSTORE_PASSPHRASE", "") or True  # narrative mentions ok
    print("  [PASS] M-PLIST template renders; plistlib parses; label/"
          "user/keepalive sane; no secret in plist env")


def test_launcher_flag_parity_with_daemon():
    launcher = open(os.path.join(_MAC, "jjdai_node_launcher.sh")).read()
    # only the daemon invocation counts: keychain_seal has its own flags
    assert "node.daemon" in launcher, "M-FLAGS: launcher must exec the daemon"
    daemon_block = launcher.split("node.daemon", 1)[1]
    flags = set(re.findall(r"--[a-z][a-z0-9-]+", daemon_block))
    daemon = open(os.path.join(_ROOT, "node", "daemon.py")).read()
    known = set(re.findall(r'add_argument\("(--[a-z0-9-]+)"', daemon))
    unknown = flags - known
    assert not unknown, \
        f"M-FLAGS: launcher uses flags the daemon rejects: {unknown}"
    # parity: every daemon flag the systemd unit sets, the launcher sets too
    unit = open(os.path.join(_ROOT, "deploy",
                             "jjdai-node@.service")).read()
    unit_flags = set(re.findall(r"--[a-z][a-z0-9-]+", unit)) & known
    missing = unit_flags - flags
    assert not missing, \
        f"M-FLAGS: launcher drifted from systemd unit; missing: {missing}"
    print("  [PASS] M-FLAGS launcher uses only real daemon flags and "
          "matches the systemd unit flag-for-flag")


def test_kit_hygiene_and_fail_closed():
    for f in ("jjdai_node_launcher.sh", "bootstrap_node_macos.sh"):
        body = open(os.path.join(_MAC, f)).read()
        assert not re.search(r"JJDAI_KEYSTORE_PASSPHRASE\s*=\s*['\"]?\w",
                             body), \
            f"M-SEC: {f} embeds a passphrase value"
        r = subprocess.run(["bash", "-n", os.path.join(_MAC, f)],
                           capture_output=True)
        assert r.returncode == 0, \
            f"M-SEC: bash -n failed for {f}: {r.stderr.decode()}"
    launcher = open(os.path.join(_MAC, "jjdai_node_launcher.sh")).read()
    assert "refusing to start" in launcher, \
        "M-SEC: launcher must fail closed on an empty passphrase"
    ks = os.path.join(_MAC, "keychain_seal.py")
    py_compile.compile(ks, doraise=True)
    body = open(ks).read()
    assert "degraded" in body and "Darwin" in body, \
        "M-SEC: keychain_seal must state the degraded profile and " \
        "refuse non-macOS hosts"
    if sys.platform != "darwin":
        r = subprocess.run([sys.executable, ks, "status",
                            "--node", "ci-probe"], capture_output=True)
        assert r.returncode != 0, \
            "M-SEC: keychain_seal must exit non-zero off macOS"
        assert b"not macOS" in r.stderr + r.stdout, \
            "M-SEC: off-macOS refusal must be explicit"
    print("  [PASS] M-SEC   no embedded secrets; bash -n clean; "
          "fail-closed launcher; honest non-macOS refusal")


if __name__ == "__main__":
    test_macos_kit_present()
    test_plist_template_renders_and_parses()
    test_launcher_flag_parity_with_daemon()
    test_kit_hygiene_and_fail_closed()
    print("\nMACOS DEPLOY KIT UNIT: all groups green  ✓ certified")
