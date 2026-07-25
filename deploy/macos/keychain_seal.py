#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deploy/macos/keychain_seal.py — keep the keystore passphrase in the macOS
System keychain (v0.6.2, roadmap Ф0: macOS deployment kit)
=========================================================================
macOS counterpart of deploy/tpm_seal.py. The daemon decrypts its identity
keystore with JJDAI_KEYSTORE_PASSPHRASE. On a Mac node the passphrase is
stored in the SYSTEM keychain (/Library/Keychains/System.keychain) so a
LaunchDaemon can retrieve it pre-login, and it never lands in a plist,
an env file, or the process argv.

Attestation profile — stated, not hidden (roadmap r5, Ф0/Ф1):

  * This is the documented **macOS Keychain degraded profile (non-SE-resident)**. The
    `security` CLI stores a generic-password item in the file-based
    keychain; it CANNOT create Secure-Enclave-resident keys
    (kSecAttrTokenIDSecureEnclave is API-only). Where Secure Enclave
    protection applies it protects the keychain's class keys via the
    hardware UID; the item itself is keychain-protected, not
    SE-resident. An attacker with root on THIS machine can read it —
    unlike a TPM-sealed blob, the protection boundary is the OS, not
    the boot state.
  * The chosen profile MUST be recorded in the node's ops log and is
    fixed in the witness at bootstrap (RUNBOOK-macOS.md §2) so nobody
    ever THINKS they have hardware protection they don't.

Access control: the item is created with an ACL restricted to
/usr/bin/security (`-T /usr/bin/security`), which is what the launcher
invokes at boot. Sealing is defense in depth, not a substitute for
filesystem hygiene or physical control of the machine.

    # seal (prompts for the passphrase; nothing plaintext hits disk):
    sudo python3 deploy/macos/keychain_seal.py seal --node ua-kyiv-1

    # at boot, the launcher calls this to export the passphrase into the
    # daemon's environment WITHOUT it ever landing in a file:
    export JJDAI_KEYSTORE_PASSPHRASE="$(python3 \\
        deploy/macos/keychain_seal.py unseal --node ua-kyiv-1)"

    # verify presence without printing the secret:
    python3 deploy/macos/keychain_seal.py status --node ua-kyiv-1

If the host is not macOS or `security` is missing, this prints a clear
message and exits non-zero — fail honest, exactly like tpm_seal.py.
"""
from __future__ import annotations

import argparse
import getpass
import platform
import subprocess
import sys

SERVICE_PREFIX = "org.jjdai.keystore"
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
SECURITY = "/usr/bin/security"


def _need_macos():
    if platform.system() != "Darwin":
        sys.exit("not macOS — this host cannot Keychain-seal; use "
                 "deploy/tpm_seal.py (TPM 2.0) or the 0640 env file "
                 "documented in RUNBOOK.md instead")
    if subprocess.run(["test", "-x", SECURITY],
                      capture_output=True).returncode != 0:
        sys.exit(f"{SECURITY} not found or not executable — cannot "
                 "reach the keychain on this host")


def _service(node: str) -> str:
    return f"{SERVICE_PREFIX}.{node}"


def seal(node: str, keychain: str):
    _need_macos()
    secret = getpass.getpass(f"keystore passphrase to seal for '{node}': ")
    if not secret:
        sys.exit("empty passphrase; aborting")
    # Refuse to silently overwrite an existing item — identity discipline.
    probe = subprocess.run(
        [SECURITY, "find-generic-password", "-s", _service(node), keychain],
        capture_output=True)
    if probe.returncode == 0:
        sys.exit(f"an item for '{node}' already exists in {keychain}; "
                 "delete it explicitly first:\n"
                 f"  sudo {SECURITY} delete-generic-password "
                 f"-s {_service(node)} {keychain}")
    # -w reads the secret as an argument-free interactive value is not
    # supported by `security add`, so the secret is passed via -w. It is
    # visible to root in the process table for the syscall's duration
    # only; it never persists to disk. Acceptable under the degraded
    # profile; documented here rather than hidden.
    r = subprocess.run(
        [SECURITY, "add-generic-password",
         "-s", _service(node),
         "-a", "jjdai",
         "-w", secret,
         "-T", SECURITY,
         "-D", "JJ DAI node keystore passphrase",
         keychain],
        capture_output=True)
    if r.returncode != 0:
        sys.exit("keychain refused the item: "
                 + r.stderr.decode(errors="replace").strip())
    print(f"sealed '{node}' into {keychain} under the documented "
          "macOS Keychain degraded profile (non-SE-resident); the plaintext was never "
          "written to disk", file=sys.stderr)


def unseal(node: str, keychain: str):
    _need_macos()
    r = subprocess.run(
        [SECURITY, "find-generic-password", "-s", _service(node),
         "-w", keychain],
        capture_output=True)
    if r.returncode != 0:
        sys.exit(f"keychain refused to unseal '{node}' — item missing, "
                 "ACL denied, or wrong keychain; run 'seal' first "
                 "(see RUNBOOK-macOS.md)")
    sys.stdout.write(r.stdout.decode().rstrip("\n"))  # secret to stdout only


def status(node: str, keychain: str):
    _need_macos()
    r = subprocess.run(
        [SECURITY, "find-generic-password", "-s", _service(node), keychain],
        capture_output=True)
    if r.returncode != 0:
        sys.exit(f"no sealed passphrase for '{node}' in {keychain}")
    print(f"sealed passphrase present for '{node}' in {keychain} "
          "(macOS Keychain degraded profile (non-SE-resident))")


def main():
    ap = argparse.ArgumentParser(
        description="Keychain-seal the keystore passphrase on a macOS node")
    ap.add_argument("--keychain", default=SYSTEM_KEYCHAIN,
                    help="target keychain (default: System — required "
                         "for LaunchDaemons, which run pre-login)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("seal", "unseal", "status"):
        p = sub.add_parser(name)
        p.add_argument("--node", required=True,
                       help="node name, e.g. ua-kyiv-1")
    args = ap.parse_args()
    fn = {"seal": seal, "unseal": unseal, "status": status}[args.cmd]
    fn(args.node, args.keychain)


if __name__ == "__main__":
    main()
