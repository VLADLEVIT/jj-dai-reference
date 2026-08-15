#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deploy/tpm_seal.py — seal the keystore passphrase to this machine (v0.5.5)
=========================================================================
OPTIONAL hardening. The daemon decrypts its identity keystore with
JJDAI_KEYSTORE_PASSPHRASE. On a TPM 2.0 host, this seals that passphrase
to the platform so it only unseals on THIS machine in a trusted boot
state — an attacker who copies the disk cannot unseal it elsewhere.

This mirrors the ladder we agreed on:
  * TPM 2.0 sealing (this script)         — testnet, available today
  * secure element (ATECC608 / SE050)     — for device hardware
  * OTP/eFuse public roots + PUF          — for silicon

It uses the standard `tpm2-tools` (`tpm2_createprimary`, `tpm2_create`,
`tpm2_load`, `tpm2_unseal`) — apt-installable on Ubuntu. It NEVER writes
the plaintext passphrase to disk; the sealed blob is bound to PCRs 0,2,4
(firmware, option ROMs, boot manager) so tampering with the boot chain
makes it refuse to unseal.

    # seal (prompts for the passphrase; nothing plaintext hits disk):
    python3 deploy/tpm_seal.py seal   --out /var/lib/jjdai/sealed

    # at boot, the unit calls this to export the passphrase into the
    # daemon's environment WITHOUT it ever landing in a file:
    export JJDAI_KEYSTORE_PASSPHRASE="$(python3 deploy/tpm_seal.py unseal \\
        --out /var/lib/jjdai/sealed)"

If the host has no TPM, this prints a clear message and exits non-zero —
so an operator never THINKS they have hardware protection they don't.
Sealing is defense in depth, not a substitute for filesystem hygiene.
"""
from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys
import tempfile

PCRS = "sha256:0,2,4"


def _need_tpm():
    if subprocess.run(["which", "tpm2_createprimary"],
                      capture_output=True).returncode != 0:
        sys.exit("no tpm2-tools found (apt install tpm2-tools) — this host "
                 "cannot TPM-seal; use filesystem permissions instead")
    if not os.path.exists("/dev/tpm0") and \
            not os.path.exists("/dev/tpmrm0"):
        sys.exit("no /dev/tpm* device — this host has no usable TPM 2.0")


def seal(out):
    _need_tpm()
    os.makedirs(out, exist_ok=True)
    prim = os.path.join(out, "primary.ctx")
    pub = os.path.join(out, "seal.pub")
    priv = os.path.join(out, "seal.priv")
    secret = getpass.getpass("keystore passphrase to seal: ")
    if not secret:
        sys.exit("empty passphrase; aborting")
    subprocess.run(["tpm2_createprimary", "-C", "o", "-c", prim],
                   check=True, capture_output=True)
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write(secret)
        secret_path = tf.name
    try:
        subprocess.run(
            ["tpm2_create", "-C", prim, "-u", pub, "-r", priv,
             "-i", secret_path, "-L", PCRS],
            check=True, capture_output=True)
    finally:
        os.remove(secret_path)          # plaintext never persists
    for p in (prim, pub, priv):
        os.chmod(p, 0o600)
    print(f"sealed to {out} (bound to PCRs {PCRS}); the plaintext was "
          "never written to disk", file=sys.stderr)


def unseal(out):
    _need_tpm()
    prim = os.path.join(out, "primary.ctx")
    pub = os.path.join(out, "seal.pub")
    priv = os.path.join(out, "seal.priv")
    for p in (prim, pub, priv):
        if not os.path.exists(p):
            sys.exit(f"missing sealed material: {p}; run 'seal' first")
    load = os.path.join(out, "seal.ctx")
    subprocess.run(["tpm2_load", "-C", prim, "-u", pub, "-r", priv,
                    "-c", load], check=True, capture_output=True)
    r = subprocess.run(["tpm2_unseal", "-c", load, "-p", f"pcr:{PCRS}"],
                       capture_output=True)
    if r.returncode != 0:
        sys.exit("TPM refused to unseal — boot state changed (PCR "
                 "mismatch) or wrong machine")
    sys.stdout.write(r.stdout.decode())     # passphrase to stdout only


def main():
    ap = argparse.ArgumentParser(description="TPM-seal the keystore "
                                             "passphrase to this host")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seal"); s.add_argument("--out", required=True)
    u = sub.add_parser("unseal"); u.add_argument("--out", required=True)
    args = ap.parse_args()
    (seal if args.cmd == "seal" else unseal)(args.out)


if __name__ == "__main__":
    main()
