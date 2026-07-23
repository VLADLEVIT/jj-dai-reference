#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/gen_dev_certs.py — dev CA + per-node TLS certificates (v0.5.1)
======================================================================
Generates, via the system `openssl` binary:

    <out>/ca.crt  ca.key            — a throwaway development CA
    <out>/<name>.crt  <name>.key    — one leaf per node name, signed by the
                                      CA, SAN = DNS:localhost, IP:127.0.0.1
                                      (+ any extra --san entries)

These are DEVELOPMENT certificates for loopback and lab networks. For a
real deployment: real PKI, real names, real rotation. The daemon's mTLS
mode (`--tls-ca --tls-require-client-cert`) trusts exactly the CA you pass
it — nothing from the system store.

    python3 scripts/gen_dev_certs.py --out ./certs node-a node-b node-c
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys


def sh(*cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"openssl failed: {' '.join(cmd)}\n{r.stderr}")


def gen_ca(out: str, days: int):
    ca_key = os.path.join(out, "ca.key")
    ca_crt = os.path.join(out, "ca.crt")
    sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", ca_key)
    sh("openssl", "req", "-x509", "-new", "-key", ca_key, "-out", ca_crt,
       "-days", str(days), "-subj", "/CN=jjdai-dev-ca",
       "-addext", "basicConstraints=critical,CA:TRUE",
       "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    os.chmod(ca_key, 0o600)
    return ca_key, ca_crt


def gen_leaf(out: str, name: str, ca_key: str, ca_crt: str,
             sans: list, days: int):
    key = os.path.join(out, f"{name}.key")
    csr = os.path.join(out, f"{name}.csr")
    crt = os.path.join(out, f"{name}.crt")
    ext = os.path.join(out, f"{name}.ext")
    san = ",".join(["DNS:localhost", "IP:127.0.0.1"] + list(sans))
    sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", key)
    sh("openssl", "req", "-new", "-key", key, "-out", csr,
       "-subj", f"/CN={name}")
    with open(ext, "w") as f:
        f.write("basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth,clientAuth\n"
                f"subjectAltName={san}\n")
    sh("openssl", "x509", "-req", "-in", csr, "-CA", ca_crt,
       "-CAkey", ca_key, "-CAcreateserial", "-out", crt,
       "-days", str(days), "-extfile", ext)
    os.chmod(key, 0o600)
    os.remove(csr)
    os.remove(ext)
    return key, crt


def main(argv=None):
    ap = argparse.ArgumentParser(description="JJ DAI dev TLS certificates")
    ap.add_argument("names", nargs="+", help="node names (one leaf each)")
    ap.add_argument("--out", default="./certs")
    ap.add_argument("--days", type=int, default=30,
                    help="validity (short by design: dev certs rot fast)")
    ap.add_argument("--san", action="append", default=[],
                    help="extra SAN entries, e.g. DNS:node-a.lab")
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    ca_key, ca_crt = gen_ca(args.out, args.days)
    for name in args.names:
        gen_leaf(args.out, name, ca_key, ca_crt, args.san, args.days)
        print(f"  leaf: {name}.crt / {name}.key")
    print(f"CA: {ca_crt}  (dev only — {args.days}d)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
