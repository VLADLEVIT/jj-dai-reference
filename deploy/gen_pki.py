#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deploy/gen_pki.py — production PKI for a JJ DAI node fleet (v0.5.5)
==================================================================
Unlike scripts/gen_dev_certs.py (dev convenience: one call, everything
in a temp dir), this builds a PKI you can actually operate:

  * an OFFLINE root CA (the key never needs to touch a node);
  * per-node leaf certs with correct SANs (DNS + IP), 825-day validity,
    recorded serials, and role hints via the CN;
  * an admin client cert whose CN matches the daemon's authz admin_cns;
  * a revocation list file the daemon reads with --revoked-serials.

It shells out to `openssl` (universally present on Ubuntu) rather than
depending on a Python x509 library, so the kit stays stdlib-only.

    # once, on an offline/secured machine:
    python3 deploy/gen_pki.py init-ca  --out pki --cn "JJ DAI testnet-0 Root"

    # per node (repeat; --ip and --dns as the node will be reached):
    python3 deploy/gen_pki.py node  --out pki --name ua-kyiv-1 \\
        --dns ua1.testnet.jj-dai.org --ip 10.0.0.11

    # one admin client cert (CN must be in the authz policy admin_cns):
    python3 deploy/gen_pki.py admin --out pki --cn ops-ua

    # revoke a leaf by serial (serials live in pki/serials.tsv):
    python3 deploy/gen_pki.py revoke --out pki --serial 1a2b3c...

The root key (pki/ca.key) is the crown jewel: after issuing, move it to
cold storage. Nodes need only ca.crt + their own leaf.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

VALID_DAYS = 825                          # CA/Browser-forum leaf ceiling


def _run(args, **kw):
    r = subprocess.run(args, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"openssl failed: {' '.join(args)}")
    return r


def _ca_paths(out):
    return (os.path.join(out, "ca.key"), os.path.join(out, "ca.crt"),
            os.path.join(out, "serials.tsv"),
            os.path.join(out, "revoked.txt"))


def init_ca(out, cn):
    os.makedirs(out, exist_ok=True)
    ca_key, ca_crt, serials, revoked = _ca_paths(out)
    if os.path.exists(ca_key):
        raise SystemExit(f"CA already exists at {ca_key}; refusing to "
                         "overwrite the root of trust")
    _run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", ca_key])
    os.chmod(ca_key, 0o600)
    _run(["openssl", "req", "-x509", "-new", "-key", ca_key,
          "-days", "3650", "-out", ca_crt,
          "-subj", f"/CN={cn}",
          "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
          "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    open(serials, "a").close()
    open(revoked, "a").close()
    print(f"root CA created:\n  key  {ca_key}  (0600 — move to cold "
          f"storage after issuing)\n  cert {ca_crt}")


def _issue(out, name, cn, san_ext=None):
    ca_key, ca_crt, serials, _rev = _ca_paths(out)
    if not os.path.exists(ca_key):
        raise SystemExit("no CA yet — run init-ca first")
    key = os.path.join(out, f"{name}.key")
    csr = os.path.join(out, f"{name}.csr")
    crt = os.path.join(out, f"{name}.crt")
    _run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", key])
    os.chmod(key, 0o600)
    _run(["openssl", "req", "-new", "-key", key, "-out", csr,
          "-subj", f"/CN={cn}"])
    ext_args = []
    if san_ext:
        ext_file = os.path.join(out, f"{name}.ext")
        with open(ext_file, "w") as f:
            f.write(san_ext)
        ext_args = ["-extfile", ext_file]
    _run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_crt,
          "-CAkey", ca_key, "-CAcreateserial", "-days", str(VALID_DAYS),
          "-out", crt] + ext_args)
    serial = _run(["openssl", "x509", "-in", crt, "-noout",
                   "-serial"]).stdout.strip().split("=")[1]
    with open(serials, "a") as f:
        f.write(f"{serial}\t{name}\t{cn}\n")
    for tmp in (csr,):
        if os.path.exists(tmp):
            os.remove(tmp)
    print(f"issued {name}: {crt}\n  serial {serial}")
    return crt


def node(out, name, dns, ip):
    sans = []
    if dns:
        sans += [f"DNS:{d}" for d in dns.split(",") if d]
    if ip:
        sans += [f"IP:{a}" for a in ip.split(",") if a]
    if not sans:
        raise SystemExit("a node cert needs at least one --dns or --ip")
    ext = ("subjectAltName=" + ",".join(sans) + "\n"
           "keyUsage=critical,digitalSignature,keyEncipherment\n"
           "extendedKeyUsage=serverAuth,clientAuth\n")
    _issue(out, name, cn=name, san_ext=ext)


def admin(out, cn):
    ext = ("keyUsage=critical,digitalSignature\n"
           "extendedKeyUsage=clientAuth\n")
    _issue(out, f"admin-{cn}", cn=cn, san_ext=ext)


def revoke(out, serial):
    _ca_key, _ca_crt, _serials, revoked = _ca_paths(out)
    serial = serial.strip().lower()
    existing = set()
    if os.path.exists(revoked):
        existing = {ln.strip().lower() for ln in open(revoked)
                    if ln.strip()}
    if serial in existing:
        print(f"{serial} already revoked")
        return
    with open(revoked, "a") as f:
        f.write(serial + "\n")
    print(f"revoked {serial}\n  feed the node: --revoked-serials @{revoked}")


def main():
    ap = argparse.ArgumentParser(description="JJ DAI production PKI")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("init-ca"); a.add_argument("--out", required=True)
    a.add_argument("--cn", default="JJ DAI testnet-0 Root CA")
    n = sub.add_parser("node"); n.add_argument("--out", required=True)
    n.add_argument("--name", required=True)
    n.add_argument("--dns", default=""); n.add_argument("--ip", default="")
    m = sub.add_parser("admin"); m.add_argument("--out", required=True)
    m.add_argument("--cn", required=True)
    r = sub.add_parser("revoke"); r.add_argument("--out", required=True)
    r.add_argument("--serial", required=True)
    args = ap.parse_args()
    if args.cmd == "init-ca":
        init_ca(args.out, args.cn)
    elif args.cmd == "node":
        node(args.out, args.name, args.dns, args.ip)
    elif args.cmd == "admin":
        admin(args.out, args.cn)
    elif args.cmd == "revoke":
        revoke(args.out, args.serial)


if __name__ == "__main__":
    main()
