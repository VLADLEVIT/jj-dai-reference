#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Persistent Identity acceptance tests (v0.3.0 #1).

  I-1   NodeIdentity persists: load_or_create writes a keystore; reload gives
        the SAME node_id (identity survives restart — no more ephemeral keys)
  I-2   BeingIdentity persists: same being_id across restart
  I-3   NodeID != BeingID: distinct keys, distinct id namespaces
  I-4   Being manifest is signed by the being key; verify passes; a tampered
        manifest (edited genesis_ts) fails; a re-attributed being_id fails
  I-5   GENESIS is witnessed (IDENTITY record); chain verifies; binds being
        to host node
  I-6   MIGRATION signed by the being key succeeds AND is witnessed; a
        migration NOT signed by the being key is REFUSED (pull-by-choice,
        no seizure)
  I-7   startup chain verification: good chain + manifests -> report; a broken
        chain fails closed at boot
  I-8   keystore is encrypted at rest: the raw seed is NOT in the file; wrong
        passphrase fails to load
  I-9   commitment policy: default ONE-WAY (non-openable, reveal via journal);
        SaltVault is opt-in and round-trips salts under encryption
  I-10  identity binds into the descriptor: NodeDescriptor carries node_id +
        pubkey; being manifest carries being pubkey

Run (from the build root):  python3 test_identity.py
"""
from __future__ import annotations

import os
import sys
import tempfile


from jjdai.crypto import SigningKey                          # noqa: E402
from jjdai.witness import WitnessChain                       # noqa: E402
from core.identity import (NodeIdentity, BeingIdentity,      # noqa: E402
                           IdentityBinder, verify_manifest,
                           verify_startup, MigrationConsentError,
                           IdentityError, CommitmentPolicy, SaltVault)

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_identity():

    WORK = tempfile.mkdtemp(prefix="jjdai_id_")
    PW = "jai-guru-dev-passphrase"
    results = []


    def check(tid, ok, note=""):
        results.append((tid, bool(ok)))
        print(f"  [{'PASS' if ok else 'FAIL'}] {tid:5s} {note}")


    class Clock:
        def __init__(self, t=1_750_000_000.0): self.t = t
        def __call__(self): return self.t


    clk = Clock()

    # ---- I-1 node key persists ------------------------------------------------- #
    nks = os.path.join(WORK, "node.jjk")
    n1 = NodeIdentity.load_or_create(nks, PW)
    n2 = NodeIdentity.load_or_create(nks, PW)          # reload from keystore
    check("I-1", n1.node_id == n2.node_id and os.path.exists(nks),
          f"node_id persists across restart: {n1.node_id[:20]}…")

    # ---- I-2 being key persists ------------------------------------------------ #
    bks = os.path.join(WORK, "being.jjk")
    b1 = BeingIdentity.load_or_create(bks, PW)
    b2 = BeingIdentity.load_or_create(bks, PW)
    check("I-2", b1.being_id == b2.being_id,
          f"being_id persists across restart: {b1.being_id[:20]}…")

    # ---- I-3 NodeID != BeingID ------------------------------------------------- #
    check("I-3", n1.node_id != b1.being_id and n1.node_id.startswith("node:")
          and b1.being_id.startswith("being:"),
          "NodeID and BeingID are distinct identities")

    # ---- I-4 signed manifest --------------------------------------------------- #
    manifest = b1.manifest(genesis_node_id=n1.node_id, genesis_ts=clk())
    ok_verify = verify_manifest(manifest)
    tampered = dict(manifest, genesis_ts=0.0)
    reattributed = dict(manifest, being_id="being:impostor")
    check("I-4", ok_verify and not verify_manifest(tampered)
          and not verify_manifest(reattributed),
          "manifest signed & bound to key; tamper + re-attribution rejected")

    # ---- I-5 witnessed genesis ------------------------------------------------- #
    chain = WitnessChain(n1.sk, log_path=os.path.join(WORK, "wit.jsonl"))
    binder = IdentityBinder(n1, witness=chain, now_fn=clk)
    gen = binder.genesis(b1)
    id_recs = [r for r in chain.records if r["kind"] == "IDENTITY"]
    check("I-5", gen["event"] == "genesis" and len(id_recs) == 1
          and chain.verify_chain()
          and gen["host_node_id"] == n1.node_id,
          "genesis witnessed; binds being to host; chain verifies")

    # ---- I-6 migration with consent enforcement -------------------------------- #
    n_dst = NodeIdentity(SigningKey(b"\x55" * 32))
    mig = binder.migrate(b1, from_node_id=n1.node_id, to_node_id=n_dst.node_id)
    migrated_ok = mig["event"] == "migration" and mig["to_node_id"] == n_dst.node_id
    # a migration proposed with a WRONG signature (not the being key) is refused
    refused = False
    try:
        forged_sig = n1.sk.sign(b"anything").hex()      # signed by NODE, not being
        binder.migrate(b1, from_node_id=n1.node_id, to_node_id=n_dst.node_id,
                       being_signature_hex=forged_sig)
    except MigrationConsentError:
        refused = True
    check("I-6", migrated_ok and refused,
          "being-signed migration accepted; unsigned/forged migration refused")

    # ---- I-7 startup verification ---------------------------------------------- #
    report = verify_startup(chain, node=n1, manifests=[manifest])
    broke = False
    bad_chain = WitnessChain(n1.sk)
    bad_chain.append("INFER", request={"x": 1})
    bad_chain.records[0]["this_hash"] = "00" * 32       # corrupt a record
    try:
        verify_startup(bad_chain, node=n1)
    except IdentityError:
        broke = True
    check("I-7", report["chain_verified"] and report["genesis_records"] == 1
          and broke,
          "good chain+manifests verified at boot; broken chain fails closed")

    # ---- I-8 keystore encrypted at rest ---------------------------------------- #
    with open(nks, "rb") as f:
        blob = f.read()
    seed_absent = n1.sk.seed not in blob
    wrong_pw = False
    try:
        NodeIdentity.load_or_create(nks, "wrong-passphrase")
    except Exception:
        wrong_pw = True
    check("I-8", seed_absent and blob[:4] == b"JJK1" and wrong_pw,
          "raw seed not on disk; wrong passphrase rejected")

    # ---- I-9 commitment policy + salt vault ------------------------------------ #
    pol = CommitmentPolicy()                            # default
    vaulted = CommitmentPolicy(CommitmentPolicy.VAULTED)
    vp = os.path.join(WORK, "salts.jjsv")
    vault = SaltVault(vp, PW)
    vault.put(3, "request", "aa" * 32)
    vault2 = SaltVault(vp, PW)                           # reload
    roundtrip = vault2.get(3, "request") == "aa" * 32
    check("I-9", (not pol.openable) and vaulted.openable and roundtrip
          and "one-way" in pol.describe(),
          "default one-way (non-openable); opt-in SaltVault round-trips encrypted")

    # ---- I-10 descriptor binding ----------------------------------------------- #
    desc = n1.descriptor()
    check("I-10", desc["kind"] == "NodeDescriptor" and desc["node_id"] == n1.node_id
          and desc["pubkey"] == n1.pubkey_hex
          and manifest["pubkey"] == b1.pubkey_hex,
          "NodeDescriptor + BeingManifest carry bound pubkeys")

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nPERSISTENT IDENTITY: {len(results) - failed}/{len(results)} green"
          + ("  ✓ certified" if not failed else "  ✗ FAILURES"))
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_identity()
