#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
node/test_identity_continuity — v0.4.1 P0-1 / P0-2 acceptance
=============================================================
Reproduces the restart scenario that motivated the fix:

  1. daemon boots with a persistent keystore, appends witnessed records;
  2. daemon "restarts" (new Node) on the SAME keystore + SAME log:
     node_id is identical, the chain re-verifies, appends continue;
  3. a DIFFERENT identity pointed at the same log is REFUSED at boot
     (IdentityError) — no silent re-key over existing history;
  4. main() refuses an ephemeral identity over an existing log (exit 2);
  5. main() refuses --allow-test-hooks on a non-loopback host (exit 2).

Each check is a plain pytest-style function; the __main__ runner keeps the
legacy script workflow alive until the P0-5 test-layout migration lands.
"""
from __future__ import annotations

import os
import sys

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location

import tempfile


from core.identity import NodeIdentity, IdentityError            # noqa: E402
from daemon import Node, HashEngine, main as daemon_main         # noqa: E402

PASS = "JJDAI_TEST_PASSPHRASE"


def _mk_node(tmp, keystore_name, log_name="witness.jsonl"):
    ident = NodeIdentity.load_or_create(os.path.join(tmp, keystore_name), PASS)
    node = Node(name="t", profile="B", substrates=["sha256:base-A"],
                adapters={}, engine=HashEngine("fp-test"),
                log_path=os.path.join(tmp, log_name), identity=ident)
    return ident, node


def _infer(node, rid):
    code, resp = node.handle({
        "substrate_id": "sha256:base-A", "adapter_ids": [],
        "sampling": {"temperature": 0.0, "top_p": 1.0, "max_tokens": 8,
                     "seed": 1},
        "request_id": rid, "nonce": ("nonce-" + rid).ljust(16, "x"),
        "messages": [{"role": "user", "content": "hello"}]})
    assert code == 200, f"inference failed: {code} {resp}"
    return resp


def test_persistent_identity_survives_restart():
    with tempfile.TemporaryDirectory() as tmp:
        ident1, node1 = _mk_node(tmp, "node.keystore")
        _infer(node1, "r1")
        _infer(node1, "r2")
        assert node1.chain.verify_chain(), "chain must verify before restart"
        nid_before, head_before = node1.chain.node_id, node1.chain.head_hash()
        del node1

        # ---- restart on the same keystore + same log ----
        ident2, node2 = _mk_node(tmp, "node.keystore")
        assert ident2.node_id == ident1.node_id, "keystore must yield same identity"
        assert node2.chain.node_id == nid_before, "live signer must be persistent"
        assert len(node2.chain.records) == 2, "history must be loaded"
        assert node2.chain.verify_chain(), "old records must verify under reloaded key"
        assert node2.chain.head_hash() == head_before, "head must be continuous"
        _infer(node2, "r3")
        assert node2.chain.verify_chain(), \
            "chain must stay coherent after post-restart append"
        assert len({r["node_id"] for r in node2.chain.records}) == 1, \
            "every record must carry the same node identity"


def test_foreign_identity_refused_over_existing_log():
    with tempfile.TemporaryDirectory() as tmp:
        _, node1 = _mk_node(tmp, "node.keystore")
        _infer(node1, "r1")
        del node1
        try:
            _mk_node(tmp, "OTHER.keystore")          # different key, same log
        except IdentityError:
            pass
        else:
            raise AssertionError(
                "a different signer over an existing witness log must be "
                "refused at boot (P0-2)")


def test_main_refuses_ephemeral_over_existing_log():
    with tempfile.TemporaryDirectory() as tmp:
        _, node1 = _mk_node(tmp, "node.keystore")
        _infer(node1, "r1")
        log = node1.chain.log_path
        del node1
        rc = daemon_main(["--log", log])             # no --node-keystore
        assert rc == 2, "ephemeral identity over persisted log must exit 2"


def test_main_refuses_keystore_without_passphrase():
    with tempfile.TemporaryDirectory() as tmp:
        os.environ.pop("JJDAI_KEYSTORE_PASSPHRASE", None)
        rc = daemon_main(["--node-keystore", os.path.join(tmp, "k.keystore")])
        assert rc == 2, "keystore without passphrase env must exit 2"


def test_main_refuses_test_hooks_off_loopback():
    rc = daemon_main(["--allow-test-hooks", "--host", "0.0.0.0"])
    assert rc == 2, "test hooks on non-loopback bind must exit 2"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\nidentity continuity — {len(tests)}/{len(tests)} checks green")
