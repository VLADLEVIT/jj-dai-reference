#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.5.5 unit acceptance — authorization policy + deploy kit integrity
====================================================================
  A-DEF  a policy with default:deny denies unmatched paths; roles are
         derived from CN vs admin_cns; anonymous is the no-cert case
  A-LP   LONGEST matching prefix wins: a specific rule overrides a broad
         one regardless of declaration order
  A-FC   malformed policies refuse construction (bad default, unknown
         role, empty allow, missing prefix) — authz fails closed
  A-KIT  the deployment kit is self-consistent: the shipped
         authz.testnet.json parses and its admin_cns are non-empty; the
         systemd unit references only flags the daemon actually accepts;
         gen_pki.py and the runbook are present
"""
from __future__ import annotations

import os
import re
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from authz import AuthzPolicy, AuthzError                          # noqa: E402


def test_default_deny_and_roles():
    pol = AuthzPolicy({"default": "deny", "admin_cns": ["ops-ua"],
                       "rules": [{"prefix": "/healthz",
                                  "allow": ["anonymous", "peer", "admin"]},
                                 {"prefix": "/v1/", "allow": ["peer",
                                                              "admin"]}]})
    assert pol.role_of(None) == "anonymous"
    assert pol.role_of("random-peer") == "peer"
    assert pol.role_of("ops-ua") == "admin"
    assert pol.check("/healthz", "anonymous") == (True, "/healthz")
    assert pol.check("/v1/tasks", "peer")[0] is True
    assert pol.check("/v1/tasks", "anonymous")[0] is False
    # unmatched path -> default deny
    assert pol.check("/secret", "admin") == (False, "<default>")
    print("  [PASS] A-DEF  default:deny; roles from CN; anonymous = no "
          "cert; unmatched path denied")


def test_longest_prefix_wins():
    # broad rule declared FIRST, specific rule declared SECOND
    pol = AuthzPolicy({"default": "deny", "admin_cns": [], "rules": [
        {"prefix": "/challenge/", "allow": ["peer", "admin"]},
        {"prefix": "/challenge/open", "allow": ["admin"]}]})
    # a peer may hit /challenge/seat (broad) ...
    assert pol.check("/challenge/seat", "peer")[0] is True
    # ... but NOT /challenge/open (specific rule wins despite order)
    ok, rule = pol.check("/challenge/open", "peer")
    assert ok is False and rule == "/challenge/open", (ok, rule)
    print("  [PASS] A-LP   longest matching prefix wins over declaration "
          "order")


def test_fail_closed():
    bad = [
        {"default": "maybe", "rules": []},                 # bad default
        {"default": "deny", "rules": [{"prefix": "/x",
                                       "allow": ["wizard"]}]},  # bad role
        {"default": "deny", "rules": [{"prefix": "/x",
                                       "allow": []}]},      # empty allow
        {"default": "deny", "rules": [{"allow": ["peer"]}]},  # no prefix
    ]
    for spec in bad:
        try:
            AuthzPolicy(spec)
            assert False, f"A-FC: malformed policy accepted: {spec}"
        except AuthzError:
            pass
    print("  [PASS] A-FC   malformed policies refuse construction")


def test_deploy_kit_integrity():
    dep = os.path.join(_ROOT, "deploy")
    import json
    authz = json.load(open(os.path.join(dep, "authz.testnet.json")))
    pol = AuthzPolicy(authz)                    # must parse under the real class
    assert pol.admin_cns, "A-KIT: shipped policy has no admin CNs"
    assert pol.default == "deny", "A-KIT: shipped policy must default deny"

    unit = open(os.path.join(dep, "jjdai-node@.service")).read()
    flags = set(re.findall(r"--[a-z][a-z0-9-]+", unit))
    daemon = open(os.path.join(_ROOT, "node", "daemon.py")).read()
    known = set(re.findall(r'add_argument\("(--[a-z0-9-]+)"', daemon))
    unknown = flags - known
    assert not unknown, f"A-KIT: unit uses flags the daemon rejects: {unknown}"

    for essential in ("gen_pki.py", "tpm_seal.py", "bootstrap_node.sh",
                      "RUNBOOK.md", "authz.testnet.json"):
        assert os.path.exists(os.path.join(dep, essential)), \
            f"A-KIT: deploy kit missing {essential}"
    print("  [PASS] A-KIT  shipped policy valid; unit uses only real "
          "daemon flags; PKI/TPM/bootstrap/runbook all present")


if __name__ == "__main__":
    test_default_deny_and_roles()
    test_longest_prefix_wins()
    test_fail_closed()
    test_deploy_kit_integrity()
    print("\nAUTHZ + DEPLOY KIT UNIT: all groups green  ✓ certified")
