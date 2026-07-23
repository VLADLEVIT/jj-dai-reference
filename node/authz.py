# -*- coding: utf-8 -*-
"""
node.authz — authorization policy for the trust node (v0.5.5)
=============================================================
Rate limiting (v0.5.4) bounds HOW MUCH an identity may call; this module
decides WHO MAY CALL WHAT. The two are different boundaries and both are
enforced before any heavy work.

PRINCIPALS — derived from the mTLS layer, never from request bodies:
  anonymous   no client certificate (only possible when the daemon does
              not require one)
  peer        a client certificate chaining to --peer-ca / --tls-ca
  admin       a peer certificate whose CN is in the policy's admin_cns

POLICY FILE (JSON):
  {
    "default": "deny",                  # the only honest default
    "admin_cns": ["ops-ua", "ops-kr"],
    "rules": [
      {"prefix": "/capabilities", "allow": ["anonymous","peer","admin"]},
      {"prefix": "/witness/",     "allow": ["peer","admin"]},
      {"prefix": "/v1/",          "allow": ["peer","admin"]},
      {"prefix": "/challenge/open", "allow": ["admin"]},
      {"prefix": "/admin/",       "allow": ["admin"]}
    ]
  }

Longest matching prefix wins (a specific rule beats a broad one); no
matching rule falls to "default". A malformed policy refuses the boot —
authorization is configuration that MUST fail closed. Denials are 403
with the matched rule named; systematic denial storms are already
bounded by the rate limiter in front of everything.
"""
from __future__ import annotations

import json

ROLES = ("anonymous", "peer", "admin")


class AuthzError(RuntimeError):
    pass


class AuthzPolicy:
    def __init__(self, spec: dict):
        default = spec.get("default")
        if default not in ("deny", "allow"):
            raise AuthzError("policy needs default: 'deny'|'allow' "
                             "(and 'deny' is the honest one)")
        self.default = default
        self.admin_cns = set(spec.get("admin_cns") or [])
        self.rules = []
        for i, r in enumerate(spec.get("rules") or []):
            prefix, allow = r.get("prefix"), r.get("allow")
            if not prefix or not isinstance(allow, list) or not allow:
                raise AuthzError(f"rule #{i}: needs prefix + allow[]")
            bad = [a for a in allow if a not in ROLES]
            if bad:
                raise AuthzError(f"rule #{i}: unknown roles {bad} "
                                 f"(known: {ROLES})")
            self.rules.append((prefix, frozenset(allow)))
        # longest prefix first => most specific rule wins
        self.rules.sort(key=lambda pr: len(pr[0]), reverse=True)

    @classmethod
    def load(cls, path: str) -> "AuthzPolicy":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    def role_of(self, client_cn: str | None) -> str:
        if client_cn is None:
            return "anonymous"
        return "admin" if client_cn in self.admin_cns else "peer"

    def check(self, path: str, role: str) -> tuple:
        """-> (allowed: bool, matched_rule: str)"""
        for prefix, allow in self.rules:
            if path.startswith(prefix):
                return role in allow, prefix
        return self.default == "allow", "<default>"
