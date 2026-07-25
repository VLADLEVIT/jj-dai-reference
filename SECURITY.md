# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately to **security@jj-dai.org**. Do not open
public issues for flaws in identity, witness, sandbox, containment or
governance paths. We aim to acknowledge within 72 hours.

### Report template (Ф0 triage)

Please include, as far as you can:

```
Component:   (e.g. jjdai/witness.py, node/daemon.py, deploy kit)
Version:     (git commit or release tag, e.g. v0.6.3)
Class:       forgeability / identity bypass / sandbox escape /
             containment bypass / canonicalization / other
Impact:      what an attacker gains; preconditions (network position,
             valid cert, operator access, root on host)
Repro:       minimal steps or PoC; config used
Suggested severity:  P0 (network/identity integrity broken now) ·
             P1 (exploitable with realistic preconditions) ·
             P2 (hardening gap) · P3 (informational)
Disclosure:  your preferred timeline and credit line
```

Triage: we confirm severity within 72 h of acknowledgment; P0 issues
may trigger the Emergency Security Procedure (reversible containment
outside DIIP, witnessed, ratified afterwards — roadmap r5, Ф2).

## Scope notes for this release (v0.6.3)

This is a REFERENCE implementation (v0.6.3). Known, documented
non-goals of this build — not reportable as vulnerabilities:
weight attestation proves the operator MEASURED and signed the artifact
it claims to serve — without TEE/secure-boot it cannot prove the engine
process loaded those bytes into memory (runtime attestation is the
roadmap seam); OpenTimestamps anchoring takes CUSTODY of calendar proofs
and records them durably — Bitcoin inclusion is verified with standard
`ots` tooling against the stored proof, never locally; Monero anchoring
(hash-as-spend-key) verifies the root->address BINDING offline but full
proof is a chain operation against a Monero node, and anyone who learns
a revealed root can sweep the anchoring piconero (dust by design);
the xmr wallet behind --xmr-wallet-rpc must hold anchoring dust only;
the Being runtime processes tasks strictly serially and its production
profile refuses self-verification and unprovenanced panels, but Karma
remains a REFERENCE sandbox — do not expose POST /v1/tasks beyond a
trusted mTLS perimeter until the security-alpha hardening lands; rate
limiting bounds request VOLUME per identity but is not authorization —
who may call what is now role-based (peer/admin/anonymous from the mTLS CN) with default-deny; capability- and steward-ballot authorization remain future work; certificate revocation is serial-list based, checked before authz; the challenge
round runs networked over mTLS (open→seat→commit→reveal→resolve) but
its VRF keys are ordinary node keys (dedicated VRF key hygiene remains
future work); witness recovery
restores only what the origin REPLICATED (coverage gaps are named, never
papered over) and never the hiding-commitment salts, which are
local-only by design; entanglement attribution is cryptographic ONLY
under the stated assumption that the issuer chain is honest/anchored
(use m-of-n distinct issuers) and degrades to evidential without the
cross-link; the dev CA script issues DEVELOPMENT certificates (loopback
and lab use); the Karma sandbox is not a hardened isolation boundary;
rate limiting exists (token-bucket per endpoint class) but is keyed by
client IP, not certificate identity, and there are no request-body
size caps or concurrency limits yet (scheduled with ingress
hardening); the macOS deployment kit runs under
the documented macOS Keychain degraded profile (non-SE-resident) — Keychain-stored
passphrase readable by root, no launchd equivalent of
seccomp/MemoryDenyWriteExecute/ProtectSystem (RUNBOOK-macOS.md §6) —
this is stated by design and not reportable as a vulnerability.

Reports that ARE in scope: witness chain forgeability, identity
continuity bypasses, sandbox escapes (path confinement, rlimit or
flood-budget bypass), containment-gate bypasses, canonicalization or
commitment weaknesses.
