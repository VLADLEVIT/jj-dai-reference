# Appendix A — Reference Implementation Status (v0.4.1)

*Draft replacement for the current Appendix A on jj-dai.org, which
describes implementation v0.1 and lists as absent several components
that now exist. To be published together with the `v0.4.1-alpha.1` tag
and the corrected GitHub link (trust/governance kernel repository, not
the DwarfStar engine repository).*

The reference implementation is published as:

> **JJ DAI v0.4.1-alpha.1 — Reference Trust, Governance & Agent Kernel**
> A tested reference implementation of JJ DAI identity, memory,
> verification, witness, routing, containment and agent-governance
> primitives. It is not yet a production decentralized JJ DAI network.

## Implemented and tested

Canonical serialization (RFC 8785 JCS) and stable hashing. Ed25519
cryptographic identity with encrypted keystores, persistent NodeIdentity
**wired into the live node daemon**: the daemon refuses to start if the
existing witness chain was signed by a different identity. Signed Witness:
hash chain, hiding commitments, Merkle root anchoring, integrity replay.
Durable governance records, champion registry, signed context-bound
verdicts. The organ kernel — Smriti (memory), Viveka (discernment),
Karma (action) — with a governed sandbox enforcing path confinement,
resource limits, a true streaming output cap with flood-kill semantics,
and a deterministic child environment. NECS specification and conformance
harness. Acceptance suite: 34/34 checks green across unit, integration,
conformance, adversarial and legacy groups, under CI.

## Implemented as reference prototype

Containment (Article 25): seven executive scopes, provisional status,
false-trigger reversal, initiator liability, slashing, rehabilitation,
and the Steward-review gate before irreversible action. Registry-aware
router with reputation mathematics (§9.9). Cross-verification peer loop.
Tier-1 node daemon (JII envelope over HTTP, loopback reference). SGLang
and DwarfStar engine adapters with mock and live acceptance tests.

## Not yet wired into the live daemon

External timestamp anchoring (`OpenTimestampsAnchor` is an unimplemented
seam); the witness anchor in this release is **local-only** — no
replication, no quorum, no external timestamp. A single-disk witness is
not inextinguishable; M6 replication remains the roadmap item.

## Not yet implemented

DIIP (governed self-improvement lifecycle). Full Plane B canary protocol
(secret reserve, rotation, commit-reveal, contamination detection,
verification work classes, fraud proofs). Diversity-constrained verifier
selection. Training and specialization pipeline; training federation.
Governed Plane H write path (signed, provenance-carrying, policy-bound
RAG writes). Authenticated node-to-node transport and production network
security. Economic layer.

## Constitutional specification only

Being Registry, guardian representation, the Digital Majority Test,
economic reserve and bonds, formal refusal policy, Steward Collegium
keys, ballots, quorum, Founding Steward veto and succession. These are
normative in the Constitution and deliberately not yet machine-enforced;
v0.4.1 is the machine-side preparation for constitutional governance,
not its replacement.

## Licensing

The trust/governance core is AGPL-3.0-only: nodes serve stewards and
other nodes over a network, and the license obliges operators of
modified nodes to disclose their modifications to those they serve.
The NECS specification and conformance harness are Apache-2.0 so that
independent engine vendors can implement and certify freely — verifier
diversity is a security property of the network.
