# JJ DAI — Code Architecture Map v0.6.3

> GENERATED from `docs/architecture_status.json` by `scripts/gen_architecture_docs.py` — edit the JSON, not this file. `scripts/check_docs_drift.py` fails CI on divergence.

Acceptance: 94/94 green (stdlib runner; CI matrix Python 3.10-3.12).

## #00 · The neurosymbolic stack

Mutable knowledge lives outside frozen weights; everything that touches a decision is verified; the Witness is non-executive, not causally inert (INV-9 v1.1): it never commands, selects or executes a decision; what it witnesses may return through Smṛti and Viveka into Chitta before finalization — the resulting decision belongs to Chitta, not to Purusha.

| Layer | Status |
|---|---|
| 5. LLM / agent — frozen substrate + adapters | **Prototype** |
| 4. Knowledge — governed Plane H store (graph semantics planned) | **Prototype** |
| 3. Deterministic tools — Karma reference sandbox | **Implemented** |
| 2. Verification — diversity panels, verdicts, cross-verify | **Implemented** |
| 1. Sākṣī — Witness: local implemented, distributed fabric prototype | **Implemented** |

## #01 · Cryptographic primitives — jjdai/

| Module | What it is | Status |
|---|---|---|
| `jjdai/canonical.py` | Canonical serialization: RFC 8785 JCS: one deterministic byte-stream per object across identity, signatures, manifests and witness records. | **Implemented** (Implemented) |
| `jjdai/crypto.py` | Ed25519, ids, commitments, keystore: Strict small-order rejection, cofactored verification, canonical node/Being ids, hiding commitments, atomic 0600 encrypted keystore. | **Implemented** (Implemented, reference crypto) |
| `jjdai/crypto.py::vrf_prove · jjdai/crypto.py::multisig_verify` | VRF and threshold governance: ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) pinned to all three official B.3 vectors, with validate_key fail-closed checks; naive m-of-n multisig verification (aggregate FROST signing deferred). | **Implemented** (Implemented, RFC 9381 vectors, FROST deferred) |
| `jjdai/merkle.py` | Merkle trees: Legacy padding tree plus RFC 6962 inclusion and consistency proofs, property-tested across tree shapes and forgery cases. | **Implemented** (Implemented) |
| `jjdai/witness.py` | Witness chain: Hash-chained, Ed25519-signed, persist-before-expose append under a chain-internal lock, offline replay and legacy-log verification. Fail-closed witnessing is not executive agency (INV-9 v1.1): the Witness may gate exposure when witnessing fails, but cannot select, modify, approve or reject the substance of a decision. | **Implemented** (Implemented) |
| `jjdai/schema.py · jjdai/durable.py` | Typed boundary and durability: Fail-closed typed envelopes; fsynced journals, torn-tail repair and reload-time re-verification. | **Implemented** (Implemented) |
| `core/anchoring.py` | External anchoring: Durable receipt log with local, peer-quorum and OTS-calendar backends. OTS is proof custody; standard tooling verifies the stored calendar proof. | **Prototype** (Prototype) |
| `core/anchoring_xmr.py` | Monero root-as-spend-key anchor: The witness root deterministically becomes a Monero address; a dust payment timestamps the binding without storing the root in tx_extra. | **Prototype** (Prototype, v0.5.2) |

## #02 · The organ kernel — kernel/

| Module | What it is | Status |
|---|---|---|
| `kernel/smriti.py` | Smriti — continuity and memory: Core/archival memory, verified recall, signed export/import, read-only thinking view and journal reconstruction. | **Implemented** (Implemented) |
| `kernel/viveka.py` | Viveka — discernment and deliberation: Deterministic graphs, conditional routing, checkpoints, visible rollback, bounded loops and containment-aware executive steps. | **Implemented** (Implemented) |
| `kernel/karma.py` | Karma — governed action: Witnessed intent/outcome, path confinement, rlimits, streaming flood-kill, deterministic child environment. Reference sandbox, not hardened isolation. | **Implemented** (Implemented, reference sandbox) |

## #03 · The organism — runtime/

| Module | What it is | Status |
|---|---|---|
| `runtime/being.py` | BeingRuntime: One long-lived composition owning one identity, ONE witness chain, Smriti, Plane H, Viveka, Router, Karma and Containment. Closes the v0.5.2 audit composition gap. | **Prototype** (Prototype, v0.5.3) |
| `runtime/state_machine.py · runtime/decision_trace.py` | Decision lifecycle: RECEIVED → GROUNDED → PLANNED → GENERATED → VERIFIED → AUTHORIZED → ACTED → RECORDED with REFUSED / FAILED / FATE_UNKNOWN / CONTAINED branches; every transition witnessed then journaled. | **Prototype** (Prototype, v0.5.3) |
| `runtime/recovery.py` | Semantic recovery: After restart every trace is rebuilt from the durable journal; an orphaned Karma intent closes as FATE_UNKNOWN — the system that does not know says so. | **Prototype** (Prototype, v0.5.3) |
| `node/daemon.py::/v1/tasks` | POST /v1/tasks: Returns a full DecisionTrace, not a raw completion: states, citations, plan hash, generator and panel provenance, containment decision, action receipt, witness span. | **Prototype** (Prototype, v0.5.3) |

## #04 · Trust core — core/

| Module | What it is | Status |
|---|---|---|
| `core/identity.py` | Node and Being identity: Persistent keystores, genesis binding, boot verification and migration consent. The daemon fails closed on signer/witness mismatch. | **Implemented** (Implemented) |
| `core/registry.py · core/verdict.py` | Reputation §9.9 and sealed verdicts: Decay, Bayesian shrinkage, slashing and signed context-bound verdict envelopes with replay refusal. | **Implemented** (Implemented) |
| `core/plane_h.py` | Governed Plane H: Signed proposals, namespace ACL, transactional witness-bound append, supersede/redact, root-preserving redaction. Retrieval remains a token-overlap baseline; not yet a semantic knowledge graph. | **Implemented** (Governance implemented, retrieval baseline) |
| `core/replication.py · core/segments.py` | Witness replication and recovery: Signed RFC 6962 roots, quorum receipts, consistency proofs, segment coverage, divergence evidence and restore-and-resume against an anchored root. | **Prototype** (Prototype fabric) |
| `core/entanglement.py` | Cross-chain entanglement: Recipient-root cross-links, PEER_ROOT checkpoints and issuance inclusion proofs. Attribution is cryptographic only under the documented honest/anchored issuer assumption. | **Prototype** (Prototype) |
| `core/peers.py` | IFF — friend or foe: Durable peer registry, steward admission, key pinning and replay-protected signed requests, layered under TLS/mTLS transport. | **Prototype** (Prototype) |
| `core/manifests.py · core/diversity.py` | Provenance and diversity: Signed immutable manifests and correlation-constrained panel selection. Unknown provenance counts as correlated; short panels fail honest. | **Implemented** (Implemented algorithm) |
| `core/attestation.py` | Weight attestation: Streamed artifact measurement, signed DeploymentManifest, durable store and daemon boot gate. Proves operator measurement, not engine memory. | **Prototype** (Prototype) |
| `core/router.py` | Unified router: Registry-aware champion routing, signed ROUTE records and diversity-constrained verifier panels — now driven by the BeingRuntime lifecycle as well as usable as a library. | **Prototype** (Prototype, composed in v0.5.3) |
| `core/challenge.py` | Adversarial challenge round: VRF sortition (transcript-bound, unbiasable seats), blind commit-reveal verdicts, deadline/abstention semantics and offline-verifiable fraud proofs that slash via the registry — now driven over mTLS via /challenge/* as well as in-process. | **Prototype** (Prototype, networked v0.5.5) |
| `core/crossverify.py` | Peer cross-verification loop: Remote teacher-forcing score, offline peer-Witness re-audit and registry feedback. The challenge round now runs across the network (core/challenge.py + /challenge/* endpoints). | **Prototype** (Prototype) |
| `core/containment.py` | Containment — Article 25: Seven executive scopes, provisional containment, reversal, initiator liability, slashing, rehabilitation and Steward-review gate. Steward keys and ballots remain absent. | **Prototype** (Reference prototype) |

## #05 · Node layer — node/ · necs/

| Module | What it is | Status |
|---|---|---|
| `node/daemon.py` | Tier-1 trust node daemon: Inference/scoring, Witness export, replication, entanglement, attestation, anchoring, peers, containment, the Being task lifecycle, per-identity rate limiting, role-based authorization, cert revocation, /healthz and /metrics, and the networked challenge round — all over TLS/mTLS. | **Prototype** (Prototype) |
| `node/engine_sglang.py · node/engine_dwarfstar.py` | Engine adapters: Generation plus teacher-forcing score with mock and live acceptance seams. Real GPU acceptance and operational profiles remain pending (operator-run gate). | **Prototype** (Prototype adapters) |
| `necs/` | NECS v0.1 + harness: Conformance specification and harness under Apache-2.0, preserving vendor-neutral adoption. | **Implemented** (Implemented) |
| `tests/ · .github/workflows/ci.yml` | Acceptance and CI: Acceptance functions across unit, integration, conformance, adversarial and legacy groups; CI matrix targets Python 3.10-3.12; docs drift is CI-checked. | **Implemented** (generated count) |
| `m1m5/` | Retired M1-M5 lineage: Frozen legacy code retained for auditability and migration coverage. | **Implemented** (Frozen) |
| `deploy/ · deploy/macos/` | Deployment kit (Linux + macOS): Ubuntu: hardened systemd unit, TPM-sealed passphrase, bootstrap, production PKI generator, operator RUNBOOK. macOS (roadmap Ф0): launchd daemon template, Keychain sealing under the documented macOS Keychain degraded profile (non-SE-resident), bootstrap with 24/7 power discipline, RUNBOOK-macOS. Flag parity between the two kits is enforced by unit acceptance (M-FLAGS). | **Implemented** (Implemented, macOS kit v0.6.2) |

## #06 · Not yet in the codebase

Designed in the Whitepaper and Charter — and deliberately absent from the code today. Naming the absence is part of the architecture.

| Module | What it is | Status |
|---|---|---|
| — | Plane B canary lifecycle: Secret reserve, expiry and rotation, commit-reveal, contamination detection, work classes and fraud proofs. | **Planned** (Planned) |
| — | Knowledge graph / ontology semantics: Typed entities and relations, ontology versioning, graph provenance, deterministic query contracts and verified graph mutation above the governed Plane H store. | **Planned** (Planned) |
| — | TEE / runtime attestation: Evidence that the serving process loaded the measured model and adapter bytes into the executing memory boundary. | **Planned** (Planned) |
| — | DIIP — governed self-improvement: Proposals, bonds, shadow execution, quorum, time-lock, rollback and circuit breaker. It should govern a stable runtime, not become the mechanism that invents one. | **Planned** (Do not start yet) |
| — | Training federation: Specialization pipeline, DiLoCo/PRIME-class federation and a multi-jurisdiction training/Witness topology. | **Planned** (Planned) |
| — | Human governance layer: Being Registry, guardian representation, Digital Majority Test, economic reserve, Steward Collegium keys, ballots, veto, succession and refusal policy. | **Constitutional text only** (Constitutional text only) |

## The honest sentence

v0.4.1 closed the identity gap. v0.5-dev5 closed the cryptographic boundary. v0.5-dev6 made replication sound. v0.5.1 closed P1 mechanisms. v0.5.2 added the Monero anchor. v0.5.3 closed the COMPOSITION GAP: one BeingRuntime drives every organ through one witnessed lifecycle over one identity, and POST /v1/tasks returns the full DecisionTrace — including the honest endings REFUSED, FAILED, FATE_UNKNOWN and CONTAINED. v0.5.4 made verification ADVERSARIAL: RFC 9381 ECVRF (vector-pinned) drives transcript-bound panel sortition nobody can grind; verdicts are sealed before any are shown; silence and fraud become witnessed, offline-verifiable evidence; and the daemon holds its first operational boundary — per-identity rate limiting whose systematic abuse is itself witnessed. v0.5.5 is the SECURITY-ALPHA: role-based authorization (default-deny, longest-prefix), certificate revocation that beats identity, /healthz + /metrics, the challenge round carried over mTLS, a production PKI with an offline root, optional TPM-sealed keystores, a hardened systemd unit and an operator runbook — the kit to stand up testnet-0 on Ubuntu. v0.6.1 propagates INV-9 v1.1: the invariant is reworded from “non-acting” to “non-executive, not causally inert” — the executive prohibition is unchanged, the sanctioned reflexive path (J-Lens → Viveka → Chitta, pre-finalization) is named, and direct mutation of an output or verdict remains forbidden; the reflexive loop itself is a Ф3 runtime deliverable (roadmap r5), so the archive-only runtime stays compliant. v0.6.2 ports the deployment kit to macOS (roadmap Ф0): a launchd daemon template, Keychain sealing of the keystore passphrase under the explicitly documented macOS Keychain degraded profile (non-SE-resident); a true Secure Enclave-backed profile is reserved as a separate future attestation profile, a bootstrap that enforces the 24/7 power discipline of a laptop-chassis server, RUNBOOK-macOS, and an SECURITY.md triage template — with unit acceptance pinning flag parity between the systemd and launchd paths so the two kits cannot drift apart silently. v0.6.3 answers the external audit of v0.6.2: the systemd watchdog that would have killed a healthy node every 60 s is removed until sd_notify lands; /opt/jjdai is root-owned on both platforms so the daemon can no longer rewrite its own code; the macOS profile is renamed to “macOS Keychain degraded profile (non-SE-resident)” with a true Secure Enclave-backed profile reserved for the future and an M-LIVE operational-evidence checklist added; hand-written docs are pinned to the code by a release-integrity test (versions, outgrown claims, acceptance count, AGPL placeholder loudness). Known-and-scheduled: per-identity rate-limit keying, ingress body/concurrency limits, /readyz, and the canonical AGPL text remain open, tracked items.

Said plainly: authorization is transport-role based (peer/admin/anonymous from the mTLS CN), not yet capability- or steward-ballot based; certificate revocation is serial-list based; Karma is still a reference sandbox, not hardened isolation; the knowledge store is retrieval-baseline, not a knowledge graph; and DIIP remains deliberately absent. This is an alpha to operate among known operators, not to expose to untrusted load.
