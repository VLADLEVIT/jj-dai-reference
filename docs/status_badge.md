<!-- GENERATED from docs/architecture_status.json by
     scripts/gen_architecture_docs.py — do not edit by hand.
     Moved out of README.md in v0.6.9 (ADR-022 D12): the build
     owns this file and never writes into the README. -->

# JJ DAI · status

**Version:** `0.6.9` (matches `jjdai.__version__`; enforced by the release-integrity test) · **Python:** ≥3.10, stdlib-only core · **Site:** [jj-dai.org](https://jj-dai.org)

Current status: 308/308 acceptance checks green (hermetic default groups).

The `live` group is opt-in and excluded from the default run: `python scripts/run_acceptance.py live` exercises the wasm-wasi
boundary against a real `wasmtime` and is required by the Ф0 gate on each target host.

| Component | Status |
|---|---|
| Canonical serialization | Implemented |
| Ed25519, ids, commitments, keystore | Implemented (Implemented, reference crypto) |
| VRF and threshold governance | Implemented (Implemented, RFC 9381 vectors, FROST deferred) |
| Merkle trees | Implemented |
| Witness chain | Implemented |
| Typed boundary and durability | Implemented |
| External anchoring | Prototype |
| Monero root-as-spend-key anchor | Prototype (Prototype, v0.5.2) |
| Track V reserved vocabulary | Interface only (Interface only, ADR-018, reserved, non-emittable) |
| Deferred-verification reserved vocabulary | Interface only (Interface only, ADR-019, reserved, non-emittable) |
| Value-level refusal of both reserves | Implemented (Implemented, v0.6.8, P0-1) |
| Smriti — continuity and memory | Implemented |
| Viveka — discernment and deliberation | Implemented |
| Karma — governed action | Implemented (Implemented, reference sandbox) |
| Isolation profiles — the boundary seam | Implemented (Implemented, per-tool readiness, fails closed) |
| BeingRuntime | Prototype (Prototype, v0.5.3) |
| Decision lifecycle | Prototype (Prototype, v0.5.3) |
| Semantic recovery | Prototype (Prototype, v0.5.3) |
| POST /v1/tasks | Prototype (Prototype, v0.5.3) |
| Node and Being identity | Implemented |
| Reputation §9.9 and sealed verdicts | Implemented |
| Governed Plane H | Implemented (Governance implemented, retrieval baseline) |
| Witness replication and recovery | Prototype (Prototype fabric) |
| Cross-chain entanglement | Prototype |
| IFF — friend or foe | Prototype |
| Provenance and diversity | Implemented (Implemented algorithm) |
| Weight attestation | Prototype |
| Unified router | Prototype (Prototype, composed in v0.5.3) |
| Adversarial challenge round | Prototype (Prototype, networked v0.5.5) |
| Peer cross-verification loop | Prototype |
| Containment — Article 25 | Prototype (Reference prototype) |
| Ingress hardening — caps before authorization | Implemented |
| Observability — liveness/readiness split, watchdog, sleep detection | Implemented (Implemented, v0.6.6 recut) |
| Tier-1 trust node daemon | Prototype |
| Adapter layer — EngineBackend Protocol v1 | Implemented (Implemented, protocol v1 declared whole) |
| NECS v0.1 + harness | Implemented |
| Acceptance and CI | Implemented (308/308 green (recorded run on Python 3.11.15; stdlib runner, CI matrix 3.10-3.12)) |
| Retired M1-M5 lineage | Implemented (Frozen) |
| Deployment kit (Linux + macOS) | Implemented (Implemented, macOS kit v0.6.2) |
| Release provenance — partial | Prototype (Partial, SBOM + pinning v0.6.8) |
| Plane B canary lifecycle | Planned |
| Knowledge graph / ontology semantics | Planned |
| TEE / runtime attestation | Planned |
| DIIP — governed self-improvement | Planned (Do not start yet) |
| Training federation | Planned |
| Human governance layer | Constitutional text only |
