# JJ DAI — Reference Trust, Governance & Agent Kernel

**Version:** `0.5.2` (dev branch — NOT a security-alpha tag) · **Python:** ≥3.10, stdlib-only core · **Site:** [jj-dai.org](https://jj-dai.org)

> A tested reference implementation of JJ DAI identity, memory, verification,
> witness, routing, containment and agent-governance primitives, with an
> EXPERIMENTAL distributed trust fabric: replication with CT-style
> consistency proofs and witness RECOVERY, WEIGHT ATTESTATION with signed
> DeploymentManifests, diversity-constrained verifier panels in the live
> router, external anchoring (local / peer-quorum / OTS custody / Monero hash-as-spend-key), and
> TLS/mTLS on every network path.
> **It is not yet a production decentralized JJ DAI network, and this dev
> build carries no public security guarantees.**

## 1. What is JJ DAI

JJ DAI is an architecture for verifiable AI agents built on one principle:
**everything touching a decision is verified.** Mutable knowledge lives
outside frozen model weights (RAG, Plane H); every inference, memory write,
routing decision and containment act is bound to cryptographic evidence and
recorded in an Ed25519-signed, hash-chained witness log; inference and
verification are performed by separate roles (generator/verifier asymmetry);
and an agent's executive capabilities can be selectively severed — with due
process, reversibility and rehabilitation — without silencing its voice or
destroying its memory.

The five-layer composition: LLM/agent → knowledge graph/ontology →
deterministic tools → verification → non-acting Witness plane (Sākṣī).
The organ kernel: **Smriti** (memory) observes and indexes, **Viveka**
(discernment) distinguishes states and drift, **Karma** (action) executes
inside a governed sandbox — each act witnessed before and after.

## 2. What is in this release

<!-- STATUS:BEGIN (generated from docs/architecture_status.json — do not edit by hand) -->
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
| Smriti — continuity and memory | Implemented |
| Viveka — discernment and deliberation | Implemented |
| Karma — governed action | Implemented (Implemented, reference sandbox) |
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
| Tier-1 trust node daemon | Prototype |
| Engine adapters | Prototype (Prototype adapters) |
| NECS v0.1 + harness | Implemented |
| Acceptance and CI | Implemented (86/86 green) |
| Retired M1-M5 lineage | Implemented (Frozen) |
| Plane B canary lifecycle | Planned |
| Knowledge graph / ontology semantics | Planned |
| TEE / runtime attestation | Planned |
| DIIP — governed self-improvement | Planned (Do not start yet) |
| Training federation | Planned |
| Human governance layer | Constitutional text only |
<!-- STATUS:END -->

## 3. What is NOT in this release

No DIIP (governed self-improvement), no full Plane B canary lifecycle, no
training federation, no TEE/runtime attestation (weight attestation proves
the operator's measurement, not what the engine loaded into memory), no
economic layer, no Being Registry, no rate limits. OTS anchoring holds
calendar proofs in custody; Bitcoin inclusion is verified with standard
`ots` tooling. Witness recovery restores only what the origin replicated,
and never the local-only commitment salts. The daemon is a **reference
node**, not a production peer. See
`docs/JJDAI_Code_Architecture_Map_v0.5.md` for the full classification.

## 4. Quick start

```bash
git clone https://github.com/VLADLEVIT/jjdai-reference && cd jjdai-reference

# run the acceptance suite (pytest, or the stdlib runner where pytest is absent)
python -m pytest tests/ -q
python scripts/run_acceptance.py

# boot a node with a PERSISTENT identity (first boot creates the keystore)
export JJDAI_KEYSTORE_PASSPHRASE='choose-a-real-passphrase'
python node/daemon.py --port 8471 \
    --node-keystore ./node-a.keystore \
    --log ./witness-a.jsonl

# talk to it
curl -s localhost:8471/capabilities | python -m json.tool
```

Without `--node-keystore` the daemon runs with an **ephemeral dev identity**
and will refuse to start over any existing witness log — a node must never
re-key over its own history.

## 5. Architecture

```
            ┌────────────────────────────────────────────────┐
            │              Purusha / Witness plane           │
            │   Sākṣī: non-acting, append-only, Ed25519      │
            │   (INV-9: the Witness never acts)              │
            └──────────────▲───────────────▲─────────────────┘
                   signed  │               │  signed
   ┌───────────────────────┴──┐   ┌────────┴─────────────────┐
   │   Verification            │   │  Governance              │
   │   verdicts · conformance  │   │  registry · reputation   │
   │   cross-verification      │   │  containment (Art. 25)   │
   └──────────▲────────────────┘   └────────▲─────────────────┘
              │                             │
   ┌──────────┴─────────────────────────────┴─────────────────┐
   │  Organ kernel:  Smriti (memory) → Viveka (discernment)   │
   │                 → Karma (sandboxed action)               │
   └──────────▲───────────────────────────────────────────────┘
              │ JII envelope (NECS C1)
   ┌──────────┴───────────────────────────────────────────────┐
   │  Node daemon · engine seam: HashEngine | SGLang | DwarfStar│
   │  frozen substrate + adapters · RAG (Plane H) outside weights│
   └───────────────────────────────────────────────────────────┘
```

## 6. Security model (read before deploying)

- **Replication restores, within limits.** Roots are RFC 6962 tree heads
  with quorum receipts and CT-style consistency proofs; SEGMENTS let peers
  restore a destroyed log against a quorum-anchored root. Recovery names
  its gaps honestly; hiding-commitment salts are local-only by design and
  die with the disk. External timestamping runs through
  `core/anchoring.py` (OTS custody, v0.5.1) and `core/anchoring_xmr.py`
  (Monero root-as-spend-key, v0.5.2).
- **TLS/mTLS everywhere it talks (v0.5.1).** `--tls-cert/--tls-key` serve
  HTTPS (TLS >= 1.2); `--tls-ca --tls-require-client-cert` enforce mTLS
  fail-closed; peer and salt paths verify servers against `--peer-ca` and
  present `--client-cert`. `scripts/gen_dev_certs.py` issues a DEV CA —
  production PKI is the operator's duty. No rate limits yet.
  `--allow-test-hooks` (admin endpoints) refuses non-loopback binds.
- **Weights are attested at boot (v0.5.1).** `--substrate-artifacts`
  measures the real files; a content-addressed id with mismatching bytes
  refuses the boot; `--require-attestation` refuses unattested substrates;
  the signed DeploymentManifest is witnessed and served at
  `GET /attestation`. Without TEE this proves the operator's measurement,
  not engine memory — stated, not hidden.
- **External anchoring (v0.5.1 / v0.5.2).** `--anchor-backends
  local,peer-quorum,ots,xmr` (+ `--ots-calendar`, `--xmr-wallet-rpc`,
  `--xmr-network`) anchor the RFC 6962 chain root beyond the trust
  domain; receipts are durable and served at `GET /witness/anchors`.
  The xmr backend writes NOTHING on-chain: the root becomes a spend key
  and one piconero to the derived address is the timestamp — independent
  of Monero's tx_extra policy by construction. Different anchors fail
  differently; a dead backend never silences the round.
- **Identity fails closed.** A signer mismatch against an existing witness
  log aborts boot; keystore passphrases are taken from the environment,
  never the CLI.
- **Karma sandbox** confines paths (realpath), applies rlimits, streams
  output with a flood budget (process-group kill on `OUTPUT_LIMIT_EXCEEDED`),
  and scrubs/hardens the child environment. It is a *reference* sandbox, not
  a hardened isolation boundary — production profiles (wasm-wasi, microvm,
  OCI) are roadmap.

## 7. Tests

```bash
python -m pytest tests/unit tests/adversarial -q     # fast
python -m pytest tests/ -q                           # everything (spawns loopback daemons)
python scripts/run_acceptance.py [unit|integration|conformance|adversarial|legacy]
```

CI runs the matrix on Python 3.10–3.12 (`.github/workflows/ci.yml`).
Current status: 68/68 acceptance checks green.

## 8. Roadmap

**P1 (remaining):** full Plane B canary protocol · GPU acceptance runs ·
rate limiting / DoS controls.
**P2:** DIIP · training federation · champion/challenger deployment ·
constitutional human governance (Steward Collegium, Being Registry) ·
economic layer · TEE attestation · multi-jurisdiction Witness network.

## 9. License

Two-license structure (see `LICENSE`): the trust/governance **core is
AGPL-3.0-only** — nodes serve other nodes over a network, and §13 obliges
operators of modified nodes to disclose their modifications to those they
serve; the **NECS specification and harness are Apache-2.0** so that
independent engine vendors can implement and certify without copyleft
obligations. Contributions require a CLA (see `CONTRIBUTING.md`).

## 10. Responsible disclosure

Security reports: see `SECURITY.md`. Do not open public issues for
vulnerabilities in identity, witness, sandbox or containment paths.

---
*Jai Guru Dev.*
