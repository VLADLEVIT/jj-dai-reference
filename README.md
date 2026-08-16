# JJ DAI — Reference Trust, Governance & Agent Kernel

**Version:** `0.6.5` (matches `jjdai.__version__`; enforced by the release-integrity test) · **Python:** ≥3.10, stdlib-only core · **Site:** [jj-dai.org](https://jj-dai.org)

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
deterministic tools → verification → non-executive Witness plane (Sākṣī).
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
| Tier-1 trust node daemon | Prototype |
| Adapter layer — EngineBackend Protocol v1 | Implemented (Implemented, protocol v1 declared whole) |
| NECS v0.1 + harness | Implemented |
| Acceptance and CI | Implemented (129/129 green) |
| Retired M1-M5 lineage | Implemented (Frozen) |
| Deployment kit (Linux + macOS) | Implemented (Implemented, macOS kit v0.6.2) |
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
economic layer, no Being Registry. OTS anchoring holds
calendar proofs in custody; Bitcoin inclusion is verified with standard
`ots` tooling. Witness recovery restores only what the origin replicated,
and never the local-only commitment salts. The daemon is a **reference
node**, not a production peer.

Two things this release declares without yet carrying, both deliberate and
both stated in the CHANGELOG: the `wasm-wasi` isolation profile ships as
**mechanism only** — no compiled toolset modules travel in this build, so
in practice execution is still the `reference` fence — and of the seven
registered backend drivers only `hash`, `dwarfstar` and `sglang` implement
generation. `vllm`, `llama.cpp`, `mlx` and `asic` exist so the registry,
the conformance suite and the compatibility matrix have real objects to
interrogate, and they refuse by type (`NotSupported`) rather than by
absence. `microvm` is a reserved profile name with no implementation
behind it, and selecting it refuses. So do the reserved witness fields
`session_id` and `ir_schema_version`, and the reserved record kinds. See
`docs/JJDAI_Code_Architecture_Map_v0.5.md` for the full classification.

## 4. Quick start

```bash
git clone https://github.com/VLADLEVIT/jj-dai-reference && cd jj-dai-reference

# run the acceptance suite (pytest, or the stdlib runner where pytest is absent)
python -m pytest tests/ -q
python scripts/run_acceptance.py

# boot a node with a PERSISTENT identity (first boot creates the keystore)
export JJDAI_KEYSTORE_PASSPHRASE='choose-a-real-passphrase'
python node/daemon.py --port 8471 \
    --node-keystore ./node-a.keystore \
    --log ./witness-a.jsonl

# talk to it — capabilities carries the engine seam and the isolation
# profiles this node will actually honour; /healthz carries the same
# declaration until the liveness split moves it to /readyz (v0.6.6)
curl -s localhost:8471/capabilities | python -m json.tool
curl -s localhost:8471/healthz | python -m json.tool
```

Without `--node-keystore` the daemon runs with an **ephemeral dev identity**
and will refuse to start over any existing witness log — a node must never
re-key over its own history.

Ingress ceilings and the execution boundary are flags, and their defaults
are the safe ones: `--max-body-bytes` (1 MiB), `--max-concurrency` (64
connections), `--request-timeout-s` (15), `--isolation-profiles`
(`reference`). A profile named here whose runtime is absent makes the node
REFUSE the action rather than fall back to a weaker one, so declaring
`wasm-wasi` on a host without `wasmtime` is a loud failure, not a quiet
downgrade. `--engine` has no hardcoded list: it accepts whatever the
registry carries on this host, and `--help` prints both the registered
drivers and any that failed to import.

## 5. Architecture

```
            ┌────────────────────────────────────────────────┐
            │              Purusha / Witness plane           │
            │   Sākṣī: non-executive, append-only, Ed25519   │
            │   (INV-9: non-executive, not causally inert)   │
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
   │  Node daemon · engine seam: jjdai/adapters/               │
   │  EngineBackend Protocol v1 · registry · model profiles    │
   │  frozen substrate + weight adapters · RAG (Plane H)       │
   │  outside the weights                                      │
   └───────────────────────────────────────────────────────────┘
```

**The engine seam is one protocol, not one adapter per model (v0.6.5).**
Engines integrate through `jjdai/adapters/` — a single `EngineBackend`
protocol, a registry that admits nothing failing the contract, declarative
model profiles, and one conformance suite. Protocol v1 is declared WHOLE:
every driver carries the entire v1 method set, and what a driver has not
implemented raises the typed `NotSupported`. An absent method would grow a
`hasattr` probe and a quiet fallback in every caller, and a quiet fallback
is how a node comes to believe it has a capability it does not have.
Capability is *derived* from what a driver actually overrides, never
hand-declared, because a hand-written list is a claim and claims drift from
code.

**The registry is the only door, and the door has one shape.** Drivers take
a single `BackendConfig`; what a driver does not use it ignores, and what it
requires and does not find it refuses at construction by name — an operator
reads "dwarfstar requires url", not a `TypeError` three frames down. This is
what makes the seam real rather than relocated: factories with differing
signatures would leave the daemon knowing which driver needs what, and
`if args.engine == ...` would survive. It does not, and check A-10 reads
`daemon.py` and fails if the branch returns. Adding a driver never edits the
daemon. Three terms that used to share the word "adapter" now have separate
names: **backend driver** (our code, connecting to an engine), **model
profile** (a declarative description of a family), **weight adapter**
(LoRA/DoRA over a checkpoint).

**INV-9 — Purusha is non-executive, not causally inert.**
Purusha never commands, selects or executes a decision. What it witnesses
may be reflected through Smṛti and Viveka into Chitta, allowing the Being
to reconsider, revise or reverse its thoughts and actions. The resulting
decision belongs to Chitta, not to Purusha.

Fail-closed witnessing is not executive agency. Purusha may gate exposure
when witnessing fails (persist-before-expose), but it cannot select, modify,
approve or reject the substance of a decision. J-Lens evidence may return
through Viveka into Chitta before a decision is finalized
(draft D0 → reconsideration → D1); direct mutation of an output or verdict
is forbidden — a finalized decision is never rewritten, a new witnessed
decision supersedes it. The reflexive loop is a Ф3 roadmap deliverable;
until it ships, the runtime remains archive-only, which is compliant with
INV-9 v1.1.

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
  production PKI is the operator's duty. Token-bucket rate limiting (v0.5.4,
  `--rate-limit`, per endpoint class) bounds request volume, and since
  v0.6.4 **the budget belongs to an identity, not to an address**: the key
  is `cert:<CN>:<serial>` from the already-verified mTLS chain, with a
  namespaced `ip:` key only where no client certificate was presented (the
  two key spaces cannot collide). IP keying charged everyone behind one NAT
  to a single bucket and let one certificate holder reset their own budget
  by moving address. `--allow-test-hooks` (admin endpoints) refuses
  non-loopback binds.
- **Ingress is capped before authorization is reached (v0.6.4).** The
  framing gate runs before the first byte of body: over `--max-body-bytes`
  → `413`, non-integer or negative `Content-Length` → `400`, chunked
  encoding → `411` (a length that is not declared cannot be capped before
  it is read), and the reader then consumes at most the validated length so
  a lying header cannot smuggle a larger body past the parser. Admission is
  bounded on the ACCEPT LOOP, not in the handler — over `--max-concurrency`
  the socket gets a `503` and a half-close before any worker thread is
  spawned, deliberately not a bare close, since a reset cannot tell
  "overloaded, retry" from "node is dead". Every connection carries
  `--request-timeout-s`. New metrics: `body_too_large_total`,
  `bad_framing_total`, `overloaded_total`.
- **A signature is not a schema (v0.6.5).** `verify_manifest()` used to
  recompute the hash, check the signature and stop — so a buggy or hostile
  signer could emit cryptographically perfect nonsense and every verifier
  would accept it. For a provenance object that admits a model to the
  decision path, shape is part of what must be true, so
  `validate_manifest_body()` now runs FIRST: exact schema version, required
  fields, unknown keys refused, `checkpoint_hash` and every weight adapter
  in `<algo>:<hex>` content-address form, `profile_hash` a 64-hex digest,
  protocol version supported.
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
- **The witness plane takes a vocabulary, not prose (v0.6.5).** `request`
  and `response` already entered the chain as hiding commitments and
  `provenance` as a hash; `semantic_digest` was the one field placed in the
  hashed body verbatim, and it is now constrained to enum tokens, integers
  and hex digests (with one named exception for the fixed numeric
  histogram), bounded in depth and value count. Prose is refused with the
  remedy named — pass `H(x)`, not `x`. Refusal reasons that used to travel
  as sentences (the challenge round, the rate limiter) are versioned codes
  with an optional evidence hash; the sentences still reach the caller and
  the local log, where they neither replicate nor persist forever. Not
  because a caller misused the field, but because an append-only,
  replicated, undeletable store that accepts free text is both a covert
  channel and an unbounded write. Reserved means reserved **on both axes**:
  the record kinds `SESSION_OPEN`, `SESSION_CLOSE`, `LEDGER_ANCHOR`,
  `SNAPSHOT` refuse on emission, and so does populating `session_id` or
  `ir_schema_version` — the first cut let those two fields bypass the
  vocabulary check entirely, re-opening the channel through the new door
  while the old one was being bolted. A value that has entered a
  JCS-canonicalized, hash-chained log cannot be added or renamed afterwards
  without breaking every hash after it.
- **Karma executes inside a NAMED isolation profile (v0.6.4).** The
  `reference` profile is the v0.6.3 sandbox unchanged and still the default:
  it confines paths (realpath), applies rlimits, streams output with a flood
  budget (process-group kill on `OUTPUT_LIMIT_EXCEEDED`) and scrubs the
  child environment. It is honest, and it is a DENY-LIST — the child holds
  the kernel's full syscall surface and we subtract from it. The `wasm-wasi`
  profile is the allow-list counterpart: a module cannot EXPRESS a syscall
  it was not granted — no filesystem beyond the single preopened workspace,
  no sockets, no fork, no exec. The cost is stated rather than hidden:
  **arbitrary shell does not exist there.** It runs a fixed set of
  precompiled tools pinned by digest in `deploy/wasm-toolset/toolset.json`,
  verified on every execution, and `wasmtime` is invoked as a system binary
  so the codebase stays stdlib-only. Readiness is computed per tool
  (`toolset_ready` / `toolset_broken` in `capabilities()`), so one drifted
  digest does not take the whole boundary dark and a refusal names the right
  cause. **Profiles fail closed and are never downgraded** — a declared
  profile whose runtime is absent refuses the action, because the witness
  plane cannot save a node that believes it is acting inside a boundary it
  is not inside (INV-9: it observes, it does not intervene). Both refusal
  and execution are witnessed, and since v0.6.5 the provenance carries the
  `toolset_hash` and the runtime as well as the profile — so a record proves
  not merely that the being acted inside `wasm-wasi`, but which executables
  its hand could reach.

## 7. Tests

```bash
python -m pytest tests/unit tests/adversarial -q     # fast
python -m pytest tests/ -q                           # everything (spawns loopback daemons)
python scripts/run_acceptance.py [unit|integration|conformance|adversarial|legacy]
```

CI runs the matrix on Python 3.10–3.12 (`.github/workflows/ci.yml`).
Current status: 129/129 acceptance checks green (hermetic default groups),
up from 94 at v0.6.3 — v0.6.4 added I-1…I-9 (isolation profiles) and
G-1…G-8 (ingress hardening) for 111, v0.6.5 added A-1…A-11 (adapter layer)
and W-1…W-7 (plane vocabulary) for 129.

Each new check is written to fail against the previous release. Some are
also written to fail against the FIRST CUT of their own drop, which is the
more useful property: G-6, I-9, A-10 and W-6 all exist because an audit
found a test named after a claim while checking something adjacent to it.
The concurrency check tested the semaphore's semantics rather than the
ceiling, and passed while nothing was bounded; "the registry is the only
door" checked the registry in isolation while `daemon.py` still branched on
the engine name and walked past it; W-6 asserted that the reserved fields
*could* be set, enshrining the hole it was meant to close. A green suite is
evidence only about what the checks actually reach.

The `live` group is opt-in and excluded from the default run and from the
published badge: `python scripts/run_acceptance.py live` exercises the
wasm-wasi boundary against a real `wasmtime` (L-1…L-5: workspace reachable,
external filesystem unreachable, no network capability, no host binary
launchable, digest tampering fail-closed) and is required by the Ф0 gate on
each target host. Without a runtime it FAILS LOUDLY rather than skipping —
a check that skips itself is not evidence.

Release integrity is itself a test (`tests/unit/test_release_integrity.py`):
R-VER pins this README's version line, `pyproject`, `SECURITY.md` and the
last CHANGELOG header to `jjdai.__version__`; R-ACCEPT pins the badge above
to what the runner actually collects, hand-written surfaces included, after
a v0.6.4 audit found a README badge reading `68/68` while the generated one
said `109/109`.

## 8. Roadmap

**Open after v0.6.5 (near term):** `/readyz` and the liveness split ·
`sd_notify` with the `WatchdogSec` return · Prometheus alert rules
(v0.6.6) · SBOM and the supply-chain stream that `wasmtime` enters as a
declared host requirement (v0.6.7) · **the canonical AGPL-3.0 text, which
is a PUBLICATION BLOCKER** — `LICENSES/AGPL-3.0.txt` is still a placeholder
and is loudly marked as one · compiled modules for the wasm toolset · the
Profile Gauntlet that ADR-015 requires before adding an executable tool
(until it exists the toolset digest travels in `capabilities()`, so a change
is visible even though it is not yet governed).

**P1 (remaining):** full Plane B canary protocol · GPU acceptance runs ·
the bounded metadata channel the dead-drop analysis leaves open (record
counts, kinds, timing).
**P2:** DIIP · training federation · champion/challenger deployment ·
constitutional human governance (Collegium of Guardians, Being Registry) ·
economic layer · TEE attestation · multi-jurisdiction Witness network ·
the Ф3 form of the append rule, where the runtime keeps the local chain and
the witness plane does the anchoring, so no organ of a being calls
`append` at all.

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
