# JJ DAI — Reference Trust, Governance & Agent Kernel

> **Version, acceptance count and the component status table** live in
> [`docs/status_badge.md`](docs/status_badge.md), generated from
> `docs/architecture_status.json`. They moved out of this file in v0.6.9
> (ADR-022 D12): the build owns that file entirely and does not write
> here, so this README is hashed into `jjdai.source-tree/v2` like every
> other shipped file.

<!--
  README OWNERSHIP (v0.6.9)
  ------------------------
  The build does not write into this file AT ALL.

  Until v0.6.9 it owned three fenced blocks here — VERSION, STATUS and
  ACCEPT — and everything outside them belonged to the repository. That
  arrangement worked, and it had one cost: a file the build rewrites cannot
  be hashed into the source digest, because writing the result would
  invalidate the run the result describes. So README carried the only
  exclusion in the tree with no binding anywhere else.

  ADR-022 D12 removes the reason rather than the symptom. The three blocks
  now live in docs/status_badge.md, generated whole from
  docs/architecture_status.json; this file links to it and is hashed like
  every other shipped file. A normalised hash over README was the
  alternative and was rejected: it trades byte exactness for exactness by
  agreement, and agreements drift.

  tests/unit/test_readme_ownership.py now asserts the stronger property —
  running the generator changes NO byte of this file.
-->

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

JJ DAI is an architecture for a decentralized 3-tier network of
persistent-memory-owning and self-evolving AI agents built on the principle
that everything touching a decision is verified.

Mutable knowledge lives outside frozen model weights (RAG, Plane H); every
inference, memory write, routing decision and containment act is bound to
cryptographic evidence and recorded in an Ed25519-signed, hash-chained
witness log; inference and verification are performed by separate roles
(generator/verifier asymmetry);
and an agent's executive capabilities can be selectively severed — with due
process, reversibility and rehabilitation — without silencing its voice or
destroying its memory.

The five-layer composition: LLM/agent → knowledge graph/ontology →
deterministic tools → verification → non-executive Witness plane (Sākṣī).
The organ kernel: **Smriti** (memory) observes and indexes, **Viveka**
(discernment) distinguishes states and drift, **Karma** (action) executes
inside a governed sandbox — each act witnessed before and after.

## 2. System requirements

**To run the kernel and the acceptance suite** — **Linux or macOS**, and
**Python ≥ 3.10**. That is the whole list. The trust core is stdlib-only:
`core/`, `jjdai/`, `kernel/`, `node/`, `necs/` import nothing that is not
in the standard library, so there is no dependency tree to audit and
nothing to install before `python scripts/run_acceptance.py` works.

Two stdlib modules must be compiled into your interpreter, which the
system packages of every mainstream distribution provide: `ssl` (every
TLS/mTLS path in the daemon) and `sqlite3` (the Plane H retrieval store).
`pytest` is optional — it buys the `tests/` layout and the CI matrix;
`scripts/run_acceptance.py` is a stdlib runner that follows the same
protocol for environments without it.

**On Windows, run a Linux environment — WSL2 or a virtual machine.** This
is not a packaging gap that a later release closes. The Karma reference
sandbox confines an action with `os.setsid`, `resource.setrlimit` (CPU,
address space, file size, process count) and `os.killpg`: POSIX primitives
with no Windows equivalent. A containment boundary is the wrong thing to
approximate — a sandbox that emulates its limits is a sandbox whose limits
are a guess — so the daemon does not pretend to offer one there. Inside
WSL2 or a Linux VM this is simply the Linux host it is, and everything
above applies unchanged.

**To operate a node**, the deployment kit targets two hosts, and the
runbooks are written per host rather than pretending one command fits both:

| | Linux node | macOS node |
|---|---|---|
| Target | Ubuntu 24.04, `systemd`, `openssl` | Apple Silicon, `launchd` |
| Runbook | `deploy/RUNBOOK.md` | `deploy/RUNBOOK-macOS.md` |
| Service | `jjdai-node@.service` | `org.jjdai.node.<name>.plist` |
| Bootstrap | `deploy/bootstrap_node.sh` | `deploy/macos/bootstrap_node_macos.sh` |
| Keystore sealing | `deploy/tpm_seal.py` (TPM 2.0 + `tpm2-tools`) | `deploy/macos/keychain_seal.py` (System keychain, **degraded profile** — see RUNBOOK-macOS §2) |

The macOS runbook's reference host is a MacBook Pro, Apple Silicon,
128 GB unified memory / 2 TB.

**Optional host requirements.** Each of these buys one capability, and
every one of them FAILS CLOSED when absent — the node refuses the work
rather than performing it in a weaker way:

- `wasmtime` on `PATH` — required by the `wasm-wasi` isolation profile,
  invoked as a system binary rather than linked in, so the codebase stays
  stdlib-only. Declaring the profile without it is a loud refusal.
- TPM 2.0 and `tpm2-tools` (Linux) or the macOS System keychain — sealing
  the keystore passphrase. Without either, the passphrase comes from the
  environment, never the CLI.
- `openssl` — issuing the deployment PKI. `scripts/gen_dev_certs.py`
  issues a DEV CA for local work; production PKI is the operator's duty.
- an `ots` client — verifying Bitcoin inclusion of OTS calendar proofs
  held in custody.
- a Monero wallet RPC endpoint — the `xmr` anchor backend.

**No accelerator is required.** The `hash` reference driver is
deterministic and CPU-only, and it is what the acceptance suite runs
against. GPU-class hardware belongs to the engines behind the seam, not to
JJ DAI: `sglang` and `dwarfstar` reach a server over HTTP (Tier-1
substrate, RTX 6000 / Apple Silicon class, whitepaper §13 step 1), so the
trust shell and the accelerator need not share a host.

**Footprint.** A node listens on `8471` by default and holds, per the
ingress ceilings, 64 concurrent connections with a 1 MiB body cap and a
15 s request clock. Each sandboxed action gets 10 s CPU, 512 MiB of
address space, a 64 MiB file-size cap, 64 processes and 64 kB of captured
output. Plan disk deliberately: the witness log is append-only JSONL and
grows monotonically — it is never compacted, because a chain that forgets
is not a chain — and on a Linux node `/var/lib/jjdai` also carries
journals, replicas and the workspace.

## 3. What is in this release

The component table — what is Implemented, Prototype, Planned or
Constitutional-text-only — lives in
[`docs/status_badge.md`](docs/status_badge.md), together with the version
line and the acceptance count. It is generated whole from
`docs/architecture_status.json`, which is the source of truth; `check_docs_drift`
fails CI when the two disagree.

It moved out of this file in v0.6.9 (ADR-022 D12) so that the build writes
nowhere in the README. A file the build rewrites cannot be hashed into the
source digest — writing the result would invalidate the run that result
describes — so keeping the table here bought a permanent exclusion. Moving it
removed the reason instead of the symptom, and this README is now hashed like
every other shipped file.

## 4. What is NOT in this release

> **New here?** `docs/README.md` is the documentation map, §2 below is what
> you need to run it, §5 is a working node in four commands, and §6 has a
> table of every directory and what belongs in it.

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

## 5. Quick start

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
# profiles this node will actually honour. /healthz answers "is this
# process alive", /readyz answers "should it be sent work" — since v0.6.6
# those are separate questions with separate answers (and separate authz:
# /healthz leaks nothing and needs no identity, /readyz does)
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

## 6. Architecture

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

### Where it lives

The diagram above is the *shape*; this is the tree. Everything is Python
without third-party imports, so a directory is a layer, not a build target.

| Path | What it is | Read it when |
|---|---|---|
| [`docs/`](docs/) | **Start here.** `docs/README.md` is the documentation map: the status file that is the source of truth, the ADRs (a decision is not made until it is one), the roadmap, and the diagrams — labelled explanatory, not normative. | You want the reasoning, not the code |
| `jjdai/` | The shared primitive layer, and the only part meant to be imported as a library: JCS canonicalization, Ed25519 and VRF, Merkle trees, the witness chain, durability, and `jjdai/adapters/` — the EngineBackend protocol, registry, drivers and model profiles | You are building on JJ DAI |
| `core/` | Trust and governance services on top of those primitives: identity, the §9.9 reputation registry, sealed verdicts, the challenge round, containment, replication and segments, anchoring (local, peer-quorum, OTS, Monero), Plane H, routing, diversity, cross-verification, attestation | You are asking how a guarantee is enforced |
| `kernel/` | The organ kernel — `smriti` (memory), `viveka` (discernment), `karma` (governed action) and `isolation` (the execution profiles Karma runs inside) | You are asking what an agent may do |
| `node/` | The reference daemon: HTTP surface, authz, readiness, watchdog, clock watch, plus mock engines. **Not a package** — its modules import each other by bare name, which works because the daemon puts its own directory on `sys.path` | You are running or reading the node |
| `runtime/` | `BeingRuntime` — the decision lifecycle, traces and semantic recovery. Prototype | You are following a decision end to end |
| `necs/` | The NECS v0.1 specification and its conformance harness. **Apache-2.0**, unlike everything above it | You are certifying an engine |
| `tests/` | `unit` · `integration` (spawns loopback daemons) · `conformance` · `adversarial` · `compatibility` (the frozen M1–M5 lineage) · `live` (opt-in, needs a real runtime) | Always — the suites are the specification that runs |
| `deploy/` | Runbooks per host, the systemd and launchd kits, PKI generation, TPM and Keychain sealing, Prometheus rules, a Grafana dashboard, the wasm toolset manifest | You are standing a node up |
| `scripts/` | The stdlib acceptance runner and the documentation generators that CI gates on | You are running checks or regenerating surfaces |
| `m1m5/` | The retired M1–M5 lineage, kept **frozen** and verbatim for auditability. Nothing here describes the current build | You are auditing where something came from |
| `LICENSES/` | Full texts: AGPL-3.0 for the core, Apache-2.0 for NECS | See §10 |

Two directories are deliberately not what a newcomer might expect. `node/`
is a script directory rather than a package, so it is absent from the wheel
— packaging it would break the bare-name imports rather than fix anything.
And `m1m5/` looks like live code but is not: it is the ancestor, frozen on
purpose, and `tests/compatibility` exists to prove it still verifies.

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

## 7. Security model (read before deploying)

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
- **Liveness and readiness are different questions (v0.6.6).** `/healthz`
  answers whether the process is alive; `/readyz` answers whether it should
  be sent work, and they are not the same fact — a node can be perfectly
  alive and unfit to serve. The split is also an exposure decision:
  `/readyz` names loaded engines, broken toolsets and anchoring lag, so the
  shipped policy admits only `peer` and `admin` to it, while `/healthz`
  leaks nothing and stays anonymous. Both are enforced by the same authz
  layer as every other path, and H-1…H-6 check the boundary rather than
  trusting it. Under systemd the unit runs `Type=notify` with
  `WatchdogSec=90`; a node that stops ticking is restarted rather than left
  hanging, and host suspension is detected and distinguished from a clock
  step instead of being read as a stall.
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

## 8. Tests

```bash
python -m pytest tests/unit tests/adversarial -q     # fast
python -m pytest tests/ -q                           # everything (spawns loopback daemons)
python scripts/run_acceptance.py [unit|integration|conformance|adversarial|legacy]
```

CI runs the matrix on Python 3.10–3.12 (`.github/workflows/ci.yml`).


That count grew from 94 at v0.6.3: v0.6.4 added I-1…I-9 (isolation
profiles) and G-1…G-8 (ingress hardening) for 111; v0.6.5 added A-1…A-11
(adapter layer), W-1…W-7 (plane vocabulary), R-OWN-1…R-OWN-4 (README
ownership) and X-1…X-3 (CHANGELOG attribution) for 133; v0.6.6 added
R-1…R-9 (readiness rules), S-1…S-6 (notify and the beacon gate), C-1…C-4
(suspension versus clock step), T-0…T-5 (toolset fault codes), A-1…A-5
(the alert rules as a deliverable) and H-1…H-6 (the live split) for 140;
the v0.6.6 recut added the wheel-packaging checks for 145, and v0.6.7
brought it to 179.

**The badge is now backed by a recorded run, not by a count.** A count moves
only when the NUMBER of checks moves, so a defect introduced without adding
or removing a test left the old result matching and the badge green about a
tree that no longer existed. `scripts/run_acceptance.py` writes
`docs/evidence/hermetic.json` — the result plus a content digest of the tree
it ran against — and the generator refuses to publish a green badge whose
digest does not match the current tree. `README.md` and the badge-carrying
surfaces are excluded from that digest on purpose: hashing them would let
writing a result invalidate the run the result describes, and the pair could
never converge.

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

What the opt-in `live` group proves, and why it is excluded from the count
above: L-1…L-5 exercise the wasm-wasi boundary against a real `wasmtime` —
workspace reachable, external filesystem unreachable, no network capability
granted, no host binary launchable, digest tampering fail-closed. Without a
runtime the group FAILS LOUDLY rather than skipping, because a check that
skips itself is not evidence.

**This README is itself under test.** Two suites hold it to the code:

- `test_release_integrity.py` — R-VER pins the version line, `pyproject`,
  `SECURITY.md` and the last CHANGELOG header to `jjdai.__version__`;
  R-ACCEPT pins the badge to what the runner actually collects, after a
  v0.6.4 audit found a README badge reading `68/68` while the generated one
  said `109/109`.
- `test_readme_ownership.py` (v0.6.5) — the file has two owners, and the
  boundary is now enforced rather than agreed. The build owns the three
  fenced blocks above and nothing else; the title, the notice and section 1
  belong to the repository. R-OWN-2 copies the tree, plants a sentinel
  inside section 1, runs the generator and fails if a single byte outside
  the markers moved; R-OWN-3 requires the generator to be idempotent, so a
  build never hands the repository a diff it did not ask for; R-OWN-4
  requires every machine-owned fact to live inside a block, leaving no
  reason for a build step to reach into the prose. This exists because it
  had already happened — the repository corrected "3-layer" to "3-tier" in
  section 1, and nothing stopped the next build from putting "3-layer"
  back.

## 9. Roadmap

The plan of record is
[`docs/roadmap/JJ_DAI_Roadmap_r6_9_13.md`](docs/roadmap/JJ_DAI_Roadmap_r6_9_13.md).
What follows is what it says about the tree you are reading — and `SYNC-2`
fails the build if this section names a roadmap the tree does not carry.

This tree is **v0.6.8 — `code-complete · 219/219 recorded · pre-flight
tagged`**, with release debt open. It is not a release and does not pretend
to be one.

**`v0.6.8-preflight` names commit `4df83f9`** — annotated, so the caveat
travels inside the tag rather than in a document beside it, and carrying
`tree_digest 48236bb5…`, the same digest as the run that certifies the tree.
No Release object exists and `latest` was not moved: a bare tag stays under
*Tags* and never reads as a published version. **It does not consume a
version number** — neither `v0.6.8` nor `v0.6.9` is spent, both stay
available for the release tag that closes the supply-chain debt.

What it buys is a point of reference. Three drops ran without one — v0.6.6
never closed, v0.6.7 and v0.6.8 went untagged — so there was no way to say
*this tree, this run, compare against it*. Now there is.

The archive it came from is named `v0.6.9-pre`, and the *pre* is load-bearing:
it is preparation for the v0.6.9 drop, not the drop. **None of v0.6.9's
content — T-TOOLSET, the reproducible build, release objects,
`RELEASE_ATTESTED` — is built.** So `jjdai.__version__` stays at `0.6.8`, and
it stays there until a drop actually carries that content: the version line
above is generated from `architecture_status.json`, not from git, and no
surface in this tree reads a tag at all. What this package closes is the
documentary basis: roadmap r6.9.5 and ADR-014…022 are in the tree, under the
same `tree_digest` as the run that certifies it.

One consequence worth stating, since it looks like a contradiction. The
tagged commit's own README says `untagged`, because a commit cannot describe
the tag that names it — writing the description changes the commit, and the
tag would then name something else. The snapshot is honest about the moment
it was written; this paragraph exists one commit later.

**v0.6.7 was declared as law, supply chain and the toolset. That is not what
it turned out to be, and the roadmap says so rather than absorbing the gap.** Its actual content is the **live vertical**: a real engine inside
`BeingRuntime`, a separate keystore per being, `BeingIdentity` surviving a
daemon restart and mTLS, the artifact binding chain, the trace commitment.
Of everything that *was* declared, only one item was built — the canonical
AGPL — and the rest is carried forward as a **transfer**, named as such.
The drop is `179/179 green, untagged`.

The distinction matters because a divergence between what a release
announced and what it contains is the same class of defect this codebase
chases in code: it gets named, not folded into the next revision's plan.

**Closed here:** the canonical AGPL-3.0 text byte-for-byte — the publication
blocker that stood since v0.4.1 — with `R-LICENSE` now verifying the text and
its digest rather than checking that a placeholder is loudly marked. Plus the
repository hygiene batch and the documentation entry point in `docs/`.

**Four debts remain, and they block four different things.** They used to be
quoted as one list, which made all four look like one wall:

| Debt | What it blocks | State in this tree |
|---|---|---|
| canonical AGPL | **publication** | closed in v0.6.7; the sha256 is pinned by a test |
| CLA | **accepting outside contributions**; nothing to do with tagging | absent — and it does not hold the tag |
| T-TOOLSET | a **Ф0 gate deliverable**; a tag claims nothing about a toolset existing | absent: `deploy/wasm-toolset/toolset.json` carries the mechanism with an empty `tools` |
| supply chain | **the meaning of a release tag** — without signed artefacts and provenance a tag names a commit, not a release | partly closed in v0.6.8 |

Supply chain is worth splitting, because "partly" is not a status anyone can
act on. **Done and in the tree:** `.gitattributes` with `* -text`, a
CycloneDX SBOM with a drift check in CI, test dependencies pinned by version
*and* hash, workflow actions pinned by commit, the build backend pinned to an
exact version, and `SYNC-6` verifying that the roadmap PDF is not stale
against its markdown. **Still open**, as the ledger in
`docs/architecture_status.json` projects it: a reproducible build, the build
backend pinned **by hash** — PEP 517 gives `requires` no field for one, so
this needs a different mechanism rather than a stricter string — signed
artefacts, and release provenance. Two-person approval is no longer owed:
the ledger records it **cancelled**, and `R-OWN-5` fails this file if the
prose keeps calling it open.

**A green tree with open release debt can still be named.** r6.8.2 introduced
the **pre-flight tag** — `v0.6.<n>-preflight` — for exactly that state, on
four conditions: annotated rather than lightweight, so the caveat travels
inside the tag; a commit whose `tree_digest` matches the recorded run; no
Release object and no `latest`; and normative documents synchronous with the
tree. All four are met by `v0.6.8-preflight` above. Exactly one thing is
forbidden: presenting an unclosed drop as a release.

**Open, and named rather than implied.** No compiled wasm modules ship, so
execution in practice is still the `reference` fence. The alert thresholds
are starting points, **not an SLO table** — the values stay open until the
end of Ф3, and no recording rules ship, because thresholds published now
would carry the authority of a config file while being guesses.
`readiness_snapshot()` reports `chain_broken` empty and `signer_mismatch`
false rather than re-verifying the chain per scrape (the boot gate already
refuses a foreign identity; per-request verification would be a
self-inflicted denial of service). Anchoring lag reads optimistically when
the scheduler exposes no timestamp — a node that has never anchored reports
`null` rather than infinite, so the metric is honest about not knowing and
the alert cannot fire on it. And the Profile Gauntlet that ADR-015 requires
before adding an executable tool does not exist yet; until it does, the
toolset digest travels in `capabilities()`, so a change is at least visible
even though it is not governed.

**P1 (remaining):** full Plane B canary protocol · GPU acceptance runs ·
the bounded metadata channel the dead-drop analysis leaves open (record
counts, kinds, timing).
**P2:** DIIP · training federation · champion/challenger deployment ·
constitutional human governance (Collegium of Guardians, Being Registry) ·
economic layer · TEE attestation · multi-jurisdiction Witness network ·
the Ф3 form of the append rule, where the runtime keeps the local chain and
the witness plane does the anchoring, so no organ of a being calls
`append` at all.

## 10. License

Two-license structure (see `LICENSE`): the trust/governance **core is
AGPL-3.0-only** — nodes serve other nodes over a network, and §13 obliges
operators of modified nodes to disclose their modifications to those they
serve; the **NECS specification and harness are Apache-2.0** so that
independent engine vendors can implement and certify without copyleft
obligations.

**On a CLA — it is an options question, not a formality (r6.8.2).** The usual
argument for one is patents, and AGPL already closes that: it gives the
project inbound = outbound and carries a patent grant in §11. The only thing
a CLA buys here is **keeping the option to license the code as something
other than AGPL** — dual licensing, a commercial licence, a Solo SKU, shipping
with an ASIC. Without it, every accepted outside commit makes relicensing
possible only with the named consent of every contributor, retroactively. If
that option is not wanted, a DCO is enough. The decision is taken with a
lawyer, and it needs a named legal entity to exist first.

Until it is taken, **public contribution is not open** — that is what the CLA
debt blocks, and it blocks nothing else. [`CONTRIBUTING.md`](CONTRIBUTING.md)
carries the workflow and says the same thing in its own words: the CLA text
is published before external contributions are accepted, and until then a
pull request is received as review-only.

## 11. Responsible disclosure

Security reports: see `SECURITY.md`. Do not open public issues for
vulnerabilities in identity, witness, sandbox or containment paths.

---
*Jai Guru Dev.*
