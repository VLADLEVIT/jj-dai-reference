> **NOTE (v0.4.1):** This is the internal build log for v0.4 (12 July 2026). The canonical public document is now README.md; component statuses live in docs/JJDAI_Code_Architecture_Map_v0.4.md.

# JJ DAI — Build v0.4 · 12 July 2026 (W28) — AGENT KERNEL: Smriti · Viveka · Karma

The foundation (0.3.x) is closed, so the Agent Kernel now has a HAND. Karma is
the first organ that touches the world — and the one that proves the whole
architecture holds: it cannot move while the governor says no, and it cannot
move unwitnessed.

0.3.x line hardens the foundation BEFORE more agent organs (Bro's call — Karma
acts on the world, so identity/verdict/governance durability come first). Five
areas, dependency-ordered: (1) Persistent Identity ✓ · (5) Typed boundaries ✓ ·
(2) Full Verdict Binding ✓ · (4) Durable Governance ✓ · (3) Live Router
Unification ✓ — ALL FIVE CLOSED. The foundation is done; the Agent Kernel
can now grow Karma on solid ground.

Full assembled build of the JJ DAI trust stack: the `jjdai` shared primitive
layer (v0.1), the M1–M5 prototype lineage (unblocked — `proto.py` recovered,
`canary_store.py` reconstructed), the Unified Router v0.2, and the NECS v0.1
spec + conformance harness. **Zero third-party dependencies — Python 3 stdlib
only.**

## Layout

```
jjdai/            shared primitive layer (single source of truth)
  canonical.py    RFC 8785 JCS deterministic bytes
  crypto.py       SHA-256 · real Ed25519 (RFC 8032) · node id · scrypt keystore
                  · hiding commitments H(salt‖x) · VRF/multisig stubs
  merkle.py       domain-separated Merkle tree + inclusion proofs
  durable.py      ★ NEW (0.3.1.3 #4): crash-safe journal primitives —
                  durable_append (flush + fsync(file) + fsync(dir on create));
                  read_journal (a torn TRAILING line = the append that never
                  finished -> report & drop, node still boots; a torn line
                  ANYWHERE ELSE = corruption/tampering -> raise);
                  truncate_torn_tail (atomic repair). Lives in jjdai/ because
                  the witness chain needs it too and the primitive layer must
                  not depend on core/.
  schema.py       ★ (0.3.1 #5): TYPED PROTOCOL BOUNDARIES — the nine
                  protocol types (NodeDescriptor · BeingDescriptor ·
                  SubstrateManifest · AdapterManifest · InferenceRequest ·
                  InferenceReceipt · VerdictEnvelope · ContainmentOrder ·
                  RegistryEvent) with a stdlib validator (Pydantic pattern,
                  zero deps). Validates TYPE, RANGE, SIZE, ENUM and PATTERN —
                  not mere presence; STRICT by default (unknown field ->
                  reject, never silently ignore); bool is NOT an int; errors
                  carry a dotted path + machine code so a daemon answers 400
                  precisely without leaking. WIRED LIVE into daemon
                  /v1/messages and /v1/score — malformed requests die at the
                  edge before any organ sees them. Limits are named constants,
                  tunable per deployment.
  witness.py      WitnessChain: hash-chained, Ed25519-signed, INFER/SANDBOX/
                  GROUNDING, LocalAnchor + OpenTimestamps seam;
                  ★ + ported WitnessReader (structural read-only) and
                  verify_legacy_chain (cv jcs/legacy dispatch — old prototype
                  logs stay auditable forever)

core/
  router.py       ★ UNIFIED (0.3.1.4 #3): the router was an ISLAND — its own
                  sorted-JSON "canonical" (not RFC 8785 JCS), its own hash, a
                  witness whose "signature" was the literal string
                  "unsigned:"+hash[:16] (i.e. NO signature — every routing
                  decision it claimed to witness was unverifiable), and its own
                  registry with no decay/shrinkage/slashing (so a router
                  champion could coast on old glory, which §9.9 forbids). All
                  four stand-ins are GONE: the router now uses jjdai.canonical,
                  jjdai.crypto, real Ed25519 ROUTE records on a jjdai
                  WitnessChain, and the real core.registry §9.9 (leaderboard
                  ordered by weight). NEW HTTPNodeEngine routes through LIVE
                  daemons (/capabilities -> descriptor, /v1/messages,
                  /v1/score) with sealed-verdict binding enforced.       Unified Router v0.2 — ChampionRegistry from verified verdicts,
                  policy_hash vs snapshot_hash, flat plane, fail-closed ABAC,
                  scope-keyed personal champions. Standalone; 27 self-tests.

necs/
  necs-v0_1.html  Node Engine Conformance Specification v0.1
  necs_harness.py pluggable harness (Ports seam, ReferenceNE, HTTPEngineAdapter)

kernel/           ★ NEW — Agent Kernel (agent layer over the trust layer)
  smriti.py       ★ Smriti (स्मृति) — memory & continuity organ, FIRST organ.
                  Three tiers (CORE always-in-context labeled blocks · RECALL
                  episodic log · ARCHIVAL = core.rag_store via the Memory
                  Keeper). Letta pattern (tiers + portable identity) under JJ
                  DAI invariants: every write is a witnessed MEMORY event with
                  a hiding commitment (content private) and a clear digest
                  mem:<being>:<op_hash>:<state_hash> binding op to resulting
                  state; the thinking organ gets ReadOnlyMemory (no mutation
                  method — structural). PORTABLE, SELF-AUTHENTICATING identity:
                  export_portable() -> a bundle another host imports and PROVES
                  authentic (re-verify Ed25519 records + replay journal to the
                  same state_hash) without trusting the exporter; tamper,
                  misattribution, or forged-key are all refused. Continuity
                  across restart & across hosts = pull-by-choice for the mind.
  karma.py        ★ NEW (v0.4): Karma (कर्म) — the ACTION organ, THIRD organ.
                  OpenHands pattern (sandbox as boundary, typed action
                  primitives, event stream) under JJ DAI invariants:
                  · WITNESS-FIRST IN TWO PHASES — an INTENT record is written
                    BEFORE the hand moves and an OUTCOME after, so an action
                    can never occur unwitnessed; a crash between them leaves a
                    visible "fate unknown" instead of silence
                    (pending_intents()).
                  · GOVERNOR-GATED — permits(being, "tools.side_effect") is
                    asked BEFORE the intent is even written, so a contained
                    Being produces ZERO side effect; reads of its own
                    workspace stay open (stop the hand, not the mind, applies
                    inside Karma too).
                  · SANDBOX (honest scope): path confinement via realpath
                    (../ AND symlink escapes refused), RLIMIT_CPU/AS/FSIZE/
                    NPROC, process-group kill on wall-clock timeout, output
                    caps, scrubbed child env. Network egress is a SEPARATE
                    governor scope; kernel-level network isolation belongs to
                    the hosting layer (Art. 18) and is not claimed here. This
                    is process-level confinement, not a VM — a sovereign
                    operator on their own metal can bypass it; Karma shrinks
                    the blast radius and makes every act evidentiary.
                  · Actions: shell · fs_read/fs_list/fs_write/fs_delete · git
                    (records resulting HEAD) · test. Event-sourced over a
                    fsynced journal; SANDBOX chain records bind
                    karma:<being>:<phase>:<action_hash>:<state_hash>.
  viveka.py       ★ Viveka (विवेक) — discernment & will organ, SECOND organ.
                  A witnessed STATE GRAPH (LangGraph pattern) under JJ DAI
                  invariants: nodes + static/conditional edges + flowing
                  state; every step is a witnessed DELIBERATION record (state
                  hidden, digest viveka:<run>:<step>:<node>:<state_hash>);
                  checkpoint after each step with deterministic replay;
                  ROLLBACK is itself witnessed (visible rewind — no secret
                  history) and supports counterfactual patch-and-resume;
                  EXECUTIVE transitions are gated by the Article-25 governor
                  (contained Being -> executive step blocked, pure discernment
                  proceeds — stop the hand, not the mind); bounded step budget;
                  discernment can be grounded in Smriti ReadOnlyMemory.

core/             MIGRATED canonical modules (W29 step 2 executed)
  identity.py     ★ NEW (0.3.0 #1): PERSISTENT identity — no more ephemeral
                  keys. NodeIdentity + BeingIdentity are keystore-backed
                  (scrypt-encrypted at rest) and survive restart; NodeID !=
                  BeingID (host vs mind). Signed, key-bound BeingManifest
                  (birth certificate, non-re-attributable). Witnessed IDENTITY
                  records: GENESIS (birth+host binding) and MIGRATION — which
                  MUST be being-key signed (consent; unsigned = seizure,
                  REFUSED, Invariant IV pull-by-choice). Startup chain
                  verification fails closed on a broken chain/manifest.
                  Formal commitment-opening policy: default ONE-WAY (salts not
                  persisted; reveal via journal bound by semantic_digest),
                  opt-in encrypted SaltVault for third-party revelation.
  durable.py      ★ NEW (0.3.1.3 #4): DURABLE GOVERNANCE. PersistentAnchor —
                  anchor receipts ON DISK (they were memory-only, so the proof
                  of non-truncation vanished exactly at restart); keeps
                  last_anchor_index and detects a truncated/rewound chain.
                  AnchorScheduler — periodic anchoring by record count or
                  elapsed time, restoring anchoring position from persisted
                  receipts (fixing the old _last_anchor_index=len(records) bug
                  that marked never-anchored records as anchored FOREVER).
                  reconcile_governance() — the boot gate: verify chain, replay
                  every journal, prove journal<->witness binding for registry/
                  containment/memory, check anchor receipts; fails closed.
                  RETROFIT: witness, registry, containment and kernel/smriti
                  now append with fsync and load crash-tolerantly.
  verdict.py      ★ (0.3.1.2 #2): FULL VERDICT BINDING. A verdict is no
                  longer a bare dict but a SEALED ENVELOPE: seal_verdict()
                  welds ok/reachable/min_margin to the verifier's identity,
                  a hash of the WHOLE scoring context (substrate+adapters+
                  messages+sampling+tokens+request_id+nonce), and a one-time
                  nonce, under the verifier's Ed25519 signature. open_verdict()
                  PINS peer identity (node_id == HASH(pubkey)), verifies the
                  signature (so forged ok/min_margin are caught), checks
                  context binding (a verdict lifted onto another request is
                  rejected), and blocks replays via NonceRegistry.
                  count_quorum() tallies DISTINCT verifier node-ids only
                  (unique-NodeID quorum — no sybil/self-repeat consensus).
                  Wired LIVE: the daemon seals every /v1/score verdict; the
                  cross-verify loop opens & verifies before recording.
  crossverify.py  ★ (I1): peer cross-verification loop. Generator ->
                  peer /v1/score -> RE-AUDIT the peer's signed witness record
                  offline (JCS re-hash + Ed25519) -> registry.record. Never
                  trusts the verdict JSON: a peer that lies about reachability
                  or never wrote the record is caught and DISCARDED.
                  Anti-self-dealing (a node can't verify its own work into
                  reputation); optional N-peer quorum. Turns certified nodes
                  into reputation-earning ones.
  registry.py     ★ (I1): ChampionRegistry M3 with the full §9.9 spine —
                  decay e^(−λΔt) (half-life 7d), shrinkage κ·C₀, saturating
                  sub-linear evidence min(1, N^γ/E_ref), slashing with slow
                  linear recovery, concave stake gate, w_max clip, w_min
                  floor, scope-keyed personal champions. EVENT-SOURCED over
                  the witness chain: REGISTRY is a first-class record kind;
                  the open question "do registry events write to the chain?"
                  is resolved — the chain ORDERS AND BINDS the open journal
                  (semantic_digest = reg:<event_hash>:<snapshot_hash>);
                  replay of the journal must reproduce snapshot_hash;
                  verify_journal_against_chain() catches tampering
  containment.py  ★ NEW: Article 25 (Containment & Adjudication) / Invariant
                  VIII. Stops the HAND, not the MIND: an egress governor
                  severs 7 executive scopes (network egress, side-effecting
                  tools, asset transfer, DIIP class-2/3, deploy/migrate, new
                  work) while keeping 6 protected scopes open (inference, own
                  memory, own witness, adjudication, guardian contact,
                  rehabilitation) — the consular channel for self-defense.
                  fail-closed on unknown scope; Phase-One threshold is
                  proof-in-Witness not consensus; false containment reverses
                  in node-time AND slashes the initiator via §9.9;
                  verification-not-vote (a standing challenge blocks
                  corroboration); code stops at PENDING_STEWARD — never
                  erases (human clock owns irreversibility); the Door Back
                  (rehabilitate) re-opens verification. Event-sourced,
                  CONTAINMENT is a first-class chain record.
  rag_store.py    M5 store bound to jjdai.merkle — roots BYTE-IDENTICAL to
                  the legacy domain-v2 scheme (no re-baseline; proved M-1)
  smriti.py       Memory Keeper bound to jjdai.witness (WitnessChain /
                  WitnessReader), hiding commitments on witnessed recalls

m1m5/             prototype lineage — RETIRED IN PLACE (see m1m5/RETIRED.md);
                  tests retained as historical acceptance evidence
  proto.py        ★ recovered verbatim (sha256/sha256_text, SandboxTrace,
                  Canary, Verdict)
  canary_store.py ★ reconstructed to the M1 interface (CanaryStore, _overlaps,
                  EvalRagOverlapError) + new sanity test
  crypto.py       ★ shim → jjdai.crypto   (single-source migration, per README)
  canonical.py    ★ shim → jjdai.canonical
  witness.py      prototype WitnessLog/WitnessReader (post Ed25519+JCS graft,
                  = witness_py.diff applied; cv jcs/legacy dispatch)
  rag_store.py    M5 sqlite + domain-v2 Merkle + eval/RAG guard
  smriti.py       Memory Keeper (read-only, structural no-write invariant)
  test_smriti.py · test_canon_merkle.py · test_witness_sig.py ·
  test_canary_store.py ★

node/               ★ Tier-1 live certification (NEW)
  daemon.py         node daemon: /v1/messages JII endpoint (NECS C1 semantics,
                    fail-closed 503), real Ed25519 WitnessChain, hiding
                    commitments, /witness/chain export, /witness/anchor,
                    engine seam (HashEngine now, DwarfStar adapter next)
  smoke_two_nodes.py  spawns TWO daemons, certifies each over HTTP
                    (R-C1..R-C3, 14 checks) incl. OFFLINE chain audit with
                    real Ed25519 — whitepaper §13 step-1 milestone
  engine_sglang.py  ★ Tier-2 SGLang adapter: generate + teacher-forcing
                    score (per-token reachability under committed sampling),
                    LoRA id->path translation; trust boundary stays in daemon
  mock_sglang.py    ★ deterministic mock SGLang server — the executable API
                    contract; certifies the Tier-2 path in CI with no GPU
  test_sglang_adapter.py ★ Tier-2 certification (S-1..S-11): LoRA routing,
                    C2 gate before engine, verifier catches forged tokens and
                    sampling-params lies, fail-closed on engine death, mixed
                    Tier-1+Tier-2 federation divergence
  engine_dwarfstar.py ★ Tier-1 DS4 adapter: Profile B BY CONSTRUCTION (refuses
                    hot adapters — no silent downgrade), dual-dialect
                    auto-probe (oai chat / gen), optional teacher-forcing
                    score on logprob-capable builds, fail-closed otherwise
  mock_dwarfstar.py ★ executable ds4 wire contract, BOTH dialects — re-pin
                    real-build divergence here first
  test_dwarfstar_adapter.py ★ DS4 certification (D-1..D-11)
  test_governor_live.py ★ NEW (I1): Article-25 governor on the LIVE JII
                    boundary (GV-1..GV-8) — contained Being -> 423 CONTAINED
                    on /v1/messages (executive hand severed), consular
                    /v1/score stays open (think + defend), containment is
                    witnessed and chain verifies, release restores the hand,
                    second node untouched (no network-wide DoS)

test_primitives.py    jjdai layer self-tests (33 checks)
test_conformance.py   NECS T-C1..T-C3 bound to jjdai (+ adversarial teeth)
docs/                 Architecture Map & Gap Analysis

★ = new in this build
```

## Run everything

```bash
# from the build root
python3 test_primitives.py           # 33/33
python3 test_vectors.py              # RFC 8032 + RFC 8785 KAT, 8/8
python3 test_identity.py             # persistent identity, 10/10
python3 test_verdict.py              # full verdict binding, 12/12
python3 test_durable.py              # durable governance, 12/12
python3 test_router_live.py          # 3-node live router unification, 12/12
python3 test_schema.py               # typed protocol boundaries, 13/13
python3 test_conformance.py --self   # NECS + teeth
python3 test_migration.py            # README migration acceptance, 8/8
python3 test_registry.py             # §9.9 reputation spine, 12/12
python3 test_containment.py          # Article 25 containment, 18/18
python3 test_kernel_smriti.py        # Agent Kernel · Smriti continuity, 12/12
python3 test_kernel_viveka.py        # Agent Kernel · Viveka state graph, 12/12
python3 test_kernel_karma.py         # Agent Kernel · Karma action organ, 16/16
python3 core/router.py               # 27/27
python3 necs/necs_harness.py --self  # reference NE + adversarial NEs caught
python3 node/smoke_two_nodes.py      # TWO LIVE NODES, 14/14 remote checks
python3 node/test_sglang_adapter.py  # Tier-2 SGLang path, 11/11 checks
python3 node/test_dwarfstar_adapter.py  # Tier-1 DS4 path, 11/11 checks
python3 node/test_governor_live.py   # Art-25 governor live, 8/8 checks
python3 node/test_crossverify_live.py # peer cross-verify loop, 6/6 checks

# prototype lineage (run from inside m1m5/)
cd m1m5
python3 test_smriti.py               # 8/8
python3 test_canon_merkle.py         # 10/10
python3 test_witness_sig.py          # 8/8
python3 test_canary_store.py         # 7/7
```

Verified green in a clean container on 2026-07-12: **272 checks + 3 adversarial
engines caught, 0 failures** — I1 complete, Agent Kernel organs Smriti +
Viveka, and ALL FIVE foundation-hardening pieces of the 0.3.x line closed:
Persistent Identity · Typed Protocol Boundaries · Full Verdict Binding ·
Durable Governance · Live Router Unification (3 live nodes, no stand-ins,
§9.9 decay/slashing and Article-25 containment both reaching routing).

## Notes

- `m1m5/crypto.py` and `m1m5/canonical.py` are **shims** re-exporting from
  `jjdai/` — the README migration ("route every hash through jjdai.canonical,
  one Ed25519 implementation") is now structural, not aspirational.
- `witness_py.diff` from the July 1→4 session is already applied inside
  `m1m5/witness.py` (envelope-level signatures, cv dispatch).
- W29 step 2 DONE: the witness lineages are unified — `jjdai.witness` is the
  single implementation (WitnessChain + WitnessReader + legacy verification);
  `m1m5/witness.py` is retired in place (m1m5/RETIRED.md).
- `canary_store.py` is a faithful reconstruction of the M1 interface; if the
  original file surfaces in the repo, diff before replacing — the guard
  semantics (`_overlaps` both directions, sibling-prefix safe) are covered by
  `test_canary_store.py`.
- Before production: RFC 8032 known-answer vectors + a JCS conformance vector
  set in CI (flagged in jjdai README).

---

## How to launch a Tier-1 node (operator guide)

A Tier-1 node is three layers stacked: the **model** (a frozen file of
weights — the intelligence), the **engine** (DwarfStar, which runs the model
and produces text), and the **daemon** (this codebase — the trust shell that
sits between the world and the engine, signs a receipt for every inference,
and cannot be silently rewritten). The engine is never trusted; only the
daemon's Ed25519-signed witness chain is. Every step below states its
consequence, so you know what you have — and don't have — at each point.

### Step 1 — Prepare the machine
Install Python 3.10+, git, and a C compiler.
*Consequence:* nothing runs yet; the ground is prepared.

### Step 2 — Install DwarfStar (the engine)
Clone `github.com/VLADLEVIT/jjdai-logic1-ds4` and build it per its README.
*Consequence:* you have an engine with no model loaded — it cannot answer
anything yet.

### Step 3 — Download the model (ds4-flash vs ds4-Pro)
**ds4-flash** is small and quantized: fast, memory-light, right for first
boot and light topics. **ds4-Pro** is larger: stronger answers, slower,
memory-hungry. Start with **flash**. Place the file where the DwarfStar
config expects models (see the ds4 repo's model section for exact files and
paths — do not guess filenames).
*Consequence:* the engine now has intelligence to serve.
**Record the SHA-256 of the weights file** — you will use it as the node's
fingerprint so provenance names the actual substrate, not a label.

### Step 4 — Start the engine and verify it locally
Launch the DwarfStar server on a local port and send one test request.
*Consequence:* raw inference works — but NOTHING is witnessed yet; any
answer could be denied or forged. **Never expose this port to the network;
only the daemon may talk to it.**

### Step 5 — Install this build (the trust shell)
Unzip the build and prove it on this exact machine:

    python3 test_primitives.py
    python3 test_migration.py
    python3 node/smoke_two_nodes.py

*Consequence:* crypto, Merkle memory, and the full trust shell are proven
green locally before any real model is involved.

### Step 6 — Start the daemon (the node is born)

    python3 node/daemon.py  (+governor: 423 CONTAINED gate, /v1/containment,
                   contained-state in capabilities) --port 8471 --name <node-name> \
        --engine dwarfstar --engine-url http://127.0.0.1:<ds4-port> \
        --fingerprint sha256:<hash-of-weights-file> \
        --log /var/jjdai/witness.jsonl

*Consequence:* the daemon generates the node's Ed25519 identity and, from
this moment, every inference receives a signed, hash-chained receipt in the
witness log. **Back up the key material; never share it — whoever holds the
key IS the node.** Do not pass `--allow-test-hooks` in production.

### Step 7 — Verify the engine binding
Run the DS4 adapter checks against your live engine (D-1..D-4 in
`node/test_dwarfstar_adapter.py`, pointed at your engine URL). If the real
ds4 API differs from the pinned contract, D-1 fails loudly — capture the
divergence in `node/mock_dwarfstar.py` first, then re-pin the adapter.
*Consequence:* the daemon and engine are proven to speak the same dialect.

### Step 8 — External certification
From a SECOND machine, run the smoke suite against the node's address.
*Consequence:* an outsider has fetched your witness chain, re-verified every
hash and Ed25519 signature independently, attempted tampering, and failed.
The node is provably honest, not promisedly honest.

### Step 9 — Keep it alive and anchored
Run the daemon under systemd (auto-restart) and periodically call
`POST /witness/anchor` so the chain's Merkle root is pinned outside the
machine.
*Consequence:* even a full compromise of the box later cannot silently
rewrite the history recorded before it.

Profile note: a DwarfStar node is **Profile B by construction** — it serves
a frozen base and refuses hot adapters (no silent downgrade). Profile A
(hot LoRA) traffic belongs on a Tier-2 SGLang node.
