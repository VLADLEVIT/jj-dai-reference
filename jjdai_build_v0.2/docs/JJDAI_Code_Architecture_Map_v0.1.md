# JJ DAI — Code ↔ Architecture Map & Gap Analysis
**Against jj-dai.org Whitepaper 1.0 · 12 July 2026 (W28)**

All self-contained suites verified green in a clean container:
`test_primitives.py` 33/33 · `router.py` self-tests 27/27 · `necs_harness.py` ALL GREEN · `test_conformance.py --self` ALL GREEN + all three adversarial engines CAUGHT.

---

## 1. What the uploaded files actually are — three lineages

### Lineage A — `jjdai` shared primitive layer (v0.1, the clean current home)

| File | Whitepaper anchor | Role | Status |
|---|---|---|---|
| `__init__.py` | — | package binding (canonical, crypto, merkle, witness) | ✅ |
| `canonical.py` | §6 Plane H, NECS Canonicalization | RFC 8785 JCS deterministic bytes | ✅ runs |
| `crypto.py` | §9.1 Identity, §12.4 | SHA-256, **real Ed25519 (RFC 8032)**, node_id, scrypt keystore, hiding commitments H(salt‖x), VRF/multisig **stubs** | ✅ runs |
| `merkle.py` | §6 Plane H | domain-separated Merkle root + inclusion proofs | ✅ runs |
| `witness.py` (new) | §12 Witness Layer | `WitnessChain`: hash-chained, Ed25519-signed, kinds INFER/SANDBOX/GROUNDING, hiding commitments, `LocalAnchor` + `OpenTimestampsAnchor` seam, JSONL persistence | ✅ runs |
| `test_primitives.py` | — | 33 checks over the four modules | ✅ 33/33 |
| `test_conformance.py` | NECS | T-C1..T-C3 bound to jjdai primitives, + teeth | ✅ green |

Note: `canonical-1.py ≡ canonical.py` and `crypto-1.py ≡ crypto.py` — **byte-identical duplicates**, no version drift. Safe to delete the `-1` copies.

### Lineage B — M1–M5 prototype (older, pre-migration)

| File | Whitepaper anchor | Role | Status |
|---|---|---|---|
| `witness-1.py` | §12 / whitepaper §13, §7.4 | prototype `WitnessLog` + `WitnessReader` (JSONL, cv=legacy/jcs dispatch) | ⚠️ **cannot run** — imports missing `proto` |
| `rag_store.py` | §6 Plane H, §3 personalization | M5 sqlite chunk store + **inline** Merkle + eval/RAG separation guard | ⚠️ missing `proto`, `canary_store` |
| `smriti.py` | §3 (Smriti = individuating memory) | Memory Keeper: read-only agent, structural no-write invariant, Merkle-proofed citations | ⚠️ missing `proto` |
| `test_smriti.py`, `test_canon_merkle.py`, `test_witness_sig.py` | — | prototype-side tests | ⚠️ same missing deps |

### Bridge

| File | Role |
|---|---|
| `witness_py.diff` | The Jul 1→4 graft: envelope-level Ed25519 signatures + JCS canonicalization (`cv="jcs"` / `"legacy"` dispatch) onto prototype `WitnessLog`, fully backward-compatible with unsigned legacy logs |

### Standalone reference implementations

| File | Whitepaper anchor | Status |
|---|---|---|
| `router.py` v0.2 | §7 Inference routing (+ "router as power center") | ✅ 27/27. ChampionRegistry from **verified verdicts only**; `policy_hash` (static, replicated) vs `snapshot_hash` (dynamic, local) separation; flat single pool; ABAC fail-closed; capability-match fail-closed; requester override witnessed; `scope` keying for personal champions **implemented** |
| `necs-v0_1.html` | §6 verification | NECS spec: Definitions & Profiles (A/B), Composition & Certification, Canonicalization, DwarfStar → Profile B, "Where specialization lives" |
| `necs_harness.py` | §6 | Pluggable Ports seam, `StdlibPorts` + `M1M5Ports` binding, `ReferenceNE`, `HTTPEngineAdapter` for a live `/v1/messages` engine | ✅ green + teeth |

---

## 2. Mapping to the five-layer architecture / whitepaper sections

| Whitepaper section | Code coverage | Verdict |
|---|---|---|
| §1–2 Frozen substrate, trust tiers T1–T3 | NECS Profiles A/B; `NodeDescriptor.profile` | conceptually covered |
| §3 Personalization (RAG, Smriti) | `smriti.py` + `rag_store.py` | prototype only, blocked by missing deps |
| §4 Distillation production line | — | ❌ not in code |
| §5 Training federation | — | ❌ not in code (later phase per §13) |
| §6 Plane H (memory integrity) | `merkle.py`, `rag_store.py` | ✅ / migration pending |
| §6 Plane B (canaries, A/B/C classes) | `canary_store` referenced but **missing**; canary lifecycle (rotation, secret reserve, bounty) absent | ⚠️ partial |
| §6 Attestation slot | generator "attested" / verifier "reproducible" in router descriptors | interface only |
| §7 Routing | `router.py` v0.2 | ✅ strongest artifact |
| §9.1 Identity & Sybil | `crypto.node_id`, keystore; VRF stub | partial |
| §9.2–9.5 Work protocol, challenge game, ledger | — | ❌ |
| §9.9 Reputation math | `_Stats` = decayed-free pass_rate + avg_margin | ⚠️ see gap R below |
| §10 Diversity & provenance | `NodeDescriptor.attributes` (free-form) | ❌ no provenance manifest, no independence weighting |
| §11 DIIP | — | ❌ no gauntlet / classes / lifecycle code |
| §12 Witness Layer | `witness.py` + anchors + commitments; every routing decision is a C3 event | ✅ core is real; anchor is a seam |
| §13 Deployment step 1 (2 nodes, Plane H, no fine-tune) | matches current code scope well | ✅ aligned |

---

## 3. What is missing — prioritized

### M — Missing modules (referenced by uploaded code but not uploaded / possibly not written)
1. **`proto.py`** — `sha256_text`, `sha256` helpers. Blocks the entire prototype lineage (rag_store, smriti, witness-1, three test files).
2. **`canary_store.py`** — `_overlaps`, `EvalRagOverlapError`, and the M1 canary eval store itself. Blocks `rag_store.py` and Plane B.
3. **`anchor.py`** — referenced in witness-1 docstring (external anchoring).
4. **`registry.py` (M3)** — the real ChampionRegistry that `router.py` explicitly mirrors.
5. **Node daemon / `/v1/messages` server** — `HTTPEngineAdapter` exists but nothing to point it at; conformance has never been run against a live engine.

### U — Unification decisions (two witness lineages)
6. `jjdai.witness.WitnessChain` (Lineage A) vs prototype `WitnessLog` + `witness_py.diff` graft (Lineage B) are **two parallel witness implementations**. README says migrate everything to `jjdai.witness`; the diff instead patches the old one. Pick one — recommendation: finish the README migration, keep the diff's `cv` legacy-dispatch idea for reading old logs.
7. **README migration not executed:** `rag_store.py` still uses inline Merkle via `proto`, not `jjdai.merkle` (namespace roots will re-baseline — re-run M5 grounding tests); `smriti.py` still imports the prototype witness.

### R — Reputation math gap (§9.9 — biggest spec/code divergence)
8. Router's `_Stats` keeps only `(passes, fails, avg_margin)`. The whitepaper's spine is absent: **exponential decay e^(−λΔt), difficulty weights dₐ, shrinkage κ·C₀, sub-linear N^γ, slashing factor S, stake g(), w_max clipping.** Without decay, a champion can coast forever — exactly what §9.9 forbids ("influence requires continuous fresh verified work").

### G — Governance & network layers not yet in code
9. **DIIP machinery (§11)** — champion–challenger shadow mode, blind holdout head-to-head, class 1/2/3 thresholds, bond, circuit-breaker/rollback. The ChampionRegistry is the natural substrate for class-1 auto-adopt, but the gauntlet doesn't exist.
10. **Provenance manifests + independence-weighted consensus (§10)** — multi-axis manifest schema, agreement-correlation tracking, diversity-constrained panel selection.
11. **Canary lifecycle (§6)** — rotation/expiry, secret reserve, adversarial bounty, commit-reveal sampling.
12. **Challenge game / slashing / bonded collateral (§9)**.

### H — Hardening (small, near-term)
13. **RFC 8032 known-answer vectors** in CI (README explicitly flags this — property tests only today).
14. **JCS vector-set validation** for `canonical.py` ES6 number edge cases.
15. **Real external anchor** — `OpenTimestampsAnchor.submit` is a seam that raises; wire opentimestamps client (dev can stay LocalAnchor).
16. **Registry mutations are only indirectly witnessed** — `registry.record()` (router.py:553) precedes the `route.verify` event; the verdict is witnessed but the registry state transition has no dedicated event. Your open question ("do registry events write to the witness chain?") remains open *in the code* too. Cheapest resolution: emit a `registry.update` C3 event carrying `(topic, object_id, ok, margin, new snapshot_hash)`.
17. **LLM classifier** — only `RuleClassifier`; the `Classifier` ABC seam is ready.
18. **Real engines** — `ReferenceEngine` / `MockMemoryEngine` only; no DwarfStar (Metal, attested generator) or CPU teacher-forcing verifier binding yet.
19. **Smriti retrieval ranking** — naive token overlap (honest seam); sqlite-vec + embedder, and HOLA surprise-weighting sits in backlog.

---

## 4. Suggested repo structure (target)

```
jjdai/                      # Lineage A — the one true primitive layer
  __init__.py canonical.py crypto.py merkle.py witness.py
  proto.py                  # ← write or fold into crypto (sha256_text/sha256)
core/
  router.py                 # v0.2 reference → bind to jjdai.* at the seams
  registry.py               # M3 real ChampionRegistry (+ §9.9 math)
  canary_store.py           # M1 + lifecycle
  rag_store.py smriti.py    # repointed to jjdai.merkle / jjdai.witness
necs/
  necs-v0_1.html necs_harness.py test_conformance.py
node/
  daemon.py                 # /v1/messages, wraps engine + WitnessChain
tests/
  test_primitives.py test_smriti.py test_canon_merkle.py test_witness_sig.py
```

## 5. Recommended W29 sequence

1. Write `proto.py` (trivial) + recover/write `canary_store.py` → unblocks the entire prototype lineage and its 3 test files.
2. Execute the README migration (rag_store → jjdai.merkle; smriti/daemon → jjdai.witness.WitnessChain) and retire `witness-1.py` after porting its `WitnessReader` + cv-dispatch.
3. Add the `registry.update` witness event (closes open question #16 fail-safe).
4. Drop RFC 8032 KAT vectors + a JCS vector file into `test_primitives.py`.
5. Stand up a minimal node daemon and run `test_conformance.py --http` against it — first live certification.
6. Then start §9.9 reputation math inside `registry.py` (decay + shrinkage first; slashing/stake later).
