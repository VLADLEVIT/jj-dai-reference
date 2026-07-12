# JJ DAI — Build v0.2 · 12 July 2026 (W28)

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
  witness.py      WitnessChain: hash-chained, Ed25519-signed, INFER/SANDBOX/
                  GROUNDING, LocalAnchor + OpenTimestamps seam

core/
  router.py       Unified Router v0.2 — ChampionRegistry from verified verdicts,
                  policy_hash vs snapshot_hash, flat plane, fail-closed ABAC,
                  scope-keyed personal champions. Standalone; 27 self-tests.

necs/
  necs-v0_1.html  Node Engine Conformance Specification v0.1
  necs_harness.py pluggable harness (Ports seam, ReferenceNE, HTTPEngineAdapter)

m1m5/             prototype lineage (flat imports), NOW RUNNABLE
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

test_primitives.py    jjdai layer self-tests (33 checks)
test_conformance.py   NECS T-C1..T-C3 bound to jjdai (+ adversarial teeth)
docs/                 Architecture Map & Gap Analysis

★ = new in this build
```

## Run everything

```bash
# from the build root
python3 test_primitives.py           # 33/33
python3 test_conformance.py --self   # NECS + teeth
python3 core/router.py               # 27/27
python3 necs/necs_harness.py --self  # reference NE + adversarial NEs caught
python3 node/smoke_two_nodes.py      # TWO LIVE NODES, 14/14 remote checks

# prototype lineage (run from inside m1m5/)
cd m1m5
python3 test_smriti.py               # 8/8
python3 test_canon_merkle.py         # 10/10
python3 test_witness_sig.py          # 8/8
python3 test_canary_store.py         # 7/7
```

Verified green in a clean container on 2026-07-12: **107 checks + 3 adversarial
engines caught, 0 failures** (incl. the 14-check two-node live certification).

## Notes

- `m1m5/crypto.py` and `m1m5/canonical.py` are **shims** re-exporting from
  `jjdai/` — the README migration ("route every hash through jjdai.canonical,
  one Ed25519 implementation") is now structural, not aspirational.
- `witness_py.diff` from the July 1→4 session is already applied inside
  `m1m5/witness.py` (envelope-level signatures, cv dispatch).
- Two witness implementations still coexist by design for now:
  `jjdai.witness.WitnessChain` (target) and `m1m5.witness.WitnessLog`
  (prototype). Unification is step 2 of the W29 plan (see docs/).
- `canary_store.py` is a faithful reconstruction of the M1 interface; if the
  original file surfaces in the repo, diff before replacing — the guard
  semantics (`_overlaps` both directions, sibling-prefix safe) are covered by
  `test_canary_store.py`.
- Before production: RFC 8032 known-answer vectors + a JCS conformance vector
  set in CI (flagged in jjdai README).
