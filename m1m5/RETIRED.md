# m1m5/ — RETIRED (W29, 2026-07-12)

This directory is the frozen M1–M5 prototype lineage. Per Manifesto Art. VII
("history shall not be erased") it is retained in-place with its acceptance
tests runnable, but **nothing outside this directory imports it anymore.**

Superseded by:

| Retired module        | Canonical successor                                  |
|-----------------------|------------------------------------------------------|
| witness.py (WitnessLog / WitnessReader / cv-dispatch) | jjdai/witness.py — WitnessChain + ported WitnessReader + verify_legacy_chain |
| rag_store.py          | core/rag_store.py (bound to jjdai.merkle; roots byte-identical — proved by test_migration.py M-1) |
| smriti.py             | core/smriti.py (bound to jjdai.witness)              |
| crypto.py / canonical.py (shims) | jjdai/crypto.py · jjdai/canonical.py     |

Old prototype-format witness logs remain auditable forever via
`jjdai.witness.verify_legacy_chain` (per-record cv dispatch, jcs + legacy).

proto.py and canary_store.py remain LIVE pending the canary-lifecycle
migration (Plane B / §6) — they are the M1 eval store until then.
