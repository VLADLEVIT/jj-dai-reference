# Architecture diagrams (explanatory, not normative)

> **Solid blue = exists in the current build. Dashed purple = Ф3 target.**
> The ADRs and the code are authoritative.

| File | What it shows |
|---|---|
| `jj-dai-reference-node-r6.7.png` | The node as a whole: trust boundary, API surface, cognition and continuity, the deterministic action boundary, the state and cognitive ledger, the ADR-017 key plane and the external services. |
| `jj-dai-cognition-reflection-external-interaction-r6.7.png` | The being's cognitive loop and the Svādhyāya reflexive loop in detail, with the interaction and perception plane and the controlled action path. |

## Known divergences between the diagrams and this build

Listed rather than quietly corrected, because a diagram nobody audits becomes
a second, wrong source of truth:

- **`Health / Readiness` appears as one block** on the node diagram. They are
  two endpoints with different authorization: `/healthz` is anonymous and
  returns `{"ok": true}` and nothing else; `/readyz` is peer/admin because it
  names loaded engines, broken toolsets and anchoring lag.
- **`Engine Backend` sits inside the deterministic action boundary.** The
  engine is the one non-deterministic component in the system; it belongs to
  the cognitive contour, where the second diagram correctly places it.
- **Anchoring is absent from both diagrams** — no `AnchorScheduler`, no XMR,
  no OTS calendar — although the mandatory XMR anchor is an architectural
  constant outside DIIP and anchoring is an input to readiness.
- **`Vector DB · Qdrant`** is shown as an external service. Smriti retrieval
  is sqlite-vec with Merkle proofs and the core is stdlib-only; an external
  vector service has not been decided and would need an answer for the
  contamination proof, which requires an `AuthenticatedIndexRoot` derived
  deterministically from a witnessed `SmritiRoot`.
- **Key-plane domain names** are drawn as `network · secret · reflexive ·
  prediction · round_ephemeral`; the reserved values are `reflexive_recovery`,
  `prediction_round`, `prediction_resolution`, `round_ephemeral`. These are
  serialized values and the drift must be resolved before genesis.
