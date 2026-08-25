# Documentation map

Start here. The code and the ADRs are authoritative; everything else in this
tree explains them.

| Path | What it is | Authority |
|---|---|---|
| [`architecture_status.json`](architecture_status.json) | **Source of truth** for the component table: what is Implemented, Prototype, Planned or Constitutional-text-only. Three surfaces are generated from it — the README table, the code map and the status page — and CI fails on drift. | normative |
| `JJDAI_Code_Architecture_Map_v<version>.md` | Generated code map. **Do not cite it by filename**: the name moves with every release. Cite `architecture_status.json`. | generated |
| [`adr/`](adr/) | Architecture Decision Records. A decision is not made until it is here. | **normative** |
| [`roadmap/JJ_DAI_Roadmap_r6_8_5.md`](roadmap/JJ_DAI_Roadmap_r6_8_5.md) | Roadmap **r6.8.5** — phases Ф0…Ф5b, gates, drop numbering, the six cross-cutting tracks, Agent Alpha as the goal of Ф0. Markdown is canonical; the PDF is the same document typeset. | normative for plan |
| [`architecture/`](architecture/) | Explanatory diagrams. **Not normative** — see the warning below. | explanatory |
| [`site/`](site/) | Generated status pages, one per release. | generated |
| [`history/`](history/) | Superseded build documents, kept for auditability. Nothing here describes the current build. | historical |

## Reading the diagrams

> **Solid blue components exist in the current build. Dashed purple components
> are Ф3 targets that do not exist yet.** The diagrams are explanatory; the
> ADRs and the code remain authoritative. A block on a diagram is not evidence
> that anything implements it.

That warning is not a formality. The diagrams show `ChittaRuntime`, the
cognitive ledger, Self-Model and the Skill Gate — none of which exist in code
today. They are Ф3.

## ADR index

| ADR | Subject | Status |
|---|---|---|
| [ADR-014 (+A-1)](adr/ADR-014-Profile-Promotion-Being-Role-Contest.pdf) | Profile Promotion and Being Role Contest | Accepted |
| [ADR-014 · amendment A-1](adr/ADR-014-amendment-A1.md) | Replicas, comparator panel, containment branches | Accepted |
| [ADR-015](adr/ADR-015-Cognitive-IR-Being.md) | Cognitive IR, Session/Being boundary, Cognitive Ledger | Accepted · ready for implementation |
| [ADR-016 rev 2](adr/ADR-016-Purusha-Layer.md) | The Purusha layer: plural Sākṣī, archive, blinding | Proposed |
| [ADR-017 (+A-1)](adr/ADR-017-Key-Plane.md) | Key Plane: identity, object encryption, threshold recovery | Accepted |
| [ADR-018 rev 2](adr/ADR-018-Chitta-Loop.md) | Chitta Loop: evidence-grounded self-analysis and bounded self-improvement | Accepted |
| [ADR-019 rev 3.1](adr/ADR-019-Deferred-Verification.md) | Deferred verification: a decision in custody and the node's offline mode | Accepted |
| [ADR-020 rev 4.1](adr/ADR-020-Agent-Alpha.md) | Agent Alpha: harness, profile, being, host conformance; guardian trust root and signed feedback | Accepted |
| [ADR-021 rev 4](adr/ADR-021-Memory-Inheritance.md) | Memory inheritance: loaded experience and telling it from what was lived | **Proposed** |

**Read A-1 before acting on ADR-014.** The PDF is the document as issued on
31 July 2026 and still carries `Status: Proposed` on its face; it was accepted
subsequently and amendment A-1 **revokes part of D6**. Where ADR-014 says a
Being Role Contest runs by direct attested participation and "the cell travels
to the being", A-1.1 replaces that with replicas in two symmetric evaluation
cells. A PDF cannot be patched in place, so the correction is stated here
rather than left for a reader to hit at D6.

**ADR-017 carries amendment A-1 INSIDE the document, at K4-bis.** Unlike ADR-014, ADR-017 is markdown and can be patched in place, so the amendment sits where a reader of K4 will hit it rather than in a separate file. A-1 names one exception to K4's epoch committee — a
principal-local wrapping key for access class `GUARDIAN_PRIVATE` and only that class — and it is the one place where ADR-017 permits runtime in Ф0. Its normative basis is ADR-020 rev 4.1 §A9-bis.

**ADR-017 was flipped to Accepted in v0.6.8, before the reserve was built.**
The same rule that applied to ADR-018 in the first v0.6.8 cut: a pre-genesis
reserve must not rest on a Proposed decision. `jjdai/cognitive.py` pins four of
its wrapping domains and `jjdai/custody.py` pins a fifth, so the strings were
already frozen while the document said Proposed.

**Still missing: nothing.** Every ADR referenced by the roadmap is in this
tree, and so is the roadmap revision that references them — the first cut of
v0.6.8 shipped r6.7 while r6.8.2 was already normative, which is how the code
came to be proved against a plan the tree did not contain.

**Two are Proposed, and the index says so rather than levelling them.** ADR-016
rev 2 and ADR-021 rev 4. Neither may be relied on by an implementation. An
index that silently omits a status difference is worse than no index.

## Where a decision lives

Cognition and reflection → ADR-018. Keys and encryption → ADR-017.
Witnessing and the archive → ADR-016. Contest and containment → ADR-014.
Continuity, sessions and the ledger → ADR-015. The Alpha harness, the guardian
trust root and signed feedback → ADR-020. Loading experience into a being →
ADR-021. Phases, gates and drop order → `roadmap/`. What actually exists →
`architecture_status.json`.
