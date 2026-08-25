# Documentation map

Start here. The code and the ADRs are authoritative; everything else in this
tree explains them.

| Path | What it is | Authority |
|---|---|---|
| [`architecture_status.json`](architecture_status.json) | **Source of truth** for the component table: what is Implemented, Prototype, Planned or Constitutional-text-only. Three surfaces are generated from it — the README table, the code map and the status page — and CI fails on drift. | normative |
| `JJDAI_Code_Architecture_Map_v<version>.md` | Generated code map. **Do not cite it by filename**: the name moves with every release. Cite `architecture_status.json`. | generated |
| [`adr/`](adr/) | Architecture Decision Records. A decision is not made until it is here. | **normative** |
| [`roadmap/`](roadmap/) | Roadmap r6.7 — phases Ф0…Ф5b, gates, drop numbering, the five cross-cutting tracks. Markdown is canonical; the PDF is the same document typeset. | normative for plan |
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
| ADR-014 (+A-1) | Profile Promotion and Being Role Contest | Accepted |
| ADR-015 | Cognitive IR, Session/Being boundary, Cognitive Ledger | Accepted · ready for implementation |
| [ADR-016 rev 2](adr/ADR-016-Purusha-Layer.md) | The Purusha layer: plural Sākṣī, archive, blinding | Proposed |
| ADR-017 | Key Plane: identity, object encryption, threshold recovery | Proposed |
| [ADR-018 rev 2](adr/ADR-018-Chitta-Loop.md) | Chitta Loop: evidence-grounded self-analysis and bounded self-improvement | Proposed · put to Accepted |

**ADR-014, ADR-015 and ADR-017 are not in this tree yet.** They exist and are
referenced by the roadmap and by ADR-018; they are added as their own
documentation drop. Naming the gap here is the point — an index that silently
omits what is missing is worse than no index.

## Where a decision lives

Cognition and reflection → ADR-018. Keys and encryption → ADR-017.
Witnessing and the archive → ADR-016. Contest and containment → ADR-014.
Continuity, sessions and the ledger → ADR-015. Phases, gates and drop order →
`roadmap/`. What actually exists → `architecture_status.json`.
