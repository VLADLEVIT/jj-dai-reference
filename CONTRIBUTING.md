# Contributing

## Workflow

1. Read `docs/architecture_status.json` — the source of truth for component
   status, and what the architecture map in `docs/` is generated from. Do not
   cite the map by filename: it now carries the release version, so any
   pinned name goes stale at the next bump. Statuses matter:
   PRs against Planned components need a design discussion first.
2. Tests: `python -m pytest tests/ -q` must be green; new behavior needs
   new tests in the appropriate group (unit / integration / conformance /
   adversarial / compatibility). Those five are the HERMETIC groups and are
   what the badge counts. `tests/live` is opt-in, needs a real runtime on the
   host, and is excluded from `pytest tests/` — run it explicitly. Sequential certification suites (e.g. Karma A-1..A-16)
   are single narrative functions by design — extend the narrative,
   don't fragment it.
3. Core is stdlib-only. Dependencies require a maintainer decision.
4. Invariants (the eight in the Invariant Core, INV-9 included) are not
   negotiable in code review.

## CLA

Contributions require a Contributor License Agreement assigning
sufficient rights to JJ GROUP to preserve the project's licensing
structure (AGPL-3.0 core / Apache-2.0 NECS) and the option of
dual-licensing the core. The CLA text will be published before external
contributions are accepted; until then, PRs are received as review-only.
