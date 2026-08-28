# Roadmap

`JJ_DAI_Roadmap_r6_9_5.md` is canonical; the PDF is the same document typeset
for reading. Markdown is what gets reviewed, because a PDF does not diff.

**That sentence is now enforced, not asserted.** `scripts/typeset_roadmap.py`
stamps the sha256 of the source markdown into the PDF's own metadata, and
`SYNC-6` plus a CI step verify it. recut2 shipped a PDF built from an earlier
draft — 211/211 against a markdown saying 213/213, in three places — and
nothing in the tree could see it, because `check_docs_drift.py` verifies the
surfaces generated from `architecture_status.json` and the roadmap PDF is not
one of them. Rebuild the PDF with that script; never by hand.

The roadmap is self-contained by convention: each revision includes the
previous one in full, so reading r6.7, r6.8, r6.8.1, r6.8.2, r6.8.3
or r6.8.4 is not required to read r6.9.5. The changes tables at the top are the delta.

**Only the current revision lives here.** Superseded revisions are not kept
beside it: a directory holding two self-contained roadmaps invites an
implementation to read the wrong one, and "correct text beside a stale table"
is a defect this project has already paid for. Previous revisions are
recoverable from git history.

**Gates are more important than the calendar.** A phase closes on an evidence
artefact, not on a date, and a build tag means "the phase's work is under
way", never "the phase is closed".
