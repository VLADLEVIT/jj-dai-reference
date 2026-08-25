# Roadmap

`JJ_DAI_Roadmap_r6_8_2.md` is canonical. Markdown is what gets reviewed,
because a PDF does not diff.

The roadmap is self-contained by convention: each revision includes the
previous one in full, so reading r6.7, r6.8 or r6.8.1 is not required to read
r6.8.2. The changes table at the top is the delta.

**No PDF for this revision yet.** r6.7 shipped as markdown plus a typeset PDF;
r6.8.2 has only the markdown. The superseded r6.7 pair — markdown and PDF —
moved to [`../history/`](../history/), where nothing describes the current
plan.

**Gates are more important than the calendar.** A phase closes on an evidence
artefact, not on a date, and a build tag means "the phase's work is under
way", never "the phase is closed".

## What r6.8.2 changes

Four things, on top of r6.8.1:

- **Pre-flight tags enter the numbering rules.** A tag of the form
  `v0.6.8-preflight` names a green tree whose release debt is still open. It
  must be annotated rather than lightweight, so the caveat travels in the tag
  itself; the commit must carry a `tree_digest` matching the recorded run; no
  GitHub Release object is created and `latest` is not moved. **It does not
  consume the version number.**
- **The four debts are separated by what each one blocks**, because they used
  to be quoted as one list: the canonical AGPL blocked *publication* and is
  closed; a CLA blocks *accepting outside contributions* and has nothing to do
  with tagging; T-TOOLSET is a *Ф0 gate deliverable*; supply chain is *the
  meaning of a release tag*.
- **The unbuilt content of v0.6.7 is called a transfer, not a plan.** r6.7
  declared v0.6.7 to be law, supply chain and T-TOOLSET. After nine recuts its
  actual content was the live vertical, and of what was declared only the AGPL
  was built. r6.8 carried the remainder forward as if it had always been
  scheduled that way; r6.8.2 names the divergence instead — the same rule the
  project applies to code.
- **Byte-exactness of the tree moves into supply chain** rather than staying
  hygiene. `source_digest()` reads raw bytes and the repository had no
  `.gitattributes`, so any line-ending conversion broke both the `tree_digest`
  and the AGPL pin at once — while the failure reported "a different tree",
  not "line endings". The repository's `.gitattributes` closes that.
