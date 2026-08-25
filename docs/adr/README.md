# Architecture Decision Records

An ADR is normative. If the code and an ADR disagree, one of them is a defect
and the disagreement is itself reportable.

Numbering is sequential and never reused. A number is spent when an ADR is
written, not when it is accepted — ADR-018 was briefly renumbered to 017 on
the assumption that 017 was free; it was not, and the renumber was withdrawn.

Statuses: **Proposed** (written, under review) · **Accepted** (ruled on;
implementation may reference it) · **Superseded by ADR-NNN**.

Amendments are journalled inside the document (`rev 1`, `rev 2`, with a table
of what changed and why) rather than rewritten in place, so a reviewer can
read the history of a decision without a diff.

A **named amendment** (`A-1`) is used where a decision is corrected after it
was accepted rather than revised before. It goes INSIDE the document, at the
point it corrects — ADR-017 / A-1 sits at K4-bis, immediately after the K4 it
limits. The one exception is ADR-014, whose issued form is a PDF and cannot
be patched: its A-1 is a separate file, and the index warns about it.

**The full index, with statuses, is in [`../README.md`](../README.md).** It is
kept in one place on purpose; two indexes drift.
