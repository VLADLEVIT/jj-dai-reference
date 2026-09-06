#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
README ownership — after ADR-022 D12 the build does not write here at all.

Until v0.6.9 the build owned three fenced blocks inside the README and the
check was that it wrote nowhere else. That arrangement carried one cost: a
file the build rewrites cannot be hashed into the source digest, because
writing the result would invalidate the run that result describes. So README
held the only exclusion in the tree with no binding anywhere else, and
"excluded, bound nowhere" is exactly what D11 forbids.

The blocks moved to `docs/status_badge.md`. These checks assert the stronger
property that replaces the old one.

  R-OWN-1  The generated blocks are GONE from README, and the file points at
           where they went.
  R-OWN-2  Running the generator changes NOT ONE BYTE of README — asserted
           with a sentinel planted in the prose a maintainer edits by hand.
  R-OWN-3  README is inside the source digest, and `docs/status_badge.md`
           is in the output set with a binding.
  R-OWN-4  The generated file regenerates identically, so its exclusion is
           an exclusion and not a hiding place.
  R-OWN-5  The HAND-WRITTEN prose agrees with the debt ledger. No generator
           touches it, so nothing else would ever catch it drifting — and it
           did: §8 listed two-person release approval as open debt for a
           drop and a half after ADR-022/D2 cancelled it, contradicting the
           ledger, the roadmap and the CHANGELOG at once. Sections that
           exist and say nothing are caught here for the same reason.
"""
from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

README = os.path.join(_ROOT, "README.md")
BADGE = os.path.join(_ROOT, "docs", "status_badge.md")
SENTINEL = "<!-- sentinel: a maintainer's own sentence -->"

from jjdai import source_tree as st                            # noqa: E402


def test_generated_blocks_have_left_the_readme():
    """R-OWN-1"""
    text = io.open(README, encoding="utf-8").read()
    for name in ("VERSION", "STATUS", "ACCEPT"):
        assert f"{name}:BEGIN" not in text, (
            f"{name} block is still spliced into README; D12 moves the "
            f"generated surface out so the file can be hashed")
    assert "docs/status_badge.md" in text, (
        "README must say where the generated status went — a block that "
        "vanishes without a pointer reads as a deletion")
    assert os.path.exists(BADGE)
    print("  [PASS] R-OWN-1  the three generated blocks are gone and README "
          "points at docs/status_badge.md")


def test_generator_changes_no_byte_of_the_readme():
    """R-OWN-2"""
    with tempfile.TemporaryDirectory() as tmp:
        work = os.path.join(tmp, "repo")
        shutil.copytree(_ROOT, work, ignore=shutil.ignore_patterns(
            "__pycache__", ".git", "*.pyc"))
        path = os.path.join(work, "README.md")
        text = io.open(path, encoding="utf-8").read()
        marker = "## 1. What is JJ DAI\n"
        assert marker in text, "section 1 heading moved; update this check"
        text = text.replace(marker, marker + "\n" + SENTINEL + "\n")
        io.open(path, "w", encoding="utf-8", newline="\n").write(text)

        r = subprocess.run([sys.executable,
                            os.path.join("scripts",
                                         "gen_architecture_docs.py")],
                           cwd=work, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        after = io.open(path, encoding="utf-8").read()
        assert after == text, (
            "the generator rewrote README. It owns docs/status_badge.md and "
            "nothing here; the whole point of D12 is that this file can be "
            "hashed because the build never touches it")
        assert SENTINEL in after
    print("  [PASS] R-OWN-2  the generator changes no byte of README, "
          "sentinel intact")


def test_readme_is_hashed_and_the_badge_is_bound():
    """R-OWN-3"""
    scope = st.load_scope(_ROOT)
    assert not st.in_output_set("README.md", scope), (
        "README is in the OUTPUT set: it is not generated any more, so "
        "excluding it would be an exclusion with nothing behind it")
    assert st.in_output_set("docs/status_badge.md", scope), (
        "the generated status file must be in the output set — hashing a "
        "file the run writes stops the pair converging")
    bindings = scope["bindings"]
    key = [k for k in bindings if k.startswith("docs/status_badge")]
    assert key, ("docs/status_badge.md is excluded and bound nowhere; a "
                 "merely excluded file does not exist (ADR-022 D11)")
    entries = [e[0] for e in st.worktree_entries(_ROOT)]
    assert "README.md" in entries
    print("  [PASS] R-OWN-3  README is in the subject tree; the generated "
          "status file is in the output set with a binding")


def test_generated_status_regenerates_identically():
    """R-OWN-4"""
    before = io.open(BADGE, encoding="utf-8").read()
    sys.path.insert(0, os.path.join(_ROOT, "scripts"))
    import gen_architecture_docs as gen                         # noqa: E402
    result = gen.generate(write=False)
    assert result["badge"] == before, (
        "docs/status_badge.md drifted from what the generator produces. It "
        "sits outside the digest, so nothing else would catch it: an "
        "exclusion is only safe while the file is provably derived")
    print("  [PASS] R-OWN-4  the generated status file regenerates byte for "
          "byte")


def test_readme_prose_agrees_with_the_ledger():
    """R-OWN-5"""
    import json
    from jjdai import provenance as prv
    text = io.open(README, encoding="utf-8").read()
    status = json.load(io.open(os.path.join(_ROOT, "docs",
                                            "architecture_status.json"),
                               encoding="utf-8"))
    state = prv.load_debt_ledger(status)
    # A cancelled or closed position must not be described as owed. The
    # ledger is the source of truth; this file is prose beside it, and prose
    # beside a source of truth is where a stale claim survives longest.
    for position, phrase in (
            ("two-person-approval", "two-person release approval"),
            ("sbom", "an SBOM is still owed"),
            ("gitattributes", ".gitattributes is missing")):
        if state.get(position) != prv.DEBT_OPEN:
            assert phrase not in text, (
                f"README still describes {position!r} as owed; the ledger "
                f"projects it as {state.get(position)!r}")
    # every non-empty numbered section actually says something
    import re
    sections = re.split(r"^## ", text, flags=re.M)[1:]
    for section in sections:
        head, _, body = section.partition("\n")
        assert body.strip(), (
            f"section {head.strip()!r} is empty. An empty section is worse "
            f"than a missing one: a reader takes the heading as a promise "
            f"that was kept somewhere below")
    print("  [PASS] R-OWN-5  the hand-written prose agrees with the debt "
          "ledger, and no section is empty")


if __name__ == "__main__":
    for fn in (test_generated_blocks_have_left_the_readme,
               test_generator_changes_no_byte_of_the_readme,
               test_readme_is_hashed_and_the_badge_is_bound,
               test_generated_status_regenerates_identically,
               test_readme_prose_agrees_with_the_ledger):
        fn()
