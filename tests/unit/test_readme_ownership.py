#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_readme_ownership — v0.6.5: the build may not touch the prose
=================================================================
The README has two owners. The repository owns the title, the notice and
section 1 "What is JJ DAI" — the sentence that explains the project to
someone who has not met it, which a generator knowing only a status file has
no business rewriting. The build owns three fenced blocks and nothing else.

Until now that was a convention, and a convention loses to a `sed` in a hurry:
the acceptance badge and the version line were hand-written, the build edited
them anyway, and a repository maintainer editing the same region got a
conflict — or worse, silently lost their wording to the next generated
README.

  R-OWN-1  The three marker blocks exist and are well formed.
  R-OWN-2  Running the generator changes NOTHING outside them, byte for
           byte — proven with a sentinel planted in the prose, including in
           section 1 itself.
  R-OWN-3  The generator is idempotent: a second run is a no-op, so a build
           never produces a spurious diff for the repository to resolve.
  R-OWN-4  The build's own facts live INSIDE the blocks, so no build step
           has a reason to reach outside them.
"""
from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

README = os.path.join(_ROOT, "README.md")
BLOCKS = ("VERSION", "STATUS", "ACCEPT")
SENTINEL = ("JJ DAI is an architecture for a decentralized 3-tier network of "
            "persistent-memory-owning and self-evolving AI agents. "
            "SENTINEL-DO-NOT-TOUCH-7f3a")


def _blocks(text: str) -> dict:
    out = {}
    for name in BLOCKS:
        m = re.search(re.escape(f"<!-- {name}:BEGIN") + r".*?"
                      + re.escape(f"<!-- {name}:END -->"), text, re.S)
        assert m, f"R-OWN-1: README has no {name} marker block"
        out[name] = m.span()
    return out


def _outside(text: str) -> str:
    """Everything the build must not touch, concatenated."""
    spans = sorted(_blocks(text).values())
    keep, cursor = [], 0
    for start, end in spans:
        keep.append(text[cursor:start])
        cursor = end
    keep.append(text[cursor:])
    return "".join(keep)


def test_marker_blocks_exist():
    text = io.open(README, encoding="utf-8").read()
    spans = _blocks(text)
    ordered = sorted(spans.values())
    for (s1, e1), (s2, _) in zip(ordered, ordered[1:]):
        assert e1 <= s2, "R-OWN-1: marker blocks overlap"
    print("  [PASS] R-OWN-1  VERSION / STATUS / ACCEPT blocks are well formed")


def test_generator_touches_nothing_outside_its_blocks():
    with tempfile.TemporaryDirectory() as tmp:
        work = os.path.join(tmp, "repo")
        shutil.copytree(_ROOT, work, ignore=shutil.ignore_patterns(
            "__pycache__", ".git", "*.pyc"))
        path = os.path.join(work, "README.md")
        text = io.open(path, encoding="utf-8").read()

        # plant a sentinel in the prose the repository owns — the very
        # sentence a maintainer edits by hand
        marker = "## 1. What is JJ DAI\n"
        assert marker in text, "section 1 heading moved; update this check"
        text = text.replace(marker, marker + "\n" + SENTINEL + "\n")
        io.open(path, "w", encoding="utf-8").write(text)
        before_outside = _outside(text)

        r = subprocess.run([sys.executable,
                            os.path.join("scripts", "gen_architecture_docs.py")],
                           cwd=work, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

        after = io.open(path, encoding="utf-8").read()
        assert SENTINEL in after, \
            "R-OWN-2: the build overwrote hand-owned prose in section 1"
        assert _outside(after) == before_outside, \
            "R-OWN-2: the build changed bytes outside its marker blocks"
        print("  [PASS] R-OWN-2  generator left every hand-owned byte intact")

        r2 = subprocess.run([sys.executable,
                             os.path.join("scripts", "gen_architecture_docs.py")],
                            cwd=work, capture_output=True, text=True)
        assert r2.returncode == 0, r2.stderr
        assert io.open(path, encoding="utf-8").read() == after, \
            "R-OWN-3: the generator is not idempotent — a build would hand " \
            "the repository a diff it did not ask for"
        print("  [PASS] R-OWN-3  second run is a no-op")


def test_build_facts_live_inside_the_blocks():
    text = io.open(README, encoding="utf-8").read()
    spans = _blocks(text)
    inside = {name: text[a:b] for name, (a, b) in spans.items()}
    outside = _outside(text)

    assert "**Version:**" in inside["VERSION"], \
        "R-OWN-4: the version line is not inside its block"
    assert "acceptance checks green" in inside["ACCEPT"], \
        "R-OWN-4: the acceptance badge is not inside its block"
    # and no copy of either survives in hand-owned territory, where a build
    # step would be tempted to edit it
    assert "acceptance checks green" not in outside, \
        "R-OWN-4: a second acceptance badge lives outside the blocks"
    assert not re.search(r"^\*\*Version:\*\*", outside, re.M), \
        "R-OWN-4: a second version line lives outside the blocks"
    print("  [PASS] R-OWN-4  every machine-owned fact sits inside a block")


if __name__ == "__main__":
    tests = [test_marker_blocks_exist,
             test_generator_touches_nothing_outside_its_blocks,
             test_build_facts_live_inside_the_blocks]
    for t in tests:
        t()
    print(f"\nreadme ownership — {len(tests)}/{len(tests)} checks green")
