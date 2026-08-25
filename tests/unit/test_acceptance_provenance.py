#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_acceptance_provenance — v0.6.7 audit: a badge about which code?
=====================================================================
The v0.6.7 recut fixed one half of this: the badge stopped being a count of
`def test_*` declarations and started coming from a recorded run. What it
did not fix is which TREE that run happened against.

The recorded result carried counts. `total` moves only when the NUMBER of
checks moves, so any defect introduced without adding or removing a test
function left the recorded result matching and the badge reading green about
code that no longer existed. Demonstrated on the v0.6.8 tree: an entire
reserve was short-circuited to accept everything it exists to refuse, no
test function changed, and the generator printed "158/158 green" with a
clean drift check.

So the run now records a content address of the source it executed against,
and the badge refuses to claim green for a different tree.

  ACC-TREE-1  the recorded result carries a tree digest, and it matches this
              tree right now.
  ACC-TREE-2  the digest is a function of CONTENT: changing one byte of one
              source file changes it, and changing it back restores it.
  ACC-TREE-3  a stale digest costs the badge its green — the badge says the
              evidence is not about this code, and names both digests.
  ACC-TREE-4  the digest ignores what the run itself produces: regenerating
              the documentation surfaces, and byte-compiling the tree, leave
              it unchanged. A digest that moved when the badge was written
              could never converge.
"""
from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gen_architecture_docs as G                             # noqa: E402
from run_acceptance import read_result, source_digest         # noqa: E402


def test_result_names_the_tree_it_ran_against():
    res = read_result()
    assert res is not None, (
        "ACC-TREE-1: no recorded run — a badge without a run behind it is a "
        "claim about nothing")
    assert res.get("tree_digest"), \
        "ACC-TREE-1: the recorded run does not name a source tree"
    assert res["tree_digest"] == source_digest(), (
        "ACC-TREE-1: the recorded run was against a different source tree "
        "than the one being tested — re-run scripts/run_acceptance.py")
    # /v4 since v0.6.8-recut3, which added `collector`. The pin is on an
    # EXACT version rather than a prefix, and that is the point: it is what
    # forces a shape change to be acknowledged here instead of absorbed
    # silently. A downstream reader parsing /v3 must be told the shape moved.
    assert res.get("schema", "").endswith("/v4"), (
        "ACC-TREE-1: the artefact schema was not versioned with its shape. "
        "If a field was added or removed, bump the schema AND this pin — "
        "they move together on purpose.")
    assert res.get("suite") == "hermetic", (
        "ACC-TREE-1: the recorded run does not say WHICH suite it is — one "
        "unnamed artefact is how hermetic and live evidence overwrote each "
        "other")
    print(f"  [PASS] ACC-TREE-1 recorded run names this tree "
          f"({res['tree_digest'][:12]}…)")


def test_digest_is_a_function_of_content():
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "tree")
        os.makedirs(os.path.join(root, "pkg"))
        a = os.path.join(root, "pkg", "a.py")
        io.open(a, "w", encoding="utf-8").write("x = 1\n")
        io.open(os.path.join(root, "pkg", "b.py"), "w",
                encoding="utf-8").write("y = 2\n")
        first = source_digest(root)

        io.open(a, "w", encoding="utf-8").write("x = 2\n")
        assert source_digest(root) != first, \
            "ACC-TREE-2: a changed source byte left the digest identical"

        io.open(a, "w", encoding="utf-8").write("x = 1\n")
        assert source_digest(root) == first, \
            "ACC-TREE-2: the digest is not a pure function of content"

        # a renamed file is a changed tree, even at identical content
        shutil.move(a, os.path.join(root, "pkg", "c.py"))
        assert source_digest(root) != first, \
            "ACC-TREE-2: a rename left the digest identical"
    print("  [PASS] ACC-TREE-2 the digest follows content and path")


def _badge_with(result: dict) -> str:
    import run_acceptance as RA
    original = RA.read_result
    try:
        RA.read_result = lambda: result
        return G.acceptance_badge()
    finally:
        RA.read_result = original


def test_stale_digest_costs_the_badge_its_green():
    """Two synthetic runs, identical but for the tree they name.

    Deliberately NOT written as "the current badge is green, now break it".
    That shape is a circular dependency and this project has already shipped
    it once: R-ACCEPT demanded the literal phrase "N/N green", which an
    honest badge cannot produce during a red run, so the check that goes red
    could never go green again. A check about the RULE must not depend on
    the state of the tree it is checked in.
    """
    n = G.count_acceptance()
    good = {"schema": "jjdai.acceptance_result/v2", "passed": n, "total": n,
            "import_errors": 0, "python": "3.12.3",
            "tree_digest": source_digest()}
    stale = dict(good, tree_digest="0" * 64)

    fresh_badge = _badge_with(good)
    assert "green" in fresh_badge, (
        f"ACC-TREE-3: a green run against THIS tree did not read green: "
        f"{fresh_badge}")

    stale_badge = _badge_with(stale)
    assert "green" not in stale_badge, (
        f"ACC-TREE-3: a green run against ANOTHER tree still published "
        f"green: {stale_badge}")
    assert "NOT EVIDENCE ABOUT THIS CODE" in stale_badge, stale_badge
    assert "000000000000" in stale_badge, \
        "ACC-TREE-3: the badge does not say which tree the run was against"
    assert source_digest()[:12] in stale_badge, \
        "ACC-TREE-3: the badge does not say which tree it is standing in"
    print("  [PASS] ACC-TREE-3 a stale tree digest is published, not hidden")


def test_digest_ignores_what_the_run_produces():
    before = source_digest()
    # The generated surfaces live under docs/ — including the recorded
    # result itself. If the digest covered them, writing the badge would
    # invalidate the run the badge describes and the pair could never
    # converge. Checked by writing there, not by trusting the exclusion
    # list. Deliberately NOT by calling the generator: a test that rewrites
    # the repository's documentation mid-run makes every later check depend
    # on the order it ran in.
    excluded = os.path.join(_ROOT, "docs", "evidence", ".probe.json")
    os.makedirs(os.path.dirname(excluded), exist_ok=True)
    try:
        io.open(excluded, "w", encoding="utf-8").write("{}\n")
        assert source_digest() == before, (
            "ACC-TREE-4: a file written into the evidence directory changed "
            "the source digest — writing a result would invalidate the run "
            "that result describes and the pair could never converge")
    finally:
        if os.path.exists(excluded):
            os.remove(excluded)

    # The mirror, and since recut3 the more important half: docs/ is NOT
    # excluded wholesale any more. The ADRs and the roadmap are normative
    # and shipped, so a change to them IS a change to what the run proved.
    normative = os.path.join(_ROOT, "docs", "adr", ".probe.md")
    try:
        io.open(normative, "w", encoding="utf-8").write("probe\n")
        assert source_digest() != before, (
            "ACC-TREE-4: a new file under docs/adr left the digest "
            "unchanged — the normative documents are outside the evidence")
    finally:
        if os.path.exists(normative):
            os.remove(normative)
    assert source_digest() == before
    import compileall
    compileall.compile_dir(os.path.join(_ROOT, "jjdai"), quiet=2)
    assert source_digest() == before, \
        "ACC-TREE-4: byte-compiling the tree changed the source digest"
    print("  [PASS] ACC-TREE-4 generated surfaces and caches are outside "
          "the digest")


if __name__ == "__main__":
    for t in (test_result_names_the_tree_it_ran_against,
              test_digest_is_a_function_of_content,
              test_stale_digest_costs_the_badge_its_green,
              test_digest_ignores_what_the_run_produces):
        t()
    print("\nacceptance provenance — 4/4 checks green")
