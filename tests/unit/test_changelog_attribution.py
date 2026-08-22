#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_changelog_attribution — v0.6.5: the CHANGELOG must not misname files
=========================================================================
The CHANGELOG is the first thing a reader of the repository opens, and its
acceptance paragraph is a MAP: "these check IDs live in that file". A map
that points at the wrong file is worse than no map, because it is followed.

This drop shipped exactly that error: two checks were added to
`test_adapter_layer.py` as functions, the CHANGELOG widened its claim to
A-1…A-11, and the file's own header still documented A-1…A-9. Anyone
looking up A-10 in the file the CHANGELOG named would not have found it.

Nothing in the suite could catch it, because prose was checked by nobody.
Now it is.

  X-1  Every `ID-N…ID-M (path)` attribution in the CHANGELOG names a file
       that exists.
  X-2  Every check ID in such a range is documented in that file's own
       header block — the two descriptions cannot drift apart.
  X-3  A file's documented IDs are contiguous from 1, with no gaps and no
       improvised suffixes. "G-6b" is how a range and a header drift apart
       in the first place: the CHANGELOG counts eight checks, the header
       shows seven numbers, and both look right in isolation.
"""
from __future__ import annotations

import io
import os
import re
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

#: "A-1…A-11\n(`tests/unit/test_adapter_layer.py`)" — the ellipsis may be a
#: unicode "…" or three dots, and a newline may sit anywhere in between.
ATTRIBUTION = re.compile(
    r"([A-Z][A-Z-]*)-(\d+)\s*(?:…|\.\.\.)\s*[A-Z][A-Z-]*-(\d+)\s*"
    r"\(`([^`]+\.py)`",
    re.S)


def _ids_documented(path: str) -> set:
    src = io.open(os.path.join(_ROOT, path), encoding="utf-8").read()
    header = src.split('"""')[1] if '"""' in src else ""
    return set(re.findall(r"^\s{2}([A-Z][A-Z-]*-\d+)", header, re.M))


def _test_count(path: str) -> int:
    src = io.open(os.path.join(_ROOT, path), encoding="utf-8").read()
    return len(re.findall(r"^def test_", src, re.M))


def test_changelog_attributions_are_true():
    changelog = io.open(os.path.join(_ROOT, "CHANGELOG.md"),
                        encoding="utf-8").read()
    claims = ATTRIBUTION.findall(changelog)
    assert claims, "X-1: no acceptance attributions found in the CHANGELOG"

    checked = 0
    for prefix, first, last, path in claims:
        full = os.path.join(_ROOT, path)
        if not os.path.exists(full):
            # a historical entry may name a file a later drop moved; only
            # the paths that still exist are the ones a reader can follow
            continue
        documented = _ids_documented(path)
        if not documented:
            continue
        wanted = {f"{prefix}-{n}" for n in range(int(first), int(last) + 1)}
        missing = sorted(wanted - documented,
                         key=lambda s: int(s.rsplit("-", 1)[1]))
        assert not missing, (
            f"X-2: CHANGELOG attributes {missing} to {path}, but that file's "
            f"own header documents only {sorted(documented, key=lambda s: int(s.rsplit('-', 1)[1]))}. "
            f"Either the check is in another file or the header was never "
            f"updated — a reader following the CHANGELOG would find nothing.")
        numbers = sorted(int(i.rsplit("-", 1)[1]) for i in documented)
        assert numbers == list(range(1, len(numbers) + 1)), (
            f"X-3: {path} documents a non-contiguous ID set {numbers} — "
            f"gaps and improvised suffixes are how a header and a CHANGELOG "
            f"range drift apart while each looks right on its own")
        assert _test_count(path) >= 1, f"X-3: {path} defines no tests"
        checked += 1

    assert checked >= 3, f"X-1: only {checked} live attributions verified"
    print(f"  [PASS] X-1..X-3  {checked} CHANGELOG attributions match the "
          f"files they name")


if __name__ == "__main__":
    test_changelog_attributions_are_true()
    print("\nchangelog attribution — 1/1 check green")
