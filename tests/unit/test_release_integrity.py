# -*- coding: utf-8 -*-
"""
v0.6.3 unit acceptance — release integrity (audit item #3)

The docs-drift checker verifies the GENERATED status surfaces; this test
pins the HAND-WRITTEN surfaces to the code so version and capability
claims cannot rot:

  R-VER     README version == jjdai.__version__ == pyproject version ==
            SECURITY scope version == last CHANGELOG release header
  R-PHRASES README/SECURITY must not contain claims the code outgrew
            ("no rate limits", "challenge round ... in-process", the old
            "degraded / secure-enclave profile" wording)
  R-ACCEPT  acceptance count printed in generated docs == tests actually
            collected by the runner
  R-LICENSE LICENSES/AGPL-3.0.txt is the canonical AGPL-3.0 text
            BYTE-FOR-BYTE, pinned by sha256 (v0.6.7: was a placeholder
            guard while the text was missing)
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _ROOT)


def _read(*parts):
    return open(os.path.join(_ROOT, *parts), encoding="utf-8").read()


def _pkg_version():
    import jjdai
    return jjdai.__version__


def test_versions_agree_everywhere():
    v = _pkg_version()
    readme = _read("README.md")
    m = re.search(r"\*\*Version:\*\*\s*`([^`]+)`", readme)
    assert m, "R-VER: README has no **Version:** `x.y.z` line"
    assert m.group(1) == v, \
        f"R-VER: README says {m.group(1)}, package says {v}"
    pyproject = _read("pyproject.toml")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    assert m and m.group(1) == v, \
        f"R-VER: pyproject={m.group(1) if m else None}, package={v}"
    security = _read("SECURITY.md")
    m = re.search(r"Scope notes for this release \(v([0-9.]+)\)", security)
    assert m and m.group(1) == v, \
        f"R-VER: SECURITY scope={m.group(1) if m else None}, package={v}"
    changelog = _read("CHANGELOG.md")
    headers = re.findall(r"^# JJ DAI v([0-9.]+[^ ]*)\s*—", changelog, re.M)
    assert headers, "R-VER: CHANGELOG has no release headers"
    assert headers[-1] == v, \
        f"R-VER: last CHANGELOG header is v{headers[-1]}, package is v{v}"
    print(f"  [PASS] R-VER    README / pyproject / SECURITY / CHANGELOG "
          f"all say v{v}")


def test_no_outgrown_claims():
    forbidden = [
        r"no rate limit",            # rate limiting shipped in v0.5.4
        r"No rate limits",
        r"round protocol is in-process",  # networked over mTLS since v0.5.5
        r"degraded\s*/\s*secure-enclave", # renamed: macOS Keychain degraded
    ]
    for fname in ("README.md", "SECURITY.md"):
        body = _read(fname)
        for pat in forbidden:
            assert not re.search(pat, body, re.I), \
                f"R-PHRASES: {fname} still contains outgrown claim: {pat!r}"
    print("  [PASS] R-PHRASES README/SECURITY carry no outgrown "
          "capability claims")


def test_acceptance_count_matches_collected():
    spec = importlib.util.spec_from_file_location(
        "genarch", os.path.join(_ROOT, "scripts",
                                "gen_architecture_docs.py"))
    genarch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(genarch)
    counted = genarch.count_acceptance()
    mapdoc = _read("docs", os.path.basename(genarch.MAP))
    # v0.6.7 recut: the badge no longer has to read "N/N green", because it
    # no longer INVENTS that phrase. It is rendered from the recorded run, so
    # a red run publishes a red badge — and demanding the word "green" here
    # would make this check unsatisfiable exactly when it matters, which is
    # also a circular dependency: the badge could never go green while the
    # check that goes red is this one.
    m = re.search(r"Acceptance:\s*(\d+)/(\d+)", mapdoc)
    assert m, "R-ACCEPT: Architecture Map lacks an acceptance badge"
    assert int(m.group(2)) == counted, \
        f"R-ACCEPT: map says {m.group(2)} total, runner collects {counted}"
    sys.path.insert(0, os.path.join(_ROOT, "scripts"))
    from run_acceptance import read_result
    res = read_result()
    assert res is not None, (
        "R-ACCEPT: no recorded acceptance run — a badge without a run behind "
        "it is a claim about nothing")
    assert int(m.group(1)) == res["passed"] and \
        int(m.group(2)) == res["total"], (
        f"R-ACCEPT: badge says {m.group(1)}/{m.group(2)}, the recorded run "
        f"says {res['passed']}/{res['total']}")
    assert ("green" in mapdoc.split("Acceptance:")[1][:120]) == \
        (res["passed"] == res["total"] and not res["import_errors"]), (
        "R-ACCEPT: the badge's wording and the recorded run disagree about "
        "whether the run was green")
    # v0.6.4 audit: the GENERATED badge was correct while a HAND-WRITTEN
    # one in the README still said 68/68 — drift the checker could not see,
    # because it only ever compared generated surfaces.
    # v0.6.5: the badge moved INSIDE the ACCEPT marker block so no build
    # step has a reason to edit hand-owned prose (see
    # tests/unit/test_readme_ownership.py). It is still checked here, from
    # inside the block.
    readme = _read("README.md")
    manual = re.findall(r"(\d+)/(\d+)\s+acceptance checks green", readme)
    assert manual, "R-ACCEPT: README lacks an acceptance badge"
    for a, b in manual:
        assert int(a) == counted and int(b) == counted, \
            (f"R-ACCEPT: README hand-written badge says {a}/{b}, runner "
             f"collects {counted}")
    print(f"  [PASS] R-ACCEPT generated docs and runner agree on "
          f"{counted} tests")


#: sha256 of the canonical AGPL-3.0 text as published at
#: https://www.gnu.org/licenses/agpl-3.0.txt — 34523 bytes, 661 lines,
#: fetched twice and compared before being pinned here.
AGPL_SHA256 = "0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0"


def test_license_is_the_canonical_text():
    """R-LICENSE, rewritten in v0.6.7 from a placeholder guard into a text
    guard.

    The old check asked whether a placeholder was loudly marked. That was
    the right check while the text was missing and the wrong one the moment
    it landed: "contains the title and is over 30000 bytes" is satisfied by
    the canonical text and also by a truncated, edited or wrong-version
    copy of it. `pyproject.toml` declares AGPL-3.0-only, so the file is a
    legal instrument and BYTE-EXACT is the requirement — which means a
    hash, not a heuristic.
    """
    raw = open(os.path.join(_ROOT, "LICENSES", "AGPL-3.0.txt"), "rb").read()
    assert b"PUBLICATION BLOCKER" not in raw, \
        "R-LICENSE: the AGPL placeholder is back"
    got = hashlib.sha256(raw).hexdigest()
    assert got == AGPL_SHA256, (
        f"R-LICENSE: LICENSES/AGPL-3.0.txt is not the canonical AGPL-3.0 "
        f"text byte-for-byte (sha256 {got[:16]}…, expected "
        f"{AGPL_SHA256[:16]}…). A licence that has been reformatted is a "
        f"licence that has been modified.")
    assert raw.startswith(b"                    GNU AFFERO GENERAL PUBLIC "
                          b"LICENSE\n"), "R-LICENSE: unexpected header"
    print(f"  [PASS] R-LICENSE canonical AGPL-3.0 text, byte-exact "
          f"({len(raw)} bytes, sha256 {got[:12]}…)")


if __name__ == "__main__":
    test_versions_agree_everywhere()
    test_no_outgrown_claims()
    test_acceptance_count_matches_collected()
    test_license_is_the_canonical_text()
    print("\nRELEASE INTEGRITY UNIT: all groups green  ✓ certified")
