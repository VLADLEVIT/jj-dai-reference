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
  R-LICENSE the AGPL placeholder is loudly marked as a publication
            blocker until the canonical text lands (reported, not
            silently tolerated)
"""
from __future__ import annotations

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
    mapdoc = _read("docs", "JJDAI_Code_Architecture_Map_v0.5.md")
    m = re.search(r"Acceptance:\s*(\d+)/(\d+)\s+green", mapdoc)
    assert m, "R-ACCEPT: Architecture Map lacks an acceptance badge"
    assert int(m.group(1)) == counted, \
        f"R-ACCEPT: map says {m.group(1)}, runner collects {counted}"
    # v0.6.4 audit: the GENERATED badge was correct while a HAND-WRITTEN
    # one in the README still said 68/68. A drift the drift-checker could
    # not see, because it only ever compared generated surfaces.
    readme = _read("README.md")
    manual = re.findall(r"(\d+)/(\d+)\s+acceptance checks green", readme)
    assert manual, "R-ACCEPT: README lacks a hand-written acceptance badge"
    for a, b in manual:
        assert int(a) == counted and int(b) == counted, \
            (f"R-ACCEPT: README hand-written badge says {a}/{b}, runner "
             f"collects {counted}")
    print(f"  [PASS] R-ACCEPT generated docs and runner agree on "
          f"{counted} tests")


def test_license_placeholder_is_loud():
    lic = _read("LICENSES", "AGPL-3.0.txt")
    canonical = "GNU AFFERO GENERAL PUBLIC LICENSE" in lic and len(lic) > 30000
    if canonical:
        print("  [PASS] R-LICENSE canonical AGPL-3.0 text present")
        return
    assert "PUBLICATION BLOCKER" in lic, \
        "R-LICENSE: AGPL placeholder exists but is not marked as a " \
        "publication blocker — it could be shipped silently"
    print("  [PASS] R-LICENSE placeholder is loudly marked as a "
          "publication blocker (canonical text still REQUIRED before "
          "any distribution — open audit item #4)")


if __name__ == "__main__":
    test_versions_agree_everywhere()
    test_no_outgrown_claims()
    test_acceptance_count_matches_collected()
    test_license_placeholder_is_loud()
    print("\nRELEASE INTEGRITY UNIT: all groups green  ✓ certified")
