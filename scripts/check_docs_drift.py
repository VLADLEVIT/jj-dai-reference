#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/check_docs_drift.py — CI gate against documentation drift
=================================================================
The v0.5.2 audit found four concrete contradictions between README, the
architecture map and the code. This gate makes that class of bug a CI
failure:

  1. every `path` referenced in architecture_status.json EXISTS
     (multi-paths split on '·', member refs split on '::');
  2. README table and the markdown map match a fresh regeneration
     byte-for-byte (edit the JSON, not the surfaces);
  3. forbidden stale phrases are absent from README and the map
     (each phrase is a fossil of a specific past drift);
  4. CONTRIBUTING.md references only existing doc files.

Exit 0 = clean; exit 1 = drift, with every finding named.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from gen_architecture_docs import generate, load, README, MAP   # noqa: E402

FORBIDDEN = {
    "unimplemented seam":
        "OTS anchoring shipped in v0.5.1 (the v0.5.2 audit fossil)",
    "no TLS/mTLS":
        "TLS/mTLS shipped in v0.5.1",
    "no transport security":
        "TLS/mTLS shipped in v0.5.1",
    "not yet wired into the live router":
        "diversity wired in v0.5.1",
}


def main() -> int:
    findings = []
    st = load()

    # 1. paths exist
    for sec in st["sections"]:
        for c in sec.get("cards", []):
            for p in (c.get("path") or "").split("·"):
                p = p.strip().split("::")[0]
                if p and not os.path.exists(os.path.join(ROOT, p)):
                    findings.append(f"missing path: {p!r} "
                                    f"(card {c['name']!r})")

    # 2. surfaces match regeneration
    fresh = generate(write=False)
    if io.open(README, encoding="utf-8").read() != fresh["readme"]:
        findings.append("README status table drifted from "
                        "architecture_status.json — run "
                        "scripts/gen_architecture_docs.py")
    if io.open(MAP, encoding="utf-8").read() != fresh["map"]:
        findings.append("architecture map drifted — run the generator")
    if not os.path.exists(fresh["html_path"]):
        findings.append(f"HTML surface missing: {fresh['html_path']}")
    elif io.open(fresh["html_path"], encoding="utf-8").read() != fresh["html"]:
        findings.append("HTML architecture page drifted — run the generator")

    # 3. fossils
    for surface in (README, MAP):
        text = io.open(surface, encoding="utf-8").read()
        for phrase, why in FORBIDDEN.items():
            if phrase in text:
                findings.append(f"stale phrase {phrase!r} in "
                                f"{os.path.basename(surface)} — {why}")

    # 4. CONTRIBUTING references
    contrib = os.path.join(ROOT, "CONTRIBUTING.md")
    if os.path.exists(contrib):
        text = io.open(contrib, encoding="utf-8").read()
        for ref in re.findall(r"docs/[\w./-]+\.md", text):
            if not os.path.exists(os.path.join(ROOT, ref)):
                findings.append(f"CONTRIBUTING references missing {ref!r}")

    if findings:
        print("DOCS DRIFT — the surfaces disagree with the source of truth:")
        for f in findings:
            print("  ✗", f)
        return 1
    print(f"docs integrity: clean "
          f"(acceptance count in surfaces: {fresh['acceptance']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
