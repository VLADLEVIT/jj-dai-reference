#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Docs integrity acceptance: the three surfaces (README table, markdown
map, HTML page) never drift from docs/architecture_status.json, every
referenced path exists, and the fossils of past drifts stay dead."""
import os
import subprocess
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def test_docs_integrity():
    r = subprocess.run(
        [sys.executable, os.path.join(_ROOT, "scripts",
                                      "check_docs_drift.py")],
        capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, "docs drift:\n" + r.stdout
    print("  [PASS] DOC-1  README/map/HTML match architecture_status.json; "
          "all paths exist; no stale phrases")


if __name__ == "__main__":
    test_docs_integrity()
