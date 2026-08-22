#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The wheel must contain the adapter layer (v0.6.6 recut)
=======================================================
Audit response. `pyproject.toml` listed three packages by hand, so every
wheel built after v0.6.5 silently dropped `jjdai.adapters` — the whole
EngineBackend layer — along with its backends, formats and model profiles.
Invisible when running from a checkout; fatal for anyone who installs the
library. A hand-written package list is a list that goes stale the next time
a package is added, so the fix is checked rather than trusted.

  WHEEL-PKG-1  every runtime package is declared
  WHEEL-PKG-2  model profiles are declared as package data — a wheel with
               the registry and without the profiles refuses every model it
               advertises
  WHEEL-PKG-3  the declared packages actually exist in the tree, and every
               importable package in the tree is declared (no silent gaps)
"""
from __future__ import annotations

import io
import os
import re
import sys

try:                                    # Python >= 3.11
    import tomllib
except ModuleNotFoundError:             # pragma: no cover - 3.10 only
    tomllib = None

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

REQUIRED = ("jjdai", "jjdai.adapters", "jjdai.adapters.backends",
            "jjdai.adapters.formats", "core", "kernel")


def _array(text: str, table: str, key: str) -> list:
    """Read one string array out of one TOML table, stdlib-only.

    `tomllib` arrived in 3.11 and this project supports 3.10, which the CI
    matrix actually runs — so importing it unguarded took the whole check out
    of the 3.10 job with an import error rather than a verdict. Skipping there
    would be worse: a check that does not run on the oldest supported version
    is not evidence about it, and this one guards a wheel that any of those
    users would install. The two values it needs are literal arrays, so they
    are read directly.
    """
    m = re.search(r"^\[" + re.escape(table) + r"\]$(.*?)(?=^\[|\Z)",
                  text, re.M | re.S)
    if not m:
        return []
    body = re.sub(r"#.*", "", m.group(1))
    m2 = re.search(re.escape(key) + r"\s*=\s*\[(.*?)\]", body, re.S)
    return re.findall(r'"([^"]+)"', m2.group(1)) if m2 else []


def _load_cfg():
    path = os.path.join(_ROOT, "pyproject.toml")
    if tomllib is not None:
        with open(path, "rb") as fh:
            cfg = tomllib.load(fh)
        st = cfg["tool"]["setuptools"]
        return list(st["packages"]), st.get("package-data", {})
    text = io.open(path, encoding="utf-8").read()
    return (_array(text, "tool.setuptools", "packages"),
            {"jjdai.adapters": _array(text, "tool.setuptools.package-data",
                                      '"jjdai.adapters"')})


def test_wheel_pkg_recut():
    passed = 0
    declared, pkg_data = _load_cfg()

    # WHEEL-PKG-1
    missing = [p for p in REQUIRED if p not in declared]
    assert not missing, f"wheel would not contain: {missing}"
    print(f"  [PASS] WHEEL-PKG-1 {len(declared)} packages declared, "
          f"adapter layer included")
    passed += 1

    # WHEEL-PKG-2
    pats = pkg_data.get("jjdai.adapters", [])
    assert any("models/" in p for p in pats), (
        "model profiles are not package data; a wheel with the registry and "
        "without the profiles refuses every model it advertises")
    prof_dir = os.path.join(_ROOT, "jjdai", "adapters", "models")
    profiles = [f for f in os.listdir(prof_dir) if f.endswith(".json")]
    assert profiles, "no model profiles in the tree to ship"
    print(f"  [PASS] WHEEL-PKG-2 model profiles shipped as data "
          f"({', '.join(sorted(profiles))})")
    passed += 1

    # WHEEL-PKG-3 — both directions
    for pkg in declared:
        path = os.path.join(_ROOT, *pkg.split("."))
        assert os.path.isdir(path), f"declared package {pkg} does not exist"
        assert os.path.exists(os.path.join(path, "__init__.py")), (
            f"{pkg} has no __init__.py and will not be packaged")
    found = set()
    # `node/` is a script directory, not a package (no __init__.py, bare
    # sibling imports). Excluded knowingly, not overlooked.
    for top in ("jjdai", "core", "kernel", "runtime"):
        base = os.path.join(_ROOT, top)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            if "__init__.py" in filenames:
                rel = os.path.relpath(dirpath, _ROOT).replace(os.sep, ".")
                found.add(rel)
    undeclared = sorted(found - set(declared))
    assert not undeclared, (
        f"importable packages in the tree that no wheel would carry: "
        f"{undeclared}")
    print(f"  [PASS] WHEEL-PKG-3 declaration and tree agree in both "
          f"directions ({len(found)} packages)")
    passed += 1

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_wheel_pkg_recut()
