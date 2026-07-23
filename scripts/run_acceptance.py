#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/run_acceptance.py — stdlib acceptance runner (v0.4.1)
=============================================================
Follows the pytest protocol: IMPORT each tests/**/test_*.py (imports must be
side-effect-free), COLLECT test_* functions, RUN them, report. Use this where
pytest is unavailable; under CI, `python -m pytest tests/` is the canonical
entrypoint and collects the exact same functions.

    python3 scripts/run_acceptance.py                  # everything
    python3 scripts/run_acceptance.py unit adversarial # chosen groups
"""
from __future__ import annotations

import importlib.util
import os
import sys
import time
import traceback

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GROUPS = ("unit", "integration", "conformance", "adversarial", "legacy")

for _p in (ROOT, os.path.join(ROOT, "node"), os.path.join(ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def collect(groups):
    for group in groups:
        gdir = os.path.join(ROOT, "tests", group)
        if not os.path.isdir(gdir):
            continue
        for fname in sorted(os.listdir(gdir)):
            if fname.startswith("test_") and fname.endswith(".py"):
                yield group, os.path.join(gdir, fname)


def load(path, group):
    modname = f"tests.{group}.{os.path.splitext(os.path.basename(path))[0]}"
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)          # must be side-effect-free
    return mod


def main(argv):
    groups = [g for g in argv if g in GROUPS] or list(GROUPS)
    total = failed = errors = 0
    t0 = time.time()
    for group, path in collect(groups):
        rel = os.path.relpath(path, ROOT)
        try:
            mod = load(path, group)
        except Exception:
            print(f"\nIMPORT ERROR  {rel}")
            traceback.print_exc()
            errors += 1
            continue
        fns = [(k, v) for k, v in sorted(vars(mod).items())
               if k.startswith("test_") and callable(v)]
        for name, fn in fns:
            total += 1
            try:
                fn()
                print(f"  PASS  {rel}::{name}")
            except AssertionError as e:
                failed += 1
                print(f"  FAIL  {rel}::{name}  {e}")
            except Exception:
                failed += 1
                print(f"  ERROR {rel}::{name}")
                traceback.print_exc()
    dt = time.time() - t0
    print(f"\nacceptance: {total - failed}/{total} passed, "
          f"{errors} import error(s), {dt:.1f}s")
    return 1 if (failed or errors) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
