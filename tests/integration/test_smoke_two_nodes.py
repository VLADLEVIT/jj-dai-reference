#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Two-node live smoke (R-C1..R-C3) — thin pytest wrapper over the canonical
node/smoke_two_nodes.py suite (which stays a library + CLI: its get/post/
wait_up/jii helpers are shared by other live suites)."""
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def test_smoke_two_nodes():
    import smoke_two_nodes
    try:
        smoke_two_nodes.main()
    except SystemExit as e:
        assert not e.code, f"smoke suite reported failures (exit {e.code})"


if __name__ == "__main__":
    test_smoke_two_nodes()
