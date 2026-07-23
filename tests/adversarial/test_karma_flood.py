#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_karma_flood — v0.4.1 P0-3 / P0-4 adversarial acceptance
============================================================
  F-1  FLOOD KILL: a child emitting far beyond the flood budget is killed
       (process group), verdict OUTPUT_LIMIT_EXCEEDED, ok=False, and the
       parent retains only max_output bytes (bounded memory).
  F-2  LEGITIMATE OVERFLOW: output modestly above the cap but under the
       budget is truncated, NOT killed (A-9 semantics preserved).
  F-3  DETERMINISTIC ENV: the child sees the hardening variables
       (PYTHONNOUSERSITE, single-thread BLAS/OMP) and nothing inherited.
"""
from __future__ import annotations

import os
import sys

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location

import tempfile


from kernel.karma import Sandbox                                 # noqa: E402


def test_flood_kill():
    with tempfile.TemporaryDirectory() as ws:
        sb = Sandbox(ws, max_output=1000, timeout_s=30.0,
                     fsize_bytes=512 * 1024 * 1024)
        # ~64 MiB of stdout: far beyond the 1 MiB flood budget
        r = sb.run([sys.executable, "-c",
                    "import sys\n"
                    "b = b'x' * 65536\n"
                    "for _ in range(1024): sys.stdout.buffer.write(b)"])
        assert not r.ok, "flooding child must not be reported ok"
        assert r.truncated, "flood must be marked truncated"
        assert r.detail.get("verdict") == "OUTPUT_LIMIT_EXCEEDED", \
            f"expected OUTPUT_LIMIT_EXCEEDED, got {r.detail}"
        assert len(r.stdout) <= 1000, \
            f"parent must retain <= max_output bytes, kept {len(r.stdout)}"
        assert not r.timed_out, "flood kill must fire before the wall clock"


def test_legitimate_overflow_truncates_not_kills():
    with tempfile.TemporaryDirectory() as ws:
        sb = Sandbox(ws, max_output=1000)
        r = sb.run([sys.executable, "-c", "print('x' * 100000)"])
        assert r.ok and r.exit_code == 0, "modest overflow must complete"
        assert r.truncated and len(r.stdout) == 1000
        assert "verdict" not in (r.detail or {}), "no flood verdict expected"


def test_deterministic_child_env():
    os.environ["JJDAI_PARENT_LEAK"] = "must-not-appear"
    with tempfile.TemporaryDirectory() as ws:
        sb = Sandbox(ws)
        r = sb.run([sys.executable, "-c",
                    "import os\n"
                    "print(os.environ.get('JJDAI_PARENT_LEAK', 'ABSENT'))\n"
                    "print(os.environ.get('PYTHONNOUSERSITE', 'MISSING'))\n"
                    "print(os.environ.get('OPENBLAS_NUM_THREADS', 'MISSING'))\n"
                    "print(os.environ.get('OMP_NUM_THREADS', 'MISSING'))"])
        lines = r.stdout.split()
        assert lines == ["ABSENT", "1", "1", "1"], \
            f"env hardening mismatch: {lines}"


if __name__ == "__main__":
    tests = [test_flood_kill, test_legitimate_overflow_truncates_not_kills,
             test_deterministic_child_env]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\nkarma flood/env hardening — {len(tests)}/{len(tests)} checks green")
