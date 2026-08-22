#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sd_notify and the watchdog (v0.6.6) — closing audit item #1 of v0.6.3
=====================================================================
v0.6.3 removed `WatchdogSec=60` because the daemon could not answer it. The
requirement being checked here is not "a heartbeat exists" but "the heartbeat
reports the serving path", which is the only version of the feature worth
having: a timer thread that pings unconditionally survives every failure a
watchdog exists to catch.

  S-1  datagrams actually reach a NOTIFY_SOCKET, including READY=1
  S-2  no socket in the environment ⇒ no-op, never an exception
  S-3  WATCHDOG_USEC is halved, per the systemd contract; absent/garbage
       values disable the watchdog rather than defaulting to something
  S-4  WATCHDOG_PID naming another process disables it
  S-5  THE ONE THAT MATTERS: a stale beacon withholds the ping, and a fresh
       one sends it — i.e. a wedged accept loop is reported by SILENCE
  S-6  a busy-but-moving node is not restarted: staleness tolerance is
       wider than one interval
"""
from __future__ import annotations

import os
import socket
import sys
import tempfile
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import sdnotify                                              # noqa: E402


class _Env:
    """Set/restore environment without leaking into other checks."""

    def __init__(self, **kw):
        self.kw = kw
        self.old = {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *a):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_sdnotify_watchdog():
    passed = 0
    tmp = tempfile.mkdtemp(prefix="jjdai-sdnotify-")
    path = os.path.join(tmp, "notify.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(path)
    srv.settimeout(2.0)

    try:
        # S-1
        with _Env(NOTIFY_SOCKET=path):
            assert sdnotify.available() is True
            assert sdnotify.notify("WATCHDOG=1") is True
            assert srv.recv(256) == b"WATCHDOG=1"
            assert sdnotify.ready("listening on 0.0.0.0:8443") is True
            got = srv.recv(256).decode()
            assert got.startswith("READY=1"), got
            assert "STATUS=listening" in got, got
        print("  [PASS] S-1 READY=1 and WATCHDOG=1 reach the notify socket")
        passed += 1

        # S-2
        with _Env(NOTIFY_SOCKET=None):
            assert sdnotify.available() is False
            assert sdnotify.notify("WATCHDOG=1") is False
            assert sdnotify.ready() is False
        print("  [PASS] S-2 absent socket is a no-op, never an exception")
        passed += 1

        # S-3
        with _Env(WATCHDOG_USEC="60000000", WATCHDOG_PID=None):
            assert sdnotify.watchdog_interval_s() == 30.0
        for bad in (None, "", "not-a-number", "0", "-5"):
            with _Env(WATCHDOG_USEC=bad, WATCHDOG_PID=None):
                assert sdnotify.watchdog_interval_s() == 0.0, bad
        print("  [PASS] S-3 interval is half of WATCHDOG_USEC; junk disables")
        passed += 1

        # S-4
        with _Env(WATCHDOG_USEC="60000000",
                  WATCHDOG_PID=str(os.getpid() + 1)):
            assert sdnotify.watchdog_interval_s() == 0.0
        with _Env(WATCHDOG_USEC="60000000", WATCHDOG_PID=str(os.getpid())):
            assert sdnotify.watchdog_interval_s() == 30.0
        print("  [PASS] S-4 a watchdog addressed to another PID is not ours")
        passed += 1

        # S-5 — the requirement itself
        with _Env(NOTIFY_SOCKET=path):
            beacon = sdnotify.Beacon()
            wd = sdnotify.Watchdog(beacon, interval_s=0.01, stale_after=0.05)
            assert wd.tick() is True, "fresh beacon must ping"
            assert srv.recv(256) == b"WATCHDOG=1"
            assert wd.pings == 1 and wd.silences == 0
            time.sleep(0.08)                       # let the beacon go stale
            assert wd.tick() is False, "stale beacon must NOT ping"
            assert wd.silences == 1, wd.silences
            srv.settimeout(0.2)
            try:
                stray = srv.recv(256)
                raise AssertionError(
                    f"watchdog spoke while wedged: {stray!r}")
            except socket.timeout:
                pass
            srv.settimeout(2.0)
            beacon.touch()                         # accept loop moves again
            assert wd.tick() is True
            assert srv.recv(256) == b"WATCHDOG=1"
        print("  [PASS] S-5 a wedged accept loop is reported by SILENCE, "
              "and recovery resumes the ping")
        passed += 1

        # S-6
        beacon = sdnotify.Beacon()
        wd = sdnotify.Watchdog(beacon, interval_s=1.0)
        assert wd.stale_after >= wd.interval_s * 2, (
            "a busy node must survive more than one missed interval")
        print("  [PASS] S-6 staleness tolerance is wider than one interval")
        passed += 1

    finally:
        srv.close()
        try:
            os.unlink(path)
            os.rmdir(tmp)
        except OSError:
            pass

    print(f"\nsummary: {passed} passed, 0 failed")


if __name__ == "__main__":
    test_sdnotify_watchdog()
