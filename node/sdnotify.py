"""node/sdnotify.py — sd_notify and the watchdog heartbeat (build v0.6.6).

v0.6.3 REMOVED `WatchdogSec=60` from the systemd unit, and removed it for the
right reason: the daemon did not implement `sd_notify(WATCHDOG=1)`, so systemd
would have killed a perfectly healthy node once per interval. The removal was
recorded as audit item #1 with the note that the heartbeat and the watchdog
return together. This module is that return.

WHY THE HEARTBEAT IS GATED
--------------------------
A heartbeat that fires unconditionally from its own thread is theatre. The
failure a watchdog exists to catch is a process that is ALIVE and STUCK — a
deadlocked accept loop, an organ holding a lock forever, a thread pool with
no free worker. A dedicated timer thread survives all of those and keeps
pinging, so systemd concludes the node is fine precisely when it is not.

So the ping is gated on a BEACON that the serving path itself must refresh:

    serve loop  ──touch()──▶  beacon timestamp
    watchdog    ──read()───▶  age > limit ⇒ DO NOT PING ⇒ systemd restarts

The watchdog therefore reports "the part of me that answers the network is
moving", not "a timer thread is scheduled".

WHAT THE HEARTBEAT IS *NOT* GATED ON
------------------------------------
Readiness. A node whose anchor lag exceeds policy is NOT ready and must stop
receiving work — but killing and restarting it would not fix an anchor
backend and would destroy a node that is holding its chain correctly.
Liveness answers "is this process still moving"; readiness answers "should
work come here". Feeding the second into the watchdog turns every upstream
outage into a restart loop across the whole fleet at once.

PORTABILITY. There is no `sd_notify` on macOS. `available()` is false there,
every call becomes a no-op, and the Mac node's liveness is covered by launchd
plus the sleep-gap detector in node/clockwatch.py. Nothing in this module
requires systemd to be present in order to import.

Stdlib only: an AF_UNIX datagram socket and `os.environ`.
"""
from __future__ import annotations

import os
import socket
import threading
import time

#: systemd sets these; both absent means "not running under a supervisor
#: that wants to hear from us".
ENV_SOCKET = "NOTIFY_SOCKET"
ENV_WATCHDOG_USEC = "WATCHDOG_USEC"
ENV_WATCHDOG_PID = "WATCHDOG_PID"


def available() -> bool:
    """True when a notify socket is present in the environment."""
    return bool(os.environ.get(ENV_SOCKET))


def notify(state: str) -> bool:
    """Send one datagram to the notify socket. Never raises.

    A failure to notify must not take down a node: the supervisor's opinion
    of us is not a precondition for holding the witness chain correctly. The
    boolean is returned for tests and metrics, not for control flow.
    """
    addr = os.environ.get(ENV_SOCKET)
    if not addr:
        return False
    # Abstract namespace sockets are spelled with a leading '@' in the
    # environment and a leading NUL on the wire.
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(state.encode("utf-8"))
        return True
    except OSError:
        return False


def watchdog_interval_s() -> float:
    """Half of WATCHDOG_USEC, per the systemd contract. 0 = no watchdog.

    systemd's own guidance is to ping at half the configured interval so one
    lost datagram or one scheduling hiccup does not kill the service.
    """
    raw = os.environ.get(ENV_WATCHDOG_USEC)
    if not raw:
        return 0.0
    try:
        usec = int(raw)
    except ValueError:
        return 0.0
    if usec <= 0:
        return 0.0
    # WATCHDOG_PID, when set, names the process the watchdog belongs to.
    pid = os.environ.get(ENV_WATCHDOG_PID)
    if pid and pid.strip().isdigit() and int(pid) != os.getpid():
        return 0.0
    return (usec / 1_000_000.0) / 2.0


class Beacon:
    """A monotonic timestamp the serving path refreshes.

    Deliberately trivial and lock-free on the read side: the watchdog must
    never be able to block on the thing it is measuring, or a lock held by a
    stuck request would silence the watchdog by hanging it too — which is the
    exact failure it is supposed to report.
    """

    def __init__(self):
        self._t = time.monotonic()

    def touch(self) -> None:
        self._t = time.monotonic()

    def age(self) -> float:
        return time.monotonic() - self._t


class Watchdog(threading.Thread):
    """Pings systemd while the beacon is fresh; goes silent when it is not.

    `stale_after` defaults to three missed intervals: a node under heavy
    inference can legitimately be slow to come back round the accept loop,
    and a watchdog that restarts a busy node is a load amplifier.
    """

    def __init__(self, beacon: "Beacon", interval_s: float,
                 stale_after: float = None, on_ping=None, on_silence=None):
        super().__init__(name="jjdai-watchdog", daemon=True)
        self.beacon = beacon
        self.interval_s = float(interval_s)
        self.stale_after = float(stale_after if stale_after is not None
                                 else interval_s * 3)
        self.on_ping = on_ping
        self.on_silence = on_silence
        self.pings = 0
        self.silences = 0
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def tick(self) -> bool:
        """One decision. Split out so the policy is testable without sleeping."""
        if self.beacon.age() > self.stale_after:
            self.silences += 1
            if self.on_silence:
                self.on_silence(self.beacon.age())
            return False
        notify("WATCHDOG=1")
        self.pings += 1
        if self.on_ping:
            self.on_ping()
        return True

    def run(self) -> None:
        while not self._stop.wait(self.interval_s):
            try:
                self.tick()
            except Exception:                       # never die quietly
                self.silences += 1


def ready(status: str = "") -> bool:
    """READY=1 for `Type=notify`. Sent once the listener is actually bound.

    Ordering matters: under `Type=notify` systemd holds dependent units until
    this datagram arrives, so sending it before the socket is listening would
    hand the ordering guarantee away for nothing.
    """
    msg = "READY=1"
    if status:
        msg += f"\nSTATUS={status}"
    return notify(msg)


def status(text: str) -> bool:
    """STATUS= line shown by `systemctl status`. Readiness lives here."""
    return notify(f"STATUS={text}")


def stopping(text: str = "shutting down") -> bool:
    return notify(f"STOPPING=1\nSTATUS={text}")
