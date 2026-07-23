# -*- coding: utf-8 -*-
"""
jjdai.durable — crash-safe journal primitives (v0.3.1.3 #4).

Lives in the primitive layer because BOTH the witness chain and every
governance journal need it, and jjdai/ must never depend on core/.

  durable_append — append + flush + fsync(file) + fsync(dir on create).
                   Without fsync the bytes sit in the page cache and a power
                   loss silently eats the last governance events.
  read_journal   — crash-tolerant read. A torn TRAILING line is the write that
                   did not finish: report and drop it. A torn line ANYWHERE
                   ELSE is corruption/tampering, not a crash: raise.
  truncate_torn_tail — durably rewrite without the torn tail (atomic replace).
"""
from __future__ import annotations

import json
import os


class DurabilityError(RuntimeError):
    pass


class JournalCorruption(DurabilityError):
    """A journal line is malformed somewhere other than the tail."""


def durable_append(path: str, obj: dict) -> None:
    """Append one JSON line and make it SURVIVE power loss.

    fsync(file) forces the bytes to the device. fsync(dir) is needed too the
    first time: without it the file's directory entry may not survive, so a
    perfectly fsynced file can still vanish."""
    line = json.dumps(obj, sort_keys=True, ensure_ascii=False) + "\n"
    d = os.path.dirname(os.path.abspath(path)) or "."
    is_new = not os.path.exists(path)
    os.makedirs(d, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())
    if is_new:
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def read_journal(path: str, *, repair_tail: bool = True) -> tuple:
    """Read a JSONL journal. Returns (events, report).

    report = {"torn_tail": bool, "dropped": int, "lines": int}
    A torn TRAILING line means the process died mid-append: that event never
    completed, so dropping it is correct and the state is consistent. A torn
    line in the MIDDLE cannot be explained by a crash -> raise."""
    if not os.path.exists(path):
        return [], {"torn_tail": False, "dropped": 0, "lines": 0}
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    lines = [l for l in raw.split("\n") if l.strip()]
    events, torn, dropped = [], False, 0
    for i, line in enumerate(lines):
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            is_tail = (i == len(lines) - 1) and not raw.endswith("\n")
            if is_tail and repair_tail:
                torn, dropped = True, 1
                break
            raise JournalCorruption(
                f"{path}: malformed line {i} of {len(lines)} — not a torn tail "
                "(corruption or tampering)")
    return events, {"torn_tail": torn, "dropped": dropped, "lines": len(lines)}


def truncate_torn_tail(path: str) -> bool:
    """Rewrite the journal without its torn tail, durably. Call once at boot
    after read_journal reports torn_tail, so the next append starts clean."""
    events, report = read_journal(path)
    if not report["torn_tail"]:
        return False
    tmp = path + ".repair"
    with open(tmp, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)                     # atomic
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


