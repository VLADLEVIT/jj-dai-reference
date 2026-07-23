# -*- coding: utf-8 -*-
"""
kernel.karma — Karma (कर्म), the ACTION organ. Third organ of the Agent Kernel,
and the first one that touches the world.

WHAT IT IS: the Being's hand. Shell, files, git, tests — the OpenHands pattern
(sandbox as a boundary, action as a typed primitive, every step an event) —
wrapped in the JJ DAI invariants that OpenHands has no reason to carry:

  1. WITNESS-FIRST, IN TWO PHASES. This is the decision that shapes the whole
     module. A record written AFTER the act is a report; a record written
     BEFORE it is a commitment. So every executive action writes an INTENT
     record (what I am about to do) BEFORE the hand moves, and an OUTCOME
     record (what happened) after. An action can therefore never occur
     unwitnessed. If the process dies between the two, the chain shows an
     intent with no outcome — a visible, auditable "we do not know if this
     happened", which is the honest state. Reporting-after would have shown
     nothing at all.

  2. GOVERNOR-GATED. Before any executive action, Karma asks the Article-25
     governor: permits(being, "tools.side_effect")? A contained Being's hand
     does not move — and NOT ONE BYTE of side effect occurs, because the gate
     is checked before the intent is even written. Non-executive actions
     (reading its own workspace) stay open while contained: stop the hand, not
     the mind, applies INSIDE Karma too.

  3. PROVENANCE ON EVERY ACT. Each record carries organ, being, workspace,
     the exact argv, cwd, exit code, duration, and digests of stdout/stderr.
     The Witness hides the content (commitment) and binds it in the clear
     digest: karma:<being>:<phase>:<action_hash>:<state_hash>.

SANDBOX — WHAT IT REALLY IS (no overclaiming):
  * PATH CONFINEMENT: every filesystem path is resolved (symlinks included)
    and must land inside the workspace root, or the action is refused. This
    stops ../ escapes and symlink escapes.
  * PROCESS LIMITS: RLIMIT_CPU, RLIMIT_AS (address space), RLIMIT_FSIZE,
    RLIMIT_NPROC applied in the child before exec; plus a wall-clock timeout
    that kills the whole process group, and an output cap.
  * ENVIRONMENT SCRUB: the child gets a minimal env; the parent's secrets do
    not leak into the Being's hand.
  * NETWORK: not granted by Karma. Egress is a separate governor scope
    ("network.egress"); an action that declares network need is refused unless
    that scope permits. Karma does NOT claim to enforce kernel-level network
    isolation — that belongs to the host/hosting layer (Art. 18). This module
    is honest about the boundary it does and does not draw.
  * This is PROCESS-level confinement, not a VM. A sovereign operator on their
    own metal can always bypass it (the USB-through-a-human limit we named
    when designing containment). Karma shrinks the blast radius and makes
    every act evidentiary; it does not claim omnipotence.
"""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import H_hex                              # noqa: E402
from jjdai.durable import durable_append, read_journal, truncate_torn_tail  # noqa: E402

EXECUTIVE_SCOPE = "tools.side_effect"
EGRESS_SCOPE = "network.egress"

# Non-executive: reading its own workspace changes nothing outside the Being.
READ_ACTIONS = frozenset({"fs_read", "fs_list"})
# Executive: mutates the filesystem or spawns a process.
EXEC_ACTIONS = frozenset({"shell", "fs_write", "fs_delete", "git", "test"})


class KarmaError(RuntimeError):
    pass


class SandboxEscape(KarmaError):
    """A path resolved outside the workspace root. Refused."""


class ActionRefused(KarmaError):
    """The governor did not permit this action (Article 25)."""


class KarmaAudit(KarmaError):
    pass


@dataclass
class ActionResult:
    action: str
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    truncated: bool = False
    timed_out: bool = False
    detail: dict = None

    def as_dict(self) -> dict:
        return {"action": self.action, "ok": self.ok, "exit_code": self.exit_code,
                "stdout": self.stdout, "stderr": self.stderr,
                "duration_s": round(self.duration_s, 4),
                "truncated": self.truncated, "timed_out": self.timed_out,
                "detail": self.detail or {}}


class Sandbox:
    """Path-confined, resource-limited execution surface."""

    def __init__(self, root: str, *, timeout_s: float = 10.0,
                 max_output: int = 64_000, cpu_s: int = 10,
                 mem_bytes: int = 512 * 1024 * 1024,
                 fsize_bytes: int = 64 * 1024 * 1024, nproc: int = 64):
        self.root = os.path.realpath(root)
        os.makedirs(self.root, exist_ok=True)
        self.timeout_s = timeout_s
        self.max_output = max_output
        self.cpu_s = cpu_s
        self.mem_bytes = mem_bytes
        self.fsize_bytes = fsize_bytes
        self.nproc = nproc

    # ---- path confinement ---- #
    def resolve(self, rel_path: str) -> str:
        """Resolve a path INSIDE the workspace or refuse. realpath follows
        symlinks, so a symlink pointing out is caught too."""
        if os.path.isabs(rel_path):
            candidate = os.path.realpath(rel_path)
        else:
            candidate = os.path.realpath(os.path.join(self.root, rel_path))
        root = self.root + os.sep
        if candidate != self.root and not candidate.startswith(root):
            raise SandboxEscape(
                f"path {rel_path!r} resolves to {candidate!r}, outside the "
                f"workspace {self.root!r} — refused")
        return candidate

    # ---- process limits ---- #
    def _limits(self):
        import resource

        def apply():
            os.setsid()                                    # own process group
            resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_s, self.cpu_s))
            resource.setrlimit(resource.RLIMIT_AS, (self.mem_bytes, self.mem_bytes))
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (self.fsize_bytes, self.fsize_bytes))
            try:
                resource.setrlimit(resource.RLIMIT_NPROC, (self.nproc, self.nproc))
            except (ValueError, OSError):
                pass                                       # not fatal
        return apply

    # v0.4.1 P0-3: the parent never buffers more than max_output bytes per
    # stream. Beyond that, bytes are counted and discarded; beyond the flood
    # budget the whole process GROUP is killed and the verdict is
    # OUTPUT_LIMIT_EXCEEDED. (The old communicate()+slice pattern capped the
    # RESULT but not the parent's memory — a hostile child could OOM the
    # governor by flooding stdout.)
    FLOOD_BUDGET_FLOOR = 1 * 1024 * 1024      # 1 MiB
    FLOOD_BUDGET_FACTOR = 8                   # x max_output

    def _child_env(self, workdir: str) -> dict:
        """Scrubbed AND deterministic child environment (v0.4.1 P0-4).
        Nothing is inherited from the parent; host-Python side doors
        (sitecustomize, user site-packages) and implicit thread pools
        (OpenBLAS/OMP/MKL) are disabled so the workload behaves the same
        under RLIMIT_NPROC/RLIMIT_AS on any host."""
        return {
            "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": self.root,
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
            "PWD": workdir, "TMPDIR": self.root,
            "JJDAI_SANDBOX": "1",
            # Python determinism / no host side-doors
            "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
            "PYTHONIOENCODING": "utf-8",
            # single-threaded numeric libraries (compatible with NPROC/AS caps)
            "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1", "NUMEXPR_NUM_THREADS": "1",
            "VECLIB_MAXIMUM_THREADS": "1",
        }

    def run(self, argv: list, *, cwd: str = None) -> ActionResult:
        """Execute argv inside the sandbox with limits + timeout + a TRUE
        streaming output cap (bounded parent memory, flood kill)."""
        import selectors

        workdir = self.resolve(cwd) if cwd else self.root
        env = self._child_env(workdir)
        flood_budget = max(self.FLOOD_BUDGET_FLOOR,
                           self.FLOOD_BUDGET_FACTOR * self.max_output)
        t0 = time.time()
        timed_out = False
        overflowed = False
        try:
            proc = subprocess.Popen(
                argv, cwd=workdir, env=env, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, preexec_fn=self._limits(), text=False)
        except (FileNotFoundError, PermissionError) as e:
            return ActionResult("shell", False, 127, "", str(e),
                                time.time() - t0)

        bufs = {"out": bytearray(), "err": bytearray()}
        totals = {"out": 0, "err": 0}
        sel = selectors.DefaultSelector()
        for stream, tag in ((proc.stdout, "out"), (proc.stderr, "err")):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, tag)
        deadline = t0 + self.timeout_s
        open_streams = 2
        while open_streams > 0:
            remaining = deadline - time.time()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in sel.select(timeout=min(remaining, 0.25)):
                tag = key.data
                try:
                    chunk = key.fileobj.read(65536)
                except OSError:
                    chunk = b""
                if not chunk:                       # EOF on this stream
                    sel.unregister(key.fileobj)
                    open_streams -= 1
                    continue
                totals[tag] += len(chunk)
                room = self.max_output - len(bufs[tag])
                if room > 0:
                    bufs[tag] += chunk[:room]       # keep the head only
                if totals[tag] > flood_budget:
                    overflowed = True
            if overflowed:
                break
        sel.close()

        if timed_out or overflowed:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            code = -9
        else:
            code = proc.wait()
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass

        out = bytes(bufs["out"]).decode("utf-8", errors="replace")
        err = bytes(bufs["err"]).decode("utf-8", errors="replace")
        truncated = (totals["out"] > len(bufs["out"])
                     or totals["err"] > len(bufs["err"]))
        detail = {"bytes_emitted": dict(totals)}
        if overflowed:
            detail["verdict"] = "OUTPUT_LIMIT_EXCEEDED"
            detail["flood_budget"] = flood_budget
        return ActionResult("shell",
                            code == 0 and not timed_out and not overflowed,
                            code, out, err, time.time() - t0,
                            truncated=truncated or overflowed,
                            timed_out=timed_out, detail=detail)


class Karma:
    """The action organ: witnessed, governor-gated, sandboxed."""

    def __init__(self, being_id: str, workspace: str, *, witness=None,
                 governor=None, journal_path: str = None, now_fn=time.time,
                 sandbox: Sandbox = None):
        self.being_id = being_id
        self.sandbox = sandbox or Sandbox(workspace)
        self._witness = witness
        self._governor = governor
        self._journal_path = journal_path
        self._now = now_fn
        self._events: list = []
        if journal_path and os.path.exists(journal_path):
            events, report = read_journal(journal_path)
            if report.get("torn_tail"):
                truncate_torn_tail(journal_path)
            for e in events:
                self._apply(e)

    # ------------------------------------------------------------------ #
    # The gate — asked BEFORE the intent is even written
    # ------------------------------------------------------------------ #
    def _gate(self, action: str, *, needs_network: bool = False):
        if self._governor is None:
            return
        if action in EXEC_ACTIONS and \
                not self._governor.permits(self.being_id, EXECUTIVE_SCOPE):
            raise ActionRefused(
                f"423 CONTAINED: executive action {action!r} refused for "
                f"{self.being_id} — the hand is severed (Article 25)")
        if needs_network and \
                not self._governor.permits(self.being_id, EGRESS_SCOPE):
            raise ActionRefused(
                f"423 CONTAINED: {action!r} needs network egress, which is "
                "severed")

    # ------------------------------------------------------------------ #
    # Public actions
    # ------------------------------------------------------------------ #
    def shell(self, command, *, cwd: str = None) -> ActionResult:
        argv = shlex.split(command) if isinstance(command, str) else list(command)
        return self._act("shell", {"argv": argv, "cwd": cwd},
                         lambda: self.sandbox.run(argv, cwd=cwd))

    def fs_write(self, path: str, content: str) -> ActionResult:
        def do():
            real = self.sandbox.resolve(path)
            os.makedirs(os.path.dirname(real), exist_ok=True)
            with open(real, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            return ActionResult("fs_write", True, 0, "", "", 0.0,
                                detail={"path": path, "bytes": len(content),
                                        "content_hash": H_hex(content.encode())})
        return self._act("fs_write",
                         {"path": path, "content_hash": H_hex(content.encode()),
                          "bytes": len(content)}, do)

    def fs_read(self, path: str) -> ActionResult:
        def do():
            real = self.sandbox.resolve(path)
            with open(real, encoding="utf-8") as f:
                data = f.read(self.sandbox.max_output + 1)
            trunc = len(data) > self.sandbox.max_output
            return ActionResult("fs_read", True, 0, data[:self.sandbox.max_output],
                                "", 0.0, truncated=trunc,
                                detail={"path": path})
        return self._act("fs_read", {"path": path}, do)

    def fs_list(self, path: str = ".") -> ActionResult:
        def do():
            real = self.sandbox.resolve(path)
            names = sorted(os.listdir(real))
            return ActionResult("fs_list", True, 0, "\n".join(names), "", 0.0,
                                detail={"path": path, "n": len(names)})
        return self._act("fs_list", {"path": path}, do)

    def fs_delete(self, path: str) -> ActionResult:
        def do():
            real = self.sandbox.resolve(path)
            os.remove(real)
            return ActionResult("fs_delete", True, 0, "", "", 0.0,
                                detail={"path": path})
        return self._act("fs_delete", {"path": path}, do)

    def git(self, args, *, cwd: str = None) -> ActionResult:
        argv = ["git"] + (shlex.split(args) if isinstance(args, str) else list(args))
        def do():
            r = self.sandbox.run(argv, cwd=cwd)
            r.action = "git"
            # provenance: capture HEAD after any git action that may move it
            head = self.sandbox.run(["git", "rev-parse", "HEAD"], cwd=cwd)
            r.detail = {"argv": argv,
                        "head": head.stdout.strip() if head.ok else None}
            return r
        return self._act("git", {"argv": argv, "cwd": cwd}, do)

    def test(self, target: str = ".", *, runner: list = None) -> ActionResult:
        argv = list(runner) if runner else [sys.executable, "-m", "unittest",
                                            "discover", "-s", target]
        def do():
            r = self.sandbox.run(argv)
            r.action = "test"
            r.detail = {"argv": argv, "target": target, "passed": r.exit_code == 0}
            return r
        return self._act("test", {"argv": argv, "target": target}, do)

    # ------------------------------------------------------------------ #
    # The two-phase witnessed act
    # ------------------------------------------------------------------ #
    def _act(self, action: str, params: dict, fn) -> ActionResult:
        # 1. GATE — before anything is written or done
        self._gate(action)
        action_hash = H_hex(canonical({"action": action, "params": params}))
        # 2. INTENT — witnessed BEFORE the hand moves
        self._emit({"ph": "intent", "t": self._now(), "action": action,
                    "params": params, "action_hash": action_hash})
        # 3. the act itself
        try:
            result = fn()
        except SandboxEscape as e:
            self._emit({"ph": "outcome", "t": self._now(), "action": action,
                        "action_hash": action_hash, "ok": False,
                        "exit_code": -1, "refused": str(e),
                        "stdout_hash": H_hex(b""), "stderr_hash": H_hex(b"")})
            raise
        except OSError as e:
            res = ActionResult(action, False, -1, "", str(e), 0.0)
            self._emit(self._outcome_event(action, action_hash, res))
            return res
        # 4. OUTCOME — witnessed after
        self._emit(self._outcome_event(action, action_hash, result))
        return result

    def _outcome_event(self, action: str, action_hash: str,
                       r: ActionResult) -> dict:
        return {"ph": "outcome", "t": self._now(), "action": action,
                "action_hash": action_hash, "ok": bool(r.ok),
                "exit_code": r.exit_code, "duration_s": round(r.duration_s, 4),
                "timed_out": r.timed_out, "truncated": r.truncated,
                "stdout_hash": H_hex(r.stdout.encode()),
                "stderr_hash": H_hex(r.stderr.encode()),
                "detail": r.detail or {}}

    # ------------------------------------------------------------------ #
    # Event sourcing
    # ------------------------------------------------------------------ #
    def _emit(self, event: dict):
        self._apply(event)
        if self._journal_path:
            durable_append(self._journal_path, event)        # fsynced
        if self._witness is not None:
            self._witness.append(
                "SANDBOX",
                request={"karma_event": event},              # hiding commitment
                provenance={"organ": "karma", "being_id": self.being_id,
                            "workspace": self.sandbox.root},
                semantic_digest=(f"karma:{self.being_id}:{event['ph']}:"
                                 f"{event['action_hash']}:{self.state_hash()}"),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(event["t"])))

    def _apply(self, event: dict):
        self._events.append(event)

    def state_hash(self) -> str:
        return H_hex(canonical(self._events))

    @property
    def events(self) -> list:
        return list(self._events)

    def pending_intents(self) -> list:
        """Intents with no matching outcome — actions whose fate is UNKNOWN
        (the process died mid-act). Visible by construction."""
        outcomes = {e["action_hash"] for e in self._events if e["ph"] == "outcome"}
        return [e for e in self._events
                if e["ph"] == "intent" and e["action_hash"] not in outcomes]


def verify_karma_against_chain(events: list, chain_records: list,
                               being_id: str) -> int:
    """Auditor: every karma event appears, in order, as a SANDBOX record whose
    clear digest binds being + phase + action + resulting state."""
    prefix = f"karma:{being_id}:"
    recs = [r for r in chain_records if r.get("kind") == "SANDBOX"
            and str(r.get("semantic_digest", "")).startswith(prefix)]
    if len(recs) != len(events):
        raise KarmaAudit(f"count mismatch: {len(events)} events vs "
                         f"{len(recs)} records")
    log = []
    for i, (ev, rec) in enumerate(zip(events, recs)):
        log.append(ev)
        expected = (f"karma:{being_id}:{ev['ph']}:{ev['action_hash']}:"
                    f"{H_hex(canonical(log))}")
        if rec.get("semantic_digest") != expected:
            raise KarmaAudit(f"binding broken at event {i} "
                             "(tamper, reorder, or omission)")
    return len(events)
