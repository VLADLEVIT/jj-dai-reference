# -*- coding: utf-8 -*-
"""
core.anchoring — External witness anchoring (v0.5.1)
====================================================
Fills the last hole in the "inextinguishable witness" story. Replication
(core.replication / core.segments) makes the witness survivable ACROSS
PEERS; external anchoring binds it to systems OUTSIDE the JJ DAI trust
domain, so even a full-quorum collusion cannot silently rewrite time.

    AnchorLog            — durable journal of anchor receipts (pending /
                           recorded), fail-closed reload
    LocalFileAnchor      — journal-backed local anchor (supersedes the
                           in-memory LocalAnchor for production paths;
                           still LOCAL — labeled, never oversold)
    PeerQuorumAnchor     — bridges existing replication quorum receipts
                           into the anchor log (k peers hold the root)
    OtsCalendarAnchor    — OpenTimestamps calendar client: POST the
                           32-byte root digest to <calendar>/digest and
                           keep the returned proof bytes in CUSTODY
    AnchorScheduler      — computes the RFC 6962 chain root, submits to
                           every configured backend, journals receipts,
                           and witnesses ONE ANCHOR_EXTERNAL record

HONEST STATEMENT on OpenTimestamps (read before trusting):
  * The calendar's response is an INCOMPLETE timestamp (a pending
    attestation). It commits the calendar operator; it becomes a Bitcoin
    fact only after the calendar aggregates into a block (~hours).
  * This module takes CUSTODY of the proof bytes and records exactly what
    it holds ("pending-attestation"). It does NOT parse the OTS binary
    format and does NOT verify Bitcoin inclusion — final verification is
    performed with standard `ots` tooling against the stored proof, or by
    the future upgrade seam. A receipt here means "submitted and held",
    never "proven on-chain". Anything stronger would be a lie.
  * stdlib-only HTTP; a mock calendar in the test suite exercises the
    protocol; the real calendars (alice/bob.btc.calendar.opentimestamps.org,
    finney.calendar.eternitywall.com) speak the same POST /digest.

INV-9 intact: anchoring is an act of the NODE; the chain receives one
record ABOUT the anchoring, and the record itself is what gets anchored
next round — the ratchet, not a recursion.
"""
from __future__ import annotations

import os
import time
import urllib.request

from jjdai.canonical import canonical
from jjdai.crypto import H_hex
from jjdai.durable import durable_append, read_journal
from jjdai.merkle import mth_root

OTS_MAX_PROOF = 1 << 16      # 64 KiB cap on stored calendar responses


class AnchorError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
#  Durable receipt log
# --------------------------------------------------------------------------- #

class AnchorLog:
    """Durable journal of anchor receipts. Reload is FAIL CLOSED on
    structure (unknown kinds / malformed entries refuse the boot); receipt
    CONTENT is backend-opaque by design — an OTS proof is bytes we hold,
    not something we can locally re-verify (see module docstring)."""

    REQUIRED = ("backend", "root", "count", "status", "ts")

    def __init__(self, path: str = None):
        self.path = path
        self.receipts: list = []
        if path and os.path.exists(path):
            entries, _ = read_journal(path)
            for e in entries:
                if e.get("kind") != "ANCHOR_RECEIPT" or not all(
                        k in (e.get("receipt") or {}) for k in self.REQUIRED):
                    raise AnchorError(
                        "anchor journal integrity failure on reload: "
                        f"malformed entry {str(e)[:80]!r}")
                self.receipts.append(e["receipt"])

    def add(self, receipt: dict) -> dict:
        missing = [k for k in self.REQUIRED if k not in receipt]
        if missing:
            raise AnchorError(f"receipt missing fields: {missing}")
        self.receipts.append(receipt)
        if self.path:
            durable_append(self.path, {"kind": "ANCHOR_RECEIPT",
                                       "receipt": receipt})
        return receipt

    def latest(self, backend: str = None) -> dict | None:
        for r in reversed(self.receipts):
            if backend is None or r["backend"] == backend:
                return r
        return None

    def for_root(self, root: str) -> list:
        return [r for r in self.receipts if r["root"] == root]


# --------------------------------------------------------------------------- #
#  Backends
# --------------------------------------------------------------------------- #

class LocalFileAnchor:
    """Local durable anchor. Detects truncation/rewrite of the chain by
    remembering roots on THIS host — and says so: an attacker with host
    access rewrites chain and anchor together. Pair with peer + external
    backends; alone it is a dev convenience, not a guarantee."""
    name = "local"

    def submit(self, node_id: str, root: str, count: int) -> dict:
        return {"backend": self.name, "node": node_id, "root": root,
                "count": count, "status": "recorded", "ts": time.time(),
                "scope": "single-host"}


class PeerQuorumAnchor:
    """Bridges core.replication quorum receipts into the anchor log: the
    strongest anchor JJ DAI itself can provide — k independent peers hold
    and acked this exact root. Receives the verified QUORUM_RECEIPT from
    the node (the node runs the push; INV-9)."""
    name = "peer-quorum"

    def __init__(self, get_receipt):
        # get_receipt: (count, root) -> verified QUORUM_RECEIPT | None
        self._get = get_receipt

    def submit(self, node_id: str, root: str, count: int) -> dict:
        rec = self._get(count, root)
        if rec is None:
            return {"backend": self.name, "node": node_id, "root": root,
                    "count": count, "status": "pending",
                    "detail": "no quorum receipt for this root yet",
                    "ts": time.time()}
        return {"backend": self.name, "node": node_id, "root": root,
                "count": count, "status": "recorded",
                "k": rec.get("k"),
                "receivers": sorted({a["body"]["receiver_node"]
                                     for a in rec.get("acks", [])}),
                "quorum_receipt_hash": H_hex(canonical(rec)),
                "ts": time.time()}


class OtsCalendarAnchor:
    """OpenTimestamps calendar client (custody-only — module docstring).
    POSTs the raw 32-byte digest to <calendar_url>/digest; the response
    bytes are the calendar's pending timestamp proof, stored hex-encoded."""
    name = "ots-calendar"

    def __init__(self, calendar_url: str, timeout: float = 10.0):
        self.url = calendar_url.rstrip("/")
        self.timeout = float(timeout)

    def submit(self, node_id: str, root: str, count: int) -> dict:
        digest = bytes.fromhex(root)
        if len(digest) != 32:
            raise AnchorError("OTS anchor needs a 32-byte sha256 root")
        req = urllib.request.Request(
            self.url + "/digest", data=digest,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/vnd.opentimestamps.v1",
                     "User-Agent": "jjdai-anchor/0.5.1"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                proof = r.read(OTS_MAX_PROOF + 1)
        except OSError as e:
            return {"backend": self.name, "node": node_id, "root": root,
                    "count": count, "status": "failed",
                    "calendar": self.url, "detail": str(e),
                    "ts": time.time()}
        if len(proof) > OTS_MAX_PROOF:
            return {"backend": self.name, "node": node_id, "root": root,
                    "count": count, "status": "failed",
                    "calendar": self.url,
                    "detail": "calendar response exceeds proof cap",
                    "ts": time.time()}
        if not proof:
            return {"backend": self.name, "node": node_id, "root": root,
                    "count": count, "status": "failed",
                    "calendar": self.url,
                    "detail": "empty calendar response", "ts": time.time()}
        return {"backend": self.name, "node": node_id, "root": root,
                "count": count, "status": "pending-attestation",
                "calendar": self.url,
                "proof_hex": proof.hex(),
                "proof_sha256": H_hex(proof),
                "note": "custody of calendar proof; Bitcoin inclusion is "
                        "verified with standard ots tooling, not here",
                "ts": time.time()}


# --------------------------------------------------------------------------- #
#  Scheduler
# --------------------------------------------------------------------------- #

class AnchorScheduler:
    """Computes the RFC 6962 root over the FULL chain (the same tree the
    replication layer signs — one root, all layers), submits it to every
    configured backend, journals every receipt, and appends ONE
    ANCHOR_EXTERNAL record summarizing the round.

    Ratchet, not recursion: a round whose only news since the last anchored
    count is anchor bookkeeping is skipped (`skipped: not-substantive`)."""

    BOOKKEEPING = ("ANCHOR_QUORUM", "ANCHOR_EXTERNAL", "PEER_ROOT")

    #: Receipt statuses that MEAN the range is externally anchored. Nothing
    #: else advances coverage. Split out in the v0.6.6 recut, where an audit
    #: reproduced a failed XMR receipt advancing `_covered` and thereby
    #: retiring the range forever: the anchor had not happened, the log said
    #: it had failed, and the scheduler never tried again.
    TERMINAL_SUCCESS = ("recorded",)
    #: Attempted, outcome not yet known. Never coverage — a proof that may
    #: arrive is not a proof that has.
    PENDING = ("pending", "pending-attestation")
    #: Attempted and known not to have worked. Never coverage; retried.
    FAILED = ("failed",)

    #: A local file is evidence that WE wrote something down. It is not
    #: external anchoring and cannot discharge an external-anchor policy.
    LOCAL_BACKENDS = ("local",)

    def __init__(self, chain, backends: list, log: AnchorLog,
                 *, lock=None, required_backends=None, retry_backoff_s=60.0):
        if not backends:
            raise AnchorError("anchor scheduler needs at least one backend")
        self.chain = chain
        self.backends = list(backends)
        self.log = log
        self._lock = lock
        self.retry_backoff_s = float(retry_backoff_s)

        names = [be.name for be in self.backends]
        if required_backends is None:
            # Everything that is not merely local. A node configured with
            # only a local backend has no external policy to discharge, and
            # reporting it as permanently behind would be a false red as
            # surely as the false green this fixes.
            external = [n for n in names if n not in self.LOCAL_BACKENDS]
            required_backends = external or list(names)
        self.required_backends = [n for n in required_backends if n in names]

        # Coverage is PER BACKEND. One number for all of them cannot express
        # "the calendar has it and Monero does not", which is the ordinary
        # state of a healthy node.
        self._covered_by = {n: 0 for n in names}
        self._attempted_by = {n: 0 for n in names}
        self._last_success_at = {n: None for n in names}
        self._last_attempt_at = None
        self._last_failure = {}          # backend -> status/message
        self._next_retry_at = 0.0
        for r in log.receipts:
            if r.get("node") != chain.node_id:
                continue
            be, cnt = r.get("backend"), int(r.get("count", 0))
            if be not in self._attempted_by:
                continue
            self._attempted_by[be] = max(self._attempted_by[be], cnt)
            # Restart must NOT resurrect coverage from a failed receipt.
            if r.get("status") in self.TERMINAL_SUCCESS:
                self._covered_by[be] = max(self._covered_by[be], cnt)
                self._last_success_at[be] = r.get("ts")
            elif r.get("status") in self.FAILED:
                self._last_failure[be] = r.get("status")

    # ---- coverage policy ------------------------------------------------ #

    @property
    def _covered(self) -> int:
        """The ratchet: how far EVERY required backend has actually got.

        Kept as a property under the old name so the substantive-news check
        and any external reader keep working — but it is now derived from
        per-backend success rather than assigned after a submission round.
        """
        if not self.required_backends:
            return min(self._covered_by.values()) if self._covered_by else 0
        return min(self._covered_by[n] for n in self.required_backends)

    def _behind(self, count: int, recs=None) -> list:
        """Required backends with SUBSTANTIVE records they have not covered.

        Deliberately not `covered_by[n] < count`: the chain grows by its own
        anchor bookkeeping, so a plain count comparison makes every backend
        look behind one record after every successful round, and the node
        re-anchors itself forever. Behind means "there is real news this
        backend has not witnessed", which is the same ratchet the skip rule
        has always used — now applied per backend.
        """
        if recs is None:
            recs, _ = self._snapshot()
        out = []
        for n in self.required_backends:
            cov = self._covered_by[n]
            if any(r["kind"] not in self.BOOKKEEPING for r in recs[cov:]):
                out.append(n)
        return out

    def unanchored_depth(self) -> int:
        """Substantive records past the covered point — the SLO metric."""
        recs, _ = self._snapshot()
        cov = self._covered
        return sum(1 for r in recs[cov:] if r["kind"] not in self.BOOKKEEPING)

    def anchor_status(self) -> dict:
        """One thread-safe view of the facts readiness needs.

        Readiness used to read `last_anchor_at` and `unanchored_depth` off
        this object. Neither attribute existed, so `getattr` defaults turned
        an ABSENT MEASUREMENT into a green light — the exact false green the
        observability drop was written to remove. The facts are published
        here explicitly so that mistake cannot be repeated silently.
        """
        recs, _ = self._snapshot()
        count = len(recs)
        cov = self._covered
        depth = sum(1 for r in recs[cov:] if r["kind"] not in self.BOOKKEEPING)
        succ = [self._last_success_at[n] for n in self.required_backends
                if self._last_success_at[n]]
        return {
            "required_backends": list(self.required_backends),
            "backends": list(self._covered_by),
            "covered_by": dict(self._covered_by),
            "attempted_by": dict(self._attempted_by),
            "covered": cov,
            "count": count,
            "unanchored_depth": depth,
            "last_attempt_at": self._last_attempt_at,
            "last_success_at": (min(succ) if succ and
                                len(succ) == len(self.required_backends)
                                else None),
            "last_success_by": dict(self._last_success_at),
            "behind": self._behind(count, recs),
            "last_failure": dict(self._last_failure),
            "next_retry_at": self._next_retry_at,
            #: True when a required backend has NEVER succeeded. Distinct
            #: from "lagging": a node that has never anchored has no lag to
            #: report, and reporting `None` as healthy is how this broke.
            "never_succeeded": any(self._last_success_at[n] is None
                                   for n in self.required_backends),
        }

    def _snapshot(self):
        if self._lock is not None:
            with self._lock:
                recs = list(self.chain.records)
        else:
            recs = list(self.chain.records)
        root = mth_root([r["this_hash"].encode() for r in recs])
        return recs, root

    def anchor_now(self, *, now=None) -> dict:
        recs, root = self._snapshot()
        count = len(recs)
        now = time.time() if now is None else now
        # "Is there news worth submitting" is measured against what has been
        # ATTEMPTED, not against what is confirmed. Measuring against
        # coverage looked right until a required backend went `pending` —
        # then coverage froze at zero, every old record looked new forever,
        # and the node re-anchored itself on every tick.
        attempted_hwm = (max(self._attempted_by.values())
                         if self._attempted_by else 0)
        substantive = any(r["kind"] not in self.BOOKKEEPING
                          for r in recs[attempted_hwm:])
        behind = self._behind(count, recs)
        # A required backend that is behind is REASON ENOUGH to run, even
        # with no new cognition since the last attempt. Requiring fresh
        # substantive news before retrying meant a failed anchor waited for
        # unrelated work to happen before it was tried again — on a quiet
        # node, forever.
        retry_due = bool(behind) and now >= self._next_retry_at
        if count == 0 or not (substantive or retry_due):
            return {"skipped": "not-substantive", "count": count,
                    "covered": self._covered, "behind": behind}
        # On a pure retry only the backends that are behind are contacted:
        # re-submitting to a backend that already holds this range wastes
        # its quota and muddies its receipt log.
        targets = ([be for be in self.backends if be.name in behind]
                   if (retry_due and not substantive) else self.backends)
        self._last_attempt_at = now
        receipts = []
        for be in targets:
            rec = be.submit(self.chain.node_id, root, count)
            self.log.add(rec)
            receipts.append(rec)
            self._attempted_by[be.name] = max(self._attempted_by[be.name],
                                              count)
            if rec.get("status") in self.TERMINAL_SUCCESS:
                self._covered_by[be.name] = max(self._covered_by[be.name],
                                                count)
                self._last_success_at[be.name] = rec.get("ts", now)
                self._last_failure.pop(be.name, None)
            else:
                self._last_failure[be.name] = rec.get("status", "failed")
        still_behind = self._behind(count, recs)
        self._next_retry_at = (now + self.retry_backoff_s if still_behind
                               else 0.0)
        progressed = any(r.get("status") in self.TERMINAL_SUCCESS
                         for r in receipts)
        # "Is there NEW news" must be measured against what we last
        # ATTEMPTED, not against what is covered. While a required backend
        # is failing, coverage never advances, so measuring against coverage
        # makes the same old records look new forever — and every retry
        # writes another ANCHOR_EXTERNAL, at the backoff interval, without
        # end.
        if not progressed and not substantive:
            # A retry that changed nothing must NOT append a chain record.
            # Otherwise every failed retry is itself an event, and the node
            # writes bookkeeping to itself forever at the backoff interval.
            return {"retried": True, "anchored": False, "count": count,
                    "covered": self._covered, "behind": still_behind,
                    "receipts": receipts}
        summary = {
            "count": count, "root": root, "root_alg": "rfc6962",
            "backends": [{"backend": r["backend"], "status": r["status"]}
                         for r in receipts],
            "covered": self._covered,
        }
        append = (lambda: self.chain.append(
            "ANCHOR_EXTERNAL",
            response={"receipts": receipts},     # full detail under commitment
            semantic_digest=summary,             # public auditable summary
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        if self._lock is not None:
            with self._lock:
                append()
        else:
            append()
        # NOTE: coverage was already advanced per backend above, by receipt
        # status. There is deliberately no blanket assignment here — that
        # assignment was the defect.
        # `anchored` keeps its established meaning — a round was submitted
        # and ONE ANCHOR_EXTERNAL record was appended. Whether every required
        # backend actually holds the range is a different question and gets
        # its own field rather than quietly redefining an old one.
        return {"anchored": True, "fully_covered": not still_behind,
                "partial": bool(still_behind),
                "count": count, "root": root, "covered": self._covered,
                "behind": still_behind, "receipts": receipts}
