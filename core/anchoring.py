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

    def __init__(self, chain, backends: list, log: AnchorLog,
                 *, lock=None):
        if not backends:
            raise AnchorError("anchor scheduler needs at least one backend")
        self.chain = chain
        self.backends = list(backends)
        self.log = log
        self._lock = lock
        self._covered = 0
        for r in log.receipts:
            if r.get("node") == chain.node_id:
                self._covered = max(self._covered, int(r.get("count", 0)))

    def _snapshot(self):
        if self._lock is not None:
            with self._lock:
                recs = list(self.chain.records)
        else:
            recs = list(self.chain.records)
        root = mth_root([r["this_hash"].encode() for r in recs])
        return recs, root

    def anchor_now(self) -> dict:
        recs, root = self._snapshot()
        count = len(recs)
        substantive = any(r["kind"] not in self.BOOKKEEPING
                          for r in recs[self._covered:])
        if count == 0 or not substantive:
            return {"skipped": "not-substantive", "count": count,
                    "covered": self._covered}
        receipts = []
        for be in self.backends:
            rec = be.submit(self.chain.node_id, root, count)
            self.log.add(rec)
            receipts.append(rec)
        summary = {
            "count": count, "root": root, "root_alg": "rfc6962",
            "backends": [{"backend": r["backend"], "status": r["status"]}
                         for r in receipts],
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
        self._covered = count
        return {"anchored": True, "count": count, "root": root,
                "receipts": receipts}
