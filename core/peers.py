# -*- coding: utf-8 -*-
"""
core.peers — Peer registry, admission, and authenticated requests (v0.5, P1)
=============================================================================
The "friend-or-foe" (IFF) system for JJ DAI nodes, in four layers:

  1. TRANSPORT   — TLS/mTLS: deployment concern, out of scope here (noted).
  2. MESSAGE     — every privileged request is a signed envelope with a
                   timestamp window and single-use nonce (replay refused).
  3. MEMBERSHIP  — this module: a durable PeerRegistry of ADMITTED nodes.
                   Identity is self-certifying (node_id derives from the
                   public key — a name cannot be claimed without the key);
                   MEMBERSHIP is granted by an admission authority whose
                   signature over the peer record is verified. Fail closed:
                   unknown or suspended nodes are foes.
  4. BEHAVIORAL  — NECS conformance, reputation, containment status
                   (existing components; consulted by callers).

Envelopes are JCS-canonical, Ed25519-signed, domain-separated.
"""
from __future__ import annotations

import os
import time

from jjdai.canonical import canonical
from jjdai.crypto import H_hex, SigningKey, verify, node_id, canonical_node_id
from jjdai.durable import durable_append, read_journal

PEER_DOMAIN = b"jjdai/peers/record/v1:"
ADMIT_DOMAIN = b"jjdai/peers/admission/v1:"
REQUEST_DOMAIN = b"jjdai/peers/request/v1:"

STATUSES = ("active", "suspended")


class PeerError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
#  Peer records + admission
# --------------------------------------------------------------------------- #

def make_peer_record(sk: SigningKey, *, base_url: str,
                     roles: list = ("inference", "verify", "replicate")) -> dict:
    """Self-signed claim: 'this key serves at this URL with these roles'."""
    body = {
        "kind": "PEER_RECORD",
        "node_id": canonical_node_id(sk.public),
        "base_url": base_url,
        "roles": sorted(roles),
        "created_at": time.time(),
    }
    sig = sk.sign(PEER_DOMAIN + canonical(body))
    return {"body": body, "pub": sk.public.hex(), "sig": sig.hex()}


def admit_peer(admission_sk: SigningKey, peer_record_env: dict) -> dict:
    """Admission authority countersigns a peer record: membership grant."""
    body = {
        "kind": "PEER_ADMISSION",
        "peer_node": peer_record_env["body"]["node_id"],
        "record_digest": H_hex(canonical(peer_record_env["body"])),
        "admitted_by": canonical_node_id(admission_sk.public),
        "admitted_at": time.time(),
    }
    sig = admission_sk.sign(ADMIT_DOMAIN + canonical(body))
    return {"record": peer_record_env,
            "admission": {"body": body,
                          "pub": admission_sk.public.hex(),
                          "sig": sig.hex()}}


def verify_admitted_record(bundle: dict, admission_keys: set) -> tuple:
    """Offline: the peer record is self-consistent AND countersigned by a
    recognized admission authority."""
    rec = bundle.get("record", {})
    adm = bundle.get("admission", {})
    try:
        rb, rpub, rsig = rec["body"], bytes.fromhex(rec["pub"]), bytes.fromhex(rec["sig"])
        ab, apub, asig = adm["body"], bytes.fromhex(adm["pub"]), bytes.fromhex(adm["sig"])
    except (KeyError, TypeError, ValueError):
        return False, "malformed bundle"
    if rb.get("kind") != "PEER_RECORD" or ab.get("kind") != "PEER_ADMISSION":
        return False, "wrong kind"
    if canonical_node_id(rpub) != rb.get("node_id"):
        return False, "peer node_id does not match its key"
    if not verify(rpub, PEER_DOMAIN + canonical(rb), rsig):
        return False, "bad peer signature"
    if canonical_node_id(apub) != ab.get("admitted_by"):
        return False, "admitted_by does not match admission key"
    if ab.get("admitted_by") not in admission_keys:
        return False, "admission authority not recognized (fail closed)"
    if ab.get("peer_node") != rb.get("node_id"):
        return False, "admission names a different peer"
    if ab.get("record_digest") != H_hex(canonical(rb)):
        return False, "admission does not cover this exact record"
    if not verify(apub, ADMIT_DOMAIN + canonical(ab), asig):
        return False, "bad admission signature"
    return True, "ok"


class PeerRegistry:
    """Durable membership registry. Fail closed: is_friend() is True only
    for a verified-admitted, non-suspended node_id."""

    def __init__(self, path: str = None, admission_keys: set = None):
        self.path = path
        self.admission_keys = set(admission_keys or ())
        self._peers: dict = {}          # node_id -> bundle
        self._status: dict = {}         # node_id -> status
        if path and os.path.exists(path):
            entries, _ = read_journal(path)
            for e in entries:
                if e.get("kind") == "PEER_ADMITTED":
                    b = e["bundle"]
                    # FAIL CLOSED on reload: a durable journal is not trusted
                    # blindly — every admitted bundle is re-verified against
                    # the recognized admission authorities, exactly as at
                    # registration. A forged journal line cannot smuggle a peer.
                    ok, reason = verify_admitted_record(b, self.admission_keys)
                    if not ok:
                        raise PeerError(
                            f"peer journal integrity failure on reload: "
                            f"{reason}")
                    nid = b["record"]["body"]["node_id"]
                    self._peers[nid] = b
                    self._status[nid] = "active"
                elif e.get("kind") == "PEER_STATUS":
                    if e["node_id"] in self._peers:
                        self._status[e["node_id"]] = e["status"]

    def register(self, bundle: dict) -> str:
        ok, reason = verify_admitted_record(bundle, self.admission_keys)
        if not ok:
            raise PeerError(f"peer refused: {reason}")
        nid = bundle["record"]["body"]["node_id"]
        already = nid in self._peers
        self._peers[nid] = bundle
        # Re-registration must NOT resurrect a suspended peer: replaying an
        # old admission bundle is not a governance event. Status only moves
        # to active for a genuinely new peer; reactivation requires an
        # explicit authority-signed set_status (governance action).
        if not already:
            self._status[nid] = "active"
            if self.path:
                durable_append(self.path, {"kind": "PEER_ADMITTED",
                                           "bundle": bundle})
        return nid

    def set_status(self, nid: str, status: str):
        if status not in STATUSES:
            raise PeerError(f"unknown status {status!r}")
        if nid not in self._peers:
            raise PeerError(f"unknown peer {nid!r}")
        self._status[nid] = status
        if self.path:
            durable_append(self.path, {"kind": "PEER_STATUS",
                                       "node_id": nid, "status": status})

    def is_friend(self, nid: str) -> bool:
        return self._status.get(nid) == "active"

    def peer(self, nid: str) -> dict | None:
        return self._peers.get(nid)

    def pubkey(self, nid: str) -> bytes | None:
        b = self._peers.get(nid)
        return bytes.fromhex(b["record"]["pub"]) if b else None

    def friends(self) -> list:
        return sorted(n for n in self._peers if self.is_friend(n))


# --------------------------------------------------------------------------- #
#  Signed requests (message-layer auth + replay protection)
# --------------------------------------------------------------------------- #

def make_signed_request(sk: SigningKey, *, path: str, payload: dict) -> dict:
    body = {
        "kind": "SIGNED_REQUEST",
        "path": path,
        "payload_hash": H_hex(canonical(payload)),
        "sender_node": canonical_node_id(sk.public),
        "ts": time.time(),
        "nonce": os.urandom(16).hex(),
    }
    sig = sk.sign(REQUEST_DOMAIN + canonical(body))
    return {"auth": {"body": body, "pub": sk.public.hex(), "sig": sig.hex()},
            "payload": payload}


class RequestAuthenticator:
    """Server side: registry membership + signature + freshness window +
    single-use nonce. Fail closed on every branch."""

    def __init__(self, registry: PeerRegistry, *, window_s: float = 60.0,
                 nonce_capacity: int = 100_000):
        self.registry = registry
        self.window_s = window_s
        self._seen: dict = {}           # nonce -> expiry ts
        self._capacity = nonce_capacity
        import threading
        self._lock = threading.Lock()

    def _gc(self, now: float):
        if len(self._seen) > self._capacity:
            self._seen = {n: t for n, t in self._seen.items() if t > now}

    def check(self, envelope: dict, *, path: str) -> tuple:
        try:
            auth = envelope["auth"]
            body, pub, sig = auth["body"], bytes.fromhex(auth["pub"]), \
                bytes.fromhex(auth["sig"])
            payload = envelope["payload"]
        except (KeyError, TypeError, ValueError):
            return False, "malformed request envelope"
        if body.get("kind") != "SIGNED_REQUEST":
            return False, "wrong kind"
        sender = body.get("sender_node")
        if canonical_node_id(pub) != sender:
            return False, "sender_node does not match key"
        if not self.registry.is_friend(sender):
            return False, "sender is not an admitted active peer (foe)"
        pinned = self.registry.pubkey(sender)
        if pinned != pub:
            return False, "key does not match the registered peer record"
        if body.get("path") != path:
            return False, f"envelope is bound to {body.get('path')!r}, not {path!r}"
        if H_hex(canonical(payload)) != body.get("payload_hash"):
            return False, "payload hash mismatch"
        ts = body.get("ts")
        if not isinstance(ts, (int, float)):
            return False, "malformed timestamp"
        now = time.time()
        if abs(now - ts) > self.window_s:
            return False, f"stale request (|Δt| > {self.window_s}s)"
        nonce = body.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            return False, "missing nonce"
        # SIGNATURE FIRST — an unauthenticated sender must never write into
        # the nonce cache (memory exhaustion / replay-cache poisoning).
        if not verify(pub, REQUEST_DOMAIN + canonical(body), sig):
            return False, "bad signature"
        # atomic check-and-insert (ThreadingHTTPServer is concurrent):
        with self._lock:
            self._gc(now)
            if len(self._seen) >= self._capacity:
                return False, "nonce cache saturated (retry)"
            if nonce in self._seen:
                return False, "replay: nonce already used"
            self._seen[nonce] = now + self.window_s
        return True, sender
