#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — Tier-1 Node Daemon (v0.1)
==================================
The first LIVE certification target for the NECS conformance suite: a stdlib
HTTP server exposing the /v1/messages JII envelope (NECS C1), backed by the
REAL jjdai primitive layer — Ed25519-signed WitnessChain, RFC 8785 JCS
canonicalization, hiding commitments H(salt‖x).

Whitepaper §13 step 1: "2 nodes (Xeon + RTX 6000): memory integrity, base +
RAG + prompting + tools, no fine-tuning." This daemon is that node's trust
shell. The inference engine is a SEAM: `HashEngine` (deterministic reference)
runs today; a DwarfStar `/v1` adapter (Profile B) plugs into the same three
methods without touching the envelope or witness logic.

Endpoints
---------
GET  /capabilities       NECS capability descriptor (+ witness pubkey)
POST /v1/messages        JII request -> JII response  (C1 semantics:
                         400 BAD_ENVELOPE · 404 SUBSTRATE_UNKNOWN ·
                         404 ADAPTER_UNKNOWN · 422 PROVENANCE_MISMATCH ·
                         503 WITNESS_UNAVAILABLE — fail-closed, NO output)
GET  /witness/chain      full chain export (bodies only — salts never leave)
GET  /witness/head       {head, count, node_id}
POST /witness/anchor     batch-anchor new records; returns Merkle root receipt
POST /admin/witness      TEST HOOK (only with --allow-test-hooks):
                         {"up": false} simulates witness failure

Run
---
    python3 daemon.py --port 8471 --fingerprint fp-node-A
    python3 daemon.py --port 8472 --fingerprint fp-node-B --profile A \
        --adapters '{"sha256:adp-good":"sha256:base-A","sha256:adp-bad":"sha256:base-OTHER"}'

Certification: node/smoke_two_nodes.py (remote R-C1..R-C3 suite).
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import H_hex, SigningKey, node_id         # noqa: E402
from jjdai.witness import WitnessChain, LocalAnchor         # noqa: E402
from core.containment import ContainmentLedger              # noqa: E402
from core.identity import (NodeIdentity, IdentityError,     # noqa: E402
                           verify_startup)
from core.attestation import (measure_artifact,             # noqa: E402
                              make_weight_attestation,
                              make_deployment_manifest,
                              AttestationStore, AttestationError)
from core.anchoring import (AnchorLog, AnchorScheduler,     # noqa: E402
                            LocalFileAnchor, PeerQuorumAnchor,
                            OtsCalendarAnchor, AnchorError)
from core.anchoring_xmr import XmrAnchor, XmrAnchorError    # noqa: E402
from runtime.being import BeingRuntime, BeingRuntimeError   # noqa: E402
from authz import AuthzPolicy, AuthzError                   # noqa: E402
from core.challenge import ChallengeRound                   # noqa: E402
from core.challenge import (ChallengeRound, ChallengeError,  # noqa: E402
                            verify_fraud_proof)
from jjdai.crypto import verify as ed_verify                 # noqa: E402
from jjdai.canonical import canonical as _canonical          # noqa: E402
from core.replication import (ReplicaStore, QuorumTracker,  # noqa: E402
                              make_signed_root, make_ack,
                              verify_quorum_receipt, reconcile,
                              make_consistency, ReplicationError)
from core.segments import (SegmentStore, make_segment,      # noqa: E402
                           SegmentError, MAX_SEGMENT_RECORDS)
from core.peers import (PeerRegistry, RequestAuthenticator,  # noqa: E402
                        make_signed_request, PeerError)
from core.entanglement import (SaltBeacon, beacon_from,      # noqa: E402
                               EntanglementError)
from jjdai.schema import (InferenceRequest, ValidationError,  # noqa: E402
                          validate as schema_validate)
from core.verdict import seal_verdict                        # noqa: E402

JII_REQUIRED = ("substrate_id", "adapter_ids", "sampling", "request_id", "nonce")


def semantic_digest(text: str) -> str:
    """8-dim char-class histogram — the harness's cheap embedding stand-in.
    Consensus (C3.6) compares THIS, never hiding commitments."""
    buckets = [0] * 8
    for ch in text:
        buckets[ord(ch) % 8] += 1
    return ",".join(str(b) for b in buckets)


# --------------------------------------------------------------------------- #
# Engine seam
# --------------------------------------------------------------------------- #

class HashEngine:
    """Deterministic reference engine (Profile B). Same input -> same bytes,
    so the node can honestly declare determinism_level='reproducible'.

    PRODUCTION SEAM: replace with DwarfStarEngine — an adapter that forwards
    `messages`+`sampling` to the local DwarfStar /v1 endpoint and declares
    determinism_level='attested'. The daemon's envelope/witness logic does
    not change."""

    determinism_level = "reproducible"
    backend = "cpu"

    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint

    def generate(self, messages: list, sampling: dict,
                 adapter_ids: list = ()) -> str:
        prompt = canonical(messages).decode()
        tag = "+".join(adapter_ids)
        return "out:" + H_hex((prompt + tag + self.fingerprint).encode())[:24]

    def score(self, messages: list, tokens: list, sampling: dict,
              adapter_ids: list = ()) -> dict:
        """Reference verifier: the genuine completion is exactly what this
        engine would generate; anything else is unreachable."""
        genuine = self.generate(messages, sampling, adapter_ids).split()
        reachable = [i < len(genuine) and t == genuine[i]
                     for i, t in enumerate(tokens)]
        ok = all(reachable) and bool(tokens)
        return {"ok": ok, "reachable": reachable,
                "min_margin": 1.0 if ok else 0.0,
                "verifier_fp": self.fingerprint,
                "determinism": self.determinism_level,
                "note": "" if ok else "token mismatch"}


# --------------------------------------------------------------------------- #
# Node
# --------------------------------------------------------------------------- #

class Node:
    def __init__(self, *, name: str, profile: str, substrates: list,
                 adapters: dict, engine: HashEngine, log_path: str = None,
                 allow_test_hooks: bool = False, being_id: str = None,
                 governor: ContainmentLedger = None,
                 identity: NodeIdentity = None,
                 peers: list = None, quorum_k: int = 2,
                 replica_store_path: str = None, receipt_path: str = None,
                 segment_store_path: str = None,
                 peer_registry: PeerRegistry = None,
                 require_admission: bool = False,
                 salt_peers: list = None, entangle_min: int = 1,
                 entangle_strict: bool = False,
                 entangle_max_age_s: float = 300.0,
                 client_ssl_context: ssl.SSLContext = None,
                 attest_artifacts: dict = None,
                 require_attestation: bool = False,
                 attestation_store_path: str = None,
                 anchor_backends: list = None,
                 anchor_store_path: str = None,
                 being_profile: str = None,
                 being_workspace: str = None,
                 being_journal_dir: str = None,
                 being_provenance: dict = None,
                 rate_limits: dict = None,
                 authz: "AuthzPolicy" = None,
                 revoked_serials: set = None,
                 challenge_windows: tuple = None,
                 operator_cns: list = None,
                 fraud_log_path: str = None):
        self.name = name
        self.profile = profile
        self.substrates = list(substrates)
        self.adapters = dict(adapters)          # adapter_id -> base_compat_tag
        self.engine = engine
        # IDENTITY CONTINUITY (v0.4.1, P0-1): the live node's signer IS the
        # persistent NodeIdentity when one is supplied. An ephemeral key is a
        # DEV-ONLY convenience and is refused whenever a persisted witness log
        # already exists (see main()) — a node must never silently re-key over
        # its own history (Invariant I: identity is continuous).
        self.identity = identity
        self.identity_mode = "persistent" if identity else "ephemeral"
        self.sk = identity.sk if identity else SigningKey.generate()
        self.chain = WitnessChain(self.sk, anchor=LocalAnchor(),
                                  log_path=log_path)
        # BOOT GATE (v0.4.1, P0-2): if a chain was loaded from disk, every
        # record must have been written by THIS signer and the whole chain
        # must re-verify under THIS public key. Otherwise the daemon refuses
        # to start rather than appending with a divergent key and leaving the
        # log cryptographically incoherent.
        if self.chain.records:
            foreign = [r["index"] for r in self.chain.records
                       if r.get("node_id") != self.chain.node_id]
            if foreign:
                raise IdentityError(
                    "startup refused: witness log at %r contains %d record(s) "
                    "signed by a different node identity (first at index %s). "
                    "Supply the original --node-keystore or point --log at a "
                    "fresh path. Re-keying over existing history is forbidden."
                    % (log_path, len(foreign), foreign[0]))
            verify_startup(self.chain, node=identity)
        # ---- replication (v0.5, P1/M6) --------------------------------- #
        self.peers = list(peers or [])
        self.replica_store = ReplicaStore(replica_store_path)
        self.segment_store = SegmentStore(segment_store_path)
        self.quorum_k = int(quorum_k)
        self.quorum = QuorumTracker(self.chain.node_id, self.quorum_k)
        self.receipts = {}          # count -> QUORUM_RECEIPT (anchored)
        self.receipt_path = receipt_path
        self._anchor_covered = 0    # chain count covered by the last anchor
        # RESTART RESTORATION (v0.5 drop 6): quorum receipts are durable —
        # a reboot must not forget which counts were already anchored, or
        # the anchor-recursion guard restarts from zero and the node
        # re-anchors covered history. Every persisted receipt is RE-VERIFIED
        # before it is trusted (fail closed, same rule as every journal).
        if receipt_path and os.path.exists(receipt_path):
            from jjdai.durable import read_journal
            entries, _ = read_journal(receipt_path)
            for rec in entries:
                ok, why = verify_quorum_receipt(
                    rec, origin_node=self.chain.node_id, k=None)
                if not ok:
                    raise ReplicationError(
                        "receipt journal integrity failure on reload: "
                        f"{why}")
                self.receipts[rec["count"]] = rec
            if self.receipts:
                self._anchor_covered = max(self.receipts)
        # ---- IFF + entanglement (v0.5, P1) ------------------------------ #
        self.peer_registry = peer_registry or PeerRegistry()
        self.authenticator = RequestAuthenticator(self.peer_registry)
        self.require_admission = bool(require_admission)
        self.beacon_source = SaltBeacon(self.chain, self.sk)
        self.salt_peers = list(salt_peers or [])
        self.entangle_min = int(entangle_min)
        self.entangle_strict = bool(entangle_strict)
        self.entangle_max_age_s = float(entangle_max_age_s)
        self.current_beacon = None
        self.witness_up = True                  # test hook flips this
        self.allow_test_hooks = allow_test_hooks
        self._lock = threading.Lock()
        # The Being served by this node (identity for containment). A node
        # governs the Being it hosts: every inference is an executive act
        # ("tools.side_effect" — the Being changes the world by emitting a
        # witnessed output), so the governor is consulted BEFORE generate().
        self.being_id = being_id or f"being:{self.chain.node_id[:16]}"
        self.governor = governor or ContainmentLedger(
            self.chain.node_id, witness=self.chain,
            evidence_resolver=None)             # fail-closed proof resolver
        # ---- TLS client side (v0.5.1) ----------------------------------- #
        self.client_ssl = client_ssl_context    # None => plain http peers
        # ---- weight attestation (v0.5.1) -------------------------------- #
        # BOOT GATE: every artifact named in attest_artifacts is MEASURED
        # now; a content-addressed substrate id whose bytes do not match
        # refuses the boot (a node must never serve weights it cannot
        # attest under the id it advertises). --require-attestation
        # additionally refuses to serve any substrate WITHOUT a measured
        # artifact. The signed DeploymentManifest is witnessed and public.
        self.attestations = AttestationStore(attestation_store_path)
        self.deployment = None
        self.require_attestation = bool(require_attestation)
        artifacts = dict(attest_artifacts or {})
        if require_attestation:
            missing = [s for s in self.substrates if s not in artifacts]
            if missing:
                raise AttestationError(
                    "startup refused: --require-attestation set but no "
                    f"artifact declared for substrate(s) {missing}")
        if artifacts:
            att_envs = {}
            for sid, path in sorted(artifacts.items()):
                if sid not in self.substrates:
                    raise AttestationError(
                        f"artifact declared for unserved substrate {sid!r}")
                env = make_weight_attestation(
                    self.sk, manifest_id=sid, artifact_path=path,
                    engine_fingerprint=self.engine.fingerprint)
                self.attestations.hold_weight(env)
                att_envs[sid] = env
            self.deployment = make_deployment_manifest(
                self.sk, node_id=self.chain.node_id,
                operator_domain=os.environ.get("JJDAI_OPERATOR_DOMAIN",
                                               "jj-dai.org"),
                jurisdiction=os.environ.get("JJDAI_JURISDICTION", "UA"),
                engine_fingerprint=self.engine.fingerprint,
                substrate_attestations=att_envs,
                adapter_ids=list(self.adapters))
            self.attestations.hold_deployment(self.deployment)
            with self._lock:
                self.chain.append(
                    "ATTESTATION",
                    response=self.deployment,      # full bundle, committed
                    semantic_digest={
                        "deployment_hash": H_hex(canonical(
                            self.deployment["body"])),
                        "substrates": {
                            s: {"artifact_hash": a["body"]["artifact_hash"],
                                "binding": a["body"]["binding"]}
                            for s, a in att_envs.items()}},
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                            time.gmtime()))
        # ---- external anchoring (v0.5.1) -------------------------------- #
        self.anchor_log = AnchorLog(anchor_store_path) \
            if (anchor_backends or anchor_store_path) else None
        self.anchor_scheduler = None
        if anchor_backends:
            self.anchor_scheduler = AnchorScheduler(
                self.chain, anchor_backends,
                self.anchor_log or AnchorLog(None), lock=self.chain.lock)
            if self.anchor_log is None:
                self.anchor_log = self.anchor_scheduler.log
        # ---- security-alpha (v0.5.5) ------------------------------------ #
        self.operator_cns = set(operator_cns or [])
        self.metrics = {"requests_total": {}, "responses_429_total": 0,
                        "challenge_rounds_total": 0,
                        "tasks_terminal_total": {}}
        self._metrics_lock = threading.Lock()
        self.challenge = None
        if challenge_windows:
            cw, rw = challenge_windows
            self.challenge = ChallengeRound(
                self.chain, registry=None,
                fraud_log_path=fraud_log_path,
                commit_window=cw, reveal_window=rw)
        # ---- rate limiter (v0.5.4) -------------------------------------- #
        self.rate_limiter = RateLimiter(rate_limits, chain=self.chain) \
            if rate_limits else None
        # ---- authz + revocation + metrics (v0.5.5) ---------------------- #
        self.authz = authz
        self.revoked_serials = set(revoked_serials or set())
        self.started_at = time.time()
        self.metrics = {"requests_total": 0, "denied_authz_total": 0,
                        "rate_limited_total": 0, "revoked_rejected_total": 0,
                        "tasks_total": 0, "challenge_rounds_total": 0}
        if self.challenge is None:
            self.challenge = ChallengeRound(
                self.chain, registry=None,
                fraud_log_path=(log_path + ".fraud.jsonl")
                if log_path else None)
        # ---- Being Composition Runtime (v0.5.3) ------------------------- #
        # The organism over the daemon's OWN identity, witness and governor
        # (audit gate 1: one BeingIdentity, one Witness for every organ).
        self.being = None
        if being_profile:
            import core.router as _R
            from core.router import RouteObject as _RO
            sub = self.substrates[0] if self.substrates else "sha256:base-A"
            topics = ["_generalist"]
            engines = {
                "n-gen": _R._mk_node("n-gen", sub, topics, origin="UA",
                                     noise=0.05),
                "n-v1": _R._mk_node("n-v1", sub, topics, origin="KR"),
                "n-v2": _R._mk_node("n-v2", sub, topics, origin="EE"),
            }
            objects = [_RO("m:gen", "generalist", "_generalist", "n-gen"),
                       _RO("m:v1", "generalist", "_generalist", "n-v1"),
                       _RO("m:v2", "generalist", "_generalist", "n-v2")]
            self.being = BeingRuntime(
                sk=self.sk, chain=self.chain, being_id=self.being_id,
                governor=self.governor,
                workspace=being_workspace,
                profile=being_profile,
                route_objects=objects, engines=engines,
                provenance=being_provenance,
                topics={"_generalist": []},
                max_per_group=2,           # shared frozen substrate model
                journal_dir=being_journal_dir,
                lock=self._lock)
            self.challenge.registry = self.being.registry

    # ---- TLS-aware peer HTTP (v0.5.1) ----------------------------------- #
    def _urlopen(self, req, timeout: float):
        import urllib.request
        if req.full_url.startswith("https://"):
            if self.client_ssl is None:
                raise OSError("https peer configured but no --peer-ca / "
                              "client TLS material supplied")
            return urllib.request.urlopen(req, timeout=timeout,
                                          context=self.client_ssl)
        return urllib.request.urlopen(req, timeout=timeout)

    # ---- replication (v0.5, P1/M6) ------------------------------------- #
    def signed_root(self) -> dict:
        # UNDER THE NODE LOCK (v0.5 drop 6): count, head_hash and root are
        # three reads of the same chain — an append between them produced a
        # signed envelope whose fields never coexisted. The origin must
        # never sign an internally inconsistent root.
        with self._lock:
            return make_signed_root(self.chain, self.sk)

    def receive_root(self, env) -> tuple:
        """Peer pushed its root. Store durably; ack only what we stored.
        Divergence evidence is retained and reported, never acked.

        v0.5 drop 6: a STORED root is WITNESSED on this node's own chain as
        a PEER_ROOT record — the issuer-side checkpoint of the entanglement
        cross-link. The response also names what this receiver wants next:
        a consistency proof linking the new root to the previous held
        checkpoint, and the first segment gap toward full record coverage."""
        if not isinstance(env, dict):
            return 400, {"error": "400 BAD_ENVELOPE"}
        if self.require_admission:
            origin = (env.get("body") or {}).get("node_id")
            if not self.peer_registry.is_friend(origin):
                return 403, {"error": "403 FOE",
                             "detail": "origin is not an admitted active peer"}
        status, reason = self.replica_store.accept(env)
        if status in ("stored", "duplicate"):
            resp = {"status": status, "ack": make_ack(env, self.sk)}
            b = env["body"]
            if status == "stored":
                with self._lock:
                    self.chain.append(
                        "PEER_ROOT",
                        semantic_digest={"origin": b["node_id"],
                                         "count": b["count"],
                                         "root": b["root"],
                                         "root_alg": b.get("root_alg")},
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                time.gmtime()))
            wanted = self.replica_store.consistency_wanted(b["node_id"])
            if wanted:
                resp["consistency_wanted"] = wanted
            gap = self.segment_store.next_gap(b["node_id"], b["count"])
            if gap:
                resp["segments_wanted"] = gap
            return 200, resp
        if status == "divergence":
            return 409, {"status": status, "detail": reason,
                         "evidence": self.replica_store.divergence(
                             env["body"]["node_id"])[-1]}
        if status == "stale":
            return 200, {"status": status, "detail": reason}
        return 400, {"status": status, "detail": reason}

    def receive_segment(self, env) -> tuple:
        """Peer pushed a witness segment. Verify, store durably, report
        coverage; conflicting signed records become durable evidence."""
        if not isinstance(env, dict):
            return 400, {"error": "400 BAD_ENVELOPE"}
        if self.require_admission:
            origin = (env.get("body") or {}).get("node_id")
            if not self.peer_registry.is_friend(origin):
                return 403, {"error": "403 FOE",
                             "detail": "origin is not an admitted active peer"}
        status, reason = self.segment_store.accept(env)
        if status in ("stored", "duplicate"):
            origin = env["body"]["node_id"]
            held = self.replica_store.latest(origin)
            count = held["body"]["count"] if held else env["body"]["end"]
            return 200, {"status": status, "detail": reason,
                         "coverage": self.segment_store.coverage(origin),
                         "next_gap": self.segment_store.next_gap(origin, count)}
        if status == "divergence":
            return 409, {"status": status, "detail": reason,
                         "evidence": self.segment_store.divergence(
                             env["body"]["node_id"])[-1]}
        return 400, {"status": status, "detail": reason}

    def receive_consistency(self, env) -> tuple:
        """Peer pushed a signed consistency proof for its own chain.
        A failing proof under a valid signature is durable evidence."""
        if not isinstance(env, dict):
            return 400, {"error": "400 BAD_ENVELOPE"}
        status, reason = self.replica_store.record_consistency(env)
        if status == "consistent":
            origin = (env.get("body") or {}).get("node_id")
            return 200, {"status": status,
                         "verified_prefix":
                             self.replica_store.verified_prefix(origin)}
        if status == "inconsistent":
            return 409, {"status": status, "detail": reason,
                         "evidence": self.replica_store.divergence(
                             (env.get("body") or {}).get("node_id"))[-1]}
        return 400, {"status": status, "detail": reason}

    def serve_segment(self, start: int, end: int) -> tuple:
        """Serve a signed segment of THIS node's own chain."""
        try:
            with self._lock:
                env = make_segment(self.chain, self.sk, start, end)
        except SegmentError as e:
            return 400, {"error": "400 BAD_RANGE", "detail": str(e)}
        return 200, env

    def serve_consistency(self, old_count: int) -> tuple:
        """Serve a signed CT-style consistency proof from old_count to the
        current tree of THIS node's own chain."""
        try:
            with self._lock:
                env = make_consistency(self.chain, self.sk, old_count)
        except ReplicationError as e:
            return 400, {"error": "400 BAD_RANGE", "detail": str(e)}
        return 200, env

    def push_to_peers(self) -> dict:
        """Push own signed root to all peers, collect acks, assemble a
        quorum receipt, and append an ANCHOR_QUORUM record once per count.
        The push is an act of the NODE (INV-9 v1.1: the Witness itself is
        non-executive); the chain only records the achieved quorum."""
        import urllib.request
        env = self.signed_root()
        count, root = env["body"]["count"], env["body"]["root"]
        results = {}
        for peer in self.peers:
            try:
                req = urllib.request.Request(
                    peer.rstrip("/") + "/replicate/root",
                    data=json.dumps(env).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST")
                with self._urlopen(req, timeout=5) as r:
                    resp = json.loads(r.read().decode())
            except OSError as e:
                results[peer] = {"status": "unreachable", "detail": str(e)}
                continue
            results[peer] = {"status": resp.get("status")}
            ack = resp.get("ack")
            if ack:
                ok, why = self.quorum.add_ack(ack)
                results[peer]["ack_valid"] = ok
                if not ok:
                    results[peer]["ack_error"] = why
            # ---- drop 6: answer what the receiver asked for ----------- #
            wanted = resp.get("consistency_wanted")
            if wanted:
                try:
                    cons = self.serve_consistency(wanted["old"])[1]
                    req = urllib.request.Request(
                        peer.rstrip("/") + "/replicate/consistency",
                        data=json.dumps(cons).encode(),
                        headers={"Content-Type": "application/json"},
                        method="POST")
                    with self._urlopen(req, timeout=5) as r:
                        results[peer]["consistency"] = \
                            json.loads(r.read().decode()).get("status")
                except (OSError, KeyError, ValueError) as e:
                    results[peer]["consistency_error"] = str(e)
            gap = resp.get("segments_wanted")
            pushed_segments = 0
            # bounded catch-up: at most 8 chunks per push cycle so a fresh
            # receiver drains a long history across cycles, never blocking
            # one push forever.
            while gap and pushed_segments < 8:
                try:
                    code, seg = self.serve_segment(gap["start"], gap["end"])
                    if code != 200:
                        results[peer]["segment_error"] = seg
                        break
                    req = urllib.request.Request(
                        peer.rstrip("/") + "/replicate/segment",
                        data=json.dumps(seg).encode(),
                        headers={"Content-Type": "application/json"},
                        method="POST")
                    with self._urlopen(req, timeout=10) as r:
                        sresp = json.loads(r.read().decode())
                    pushed_segments += 1
                    gap = sresp.get("next_gap")
                except (OSError, KeyError, ValueError) as e:
                    results[peer]["segment_error"] = str(e)
                    break
            if pushed_segments:
                results[peer]["segments_pushed"] = pushed_segments
        receipt = self.quorum.receipt(count, root)
        anchored = False
        # RECURSION GUARD: the anchor record itself grows the chain, so a
        # naive rule would anchor every push forever. Anchor only when the
        # records beyond the last covered count contain something OTHER
        # than ANCHOR_QUORUM records.
        substantive = any(r["kind"] != "ANCHOR_QUORUM"
                          for r in self.chain.records[self._anchor_covered:])
        if receipt and count not in self.receipts and substantive:
            ok, why = verify_quorum_receipt(receipt,
                                            origin_node=self.chain.node_id,
                                            k=self.quorum_k)
            if ok:
                self.receipts[count] = receipt
                if self.receipt_path:
                    from jjdai.durable import durable_append
                    durable_append(self.receipt_path, receipt)
                # UNDER THE LOCK (v0.5 drop 6): this append raced INFER
                # appends before — one chain, serialized appends, no
                # exceptions for bookkeeping.
                with self._lock:
                    self.chain.append(
                        "ANCHOR_QUORUM",
                        # full receipt goes under a hiding commitment
                        # (openable with the local salt for audit)...
                        response=receipt,
                        # ...while the auditable summary is PUBLIC:
                        semantic_digest={
                            "count": count, "root": root, "k": self.quorum_k,
                            "receivers": sorted({a["body"]["receiver_node"]
                                                 for a in receipt["acks"]})})
                anchored = True
                self._anchor_covered = count
        return {"count": count, "root": root, "peers": results,
                "quorum_reached": receipt is not None,
                "anchored": anchored,
                "receipts_held": sorted(self.receipts)}

    # ---- IFF + entanglement (v0.5, P1) --------------------------------- #
    def _fresh_beacon(self):
        """The beacon to embed into the next witness append, or None.
        STRICT policy: refuse executive appends without a fresh beacon of
        at least entangle_min distinct issuers (anteriority is mandatory).
        RELAXED (default): embed what we have; absence is visible."""
        b = self.current_beacon
        fresh = (b is not None
                 and time.time() - b.get("min_issued_at", 0) <= self.entangle_max_age_s
                 and b["distinct_issuers"] >= self.entangle_min)
        if fresh:
            return b
        if self.entangle_strict:
            raise EntanglementError(
                "strict entanglement: no fresh beacon "
                f"(need >= {self.entangle_min} issuer(s) within "
                f"{self.entangle_max_age_s}s); pull salts first")
        return None

    def pull_salts(self) -> dict:
        """Fetch fresh witnessed salts from configured salt peers and set
        the current beacon. An act of the NODE (INV-9 intact).

        v0.5 drop 6: the request carries this node's SIGNED root — the
        recipient's own commitment to its chain length at request time.
        The issuer verifies and embeds it: the cryptographic cross-link."""
        import urllib.request
        envs, errors = [], {}
        payload = {"recipient_node": self.chain.node_id,
                   "recipient_root": self.signed_root()}
        for peer in self.salt_peers:
            try:
                wrapped = make_signed_request(self.sk, path="/entangle/salt",
                                              payload=payload)
                req = urllib.request.Request(
                    peer.rstrip("/") + "/entangle/salt",
                    data=json.dumps(wrapped).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST")
                with self._urlopen(req, timeout=5) as r:
                    resp = json.loads(r.read().decode())
                envs.append(resp["salt"])
            except (OSError, KeyError, ValueError) as e:
                errors[peer] = str(e)
        result = {"requested": len(self.salt_peers), "received": len(envs),
                  "errors": errors}
        if envs:
            try:
                self.current_beacon = beacon_from(
                    envs, recipient_node=self.chain.node_id)
                result["beacon"] = {
                    "distinct_issuers": self.current_beacon["distinct_issuers"],
                    "taken_at": self.current_beacon["taken_at"]}
            except EntanglementError as e:
                result["beacon_error"] = str(e)
        return result

    def issue_salt(self, envelope) -> tuple:
        """Serve a witnessed salt. When admission is required, only
        admitted active peers may draw salts (IFF layers 2+3).
        A recipient_root in the payload (drop 6) is verified and embedded —
        the cross-link; an invalid root refuses the issuance outright."""
        if self.require_admission:
            ok, who = self.authenticator.check(envelope,
                                               path="/entangle/salt")
            if not ok:
                return 403, {"error": "403 FOE", "detail": who}
            recipient = who
            payload = (envelope or {}).get("payload") or {}
        else:
            payload = (envelope or {}).get("payload") or envelope or {}
            recipient = payload.get("recipient_node", "anonymous")
        recipient_root = payload.get("recipient_root")
        try:
            with self._lock:
                env = self.beacon_source.issue(
                    recipient, recipient_root=recipient_root)
        except EntanglementError as e:
            return 400, {"error": "400 BAD_RECIPIENT_ROOT", "detail": str(e)}
        return 200, {"salt": env}

    # ---- capability descriptor (NECS C1.2) ----
    def capabilities(self) -> dict:
        return {
            "engine": "jjdai-tier1-daemon", "engine_version": "0.1",
            "backend": self.engine.backend, "profile": self.profile,
            "substrates": self.substrates, "adapters": list(self.adapters),
            "max_context": 65536,
            "determinism_level": self.engine.determinism_level,
            "engine_fingerprint": self.engine.fingerprint,
            "witness": {
                "sig_alg": "ed25519",
                "node_id": self.chain.node_id,
                "pubkey": self.sk.public.hex(),
                "anchor": "local",
            },
            "being_id": self.being_id,
            "contained": self.governor.is_contained(self.being_id),
            "being_runtime": (self.being.profile if self.being else None),
            "authz": (self.authz.default if self.authz else None),
            "rate_limited": self.rate_limiter is not None,
            "revoked_serials": len(self.revoked_serials),
            "challenge": bool(self.challenge),
            "attested_substrates": sorted(
                (self.deployment or {}).get("body", {})
                .get("substrates", {})) if self.deployment else [],
            "require_attestation": self.require_attestation,
        }

    # ---- JII handler (NECS C1.3–C1.8) ----
    def handle(self, request: dict) -> tuple[int, dict]:
        # TYPED BOUNDARY (v0.3.1): validate type, size, range, enum and reject
        # unknown fields BEFORE any organ sees the request. "Present" is not a
        # contract; this is.
        try:
            request = InferenceRequest.validate(request, "InferenceRequest")
        except ValidationError as e:
            body = {"error": "400 BAD_ENVELOPE", "detail": e.as_dict()}
            if e.code == "missing":         # keep the legacy field contract
                body["missing"] = e.path.rsplit(".", 1)[-1]
            return 400, body
        if request["substrate_id"] not in self.substrates:
            return 404, {"error": "404 SUBSTRATE_UNKNOWN"}
        for aid in request["adapter_ids"]:
            if aid not in self.adapters:
                return 404, {"error": "404 ADAPTER_UNKNOWN"}
            if self.adapters[aid] != request["substrate_id"]:
                return 422, {"error": "422 PROVENANCE_MISMATCH"}
        # C1.8 / C3 — FAIL CLOSED: no witness, no inference, NO output field.
        if not self.witness_up:
            return 503, {"error": "503 WITNESS_UNAVAILABLE"}
        # Article 25 governor: inference is an executive act. If the Being is
        # contained, the hand is severed — 423 CONTAINED, no output. (Pure
        # thinking / defense scopes are exercised through /v1/score-style and
        # consular paths, not this executive generate endpoint.)
        if not self.governor.permits(self.being_id, "tools.side_effect"):
            return 423, {"error": "423 CONTAINED",
                         "being_id": self.being_id,
                         "detail": "executive systems severed; consular "
                                   "channel and Witness remain open"}

        sampling = dict(request["sampling"])    # never silently mutated (C1.7)
        # ENTANGLEMENT GATE — BEFORE any inference. In strict mode a node
        # must not even call the engine without a fresh anteriority beacon;
        # gating after generate() would leak computation and side effects.
        try:
            beacon = self._fresh_beacon()
        except EntanglementError as e:
            return 503, {"error": "503 ENTANGLEMENT_REQUIRED",
                         "detail": str(e)}
        try:
            text = self.engine.generate(request["messages"], sampling,
                                        request["adapter_ids"])
        except Exception as e:                  # engine down => fail closed
            return 503, {"error": "503 ENGINE_UNAVAILABLE", "detail": str(e)}
        output = {"role": "assistant", "content": text}
        provenance = {
            "substrate_id": request["substrate_id"],
            "adapter_ids": request["adapter_ids"],
            "engine_fingerprint": self.engine.fingerprint,
            "determinism_level": self.engine.determinism_level,
            "sampling": sampling,
            "hardware_class": self.engine.backend,
        }
        with self._lock:                        # one chain, serialized appends
            receipt = self.chain.append(
                "INFER",
                request=request,                # -> hiding commitment only
                response=output,                # -> hiding commitment only
                provenance=provenance,
                semantic_digest=semantic_digest(text),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                entanglement=beacon,
            )
        return 200, {
            "request_id": request["request_id"],
            "nonce": request["nonce"],
            "champion_context": request.get("champion_context"),
            "output": output,
            "provenance": provenance,
            "witness_receipt": receipt,
        }

    def handle_score(self, request: dict) -> tuple[int, dict]:
        """Verifier role (generator/verifier asymmetry, locked decision #5):
        teacher-force the candidate tokens and attest per-token reachability
        under the COMMITTED sampling params. The verdict itself is witnessed."""
        if "tokens" not in request:
            return 400, {"error": "400 BAD_ENVELOPE", "missing": "tokens"}
        try:
            request = InferenceRequest.validate(request, "InferenceRequest")
        except ValidationError as e:
            body = {"error": "400 BAD_ENVELOPE", "detail": e.as_dict()}
            if e.code == "missing":
                body["missing"] = e.path.rsplit(".", 1)[-1]
            return 400, body
        if request["substrate_id"] not in self.substrates:
            return 404, {"error": "404 SUBSTRATE_UNKNOWN"}
        for aid in request["adapter_ids"]:
            if aid not in self.adapters:
                return 404, {"error": "404 ADAPTER_UNKNOWN"}
            if self.adapters[aid] != request["substrate_id"]:
                return 422, {"error": "422 PROVENANCE_MISMATCH"}
        if not self.witness_up:
            return 503, {"error": "503 WITNESS_UNAVAILABLE"}
        try:
            raw = self.engine.score(request["messages"], request["tokens"],
                                    dict(request["sampling"]),
                                    request["adapter_ids"])
        except Exception as e:
            return 503, {"error": "503 ENGINE_UNAVAILABLE", "detail": str(e)}
        # FULL VERDICT BINDING (v0.3.1.2): seal into a signed, context-bound
        # envelope — verifier identity + whole scoring context + nonce, under
        # this node's Ed25519 key.
        verdict = seal_verdict(raw, request=request, verifier_sk=self.sk,
                               verifier_node_id=self.chain.node_id)
        with self._lock:
            receipt = self.chain.append(
                "INFER",
                request=request,
                response=verdict,
                provenance={"role": "verifier",
                            "engine_fingerprint": self.engine.fingerprint,
                            "determinism_level": self.engine.determinism_level,
                            "sampling": dict(request["sampling"])},
                semantic_digest=semantic_digest(json.dumps(verdict["reachable"])),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
        return 200, {"request_id": request["request_id"],
                     "nonce": request["nonce"],
                     "verdict": verdict,
                     "witness_receipt": receipt}

    # ---- witness export (bodies only — salts stay local, off-chain) ----
    def chain_export(self) -> dict:
        with self._lock:
            return {"node_id": self.chain.node_id,
                    "pubkey": self.sk.public.hex(),
                    "head": self.chain.head_hash(),
                    "records": list(self.chain.records)}

    def anchor(self) -> dict:
        # v0.5.1: when an external AnchorScheduler is configured it OWNS the
        # anchoring round (local/peer-quorum/OTS backends + ANCHOR_EXTERNAL
        # record); the pre-v0.5.1 in-memory LocalAnchor path remains for
        # bare nodes so the legacy contract keeps working.
        if self.anchor_scheduler is not None:
            return self.anchor_scheduler.anchor_now()
        with self._lock:
            return self.chain.anchor_root()


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #

class RateLimiter:
    """Per-identity, per-class token buckets with witnessed abuse (v0.5.4).

    Config: {"infer": (limit, window_s), "task": (...), "read": (...),
    "write": (...)}. Every request is keyed by caller identity (client
    address in this reference; a peer's verified node id when the request
    carries one) and endpoint class. Over-budget requests get 429 with
    Retry-After — refusal is IMMEDIATE and cheap, before any heavy work.

    Systematic abuse becomes EVIDENCE: after `abuse_threshold` rejections
    of one key within one window, ONE (and only one — the limiter must
    never become a witness-flooding vector) RATE_LIMIT record lands on the
    chain, carrying the key's hash, the class and the rejection count."""

    ABUSE_THRESHOLD = 3

    def __init__(self, limits: dict, chain=None, now_fn=time.time):
        self.limits = dict(limits)
        self.chain = chain
        self._now = now_fn
        self._lock = threading.Lock()
        self._windows: dict = {}   # (key, cls) -> [window_start, used, rejected, witnessed]

    def check(self, key: str, cls: str):
        """-> (allowed: bool, retry_after_s: float|None)"""
        lim = self.limits.get(cls)
        if lim is None:
            return True, None
        limit, window = lim
        now = self._now()
        with self._lock:
            st = self._windows.get((key, cls))
            if st is None or now - st[0] >= window:
                st = [now, 0, 0, False]
                self._windows[(key, cls)] = st
            if st[1] < limit:
                st[1] += 1
                return True, None
            st[2] += 1
            retry = max(0.0, st[0] + window - now)
            if st[2] >= self.ABUSE_THRESHOLD and not st[3]                     and self.chain is not None:
                st[3] = True
                with self.chain.lock:
                    self.chain.append(
                        "RATE_LIMIT",
                        semantic_digest={
                            "key_hash": semantic_digest(key),
                            "cls": cls, "limit": limit, "window_s": window,
                            "rejected": st[2],
                            "note": "systematic over-budget traffic; one "
                                    "record per offender per window"})
            return False, retry


def make_handler(node: Node):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, obj: dict, headers: dict = None):
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for hk, hv in (headers or {}).items():
                self.send_header(hk, hv)
            self.end_headers()
            self.wfile.write(body)

        _RL_CLASSES = (("/v1/messages", "infer"), ("/v1/tasks", "task"),
                       ("/replicate/", "write"), ("/witness/anchor", "write"))

        def _peer_identity(self):
            """(-> common_name|None, serial_hex|None) from the mTLS cert.
            Trusted because ssl already verified the chain to our CA."""
            try:
                cert = self.connection.getpeercert()
            except Exception:
                return None, None
            if not cert:
                return None, None
            cn = None
            for rdn in cert.get("subject", ()):
                for k, v in rdn:
                    if k == "commonName":
                        cn = v
            return cn, cert.get("serialNumber")

        def _authz_gate(self) -> bool:
            """True = proceed; False = already answered 401/403. Revocation
            is checked FIRST: a revoked cert is nobody, whatever its CN."""
            cn, serial = self._peer_identity()
            if serial and serial.lower() in node.revoked_serials:
                node.metrics["revoked_rejected_total"] += 1
                self._send(401, {"error": "401 CERT_REVOKED",
                                 "detail": "this client certificate has "
                                           "been revoked"})
                return False
            if node.authz is None:
                return True
            role = node.authz.role_of(cn)
            ok, rule = node.authz.check(self.path, role)
            if not ok:
                node.metrics["denied_authz_total"] += 1
                self._send(403, {"error": "403 FORBIDDEN", "role": role,
                                 "rule": rule,
                                 "detail": f"role {role!r} may not access "
                                           f"{self.path!r}"})
                return False
            return True

        def _rate_gate(self) -> bool:
            """True = proceed; False = already answered 429."""
            if node.rate_limiter is None:
                return True
            cls = "read"
            for prefix, c in self._RL_CLASSES:
                if self.path.startswith(prefix):
                    cls = c
                    break
            key = self.client_address[0]
            ok, retry = node.rate_limiter.check(key, cls)
            if ok:
                return True
            self._send(429, {"error": "429 RATE_LIMITED", "class": cls,
                             "retry_after_s": round(retry, 3),
                             "detail": "budget exhausted for this identity "
                                       "and endpoint class; systematic "
                                       "abuse is witnessed"},
                       headers={"Retry-After": str(max(1, int(retry + 0.999)))})
            return False

        def _read_json(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n) if n else b"{}"
            try:
                return json.loads(raw.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None

        def do_GET(self):
            node.metrics["requests_total"] += 1
            if not self._rate_gate():
                node.metrics["rate_limited_total"] += 1
                return
            if not self._authz_gate():
                return
            if self.path == "/healthz":
                return self._send(200, {"ok": True,
                    "uptime_s": round(time.time() - node.started_at, 1),
                    "node_id": node.chain.node_id,
                    "records": len(node.chain.records)})
            if self.path == "/metrics":
                # Prometheus text exposition — the operational eye on a node
                lines = ["# JJ DAI node metrics (v0.5.5)"]
                m = dict(node.metrics)
                m["witness_records"] = len(node.chain.records)
                m["uptime_seconds"] = round(time.time() - node.started_at, 1)
                if node.being is not None:
                    m["tasks_total"] = len(node.being.traces)
                for k, v in m.items():
                    lines.append(f"jjdai_{k} {v}")
                body = ("\n".join(lines) + "\n").encode()
                self.send_response(200)
                self.send_header("Content-Type",
                                 "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/capabilities":
                return self._send(200, node.capabilities())
            if self.path == "/witness/chain":
                return self._send(200, node.chain_export())
            if self.path == "/witness/head":
                exp = node.chain_export()
                return self._send(200, {"node_id": exp["node_id"],
                                        "head": exp["head"],
                                        "count": len(exp["records"])})
            if self.path == "/witness/root":
                return self._send(200, node.signed_root())
            if self.path.startswith("/witness/segment"):
                from urllib.parse import urlparse, parse_qs
                q = parse_qs(urlparse(self.path).query)
                try:
                    start = int(q.get("start", ["0"])[0])
                    end = int(q.get("end", [str(start + MAX_SEGMENT_RECORDS)])[0])
                except ValueError:
                    return self._send(400, {"error": "400 BAD_RANGE"})
                code, resp = node.serve_segment(start, end)
                return self._send(code, resp)
            if self.path.startswith("/witness/consistency"):
                from urllib.parse import urlparse, parse_qs
                q = parse_qs(urlparse(self.path).query)
                try:
                    old = int(q.get("old", ["0"])[0])
                except ValueError:
                    return self._send(400, {"error": "400 BAD_RANGE"})
                code, resp = node.serve_consistency(old)
                return self._send(code, resp)
            if self.path == "/peers":
                return self._send(200, {"friends": node.peer_registry.friends(),
                                        "require_admission": node.require_admission})
            if self.path == "/replicate/status":
                return self._send(200, {
                    "reconcile": reconcile(node.signed_root(),
                                           node.replica_store),
                    "peers_configured": node.peers,
                    "quorum_k": node.quorum_k,
                    "receipts_held": sorted(node.receipts),
                    "anchor_covered": node._anchor_covered,
                    "verified_prefix": {
                        o: node.replica_store.verified_prefix(o)
                        for o in node.replica_store.origins()},
                    "segment_coverage": {
                        o: node.segment_store.coverage(o)
                        for o in node.replica_store.origins()}})
            if self.path.startswith("/v1/tasks/"):
                if node.being is None:
                    return self._send(404, {"error": "404 NO_BEING_RUNTIME"})
                tid = self.path[len("/v1/tasks/"):]
                tr = node.being.trace(tid)
                if tr is None:
                    return self._send(404, {"error": "404 UNKNOWN_TASK",
                                            "task_id": tid})
                return self._send(200, {"trace": tr.as_dict()})
            if self.path == "/attestation":
                # Transparency: the deployment manifest and its weight
                # attestations are PUBLIC — anyone can check what this node
                # claims to serve and hold it to that claim.
                if node.deployment is None:
                    return self._send(404, {
                        "error": "404 NO_ATTESTATION",
                        "detail": "node booted without --substrate-artifacts",
                        "require_attestation": node.require_attestation})
                return self._send(200, {"deployment": node.deployment,
                                        "require_attestation":
                                            node.require_attestation})
            if self.path == "/witness/anchors":
                if node.anchor_log is None:
                    return self._send(200, {"receipts": [],
                                            "backends": [],
                                            "detail": "no external anchoring "
                                                      "configured"})
                return self._send(200, {
                    "receipts": node.anchor_log.receipts[-50:],
                    "backends": [b.name for b in
                                 (node.anchor_scheduler.backends
                                  if node.anchor_scheduler else [])]})
            if self.path == "/v1/containment":
                # Transparency (Invariant III): the containment state of the
                # Being this node governs is public and independently checkable.
                bid = node.being_id
                c = node.governor.case(bid)
                return self._send(200, {
                    "being_id": bid,
                    "state": node.governor.state(bid),
                    "contained": node.governor.is_contained(bid),
                    "provisional_low_trust": bool(c and c.provisional_low_trust),
                    "snapshot_hash": node.governor.snapshot_hash()})
            return self._send(404, {"error": "404 NOT_FOUND"})

        def do_POST(self):
            node.metrics["requests_total"] += 1
            if not self._rate_gate():
                node.metrics["rate_limited_total"] += 1
                return
            if not self._authz_gate():
                return
            if self.path == "/v1/messages":
                req = self._read_json()
                if req is None:
                    return self._send(400, {"error": "400 BAD_ENVELOPE",
                                            "missing": "valid-json-body"})
                code, resp = node.handle(req)
                return self._send(code, resp)
            if self.path == "/v1/score":
                req = self._read_json()
                if req is None:
                    return self._send(400, {"error": "400 BAD_ENVELOPE",
                                            "missing": "valid-json-body"})
                code, resp = node.handle_score(req)
                return self._send(code, resp)
            if self.path == "/peers/hello":
                bundle = self._read_json()
                try:
                    nid = node.peer_registry.register(bundle or {})
                except PeerError as e:
                    return self._send(403, {"error": "403 FOE",
                                            "detail": str(e)})
                return self._send(200, {"admitted": nid,
                                        "friends": node.peer_registry.friends()})
            if self.path == "/entangle/salt":
                envelope = self._read_json()
                code, resp = node.issue_salt(envelope)
                return self._send(code, resp)
            if self.path == "/entangle/pull":
                return self._send(200, node.pull_salts())
            if self.path == "/challenge/open":
                env = self._read_json() or {}
                try:
                    rnd = node.challenge.open(
                        env["round_id"], env["transcript_hash"],
                        env["eligible"], int(env["k"]))
                    node.metrics["challenge_rounds_total"] += 1
                except (KeyError, Exception) as e:
                    return self._send(400, {"error": "400 CHALLENGE_OPEN",
                                            "detail": str(e)})
                return self._send(200, {"round_id": rnd["round_id"],
                    "alpha": rnd["alpha"],
                    "commit_deadline": rnd["commit_deadline"],
                    "reveal_deadline": rnd["reveal_deadline"]})
            if self.path == "/challenge/seat":
                env = self._read_json() or {}
                try:
                    won = node.challenge.claim_seat(
                        env["round_id"], env["verifier_id"], env["proof"])
                except Exception as e:
                    return self._send(400, {"error": "400 CHALLENGE_SEAT",
                                            "detail": str(e)})
                return self._send(200, {"won": won})
            if self.path == "/challenge/commit":
                env = self._read_json() or {}
                try:
                    idx = node.challenge.commit(env["round_id"],
                        env["verifier_id"], env["commitment"])
                except Exception as e:
                    return self._send(400, {"error": "400 CHALLENGE_COMMIT",
                                            "detail": str(e)})
                return self._send(200, {"witness_index": idx})
            if self.path == "/challenge/reveal":
                env = self._read_json() or {}
                try:
                    node.challenge.reveal(env["round_id"],
                        env["verifier_id"], env["verdict"], env["salt"])
                except Exception as e:
                    return self._send(400, {"error": "400 CHALLENGE_REVEAL",
                                            "detail": str(e)})
                return self._send(200, {"revealed": True})
            if self.path == "/challenge/resolve":
                env = self._read_json() or {}
                try:
                    res = node.challenge.resolve(env["round_id"])
                except Exception as e:
                    return self._send(400, {"error": "400 CHALLENGE_RESOLVE",
                                            "detail": str(e)})
                return self._send(200, res)
            if self.path == "/v1/tasks":
                if node.being is None:
                    return self._send(404, {
                        "error": "404 NO_BEING_RUNTIME",
                        "detail": "start the daemon with --being-profile"})
                env = self._read_json()
                task = (env or {}).get("task") or env or {}
                trace = node.being.handle_task(task)
                return self._send(200, {"trace": trace.as_dict()})
            if self.path == "/replicate/root":
                env = self._read_json()
                code, resp = node.receive_root(env)
                return self._send(code, resp)
            if self.path == "/replicate/segment":
                env = self._read_json()
                code, resp = node.receive_segment(env)
                return self._send(code, resp)
            if self.path == "/replicate/consistency":
                env = self._read_json()
                code, resp = node.receive_consistency(env)
                return self._send(code, resp)
            if self.path == "/replicate/push":
                return self._send(200, node.push_to_peers())
            if self.path == "/witness/anchor":
                return self._send(200, node.anchor())
            if self.path == "/admin/witness":
                if not node.allow_test_hooks:
                    return self._send(403, {"error": "403 TEST_HOOKS_DISABLED"})
                req = self._read_json() or {}
                node.witness_up = bool(req.get("up", True))
                return self._send(200, {"witness_up": node.witness_up})
            if self.path == "/admin/containment":
                if not node.allow_test_hooks:
                    return self._send(403, {"error": "403 TEST_HOOKS_DISABLED"})
                req = self._read_json() or {}
                bid = node.being_id
                if req.get("contain"):
                    node.governor.contain(
                        bid, evidence_refs=req.get("evidence_refs", ["hook"]),
                        reason=req.get("reason", "test hook"),
                        topic=req.get("topic", "global"),
                        initiator=req.get("initiator", node.chain.node_id))
                elif req.get("release"):
                    # deterministic release for the harness: reversing via the
                    # normal false-trigger path requires a resolver; the hook
                    # emits a direct release so the executive gate re-opens.
                    node.governor._emit({"ev": "release", "t": time.time(),
                                         "being_id": bid,
                                         "grounds": "test_hook_release",
                                         "slash_target": None})
                return self._send(200, {
                    "being_id": bid,
                    "state": node.governor.state(bid),
                    "contained": node.governor.is_contained(bid)})
            return self._send(404, {"error": "404 NOT_FOUND"})

        def log_message(self, fmt, *args):     # quiet by default
            if os.environ.get("JJDAI_DAEMON_VERBOSE"):
                sys.stderr.write("[%s] %s\n" % (node.name, fmt % args))

    return Handler


def main(argv=None):
    ap = argparse.ArgumentParser(description="JJ DAI Tier-1 node daemon")
    ap.add_argument("--port", type=int, default=8471)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--name", default="tier1-node")
    ap.add_argument("--profile", choices=("A", "B"), default="B")
    ap.add_argument("--substrates", default='["sha256:base-A"]',
                    help="JSON list of served substrate ids")
    ap.add_argument("--adapters", default="{}",
                    help='JSON map adapter_id -> base_compat_tag (Profile A)')
    ap.add_argument("--fingerprint", default="fp-tier1-0001")
    ap.add_argument("--engine", choices=("hash", "sglang", "dwarfstar"),
                    default="hash")
    ap.add_argument("--engine-url", default="http://127.0.0.1:30000",
                    help="SGLang server base URL (when --engine sglang)")
    ap.add_argument("--adapter-paths", default="{}",
                    help='JSON map adapter_id -> lora_path name in SGLang')
    ap.add_argument("--engine-determinism", default=None,
                    choices=("attested", "reproducible"),
                    help="override (CI mock is reproducible; GPU is attested)")
    ap.add_argument("--log", default=None, help="JSONL witness persistence path")
    ap.add_argument("--node-keystore", default=None,
                    help="path to the encrypted Ed25519 keystore holding this "
                         "node's PERSISTENT identity (created on first boot)")
    ap.add_argument("--keystore-passphrase-env", default="JJDAI_KEYSTORE_PASSPHRASE",
                    help="name of the environment variable holding the "
                         "keystore passphrase (never passed on the CLI)")
    ap.add_argument("--allow-test-hooks", action="store_true",
                    help="enable /admin/* test hooks (loopback only, NEVER in "
                         "production)")
    ap.add_argument("--peers", default="",
                    help="comma-separated peer base URLs for witness "
                         "replication (e.g. http://127.0.0.1:8472)")
    ap.add_argument("--quorum", type=int, default=2,
                    help="distinct peer acks required for a quorum receipt")
    ap.add_argument("--replica-store", default=None,
                    help="JSONL path for durably storing PEER roots "
                         "(default: <log>.replicas.jsonl when --log is set)")
    ap.add_argument("--receipt-store", default=None,
                    help="JSONL path for own quorum receipts "
                         "(default: <log>.receipts.jsonl when --log is set)")
    ap.add_argument("--segment-store", default=None,
                    help="JSONL path for durably storing PEER witness "
                         "segments (default: <log>.segments.jsonl when "
                         "--log is set)")
    ap.add_argument("--replicate-interval", type=float, default=0.0,
                    help="seconds between automatic root pushes to peers "
                         "(0 = manual via POST /replicate/push)")
    ap.add_argument("--peer-registry", default=None,
                    help="JSONL path for the durable peer (IFF) registry")
    ap.add_argument("--admission-key", default=None,
                    help="node_id of the admission authority whose "
                         "countersignature admits peers (default: this "
                         "node itself — founding bootstrap)")
    ap.add_argument("--require-admission", action="store_true",
                    help="fail closed: replication roots and salt issuance "
                         "accepted only from admitted active peers")
    ap.add_argument("--salt-peers", default="",
                    help="comma-separated peer URLs to draw witnessed "
                         "entanglement salts from")
    ap.add_argument("--entangle-min", type=int, default=1,
                    help="minimum DISTINCT salt issuers per beacon "
                         "(collusion resistance: use m-of-n)")
    ap.add_argument("--entangle-strict", action="store_true",
                    help="refuse INFER appends without a fresh beacon")
    ap.add_argument("--entangle-max-age", type=float, default=300.0,
                    help="beacon freshness window in seconds")
    # ---- TLS / mTLS (v0.5.1) -------------------------------------------- #
    ap.add_argument("--tls-cert", default=None,
                    help="server certificate (PEM). With --tls-key, the "
                         "daemon serves HTTPS (TLS >= 1.2)")
    ap.add_argument("--tls-key", default=None, help="server private key (PEM)")
    ap.add_argument("--tls-ca", default=None,
                    help="CA bundle used to VERIFY CLIENT certificates "
                         "(mTLS); implies nothing by itself — see "
                         "--tls-require-client-cert")
    ap.add_argument("--tls-require-client-cert", action="store_true",
                    help="mTLS: refuse any connection without a client "
                         "certificate signed by --tls-ca (fail closed)")
    ap.add_argument("--peer-ca", default=None,
                    help="CA bundle used to verify PEER server certificates "
                         "when peers/salt-peers are https:// URLs")
    ap.add_argument("--client-cert", default=None,
                    help="client certificate presented to mTLS peers")
    ap.add_argument("--client-key", default=None,
                    help="client private key for --client-cert")
    # ---- weight attestation (v0.5.1) ------------------------------------ #
    ap.add_argument("--substrate-artifacts", default="{}",
                    help='JSON map substrate_id -> weight artifact path. '
                         'Artifacts are MEASURED at boot; a content-addressed '
                         'id whose bytes mismatch refuses the boot; the '
                         'signed DeploymentManifest is witnessed and served '
                         'at GET /attestation')
    ap.add_argument("--require-attestation", action="store_true",
                    help="fail closed: refuse to serve any substrate without "
                         "a measured artifact")
    ap.add_argument("--attestation-store", default=None,
                    help="JSONL path for attestations "
                         "(default: <log>.attest.jsonl when --log is set)")
    # ---- external anchoring (v0.5.1) ------------------------------------ #
    ap.add_argument("--anchor-backends", default="",
                    help="comma list from {local,peer-quorum,ots,xmr}; when "
                         "set, POST /witness/anchor runs the external "
                         "scheduler")
    ap.add_argument("--ots-calendar", default=None,
                    help="OpenTimestamps calendar base URL (for the ots "
                         "backend); proof bytes are held in CUSTODY, Bitcoin "
                         "inclusion is verified with standard ots tooling")
    ap.add_argument("--anchor-store", default=None,
                    help="JSONL path for anchor receipts "
                         "(default: <log>.anchors.jsonl when --log is set)")
    ap.add_argument("--xmr-wallet-rpc", default=None,
                    help="monero-wallet-rpc base URL for the xmr backend "
                         "(hash-as-spend-key anchoring; the wallet only "
                         "needs anchoring dust)")
    ap.add_argument("--challenge-windows", default=None,
                    help="commit,reveal seconds for challenge rounds "
                         "(e.g. '30,30'); default 30,30")
    ap.add_argument("--authz-policy", default=None,
                    help="JSON authorization policy (who may call what); "
                         "malformed policy refuses the boot")
    ap.add_argument("--revoked-serials", default=None,
                    help="comma list OR @file of revoked client-cert serial "
                         "numbers (hex); revoked certs are rejected 401 "
                         "before authz")
    ap.add_argument("--rate-limit", default=None,
                    help="per-identity budgets, e.g. "
                         "'infer=30/60,task=10/60,write=60/60,read=120/60' "
                         "(requests per window-seconds per endpoint class); "
                         "over-budget = 429 + Retry-After; systematic abuse "
                         "is witnessed as RATE_LIMIT evidence")
    ap.add_argument("--being-profile", default=None,
                    choices=("production", "dev"),
                    help="enable the Being Composition Runtime "
                         "(POST /v1/tasks). production: independent "
                         "verifier panels are MANDATORY and never "
                         "degraded; dev: the labeled mode=self path is "
                         "allowed")
    ap.add_argument("--being-workspace", default=None,
                    help="Karma sandbox workspace for Being actions "
                         "(default: <log>.being.ws/ when --log is set)")
    ap.add_argument("--being-journals", default=None,
                    help="directory for the Being's durable organ journals "
                         "(default: <log>.being/ when --log is set)")
    ap.add_argument("--being-provenance", default=None,
                    help="JSON file: object_id -> ProvenanceManifest for "
                         "the route objects (REQUIRED for production)")
    ap.add_argument("--xmr-network", default="mainnet",
                    choices=("mainnet", "testnet", "stagenet"),
                    help="Monero network the anchor addresses are derived "
                         "for (default mainnet)")
    args = ap.parse_args(argv)

    # P0-11: /admin/* hooks are a test harness surface. Refuse to expose them
    # on anything but a loopback bind.
    if args.allow_test_hooks and args.host not in ("127.0.0.1", "::1", "localhost"):
        print("FATAL: --allow-test-hooks requires a loopback --host "
              "(got %r). Admin test hooks must never face a network."
              % args.host, file=sys.stderr)
        return 2

    # P0-1: resolve the node's signing identity.
    identity = None
    if args.node_keystore:
        passphrase = os.environ.get(args.keystore_passphrase_env)
        if not passphrase:
            print("FATAL: --node-keystore given but environment variable %r "
                  "is unset. Refusing to boot with an unlocked or ephemeral "
                  "identity." % args.keystore_passphrase_env, file=sys.stderr)
            return 2
        try:
            identity = NodeIdentity.load_or_create(args.node_keystore, passphrase)
        except Exception as e:
            print("FATAL: cannot load node keystore %r: %s"
                  % (args.node_keystore, e), file=sys.stderr)
            return 2
    elif args.log and os.path.exists(args.log) and os.path.getsize(args.log) > 0:
        # P0-2: an ephemeral key over an existing witness log would append
        # with a new signer and break chain coherence. Fail closed.
        print("FATAL: witness log %r already exists but no --node-keystore "
              "was supplied. An ephemeral (dev) identity may not extend a "
              "persisted chain. Provide the original keystore, or choose a "
              "fresh --log path." % args.log, file=sys.stderr)
        return 2

    if args.engine == "sglang":
        from engine_sglang import SGLangEngine
        engine = SGLangEngine(
            args.engine_url, fingerprint=args.fingerprint,
            adapter_paths=json.loads(args.adapter_paths),
            determinism_level=args.engine_determinism or "attested")
    elif args.engine == "dwarfstar":
        from engine_dwarfstar import DwarfStarEngine
        engine = DwarfStarEngine(
            args.engine_url, fingerprint=args.fingerprint,
            determinism_level=args.engine_determinism or "attested")
    else:
        engine = HashEngine(args.fingerprint)
    peers = [p.strip() for p in args.peers.split(",") if p.strip()]
    # IFF registry: admission authority defaults to THIS node (founding
    # bootstrap) — its own countersignature admits the first peers.
    self_nid = None
    if identity is not None:
        from jjdai.crypto import node_id as _nid
        self_nid = _nid(identity.sk.public)
    admission = {args.admission_key} if args.admission_key else (
        {self_nid} if self_nid else set())
    registry = PeerRegistry(args.peer_registry, admission_keys=admission)
    replica_store = args.replica_store or (args.log + ".replicas.jsonl"
                                           if args.log else None)
    receipt_store = args.receipt_store or (args.log + ".receipts.jsonl"
                                           if args.log else None)
    segment_store = args.segment_store or (args.log + ".segments.jsonl"
                                           if args.log else None)
    attest_store = args.attestation_store or (args.log + ".attest.jsonl"
                                              if args.log else None)
    being_ws = args.being_workspace or (args.log + ".being.ws"
                                        if args.log else None)
    being_jd = args.being_journals or (args.log + ".being"
                                       if args.log else None)
    authz = None
    if args.authz_policy:
        try:
            authz = AuthzPolicy.load(args.authz_policy)
        except (OSError, ValueError, AuthzError) as e:
            print(f"FATAL: authz policy: {e}", file=sys.stderr)
            return 2
    revoked = set()
    if args.revoked_serials:
        raw = args.revoked_serials
        if raw.startswith("@"):
            try:
                with open(raw[1:], encoding="utf-8") as f:
                    raw = ",".join(line.strip() for line in f
                                   if line.strip() and
                                   not line.startswith("#"))
            except OSError as e:
                print(f"FATAL: revoked serials file: {e}", file=sys.stderr)
                return 2
        revoked = {x.strip().lower() for x in raw.split(",") if x.strip()}
    rate_limits = None
    if args.rate_limit:
        rate_limits = {}
        for part in args.rate_limit.split(","):
            cls, spec = part.strip().split("=")
            limit, window = spec.split("/")
            if cls not in ("infer", "task", "write", "read"):
                print(f"FATAL: unknown rate class {cls!r} "
                      "(infer|task|write|read).", file=sys.stderr)
                return 2
            rate_limits[cls] = (int(limit), float(window))
    being_prov = None
    if args.being_provenance:
        with open(args.being_provenance, encoding="utf-8") as f:
            being_prov = json.load(f)
    if args.being_profile == "production" and not being_prov:
        print("FATAL: --being-profile production requires "
              "--being-provenance (a Being that cannot judge verifier "
              "independence must not verify).", file=sys.stderr)
        return 2
    if args.being_profile and not being_ws:
        import tempfile as _tf
        being_ws = _tf.mkdtemp(prefix="jjdai-being-ws-")
    anchor_store = args.anchor_store or (args.log + ".anchors.jsonl"
                                         if args.log else None)

    # ---- TLS contexts (v0.5.1) ------------------------------------------ #
    server_ssl = None
    if bool(args.tls_cert) != bool(args.tls_key):
        print("FATAL: --tls-cert and --tls-key must be given together.",
              file=sys.stderr)
        return 2
    if args.tls_require_client_cert and not args.tls_ca:
        print("FATAL: --tls-require-client-cert needs --tls-ca (which CA "
              "signs the clients?). mTLS fails closed, not open.",
              file=sys.stderr)
        return 2
    if args.tls_cert:
        server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ssl.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            server_ssl.load_cert_chain(args.tls_cert, args.tls_key)
        except (OSError, ssl.SSLError) as e:
            print(f"FATAL: cannot load TLS server material: {e}",
                  file=sys.stderr)
            return 2
        if args.tls_ca:
            server_ssl.load_verify_locations(args.tls_ca)
            server_ssl.verify_mode = (ssl.CERT_REQUIRED
                                      if args.tls_require_client_cert
                                      else ssl.CERT_OPTIONAL)
    client_ssl = None
    if args.peer_ca:
        client_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ssl.minimum_version = ssl.TLSVersion.TLSv1_2
        client_ssl.load_verify_locations(args.peer_ca)
        if args.client_cert:
            client_ssl.load_cert_chain(args.client_cert, args.client_key)

    # ---- anchoring backends (v0.5.1) ------------------------------------ #
    backend_names = [b.strip() for b in args.anchor_backends.split(",")
                     if b.strip()]
    anchor_backends = []
    node_ref = {}          # late-bound: PeerQuorumAnchor needs the node
    for name in backend_names:
        if name == "local":
            anchor_backends.append(LocalFileAnchor())
        elif name == "peer-quorum":
            anchor_backends.append(PeerQuorumAnchor(
                lambda count, root: node_ref.get("node")
                and node_ref["node"].receipts.get(count)))
        elif name == "ots":
            if not args.ots_calendar:
                print("FATAL: anchor backend 'ots' needs --ots-calendar.",
                      file=sys.stderr)
                return 2
            anchor_backends.append(OtsCalendarAnchor(args.ots_calendar))
        elif name == "xmr":
            if not args.xmr_wallet_rpc:
                print("FATAL: anchor backend 'xmr' needs --xmr-wallet-rpc.",
                      file=sys.stderr)
                return 2
            try:
                anchor_backends.append(XmrAnchor(args.xmr_wallet_rpc,
                                                 network=args.xmr_network))
            except XmrAnchorError as e:
                print(f"FATAL: {e}", file=sys.stderr)
                return 2
        else:
            print(f"FATAL: unknown anchor backend {name!r}.", file=sys.stderr)
            return 2
    try:
        node = Node(name=args.name, profile=args.profile,
                    substrates=json.loads(args.substrates),
                    adapters=json.loads(args.adapters),
                    engine=engine,
                    log_path=args.log, allow_test_hooks=args.allow_test_hooks,
                    identity=identity,
                    peers=peers, quorum_k=args.quorum,
                    replica_store_path=replica_store,
                    receipt_path=receipt_store,
                    segment_store_path=segment_store,
                    peer_registry=registry,
                    require_admission=args.require_admission,
                    salt_peers=[u.strip() for u in args.salt_peers.split(",")
                                if u.strip()],
                    entangle_min=args.entangle_min,
                    entangle_strict=args.entangle_strict,
                    entangle_max_age_s=args.entangle_max_age,
                    client_ssl_context=client_ssl,
                    attest_artifacts=json.loads(args.substrate_artifacts),
                    require_attestation=args.require_attestation,
                    attestation_store_path=attest_store,
                    anchor_backends=anchor_backends or None,
                    anchor_store_path=anchor_store
                    if anchor_backends else None,
                    being_profile=args.being_profile,
                    being_workspace=being_ws,
                    being_journal_dir=being_jd if args.being_profile else None,
                    being_provenance=being_prov,
                    rate_limits=rate_limits,
                    authz=authz, revoked_serials=revoked,
                    challenge_windows=(
                        tuple(float(x) for x in
                              args.challenge_windows.split(","))
                        if args.challenge_windows else None),
                    fraud_log_path=(args.log + ".fraud.jsonl")
                    if args.log else None)
    except (IdentityError, ReplicationError, SegmentError,
            AttestationError, AnchorError, BeingRuntimeError,
            AuthzError) as e:
        print("FATAL: %s" % e, file=sys.stderr)
        return 2
    node_ref["node"] = node
    if peers and args.replicate_interval > 0:
        import threading

        def _push_loop():
            # ANTI-PING-PONG (v0.5 drop 6): storing a peer's root appends a
            # PEER_ROOT bookkeeping record to OUR chain; if that alone
            # triggered a push, two idle nodes would grow each other's
            # chains forever. Push only when the SUBSTANTIVE head moved —
            # bookkeeping records (PEER_ROOT, ANCHOR_QUORUM) ride along
            # with the next substantive push instead.
            last_sub = None
            while True:
                time.sleep(args.replicate_interval)
                try:
                    sub = None
                    for r in reversed(node.chain.records):
                        if r["kind"] not in ("PEER_ROOT", "ANCHOR_QUORUM"):
                            sub = r["this_hash"]
                            break
                    if sub != last_sub or len(node.receipts) == 0:
                        node.push_to_peers()
                        last_sub = sub
                except Exception as e:          # never kill the daemon
                    print(f"[{args.name}] replication push error: {e}",
                          file=sys.stderr)

        threading.Thread(target=_push_loop, daemon=True,
                         name="witness-replication").start()
    if node.identity_mode == "ephemeral":
        print(f"[{args.name}] WARNING: EPHEMERAL identity (dev mode) — this "
              f"node's key will not survive a restart. Use --node-keystore "
              f"for any run whose witness log matters.", file=sys.stderr)
    srv = ThreadingHTTPServer((args.host, args.port), make_handler(node))
    scheme = "http"
    if server_ssl is not None:
        srv.socket = server_ssl.wrap_socket(srv.socket, server_side=True)
        scheme = "https" + ("+mtls" if args.tls_require_client_cert else "")
    print(f"[{args.name}] node_id={node.chain.node_id[:16]}…  "
          f"identity={node.identity_mode}  "
          f"profile={args.profile}  {scheme}://{args.host}:{args.port}",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
