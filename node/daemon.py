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
import queue
import socket
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
from core.identity import (BeingIdentity, NodeIdentity,     # noqa: E402
                           IdentityError, entitled_to_witness,
                           make_hosting_binding,
                           verify_hosting_binding, verify_startup)
from core.router import (EngineDescriptor, NodeDescriptor,  # noqa: E402
                         RefusalError, RouteObject as _RO, Verdict)
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
from jjdai.adapters.errors import NotSupported              # noqa: E402
from core.artifact_binding import (ArtifactBindingError,    # noqa: E402
                                   UNKNOWN, bind_artifact, unbound)
import clockwatch                                           # noqa: E402
import readiness as readiness_rules                         # noqa: E402
import sdnotify                                             # noqa: E402
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

# HashEngine moved to jjdai/adapters/backends/hash.py in v0.6.5: it was
# never node-specific — it is the reference driver the conformance suite
# measures the others against. Re-exported here so existing importers and
# tests keep working; the daemon itself now asks the registry by name.
from jjdai.adapters.backends.hash import HashEngine        # noqa: E402,F401
from jjdai.adapters.errors import RegistryError            # noqa: E402
from jjdai.adapters.registry import (BackendConfig,        # noqa: E402
                                     available as available_backends,
                                     create as create_backend,
                                     import_errors, load_builtin)


# --------------------------------------------------------------------------- #
# Node
# --------------------------------------------------------------------------- #

class _BeingEngineSeat:
    """The node's REAL engine, presented as one seat in the router.

    `core.router` speaks in `NodeEngine` — describe / generate / score over
    token lists. `jjdai.adapters` speaks the EngineBackend protocol —
    messages, sampling dicts, a text completion. This is the seam between
    them, and it exists so the Being thinks with the engine the node
    actually serves instead of with a test fixture that resembled one.

    Two properties are deliberate and both are refusals:

      * the descriptor carries the backend's OWN fingerprint and determinism
        level. It is not a label chosen here — if the driver cannot state
        one, this seat cannot describe itself and says so;
      * `score` does NOT fall back to anything. A backend that does not
        implement forced-continuation scoring has no verifier role, and the
        honest consequence is that verification on this node is unavailable
        — not that some substitute verdict gets manufactured. DwarfStar
        without logprobs is exactly this case, and its own driver already
        says to use a peer verifier node.
    """

    def __init__(self, node, seat_id: str, substrate: str,
                 topics=("_generalist",)):
        self._node = node
        self._seat_id = seat_id
        self._substrate = substrate
        self._topics = tuple(topics)

    @property
    def _engine(self):
        eng = getattr(self._node, "engine", None)
        if eng is None:
            raise RefusalError(
                "the being has no engine: this node was started without a "
                "configured backend, and a being cannot think with nothing")
        return eng

    #: What a seat may say about the ARTIFACT behind it. In recut5 the seat
    #: ASKED THE DRIVER and schema-checked whatever came back, which the
    #: fifth audit showed to be a false green four ways over (see
    #: core/artifact_binding.py). The binding is now built once at boot from
    #: an operator-supplied SIGNED manifest, verified as a chain down to
    #: measured bytes, and frozen. A seat reports it; it cannot compose it.
    def artifact_refs(self):
        refs = getattr(self._node, "artifact_refs", None)
        if refs is None:
            return unbound("this node was started without "
                           "--model-artifact-manifest",
                           engine=getattr(self._node, "engine", None))
        return refs

    def describe(self):
        eng = self._engine
        fp = getattr(eng, "fingerprint", None)
        det = getattr(eng, "determinism_level", None)
        if not fp or not det:
            raise RefusalError(
                f"backend {getattr(eng, 'backend', '?')!r} states no "
                f"fingerprint or determinism level; a seat that cannot "
                f"describe its provenance must not be routed to")
        caps = eng.capabilities()
        implemented = (caps.get("implemented") or {}).get("execution") or ()
        quant = self.artifact_refs().quantization
        engines = [EngineDescriptor("generator", fp, det, quant)]
        # The verifier role is DECLARED only if the backend really has it.
        # `capabilities()` is derived from what the driver overrides, so this
        # reads what the code does rather than what a list claims.
        if "score" in implemented:
            engines.append(EngineDescriptor("verifier", fp, det, quant))
        return NodeDescriptor(
            node_id=self._seat_id, substrate_id=self._substrate,
            profile="B", topics_served=self._topics,
            engines=tuple(engines),
            attributes={"base_origin": "self", "backend": eng.backend},
            capacity=1)

    def generate(self, prompt: str, params):
        text = self._engine.generate(
            [{"role": "user", "content": prompt}],
            {"temperature": getattr(params, "temperature", 0.0),
             "top_p": getattr(params, "top_p", 1.0),
             "top_k": getattr(params, "top_k", 0),
             "seed": getattr(params, "seed", 0)})
        return text.split(), params

    def score(self, prompt: str, tokens, params):
        r = self._engine.score(
            [{"role": "user", "content": prompt}], list(tokens),
            {"temperature": getattr(params, "temperature", 0.0),
             "top_p": getattr(params, "top_p", 1.0),
             "top_k": getattr(params, "top_k", 0),
             "seed": getattr(params, "seed", 0)})
        return Verdict(ok=bool(r["ok"]), reachable=list(r["reachable"]),
                       min_margin=float(r["min_margin"]),
                       verifier_fp=r["verifier_fp"],
                       determinism=r["determinism"], note=r.get("note", ""))


class Node:
    def __init__(self, *, name: str, profile: str, substrates: list,
                 adapters: dict, engine: HashEngine, log_path: str = None,
                 allow_test_hooks: bool = False, being_id: str = None,
                 being_identity=None, hosting_binding: dict = None,
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
                 model_artifact_manifest: dict = None,
                 require_attestation: bool = False,
                 attestation_store_path: str = None,
                 anchor_backends: list = None,
                 required_anchor_backends: list = None,
                 anchor_store_path: str = None,
                 being_profile: str = None,
                 being_workspace: str = None,
                 being_journal_dir: str = None,
                 being_provenance: dict = None,
                 rate_limits: dict = None,
                 max_body_bytes: int = 1024 * 1024,
                 max_concurrency: int = 64,
                 request_timeout_s: float = 15.0,
                 isolation_profiles: list = None,
                 anchor_lag_max_s: float = 0,
                 unanchored_depth_max: int = 0,
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
        # ---- who this node speaks for (vertical, v0.6.7) ---------------- #
        # Until now the Being's id was `being:` plus the first sixteen
        # characters of the NODE id. Three things were wrong with it at
        # once: it is not the canonical `being:<sha256(pubkey)>` form that
        # `core.identity` produces, so nothing could ever bind it to a key;
        # it makes the Being an artefact of its host, which inverts the
        # Operator → Node → Being ordering; and the Being then signed with
        # the NODE's key, so "witnessed under the Being's identity" was a
        # sentence with no cryptography behind it.
        #
        # A node with no Being keystore still gets a CANONICAL id — from a
        # freshly generated key — rather than a malformed one. It is
        # ephemeral, it does not survive restart, and readiness says so.
        # The dishonest option would be a stable-looking id that no key
        # backs; an honest ephemeral one can at least be told apart.
        self.being_identity = being_identity or BeingIdentity(
            SigningKey.generate())
        # DERIVED, never carried (recut5, audit P0.2). This used to read
        # `being_id or self.being_identity.being_id`, so a caller could name
        # one being while holding another's key and nothing compared the
        # two. An id that is not the hash of the key that signs for it is
        # not an identity, it is a label. A supplied id is now an
        # EXPECTATION and a mismatch refuses.
        derived = self.being_identity.being_id
        if being_id and being_id != derived:
            raise IdentityError(
                f"being_id {being_id!r} was supplied but the being keystore "
                f"derives {derived!r}: an identity is the hash of the key "
                "that speaks for it, so these cannot both be true")
        self.being_id = derived
        self.being_ephemeral = being_identity is None
        #: The two-signature statement that THIS node hosts THIS being.
        #: VERIFIED here, not merely stored (recut5, audit P0.2): readiness
        #: used to report `being_bound = bool(hosting_binding)`, so
        #: `{"garbage": true}` read READY and a binding belonging to another
        #: pair passed unexamined. The helpers to check it existed already —
        #: nothing called them on the runtime path.
        if hosting_binding is not None:
            if not verify_hosting_binding(hosting_binding):
                raise IdentityError(
                    "the supplied hosting binding does not verify: both "
                    "signatures must be valid and both ids bound to the "
                    "keys that signed them")
            if not entitled_to_witness(hosting_binding,
                                       being_id=self.being_id,
                                       node_id=self.chain.node_id):
                raise IdentityError(
                    f"hosting binding names being "
                    f"{hosting_binding.get('being_id')!r} on node "
                    f"{hosting_binding.get('node_id')!r}; this node is "
                    f"{self.chain.node_id!r} hosting {self.being_id!r}. A "
                    "valid binding between two OTHER parties is not an "
                    "entitlement for these")
        elif being_identity is not None and identity is not None:
            # Both keys are in hand, so the statement can be MADE here
            # rather than read from a file — the same rule main() already
            # follows: a binding read from disk is a claim, one signed at
            # boot is a fact. This is not a way around the gate. What the
            # binding proves is that the BEING consented, and only a host
            # holding the being key can produce that consent; a node that
            # does not hold it still cannot fabricate one.
            hosting_binding = make_hosting_binding(being_identity, identity,
                                                   since_ts=time.time())
        if being_profile == "production":
            # A production node witnesses under a name; without a binding
            # nothing says it may, and DEGRADED was the wrong answer to
            # that — it let the node run and write records anyway.
            if self.being_ephemeral:
                raise IdentityError(
                    "production profile requires a PERSISTENT being "
                    "identity: an ephemeral being cannot be bound to a host "
                    "in any way that survives the restart the binding "
                    "exists to outlive (start with --being-keystore)")
            if identity is None:
                raise IdentityError(
                    "production profile requires a persistent node identity: "
                    "a hosting binding signed by an ephemeral node key is "
                    "worthless after the next restart (start with "
                    "--node-keystore)")
            if not entitled_to_witness(hosting_binding,
                                       being_id=self.being_id,
                                       node_id=self.chain.node_id):
                raise IdentityError(
                    "production profile requires a valid hosting binding: a "
                    "node that cannot prove it hosts this being must not "
                    "witness under its name")
        self.hosting_binding = hosting_binding
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
            self._weight_envs = dict(att_envs)
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
                self.anchor_log or AnchorLog(None), lock=self.chain.lock,
                required_backends=required_anchor_backends)
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
        # ---- ingress hardening (v0.6.4) --------------------------------- #
        # Three caps that must exist BEFORE the network is opened to anyone
        # who is not us: a ceiling on what one request may hand us, a ceiling
        # on how many requests may be in flight, and a clock on every
        # connection. Without them a single slow or fat client is a denial of
        # service against the witness contour, and no amount of authorization
        # helps — the cost is paid before authorization is even reached.
        self.max_body_bytes = int(max_body_bytes)
        self.max_concurrency = int(max_concurrency)
        self.request_timeout_s = float(request_timeout_s)
        self.ingress_sem = threading.BoundedSemaphore(self.max_concurrency)
        self.isolation_profiles = list(isolation_profiles or ["reference"])

        # ---- observability (v0.6.6) ------------------------------------- #
        # The beacon is refreshed by the ACCEPT PATH, not by a timer, so the
        # watchdog measures the part of the process that serves the network.
        # See node/sdnotify.py for why an ungated heartbeat is worthless.
        # NAME: `liveness_beacon`, not `beacon`. This object already owns
        # `beacon_source` / `current_beacon` — the entanglement SaltBeacon —
        # and one word for two unrelated things on one object is the same
        # defect as Champion Profile vs Champion Being.
        self.liveness_beacon = sdnotify.Beacon()
        self.watchdog = None
        self.clockwatch = None
        # Anchoring policy for readiness. Zero disables the corresponding
        # check rather than making it always-true: a policy of "no policy"
        # should be visible as NOT_CONFIGURED, not silently pass.
        self._chain_checked_at = 0.0
        self._chain_verdict_cached = ""
        self.chain_check_interval_s = 30.0
        self.anchor_lag_max_s = float(anchor_lag_max_s or 0)
        self.unanchored_depth_max = int(unanchored_depth_max or 0)

        # ---- rate limiter (v0.5.4) -------------------------------------- #
        self.rate_limiter = RateLimiter(rate_limits, chain=self.chain) \
            if rate_limits else None
        # ---- authz + revocation + metrics (v0.5.5) ---------------------- #
        self.authz = authz
        self.revoked_serials = set(revoked_serials or set())
        self.started_at = time.time()
        self.metrics = {"requests_total": 0, "denied_authz_total": 0,
                        "rate_limited_total": 0, "revoked_rejected_total": 0,
                        "body_too_large_total": 0, "bad_framing_total": 0,
                        "overloaded_total": 0, "refusal_dropped_total": 0,
                        "tasks_total": 0, "challenge_rounds_total": 0}
        if self.challenge is None:
            self.challenge = ChallengeRound(
                self.chain, registry=None,
                fraud_log_path=(log_path + ".fraud.jsonl")
                if log_path else None)
        # ---- artifact binding: WHICH WEIGHTS (recut6, audit P0.1) ------- #
        # A BOOT gate, not a per-task check. recut5 verified provenance
        # after generation, so a node whose weights were unprovable served,
        # thought and only then refused — every task, forever. If the chain
        # cannot be built, a `production` node does not start.
        self.artifact_refs = None
        if model_artifact_manifest is not None:
            try:
                self.artifact_refs = bind_artifact(
                    manifest_envelope=model_artifact_manifest,
                    engine=self.engine,
                    weight_attestations=getattr(self, "_weight_envs", None),
                    deployment=self.deployment)
            except ArtifactBindingError as e:
                # A BROKEN chain refuses in any profile — the operator said
                # these are the weights and they are not. An INCOMPLETE one
                # (signed manifest, nothing measured) is honestly unbound,
                # which `production` then refuses below with the reason.
                if being_profile == "production":
                    raise ArtifactBindingError(f"startup refused: {e}") from e
                # recut8: carry WHICH link failed, so `manifest_verified`
                # means something other than a copy of `verified`.
                self.artifact_refs = unbound(
                    str(e), engine=self.engine,
                    manifest_verified=getattr(e, "manifest_verified", False))
        elif being_profile:
            self.artifact_refs = unbound(
                "no --model-artifact-manifest supplied", engine=self.engine)
        if being_profile == "production" and not (
                self.artifact_refs and self.artifact_refs.verified):
            raise ArtifactBindingError(
                "production profile requires a verified model artifact "
                "binding: "
                + (self.artifact_refs.reason if self.artifact_refs
                   else "none supplied")
                + ". A signed DecisionTrace whose generator cannot be traced "
                  "to measured weights is a declaration, not provenance")

        # ---- Being Composition Runtime (v0.5.3) ------------------------- #
        # The organism over the daemon's OWN identity, witness and governor
        # (audit gate 1: one BeingIdentity, one Witness for every organ).
        self.being = None
        if being_profile:
                        # ---- the vertical (v0.6.7) ---------------------------------- #
            # Until now this built THREE synthetic engines with
            # `core.router._mk_node` — a helper declared inside the router's
            # own acceptance-test section, returning a ReferenceEngine, one
            # of them with `noise=0.05` deliberately injected. The
            # consequence was not cosmetic: weight attestation and
            # /capabilities described the REAL configured backend while the
            # signed DecisionTrace that went into the witness chain was
            # produced by a test fixture. The node witnessed the work of an
            # engine that was never attested and is not a model.
            #
            # The fixtures are gone. The Being now thinks with the engine
            # this node actually serves — the same object behind
            # /v1/messages, readiness and attestation.
            #
            # ONE engine means ONE place, and a single place is not a panel.
            # That is not worked around here: the `production` profile
            # refuses a task it cannot verify independently, and on a lone
            # node it will refuse. Manufacturing a panel out of one engine
            # with different seeds would put imitated independence into a
            # signed trace, which ADR-019 D1 forbids by name. A truthful
            # refusal is the correct behaviour of a single node until
            # either peers exist (Ф1) or deferred verification does (Ф2).
            sub = self.substrates[0] if self.substrates else "sha256:base-A"
            engines = {"n-self": _BeingEngineSeat(self, "n-self", sub)}
            objects = [_RO("m:self", "generalist", "_generalist", "n-self")]
            self.being = BeingRuntime(
                sk=self.sk, being_sk=self.being_identity.sk,
                chain=self.chain, being_id=self.being_id,
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
            # recut5: published so a remote descriptor built by
            # core.router.RemoteNode.describe() says what the local seat
            # says. Absent, it fell back to "n/a" while the seat claimed
            # "int4" — one backend, two descriptions, depending on which
            # path assembled them.
            "quantization": (self.artifact_refs.quantization
                             if self.artifact_refs else UNKNOWN),
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
            "ingress": {"max_body_bytes": self.max_body_bytes,
                        "max_concurrency": self.max_concurrency,
                        "request_timeout_s": self.request_timeout_s},
            "isolation": self.isolation_status(),
            "revoked_serials": len(self.revoked_serials),
            "challenge": bool(self.challenge),
            "attested_substrates": sorted(
                (self.deployment or {}).get("body", {})
                .get("substrates", {})) if self.deployment else [],
            "require_attestation": self.require_attestation,
        }

    def readiness_snapshot(self) -> dict:
        """Facts about this node, in the shape node/readiness.py evaluates.

        Kept separate from the evaluation so the RULES can be tested without
        a node and the FACTS can be gathered without a rule engine. The
        v0.6.5 lesson is written on the wall here: a check named after the
        claim while testing something adjacent to it is worse than no check,
        and the cheapest defence is to keep the claim and the measurement in
        different modules.
        """
        iso = self.isolation_status()
        sched = getattr(self, "anchor_scheduler", None)
        configured = sched is not None
        anchor = {"anchoring_configured": False}
        if configured:
            try:
                # readiness.anchor_facts is the ONE converter from scheduler
                # state to rule input, so the daemon and the tests cannot
                # assemble different shapes and both look right.
                anchor = readiness_rules.anchor_facts(sched.anchor_status())
            except Exception as e:                 # never a silent green
                anchor = {"anchoring_configured": True,
                          "anchor_external_configured": True,
                          "anchor_required": ["<unavailable>"],
                          "anchor_backend_facts": {},
                          "anchor_configured_backends": [],
                          "anchor_shadow_backends": [],
                          "unanchored_depth": 0,
                          "anchor_lag_s": None,
                          "anchor_status_error": str(e)}
        eng_ready, eng_reason, eng_name = self._engine_readiness()
        chain_broken = self._chain_verdict()
        return {
            "identity_loaded": bool(getattr(self, "sk", None)),
            "identity_ephemeral": self.identity_mode == "ephemeral",
            "being_ephemeral": bool(getattr(self, "being_ephemeral", True)),
            "being_bound": entitled_to_witness(
                getattr(self, "hosting_binding", None),
                being_id=self.being_id, node_id=self.chain.node_id),
            "signer_mismatch": self._signer_mismatch(),
            "chain_loaded": self.chain is not None,
            "chain_broken": chain_broken,
            "records": len(self.chain.records) if self.chain else 0,
            **anchor,
            "anchor_lag_max_s": self.anchor_lag_max_s,
            "unanchored_depth_max": self.unanchored_depth_max,
            "engine_configured": self.engine is not None,
            "engine_ready": eng_ready,
            "engine_name": eng_name,
            "engine_reason": eng_reason,
            "isolation_declared": iso["declared"],
            "isolation_ready": iso["ready"],
            "being_configured": self.being is not None,
            "being_contained": self.governor.is_contained(self.being_id),
            "being_profile": (self.being.profile if self.being else None),
        }

    def _engine_readiness(self):
        """Ask the engine, do not merely observe that one exists.

        `engine is not None` answered "is an object present", and an
        unreachable DwarfStar reporting `healthy=False` was published as
        `engine: ready`. Where a backend implements neither `readiness()`
        nor `healthy()` the honest answer is UNKNOWN, expressed as
        not-ready-with-a-reason rather than as a green light.
        """
        eng = self.engine
        if eng is None:
            return False, "", None
        name = (getattr(eng, "backend", None) or getattr(eng, "name", None)
                or type(eng).__name__)
        last = ""
        for meth in ("readiness", "healthy", "health"):
            fn = getattr(eng, meth, None)
            if not callable(fn):
                continue
            try:
                res = fn()
            except NotSupported:
                # DECLARED-BUT-UNIMPLEMENTED IS NOT A FAILURE. Protocol v1
                # declares the contract whole, so every driver HAS a
                # readiness() and the ones that do not implement it raise
                # NotSupported. Treating that as "not ready" marked healthy
                # DwarfStar and SGLang nodes as down — the fallback existed
                # and was never reached.
                last = f"{meth}() not implemented by this backend"
                continue
            except Exception as e:
                return False, f"{meth}() raised: {type(e).__name__}: {e}", name
            if isinstance(res, dict):
                ok = res.get("ready", res.get("healthy", res.get("ok")))
                if ok is None:
                    return False, f"{meth}() returned no verdict", name
                return bool(ok), ("" if ok else
                                  str(res.get("reason", "not ready"))), name
            return bool(res), ("" if res else f"{meth}() is false"), name
        why = last or "engine exposes no readiness/healthy probe"
        return False, f"{why} — state UNKNOWN, reported as not ready", name

    def _chain_verdict(self) -> str:
        """Cached structural verdict on the witness chain.

        Verifying the whole chain on every scrape would be a self-inflicted
        denial of service, and asserting `""` — as the v0.6.6 cut did — is
        not a measurement at all. So: verify at most once per interval and
        serve the cached verdict in between.
        """
        if self.chain is None:
            return ""
        now = time.time()
        if (self._chain_checked_at and
                now - self._chain_checked_at < self.chain_check_interval_s):
            return self._chain_verdict_cached
        verdict = ""
        try:
            # THE REAL METHOD IS `verify_chain()`. The first recut probed for
            # `verify_head` (does not exist) and then `verify` (exists, but
            # returns a TUPLE and takes a resolver), so the tuple matched
            # neither the False nor the dict branch and every corrupted chain
            # came back clean. Same defect as reading anchor attributes that
            # were never there: a probe written from a guess at the API.
            fn = getattr(self.chain, "verify_chain", None)
            if not callable(fn):
                verdict = ("witness chain exposes no verify_chain() — state "
                           "UNKNOWN, reported as broken")
            else:
                lock = getattr(self.chain, "lock", None)
                if lock is not None:
                    with lock:
                        ok = fn()
                else:
                    ok = fn()
                if not ok:
                    verdict = "verify_chain() returned false"
        except Exception as e:
            verdict = f"{type(e).__name__}: {e}"
        self._chain_verdict_cached = verdict
        self._chain_checked_at = now
        return verdict

    def _signer_mismatch(self) -> bool:
        """Is the chain carrying records signed by somebody else?

        The boot gate refuses to start on this, which is why the cut simply
        wrote False. But the gate runs once and readiness is continuous, and
        a constant is not a measurement.
        """
        try:
            if self.chain is None or not self.chain.records:
                return False
            mine = self.chain.node_id
            for r in reversed(self.chain.records[-32:]):
                nid = r.get("node") or r.get("node_id")
                if nid and nid != mine:
                    return True
            return False
        except Exception:
            return True           # unreadable is not the same as fine

    def readiness(self) -> dict:
        """The full readiness report, aggregate included."""
        return readiness_rules.evaluate(self.readiness_snapshot())

    def isolation_status(self) -> dict:
        """What this node DECLARES it can execute inside (v0.6.4).

        This is the honest form of a fallback. A node missing a profile's
        runtime does not quietly execute in a weaker box and write a note
        about it; it says so here, and work needing that boundary is not
        routed to it. Moves to /readyz when the liveness/readiness split
        lands in v0.6.6.
        """
        from kernel.isolation import profile_status
        st = profile_status(self.isolation_profiles)
        return {"declared": list(self.isolation_profiles),
                "ready": sorted(k for k, v in st.items()
                                if v.get("available")),
                "profiles": st}

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
                            # v0.6.5: a CODE, not a sentence. The plane takes
                            # enum tokens, integers and digests; prose in an
                            # append-only replicated store is a covert
                            # channel and an unbounded write. The explanation
                            # lives in the docs for this code, once, instead
                            # of in every record forever.
                            "reason_code": "systematic_over_budget"})
            return False, retry


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Thread-per-connection with a REAL ceiling (v0.6.4, audit response).

    The first cut of this drop took the admission slot inside the handler —
    that is, INSIDE the worker thread, which by then already existed. It
    bounded how many requests were processed at once and did nothing about
    how many threads were created, so a client opening connections and
    saying nothing still cost one thread each until the connection clock
    expired. The mechanism claimed a property it did not have.

    Admission therefore sits in process_request, which runs on the accept
    loop BEFORE ThreadingMixIn spawns anything. Over the ceiling the socket
    gets a 503 and is closed on the accept thread itself: no worker, no
    stack, no bookkeeping. The slot is released in shutdown_request, which
    the mixin calls exactly once per dispatched connection.
    """

    daemon_threads = True

    #: Refusals are handed to ONE long-lived worker with a bounded queue.
    #: Not to the accept loop, because answering politely means draining
    #: whatever the peer is still sending — closing a socket with unread
    #: inbound data makes the kernel send RST and the 503 is lost, so the
    #: caller cannot tell "overloaded, retry" from "node is dead". And not
    #: to a thread per refusal, which would hand the attacker back exactly
    #: the thread growth this class exists to prevent. One worker, bounded
    #: queue, and past the queue we close hard: politeness degrades under
    #: extreme load, the ceiling does not.
    REFUSE_QUEUE = 64
    REFUSE_DRAIN_BYTES = 64 * 1024

    def __init__(self, addr, handler_cls, *, node):
        self.node = node
        self._refuse_q = queue.Queue(maxsize=self.REFUSE_QUEUE)
        self._refuse_worker = threading.Thread(
            target=self._refuse_loop, daemon=True, name="ingress-refusal")
        self._refuse_worker.start()
        super().__init__(addr, handler_cls)

    def _refuse_loop(self):
        while True:
            request = self._refuse_q.get()
            try:
                self._refuse(request)
            except Exception:                      # never kill the worker
                pass
            finally:
                try:
                    ThreadingHTTPServer.shutdown_request(self, request)
                except Exception:
                    pass

    def _refuse(self, request):
        payload = json.dumps({
            "error": "503 OVERLOADED",
            "max_concurrency": self.node.max_concurrency,
            "detail": "this node is at its connection ceiling; retry",
        }).encode()
        head = (b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                b"Retry-After: 1\r\nConnection: close\r\n\r\n")
        try:
            # A short clock, because the refusal runs on the ACCEPT LOOP: a
            # stalled or half-open peer must never make the refusal itself
            # the thing that blocks new connections.
            request.settimeout(min(2.0, self.node.request_timeout_s))
            request.sendall(head + payload)
            # Half-close the write side, then drain a bounded amount of
            # whatever the peer is still sending. Without the drain, close()
            # over unread inbound data resets the connection and takes the
            # answer with it. The drain is bounded in both bytes and time so
            # a slow peer cannot turn the refusal into the new bottleneck.
            request.shutdown(socket.SHUT_WR)
            drained = 0
            while drained < self.REFUSE_DRAIN_BYTES:
                chunk = request.recv(8192)
                if not chunk:
                    break
                drained += len(chunk)
        except OSError:
            pass

    def service_actions(self):
        """Called by `serve_forever()` on EVERY loop iteration, traffic or
        not — this is where the liveness beacon belongs.

        The v0.6.6 cut touched the beacon in `process_request`, which only
        runs when a connection ARRIVES. An idle but perfectly healthy node
        therefore aged its beacon, went silent, and was restarted by systemd.
        The watchdog must measure whether the accept loop is MOVING, not
        whether anyone happens to be talking to us.
        """
        super().service_actions()
        self.node.liveness_beacon.touch()

    def process_request(self, request, client_address):
        if not self.node.ingress_sem.acquire(blocking=False):
            self.node.metrics["overloaded_total"] += 1
            self.node.metrics["requests_total"] += 1
            try:
                self._refuse_q.put_nowait(request)
            except queue.Full:
                # past the queue, close hard rather than grow anything
                self.node.metrics["refusal_dropped_total"] += 1
                super().shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.node.ingress_sem.release()
            raise

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            try:
                self.node.ingress_sem.release()
            except ValueError:
                pass          # never let bookkeeping kill the accept loop


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

        # v0.6.4: a clock on every connection. socketserver applies this to
        # the accepted socket, so a client that opens a connection and then
        # stalls mid-header or mid-body releases the thread instead of
        # holding it indefinitely (the cheapest denial of service there is).
        timeout = node.request_timeout_s

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
            # v0.6.4: the budget belongs to an IDENTITY, not to an address.
            # Keying by client IP charged everyone behind one NAT to a single
            # bucket and let one holder of a certificate reset their own
            # budget by moving address. The mTLS chain is already verified at
            # this point, so CN+serial is the strongest key available; the
            # address is used only where no client certificate was presented
            # (plain-HTTP dev runs), and it is namespaced so the two key
            # spaces can never collide.
            cn, serial = self._peer_identity()
            if cn or serial:
                key = f"cert:{cn or '-'}:{serial or '-'}"
            else:
                key = f"ip:{self.client_address[0]}"
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

        def _ingress_gate(self) -> bool:
            """True = proceed; False = already answered 400/411/413.

            Runs BEFORE authorization and before any byte of the body is
            read, because an unbounded read is paid for by the server
            regardless of whether the sender turns out to be allowed."""
            te = (self.headers.get("Transfer-Encoding") or "").lower()
            if "chunked" in te:
                node.metrics["bad_framing_total"] += 1
                self._send(411, {"error": "411 LENGTH_REQUIRED",
                                 "detail": "chunked transfer-encoding is not "
                                           "accepted: a body whose length is "
                                           "not declared cannot be capped "
                                           "before it is read"})
                return False
            raw = self.headers.get("Content-Length")
            if raw is None:
                self._body_len = 0
                return True
            try:
                n = int(str(raw).strip())
            except (TypeError, ValueError):
                node.metrics["bad_framing_total"] += 1
                self._send(400, {"error": "400 BAD_FRAMING",
                                 "detail": "Content-Length is not an integer"})
                return False
            if n < 0:
                node.metrics["bad_framing_total"] += 1
                self._send(400, {"error": "400 BAD_FRAMING",
                                 "detail": "negative Content-Length"})
                return False
            if n > node.max_body_bytes:
                node.metrics["body_too_large_total"] += 1
                self._send(413, {"error": "413 BODY_TOO_LARGE",
                                 "limit_bytes": node.max_body_bytes,
                                 "declared_bytes": n,
                                 "detail": "request body exceeds this node's "
                                           "ingress cap"})
                return False
            self._body_len = n
            return True

        def _read_json(self):
            """Read at most the length the gate validated, in bounded chunks.

            The gate always runs first on the POST path; the fallback below
            keeps this method safe on its own terms, so a future caller that
            forgets the gate still cannot hand the parser an unbounded body."""
            n = getattr(self, "_body_len", None)
            if n is None:
                try:
                    n = int(str(self.headers.get("Content-Length", 0)).strip())
                except (TypeError, ValueError):
                    return None
                n = max(0, min(n, node.max_body_bytes))
            chunks, remaining = [], n
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break                      # client hung up mid-body
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks) or b"{}"
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
                # LIVENESS ONLY (v0.6.6). This process is running and can
                # form a reply. It says nothing about whether work should be
                # sent here — that is /readyz. The isolation declaration that
                # rode here since v0.6.4 has moved there as promised; the
                # anonymous role keeps this endpoint and learns nothing about
                # internal state from it, which is the point.
                # MINIMAL by design. The v0.6.6 cut claimed this endpoint
                # leaked nothing while publishing the node id, the uptime
                # and the witness record count to anyone who asked — an
                # identity and an activity volume. Everything beyond "this
                # process can answer" lives behind authorization now.
                return self._send(200, {"ok": True})
            if self.path == "/readyz":
                # READINESS. Per subsystem, with an aggregate that is red only
                # for the subsystems without which this node is not a
                # participant in the network. Authorization is peer/admin:
                # the body names which engines are loaded, what is broken and
                # how far anchoring has fallen behind — a map for whoever is
                # choosing where to push. /healthz stays anonymous.
                rep = node.readiness()
                code = readiness_rules.http_status(rep)
                return self._send(code, {"ready": rep["ready"],
                                         "reason": rep["reason"],
                                         "degraded": rep["degraded"],
                                         "subsystems": rep["subsystems"],
                                         "node_id": node.chain.node_id,
                                         "uptime_s": round(
                                             time.time() - node.started_at,
                                             1)})
            if self.path == "/metrics":
                # Prometheus text exposition — the operational eye on a node
                lines = ["# JJ DAI node metrics (v0.6.6)"]
                m = dict(node.metrics)
                m["witness_records"] = len(node.chain.records)
                m["uptime_seconds"] = round(time.time() - node.started_at, 1)
                if node.being is not None:
                    m["tasks_total"] = len(node.being.traces)
                # Readiness as gauges (v0.6.6). One numeric scale for every
                # subsystem so an alert rule never has to join two metrics to
                # learn one fact.
                rep = node.readiness()
                m.update(readiness_rules.gauge_values(rep))
                anchoring = rep["subsystems"]["anchoring"]
                if anchoring.get("anchor_lag_s") is not None:
                    m["anchor_lag_seconds"] = round(
                        anchoring["anchor_lag_s"], 1)
                m["unanchored_depth"] = anchoring.get("unanchored_depth", 0)
                # Isolation toolset, split by CAUSE. A missing module and a
                # drifted digest are different events with different owners.
                iso_profiles = node.isolation_status()["profiles"]
                drift = missing = other = 0
                for prof in iso_profiles.values():
                    for code in (prof.get("toolset_codes") or {}).values():
                        if code == "DIGEST_DRIFT":
                            drift += 1
                        elif code == "MODULE_MISSING":
                            missing += 1
                        else:
                            other += 1
                # GAUGES, not counters: these are recomputed from current
                # state and go DOWN when a module is fixed. A Prometheus
                # `_total` must be monotonic, and naming a gauge `_total` is
                # how a rule that looks right silently stops being right.
                m["toolset_digest_drift"] = drift
                m["toolset_module_missing"] = missing
                m["toolset_other_fault"] = other
                m["liveness_beacon_age_seconds"] = round(
                    node.liveness_beacon.age(), 3)
                if node.watchdog is not None:
                    m["watchdog_pings_total"] = node.watchdog.pings
                    m["watchdog_silences_total"] = node.watchdog.silences
                    m["watchdog_send_failures_total"] = \
                        node.watchdog.send_failures
                if node.clockwatch is not None:
                    m.update(node.clockwatch.metrics())
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
            if not self._ingress_gate():
                return
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
    # No hardcoded choices: the set of engines is whatever the registry
    # carries, so a new backend driver becomes selectable by existing, not
    # by editing this file. Validation happens in the registry, which can
    # also say WHY a name is missing (unknown vs. driver failed to import).
    load_builtin()
    ap.add_argument("--engine", default="hash",
                    help=f"backend driver name; registered on this host: "
                         f"{available_backends()}"
                         + (f" · failed to import: "
                            f"{sorted(import_errors())}"
                            if import_errors() else ""))
    ap.add_argument("--engine-url", default="http://127.0.0.1:30000",
                    help="base URL of the engine server, for drivers that "
                         "serve over HTTP (sglang, dwarfstar)")
    ap.add_argument("--engine-device", default="",
                    help="device selector, for drivers that address one "
                         "(asic: emulator | device)")
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
    ap.add_argument("--max-body-bytes", type=int, default=1024 * 1024,
                    help="ingress cap on a single request body (default 1 "
                         "MiB). Over the cap the node answers 413 before "
                         "reading the body.")
    ap.add_argument("--max-concurrency", type=int, default=64,
                    help="maximum requests in flight (default 64). Over the "
                         "ceiling the node answers 503 and closes rather "
                         "than queueing.")
    ap.add_argument("--request-timeout-s", type=float, default=15.0,
                    help="per-connection clock in seconds (default 15). A "
                         "stalled client releases its thread.")
    ap.add_argument("--isolation-profiles", default="reference",
                    help="comma list of isolation profiles this node "
                         "declares (reference, wasm-wasi). A declared "
                         "profile whose runtime is absent is reported "
                         "unavailable and its work is refused, never "
                         "downgraded.")
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
    ap.add_argument("--being-keystore", default=None,
                    help="path to the encrypted Ed25519 keystore holding the "
                         "identity of the BEING this node hosts. Separate "
                         "from --node-keystore on purpose: if the being "
                         "signs with the node's key, 'witnessed under the "
                         "being's identity' is a phrase with no cryptography "
                         "behind it. Without this flag the being's id is "
                         "canonical but EPHEMERAL and does not survive a "
                         "restart.")
    ap.add_argument("--model-artifact-manifest", default=None,
                    help="JSON file: a SIGNED ModelArtifactManifest envelope "
                         "for the weights this node serves. Required by "
                         "--being-profile production: the binding from a "
                         "decision to measured weights is verified at boot, "
                         "and a broken chain refuses the start.")
    ap.add_argument("--being-passphrase-env", default="JJDAI_BEING_PASSPHRASE",
                    help="environment variable holding the being keystore "
                         "passphrase (never passed on the CLI)")
    ap.add_argument("--required-anchor-backends", default=None,
                    help="comma list: which of --anchor-backends readiness "
                         "must hold to. Default: every configured backend "
                         "that is not local. A backend that is configured "
                         "but NOT required runs in SHADOW — it anchors and "
                         "is reported, and it cannot make /readyz say 503. "
                         "Use it to operate a backend before the phase that "
                         "makes it mandatory.")
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
    ap.add_argument("--anchor-lag-max-s", type=float, default=0,
                    help="readiness: max seconds since the last anchor "
                         "before /readyz reports NOT_READY (0 = no policy)")
    ap.add_argument("--unanchored-depth-max", type=int, default=0,
                    help="readiness: max depth of the unanchored ledger "
                         "segment before /readyz reports NOT_READY "
                         "(0 = no policy)")
    ap.add_argument("--beacon-stale-after-s", type=float,
                    default=sdnotify.DEFAULT_STALE_AFTER_S,
                    help="how long the accept loop may be still before the "
                         "watchdog stops answering systemd (default matches "
                         "the deployed systemd unit; OBS-WD-6 pins the two "
                         "together)")
    ap.add_argument("--no-watchdog", action="store_true",
                    help="do not answer systemd's watchdog even when "
                         "WATCHDOG_USEC is set (debugging only)")
    ap.add_argument("--sleep-gap-threshold-s", type=float, default=8.0,
                    help="wall/monotonic divergence counted as a host "
                         "suspension (Mac node sleep detection)")
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

    # v0.6.5 audit (P0-1): the daemon asks the registry BY NAME and knows
    # nothing about which engines exist. The previous branch here made the
    # seam decorative — vllm was registered and unreachable, and adding a
    # backend still meant editing this file, which is the one thing the
    # adapter layer was built to prevent.
    load_builtin()
    try:
        engine = create_backend(args.engine, BackendConfig(
            url=args.engine_url,
            fingerprint=args.fingerprint,
            determinism_level=args.engine_determinism,
            adapter_paths=json.loads(args.adapter_paths),
            device=getattr(args, "engine_device", "")))
    except RegistryError as e:
        print(f"engine: {e}", file=sys.stderr)
        raise SystemExit(2)
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
    model_artifact_manifest = None
    if args.model_artifact_manifest:
        try:
            with open(args.model_artifact_manifest, encoding="utf-8") as f:
                model_artifact_manifest = json.load(f)
        except (OSError, ValueError) as e:
            print("FATAL: cannot read --model-artifact-manifest %r: %s"
                  % (args.model_artifact_manifest, e), file=sys.stderr)
            return 2
    if args.being_profile == "production" and model_artifact_manifest is None:
        print("FATAL: --being-profile production requires "
              "--model-artifact-manifest (a decision that cannot be traced "
              "to measured weights is a declaration, not provenance).",
              file=sys.stderr)
        return 2
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
    # The being this node hosts, and the two-signature statement that it may.
    being_identity, hosting_binding = None, None
    if args.being_keystore:
        if identity is None:
            print("FATAL: --being-keystore requires --node-keystore. A "
                  "hosting binding is signed by BOTH parties, and an "
                  "ephemeral node key would make the node half of it "
                  "worthless after the next restart.", file=sys.stderr)
            return 2
        being_pass = os.environ.get(args.being_passphrase_env)
        if not being_pass:
            print("FATAL: --being-keystore given but environment variable %r "
                  "is unset. Refusing to boot a being with an unlocked or "
                  "ephemeral identity." % args.being_passphrase_env,
                  file=sys.stderr)
            return 2
        try:
            being_identity = BeingIdentity.load_or_create(args.being_keystore,
                                                          being_pass)
        except Exception as e:
            print("FATAL: cannot load being keystore %r: %s"
                  % (args.being_keystore, e), file=sys.stderr)
            return 2
        # The binding lives beside the keystore. It is re-derived rather than
        # trusted from disk when both keys are present: a binding read from a
        # file is a claim, one signed here is a fact.
        binding_path = args.being_keystore + ".binding.json"
        hosting_binding = make_hosting_binding(being_identity, identity,
                                               since_ts=time.time())
        if os.path.exists(binding_path):
            try:
                with open(binding_path, encoding="utf-8") as fh:
                    prior = json.load(fh)
                if verify_hosting_binding(prior) and \
                        prior["being_id"] == being_identity.being_id and \
                        prior["node_id"] == identity.node_id:
                    # keep the ORIGINAL since_ts: hosting began when it began
                    hosting_binding = prior
            except (OSError, ValueError, KeyError):
                pass                       # unreadable prior => re-sign
        try:
            with open(binding_path, "w", encoding="utf-8") as fh:
                json.dump(hosting_binding, fh, indent=2, sort_keys=True)
        except OSError as e:
            print("FATAL: cannot persist hosting binding %r: %s"
                  % (binding_path, e), file=sys.stderr)
            return 2

    # ---- ephemeral being over an existing history (recut5, P0.1) -------- #
    # The node rule since v0.4.1: an ephemeral identity must never be used
    # over a non-empty witness log. The being had no such rule, so every
    # restart without --being-keystore minted a new being:<hash> and then
    # served the PREVIOUS being's traces out of the journal it inherited.
    # Same defect, same fix, one level in.
    if args.being_profile and not args.being_keystore and being_jd:
        from runtime.recovery import journal_being_ids
        prior = journal_being_ids(os.path.join(being_jd, "tasks.jsonl"))
        if prior:
            print("FATAL: this being journal already holds the history of "
                  "%s and no --being-keystore was given, so this boot would "
                  "mint a NEW being and inherit that history as its own. "
                  "Supply the keystore that wrote it, or point "
                  "--being-journals at an empty directory."
                  % ", ".join(sorted(prior)), file=sys.stderr)
            return 2

    required_anchor = None
    if args.required_anchor_backends is not None:
        required_anchor = [b.strip() for b in
                           args.required_anchor_backends.split(",") if b.strip()]
        unknown = [b for b in required_anchor if b not in backend_names]
        if unknown:
            # Fail at startup, not at the first readiness scrape: a required
            # backend that is not configured would otherwise be silently
            # dropped by the scheduler and the node would report green on a
            # policy nobody is serving.
            print(f"FATAL: --required-anchor-backends names backend(s) that "
                  f"are not configured: {', '.join(unknown)}", file=sys.stderr)
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
                    required_anchor_backends=required_anchor,
                    being_identity=being_identity,
                    hosting_binding=hosting_binding,
                    anchor_store_path=anchor_store
                    if anchor_backends else None,
                    model_artifact_manifest=model_artifact_manifest,
                    being_profile=args.being_profile,
                    being_workspace=being_ws,
                    being_journal_dir=being_jd if args.being_profile else None,
                    being_provenance=being_prov,
                    rate_limits=rate_limits,
                    max_body_bytes=args.max_body_bytes,
                    max_concurrency=args.max_concurrency,
                    request_timeout_s=args.request_timeout_s,
                    anchor_lag_max_s=args.anchor_lag_max_s,
                    unanchored_depth_max=args.unanchored_depth_max,
                    isolation_profiles=[x.strip() for x in
                                        args.isolation_profiles.split(",")
                                        if x.strip()],
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
    srv = BoundedThreadingHTTPServer((args.host, args.port),
                                     make_handler(node), node=node)
    scheme = "http"
    if server_ssl is not None:
        srv.socket = server_ssl.wrap_socket(srv.socket, server_side=True)
        scheme = "https" + ("+mtls" if args.tls_require_client_cert else "")
    print(f"[{args.name}] node_id={node.chain.node_id[:16]}…  "
          f"identity={node.identity_mode}  "
          f"profile={args.profile}  {scheme}://{args.host}:{args.port}",
          flush=True)

    # ---- observability wiring (v0.6.6) ---------------------------------- #
    # Sleep detection runs everywhere, not only on the Mac node: a Linux host
    # that suspends is the same blind spot, and the detector costs one
    # comparison every two seconds.
    node.clockwatch = clockwatch.ClockWatch(
        threshold_s=args.sleep_gap_threshold_s,
        on_gap=lambda g: print(
            f"[{args.name}] HOST SUSPENDED for ~{g:.0f}s — witness "
            f"replication and anchoring are behind by at least that much",
            file=sys.stderr, flush=True),
        on_step=lambda g: print(
            f"[{args.name}] wall clock stepped {g:.0f}s relative to "
            f"monotonic (NTP correction, not a suspension)",
            file=sys.stderr, flush=True))
    node.clockwatch.start()

    interval = 0.0 if args.no_watchdog else sdnotify.watchdog_interval_s()
    if interval > 0:
        node.watchdog = sdnotify.Watchdog(
            node.liveness_beacon, interval,
            stale_after=args.beacon_stale_after_s,
            on_silence=lambda age: print(
                f"[{args.name}] WATCHDOG SILENT: accept loop has not moved "
                f"for {age:.0f}s — not answering systemd", file=sys.stderr,
                flush=True))
        node.watchdog.start()
        print(f"[{args.name}] systemd watchdog: pinging every "
              f"{interval:.0f}s while the accept loop has moved within "
              f"{args.beacon_stale_after_s:.0f}s", flush=True)
    # READY=1 goes out only now: under Type=notify systemd holds dependent
    # units until it arrives, and sending it before the socket is listening
    # would give that ordering guarantee away for nothing.
    if sdnotify.available():
        sdnotify.ready(f"listening on {args.host}:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if node.watchdog:
            node.watchdog.stop()
        if node.clockwatch:
            node.clockwatch.stop()
        if sdnotify.available():
            sdnotify.stopping()
    return 0


if __name__ == "__main__":
    sys.exit(main())
