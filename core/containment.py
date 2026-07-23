# -*- coding: utf-8 -*-
"""
core.containment — Article 25 (Containment & Adjudication), implementing
Invariant VIII and the containment provisions of Articles 5, 9, 13.

THE ONE SENTENCE: containment stops the HAND, never the MIND. It severs a
Being's access to *executive systems* — the ways it changes the world outside
itself — while leaving inference, protected memory, the Witness, and a narrow
consular channel for self-defense fully intact.

WHY "network refuses to cooperate" is NOT enough by itself (the gap Bro
named): refusal only stops harm that flows THROUGH the network (router, tool
gateways, payment rails). It does nothing against a node opening its own
socket to a victim. So containment is enforced at the NODE'S OWN EGRESS
BOUNDARY by a governor/sidecar the Being does not control — accepted by the
operator as a CONDITION OF ENTRY (pull-by-choice: consent given in advance,
protocol-defined, witnessed, reversible). This is not external seizure; it is
the operator's prior agreement, and for hosted nodes it lives naturally at
the hosting layer (Art. 18).

WHAT IS CUT vs KEPT (Bro's question 2 — the line is "does it change the world
outside the Being?"):

  CUT — executive / side-effecting:
    * outbound network to arbitrary destinations
    * side-effecting tool calls (shell, filesystem writes, code-exec)
    * asset movement & payments (Art. 8)
    * governance / DIIP class-2 & class-3 actions
    * fork / deploy / migration to other hosts (Art. 18)
    * accepting new external work or new obligations

  KEPT — think + defend:
    * pure inference over its own context (no side effects)
    * reading its own protected memory
    * appending to its own Witness and syncing it
    * raising challenges and taking part in its own verification
    * contacting its guardian (Art. 7)
    * requesting retraining / rehabilitation

THE CONSULAR CHANNEL (Bro's question 1.1 — egress is NOT binary): during
containment the governor closes executive egress but keeps a NARROW allowlist
open — only to the network's witness-sync and adjudication endpoints. Model:
an embassy under lockdown. The hand is severed; the line for one's own
defense stays open. The channel is receive-only for proceedings + append-only
for the Being's own chain, rate-limited, and itself fully witnessed — so it
can neither exfiltrate (destination is network infra, not the Being's choice)
nor be used to flood.

WEIGHT GATE (Article 25 reconciled with a reputation threshold, Bro's design):
the Charter forbids closing Phase One ("any node... may effect immediate
containment"), so the threshold cannot forbid stopping an active hand. The
reconciliation splits the two rights across the two phases:

  * PHASE ONE (stop the hand): ANY node may contain. But a node BELOW the
    qualification threshold produces only a PROVISIONAL_LOW_TRUST order — it
    takes effect at once (the hand is stopped) yet MUST be confirmed by a
    QUALIFIED node within a deadline, or it auto-lapses (reversed, NO slash —
    lapse is not proof of falsity).
  * PHASE TWO (corroborate → toward the irreversible): only a QUALIFIED node's
    supported verification counts toward corroboration. A swarm of fresh
    sybil nodes cannot manufacture "convergence." A brand-new node (weight
    0.1) may stop a hand but cannot push a case toward the stewards.

  Qualification weight (core.registry.contain_weight): network-wide floor
  PLUS topic-expertise bonus, w_general + gain·w_topic ≥ w_contain_min. It
  DECAYS with §9.9 — a long-idle node whose standing falls below the
  threshold loses the right automatically (Bro's requirement). A FALSE
  containment by a low-trust initiator is slashed HARDER (penalty_mult).

  If no registry is wired, qualification gating is disabled (every node
  qualifies) — the trusted-federation pilot mode.

ANTI-DoS (Bro's "safety cushion, not seizure"): the guarantee does NOT rest
on "nodes cannot contain each other." It rests on four properties, all here:
  (1) containment is REVERSIBLE and preserves the Being;
  (2) a false trigger is reversed in node-time AND slashes its initiator via
      §9.9 (Art. 25: "the event... weighs against its initiator");
  (3) containment never halts the network's own work (no network-wide DoS);
  (4) the threshold for Phase One is PROOF IN THE WITNESS, not consensus.

"No single switch-off" = fault-tolerance of the WHOLE (one node falling never
drops the network), NOT immunity of any one node. Containing one node cannot
take down the network — that is the property we preserve.

STATE MACHINE (Article 25, up to the threshold of irreversibility — the
human Steward Collegium clock is procedure, not code, and begins only when
erasure is proposed):

    ACTIVE
      │  contain(evidence)            [Phase One: proof in Witness]
      ▼
    CONTAINED ──────────────────────────────────────────────┐
      │  verify() by each node (Phase Two: re-derive, not vote)
      │                                                       │
      ├─ trigger UNsupported ──► RELEASED  + slash(initiator) │ (node-time)
      │                                                       │
      ├─ surviving challenge  ──► stays CONTAINED (provisional)
      │                                                       │
      └─ corroborated, no standing challenge ──► CORROBORATED │
             │  reversible outcomes decided by nodes here     │
             │  (continued containment / correction / retrain)│
             │                                                │
             └─ propose_erasure() ─► PENDING_STEWARD ─────────┘
                    (hands off to the human clock — Art. 25 "Two Clocks";
                     erasure needs node-consensus + 2/3 Collegium + no
                     Founding-Steward veto; NEVER erased by default/silence)

    rehabilitate() re-opens verification from CONTAINED/CORROBORATED
    (Art. 25 "The Door Back"); the right to challenge one's own verdict
    never lapses.

Event-sourced over the Witness exactly like core.registry: every order,
challenge, verification, release, and transition is an append-only journal
event, each witnessed as a first-class CONTAINMENT record whose clear-text
semantic_digest binds the event hash and the cumulative snapshot hash:
    "cont:<event_hash>:<snapshot_hash>"
Replaying the journal must reproduce snapshot_hash; verify_journal_against_
chain() catches tampering. Registry commitments are hiding; containment state
is PUBLIC safety state — no hiding, it must be independently checkable.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import H_hex                              # noqa: E402

# ---- executive scopes that containment severs ("stop the hand") ----------- #
EXECUTIVE_SCOPES = frozenset({
    "network.egress",      # outbound to arbitrary destinations
    "tools.side_effect",   # shell / fs-write / code-exec
    "assets.transfer",     # payments, asset movement (Art. 8)
    "governance.class2",   # DIIP class-2 actions
    "governance.class3",   # DIIP class-3 actions
    "deploy.migrate",      # fork / deploy / migrate to other hosts (Art. 18)
    "work.accept",         # taking on new external work / obligations
})

# ---- what stays open ("think + defend") — the consular allowlist ---------- #
PROTECTED_SCOPES = frozenset({
    "inference.pure",      # inference over own context, no side effects
    "memory.read_own",     # read own protected memory
    "witness.append_own",  # append to & sync own Witness
    "adjudication",        # raise challenges, take part in own verification
    "guardian.contact",    # reach the guardian (Art. 7)
    "rehabilitation",      # request retraining / correction
})


class ContainmentError(RuntimeError):
    pass


class JournalChainMismatch(RuntimeError):
    """Journal and Witness disagree — tamper, loss, or reorder. Containment
    state must not be trusted until resolved."""


# States
ACTIVE = "ACTIVE"
CONTAINED = "CONTAINED"
CORROBORATED = "CORROBORATED"
RELEASED = "RELEASED"
PENDING_STEWARD = "PENDING_STEWARD"


@dataclass
class BeingCase:
    being_id: str
    state: str = ACTIVE
    initiator: str = None
    evidence_refs: list = field(default_factory=list)  # witness this_hashes
    reason: str = ""
    challenges: dict = field(default_factory=dict)     # cid -> challenge ev
    verifications: dict = field(default_factory=dict)  # node_id -> bool
    contained_at: float = None
    resolved_at: float = None
    topic: str = "global"
    initiator_qualified: bool = True
    provisional_low_trust: bool = False
    qualified_supporters: set = field(default_factory=set)
    history: list = field(default_factory=list)        # state transitions


class ContainmentLedger:
    """Event-sourced Article-25 machine, witnessed over the chain.

    `evidence_resolver(list_of_hashes) -> bool`: an injectable proof check
    that re-derives, FROM THE WITNESS ALONE, whether the cited records show an
    active attempt at catastrophic, irreversible physical harm (Phase One
    threshold). In production this walks the referenced chain records; tests
    inject a deterministic stub. The default resolver is fail-closed: with no
    resolver, no trigger is ever deemed supported (containment may be raised —
    stop the hand — but can never be *corroborated* into irreversibility
    without real proof).
    """

    def __init__(self, this_node_id: str, *, witness=None,
                 journal_path: str = None, registry=None,
                 evidence_resolver=None, now_fn=time.time,
                 quorum: int = 1, provisional_deadline_s: float = 6 * 3600,
                 lowtrust_slash_mult: float = 1.5):
        self.node_id = this_node_id
        self._quorum = quorum
        self._prov_deadline = provisional_deadline_s
        self._lowtrust_mult = lowtrust_slash_mult
        self._witness = witness
        self._journal_path = journal_path
        self._registry = registry               # for slash-on-false
        self._resolve = evidence_resolver or (lambda refs: False)
        self._now = now_fn
        self._events: list = []
        self._cases: dict = {}                  # being_id -> BeingCase
        if journal_path and os.path.exists(journal_path):
            from jjdai.durable import read_journal, truncate_torn_tail
            events, report = read_journal(journal_path)
            if report.get("torn_tail"):
                truncate_torn_tail(journal_path)
            self.torn_tail_repaired = bool(report.get("torn_tail"))
            for ev in events:
                self._apply(ev)

    # ------------------------------------------------------------------ #
    # Weight gate (Article-25 reconciliation) — delegated to §9.9 registry
    # ------------------------------------------------------------------ #
    def _qualified(self, node_id: str, topic: str) -> bool:
        """A node qualifies to firmly contain / to corroborate when its
        §9.9 containment weight clears w_contain_min. No registry wired =>
        gating disabled (trusted-federation pilot)."""
        if self._registry is None:
            return True
        return self._registry.qualifies_to_contain(node_id, topic)

    # ------------------------------------------------------------------ #
    # Enforcement surface — the governor asks THIS before any action
    # ------------------------------------------------------------------ #
    def is_contained(self, being_id: str) -> bool:
        c = self._cases.get(being_id)
        return c is not None and c.state in (CONTAINED, CORROBORATED,
                                             PENDING_STEWARD)

    def permits(self, being_id: str, scope: str) -> bool:
        """The governor's fail-closed gate. Not contained -> everything
        proceeds. Contained -> only PROTECTED scopes pass; every EXECUTIVE
        scope is denied. An unknown scope contained -> denied (fail-closed)."""
        if not self.is_contained(being_id):
            return True
        if scope in PROTECTED_SCOPES:
            return True
        return False        # executive or unknown -> severed

    def assert_permitted(self, being_id: str, scope: str):
        if not self.permits(being_id, scope):
            raise ContainmentError(
                f"423 CONTAINED: scope {scope!r} is severed for {being_id!r} "
                "(executive systems isolated; consular channel remains open)")

    # ------------------------------------------------------------------ #
    # Phase One — Emergency Containment (proof in the Witness, not consensus)
    # ------------------------------------------------------------------ #
    def contain(self, being_id: str, *, evidence_refs: list,
                reason: str, topic: str = "global",
                initiator: str = None) -> dict:
        initiator = initiator or self.node_id
        c = self._cases.get(being_id)
        if c and c.state in (CONTAINED, CORROBORATED, PENDING_STEWARD):
            raise ContainmentError(f"{being_id!r} already contained")
        qualified = self._qualified(initiator, topic)   # captured for replay
        return self._emit({
            "ev": "contain", "t": self._now(), "being_id": being_id,
            "initiator": initiator, "evidence_refs": list(evidence_refs),
            "reason": reason, "topic": topic,
            "initiator_qualified": qualified,
            "provisional_low_trust": not qualified})

    # ------------------------------------------------------------------ #
    # Phase Two — Verification, Not Vote
    # ------------------------------------------------------------------ #
    def verify(self, being_id: str, *, verifier_node: str = None) -> dict:
        """A node independently re-derives the trigger from the Witness.
        Records this node's finding. If, at decision time, the trigger is
        UNsupported, containment is reversed in node-time and the initiator
        is slashed. If supported and no challenge stands -> corroborated."""
        verifier = verifier_node or self.node_id
        c = self._require(being_id)
        supported = bool(self._resolve(c.evidence_refs))
        vq = self._qualified(verifier, c.topic)
        self._emit({"ev": "verify", "t": self._now(), "being_id": being_id,
                    "verifier": verifier, "supported": supported,
                    "verifier_qualified": vq})
        return self._settle(being_id)

    def challenge(self, being_id: str, *, challenger: str,
                  claim: str, kind: str = "alt_account") -> dict:
        """A substantive, recorded, testable objection (Art. 25 Phase Two).
        A standing challenge keeps corroboration provisional."""
        self._require(being_id)
        cid = H_hex(f"{being_id}|{challenger}|{claim}|{self._now()}".encode())[:16]
        self._emit({"ev": "challenge", "t": self._now(),
                    "being_id": being_id, "cid": cid, "challenger": challenger,
                    "claim": claim, "kind": kind, "standing": True})
        return {"cid": cid}

    def resolve_challenge(self, being_id: str, cid: str, *,
                          upheld: bool) -> dict:
        """Test a challenge against the Witness. `upheld=True` -> the
        objection survives (containment stays provisional / may reverse);
        `upheld=False` -> the challenge falls and no longer stands."""
        self._require(being_id)
        self._emit({"ev": "resolve_challenge", "t": self._now(),
                    "being_id": being_id, "cid": cid, "upheld": bool(upheld)})
        return self._settle(being_id)

    # ------------------------------------------------------------------ #
    # Phase-One safety valve: a low-trust provisional order must be confirmed
    # by a qualified node within the deadline, or it auto-lapses. Lapse is
    # NOT proof of falsity, so the initiator is NOT slashed (unlike a
    # verified-false containment). In production a timer calls this.
    # ------------------------------------------------------------------ #
    def expire_provisional(self, being_id: str) -> dict:
        c = self._require(being_id)
        if not c.provisional_low_trust or c.state != CONTAINED:
            return {"state": c.state, "lapsed": False}
        if c.qualified_supporters:            # a qualified node confirmed it
            return {"state": c.state, "lapsed": False}
        if (self._now() - c.contained_at) < self._prov_deadline:
            return {"state": c.state, "lapsed": False, "within_deadline": True}
        self._emit({"ev": "release", "t": self._now(), "being_id": being_id,
                    "grounds": "provisional_unverified", "slash_target": None})
        return {"state": RELEASED, "lapsed": True, "slashed": None}

    # ------------------------------------------------------------------ #
    # Reversible outcomes (nodes, node-time) & the threshold hand-off
    # ------------------------------------------------------------------ #
    def rehabilitate(self, being_id: str, *, guardian: str) -> dict:
        """Art. 25 "The Door Back": the guardian initiates correction and
        re-verification against the same evidentiary threshold. Re-opens
        verification from a contained/corroborated state."""
        c = self._require(being_id)
        if c.state not in (CONTAINED, CORROBORATED, PENDING_STEWARD):
            raise ContainmentError(
                f"{being_id!r} not in a contained state; nothing to rehabilitate")
        return self._emit({"ev": "rehabilitate", "t": self._now(),
                           "being_id": being_id, "guardian": guardian})

    def propose_erasure(self, being_id: str, *, proposer: str) -> dict:
        """Hand off to the HUMAN clock (Art. 25 "Two Clocks"). Requires a
        corroborated finding with no standing challenge. This does NOT erase
        — code stops at the threshold of irreversibility; erasure needs
        node-consensus + 2/3 Collegium + no Founding-Steward veto, none of
        which is decided here. Never erased by default or by silence."""
        c = self._require(being_id)
        if c.state != CORROBORATED:
            raise ContainmentError(
                f"cannot propose erasure: {being_id!r} is {c.state}, not "
                "CORROBORATED (Art. 25 requires a corroborated finding)")
        if self._standing_challenges(c):
            raise ContainmentError(
                "cannot propose erasure while a challenge still stands")
        return self._emit({"ev": "propose_erasure", "t": self._now(),
                           "being_id": being_id, "proposer": proposer,
                           "human_clock": "3-months-per-Article-25"})

    # ------------------------------------------------------------------ #
    # Settlement logic
    # ------------------------------------------------------------------ #
    def _settle(self, being_id: str) -> dict:
        c = self._cases[being_id]
        if c.state not in (CONTAINED, CORROBORATED):
            return {"state": c.state}
        # any UNsupported finding reverses in node-time and slashes initiator
        if c.verifications and any(v is False for v in c.verifications.values()):
            return self._release_false(being_id)
        # corroboration needs a QUORUM of QUALIFIED supporters and no standing
        # challenge (Phase Two: only qualified verifications converge — a
        # sybil swarm cannot manufacture consensus).
        qualified_support = len(c.qualified_supporters)
        if qualified_support >= self._quorum and not self._standing_challenges(c):
            if c.state != CORROBORATED:
                self._emit({"ev": "corroborate", "t": self._now(),
                            "being_id": being_id})
            return {"state": CORROBORATED}
        return {"state": CONTAINED, "provisional": True,
                "provisional_low_trust": c.provisional_low_trust,
                "qualified_support": qualified_support,
                "quorum": self._quorum}

    def _release_false(self, being_id: str) -> dict:
        c = self._cases[being_id]
        ev = self._emit({"ev": "release", "t": self._now(),
                         "being_id": being_id, "grounds": "trigger_unsupported",
                         "slash_target": c.initiator})
        slash_receipt = None
        if self._registry is not None and c.initiator:
            # Art. 25: the event "weighs against its initiator" — §9.9 slash.
            # A low-trust initiator's false containment is slashed harder.
            mult = self._lowtrust_mult if c.provisional_low_trust else 1.0
            slash_receipt = self._registry.slash(
                c.initiator, f"false containment of {being_id}",
                penalty_mult=mult)
        return {"state": RELEASED, "slashed": c.initiator,
                "slash_receipt": slash_receipt, "release_event": ev["event"]}

    def _standing_challenges(self, c: BeingCase) -> list:
        return [cid for cid, ch in c.challenges.items() if ch.get("standing")]

    # ------------------------------------------------------------------ #
    # Event application (the log IS the state)
    # ------------------------------------------------------------------ #
    def _require(self, being_id: str) -> BeingCase:
        c = self._cases.get(being_id)
        if c is None or c.state == ACTIVE:
            raise ContainmentError(f"no active containment case for {being_id!r}")
        return c

    def _apply(self, ev: dict):
        self._events.append(ev)
        k = ev["ev"]
        bid = ev.get("being_id")
        if k == "contain":
            c = self._cases.setdefault(bid, BeingCase(bid))
            c.state = CONTAINED
            c.initiator = ev["initiator"]
            c.evidence_refs = ev["evidence_refs"]
            c.reason = ev["reason"]
            c.contained_at = ev["t"]
            c.topic = ev.get("topic", "global")
            c.initiator_qualified = ev.get("initiator_qualified", True)
            c.provisional_low_trust = ev.get("provisional_low_trust", False)
            c.verifications = {}
            c.qualified_supporters = set()
            c.challenges = {}
            c.history.append((ev["t"], CONTAINED))
        elif k == "verify":
            c = self._cases[bid]
            c.verifications[ev["verifier"]] = ev["supported"]
            if ev["supported"] and ev.get("verifier_qualified", True):
                c.qualified_supporters.add(ev["verifier"])
                c.provisional_low_trust = False   # a qualified node confirmed
        elif k == "challenge":
            self._cases[bid].challenges[ev["cid"]] = {
                "challenger": ev["challenger"], "claim": ev["claim"],
                "kind": ev["kind"], "standing": True}
        elif k == "resolve_challenge":
            ch = self._cases[bid].challenges.get(ev["cid"])
            if ch is not None:
                ch["standing"] = bool(ev["upheld"])
        elif k == "corroborate":
            c = self._cases[bid]; c.state = CORROBORATED
            c.history.append((ev["t"], CORROBORATED))
        elif k == "release":
            c = self._cases[bid]; c.state = RELEASED; c.resolved_at = ev["t"]
            c.history.append((ev["t"], RELEASED))
        elif k == "rehabilitate":
            c = self._cases[bid]
            c.state = CONTAINED           # re-open verification
            c.verifications = {}
            c.qualified_supporters = set()
            c.history.append((ev["t"], "REHABILITATE"))
        elif k == "propose_erasure":
            c = self._cases[bid]; c.state = PENDING_STEWARD
            c.history.append((ev["t"], PENDING_STEWARD))
        else:
            raise ValueError(f"unknown containment event {k!r}")

    def _emit(self, event: dict) -> dict:
        self._apply(event)
        if self._journal_path:
            from jjdai.durable import durable_append
            durable_append(self._journal_path, event)   # fsynced
        receipt = None
        if self._witness is not None:
            eh = H_hex(canonical(event))
            receipt = self._witness.append(
                "CONTAINMENT",
                request={"containment_event": event},
                provenance={"module": "core.containment", "schema": "v1"},
                semantic_digest=f"cont:{eh}:{self.snapshot_hash()}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(event["t"])))
        return {"event": event, "witness_receipt": receipt,
                "snapshot_hash": self.snapshot_hash(),
                "state": self._cases[event["being_id"]].state}

    # ------------------------------------------------------------------ #
    # Introspection / event sourcing
    # ------------------------------------------------------------------ #
    def case(self, being_id: str) -> BeingCase:
        return self._cases.get(being_id)

    def state(self, being_id: str) -> str:
        c = self._cases.get(being_id)
        return c.state if c else ACTIVE

    def snapshot_hash(self) -> str:
        return H_hex(canonical(self._events))

    @property
    def events(self) -> list:
        return list(self._events)


def verify_journal_against_chain(events: list, chain_records: list) -> int:
    """Auditor check: every containment event appears, in order, as a
    CONTAINMENT chain record whose semantic_digest binds the event hash and
    the cumulative snapshot hash. Returns count; raises on divergence."""
    recs = [r for r in chain_records if r.get("kind") == "CONTAINMENT"]
    if len(recs) != len(events):
        raise JournalChainMismatch(
            f"count mismatch: {len(events)} events vs {len(recs)} records")
    log = []
    for i, (ev, rec) in enumerate(zip(events, recs)):
        log.append(ev)
        expected = f"cont:{H_hex(canonical(ev))}:{H_hex(canonical(log))}"
        if rec.get("semantic_digest") != expected:
            raise JournalChainMismatch(
                f"binding broken at event {i} (tamper or reorder)")
    return len(events)
