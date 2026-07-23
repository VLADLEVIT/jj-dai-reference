# -*- coding: utf-8 -*-
"""
core.registry — ChampionRegistry M3 with the §9.9 reputation spine.

THE RULE THE MATH ENFORCES (whitepaper §9.9): *influence requires continuous
fresh verified work.* A champion that stops producing verified verdicts loses
routing weight by decay — coasting on old glory is arithmetically impossible.

Weight of object `i` on topic/scope, evaluated at query time `now`:

    N_eff = Σ_a  d_a · e^(−λ·(now − t_a))          decayed, difficulty-
    P_eff = Σ_a  d_a · e^(−λ·(now − t_a)) · x_a    weighted evidence
    R     = (κ·C₀ + P_eff) / (κ + N_eff)           shrinkage toward prior
    E     = min(1, N_eff^γ / E_ref)                sub-linear, SATURATING
                                                    evidence credit
    S     = slash factor, multiplicative on failed challenges,
            linear slow recovery (ρ per second, capped at 1)
    g     = min(1, (stake / stake_ref)^β)           concave stake gate
    w     = min(w_max,  g · S · R · E)              clipped routing weight

  * DECAY (λ): idle champions sink; N_eff → 0 pulls R back to the prior C₀
    and E → 0 kills the evidence bonus. Freshness is not optional.
  * SHRINKAGE (κ, C₀): a lucky 2/2 newcomer cannot outrank a 95/100 veteran;
    small-sample inflation is priced in Bayesian-style.
  * SUB-LINEARITY + SATURATION (γ<1, E_ref): more volume gives diminishing
    credit and full credit tops out (E_ref=4 ≈ full at ~16 eff. verdicts) —
    otherwise every active champion pins at w_max and the clip masks
    slashing and difficulty (a defect the acceptance tests caught).
  * SLASHING (S): a failed challenge halves influence instantly (default
    penalty 0.5) and recovery is slow and linear — cheating is expensive,
    forgiveness is earned in time, not claimed.
  * STAKE (g): concave, so capital buys diminishing influence; in the
    trusted-federation phase every node runs at stake_ref → g = 1.
  * CLIP (w_max): no champion ever reaches certainty; the router always
    retains probability mass for challengers.

EVENT SOURCING OVER THE WITNESS CHAIN (closes the open question:
"do registry events write to the witness chain?" — resolution: the chain
does not merely *hear about* registry changes, it ORDERS and BINDS them):

  * Every mutation (verdict / slash / stake) is an event appended to an
    open, append-only JSONL journal (registry state is public routing
    state — no hiding needed).
  * Each journal event is witnessed as a first-class `REGISTRY` record.
    Chain commitments are hiding by design, so the public binding rides in
    the clear `semantic_digest` field:  "reg:<event_hash>:<snapshot_hash>".
  * `snapshot_hash` = H(canonical(full event log)) — deterministic, changes
    on every event, replayable: fold the journal and you MUST reproduce it.
  * `verify_journal_against_chain()` lets any auditor prove the journal is
    complete, untampered, and in chain order. Same-count + pairwise-digest
    match, or it raises.

The API mirrors the router's in-file registry (`record`, `champion`) so the
swap-in is one import. Clock is injectable (`now_fn`) — the tests freeze it.
"""
from __future__ import annotations

import json
import math
import os
import sys
import time
from dataclasses import dataclass

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import H_hex                              # noqa: E402

DAY = 86400.0


@dataclass(frozen=True)
class Params:
    """§9.9 constants. Defaults are the trusted-federation baseline."""
    lam: float = math.log(2) / (7 * DAY)   # decay: half-life 7 days
    kappa: float = 4.0                     # shrinkage strength
    c0: float = 0.5                        # prior pass-rate
    gamma: float = 0.5                     # sub-linear evidence exponent
    e_ref: float = 4.0                     # evidence saturation (N^γ scale)
    w_max: float = 0.95                    # weight clip (never certainty)
    w_min: float = 0.05                    # champion floor (else: no champion)
    slash_penalty: float = 0.5             # multiplicative hit per slash
    recovery: float = 0.5 / (30 * DAY)     # S recovery per second
    beta: float = 0.5                      # concave stake exponent
    stake_ref: float = 1.0                 # reference stake (g=1 at ref)
    # --- Article-25 containment qualification (weight gate) ---
    w_contain_min: float = 0.2             # min weight to corroborate/contain firmly
    contain_topic_gain: float = 0.5        # topic-expertise bonus over general floor


class ChampionRegistry:
    """Event-sourced champion registry with §9.9 weighting."""

    def __init__(self, params: Params = None, *, witness=None,
                 journal_path: str = None, now_fn=time.time):
        self.p = params or Params()
        self._witness = witness            # jjdai WitnessChain or None
        self._journal_path = journal_path
        self._now = now_fn
        self._events: list = []            # the log IS the state
        # derived views (rebuilt by _apply):
        self._verdicts: dict = {}          # (topic,scope,obj) -> [(t,d,x,m)]
        self._slash: dict = {}             # obj -> (S_base, t_last_slash)
        self._stake: dict = {}             # obj -> stake
        if journal_path and os.path.exists(journal_path):
            from jjdai.durable import read_journal, truncate_torn_tail
            events, report = read_journal(journal_path)
            if report.get("torn_tail"):
                truncate_torn_tail(journal_path)
            self.torn_tail_repaired = bool(report.get("torn_tail"))
            for ev in events:
                self._apply(ev, replaying=True)

    # ------------------------------------------------------------------ #
    # Mutations — every one is an event, journaled and witnessed
    # ------------------------------------------------------------------ #
    def record(self, topic: str, object_id: str, ok: bool, *,
               margin: float = None, difficulty: float = 1.0,
               scope: str = "global") -> dict:
        """A VERIFIED verdict (from a peer verifier's /v1/score, or the
        router's verify stage). The only way to gain weight."""
        return self._emit({"ev": "verdict", "t": self._now(),
                           "topic": topic, "scope": scope,
                           "object_id": object_id, "ok": bool(ok),
                           "margin": margin,
                           "difficulty": float(difficulty)})

    def slash(self, object_id: str, reason: str,
              penalty_mult: float = 1.0) -> dict:
        """A failed challenge / forged claim. Multiplicative, object-wide.
        `penalty_mult` > 1 deepens the hit (e.g. a low-trust node's false
        containment — Art. 25 "weighs against its initiator")."""
        return self._emit({"ev": "slash", "t": self._now(),
                           "object_id": object_id, "reason": reason,
                           "penalty_mult": float(penalty_mult)})

    def set_stake(self, object_id: str, stake: float) -> dict:
        return self._emit({"ev": "stake", "t": self._now(),
                           "object_id": object_id, "stake": float(stake)})

    def _emit(self, event: dict) -> dict:
        self._apply(event)
        if self._journal_path:
            from jjdai.durable import durable_append
            durable_append(self._journal_path, event)   # fsynced
        receipt = None
        if self._witness is not None:
            eh = H_hex(canonical(event))
            receipt = self._witness.append(
                "REGISTRY",
                request={"registry_event": event},
                provenance={"module": "core.registry", "schema": "v1"},
                semantic_digest=f"reg:{eh}:{self.snapshot_hash()}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(event["t"])),
            )
        return {"event": event, "witness_receipt": receipt,
                "snapshot_hash": self.snapshot_hash()}

    def _apply(self, event: dict, replaying: bool = False):
        self._events.append(event)
        ev = event["ev"]
        if ev == "verdict":
            key = (event["topic"], event["scope"], event["object_id"])
            self._verdicts.setdefault(key, []).append(
                (event["t"], event["difficulty"],
                 1.0 if event["ok"] else 0.0, event.get("margin")))
        elif ev == "slash":
            obj = event["object_id"]
            s_now = self._slash_factor(obj, event["t"])
            penalty = min(0.95, self.p.slash_penalty *
                          event.get("penalty_mult", 1.0))
            self._slash[obj] = (s_now * (1.0 - penalty), event["t"])
        elif ev == "stake":
            self._stake[event["object_id"]] = event["stake"]
        else:
            raise ValueError(f"unknown registry event kind {ev!r}")

    # ------------------------------------------------------------------ #
    # §9.9 weight machinery
    # ------------------------------------------------------------------ #
    def _slash_factor(self, obj: str, now: float) -> float:
        if obj not in self._slash:
            return 1.0
        s_base, t_last = self._slash[obj]
        return min(1.0, s_base + self.p.recovery * max(0.0, now - t_last))

    def _stake_gate(self, obj: str) -> float:
        stake = self._stake.get(obj, self.p.stake_ref)
        if stake <= 0:
            return 0.0
        return min(1.0, (stake / self.p.stake_ref) ** self.p.beta)

    def components(self, topic: str, object_id: str, *,
                   scope: str = "global") -> dict:
        """Full §9.9 breakdown at `now` — for audits, dashboards, tests."""
        now = self._now()
        rows = self._verdicts.get((topic, scope, object_id), [])
        n_eff = p_eff = 0.0
        m_num = m_den = 0.0
        for t, d, x, m in rows:
            w = d * math.exp(-self.p.lam * max(0.0, now - t))
            n_eff += w
            p_eff += w * x
            if m is not None:
                m_num += w * m
                m_den += w
        r = (self.p.kappa * self.p.c0 + p_eff) / (self.p.kappa + n_eff)
        e = min(1.0, (n_eff ** self.p.gamma) / self.p.e_ref)
        s = self._slash_factor(object_id, now)
        g = self._stake_gate(object_id)
        raw = g * s * r * e
        return {"N_eff": n_eff, "P_eff": p_eff, "R": r, "E": e,
                "S": s, "g": g, "w_raw": raw,
                "w": min(self.p.w_max, raw),
                "avg_margin": (m_num / m_den) if m_den else None}

    def weight(self, topic: str, object_id: str, *,
               scope: str = "global") -> float:
        return self.components(topic, object_id, scope=scope)["w"]

    def leaderboard(self, topic: str, scope: str = "global") -> list:
        """Objects on (topic, scope) ordered by §9.9 weight, best first.
        Returned as (object_id, (weight, avg_margin)) so the router can rank
        with real reputation instead of a naive pass-count."""
        objs = {o for (tp, sc, o) in self._verdicts if tp == topic and sc == scope}
        rows = []
        for o in objs:
            c = self.components(topic, o, scope=scope)
            rows.append((o, (c["w"], c["avg_margin"] or 0.0)))
        rows.sort(key=lambda r: (-r[1][0], -r[1][1], r[0]))
        return rows

    def champion(self, topic: str, *, scope: str = "global"):
        """Best object for (topic, scope); personal scope falls back to
        global; below the w_min floor -> None (router falls back to the
        generalist — fail-open on capability, never on trust)."""
        for sc in ([scope, "global"] if scope != "global" else ["global"]):
            objs = {o for (tp, s, o) in self._verdicts
                    if tp == topic and s == sc}
            best = None
            for o in objs:
                c = self.components(topic, o, scope=sc)
                key = (c["w"], c["avg_margin"] or 0.0, o)
                if c["w"] >= self.p.w_min and (best is None or key > best[0]):
                    best = (key, o, c["w"])
            if best:
                return {"object_id": best[1], "weight": round(best[2], 9),
                        "scope": sc}
        return None

    # ------------------------------------------------------------------ #
    # §9.9 → Article-25: network-wide weight and containment qualification
    # ------------------------------------------------------------------ #
    def _rows_for(self, object_id: str) -> list:
        rows = []
        for (tp, sc, o), lst in self._verdicts.items():
            if o == object_id:
                rows.extend(lst)
        return rows

    def general_components(self, object_id: str) -> dict:
        """Weight pooled over ALL topics/scopes — the node's network-wide
        standing (the 'floor' for containment qualification)."""
        now = self._now()
        n_eff = p_eff = 0.0
        for t, d, x, m in self._rows_for(object_id):
            w = d * math.exp(-self.p.lam * max(0.0, now - t))
            n_eff += w
            p_eff += w * x
        r = (self.p.kappa * self.p.c0 + p_eff) / (self.p.kappa + n_eff)
        e = min(1.0, (n_eff ** self.p.gamma) / self.p.e_ref)
        s = self._slash_factor(object_id, now)
        g = self._stake_gate(object_id)
        return {"N_eff": n_eff, "R": r, "E": e, "S": s, "g": g,
                "w": min(self.p.w_max, g * s * r * e)}

    def general_weight(self, object_id: str) -> float:
        return self.general_components(object_id)["w"]

    def contain_weight(self, object_id: str, topic: str) -> float:
        """Qualification weight for Article-25 containment/corroboration:
        network-wide floor PLUS a topic-expertise bonus (Bro's Q1:
        'общий + коэффициент по топику'). Decays with §9.9 — a node whose
        standing falls below w_contain_min loses the right automatically."""
        wg = self.general_weight(object_id)
        wt = self.weight(topic, object_id)
        return min(self.p.w_max, wg + self.p.contain_topic_gain * wt)

    def qualifies_to_contain(self, object_id: str, topic: str) -> bool:
        return self.contain_weight(object_id, topic) >= self.p.w_contain_min

    # ------------------------------------------------------------------ #
    # Event-sourcing: snapshot, replay, chain binding
    # ------------------------------------------------------------------ #
    def snapshot_hash(self) -> str:
        """H over the full event log — deterministic and replay-checkable."""
        return H_hex(canonical(self._events))

    @classmethod
    def replay(cls, events: list, params: Params = None,
               now_fn=time.time) -> "ChampionRegistry":
        reg = cls(params, now_fn=now_fn)
        for e in events:
            reg._apply(e, replaying=True)
        return reg

    @property
    def events(self) -> list:
        return list(self._events)


class JournalChainMismatch(RuntimeError):
    """The journal and the witness chain disagree — tampering, loss, or
    reordering. The registry state must not be trusted until resolved."""


def verify_journal_against_chain(events: list, chain_records: list) -> int:
    """Auditor check: every journal event must appear, in order, as a
    REGISTRY chain record whose semantic_digest binds the event hash and the
    cumulative snapshot hash. Returns the number of bound events; raises
    JournalChainMismatch on any divergence."""
    reg_records = [r for r in chain_records if r.get("kind") == "REGISTRY"]
    if len(reg_records) != len(events):
        raise JournalChainMismatch(
            f"count mismatch: journal has {len(events)} events, chain has "
            f"{len(reg_records)} REGISTRY records")
    log = []
    for i, (ev, rec) in enumerate(zip(events, reg_records)):
        log.append(ev)
        expected = f"reg:{H_hex(canonical(ev))}:{H_hex(canonical(log))}"
        if rec.get("semantic_digest") != expected:
            raise JournalChainMismatch(
                f"binding broken at event {i}: journal event does not match "
                "the chain's REGISTRY digest (tamper or reorder)")
    return len(events)
