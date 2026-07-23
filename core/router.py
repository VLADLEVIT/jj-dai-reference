"""
JJ DAI — Unified Router (reference implementation, v0.2)
=======================================================

The *coarse, explicit, auditable* routing brain above the NECS membrane — the
metaphorical "MoE-of-specialists", NOT the neural gate inside the model (which
lives below NECS, sealed inside NodeEngine.generate(), deliberately un-witnessed).

What changed in v0.2
--------------------
Champions are no longer a static table baked into the policy. They come from a
`ChampionRegistry` — a per-topic leaderboard built ONLY from *verified verdicts*
(mirrors the M3 registry.ChampionRegistry). The verdict from our reproducible
`score()` verifier is fed straight back into the registry, so the thing that
ranks specialists is the same thing that attests their output. Loop closed:

    generate (fast, attested)  ->  score (slow, reproducible)  ->  verdict
    verdict  ->  ChampionRegistry.record  ->  leaderboard  ->  next champion

Two hashes, deliberately separated
----------------------------------
- `policy_hash`  = classifier_rules + abac_rules + version.  STATIC, replicated;
  every local router must agree. Divergence here is a BUG.
- `registry.snapshot_hash()` = the dynamic leaderboard. LOCAL, evidence-driven;
  routers may legitimately hold DIFFERENT champions (personal champion /
  pull-by-choice). Divergence here is EXPECTED and must stay auditable, so the
  snapshot hash is stamped into every dispatch record — but it is NOT part of
  the replicated policy hash. Changing a champion never changes policy_hash.

Locked design decisions (unchanged from v0.1)
---------------------------------------------
1. One router, one flat decision plane; specialists AND agents share the pool.
2. Every routing decision is a C3 witness event.
3. ABAC / political gate is fail-closed.
4. Capability-matching dispatch is fail-closed (no silent downgrade).
5. Generator/verifier asymmetry on one substrate; verifier checks per-token
   reachability under committed sampling params, not bit-equality.
6. Requester choice: the router proposes the champion, the requester may
   override; the override (or its rejection) is witnessed.

Production seams: jjdai.crypto (Ed25519) / jjdai.canonical (JCS) / real engines
/ LLM classifier / the existing registry.ChampionRegistry — all swap in at the
call sites without touching interfaces.
"""

from __future__ import annotations

import hashlib
import json
import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional, Sequence, Tuple


# --------------------------------------------------------------------------- #
# 0. Canonicalisation + hashing — UNIFIED (v0.3.1.4): the real primitives.
#    The stand-ins are gone: canonical() was plain sorted-JSON, not RFC 8785
#    JCS, so the router's hashes disagreed with every other layer's. Now there
#    is ONE canonicalisation and ONE hash in the codebase.
# --------------------------------------------------------------------------- #
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..")))

from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import H_hex as sha256_hex                # noqa: E402
from jjdai.witness import WitnessChain as _RealWitnessChain  # noqa: E402
from core.registry import (ChampionRegistry as _RealRegistry,  # noqa: E402
                           Params as RegistryParams)


def content_id(obj) -> str:
    return sha256_hex(canonical(obj))


# --------------------------------------------------------------------------- #
# 1. Witness layer (C3) — hash-chained, injectable signer (prod: Ed25519)
# --------------------------------------------------------------------------- #

@dataclass
class WitnessRecord:
    """Router-facing view of a real witness record (event_type + payload)."""

    def __init__(self, event_type: str, payload: dict, record: dict):
        self.event_type = event_type
        self.payload = payload
        self.record = record            # the REAL signed chain record

    @property
    def record_hash(self) -> str:
        return self.record["this_hash"]


class WitnessChain:
    """UNIFIED (v0.3.1.4): an ADAPTER over jjdai.witness.WitnessChain.

    The stand-in this replaces was a hash-chain whose "signature" was the
    string "unsigned:"+hash[:16] — i.e. no signature at all. Every routing
    decision the router claimed to witness was unsigned and unverifiable. Now
    each decision is a REAL Ed25519-signed ROUTE record on the real chain,
    with the payload hidden behind a commitment and the clear digest binding
    route:<event>:<policy_hash>:<payload_hash>.

    The router-facing API (append(event, policy_hash, payload) / events() /
    payloads_of() / head / verify()) is preserved so the router and its
    self-tests are unchanged."""

    def __init__(self, signer=None, chain=None):
        # `signer` is accepted (and ignored) for API compatibility with the
        # retired stand-in; real signing is Ed25519 inside the chain.
        self.chain = chain or _RealWitnessChain()
        self._views: List[WitnessRecord] = []

    @property
    def head(self) -> str:
        return self.chain.head_hash()

    @property
    def _records(self) -> list:
        """The REAL signed records (tampering these breaks verify())."""
        return self.chain.records

    def append(self, event_type: str, policy_hash: str, payload: dict) -> dict:
        ph = sha256_hex(canonical(payload))
        rec = self.chain.append(
            "ROUTE",
            request={"event": event_type, "payload": payload},
            provenance={"module": "core.router", "policy_hash": policy_hash},
            semantic_digest=f"route:{event_type}:{policy_hash}:{ph}")
        self._views.append(WitnessRecord(event_type, payload,
                                         self.chain.records[rec["index"]]))
        return rec

    def verify(self) -> bool:
        return self.chain.verify_chain()

    # alias: the real chain's name, so either convention works
    def verify_chain(self, public: bytes = None) -> bool:
        return self.chain.verify_chain(public)

    def events(self) -> list:
        return [v.event_type for v in self._views]

    def payloads_of(self, event_type: str) -> list:
        return [v.payload for v in self._views if v.event_type == event_type]

    # alias used by the router self-tests
    def payloads(self, event_type: str) -> list:
        return self.payloads_of(event_type)


class ChampionRegistry(_RealRegistry):
    """UNIFIED (v0.3.1.4): the router now uses the REAL §9.9 registry.

    The stand-in it replaces kept (passes, fails, avg_margin) with NO decay,
    NO shrinkage, NO slashing — so a champion could coast on old glory, which
    §9.9 explicitly forbids. This subclass only adapts the two call shapes the
    router uses (positional margin; champion() -> object_id string)."""

    GLOBAL = "global"          # scope constant the router references

    def record(self, topic: str, object_id: str, ok: bool, margin=None,
               scope: str = "global", **kw):
        return super().record(topic, object_id, ok, margin=margin,
                              scope=scope, **kw)

    def champion(self, topic: str, scope: str = "global"):
        best = super().champion(topic, scope=scope)
        return best["object_id"] if best else None


# --------------------------------------------------------------------------- #
# 2. Descriptors & engines
# --------------------------------------------------------------------------- #

@dataclass
class SamplingParams:
    temperature: float = 0.0
    top_p: float = 0.9
    top_k: int = 0
    seed: int = 0


@dataclass
class EngineDescriptor:
    role: str                 # "generator" | "verifier"
    engine_fingerprint: str
    determinism_level: str    # "attested" | "reproducible"
    quantization: str


@dataclass
class NodeDescriptor:
    node_id: str
    substrate_id: str
    profile: str                      # "A" (adapters) | "B" (base-only)
    topics_served: Tuple[str, ...]
    engines: Tuple[EngineDescriptor, ...]
    attributes: Dict[str, str]
    capacity: int


@dataclass
class Verdict:
    ok: bool
    reachable: List[bool]
    min_margin: float
    verifier_fp: str
    determinism: str
    note: str = ""


class NodeEngine(ABC):
    @abstractmethod
    def describe(self) -> NodeDescriptor: ...

    @abstractmethod
    def generate(self, prompt: str, params: SamplingParams) -> Tuple[List[str], SamplingParams]: ...

    @abstractmethod
    def score(self, prompt: str, tokens: Sequence[str], params: SamplingParams) -> Verdict: ...


# --------------------------------------------------------------------------- #
# 3. Reference engine — deterministic pseudo-distribution so score() is REAL
# --------------------------------------------------------------------------- #

class ReferenceEngine(NodeEngine):
    VOCAB = [f"t{i}" for i in range(16)]

    def __init__(self, desc: NodeDescriptor, kernel_noise: float = 0.0):
        self._desc = desc
        self._noise = kernel_noise

    def describe(self) -> NodeDescriptor:
        return self._desc

    def _dist(self, context: str) -> Dict[str, float]:
        base = f"{self._desc.substrate_id}|{context}"
        logits = {}
        for tok in self.VOCAB:
            h = int(sha256_hex(f"{base}|{tok}".encode()), 16)
            logits[tok] = (h % 100000) / 10000.0
        m = max(logits.values())
        exps = {k: math.exp(v - m) for k, v in logits.items()}
        z = sum(exps.values())
        return {k: v / z for k, v in exps.items()}

    def _nucleus(self, dist: Dict[str, float], params: SamplingParams) -> Dict[str, float]:
        ordered = sorted(dist.items(), key=lambda kv: kv[1], reverse=True)
        keep, cum = {}, 0.0
        for i, (tok, p) in enumerate(ordered):
            if params.top_k and i >= params.top_k:
                break
            keep[tok] = p
            cum += p
            if params.top_p and cum >= params.top_p:
                break
        return keep

    def generate(self, prompt: str, params: SamplingParams):
        ctx, out = prompt, []
        for _ in range(5):
            dist = self._dist(ctx)
            if self._noise:
                seedh = int(sha256_hex(f"{params.seed}|{ctx}".encode()), 16)
                for tok in dist:
                    jitter = ((seedh + hash(tok)) % 1000) / 1000.0
                    dist[tok] *= (1.0 + self._noise * (jitter - 0.5))
            tok = max(dist.items(), key=lambda kv: kv[1])[0]
            out.append(tok)
            ctx = f"{ctx}>{tok}"
        return out, params

    def score(self, prompt: str, tokens, params: SamplingParams) -> Verdict:
        ctx = prompt
        reachable, margins = [], []
        eng = next(e for e in self._desc.engines if e.role == "verifier")
        for tok in tokens:
            dist = self._dist(ctx)                 # verifier: no noise
            nucleus = self._nucleus(dist, params)
            in_nuc = tok in nucleus
            reachable.append(in_nuc)
            margins.append(nucleus[tok] if in_nuc else -dist.get(tok, 0.0))
            ctx = f"{ctx}>{tok}"
        ok = all(reachable)
        return Verdict(
            ok=ok, reachable=reachable, min_margin=min(margins) if margins else 0.0,
            verifier_fp=eng.engine_fingerprint, determinism=eng.determinism_level,
            note="" if ok else "token(s) unreachable under committed policy",
        )


# --------------------------------------------------------------------------- #
# 4. Routing policy — STATIC & replicated (classifier + ABAC only)
# --------------------------------------------------------------------------- #

@dataclass
class DenyRule:
    query_attr: str
    query_val: str
    node_attr: str
    node_val: str


@dataclass
class RoutingPolicy:
    """The replicated, must-agree part. NOTE: champions are NOT here — they are
    dynamic evidence in the ChampionRegistry and tracked by a separate hash."""
    classifier_rules: Dict[str, List[str]]
    abac_rules: List[DenyRule]
    version: str = "v0.2"

    @property
    def policy_hash(self) -> str:
        return content_id({
            "classifier_rules": self.classifier_rules,
            "abac_rules": [asdict(r) for r in self.abac_rules],
            "version": self.version,
        })


# --------------------------------------------------------------------------- #
# 4b. ChampionRegistry — REMOVED (v0.3.1.4 Live Router Unification).
#     The stand-in that lived here kept (passes, fails, avg_margin) with NO
#     decay, NO shrinkage, NO slashing and NO stake gate — so a router
#     champion could coast on old glory, which §9.9 forbids outright. The
#     router now uses the REAL core.registry.ChampionRegistry (adapted
#     above, section 1) and its leaderboard is ordered by §9.9 weight.
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# 5. Classifier + query/plan objects
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# LIVE HTTP NODE ENGINE (v0.3.1.4) — the router now routes through REAL nodes.
# Until now every "node" the router dispatched to was an in-process
# ReferenceEngine. This speaks the actual JII over HTTP to a running daemon:
#   /capabilities -> NodeDescriptor · /v1/messages -> generate · /v1/score ->
# verify. The verdict it returns is the daemon's SEALED envelope (v0.3.1.2),
# opened and identity-pinned before the router is allowed to believe it.
# --------------------------------------------------------------------------- #

class HTTPNodeEngine(NodeEngine):
    """A router-facing engine backed by a live JJ DAI daemon."""

    def __init__(self, base_url: str, *, http_post, http_get,
                 topics: Sequence[str] = ("_generalist",),
                 attributes: Dict[str, str] = None, capacity: int = 8,
                 open_verdict=None):
        self.base = base_url.rstrip("/")
        self._post, self._get = http_post, http_get
        self._topics = tuple(topics)
        self._attrs = dict(attributes or {})
        self._capacity = capacity
        self._open = open_verdict
        self._caps = None

    # ---- capability discovery -> NodeDescriptor ---- #
    def capabilities(self) -> dict:
        if self._caps is None:
            _, self._caps = self._get(self.base + "/capabilities")
        return self._caps

    def describe(self) -> NodeDescriptor:
        c = self.capabilities()
        engines = (
            EngineDescriptor("generator", c["engine_fingerprint"],
                             c["determinism_level"], c.get("quantization", "n/a")),
            EngineDescriptor("verifier", c["engine_fingerprint"],
                             c["determinism_level"], c.get("quantization", "n/a")),
        )
        return NodeDescriptor(
            node_id=(c.get("witness") or {}).get("node_id", self.base),
            substrate_id=c["substrates"][0], profile=c["profile"],
            topics_served=self._topics, engines=engines,
            attributes=self._attrs, capacity=self._capacity)

    def _jii(self, prompt: str, params: "SamplingParams") -> dict:
        c = self.capabilities()
        return {"substrate_id": c["substrates"][0], "adapter_ids": [],
                "champion_context": "router@v1",
                "messages": [{"role": "user", "content": prompt}],
                "sampling": {"seed": params.seed, "temperature": params.temperature,
                             "top_p": params.top_p, "top_k": params.top_k,
                             "max_tokens": 256},
                "request_id": "uuidv7:router-" + sha256_hex(prompt.encode())[:8],
                "nonce": "hex:" + sha256_hex((prompt + str(params.seed)).encode())[:16]}

    def generate(self, prompt: str, params: "SamplingParams"):
        req = self._jii(prompt, params)
        status, resp = self._post(self.base + "/v1/messages", req)
        if status == 423:
            raise RefusalError(f"{self.base}: 423 CONTAINED — executive hand severed")
        if status != 200 or "output" not in resp:
            raise RefusalError(f"{self.base}: generate failed ({status})")
        self._last_request = req
        return resp["output"]["content"].split(), params

    def score(self, prompt: str, tokens: Sequence[str],
              params: "SamplingParams") -> "Verdict":
        req = self._jii(prompt, params)
        req["tokens"] = list(tokens)
        status, resp = self._post(self.base + "/v1/score", req)
        if status != 200 or "verdict" not in resp:
            raise RefusalError(f"{self.base}: score failed ({status})")
        env = resp["verdict"]
        if self._open is not None:               # v0.3.1.2 binding enforced
            pub = (self.capabilities().get("witness") or {}).get("pubkey")
            env = self._open(env, request=req, verifier_pubkey_hex=pub)
        return Verdict(ok=bool(env["ok"]), reachable=list(env.get("reachable", [])),
                       min_margin=float(env.get("min_margin", 0.0)),
                       verifier_fp=env.get("verifier_fp", ""),
                       determinism=env.get("determinism", "attested"),
                       note=env.get("note", ""))


class Classifier(ABC):
    @abstractmethod
    def classify(self, query: "Query") -> "Plan": ...


@dataclass
class Query:
    text: str
    attributes: Dict[str, str] = field(default_factory=dict)
    require_verification: bool = True
    prefer_object: Optional[str] = None     # requester override
    scope: str = ChampionRegistry.GLOBAL    # personal-champion scope


@dataclass
class SubTask:
    topic: str
    text: str
    query_attrs: Dict[str, str]


@dataclass
class Plan:
    subtasks: List[SubTask]
    synthesize: bool


class RuleClassifier(Classifier):
    def __init__(self, policy: RoutingPolicy):
        self._policy = policy

    def classify(self, query: Query) -> Plan:
        text = query.text.lower()
        hits = [t for t, kws in self._policy.classifier_rules.items()
                if any(kw in text for kw in kws)]
        if not hits:
            hits = ["_generalist"]
        subtasks = [
            SubTask(topic=t, text=query.text,
                    query_attrs=dict(query.attributes, topic=t))
            for t in hits
        ]
        return Plan(subtasks=subtasks, synthesize=len(subtasks) > 1)


# --------------------------------------------------------------------------- #
# 6. Candidate objects (specialists AND agents — one pool)
# --------------------------------------------------------------------------- #

@dataclass
class RouteObject:
    object_id: str
    kind: str                 # "specialist" | "agent"
    topic: str
    node_id: str


# --------------------------------------------------------------------------- #
# 7. The Router
# --------------------------------------------------------------------------- #

class RefusalError(Exception):
    """Fail-closed refusal (no policy-clean, capable candidate / bad verdict)."""


@dataclass
class RouteResult:
    final_answer: str
    per_subtask: List[dict]
    policy_hash: str
    registry_snapshot: str
    witnessed_events: List[str]


class Router:
    def __init__(self, policy: RoutingPolicy, classifier: Classifier,
                 objects: List[RouteObject], nodes: Dict[str, NodeEngine],
                 registry: ChampionRegistry, witness: WitnessChain, *,
                 provenance: Dict[str, dict] = None,
                 panel_k: int = 2,
                 min_independence: float = 0.5,
                 max_per_group: int = 1,
                 allow_degraded_panel: bool = False):
        self.policy = policy
        self.classifier = classifier
        self.objects = objects
        self.nodes = nodes
        self.registry = registry
        self.witness = witness
        # ---- diversity wiring (v0.5.1) ---------------------------------- #
        # provenance: object_id -> ProvenanceManifest (core.manifests).
        # When present, verification runs through a DIVERSITY-CONSTRAINED
        # panel instead of the generator's own node; when absent the legacy
        # self-verification path remains, and every such verdict is
        # WITNESSED as mode="self" so the downgrade is visible, never
        # silent.
        self.provenance = dict(provenance) if provenance else None
        self.panel_k = int(panel_k)
        self.min_independence = float(min_independence)
        self.max_per_group = int(max_per_group)
        self.allow_degraded_panel = bool(allow_degraded_panel)

    # -- ABAC gate ---------------------------------------------------------- #
    def _gate(self, cand: RouteObject, query_attrs: Dict[str, str]) -> bool:
        node = self.nodes[cand.node_id].describe()
        for rule in self.policy.abac_rules:
            if query_attrs.get(rule.query_attr) == rule.query_val \
               and node.attributes.get(rule.node_attr) == rule.node_val:
                return False
        return True

    # -- capability matching (fail-closed) ---------------------------------- #
    def _capable(self, obj: RouteObject, need_reproducible: bool) -> bool:
        desc = self.nodes[obj.node_id].describe()
        if desc.capacity <= 0:
            return False
        if obj.topic not in desc.topics_served and obj.topic != "_generalist":
            return False
        if need_reproducible and not any(
                e.determinism_level == "reproducible" for e in desc.engines):
            return False
        return True

    # -- champion selection from the registry leaderboard ------------------- #
    def _select(self, topic: str, capable: List[RouteObject], scope: str
                ) -> Tuple[RouteObject, str]:
        by_id = {o.object_id: o for o in capable}
        for oid, _ in self.registry.leaderboard(topic, scope):
            if oid in by_id:
                return by_id[oid], "champion:leaderboard"
        # cold start: nobody with verified history among the capable set
        fallback = sorted(capable, key=lambda o: o.object_id)[0]
        return fallback, "cold-start:no-verified-history"

    @staticmethod
    def _role_engine(node: NodeEngine, role: str) -> NodeEngine:
        # Reference: one object plays both roles; prod may split generator and
        # verifier into distinct processes on one substrate_id.
        return node

    # -- diversity-constrained verifier panel (v0.5.1) ---------------------- #
    def _reputation(self, topic: str, object_id: str, scope: str) -> float:
        for oid, w in self.registry.leaderboard(topic, scope):
            if oid == object_id:
                return float(w)
        return 0.0

    def _select_panel(self, st: SubTask, chosen: RouteObject,
                      capable: List[RouteObject], scope: str) -> dict:
        """Diversity-constrained verifier panel for one routing decision.
        The generator's provenance is passed EXPLICITLY (dev-5 audit item):
        the correlation check never depends on the generator happening to
        sit in the candidate pool. A candidate without a ProvenanceManifest
        is not skipped silently — it enters with an empty manifest and is
        rejected by the unknown-is-correlated rule with a named reason."""
        from core.diversity import select_verifiers
        gen_prov = self.provenance.get(chosen.object_id)
        if gen_prov is None:
            raise RefusalError(
                f"fail-honest: no ProvenanceManifest for generator "
                f"'{chosen.object_id}' — cannot judge verifier independence")
        candidates = []
        for o in capable:
            if o.object_id == chosen.object_id:
                continue
            prov = self.provenance.get(o.object_id) \
                or {"model_id": o.object_id}
            candidates.append({
                "provenance": prov,
                "reputation": self._reputation(st.topic, o.object_id, scope),
                "_object": o,
            })
        return select_verifiers(
            candidates, self.panel_k,
            min_independence=self.min_independence,
            max_per_group=self.max_per_group,
            exclude_model=gen_prov.get("model_id"),
            generator_provenance=gen_prov)

    def _verify_with_panel(self, st: SubTask, chosen: RouteObject,
                           tokens, committed, panel: dict, ph: str):
        """Every panel member independently teacher-forces the candidate
        tokens. The panel verdict is UNANIMOUS-fail-closed: one rejection
        rejects the output. The generator's registry record carries the
        worst margin across the panel — reputation is earned against the
        hardest independent judge, not the friendliest."""
        verdicts = []
        for cand in panel["selected"]:
            obj = cand["_object"]
            v = self.nodes[obj.node_id].score(st.text, tokens, committed)
            verdicts.append((obj.object_id, v))
            self.witness.append("route.panel_verify", ph, {
                "object": chosen.object_id, "verifier": obj.object_id,
                "verifier_fp": v.verifier_fp, "ok": v.ok,
                "min_margin": round(v.min_margin, 6),
                "independence_basis": "provenance-panel"})
        ok = all(v.ok for _, v in verdicts)
        worst = min((v.min_margin for _, v in verdicts), default=0.0)
        return ok, worst, verdicts

    # -- one sub-task ------------------------------------------------------- #
    def _route_subtask(self, st: SubTask, require_verification: bool,
                       prefer: Optional[str], scope: str) -> dict:
        ph = self.policy.policy_hash

        self.witness.append("route.classify", ph,
                            {"topic": st.topic, "attrs": st.query_attrs})

        pool = [o for o in self.objects
                if o.topic == st.topic or st.topic == "_generalist"]

        # ABAC gate
        gated = [o for o in pool if self._gate(o, st.query_attrs)]
        denied = [o.object_id for o in pool if o not in gated]
        self.witness.append("route.gate", ph,
                            {"topic": st.topic,
                             "allowed": [o.object_id for o in gated],
                             "denied": denied})

        # capability filter — FAIL-CLOSED (no silent downgrade to generalist)
        capable = [o for o in gated if self._capable(o, require_verification)]
        if not capable:
            self.witness.append("route.refuse", ph,
                                {"topic": st.topic,
                                 "reason": "no policy-clean capable candidate"
                                           " (fail-closed)"})
            raise RefusalError(
                f"fail-closed: no capable candidate for topic '{st.topic}'"
                f" (verification={require_verification})")

        # requester override vs registry champion
        by_id = {o.object_id: o for o in capable}
        if prefer and prefer in by_id:
            chosen, reason, overridden = by_id[prefer], "requester-override", True
        else:
            chosen, reason = self._select(st.topic, capable, scope)
            overridden = False
            if prefer and prefer not in by_id:
                reason += ";override-ignored:not-eligible"

        node = self.nodes[chosen.node_id]
        self.witness.append("route.dispatch", ph, {
            "topic": st.topic, "object": chosen.object_id, "kind": chosen.kind,
            "node": chosen.node_id, "substrate": node.describe().substrate_id,
            "champion_reason": reason, "overridden": overridden, "scope": scope,
            "registry_snapshot": self.registry.snapshot_hash(),
        })

        # generate (fast, attested) — commit sampling params
        gen_engine = self._role_engine(node, "generator")
        params = SamplingParams(temperature=0.0, top_p=0.9, top_k=0, seed=7)
        tokens, committed = gen_engine.generate(st.text, params)
        gen_fp = next(e.engine_fingerprint for e in node.describe().engines
                      if e.role == "generator")
        self.witness.append("route.generate", ph,
                            {"object": chosen.object_id, "generator_fp": gen_fp,
                             "params": asdict(committed), "n_tokens": len(tokens)})

        # verify (slow, reproducible) + FEED THE REGISTRY (loop closure)
        verdict = None
        verified_ok = False
        if require_verification:
            if self.provenance is not None:
                # ---- diversity-constrained panel (v0.5.1) --------------- #
                panel = self._select_panel(st, chosen, capable, scope)
                self.witness.append("route.panel", ph, {
                    "object": chosen.object_id,
                    "generator_provenance_model":
                        self.provenance[chosen.object_id]["model_id"],
                    "selected": [c["provenance"]["model_id"]
                                 for c in panel["selected"]],
                    "rejected": [{"model_id": r["model_id"],
                                  "reason": r["reason"]}
                                 for r in panel["rejected"]],
                    "filled": panel["filled"],
                    "constraints": panel["constraints"]})
                if not panel["filled"] and not self.allow_degraded_panel:
                    self.witness.append("route.refuse", ph, {
                        "topic": st.topic, "object": chosen.object_id,
                        "reason": "fail-honest: diversity panel short "
                                  f"({len(panel['selected'])}/{self.panel_k})"})
                    raise RefusalError(
                        f"fail-honest: only {len(panel['selected'])} of "
                        f"{self.panel_k} independent verifier(s) available "
                        f"for '{chosen.object_id}' — constraints are never "
                        "relaxed silently")
                if not panel["selected"]:
                    raise RefusalError(
                        "fail-honest: zero independent verifiers even in "
                        "degraded mode")
                verified_ok, worst, verdicts = self._verify_with_panel(
                    st, chosen, tokens, committed, panel, ph)
                self.registry.record(st.topic, chosen.object_id, verified_ok,
                                     worst, scope)
                self.witness.append("route.verify", ph, {
                    "object": chosen.object_id, "mode": "panel",
                    "panel_size": len(panel["selected"]),
                    "degraded": not panel["filled"],
                    "ok": verified_ok, "min_margin": round(worst, 6),
                    "recorded_to_registry": True})
                if not verified_ok:
                    bad = [oid for oid, v in verdicts if not v.ok]
                    self.witness.append("route.refuse", ph,
                                        {"topic": st.topic,
                                         "object": chosen.object_id,
                                         "reason": "panel verifier(s) "
                                                   f"rejected: {bad}"})
                    raise RefusalError(
                        f"panel rejected output of '{chosen.object_id}': "
                        f"{bad}")
            else:
                # ---- legacy self-verification (visible, never silent) --- #
                verdict = node.score(st.text, tokens, committed)
                verified_ok = verdict.ok
                self.registry.record(st.topic, chosen.object_id, verdict.ok,
                                     verdict.min_margin, scope)
                self.witness.append("route.verify", ph, {
                    "object": chosen.object_id, "mode": "self",
                    "verifier_fp": verdict.verifier_fp,
                    "determinism": verdict.determinism, "ok": verdict.ok,
                    "min_margin": round(verdict.min_margin, 6),
                    "recorded_to_registry": True,
                })
                if not verdict.ok:
                    self.witness.append("route.refuse", ph,
                                        {"topic": st.topic, "object": chosen.object_id,
                                         "reason": "verifier rejected generation"})
                    raise RefusalError(
                        f"verifier rejected output of '{chosen.object_id}': {verdict.note}")

        return {
            "topic": st.topic, "object": chosen.object_id, "kind": chosen.kind,
            "answer": ">".join(tokens),
            "verified": verified_ok,
            "champion_reason": reason, "overridden": overridden,
        }

    # -- public entrypoint -------------------------------------------------- #
    def route(self, query: Query) -> RouteResult:
        ph = self.policy.policy_hash
        plan = self.classifier.classify(query)

        results = [self._route_subtask(st, query.require_verification,
                                       query.prefer_object, query.scope)
                   for st in plan.subtasks]

        if plan.synthesize:
            merged = " || ".join(f"[{r['topic']}]{r['answer']}" for r in results)
            self.witness.append("route.synthesize", ph,
                                {"inputs": [r["object"] for r in results],
                                 "n": len(results)})
            final = f"SYNTHESIS({merged})"
        else:
            final = results[0]["answer"] if results else ""

        return RouteResult(
            final_answer=final, per_subtask=results, policy_hash=ph,
            registry_snapshot=self.registry.snapshot_hash(),
            witnessed_events=self.witness.events(),
        )


# --------------------------------------------------------------------------- #
# 8. Acceptance test — proves each locked property
# --------------------------------------------------------------------------- #

def _mk_node(node_id, substrate, topics, origin, capacity=4,
             verifier_reproducible=True, noise=0.0) -> ReferenceEngine:
    engines = [
        EngineDescriptor("generator", f"{node_id}-gen-metal", "attested", "int4"),
        EngineDescriptor("verifier", f"{node_id}-ver-cpu",
                         "reproducible" if verifier_reproducible else "attested", "int4"),
    ]
    desc = NodeDescriptor(
        node_id=node_id, substrate_id=substrate, profile="A",
        topics_served=tuple(topics), engines=tuple(engines),
        attributes={"base_origin": origin}, capacity=capacity,
    )
    return ReferenceEngine(desc, kernel_noise=noise)


def _build():
    policy = RoutingPolicy(
        classifier_rules={
            "neutronics": ["reactor", "smr", "neutron"],
            "contracts": ["contract", "poa", "agreement"],
            "finmodel": ["finance", "irr", "npv", "revenue"],
            "geopolitics": ["sanction", "export control", "geopolit"],
        },
        abac_rules=[DenyRule("topic", "geopolitics", "base_origin", "CN")],
    )
    nodes = {
        "node-ua": _mk_node("node-ua", "substrate-base-1", noise=0.15,
                            topics=["neutronics", "contracts", "finmodel",
                                    "geopolitics", "_generalist"], origin="UA"),
        "node-ua2": _mk_node("node-ua2", "substrate-base-1", noise=0.15,
                             topics=["neutronics"], origin="UA"),
        "node-cn": _mk_node("node-cn", "substrate-base-1", noise=0.15,
                            topics=["geopolitics", "finmodel"], origin="CN"),
        "node-attest": _mk_node("node-attest", "substrate-base-1", noise=0.15,
                                topics=["quantum"], origin="UA",
                                verifier_reproducible=False),
    }
    objects = [
        RouteObject("spec-neutronics-ua", "specialist", "neutronics", "node-ua"),
        RouteObject("spec-neutronics-ua2", "specialist", "neutronics", "node-ua2"),
        RouteObject("spec-contracts-ua", "specialist", "contracts", "node-ua"),
        RouteObject("spec-finmodel-ua", "specialist", "finmodel", "node-ua"),
        RouteObject("spec-geo-ua", "specialist", "geopolitics", "node-ua"),
        RouteObject("spec-geo-cn", "specialist", "geopolitics", "node-cn"),
        RouteObject("agent-generalist-ua", "agent", "_generalist", "node-ua"),
        RouteObject("spec-quantum-attest", "specialist", "quantum", "node-attest"),
    ]
    return policy, RuleClassifier(policy), objects, nodes


def _run_tests():
    passed, failed = 0, 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS  {name}")
        else:
            failed += 1
            print(f"  FAIL  {name}")

    print("JJ DAI Router v0.2 (registry-wired) — acceptance suite\n" + "-" * 52)

    # T1: single-topic route + verify + witness integrity
    policy, clf, objs, nodes = _build()
    reg, w = ChampionRegistry(), WitnessChain()
    r = Router(policy, clf, objs, nodes, reg, w)
    res = r.route(Query("model the SMR neutron flux"))
    check("T1 routes to a neutronics specialist",
          res.per_subtask[0]["topic"] == "neutronics")
    check("T1 output verified by reproducible verifier",
          res.per_subtask[0]["verified"] is True)
    check("T1 witness chain verifies", w.verify_chain())

    # T2: ABAC blocks foreign base for geopolitics
    policy, clf, objs, nodes = _build()
    reg, w = ChampionRegistry(), WitnessChain()
    r = Router(policy, clf, objs, nodes, reg, w)
    res = r.route(Query("assess the new export control sanction"))
    check("T2 geopolitics did NOT route to CN base",
          res.per_subtask[0]["object"] != "spec-geo-cn")
    check("T2 geopolitics routed to UA base",
          res.per_subtask[0]["object"] == "spec-geo-ua")

    # T3: capability fail-closed (no reproducible verifier for 'quantum')
    policy, clf, objs, nodes = _build()
    policy.classifier_rules["quantum"] = ["majorana", "quantum"]
    r = Router(policy, RuleClassifier(policy), objs, nodes,
               ChampionRegistry(), (w := WitnessChain()))
    refused = False
    try:
        r.route(Query("evaluate the majorana qubit path"))
    except RefusalError:
        refused = True
    check("T3 fail-closed when no reproducible verifier", refused)
    check("T3 refusal is witnessed", "route.refuse" in w.events())

    # T4: agentic decomposition on one flat witness plane
    policy, clf, objs, nodes = _build()
    reg, w = ChampionRegistry(), WitnessChain()
    r = Router(policy, clf, objs, nodes, reg, w)
    res = r.route(Query(
        "deal touching the reactor SMR, the contract terms, and the IRR finance"))
    check("T4 decomposed into 3 specialists",
          sorted(s["topic"] for s in res.per_subtask)
          == ["contracts", "finmodel", "neutronics"])
    check("T4 synthesis produced", res.final_answer.startswith("SYNTHESIS("))
    check("T4 single flat witness chain integral", w.verify_chain())

    # T5: verifier catches a forged sequence
    _, _, _, nodes = _build()
    node = nodes["node-ua"]
    good, params = node.generate("x", SamplingParams(top_p=0.9, seed=7))
    forged = list(good); forged[2] = "t99_forged"
    check("T5 genuine generation verifies", node.score("x", good, params).ok is True)
    check("T5 forged token is rejected", node.score("x", forged, params).ok is False)

    # ---- Registry integration ---------------------------------------------
    # T-champ-1: cold start -> deterministic fallback; verdict then recorded
    policy, clf, objs, nodes = _build()
    reg, w = ChampionRegistry(), WitnessChain()
    r = Router(policy, clf, objs, nodes, reg, w)
    check("Tc1 registry empty at start", reg.champion("neutronics") is None)
    res = r.route(Query("model the SMR neutron flux"))
    disp = w.payloads("route.dispatch")[0]
    check("Tc1 cold-start reason witnessed",
          disp["champion_reason"].startswith("cold-start"))
    check("Tc1 verdict fed the registry (champion now set)",
          reg.champion("neutronics") == res.per_subtask[0]["object"])

    # T-champ-2: champion follows verified verdicts (evidence, not declaration)
    policy, clf, objs, nodes = _build()
    reg, w = ChampionRegistry(), WitnessChain()
    # seed history: ua2 strong, ua weak
    for _ in range(6):
        reg.record("neutronics", "spec-neutronics-ua2", True, 0.2)
    for _ in range(6):
        reg.record("neutronics", "spec-neutronics-ua", False, -0.1)
    r = Router(policy, clf, objs, nodes, reg, w)
    res = r.route(Query("model the SMR neutron flux"))
    check("Tc2 champion = proven specialist (ua2)",
          res.per_subtask[0]["object"] == "spec-neutronics-ua2")
    check("Tc2 selection reason = leaderboard",
          res.per_subtask[0]["champion_reason"] == "champion:leaderboard")

    # T-champ-3: requester override honored + witnessed
    policy, clf, objs, nodes = _build()
    reg, w = ChampionRegistry(), WitnessChain()
    for _ in range(6):
        reg.record("neutronics", "spec-neutronics-ua2", True, 0.2)  # champion=ua2
    r = Router(policy, clf, objs, nodes, reg, w)
    res = r.route(Query("model the SMR neutron flux",
                        prefer_object="spec-neutronics-ua"))
    check("Tc3 override honored", res.per_subtask[0]["object"] == "spec-neutronics-ua")
    check("Tc3 override witnessed", res.per_subtask[0]["overridden"] is True)

    # T-champ-4: ineligible override is IGNORED, not obeyed (ABAC wins)
    policy, clf, objs, nodes = _build()
    reg, w = ChampionRegistry(), WitnessChain()
    r = Router(policy, clf, objs, nodes, reg, w)
    res = r.route(Query("assess the export control sanction",
                        prefer_object="spec-geo-cn"))  # CN gated out
    check("Tc4 ineligible override ignored", res.per_subtask[0]["object"] == "spec-geo-ua")
    check("Tc4 ignore is witnessed",
          "override-ignored" in res.per_subtask[0]["champion_reason"])

    # T-champ-5: champions from VERIFIED verdicts only (no-verify adds nothing)
    policy, clf, objs, nodes = _build()
    reg, w = ChampionRegistry(), WitnessChain()
    r = Router(policy, clf, objs, nodes, reg, w)
    r.route(Query("model the SMR neutron flux", require_verification=False))
    check("Tc5 unverified route does NOT populate leaderboard",
          reg.champion("neutronics") is None)

    # T-champ-6: THE hash separation — champion change moves registry snapshot
    #            but NEVER the replicated policy_hash
    policy, clf, objs, nodes = _build()
    reg, w = ChampionRegistry(), WitnessChain()
    r = Router(policy, clf, objs, nodes, reg, w)
    ph_before = policy.policy_hash
    snap_before = reg.snapshot_hash()
    r.route(Query("model the SMR neutron flux"))
    check("Tc6 registry snapshot changed after a verdict",
          reg.snapshot_hash() != snap_before)
    check("Tc6 policy_hash UNCHANGED by champion movement",
          policy.policy_hash == ph_before)

    # T6: static policy edit is still detectable
    pa, _, _, _ = _build()
    pb, _, _, _ = _build()
    check("T6 identical policy -> identical hash", pa.policy_hash == pb.policy_hash)
    pb.abac_rules.append(DenyRule("topic", "finmodel", "base_origin", "CN"))
    check("T6 policy edit -> different hash", pa.policy_hash != pb.policy_hash)

    # T7: witness tamper detection
    policy, clf, objs, nodes = _build()
    reg, w = ChampionRegistry(), WitnessChain()
    r = Router(policy, clf, objs, nodes, reg, w)
    r.route(Query("model the SMR neutron flux"))
    # UNIFIED (v0.3.1.4): records are now REAL Ed25519-signed dicts, so the
    # tamper test mutates a signed record — and verification must catch it.
    # (Under the retired stand-in this line edited an unsigned payload.)
    w._records[1]["semantic_digest"] = "route:tampered:0:0"
    check("T7 tampering breaks the chain", w.verify_chain() is False)

    print("-" * 52)
    print(f"TOTAL: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    raise SystemExit(0 if _run_tests() else 1)
