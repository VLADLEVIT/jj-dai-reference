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
# 0. Canonicalisation + hashing (prod: jjdai.canonical / jjdai.crypto)
# --------------------------------------------------------------------------- #

def canonical(obj) -> bytes:
    """Deterministic byte encoding. Reference stand-in for RFC 8785 JCS."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_id(obj) -> str:
    return sha256_hex(canonical(obj))


# --------------------------------------------------------------------------- #
# 1. Witness layer (C3) — hash-chained, injectable signer (prod: Ed25519)
# --------------------------------------------------------------------------- #

@dataclass
class WitnessRecord:
    index: int
    prev_hash: str
    event_type: str
    policy_hash: str
    payload: dict
    record_hash: str = ""
    signature: str = ""


class WitnessChain:
    """Minimal hash-chained log. Real version = jjdai.witness.WitnessChain."""

    GENESIS = "0" * 64

    def __init__(self, signer: Optional[Callable[[bytes], str]] = None):
        self._records: List[WitnessRecord] = []
        self._signer = signer or (lambda b: "unsigned:" + sha256_hex(b)[:16])

    @property
    def head(self) -> str:
        return self._records[-1].record_hash if self._records else self.GENESIS

    def append(self, event_type: str, policy_hash: str, payload: dict) -> WitnessRecord:
        idx = len(self._records)
        prev = self.head
        body = {
            "index": idx, "prev_hash": prev, "event_type": event_type,
            "policy_hash": policy_hash, "payload": payload,
        }
        rec_hash = sha256_hex(canonical(body))
        rec = WitnessRecord(
            index=idx, prev_hash=prev, event_type=event_type,
            policy_hash=policy_hash, payload=payload,
            record_hash=rec_hash, signature=self._signer(rec_hash.encode()),
        )
        self._records.append(rec)
        return rec

    def verify_chain(self) -> bool:
        prev = self.GENESIS
        for i, r in enumerate(self._records):
            if r.index != i or r.prev_hash != prev:
                return False
            body = {
                "index": r.index, "prev_hash": r.prev_hash,
                "event_type": r.event_type, "policy_hash": r.policy_hash,
                "payload": r.payload,
            }
            if sha256_hex(canonical(body)) != r.record_hash:
                return False
            prev = r.record_hash
        return True

    def __len__(self):
        return len(self._records)

    def events(self) -> List[str]:
        return [r.event_type for r in self._records]

    def payloads(self, event_type: str) -> List[dict]:
        return [r.payload for r in self._records if r.event_type == event_type]


# --------------------------------------------------------------------------- #
# 2. NECS waist — describe() / generate() / score()  (prod: NodeEngine ABC)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
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
# 4b. ChampionRegistry — per-topic leaderboard from VERIFIED verdicts
#     (mirrors M3 registry.ChampionRegistry; scope-keyed => personal champion)
# --------------------------------------------------------------------------- #

class _Stats:
    __slots__ = ("n", "passes", "margin_sum")

    def __init__(self):
        self.n = 0
        self.passes = 0
        self.margin_sum = 0.0

    def update(self, ok: bool, margin: float):
        self.n += 1
        if ok:
            self.passes += 1
        self.margin_sum += margin

    @property
    def pass_rate(self) -> float:
        # Laplace-smoothed so tiny-sample objects don't leapfrog proven ones
        return (self.passes + 1) / (self.n + 2)

    @property
    def avg_margin(self) -> float:
        return self.margin_sum / self.n if self.n else 0.0

    def key(self):
        return (self.pass_rate, self.n, self.avg_margin)


class ChampionRegistry:
    """
    Champions are earned, not declared. A leaderboard per (scope, topic) built
    ONLY from verified verdicts. `scope` lets each requester/node hold a
    personal champion (pull-by-choice) — there is no single global throne.
    """

    GLOBAL = "_global"

    def __init__(self):
        self._board: Dict[Tuple[str, str], Dict[str, _Stats]] = {}

    def record(self, topic: str, object_id: str, ok: bool, margin: float,
               scope: str = GLOBAL) -> None:
        cell = self._board.setdefault((scope, topic), {})
        cell.setdefault(object_id, _Stats()).update(ok, margin)

    def leaderboard(self, topic: str, scope: str = GLOBAL) -> List[Tuple[str, tuple]]:
        cell = self._board.get((scope, topic), {})
        oids = sorted(cell.keys())                       # stable object_id asc
        oids.sort(key=lambda o: cell[o].key(), reverse=True)  # then key desc
        return [(o, cell[o].key()) for o in oids]

    def champion(self, topic: str, scope: str = GLOBAL) -> Optional[str]:
        lb = self.leaderboard(topic, scope)
        return lb[0][0] if lb else None

    def snapshot_hash(self) -> str:
        board = {}
        for (scope, topic), cell in self._board.items():
            board[f"{scope}|{topic}"] = {
                oid: [s.n, s.passes, round(s.margin_sum, 6)]
                for oid, s in cell.items()
            }
        return content_id(board)


# --------------------------------------------------------------------------- #
# 5. Classifier + query/plan objects
# --------------------------------------------------------------------------- #

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
                 registry: ChampionRegistry, witness: WitnessChain):
        self.policy = policy
        self.classifier = classifier
        self.objects = objects
        self.nodes = nodes
        self.registry = registry
        self.witness = witness

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
        if require_verification:
            verdict = node.score(st.text, tokens, committed)
            self.registry.record(st.topic, chosen.object_id, verdict.ok,
                                  verdict.min_margin, scope)
            self.witness.append("route.verify", ph, {
                "object": chosen.object_id, "verifier_fp": verdict.verifier_fp,
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
            "verified": bool(verdict.ok) if verdict else False,
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
    w._records[1].payload["tampered"] = True
    check("T7 tampering breaks the chain", w.verify_chain() is False)

    print("-" * 52)
    print(f"TOTAL: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    raise SystemExit(0 if _run_tests() else 1)
