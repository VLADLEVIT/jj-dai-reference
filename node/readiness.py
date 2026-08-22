"""node/readiness.py — readiness, split from liveness (build v0.6.6).

Until this drop a node answered exactly one health question, and answered it
with `ok: True` as long as the process could form a reply. That is LIVENESS,
and the audit of v0.6.3 said so plainly: `/healthz` is liveness-only. An
orchestrator, a peer or a router that reads a liveness answer as permission to
send work will send work to a node that is running and cannot serve.

Readiness is a different question and has a different answer shape.

WHY NOT ONE BOOLEAN
-------------------
The obvious design — one flag, ready or not — was rejected on arithmetic
rather than taste. This build ships NO compiled wasm modules; a freshly
deployed node therefore has an empty or unprovisioned toolset by
construction. Under a single flag no node would ever report ready, and the
flag would be switched off in the field within a week, which is worse than
not having it. Meanwhile the witness contour — the thing that actually makes
a node a participant in the network — does not depend on wasm at all.

So readiness is reported PER SUBSYSTEM, and the aggregate is red only for the
subsystems without which the node is not a participant:

    CORE      identity · witness · anchoring
    NON-CORE  engine · isolation · being

A non-core subsystem that is down DEGRADES the node: the aggregate stays
green, the subsystem reports its own state, and a router that needs that
capability reads the subsystem rather than the aggregate. This is the same
posture kernel/isolation.py already takes for profiles — declare the
inability precisely, do not collapse it into a global refusal.

STATES
------
    READY            performing its function
    DEGRADED         functioning below policy but not failed
    NOT_READY        cannot perform its function
    NOT_CONFIGURED   not enabled on this node — never a fault

NOT_CONFIGURED matters: a testnet node with no anchor backends is not a
broken node, and reporting it as NOT_READY would train operators to ignore
the field. Absence of a feature and failure of a feature are different facts
and are kept apart here as everywhere else in this codebase.

PURITY. This module evaluates a plain snapshot dict and imports nothing from
the daemon. The daemon builds the snapshot; the rules live here and are
testable without a socket, a keystore or a running node.
"""
from __future__ import annotations

READY = "ready"
DEGRADED = "degraded"
NOT_READY = "not_ready"
NOT_CONFIGURED = "not_configured"

#: Subsystems whose failure makes the node a non-participant. Everything
#: outside this tuple degrades the node without taking it out of the network.
CORE = ("identity", "witness", "anchoring")

#: Reported order — stable so a diff between two nodes is readable.
SUBSYSTEMS = ("identity", "witness", "anchoring", "engine", "isolation",
              "being")


def _state(ok: bool, configured: bool = True, degraded: bool = False) -> str:
    if not configured:
        return NOT_CONFIGURED
    if not ok:
        return NOT_READY
    return DEGRADED if degraded else READY


def evaluate_identity(snap: dict) -> dict:
    """The keystore is loaded and the signer is the one the chain expects.

    An ephemeral (dev) identity is deliberately DEGRADED rather than ready:
    the node functions, but nothing it signs carries continuity, and an
    operator who cannot see that difference on a dashboard will discover it
    at the worst possible moment.
    """
    if not snap.get("identity_loaded"):
        return {"state": NOT_READY, "reason": "no node identity loaded"}
    if snap.get("identity_ephemeral"):
        return {"state": DEGRADED,
                "reason": "ephemeral (dev) identity — signatures carry no "
                          "continuity across restarts"}
    if snap.get("signer_mismatch"):
        return {"state": NOT_READY,
                "reason": "witness log contains records signed by another "
                          "identity"}
    return {"state": READY, "reason": ""}


def evaluate_witness(snap: dict) -> dict:
    """The chain is loaded and its head is structurally sound."""
    if not snap.get("chain_loaded"):
        return {"state": NOT_READY, "reason": "witness chain not loaded"}
    if snap.get("chain_broken"):
        return {"state": NOT_READY,
                "reason": f"witness chain does not verify: "
                          f"{snap.get('chain_broken')}"}
    return {"state": READY, "reason": "",
            "records": snap.get("records", 0)}


def evaluate_anchoring(snap: dict) -> dict:
    """Anchoring lag against the phase policy value.

    Lag, not failure, is the interesting signal: an anchor backend that has
    stopped answering looks exactly like a healthy one until the unanchored
    segment grows. r6.6.2 makes both the segment anchoring lag and the depth
    of the unanchored segment SLO metrics, so they are surfaced here rather
    than inferred from the absence of errors.
    """
    if not snap.get("anchoring_configured"):
        return {"state": NOT_CONFIGURED,
                "reason": "no anchor backends configured on this node"}
    lag = snap.get("anchor_lag_s")
    depth = snap.get("unanchored_depth", 0)
    max_lag = snap.get("anchor_lag_max_s", 0) or 0
    max_depth = snap.get("unanchored_depth_max", 0) or 0
    behind = list(snap.get("anchor_behind") or [])
    never = bool(snap.get("anchor_never_succeeded"))

    # UNKNOWN IS NOT GREEN. A required backend that has never succeeded
    # produces no lag to measure, and the v0.6.6 cut turned that missing
    # measurement into READY. If there is substantive history that nobody
    # has anchored, the honest answer is NOT_READY.
    if never and depth > 0:
        return {"state": NOT_READY,
                "reason": ("required anchoring has never succeeded and "
                           f"{depth} substantive record(s) are unanchored"),
                "anchor_lag_s": None, "unanchored_depth": depth,
                "behind": behind}
    if never:
        return {"state": DEGRADED,
                "reason": "no successful anchor yet (nothing to anchor)",
                "anchor_lag_s": None, "unanchored_depth": depth,
                "behind": behind}
    over_lag = bool(max_lag) and lag is not None and lag > max_lag
    over_depth = bool(max_depth) and depth > max_depth
    if behind and not (over_lag or over_depth):
        return {"state": DEGRADED,
                "reason": f"backend(s) behind: {', '.join(behind)}",
                "anchor_lag_s": lag, "unanchored_depth": depth,
                "behind": behind}
    if over_lag or over_depth:
        why = []
        if over_lag:
            why.append(f"anchor lag {lag:.0f}s over policy {max_lag:.0f}s")
        if over_depth:
            why.append(f"unanchored segment {depth} over policy {max_depth}")
        return {"state": NOT_READY, "reason": "; ".join(why),
                "anchor_lag_s": lag, "unanchored_depth": depth,
                "behind": behind}
    return {"state": READY, "reason": "", "anchor_lag_s": lag,
            "unanchored_depth": depth}


def evaluate_engine(snap: dict) -> dict:
    """An inference backend is registered and reports itself ready."""
    if not snap.get("engine_configured"):
        return {"state": NOT_CONFIGURED, "reason": "no engine on this node"}
    if not snap.get("engine_ready"):
        return {"state": NOT_READY,
                "reason": snap.get("engine_reason") or "engine not ready"}
    return {"state": READY, "reason": "",
            "engine": snap.get("engine_name")}


def evaluate_isolation(snap: dict) -> dict:
    """Isolation profiles, carried over from `/healthz` as promised in v0.6.4.

    The reference profile is always executable, so a node with only
    `reference` declared is READY and not degraded — it is running the
    baseline every node can run, which is a policy choice and not a fault.
    A declared profile that cannot execute is what degrades the node.
    """
    declared = list(snap.get("isolation_declared") or [])
    ready = list(snap.get("isolation_ready") or [])
    if not declared:
        return {"state": NOT_CONFIGURED, "reason": "no profiles declared"}
    missing = [p for p in declared if p not in ready]
    if not ready:
        return {"state": NOT_READY,
                "reason": f"no declared isolation profile is executable: "
                          f"{', '.join(declared)}",
                "declared": declared, "ready": ready}
    if missing:
        return {"state": DEGRADED,
                "reason": f"declared but not executable: "
                          f"{', '.join(missing)}",
                "declared": declared, "ready": ready}
    return {"state": READY, "reason": "", "declared": declared,
            "ready": ready}


def evaluate_being(snap: dict) -> dict:
    """The Being runtime, and whether it is under containment.

    A contained being is NOT a broken node and must not read as one. Under
    Article 25 containment is a state of the identity with due process
    attached; a monitoring stack that pages the operator for it turns a
    governance event into an incident.
    """
    if not snap.get("being_configured"):
        return {"state": NOT_CONFIGURED, "reason": "no being on this node"}
    if snap.get("being_contained"):
        return {"state": DEGRADED,
                "reason": "being is under containment — network scope "
                          "limited by governance, not a fault"}
    return {"state": READY, "reason": "",
            "profile": snap.get("being_profile")}


_EVALUATORS = {"identity": evaluate_identity, "witness": evaluate_witness,
               "anchoring": evaluate_anchoring, "engine": evaluate_engine,
               "isolation": evaluate_isolation, "being": evaluate_being}


def evaluate(snap: dict) -> dict:
    """Full readiness report: per subsystem, plus the aggregate.

    Returns {"ready": bool, "reason": str, "subsystems": {...},
             "degraded": [...], "core": [...]}
    """
    subs = {name: _EVALUATORS[name](snap) for name in SUBSYSTEMS}
    blocking = [n for n in CORE if subs[n]["state"] == NOT_READY]
    degraded = sorted(n for n, v in subs.items()
                      if v["state"] in (DEGRADED, NOT_READY)
                      and n not in blocking)
    ready = not blocking
    if blocking:
        reason = "; ".join(f"{n}: {subs[n]['reason']}" for n in blocking)
    elif degraded:
        reason = f"serving, degraded in: {', '.join(degraded)}"
    else:
        reason = ""
    return {"ready": ready, "reason": reason, "subsystems": subs,
            "degraded": degraded, "core": list(CORE)}


def http_status(report: dict) -> int:
    """200 when ready, 503 when not.

    The mapping is a named function rather than an inline conditional so it
    can be checked directly. An orchestrator that reads only the status code
    must behave correctly without parsing the body — that is the contract,
    and a contract nobody tests is a comment.
    """
    return 200 if report["ready"] else 503


def gauge_values(report: dict) -> dict:
    """Prometheus-friendly flattening: one gauge per subsystem, plus one
    aggregate. 1 = ready, 0 = not ready, 0.5 = degraded, -1 = not configured.

    A single numeric scale is used deliberately: an alert rule that has to
    join two metrics to learn one fact is an alert rule that will be written
    wrong once and then trusted forever.
    """
    scale = {READY: 1, DEGRADED: 0.5, NOT_READY: 0, NOT_CONFIGURED: -1}
    out = {"ready": 1 if report["ready"] else 0}
    for name, v in report["subsystems"].items():
        out[f"ready_{name}"] = scale[v["state"]]
    return out
