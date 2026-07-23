# -*- coding: utf-8 -*-
"""
core.diversity — Diversity-constrained verifier selection (v0.5, P1)
====================================================================
The Whitepaper requires verifiers that are INDEPENDENT, not merely
numerous: k models sharing one base family, one operator, or one training
corpus fail together for the same cause, and their agreement proves little.

Correlation model (pairwise, over ProvenanceManifests):

    dimension                weight   comparison
    base_family               0.35    equality
    architecture_family       0.20    equality
    training_data_families    0.20    Jaccard overlap of the family sets
    operator_domain           0.15    equality
    jurisdiction              0.10    equality

    correlation(a, b) = Σ weight_d · overlap_d      ∈ [0, 1]
    independence(a, b) = 1 − correlation(a, b)

Selection (select_verifiers) is GREEDY BY REPUTATION UNDER CONSTRAINTS:
candidates are taken best-first; a candidate joins the panel only if
(1) its pairwise independence against EVERY already-selected member is
≥ min_independence, and (2) no correlation-group cap is exceeded
(max_per_group members sharing the same value per grouped dimension).

FAIL HONEST, not silently: if the candidate pool cannot fill k under the
constraints, the panel is returned SHORT with per-candidate rejection
diagnostics — the caller decides whether to proceed degraded, recruit
more diverse verifiers, or refuse. Diversity constraints must never be
relaxed implicitly.
"""
from __future__ import annotations

WEIGHTS = {
    "base_family": 0.35,
    "architecture_family": 0.20,
    "training_data_families": 0.20,
    "operator_domain": 0.15,
    "jurisdiction": 0.10,
}

GROUP_DIMENSIONS = ("base_family", "architecture_family",
                    "operator_domain", "jurisdiction")


class DiversityError(RuntimeError):
    pass


def _jaccard(a: list, b: list) -> float:
    sa, sb = set(a or ()), set(b or ())
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def correlation(pa: dict, pb: dict) -> dict:
    """Pairwise common-cause correlation between two provenance manifests.
    Returns {'score': float, 'shared': {dimension: overlap},
             'unknown': [dimensions with missing provenance]}.

    UNKNOWN IS NOT INDEPENDENT (v0.5 drop 6, per the external audit): a
    dimension that is missing on EITHER side contributes its FULL weight to
    correlation. Independence is a positive claim that must be demonstrated
    by declared, verifiable provenance — silence cannot earn it. Two
    manifests that declare nothing therefore correlate at 1.0: an honest
    "we cannot tell them apart", never a free pass onto the panel."""
    shared = {}
    unknown = []
    score = 0.0
    for dim, w in WEIGHTS.items():
        a, b = pa.get(dim), pb.get(dim)
        if dim == "training_data_families":
            missing = not a or not b
            ov = 1.0 if missing else _jaccard(a, b)
        else:
            missing = a is None or b is None
            ov = 1.0 if missing else (1.0 if a == b else 0.0)
        if missing:
            unknown.append(dim)
        elif ov > 0:
            shared[dim] = round(ov, 4)
        score += w * ov
    return {"score": round(score, 4), "shared": shared, "unknown": unknown}


def independence(pa: dict, pb: dict) -> float:
    return round(1.0 - correlation(pa, pb)["score"], 4)


def select_verifiers(candidates: list, k: int, *,
                     min_independence: float = 0.5,
                     max_per_group: int = 1,
                     exclude_model: str = None,
                     generator_provenance: dict = None) -> dict:
    """Select up to k verifiers.

    candidates: [{"provenance": ProvenanceManifest, "reputation": float}]
    exclude_model: model_id of the GENERATOR — a model must never verify
                   itself (generator/verifier asymmetry), and anything with
                   independence 0.0 from it is refused outright.
    generator_provenance (v0.5.1): the generator's ProvenanceManifest,
                   passed EXPLICITLY by the caller. The dev-5 audit flagged
                   the implicit pool lookup: a generator absent from the
                   candidate list silently disabled the correlation check.
                   An explicit manifest closes that hole; the lookup remains
                   only as a fallback for legacy callers.

    Returns {"selected": [...], "rejected": [{candidate, reason}, ...],
             "filled": bool, "constraints": {...}}.
    """
    if k < 1:
        raise DiversityError("k must be >= 1")
    pool = sorted(candidates, key=lambda c: (-float(c.get("reputation", 0.0)),
                                             c["provenance"]["model_id"]))
    generator = generator_provenance
    if generator is None:
        generator = next((c["provenance"] for c in candidates
                          if c["provenance"]["model_id"] == exclude_model),
                         None)
    if generator is not None and exclude_model is None:
        exclude_model = generator.get("model_id")
    selected, rejected = [], []
    group_counts = {dim: {} for dim in GROUP_DIMENSIONS}

    for cand in pool:
        p = cand["provenance"]
        mid = p["model_id"]
        if exclude_model is not None and mid == exclude_model:
            rejected.append({"model_id": mid,
                             "reason": "generator must not verify itself"})
            continue
        if generator is not None and independence(p, generator) == 0.0:
            det = correlation(p, generator)
            why = ("provenance too undeclared to distinguish from the "
                   "generator" if det["unknown"] else
                   "fully correlated with the generator")
            rejected.append({"model_id": mid, "reason": why})
            continue
        clash = None
        for s in selected:
            ind = independence(p, s["provenance"])
            if ind < min_independence:
                det = correlation(p, s["provenance"])
                cause = sorted(det["shared"])
                if det["unknown"]:
                    cause += [f"unknown:{d}" for d in sorted(det["unknown"])]
                clash = (f"independence {ind} < {min_independence} vs "
                         f"{s['provenance']['model_id']} "
                         f"(shared: {cause})")
                break
        if clash:
            rejected.append({"model_id": mid, "reason": clash})
            continue
        cap_hit = None
        for dim in GROUP_DIMENSIONS:
            val = p.get(dim)
            if val is None:
                continue
            if group_counts[dim].get(val, 0) + 1 > max_per_group:
                cap_hit = (f"group cap: already {max_per_group} member(s) "
                           f"with {dim}={val!r}")
                break
        if cap_hit:
            rejected.append({"model_id": mid, "reason": cap_hit})
            continue
        selected.append(cand)
        for dim in GROUP_DIMENSIONS:
            val = p.get(dim)
            if val is not None:
                group_counts[dim][val] = group_counts[dim].get(val, 0) + 1
        if len(selected) >= k:
            break

    return {
        "selected": selected,
        "rejected": rejected,
        "filled": len(selected) >= k,
        "constraints": {"k": k, "min_independence": min_independence,
                        "max_per_group": max_per_group,
                        "exclude_model": exclude_model},
    }
