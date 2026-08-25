"""jjdai/adapters/capabilities.py — capability manifests (v0.6.5).

Capability is DERIVED from code (protocol.capability_manifest), never
hand-declared. This module adds the parts a manifest needs that code cannot
know by itself: which model families the driver serves, which precisions it
carries, and which phase gate the resulting coverage satisfies.
"""
from __future__ import annotations

from .protocol import METHOD_GROUPS, capability_manifest, implements


def describe(backend, *, families=(), precisions=(), notes: str = "") -> dict:
    """Full capability manifest for one backend driver."""
    man = capability_manifest(backend)
    man.update({"model_families": sorted(families),
                "precisions": sorted(precisions),
                "notes": notes})
    return man


def group_complete(backend, group: str) -> bool:
    """True when every method of a protocol group is really implemented."""
    return all(implements(backend, m) for m in METHOD_GROUPS[group])


def phase_readiness(backend) -> dict:
    """Which phase's mandatory groups this backend already satisfies.

    Ф1 asks only that it can generate and be identified. Ф2 adds lifecycle,
    streaming/cancel, health and attestation — and, since r6.6 moved
    passivation down, the session/KV-state group too.
    """
    # attributes are DECLARED, methods are IMPLEMENTED — the workaround this
    # replaces existed only because the two were being asked the same
    # question
    from .protocol import declared_attributes
    exec_min = all(implements(backend, m) for m in ("generate", "score"))
    attrs = declared_attributes(backend)
    # recut9: `is not None` was true of `" "` before declared_attributes
    # normalised it, and "identified" must mean NAMED, not merely present.
    identified = all(isinstance(attrs.get(k), str) and attrs[k].strip()
                     for k in ("backend", "fingerprint"))
    return {
        "phase_1": bool(exec_min and identified),
        "phase_2": bool(group_complete(backend, "lifecycle")
                        and group_complete(backend, "execution")
                        and group_complete(backend, "health")
                        and group_complete(backend, "trust")
                        and group_complete(backend, "session")),
    }
