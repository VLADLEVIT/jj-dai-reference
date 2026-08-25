"""jjdai/adapters/protocol.py — EngineBackend Protocol v1 (v0.6.5).

THE ARCHITECTURAL DECISION THIS FILE ENCODES
--------------------------------------------
JJ DAI does not integrate each LLM with its own adapter. Execution engines
integrate through ONE stable backend protocol; model families arrive as
DECLARATIVE profiles; a single conformance suite proves compatibility. That
is what keeps the daemon from becoming a switch statement over vendor names,
and it is what lets LLaMA, Qwen, future Kimi/DeepSeek and eventually our own
silicon arrive without touching the witness contour.

WHY THE CONTRACT IS DECLARED WHOLE, TODAY
-----------------------------------------
The prototype seam (generate / score / fingerprint / capabilities) is enough
for the current code and not enough for production serving or for an ASIC
runtime. If the missing methods simply did not exist, every caller would grow
its own hasattr() probe and its own quiet fallback — and a quiet fallback is
how a node ends up believing it has a capability it does not have. So v1 is
fixed IN FULL now: unimplemented methods are present and raise the typed
`NotSupported`. Fail closed, exactly as the isolation profiles do.

Version discipline: `PROTOCOL_VERSION` is part of every capability manifest
and every ModelArtifactManifest. A backend built against v1 keeps working
when v2 appears; a v2 daemon can see, without asking, which contract a
backend was written to.

MANDATORY BY PHASE (roadmap r6.6.2, track I)
--------------------------------------------
  already        generate · score · fingerprint · capabilities
  Ф2             load_model · unload_model · stream_generate · cancel
                 health · readiness · attestation_manifest
                 create_session · export_session_state ·
                 restore_session_state · close_session
                 (session/KV-state was reserved for Ф3 in r6.5 and moved up
                  to Ф2 in r6.6, because passivation came down to Ф2 and is
                  unimplementable without it)
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .errors import NotSupported

#: Bumped only for a BREAKING change to the method set or their semantics.
PROTOCOL_VERSION = "1"

#: Groups exist so conformance can report per-group, and so a phase gate can
#: name what it requires without listing methods one by one.
METHOD_GROUPS = {
    "lifecycle": ("load_model", "unload_model"),
    "execution": ("generate", "stream_generate", "score", "cancel"),
    "health": ("health", "readiness"),
    "trust": ("attestation_manifest",),
    "session": ("create_session", "export_session_state",
                "restore_session_state", "close_session"),
}

#: Not methods. A driver DECLARES these; there is nothing to implement, so
#: asking whether they are "overridden" is a category error — and the first
#: cut of this file made exactly that error, reporting `fingerprint` as
#: not_supported on a driver that plainly had one.
REQUIRED_ATTRIBUTES = ("backend", "determinism_level", "fingerprint",
                       "protocol_version")

#: Provided BY THE FRAMEWORK, not by the driver. `capabilities()` is how the
#: adapter layer answers about a backend; it is not a capability OF the
#: backend, and counting it as one made the source of truth about
#: capabilities lie about itself.
FRAMEWORK_METHODS = ("capabilities",)


@runtime_checkable
class EngineBackend(Protocol):
    """The whole of v1. Structural: a backend need not inherit anything."""

    #: short stable name, e.g. "dwarfstar" · used in manifests and metrics
    backend: str
    #: "reproducible" | "attested" | "best_effort"
    determinism_level: str
    #: identifies the exact executable artifact behind this backend
    fingerprint: str

    # -- lifecycle ---------------------------------------------------- #
    def load_model(self, manifest: dict) -> dict: ...
    def unload_model(self, model_id: str = None) -> None: ...

    # -- execution ---------------------------------------------------- #
    def generate(self, messages: list, sampling: dict,
                 adapter_ids: list = ()) -> str: ...
    def stream_generate(self, messages: list, sampling: dict,
                        adapter_ids: list = ()): ...
    def score(self, messages: list, tokens: list, sampling: dict,
              adapter_ids: list = ()) -> dict: ...
    def cancel(self, request_id: str) -> bool: ...

    # -- health ------------------------------------------------------- #
    def health(self) -> dict: ...
    def readiness(self) -> dict: ...

    # -- trust -------------------------------------------------------- #
    def attestation_manifest(self) -> dict: ...
    def capabilities(self) -> dict: ...

    # -- session / KV-state ------------------------------------------- #
    def create_session(self, hint: dict = None) -> str: ...
    def export_session_state(self, session_id: str) -> bytes: ...
    def restore_session_state(self, blob: bytes) -> str: ...
    def close_session(self, session_id: str) -> None: ...


class BaseEngineBackend:
    """Default implementation of v1: everything declared, nothing pretended.

    A driver inherits this and overrides what it can actually do. What it
    does not override refuses by TYPE rather than by AttributeError, so the
    gap is visible in capabilities() instead of being discovered at the
    first call in production.
    """

    backend = "base"
    determinism_level = "best_effort"
    fingerprint = ""
    protocol_version = PROTOCOL_VERSION

    # -- lifecycle ---------------------------------------------------- #
    def load_model(self, manifest: dict) -> dict:
        raise NotSupported(self.backend, "load_model")

    def unload_model(self, model_id: str = None) -> None:
        raise NotSupported(self.backend, "unload_model")

    # -- execution ---------------------------------------------------- #
    def generate(self, messages: list, sampling: dict,
                 adapter_ids: list = ()) -> str:
        raise NotSupported(self.backend, "generate")

    def stream_generate(self, messages: list, sampling: dict,
                        adapter_ids: list = ()):
        raise NotSupported(self.backend, "stream_generate")

    def score(self, messages: list, tokens: list, sampling: dict,
              adapter_ids: list = ()) -> dict:
        raise NotSupported(self.backend, "score")

    def cancel(self, request_id: str) -> bool:
        raise NotSupported(self.backend, "cancel")

    # -- health ------------------------------------------------------- #
    def health(self) -> dict:
        raise NotSupported(self.backend, "health")

    def readiness(self) -> dict:
        raise NotSupported(self.backend, "readiness")

    # -- trust -------------------------------------------------------- #
    def attestation_manifest(self) -> dict:
        raise NotSupported(self.backend, "attestation_manifest")

    def capabilities(self) -> dict:
        """Declared capability, computed from what is actually overridden.

        Deliberately introspective rather than hand-written: a hand-written
        list is a claim, and claims drift from code. This one cannot.
        """
        return capability_manifest(self)

    # -- session / KV-state ------------------------------------------- #
    def create_session(self, hint: dict = None) -> str:
        raise NotSupported(self.backend, "create_session")

    def export_session_state(self, session_id: str) -> bytes:
        raise NotSupported(self.backend, "export_session_state")

    def restore_session_state(self, blob: bytes) -> str:
        raise NotSupported(self.backend, "restore_session_state")

    def close_session(self, session_id: str) -> None:
        raise NotSupported(self.backend, "close_session")


def implements(obj, method: str) -> bool:
    """True when `obj` actually implements `method` rather than inheriting
    the refusing default. This is how capability is DERIVED from code."""
    own = getattr(type(obj), method, None)
    base = getattr(BaseEngineBackend, method, None)
    return own is not None and own is not base


def declared_attributes(obj) -> dict:
    """Which required attributes a driver actually declares, and their
    values. Absence is reported as absence — never as an unimplemented
    method."""
    out = {}
    for attr in REQUIRED_ATTRIBUTES:
        value = getattr(obj, attr, None)
        # recut9: whitespace is not a value. `" "` used to survive here and
        # then read as "declared" everywhere downstream.
        out[attr] = (value if isinstance(value, str) and value.strip()
                     else None)
    return out


def capability_manifest(obj) -> dict:
    """What this backend can do, per protocol group, derived not declared.

    Three kinds of thing are kept apart, because conflating them made the
    manifest contradict itself: METHODS a driver may implement, ATTRIBUTES a
    driver declares, and FRAMEWORK methods the adapter layer supplies for
    every driver.
    """
    groups = {g: sorted(m for m in ms if implements(obj, m))
              for g, ms in METHOD_GROUPS.items()}
    missing = {g: sorted(m for m in ms if not implements(obj, m))
               for g, ms in METHOD_GROUPS.items()}
    attrs = declared_attributes(obj)
    return {
        "protocol_version": getattr(obj, "protocol_version",
                                    PROTOCOL_VERSION),
        "backend": getattr(obj, "backend", "unknown"),
        "determinism_level": getattr(obj, "determinism_level",
                                     "best_effort"),
        "fingerprint": getattr(obj, "fingerprint", ""),
        "implemented": groups,
        "not_supported": {g: ms for g, ms in missing.items() if ms},
        "attributes": attrs,
        "attributes_missing": sorted(k for k, v in attrs.items()
                                     if v is None),
        "framework": list(FRAMEWORK_METHODS),
    }
