"""jjdai/adapters/backends/hash.py — the deterministic reference backend.

Moved out of node/daemon.py in v0.6.5. It was never node-specific: it is the
reference driver every conformance run measures the others against, and the
one backend guaranteed present on any host, with no external process and no
model to load.

Behaviour is byte-for-byte unchanged from v0.6.4 — this drop moves code and
declares a contract; it does not touch what inference produces.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from jjdai.canonical import canonical                          # noqa: E402
from jjdai.crypto import H_hex                                 # noqa: E402
from jjdai.adapters.protocol import BaseEngineBackend          # noqa: E402
from jjdai.adapters.registry import BackendConfig, register    # noqa: E402


class HashEngine(BaseEngineBackend):
    """Deterministic reference engine (Profile B). Same input -> same bytes,
    so the node can honestly declare determinism_level='reproducible'.

    PRODUCTION SEAM: replace with DwarfStarEngine — a driver that forwards
    `messages`+`sampling` to the local DwarfStar /v1 endpoint and declares
    determinism_level='attested'. The daemon's envelope/witness logic does
    not change.
    """

    determinism_level = "reproducible"
    backend = "hash"

    def __init__(self, config: BackendConfig = None):
        # A bare fingerprint string is accepted as well as a config. The
        # reference driver is constructed directly in a great many places
        # that have no interest in the registry, and breaking them would be
        # churn without a safety gain — the registry path still hands a
        # BackendConfig like every other driver.
        if isinstance(config, str):
            config = BackendConfig(fingerprint=config)
        cfg = config or BackendConfig()
        self.fingerprint = cfg.fingerprint or "fp-unset"

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

    # -- health: nothing external to be unhealthy about ---------------- #
    def health(self) -> dict:
        return {"ok": True, "backend": self.backend, "detail": "in-process"}

    def readiness(self) -> dict:
        return {"ready": True, "backend": self.backend,
                "model_loaded": True,
                "detail": "no model to load; deterministic reference"}

    def attestation_manifest(self) -> dict:
        """Honest and minimal: there is no measured runtime behind this
        backend, and saying so is the point. A node that needs attestation
        must not get a manifest here that looks like one."""
        return {"attested": False, "backend": self.backend,
                "fingerprint": self.fingerprint,
                "detail": "reference backend: no hardware or runtime "
                          "measurement exists to attest"}


#: The one driver that is always registrable — no host requirement at all.
register("hash", HashEngine)
