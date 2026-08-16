"""llama.cpp backend driver — declared, not yet implemented (Ф2 deliverable).

Present so the registry, the conformance suite and the compatibility matrix
have a real object to interrogate rather than a name in a document. Every
method inherits the refusing default, so `capabilities()` reports the gap
truthfully instead of the node discovering it at the first request.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from jjdai.adapters.protocol import BaseEngineBackend        # noqa: E402
from jjdai.adapters.registry import BackendConfig, register  # noqa: E402


class LlamaCppEngine(BaseEngineBackend):
    backend = "llama.cpp"
    determinism_level = "best_effort"

    def __init__(self, config: BackendConfig = None):
        cfg = config or BackendConfig()
        self.base_url, self.fingerprint = cfg.url, cfg.fingerprint


register("llama.cpp", LlamaCppEngine)
