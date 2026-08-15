"""vLLM backend driver — declared, not yet implemented (Ф2 deliverable).

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
from jjdai.adapters.registry import register                 # noqa: E402


class VLLMEngine(BaseEngineBackend):
    backend = "vllm"
    determinism_level = "best_effort"

    def __init__(self, base_url: str = "", *, fingerprint: str = ""):
        self.base_url, self.fingerprint = base_url, fingerprint


register("vllm", VLLMEngine)
