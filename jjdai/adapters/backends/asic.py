"""JJ DAI ASIC runtime driver — declared, pre-silicon (Ф3 deliverable).

The point of declaring it now is the point of the whole protocol: the ASIC
arrives through the SAME contract as every other engine, so the Ф3 migration
test (GPU/Apple backend → ASIC emulator, trust layer untouched) is a
configuration change rather than an integration project. Ф3's gate is
deliberately independent of tape-out — a functional emulator, a simulator or
a trace-replay reference runtime all satisfy it through this seam.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from jjdai.adapters.protocol import BaseEngineBackend        # noqa: E402
from jjdai.adapters.registry import BackendConfig, register  # noqa: E402


class ASICEngine(BaseEngineBackend):
    backend = "asic"
    determinism_level = "attested"

    def __init__(self, config: BackendConfig = None):
        cfg = config or BackendConfig()
        self.device = cfg.device or "emulator"
        self.fingerprint = cfg.fingerprint


register("asic", ASICEngine)
