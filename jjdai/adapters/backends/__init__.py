"""Backend drivers. OUR code only — no engine source is vendored here.

Each module registers itself with the registry on import. Imports are
individually guarded: a driver that needs an absent host requirement must not
take the whole package down with it.
"""
from __future__ import annotations

from . import hash as _hash                    # noqa: F401  always available

for _mod in ("dwarfstar", "sglang", "vllm", "llama_cpp", "mlx", "asic"):
    try:
        __import__(f"{__name__}.{_mod}")
    except Exception:                          # pragma: no cover
        pass
