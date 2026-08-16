"""Backend drivers. OUR code only — no engine source is vendored here.

Each module registers itself with the registry on import. Failures are
RECORDED rather than swallowed: a driver that disappears from the registry
because of its own bug, silently, leaves the node reporting one fewer
capability with no way to ask why. A missing host requirement and a broken
driver look identical from outside — so the reason is kept.
"""
from __future__ import annotations

from ..registry import note_import_error

from . import hash as _hash                    # noqa: F401  always available

for _mod in ("dwarfstar", "sglang", "vllm", "llama_cpp", "mlx", "asic"):
    try:
        __import__(f"{__name__}.{_mod}")
    except Exception as _exc:                   # pragma: no cover
        note_import_error(_mod, _exc)
