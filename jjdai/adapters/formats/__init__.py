"""Weight/artifact format readers (safetensors · gguf · mlx).

Declared here so the package shape matches the architecture and so a format
reader has one obvious home. Implementations arrive with the backends that
need them in Ф2; until then a caller gets a typed refusal rather than a
guess about what a file contains.
"""
from __future__ import annotations

from ..errors import NotSupported

KNOWN_FORMATS = ("safetensors", "gguf", "mlx")


def read_header(path: str, fmt: str = None) -> dict:
    raise NotSupported("formats", "read_header",
                       f"format readers land with their backends in Ф2; "
                       f"known formats: {list(KNOWN_FORMATS)}")
