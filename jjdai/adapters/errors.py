"""jjdai/adapters/errors.py — typed, fail-closed adapter errors (v0.6.5).

The contract is versioned and declared WHOLE (see protocol.py): a method the
backend has not implemented yet still exists on the interface and raises
`NotSupported`. That is the difference between a seam and a hole. A missing
attribute makes every caller invent its own probing and its own fallback; a
typed refusal makes the gap explicit, catchable, and reportable in
capabilities — and it fails CLOSED, which is the same posture the isolation
profiles took in v0.6.4.
"""
from __future__ import annotations


class AdapterError(RuntimeError):
    """Base for everything the adapter layer refuses or cannot do."""


class NotSupported(AdapterError):
    """The contract declares this method; this backend does not implement it.

    Not an outage and not a bug — a declared absence. Callers branch on the
    TYPE, never on hasattr(), so the seam cannot rot into duck-typing.
    """

    def __init__(self, backend: str, method: str, detail: str = ""):
        self.backend, self.method = backend, method
        super().__init__(
            f"backend {backend!r} does not implement {method!r}"
            + (f": {detail}" if detail else "")
            + " (EngineBackend Protocol v1 — declared, not implemented)")


class BackendUnavailable(AdapterError):
    """The backend exists but cannot serve right now (process down, model not
    loaded, host requirement missing). Distinct from NotSupported: this one
    may become available without any code changing."""


class ModelNotLoaded(AdapterError):
    """A generation or scoring call arrived before load_model() succeeded."""


class ProfileError(AdapterError):
    """A model-family profile failed schema validation, or names a family
    this backend cannot serve."""


class ManifestError(AdapterError):
    """A ModelArtifactManifest is malformed, unsigned where a signature is
    required, or disagrees with the artifact it claims to describe."""


class RegistryError(AdapterError):
    """Unknown backend name, duplicate registration, or a registration that
    does not satisfy the protocol."""
