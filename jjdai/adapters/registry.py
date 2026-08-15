"""jjdai/adapters/registry.py — backend registry (v0.6.5).

Names map to constructors, and nothing may register that does not satisfy
EngineBackend Protocol v1. Registration is the ONLY door: the daemon asks the
registry for a backend by name and never imports a driver directly, so adding
a driver never edits the daemon.
"""
from __future__ import annotations

from .errors import RegistryError
from .protocol import METHOD_GROUPS, PROTOCOL_VERSION

_REGISTRY: dict = {}


def register(name: str, factory, *, replace: bool = False):
    """Register a backend driver factory under a stable name."""
    if not callable(factory):
        raise RegistryError(f"factory for {name!r} is not callable")
    if name in _REGISTRY and not replace:
        raise RegistryError(
            f"backend {name!r} is already registered — pass replace=True to "
            f"override deliberately (silent shadowing is how two drivers end "
            f"up disagreeing about which one served a request)")
    _REGISTRY[name] = factory
    return factory


def available() -> list:
    return sorted(_REGISTRY)


def create(name: str, *args, **kw):
    """Construct a registered backend and verify the contract before use."""
    factory = _REGISTRY.get(name)
    if factory is None:
        raise RegistryError(
            f"unknown backend {name!r}; registered: {available()}")
    backend = factory(*args, **kw)
    missing = [m for ms in METHOD_GROUPS.values() for m in ms
               if not hasattr(backend, m)]
    if missing:
        raise RegistryError(
            f"backend {name!r} does not satisfy EngineBackend Protocol "
            f"v{PROTOCOL_VERSION}: missing {missing}. Unimplemented methods "
            f"must be DECLARED and raise NotSupported, not absent — inherit "
            f"BaseEngineBackend.")
    return backend


def load_builtin():
    """Import the in-tree drivers so they self-register. Kept lazy: a driver
    whose optional host requirement is missing must not break the import of
    the package for everyone else."""
    from . import backends            # noqa: F401  (side-effect: registration)
    return available()
