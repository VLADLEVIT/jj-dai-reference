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
#: Import failures are RECORDED, never swallowed. A driver that vanishes
#: from the registry because of its own syntax error, silently, is worse
#: than one that fails loudly: the node simply reports one fewer capability
#: and nobody asks why.
_IMPORT_ERRORS: dict = {}


class BackendConfig:
    """Everything a driver may need, in one shape the daemon can build
    without knowing which driver will receive it.

    THE REASON THIS EXISTS. A registry that maps names to constructors with
    different signatures does not remove the branch — it moves it. The
    daemon still has to know that DwarfStar takes a base_url and HashEngine
    does not, so `if args.engine == ...` survives, and adding a backend
    still edits the daemon. Which is precisely what the seam was built to
    prevent.

    So drivers accept ONE argument. What a driver does not use, it ignores;
    what it requires and does not find, it refuses at construction, by name,
    where the operator can read it.
    """

    __slots__ = ("url", "fingerprint", "determinism_level", "adapter_paths",
                 "device", "extra")

    def __init__(self, *, url: str = "", fingerprint: str = "",
                 determinism_level: str = "", adapter_paths: dict = None,
                 device: str = "", extra: dict = None):
        self.url = url
        self.fingerprint = fingerprint
        self.determinism_level = determinism_level
        self.adapter_paths = adapter_paths or {}
        self.device = device
        self.extra = extra or {}

    def require(self, backend: str, *fields):
        for f in fields:
            if not getattr(self, f, None):
                raise RegistryError(
                    f"backend {backend!r} requires {f!r} in its "
                    f"BackendConfig and it was not provided")
        return self

    def as_dict(self) -> dict:
        return {f: getattr(self, f) for f in self.__slots__}


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


def import_errors() -> dict:
    """Drivers that failed to import, and why. Surfaced in capabilities so a
    missing backend is a visible fact rather than a silent absence."""
    return dict(_IMPORT_ERRORS)


def create(name: str, config: "BackendConfig" = None):
    """Construct a registered backend from a config and verify the contract.

    One argument, every driver. This is what actually lets the daemon stop
    knowing which engines exist.
    """
    factory = _REGISTRY.get(name)
    if factory is None:
        failed = _IMPORT_ERRORS.get(name)
        raise RegistryError(
            f"unknown backend {name!r}; registered: {available()}"
            + (f" (its driver failed to import: {failed})" if failed else ""))
    backend = factory(config or BackendConfig())
    missing = [m for ms in METHOD_GROUPS.values() for m in ms
               if not hasattr(backend, m)]
    if missing:
        raise RegistryError(
            f"backend {name!r} does not satisfy EngineBackend Protocol "
            f"v{PROTOCOL_VERSION}: missing {missing}. Unimplemented methods "
            f"must be DECLARED and raise NotSupported, not absent — inherit "
            f"BaseEngineBackend.")
    return backend


def note_import_error(name: str, exc: BaseException):
    _IMPORT_ERRORS[name] = f"{type(exc).__name__}: {exc}"


def load_builtin():
    """Import the in-tree drivers so they self-register. Kept lazy: a driver
    whose optional host requirement is missing must not break the import of
    the package for everyone else — but the failure is RECORDED, so an
    absence can always be explained."""
    from . import backends            # noqa: F401  (side-effect: registration)
    return available()
