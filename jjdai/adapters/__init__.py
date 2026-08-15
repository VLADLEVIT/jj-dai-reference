"""jjdai.adapters — the engine seam (v0.6.5).

Three terms that used to share the word "adapter", kept apart on purpose:

  backend driver   our code connecting JJ DAI to an execution engine. The
                   engines themselves are never vendored here — only drivers.
  model profile    a declarative description of a model FAMILY (tokenizer,
                   chat template, architecture id, attention, MoE routing,
                   precisions, required operators).
  weight adapter   extra weights over a checkpoint (LoRA/DoRA). Same word as
                   §8 of the ASIC spec, and the reason the other two needed
                   different names.

Import is unambiguous:  from jjdai.adapters.protocol import EngineBackend
"""
from .errors import (AdapterError, BackendUnavailable, ManifestError,  # noqa: F401
                     ModelNotLoaded, NotSupported, ProfileError,
                     RegistryError)
from .protocol import (BaseEngineBackend, EngineBackend,               # noqa: F401
                       METHOD_GROUPS, PROTOCOL_VERSION,
                       capability_manifest, implements)

__all__ = ["AdapterError", "BackendUnavailable", "ManifestError",
           "ModelNotLoaded", "NotSupported", "ProfileError", "RegistryError",
           "BaseEngineBackend", "EngineBackend", "METHOD_GROUPS",
           "PROTOCOL_VERSION", "capability_manifest", "implements"]
