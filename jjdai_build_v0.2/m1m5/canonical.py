"""m1m5.canonical — flat-import shim onto jjdai.canonical (RFC 8785 JCS)."""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                        # noqa: F401
