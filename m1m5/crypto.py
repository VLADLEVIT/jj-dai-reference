"""m1m5.crypto — flat-import shim onto the jjdai primitive layer.

The prototype (M1–M5) uses flat imports; the single source of truth for
Ed25519 / hashing / identity is jjdai/crypto.py (README migration).
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..")))
from jjdai.crypto import *                                   # noqa: F401,F403
from jjdai.crypto import (SigningKey, verify, node_id, H, H_hex,      # noqa: F401
                          commit, open_commit, save_keystore, load_keystore)
