# -*- coding: utf-8 -*-
"""
jjdai — shared primitive layer for the JJ DAI trust stack.

    canonical : RFC 8785 JCS deterministic byte encoding
    crypto    : SHA-256, Ed25519 (RFC 8032), node identity, hiding commitments
    merkle    : domain-separated Merkle tree + inclusion proofs
    witness   : hash-chained, signed, append-only witness log

Both the reference prototype (rag_store, node daemon) and the NECS conformance
harness bind to these modules.
"""

from . import canonical, crypto, merkle, witness   # noqa: F401

__all__ = ["canonical", "crypto", "merkle", "witness"]
__version__ = "0.6.3"
