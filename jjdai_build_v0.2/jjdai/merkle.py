# -*- coding: utf-8 -*-
"""
jjdai.merkle — domain-separated binary Merkle tree with inclusion proofs.

Factored out of rag_store so the RAG store, the witness anchor, and substrate
content-addressing all share one implementation. Domain separation (leaf vs
node prefixes) prevents second-preimage attacks that plain concatenation admits.

  leaf  digest = HASH(0x00 ‖ leaf_bytes)
  node  digest = HASH(0x01 ‖ left ‖ right)
  odd level: the last node is duplicated (paired with itself).

Proof element: (side, sibling_hex) where side ∈ {"L","R"} tells whether the
sibling sits to the left or right of the running hash.
"""

from .crypto import H, H_hex

_LEAF = b"\x00"
_NODE = b"\x01"


def _leaf(b: bytes) -> str:
    return H_hex(_LEAF + b)


def _node(l_hex: str, r_hex: str) -> str:
    return H_hex(_NODE + bytes.fromhex(l_hex) + bytes.fromhex(r_hex))


def merkle_root(leaves: list) -> str:
    """leaves: list[bytes]. Returns hex root; empty -> all-zero root."""
    if not leaves:
        return "00" * 32
    level = [_leaf(b) for b in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list, index: int) -> list:
    """Return the inclusion proof for leaves[index]."""
    if not (0 <= index < len(leaves)):
        raise IndexError("leaf index out of range")
    level = [_leaf(b) for b in leaves]
    idx = index
    proof = []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        if idx % 2 == 0:
            proof.append(("R", level[idx + 1]))
        else:
            proof.append(("L", level[idx - 1]))
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return proof


def merkle_verify(leaf_bytes: bytes, proof: list, root: str) -> bool:
    h = _leaf(leaf_bytes)
    for side, sib in proof:
        h = _node(sib, h) if side == "L" else _node(h, sib)
    return hmac_equal(h, root)


def hmac_equal(a: str, b: str) -> bool:
    # constant-time-ish hex compare
    import hmac
    return hmac.compare_digest(a, b)
