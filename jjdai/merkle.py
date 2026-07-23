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


# --------------------------------------------------------------------------- #
# RFC 6962 tree (v0.5 drop 6 — Replication Soundness)
# --------------------------------------------------------------------------- #
# The duplicate-padding tree above detects EQUAL-count divergence, but its
# root at n leaves is not a function of subtree roots of an arbitrary prefix,
# so prefix consistency between two honest roots at different counts cannot
# be proven from it. The Certificate-Transparency tree (RFC 6962: split at
# the largest power of two strictly less than n) supports both inclusion and
# CONSISTENCY proofs. Leaf/node domain prefixes (0x00/0x01) are identical to
# RFC 6962, so only the tree SHAPE differs from the legacy tree.
#
#   mth_root            — RFC 6962 §2.1  Merkle Tree Head
#   mth_inclusion       — §2.1.1 PATH(m, D[n]);  mth_verify_inclusion — audit
#   consistency_proof   — §2.1.2 PROOF(m, D[n])
#   verify_consistency  — §2.1.4.2 verification algorithm
#
# The empty tree hashes to HASH("") per the RFC — deliberately distinct from
# the legacy all-zero empty root, so the two algorithms can never be confused
# for one another at count 0.

def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth_root(leaves: list) -> str:
    """RFC 6962 Merkle Tree Hash over leaves: list[bytes] (hex digest)."""
    n = len(leaves)
    if n == 0:
        return H_hex(b"")
    if n == 1:
        return _leaf(leaves[0])
    k = _split(n)
    return _node(mth_root(leaves[:k]), mth_root(leaves[k:]))


def mth_inclusion(leaves: list, index: int) -> list:
    """RFC 6962 audit path PATH(index, D[n]) as [(side, sibling_hex), ...]."""
    n = len(leaves)
    if not (0 <= index < n):
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return mth_inclusion(leaves[:k], index) + [("R", mth_root(leaves[k:]))]
    return mth_inclusion(leaves[k:], index - k) + [("L", mth_root(leaves[:k]))]


def mth_verify_inclusion(leaf_bytes: bytes, index: int, n: int,
                         proof: list, root: str) -> bool:
    """Verify an RFC 6962 audit path. index/n bind the position: the same
    proof cannot be replayed for a different claimed position or tree size."""
    if not (0 <= index < n):
        return False
    h = _leaf(leaf_bytes)
    fn, sn = index, n - 1
    for side, sib in proof:
        if sn == 0:
            return False
        if side == "L":
            if not (fn & 1 or fn == sn):
                return False
            h = _node(sib, h)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            if fn & 1 or fn == sn:
                return False
            h = _node(h, sib)
        fn >>= 1
        sn >>= 1
    return sn == 0 and hmac_equal(h, root)


def consistency_proof(leaves: list, m: int) -> list:
    """RFC 6962 PROOF(m, D[n]): prove the tree over leaves[:m] is a prefix
    of the tree over all n = len(leaves) leaves. Returns a list of hex node
    hashes (order per the RFC subproof recursion)."""
    n = len(leaves)
    if not (0 < m <= n):
        raise IndexError("consistency: need 0 < m <= n")
    if m == n:
        return []
    return _subproof(m, leaves, True)


def _subproof(m: int, D: list, complete: bool) -> list:
    n = len(D)
    if m == n:
        return [] if complete else [mth_root(D)]
    k = _split(n)
    if m <= k:
        return _subproof(m, D[:k], complete) + [mth_root(D[k:])]
    return _subproof(m - k, D[k:], False) + [mth_root(D[:k])]


def verify_consistency(m: int, n: int, root_m: str, root_n: str,
                       proof: list) -> bool:
    """RFC 6962 §2.1.4.2: verify that root_m (over the first m leaves) is a
    prefix of root_n (over n leaves) using PROOF(m, D[n])."""
    if m == n:
        return not proof and hmac_equal(root_m, root_n)
    if not (0 < m < n):
        return False
    path = list(proof)
    if m == 1 << (m.bit_length() - 1):      # m is an exact power of two
        path = [root_m] + path
    if not path:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _node(c, fr)
            sr = _node(c, sr)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and hmac_equal(fr, root_m) and hmac_equal(sr, root_n)


def hmac_equal(a: str, b: str) -> bool:
    # constant-time-ish hex compare
    import hmac
    return hmac.compare_digest(a, b)
