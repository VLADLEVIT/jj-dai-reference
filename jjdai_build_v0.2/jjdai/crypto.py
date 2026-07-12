# -*- coding: utf-8 -*-
"""
jjdai.crypto — cryptographic primitives for the JJ DAI trust layer.

Zero third-party dependencies (stdlib only). Provides:
  * HASH            — SHA-256 by default (NECS default), pluggable per substrate
  * Ed25519         — real signatures, pure-Python RFC 8032 (deterministic)
  * node identity   — node_id = HASH(pubkey); seed + scrypt keystore seam
  * commitments     — HIDING scheme: commit = HASH(salt ‖ canonical(x))
  * VRF / threshold — interface stubs (curve arithmetic already present)

Design notes locked in conversation:
  - Signature primitive: Ed25519 / RFC 8032 (deterministic nonce; reproducible).
  - Commitment scheme:   hiding, per-record 32-byte salt kept LOCAL; only the
                         commitment is written to the witness chain.
"""

import os
import hmac
import hashlib

# ---------------------------------------------------------------------------
# Hash — NECS default SHA-256, exposed behind a name so a substrate MAY declare
# another. Everything in the layer hashes through this one function.
# ---------------------------------------------------------------------------

HASH_NAME = "sha256"

def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def H_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ===========================================================================
# Ed25519 — RFC 8032 reference arithmetic (edwards25519), pure Python.
# ===========================================================================

_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493   # group order

def _sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()

def _sha512_modL(s: bytes) -> int:
    return int.from_bytes(_sha512(s), "little") % _L

def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)

_d = (-121665 * _inv(121666)) % _p
_sqrt_m1 = pow(2, (_p - 1) // 4, _p)

# Extended homogeneous coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, x*y = T/Z
def _point_add(P, Q):
    A = ((P[1] - P[0]) * (Q[1] - Q[0])) % _p
    B = ((P[1] + P[0]) * (Q[1] + Q[0])) % _p
    C = (2 * P[3] * Q[3] * _d) % _p
    D = (2 * P[2] * Q[2]) % _p
    E, F, G_, Hh = B - A, D - C, D + C, B + A
    return ((E * F) % _p, (G_ * Hh) % _p, (F * G_) % _p, (E * Hh) % _p)

def _point_mul(s: int, P):
    Q = (0, 1, 1, 0)   # neutral element
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q

def _point_equal(P, Q) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % _p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % _p != 0:
        return False
    return True

def _recover_x(y: int, sign: int):
    if y >= _p:
        return None
    x2 = ((y * y - 1) * _inv(_d * y * y + 1)) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = (x * _sqrt_m1) % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x

_g_y = (4 * _inv(5)) % _p
_g_x = _recover_x(_g_y, 0)
_G = (_g_x, _g_y, 1, (_g_x * _g_y) % _p)

def _compress(P) -> bytes:
    zinv = _inv(P[2])
    x = (P[0] * zinv) % _p
    y = (P[1] * zinv) % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")

def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _p)

def _secret_expand(seed: bytes):
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


class SigningKey:
    """Ed25519 private key. 32-byte seed; deterministic signatures."""
    __slots__ = ("seed", "_a", "_prefix", "public")

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        self.seed = seed
        self._a, self._prefix = _secret_expand(seed)
        self.public = _compress(_point_mul(self._a, _G))

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(os.urandom(32))

    def sign(self, msg: bytes) -> bytes:
        r = _sha512_modL(self._prefix + msg)
        Rs = _compress(_point_mul(r, _G))
        k = _sha512_modL(Rs + self.public + msg)
        s = (r + k * self._a) % _L
        return Rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress(public)
    if A is None:
        return False
    Rs = sig[:32]
    R = _decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = _sha512_modL(Rs + public + msg)
    sB = _point_mul(s, _G)
    kA = _point_mul(k, A)
    return _point_equal(sB, _point_add(R, kA))


# ===========================================================================
# Node identity & keystore
# ===========================================================================

def node_id(public: bytes) -> str:
    """NECS C3.3: node_id = HASH(pubkey)."""
    return H_hex(public)


def save_keystore(sk: SigningKey, path: str, passphrase: str) -> None:
    """Passphrase-encrypted seed at rest (scrypt + XOR-stream via HMAC-CTR).
    stdlib only. Dev may skip and store the raw seed instead."""
    salt = os.urandom(16)
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    stream = b"".join(
        hmac.new(key, salt + i.to_bytes(4, "big"), hashlib.sha256).digest()
        for i in range((32 + 31) // 32)
    )[:32]
    ct = bytes(a ^ b for a, b in zip(sk.seed, stream))
    tag = hmac.new(key, ct, hashlib.sha256).digest()
    with open(path, "wb") as f:
        f.write(b"JJK1" + salt + tag + ct)


def load_keystore(path: str, passphrase: str) -> SigningKey:
    with open(path, "rb") as f:
        blob = f.read()
    assert blob[:4] == b"JJK1", "bad keystore magic"
    salt, tag, ct = blob[4:20], blob[20:52], blob[52:84]
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    if not hmac.compare_digest(tag, hmac.new(key, ct, hashlib.sha256).digest()):
        raise ValueError("keystore auth failed (wrong passphrase or tamper)")
    stream = b"".join(
        hmac.new(key, salt + i.to_bytes(4, "big"), hashlib.sha256).digest()
        for i in range((32 + 31) // 32)
    )[:32]
    return SigningKey(bytes(a ^ b for a, b in zip(ct, stream)))


# ===========================================================================
# Commitments — HIDING scheme (chosen). Only the commitment enters the chain;
# the salt is kept in the local private store and is required to open.
# ===========================================================================

SALT_BYTES = 32

def commit(canonical_bytes: bytes, salt: bytes = None):
    """Return (commitment_hex, salt). commitment = HASH(salt ‖ x).
    Hiding: without the salt an adversary cannot confirm a guessed input."""
    if salt is None:
        salt = os.urandom(SALT_BYTES)
    return H_hex(salt + canonical_bytes), salt

def open_commit(commitment_hex: str, salt: bytes, canonical_bytes: bytes) -> bool:
    return hmac.compare_digest(commitment_hex, H_hex(salt + canonical_bytes))


# ===========================================================================
# Forward-looking stubs (curve arithmetic above is reused when implemented)
# ===========================================================================

def vrf_prove(sk: "SigningKey", alpha: bytes) -> bytes:
    """RFC 9381 ECVRF-EDWARDS25519 — verifiable randomness for champion /
    canary / consensus sampling. Reuses _G / _point_mul above."""
    raise NotImplementedError("VRF: interface reserved (RFC 9381), not yet implemented")

def vrf_verify(public: bytes, alpha: bytes, proof: bytes) -> bytes:
    raise NotImplementedError("VRF: interface reserved (RFC 9381), not yet implemented")

def multisig_verify(policy, message: bytes, sigs: list) -> bool:
    """Naive m-of-n: verify each (pubkey, sig) and apply an m-of-n policy.
    For Founding Trio veto / Steward Collegium. FROST (RFC 9591) deferred."""
    raise NotImplementedError("threshold/multisig: interface reserved, not yet implemented")
