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
import tempfile
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
# Neutral element in extended twisted-Edwards coordinates: (0, 1).
_IDENTITY = (0, 1, 1, 0)

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


def _is_small_order(P) -> bool:
    """True if [8]P is the identity — i.e. P lies in the torsion subgroup
    (order 1, 2, 4, or 8). Ed25519's cofactor is 8; such points carry no
    prime-subgroup identity and must never authenticate anything."""
    return _point_equal(_point_mul(8, P), _IDENTITY)


def _decompress_checked(s: bytes):
    """Decode a compressed point AND reject the torsion subgroup. Returns
    None on any malformed encoding or small-order point."""
    P = _decompress(s)
    if P is None:
        return None
    if _is_small_order(P):
        return None
    return P


def verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress_checked(public)          # rejects small-order pubkeys
    if A is None:
        return False
    Rs = sig[:32]
    R = _decompress_checked(Rs)              # rejects small-order R
    if R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = _sha512_modL(Rs + public + msg)
    sB = _point_mul(s, _G)
    kA = _point_mul(k, A)
    # cofactored verification: [8]sB == [8]R + [8]kA. Multiplying by the
    # cofactor clears any residual torsion component and matches RFC 8032's
    # permitted cofactored equation.
    lhs = _point_mul(8, sB)
    rhs = _point_mul(8, _point_add(R, kA))
    return _point_equal(lhs, rhs)


# ===========================================================================
# Node identity & keystore
# ===========================================================================

def node_id(public: bytes) -> str:
    """NECS C3.3: node_id = HASH(pubkey). Raw hex digest (network layer)."""
    return H_hex(public)


def canonical_node_id(public: bytes) -> str:
    """THE single node identity string used everywhere: prefixed, full
    256-bit digest. Unifies the historically divergent forms (raw 64-hex
    in the network layer vs. 'node:'+128-bit in identity/verdicts). All
    modules must derive identity through this function."""
    return "node:" + H_hex(public)


def canonical_being_id(public: bytes) -> str:
    """The single Being identity string: 'being:' + full 256-bit digest."""
    return "being:" + H_hex(public)


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
    blob = b"JJK1" + salt + tag + ct
    # atomic, 0600: write to a private temp file in the same directory then
    # rename over the target. A half-written or world-readable keystore must
    # never exist on disk.
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".keystore-", dir=d)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
# VRF — RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (v0.5.4)
# ===========================================================================
# Verifiable randomness for challenge-panel sortition: only the holder of
# the secret key can compute beta = VRF(SK, alpha), anyone can verify it,
# and NOBODY — including the holder — can grind it to a different value
# (full uniqueness). suite_string = 0x03; cofactor = 8; cLen = 16;
# encode_to_curve_salt = PK. Pinned to all three RFC 9381 B.3 vectors.

_VRF_SUITE = b"\x03"


def _point_neg(P):
    X, Y, Z, T = P
    return ((-X) % _p, Y, Z, (-T) % _p)


def _vrf_encode_to_curve_tai(pk_string: bytes, alpha: bytes):
    """5.4.1.1 try-and-increment: H = 8 * string_to_point(SHA512(suite ||
    0x01 || PK || alpha || ctr || 0x00)[:32]); reject identity."""
    ctr = 0
    while True:
        if ctr > 255:
            raise ValueError("VRF encode_to_curve: ctr overflow")
        h_str = _sha512(_VRF_SUITE + b"\x01" + pk_string + alpha
                        + bytes([ctr]) + b"\x00")[:32]
        P = _decompress(h_str)
        if P is not None:
            H = _point_mul(8, P)                     # clear the cofactor
            if not _point_equal(H, _IDENTITY):
                return H
        ctr += 1


def _vrf_challenge(*points) -> int:
    """5.4.3: c = string_to_int(SHA512(suite || 0x02 || P1..P5 || 0x00)[:16])
    (little-endian for this suite)."""
    s = _VRF_SUITE + b"\x02"
    for P in points:
        s += _compress(P)
    s += b"\x00"
    return int.from_bytes(_sha512(s)[:16], "little")


def vrf_prove(sk: "SigningKey", alpha: bytes) -> bytes:
    """RFC 9381 §5.1 ECVRF_prove -> pi (80 bytes: Gamma || c16 || s32)."""
    x = sk._a                                        # RFC 8032 clamped scalar
    H = _vrf_encode_to_curve_tai(sk.public, alpha)
    h_string = _compress(H)
    Gamma = _point_mul(x, H)
    # 5.4.2.2 nonce from RFC 8032: k = SHA512(SHA512(seed)[32:] || H) mod q
    k = int.from_bytes(_sha512(sk._prefix + h_string), "little") % _L
    c = _vrf_challenge(_decompress(sk.public), H, Gamma,
                       _point_mul(k, _G), _point_mul(k, H))
    s = (k + c * x) % _L
    return (_compress(Gamma) + int.to_bytes(c, 16, "little")
            + int.to_bytes(s, 32, "little"))


def vrf_proof_to_hash(pi: bytes) -> bytes:
    """RFC 9381 §5.2: beta = SHA512(suite || 0x03 || 8*Gamma || 0x00).
    Run only on a pi produced by vrf_prove or validated by vrf_verify."""
    if len(pi) != 80:
        raise ValueError("VRF proof must be 80 bytes")
    Gamma = _decompress(pi[:32])
    if Gamma is None:
        raise ValueError("VRF proof: invalid Gamma")
    return _sha512(_VRF_SUITE + b"\x03"
                   + _compress(_point_mul(8, Gamma)) + b"\x00")


def vrf_verify(public: bytes, alpha: bytes, proof: bytes) -> bytes:
    """RFC 9381 §5.3 with validate_key=TRUE (full uniqueness AND full
    collision resistance under malicious key generation). Returns beta on
    success; raises ValueError on ANY invalidity — fail closed."""
    Y = _decompress_checked(public)                  # on-curve, canonical
    if Y is None:
        raise ValueError("VRF verify: invalid public key encoding")
    if _is_small_order(Y):
        raise ValueError("VRF verify: small-order public key")
    if len(proof) != 80:
        raise ValueError("VRF verify: proof must be 80 bytes")
    Gamma = _decompress(proof[:32])
    if Gamma is None:
        raise ValueError("VRF verify: invalid Gamma encoding")
    c = int.from_bytes(proof[32:48], "little")
    s = int.from_bytes(proof[48:80], "little")
    if s >= _L:
        raise ValueError("VRF verify: s out of range")
    H = _vrf_encode_to_curve_tai(public, alpha)
    U = _point_add(_point_mul(s, _G), _point_neg(_point_mul(c, Y)))
    V = _point_add(_point_mul(s, H), _point_neg(_point_mul(c, Gamma)))
    c_prime = _vrf_challenge(Y, H, Gamma, U, V)
    if c != c_prime:
        raise ValueError("VRF verify: challenge mismatch")
    return vrf_proof_to_hash(proof)

def multisig_verify(policy: dict, message: bytes, sigs: list) -> bool:
    """Naive m-of-n threshold verification (v0.5.4). policy = {"m": int,
    "pubkeys": [hex,...]}; sigs = [(pubkey_hex, sig_hex), ...]. Each
    distinct authorized pubkey counts at most once; unknown keys and bad
    signatures are ignored; True iff >= m distinct valid signers.
    Single-round aggregate signing (FROST, RFC 9591) remains deferred —
    this is plain m-of-n verification, not threshold key generation."""
    m = int(policy["m"])
    allowed = {p.lower() for p in policy["pubkeys"]}
    if m < 1 or m > len(allowed):
        raise ValueError("multisig policy: need 1 <= m <= len(pubkeys)")
    seen = set()
    for pub_hex, sig_hex in sigs:
        pl = pub_hex.lower()
        if pl not in allowed or pl in seen:
            continue
        try:
            if verify(bytes.fromhex(pl), message, bytes.fromhex(sig_hex)):
                seen.add(pl)
        except (ValueError, TypeError):
            continue
        if len(seen) >= m:
            return True
    return len(seen) >= m
