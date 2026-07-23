# -*- coding: utf-8 -*-
"""
core.anchoring_xmr — Monero external anchor, hash-as-spend-key (v0.5.2)
=======================================================================
Anchors the witness root into the Monero blockchain WITHOUT writing any
data on-chain. Monero deliberately resists arbitrary payloads (tx_extra
is contested territory: monero-project/monero#6668), so instead of
storing the root we make the root BE a key:

    root (32 bytes)
      -> secret spend key  b = sc_reduce32(root)
      -> secret view  key  a = sc_reduce32(keccak256(b))     [CryptoNote]
      -> public address    Addr(b*G, a*G)
      -> send one piconero to Addr

The transaction to that deterministically derived address, sealed under
Monero PoW, IS the timestamp. To prove existence-by-time, reveal the
root: anyone re-derives the keys, scans the chain (the view key falls
out of the derivation) and finds the payment in block N. Zero on-chain
footprint; independent of the tx_extra policy debate entirely.

WHAT A RECEIPT HERE MEANS (stated plainly):
  * status "pending-confirmation" = the wallet-rpc ACCEPTED and relayed
    the transfer; custody holds tx_hash + tx_key + the derived address.
  * The proof only hardens as blocks accumulate (Monero convention: 10).
  * Full verification is a CHAIN operation: derive keys from the root,
    scan for the output (or check the named tx with the derived view
    key against a node). This module verifies the BINDING root->address
    offline; it does not embed a Monero node.
  * Anyone who learns the root can sweep the piconero. That is dust and
    that is fine — the timestamp is the block, not the balance.
  * Address derivation is pinned to LEGACY CryptoNote v1 (the format
    every wallet since 2014 accepts and the network keeps honoring
    through the FCMP++/CARROT era); the derivation tag is written into
    every receipt so future formats can coexist.

stdlib-only: Keccak-f[1600] and Monero base58 are implemented here;
ed25519 group operations are reused from jjdai.crypto (same curve).
"""
from __future__ import annotations

import json
import time
import urllib.request

# Reuse of the codebase's own ed25519 group math (private by convention,
# shared by design inside this trust kernel — one curve, one code path).
from jjdai.crypto import _point_mul, _G, _compress, _L

XMR_DERIVATION = "jjdai-xmr-spendkey-v1"      # legacy CryptoNote addresses

# network tag -> (varint prefix for a STANDARD address)
_NETWORK_PREFIX = {"mainnet": 18, "testnet": 53, "stagenet": 24}

PICONERO = 1                                   # 1e-12 XMR — dust by design


class XmrAnchorError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
#  Keccak-256 (LEGACY padding 0x01 — Monero/original Keccak, NOT NIST SHA-3)
# --------------------------------------------------------------------------- #

_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_ROT = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)
_MASK = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(a: list) -> None:
    for rc in _KECCAK_RC:
        # theta
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _KECCAK_ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        # iota
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136                                  # 1088-bit rate for 256-bit out
    a = [[0] * 5 for _ in range(5)]
    # legacy multi-rate padding: 0x01 ... 0x80 (SHA-3 would use 0x06)
    padded = data + b"\x01" + b"\x00" * ((-len(data) - 2) % rate) + b"\x80"
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[8 * i:8 * i + 8], "little")
            a[i % 5][i // 5] ^= lane
        _keccak_f(a)
    out = b""
    for i in range(4):                          # 32 bytes < rate: one squeeze
        out += a[i % 5][i // 5].to_bytes(8, "little")
    return out


# --------------------------------------------------------------------------- #
#  Key & address derivation (legacy CryptoNote)
# --------------------------------------------------------------------------- #

def _sc_reduce32(b: bytes) -> int:
    return int.from_bytes(b, "little") % _L


def _sc_bytes(s: int) -> bytes:
    return s.to_bytes(32, "little")


def keys_from_root(root_hex: str) -> dict:
    """root (32-byte hex) -> the full Monero keypair, deterministically.
    Mirrors `monero-wallet-cli --generate-from-spend-key`: the spend
    scalar is the reduced root; the view scalar is hash_to_scalar of the
    spend secret (CryptoNote deterministic wallets)."""
    root = bytes.fromhex(root_hex)
    if len(root) != 32:
        raise XmrAnchorError("root must be 32 bytes of hex")
    b_sec = _sc_reduce32(root)
    a_sec = _sc_reduce32(keccak256(_sc_bytes(b_sec)))
    return {
        "spend_sec": _sc_bytes(b_sec).hex(),
        "view_sec": _sc_bytes(a_sec).hex(),
        "spend_pub": _compress(_point_mul(b_sec, _G)).hex(),
        "view_pub": _compress(_point_mul(a_sec, _G)).hex(),
    }


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_FULL_BLOCK = 8
_B58_FULL_ENC = 11
_B58_ENC_SIZES = (0, 2, 3, 5, 6, 7, 9, 10, 11)   # partial block -> chars


def _b58_encode_block(block: bytes, out_len: int) -> str:
    num = int.from_bytes(block, "big")
    chars = []
    for _ in range(out_len):
        num, r = divmod(num, 58)
        chars.append(_B58_ALPHABET[r])
    return "".join(reversed(chars))


def base58_xmr(data: bytes) -> str:
    """Monero's block-wise base58 (8-byte blocks -> 11 chars)."""
    out = []
    for off in range(0, len(data), _B58_FULL_BLOCK):
        block = data[off:off + _B58_FULL_BLOCK]
        out_len = (_B58_FULL_ENC if len(block) == _B58_FULL_BLOCK
                   else _B58_ENC_SIZES[len(block)])
        out.append(_b58_encode_block(block, out_len))
    return "".join(out)


def _varint(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def xmr_address_from_root(root_hex: str, network: str = "mainnet") -> str:
    """The deterministic standard address for a witness root."""
    if network not in _NETWORK_PREFIX:
        raise XmrAnchorError(f"unknown network {network!r}")
    k = keys_from_root(root_hex)
    payload = (_varint(_NETWORK_PREFIX[network])
               + bytes.fromhex(k["spend_pub"])
               + bytes.fromhex(k["view_pub"]))
    checksum = keccak256(payload)[:4]
    return base58_xmr(payload + checksum)


def verify_receipt_binding(root_hex: str, receipt: dict) -> tuple:
    """Offline check that a receipt's destination address IS the address
    derived from the root (the part of the proof that needs no node)."""
    try:
        expect = xmr_address_from_root(root_hex,
                                       receipt.get("network", "mainnet"))
    except XmrAnchorError as e:
        return False, str(e)
    if receipt.get("derivation") != XMR_DERIVATION:
        return False, f"unknown derivation {receipt.get('derivation')!r}"
    if receipt.get("address") != expect:
        return False, "address does not derive from this root"
    return True, "ok"


# --------------------------------------------------------------------------- #
#  Backend
# --------------------------------------------------------------------------- #

class XmrAnchor:
    """Anchor backend speaking monero-wallet-rpc JSON-RPC.

    The wallet behind the RPC is the FUNDING wallet (it pays one piconero
    plus fee); the DESTINATION wallet is the root itself. Never point this
    at a wallet holding more than anchoring dust deserves."""
    name = "xmr"

    def __init__(self, wallet_rpc_url: str, network: str = "mainnet",
                 amount: int = PICONERO, timeout: float = 30.0):
        if network not in _NETWORK_PREFIX:
            raise XmrAnchorError(f"unknown network {network!r}")
        self.url = wallet_rpc_url.rstrip("/")
        self.network = network
        self.amount = int(amount)
        self.timeout = float(timeout)

    def _rpc(self, method: str, params: dict) -> dict:
        req = urllib.request.Request(
            self.url + "/json_rpc",
            data=json.dumps({"jsonrpc": "2.0", "id": "0",
                             "method": method, "params": params}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            resp = json.loads(r.read().decode())
        if "error" in resp:
            raise XmrAnchorError(f"wallet-rpc error: {resp['error']}")
        return resp.get("result") or {}

    def submit(self, node_id: str, root: str, count: int) -> dict:
        try:
            address = xmr_address_from_root(root, self.network)
        except XmrAnchorError as e:
            raise XmrAnchorError(f"cannot derive anchor address: {e}")
        base = {"backend": self.name, "node": node_id, "root": root,
                "count": count, "network": self.network,
                "derivation": XMR_DERIVATION, "address": address,
                "amount": self.amount, "ts": time.time()}
        try:
            result = self._rpc("transfer", {
                "destinations": [{"amount": self.amount, "address": address}],
                "get_tx_key": True, "priority": 0})
        except (OSError, ValueError, XmrAnchorError) as e:
            base.update(status="failed", detail=str(e))
            return base
        tx_hash = result.get("tx_hash")
        if not tx_hash:
            base.update(status="failed",
                        detail="wallet-rpc returned no tx_hash")
            return base
        base.update(
            status="pending-confirmation",
            tx_hash=tx_hash,
            tx_key=result.get("tx_key"),
            fee=result.get("fee"),
            note="proof = the tx to the root-derived address; hardens with "
                 "confirmations (10-block convention); verify by deriving "
                 "keys from the root against a Monero node")
        return base
