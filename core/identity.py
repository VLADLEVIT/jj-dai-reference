# -*- coding: utf-8 -*-
"""
core.identity — persistent identity: the foundation authenticity layer
(v0.3.0 #1). Closes the deepest gap: keys were EPHEMERAL (regenerated every
start), NodeID and BeingID were conflated, and there was no genesis, no
migration, no startup verification.

TWO DISTINCT IDENTITIES (NodeID ≠ BeingID):

  NodeIdentity  — the physical HOST/operator (the machine). Persistent node
                  key in an encrypted keystore. Signs node-operational records
                  and hosts Beings. node_id = HASH(node_pubkey).
  BeingIdentity — the agent's MIND. Persistent, PORTABLE being key in its own
                  keystore. Signs the Being's own memory/deliberation records
                  and, crucially, its own MIGRATION (consent). being_id =
                  "being:" + HASH(being_pubkey)[:32]. A Being is not its host:
                  it can move hosts (pull-by-choice) and remain itself.

BEING MANIFEST — the Being's birth certificate: {being_id, being_pubkey,
genesis_ts, genesis_node_id, version}, SIGNED by the being key. Anyone can
verify a manifest against the being pubkey; the being_id is bound to the key
(being_id = HASH(pubkey)-derived), so a manifest cannot be re-attributed.

GENESIS & MIGRATION — witnessed IDENTITY records:
  * GENESIS: a Being is born and first bound to a host node.
  * MIGRATION: a Being moves from one host to another. It MUST be signed by
    the BEING key — the mind consents to its own move. A migration not signed
    by the being key is REFUSED (Invariant IV: no power may seize a node/mind;
    movement is pull-by-choice). The receiving node countersigns to accept.

STARTUP CHAIN VERIFICATION — on boot a node re-verifies its whole witness
chain (Ed25519 + hash links) and the manifests of the Beings it hosts, before
serving. A broken chain or an unverifiable manifest halts startup.

COMMITMENT-OPENING POLICY (Bro's fork — explicit decision, not an accident):
  Hiding commitments H(salt‖x) enter the chain; the per-record salt lives only
  in memory and is NOT persisted. We therefore FORMALLY DECLARE commitments
  ONE-WAY / NON-OPENABLE across restart. Content revelation is NOT done by
  opening a commitment; it is done from the local append-only JOURNAL, whose
  entries are bound to the chain by the clear-text semantic_digest (the model
  used by registry/containment/memory/viveka). This keeps integrity provable
  by anyone (digest binding) while content stays private and unrevealable to
  third parties — the property we actually want. A SaltVault (encrypted salt
  persistence) is provided as an OPT-IN for the narrow future case where
  third-party revelation of a specific record is required; by default it is
  OFF and the one-way policy holds. Choosing silence (losing salts) is the
  secure default; choosing the vault is a deliberate, witnessed act.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from jjdai.canonical import canonical                       # noqa: E402
from jjdai.crypto import (canonical_node_id, canonical_being_id, SigningKey, verify as ed_verify,  # noqa: E402
                          node_id as _hash_pub, H_hex,
                          save_keystore, load_keystore)

IDENTITY_VERSION = "1"


class IdentityError(RuntimeError):
    pass


class MigrationConsentError(IdentityError):
    """A migration was not signed by the being key — the mind did not consent.
    Refused (Invariant IV: movement is pull-by-choice, never seizure)."""


# --------------------------------------------------------------------------- #
# Keystore-backed persistent keys
# --------------------------------------------------------------------------- #

def _load_or_create_key(keystore_path: str, passphrase: str) -> SigningKey:
    """Load a persistent Ed25519 key from an encrypted keystore, or create +
    save one on first boot. This is what makes identity survive restart."""
    if keystore_path and os.path.exists(keystore_path):
        return load_keystore(keystore_path, passphrase)
    sk = SigningKey.generate()
    if keystore_path:
        os.makedirs(os.path.dirname(os.path.abspath(keystore_path)) or ".",
                    exist_ok=True)
        save_keystore(sk, keystore_path, passphrase)
    return sk


class NodeIdentity:
    """Persistent identity of the physical host."""

    def __init__(self, signing_key: SigningKey):
        self.sk = signing_key
        self.node_id = canonical_node_id(self.sk.public)

    @classmethod
    def load_or_create(cls, keystore_path: str, passphrase: str) -> "NodeIdentity":
        return cls(_load_or_create_key(keystore_path, passphrase))

    @property
    def pubkey_hex(self) -> str:
        return self.sk.public.hex()

    def descriptor(self) -> dict:
        return {"kind": "NodeDescriptor", "node_id": self.node_id,
                "pubkey": self.pubkey_hex, "version": IDENTITY_VERSION}


class BeingIdentity:
    """Persistent, portable identity of an agent's mind."""

    def __init__(self, signing_key: SigningKey):
        self.sk = signing_key
        self.being_id = canonical_being_id(self.sk.public)

    @classmethod
    def load_or_create(cls, keystore_path: str, passphrase: str) -> "BeingIdentity":
        return cls(_load_or_create_key(keystore_path, passphrase))

    @property
    def pubkey_hex(self) -> str:
        return self.sk.public.hex()

    def manifest(self, *, genesis_node_id: str, genesis_ts: float) -> dict:
        """The Being's signed birth certificate."""
        body = {"kind": "BeingManifest", "being_id": self.being_id,
                "pubkey": self.pubkey_hex, "genesis_node_id": genesis_node_id,
                "genesis_ts": genesis_ts, "version": IDENTITY_VERSION}
        body["sig"] = self.sk.sign(canonical(
            {k: v for k, v in body.items()})).hex()
        return body


def verify_manifest(manifest: dict) -> bool:
    """Verify a Being manifest: signature by the being key AND being_id bound
    to that key (so a manifest cannot be re-attributed to another being_id)."""
    try:
        pub = bytes.fromhex(manifest["pubkey"])
        if manifest["being_id"] != canonical_being_id(pub):
            return False
        body = {k: v for k, v in manifest.items() if k != "sig"}
        return ed_verify(pub, canonical(body), bytes.fromhex(manifest["sig"]))
    except (KeyError, ValueError):
        return False


# --------------------------------------------------------------------------- #
# Genesis & migration — witnessed IDENTITY records with consent
# --------------------------------------------------------------------------- #

class IdentityBinder:
    """Emits and verifies genesis/migration IDENTITY records on a node's
    witness chain. Migration requires the being key's signature (consent)."""

    def __init__(self, node: NodeIdentity, *, witness=None, now_fn=time.time):
        self.node = node
        self._witness = witness
        self._now = now_fn

    def genesis(self, being: BeingIdentity) -> dict:
        """Birth: a Being is created and first bound to this host."""
        manifest = being.manifest(genesis_node_id=self.node.node_id,
                                  genesis_ts=self._now())
        payload = {"event": "genesis", "being_id": being.being_id,
                   "host_node_id": self.node.node_id, "manifest": manifest,
                   "t": self._now()}
        # being consents to its birth-binding; node countersigns
        payload["being_sig"] = being.sk.sign(canonical(
            {k: v for k, v in payload.items()})).hex()
        payload["node_sig"] = self.node.sk.sign(canonical(
            {k: v for k, v in payload.items()})).hex()
        digest = H_hex(canonical(payload))
        if self._witness is not None:
            self._witness.append(
                "IDENTITY", request={"identity_event": payload},
                provenance={"module": "core.identity", "event": "genesis",
                            "being_id": being.being_id},
                semantic_digest=f"id:genesis:{being.being_id}:{digest}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(payload["t"])))
        return payload

    def migrate(self, being: BeingIdentity, *, from_node_id: str,
                to_node_id: str, being_signature_hex: str = None) -> dict:
        """A Being moves host. MUST carry the being key's signature (consent).
        Pass being_signature_hex to simulate a migration proposed WITHOUT the
        real being key (it will be refused)."""
        core = {"event": "migration", "being_id": being.being_id,
                "from_node_id": from_node_id, "to_node_id": to_node_id,
                "t": self._now()}
        signed_blob = canonical(core)
        sig = being_signature_hex or being.sk.sign(signed_blob).hex()
        # consent check: the signature must verify under the being's key
        if not ed_verify(being.sk.public, signed_blob, bytes.fromhex(sig)):
            raise MigrationConsentError(
                f"migration of {being.being_id} not signed by the being key "
                "— seizure refused (pull-by-choice)")
        payload = dict(core, being_sig=sig,
                       node_sig=self.node.sk.sign(signed_blob).hex())
        digest = H_hex(canonical(payload))
        if self._witness is not None:
            self._witness.append(
                "IDENTITY", request={"identity_event": payload},
                provenance={"module": "core.identity", "event": "migration",
                            "being_id": being.being_id},
                semantic_digest=f"id:migration:{being.being_id}:{digest}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(payload["t"])))
        return payload


def verify_startup(chain, *, node: NodeIdentity = None,
                   manifests: list = None) -> dict:
    """Boot-time gate: re-verify the whole witness chain and every hosted
    Being's manifest before the node serves. Returns a report; raises
    IdentityError on any failure so a compromised node fails closed."""
    if not chain.verify_chain():
        raise IdentityError("startup: witness chain failed verification")
    bad = [m.get("being_id") for m in (manifests or []) if not verify_manifest(m)]
    if bad:
        raise IdentityError(f"startup: unverifiable manifest(s): {bad}")
    genesis_records = [r for r in chain.records
                       if r.get("kind") == "IDENTITY"
                       and str(r.get("semantic_digest", "")).startswith("id:genesis:")]
    return {"chain_verified": True, "records": len(chain.records),
            "manifests_ok": len(manifests or []),
            "genesis_records": len(genesis_records),
            "node_id": node.node_id if node else None}


# --------------------------------------------------------------------------- #
# Commitment-opening policy — the explicit fork
# --------------------------------------------------------------------------- #

class CommitmentPolicy:
    """The formal decision on hiding-commitment opening. Default: ONE-WAY."""
    ONE_WAY = "one-way"          # salts not persisted; reveal via journal only
    VAULTED = "vaulted"          # opt-in encrypted salt persistence

    def __init__(self, mode: str = ONE_WAY):
        if mode not in (self.ONE_WAY, self.VAULTED):
            raise IdentityError(f"unknown commitment policy {mode!r}")
        self.mode = mode

    @property
    def openable(self) -> bool:
        return self.mode == self.VAULTED

    def describe(self) -> str:
        if self.mode == self.ONE_WAY:
            return ("commitments are one-way: salts are not persisted; content "
                    "revelation is via the local journal bound by semantic_digest")
        return ("commitments are vaulted: salts persisted (encrypted) for "
                "opt-in third-party revelation of specific records")


class SaltVault:
    """OPT-IN encrypted persistence of commitment salts, for the narrow case
    where a specific record must later be OPENED to a third party. Off by
    default. Uses the same scrypt-derived stream as the keystore."""

    def __init__(self, path: str, passphrase: str):
        self.path = path
        self._pass = passphrase
        self._salts: dict = {}
        if path and os.path.exists(path):
            self._load()

    def put(self, index: int, field: str, salt_hex: str):
        self._salts[f"{index}:{field}"] = salt_hex
        self._save()

    def get(self, index: int, field: str) -> str:
        return self._salts.get(f"{index}:{field}")

    # NB: reuses the keystore's scrypt+HMAC-CTR pattern for at-rest encryption.
    def _save(self):
        import hashlib, hmac
        blob = json.dumps(self._salts, sort_keys=True).encode()
        salt = os.urandom(16)
        key = hashlib.scrypt(self._pass.encode(), salt=salt, n=2**14, r=8,
                             p=1, dklen=32)
        stream = b"".join(
            hmac.new(key, salt + i.to_bytes(4, "big"), hashlib.sha256).digest()
            for i in range((len(blob) + 31) // 32))[:len(blob)]
        ct = bytes(a ^ b for a, b in zip(blob, stream))
        tag = hmac.new(key, ct, hashlib.sha256).digest()
        with open(self.path, "wb") as f:
            f.write(b"JJSV" + salt + tag + ct)

    def _load(self):
        import hashlib, hmac
        with open(self.path, "rb") as f:
            blob = f.read()
        if blob[:4] != b"JJSV":
            raise IdentityError("bad salt-vault magic")
        salt, tag, ct = blob[4:20], blob[20:52], blob[52:]
        key = hashlib.scrypt(self._pass.encode(), salt=salt, n=2**14, r=8,
                             p=1, dklen=32)
        if not hmac.compare_digest(tag, hmac.new(key, ct, hashlib.sha256).digest()):
            raise IdentityError("salt-vault auth failed (wrong passphrase/tamper)")
        stream = b"".join(
            hmac.new(key, salt + i.to_bytes(4, "big"), hashlib.sha256).digest()
            for i in range((len(ct) + 31) // 32))[:len(ct)]
        self._salts = json.loads(bytes(a ^ b for a, b in zip(ct, stream)).decode())
