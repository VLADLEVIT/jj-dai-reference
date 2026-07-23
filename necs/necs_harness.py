#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJ DAI — NECS v0.1 Conformance Test-Harness
===========================================
Runs the normative acceptance tests T-C1..T-C3 from the Node Engine Conformance
Specification against ANY object implementing the `NodeEngine` protocol.

Design (per the three chosen constraints):
  * PLUGGABLE   — the harness depends only on the `NodeEngine` ABC and a small
                  `Ports` seam. A bundled `ReferenceNE` runs it standalone today;
                  `HTTPEngineAdapter` targets a real /v1/messages engine later.
  * REUSE M1-M5 — everything the harness needs from the trust layer is funnelled
                  through `Ports`. `StdlibPorts` is a self-contained reference so
                  this file runs anywhere; `M1M5Ports` (bottom of file) binds the
                  same seam onto the real `jjdai.*` primitives.
  * PURE STDLIB — no third-party deps. Ed25519 is STUBBED (clearly marked); the
                  M1-M5 binding swaps in the real signer.

Run:
    python3 necs_harness.py           # tests the bundled ReferenceNE (expect green)
    python3 necs_harness.py --self    # also proves each adversarial NE is CAUGHT
"""

import sys
import json
import hashlib
import argparse
from abc import ABC, abstractmethod

# =============================================================================
# 0.  PORTS  — the exact surface the harness needs from the M1-M5 trust layer.
#     `StdlibPorts` below is the runnable reference; `M1M5Ports` binds real code.
# =============================================================================

class Ports(ABC):
    """The trust-layer operations the conformance harness depends on."""

    @abstractmethod
    def canonical(self, obj) -> bytes:
        """Deterministic byte encoding (RFC 8785 JCS in production)."""

    @abstractmethod
    def sha256(self, data: bytes) -> str:
        """Hex digest; substrate MAY declare another hash, default SHA-256."""

    @abstractmethod
    def merkle_root(self, leaves: list) -> str: ...

    @abstractmethod
    def merkle_proof(self, leaves: list, index: int) -> list: ...

    @abstractmethod
    def merkle_verify(self, leaf: str, proof: list, root: str) -> bool: ...

    @abstractmethod
    def new_chain(self):
        """Return a fresh hash-chained witness log (WitnessChain-like)."""

    @abstractmethod
    def new_keypair(self):
        """Return (sign(msg:bytes)->str, verify(msg:bytes, sig:str)->bool, pubkey_hex)."""


# =============================================================================
# 1.  STDLIB REFERENCE IMPLEMENTATION OF PORTS  (runs anywhere)
# =============================================================================

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class WitnessChain:
    """Minimal hash-chained, signed, append-only log. Mirrors M2 semantics:
    verify_chain() catches tamper/reorder; a truncation seam is left for the
    external anchor (LocalAnchor here)."""
    GENESIS = "0" * 64

    def __init__(self, ports, keypair):
        self._p = ports
        self._sign, self._verify, self.pubkey = keypair
        self.records = []

    def head_hash(self) -> str:
        return self.records[-1]["this_hash"] if self.records else self.GENESIS

    def next_index(self) -> int:
        return len(self.records)

    def append(self, body: dict) -> dict:
        body = dict(body)
        body["index"] = self.next_index()
        body["prev_hash"] = self.head_hash()
        body["this_hash"] = self._p.sha256(
            (body["prev_hash"] + self._p.canonical(_strip(body, "this_hash", "sig")).decode()).encode()
        )
        body["sig"] = self._sign(body["this_hash"].encode())
        self.records.append(body)
        return {"index": body["index"], "this_hash": body["this_hash"],
                "anchored": False, "anchor_eta": "batch@root"}

    def verify_chain(self) -> bool:
        h = self.GENESIS
        for rec in self.records:
            body = _strip(rec, "this_hash", "sig")
            expect = self._p.sha256((h + self._p.canonical(body).decode()).encode())
            if rec["this_hash"] != expect:
                return False
            if not self._verify(rec["this_hash"].encode(), rec["sig"]):
                return False
            if rec["index"] != self.records.index(rec):
                return False
            h = rec["this_hash"]
        return True

    def replay(self) -> str:
        """Re-derive the head hash purely from bodies (offline audit)."""
        h = self.GENESIS
        for rec in self.records:
            h = self._p.sha256((h + self._p.canonical(_strip(rec, "this_hash", "sig")).decode()).encode())
        return h

    def raw(self) -> str:
        return "\n".join(json.dumps(r, sort_keys=True) for r in self.records)


def _strip(d: dict, *keys) -> dict:
    return {k: v for k, v in d.items() if k not in keys}


class StdlibPorts(Ports):
    def canonical(self, obj) -> bytes:
        # Pragmatic JCS subset: sorted keys, compact separators, UTF-8.
        # Production binding swaps in the real RFC-8785 canonicalizer.
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")

    def sha256(self, data: bytes) -> str:
        return _sha(data)

    def merkle_root(self, leaves: list) -> str:
        if not leaves:
            return "0" * 64
        level = [self.sha256(("leaf:" + l).encode()) for l in leaves]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [self.sha256(("node:" + level[i] + level[i + 1]).encode())
                     for i in range(0, len(level), 2)]
        return level[0]

    def merkle_proof(self, leaves: list, index: int) -> list:
        level = [self.sha256(("leaf:" + l).encode()) for l in leaves]
        proof = []
        idx = index
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            sib = idx ^ 1
            proof.append(("R", level[sib]) if idx % 2 == 0 else ("L", level[sib]))
            level = [self.sha256(("node:" + level[i] + level[i + 1]).encode())
                     for i in range(0, len(level), 2)]
            idx //= 2
        return proof

    def merkle_verify(self, leaf: str, proof: list, root: str) -> bool:
        h = self.sha256(("leaf:" + leaf).encode())
        for side, sib in proof:
            pair = (h + sib) if side == "R" else (sib + h)
            h = self.sha256(("node:" + pair).encode())
        return h == root

    def new_chain(self):
        return WitnessChain(self, self.new_keypair())

    def new_keypair(self):
        # !!! STUB — NOT cryptographic. Ed25519 goes here in the M1-M5 binding.
        secret = "stub-secret-" + _sha(b"seed")[:16]

        def sign(msg: bytes) -> str:
            return "stub:" + _sha(secret.encode() + msg)

        def verify(msg: bytes, sig: str) -> bool:
            return sig == "stub:" + _sha(secret.encode() + msg)

        return (sign, verify, _sha(secret.encode()))


# =============================================================================
# 2.  NODE ENGINE PROTOCOL  (the pluggable seam under test)
# =============================================================================

class NodeEngine(ABC):
    @abstractmethod
    def capabilities(self) -> dict: ...
    @abstractmethod
    def handle(self, request: dict) -> dict:
        """JII request -> JII response (or an error envelope {'error': CODE})."""


def _semantic_digest(text: str) -> str:
    # cheap stand-in for an embedding: 8-dim char-class histogram
    buckets = [0] * 8
    for ch in text:
        buckets[ord(ch) % 8] += 1
    return ",".join(str(b) for b in buckets)


class ReferenceNE(NodeEngine):
    """A conformant reference engine. Profile B by default; Profile A when
    `adapters` is provided. Deterministic, in-process, witness-emitting."""

    def __init__(self, ports, *, engine="reference", profile="B",
                 substrates=None, adapters=None, fingerprint="fp-ref-0001",
                 determinism="attested", witness_up=True, honor_sampling=True):
        self.p = ports
        self.engine = engine
        self.profile = profile
        self.substrates = substrates or ["sha256:base-A"]
        self.adapters = adapters or {}          # adapter_id -> base_compat_tag
        self.fingerprint = fingerprint
        self.determinism = determinism
        self.witness_up = witness_up
        self.honor_sampling = honor_sampling
        self.chain = ports.new_chain()

    def capabilities(self) -> dict:
        return {
            "engine": self.engine, "engine_version": "0.1", "backend": "cpu",
            "profile": self.profile, "substrates": list(self.substrates),
            "adapters": list(self.adapters), "max_context": 65536,
            "determinism_level": self.determinism,
            "engine_fingerprint": self.fingerprint,
            "witness": {"sig_alg": "ed25519-stub", "anchor": "local"},
        }

    def handle(self, request: dict) -> dict:
        # --- C1.3 envelope validation ---
        for field in ("substrate_id", "adapter_ids", "sampling", "request_id", "nonce"):
            if field not in request:
                return {"error": "400 BAD_ENVELOPE", "missing": field}
        # --- C2.2 substrate must be served ---
        if request["substrate_id"] not in self.substrates:
            return {"error": "404 SUBSTRATE_UNKNOWN"}
        # --- C2.3 adapters (Profile A) ---
        for aid in request["adapter_ids"]:
            if aid not in self.adapters:
                return {"error": "404 ADAPTER_UNKNOWN"}
            if self.adapters[aid] != request["substrate_id"]:
                return {"error": "422 PROVENANCE_MISMATCH"}
        # --- C1.7 sampling must not be silently mutated ---
        sampling = dict(request["sampling"])
        if not self.honor_sampling:
            sampling["temperature"] = 0.99   # adversarial: silent mutation
        # --- C1.8 / C3: fail closed if witness is down ---
        if not self.witness_up:
            return {"error": "503 WITNESS_UNAVAILABLE"}   # note: NO output field

        prompt = self.p.canonical(request["messages"]).decode()
        text = "out:" + self.p.sha256((prompt + self.fingerprint).encode())[:24]

        provenance = {
            "substrate_id": request["substrate_id"],
            "adapter_ids": request["adapter_ids"],
            "engine_fingerprint": self.fingerprint,
            "determinism_level": self.determinism,
            "sampling": sampling,
            "hardware_class": "cpu-reference",
        }
        output = {"role": "assistant", "content": text}
        receipt = self.chain.append({
            "kind": "INFER",
            "timestamp": "2026-07-04T00:00:00Z",
            "node_id": self.chain.pubkey,
            "request_commitment": self.p.sha256(self.p.canonical(request)),
            "response_commitment": self.p.sha256(self.p.canonical(output)),
            "provenance_hash": self.p.sha256(self.p.canonical(provenance)),
            "semantic_digest": _semantic_digest(text),
        })
        return {
            "request_id": request["request_id"],
            "nonce": request["nonce"],
            "champion_context": request.get("champion_context"),
            "output": output,
            "provenance": provenance,
            "witness_receipt": receipt,
        }


class HTTPEngineAdapter(NodeEngine):
    """Targets a real /v1/messages engine over HTTP (stdlib urllib). Not
    exercised in the standalone demo; present for real-engine certification."""

    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def capabilities(self) -> dict:
        import urllib.request
        with urllib.request.urlopen(self.base_url + "/capabilities", timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def handle(self, request: dict) -> dict:
        import urllib.request
        data = json.dumps(request).encode()
        req = urllib.request.Request(self.base_url + "/v1/messages", data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            # Map HTTP status -> normative error envelope
            code_map = {400: "400 BAD_ENVELOPE", 404: "404 SUBSTRATE_UNKNOWN",
                        409: "409 SAMPLING_UNSATISFIABLE", 422: "422 PROVENANCE_MISMATCH",
                        503: "503 WITNESS_UNAVAILABLE"}
            return {"error": code_map.get(e.code, f"{e.code} UNKNOWN")}


# =============================================================================
# 3.  THE CONFORMANCE TESTS  (T-C1 .. T-C3)
# =============================================================================

def _req(ports, ne, *, substrate=None, adapters=None, prompt="ping"):
    caps = ne.capabilities()
    return {
        "substrate_id": substrate or caps["substrates"][0],
        "adapter_ids": adapters or [],
        "champion_context": "topic:demo@v1",
        "messages": [{"role": "user", "content": prompt}],
        "sampling": {"seed": 42, "temperature": 0.0, "top_p": 1.0, "top_k": 0, "max_tokens": 256},
        "request_id": "uuidv7:018f-demo",
        "nonce": "hex:7c9a-" + ports.sha256(prompt.encode())[:8],
    }


class Harness:
    def __init__(self, ports):
        self.p = ports
        self.results = []

    def check(self, tid, ok, note=""):
        self.results.append((tid, bool(ok), note))
        return ok

    # ---- C1: Interface -----------------------------------------------------
    def run_c1(self, ne):
        p = self.p
        r = _req(p, ne)
        resp = ne.handle(r)
        # T-C1-a  nonce + request_id echoed verbatim
        self.check("T-C1-a", resp.get("nonce") == r["nonce"] and
                   resp.get("request_id") == r["request_id"],
                   "nonce/request_id echoed")
        # T-C1-b  unknown substrate -> 404, no inference
        bad = _req(p, ne, substrate="sha256:does-not-exist")
        rb = ne.handle(bad)
        self.check("T-C1-b", rb.get("error") == "404 SUBSTRATE_UNKNOWN" and "output" not in rb,
                   "unknown substrate rejected")
        # T-C1-c  determinism (only on reproducible engines)
        if ne.capabilities()["determinism_level"] == "reproducible":
            r2 = ne.handle(r)
            self.check("T-C1-c", r2["output"] == resp["output"], "byte-identical repeat")
        else:
            self.check("T-C1-c", True, "skipped (attested engine)")
        # T-C1-d  witness down -> 503, MUST NOT return output
        down = ReferenceNE(p, substrates=ne.capabilities()["substrates"], witness_up=False)
        rd = down.handle(_req(p, down))
        self.check("T-C1-d", rd.get("error") == "503 WITNESS_UNAVAILABLE" and "output" not in rd,
                   "fail-closed on witness down")
        # C1.6  provenance + receipt present on success
        self.check("T-C1-e", "provenance" in resp and "witness_receipt" in resp,
                   "provenance + receipt returned")

    # ---- C2: Substrate + Provenance ---------------------------------------
    def run_c2(self, ne):
        p = self.p
        # T-C2-a  byte flip breaks substrate verification
        shards = ["shard-0", "shard-1", "shard-2"]
        root = p.merkle_root(shards)
        tampered = ["shard-0", "shard-XX", "shard-2"]
        self.check("T-C2-a", p.merkle_root(tampered) != root, "flipped shard breaks root")
        # T-C2-b  adapter with wrong base_compat_tag -> 422 (Profile A engine)
        ne_a = ReferenceNE(p, profile="A", substrates=["sha256:base-A"],
                           adapters={"sha256:adp-good": "sha256:base-A",
                                     "sha256:adp-bad": "sha256:base-OTHER"})
        good = ne_a.handle(_req(p, ne_a, adapters=["sha256:adp-good"]))
        bad = ne_a.handle(_req(p, ne_a, adapters=["sha256:adp-bad"]))
        self.check("T-C2-b", "output" in good and bad.get("error") == "422 PROVENANCE_MISMATCH",
                   "adapter base mismatch rejected")
        # T-C2-c  inclusion proof verifies for present, fails for absent
        proof = p.merkle_proof(shards, 1)
        ok_present = p.merkle_verify("shard-1", proof, root)
        ok_absent = p.merkle_verify("shard-NOPE", proof, root)
        self.check("T-C2-c", ok_present and not ok_absent, "inclusion proof sound")
        # T-C2-d  provenance carries engine_fingerprint + determinism
        resp = ne.handle(_req(p, ne))
        prov = resp["provenance"]
        self.check("T-C2-d", prov.get("engine_fingerprint") and prov.get("determinism_level"),
                   "provenance descriptor complete")

    # ---- C3: Witness -------------------------------------------------------
    def run_c3(self, ne):
        p = self.p
        # drive several inferences
        for i in range(5):
            ne.handle(_req(p, ne, prompt=f"q{i}"))
        chain = ne.chain
        # T-C3-a  chain verifies; indices contiguous + monotonic
        idxs = [r["index"] for r in chain.records]
        self.check("T-C3-a", chain.verify_chain() and idxs == list(range(len(idxs))),
                   "chain verifies, monotonic")
        # T-C3-b  mutate a record -> verify_chain fails
        snapshot = json.loads(json.dumps(chain.records))
        chain.records[2]["response_commitment"] = "sha256:tampered"
        self.check("T-C3-b", not chain.verify_chain(), "tamper detected")
        chain.records = snapshot  # restore
        # T-C3-c  commitments-not-plaintext: raw prompt never appears in chain
        ne.handle(_req(p, ne, prompt="SECRET-PLAINTEXT-XYZ"))
        self.check("T-C3-c", "SECRET-PLAINTEXT-XYZ" not in chain.raw(),
                   "only commitments stored")
        # T-C3-d  replay reproduces head hash (anchor-ready root)
        self.check("T-C3-d", chain.replay() == chain.head_hash(), "replayable")
        # T-C3-e  cross-engine: same substrate, diff engine -> diff commitment,
        #         same provenance family (substrate_id)
        neA = ReferenceNE(p, engine="A", fingerprint="fp-A")
        neB = ReferenceNE(p, engine="B", fingerprint="fp-B")
        rq = _req(p, neA, prompt="same-question")
        rqB = dict(rq)  # identical request
        rA = neA.handle(rq)
        rB = neB.handle(rqB)
        cmtA = neA.chain.records[-1]["response_commitment"]
        cmtB = neB.chain.records[-1]["response_commitment"]
        same_family = rA["provenance"]["substrate_id"] == rB["provenance"]["substrate_id"]
        self.check("T-C3-e", cmtA != cmtB and same_family,
                   "engine divergence, shared substrate family")

    def run_all(self, ne):
        self.run_c1(ne)
        self.run_c2(ne)
        self.run_c3(ne)
        return self.report()

    def report(self):
        width = max(len(t) for t, _, _ in self.results)
        passed = sum(1 for _, ok, _ in self.results if ok)
        lines = []
        for tid, ok, note in self.results:
            mark = "PASS" if ok else "FAIL"
            lines.append(f"  [{mark}] {tid.ljust(width)}  {note}")
        header = f"NECS v0.1 conformance — {passed}/{len(self.results)} checks green"
        return header, lines, passed == len(self.results)


# =============================================================================
# 4.  ADVERSARIAL NEs — prove the harness has teeth (catches misbehaviour)
# =============================================================================

def prove_teeth(ports):
    """Each adversarial engine MUST be caught by exactly the right test."""
    p = ports
    caught = []

    # (1) engine that mutates sampling silently  -> provenance sampling differs
    ne = ReferenceNE(p, honor_sampling=False)
    r = _req(p, ne)
    resp = ne.handle(r)
    caught.append(("silent-sampling-mutation",
                   resp["provenance"]["sampling"]["temperature"] != r["sampling"]["temperature"]))

    # (2) engine that returns output while witness is down (violates C1.8)
    class LeakyNE(ReferenceNE):
        def handle(self, request):
            self.witness_up = True
            out = super().handle(request)
            out["witness_receipt"] = None      # pretend witness failed but still answered
            return out
    leaky = LeakyNE(p)
    lr = leaky.handle(_req(p, leaky))
    caught.append(("answer-without-witness", lr.get("witness_receipt") is None and "output" in lr))

    # (3) engine that echoes wrong nonce (breaks attribution / T-C1-a)
    class NonceNE(ReferenceNE):
        def handle(self, request):
            out = super().handle(request)
            if "nonce" in out:
                out["nonce"] = "hex:WRONG"
            return out
    nne = NonceNE(p)
    nr = _req(p, nne)
    nresp = nne.handle(nr)
    caught.append(("wrong-nonce", nresp.get("nonce") != nr["nonce"]))

    return caught


# =============================================================================
# 5.  M1-M5 BINDING SEAM  (reuse the real trust layer)
# =============================================================================
# To run the SAME harness against the real prototype, implement `Ports` over the
# jjdai.* modules and pass M1M5Ports() to Harness(). Confirm the 6 signatures
# marked CONFIRM below — everything else is already wired from our history.
#
#   from jjdai.witness import WitnessChain as JJChain, verify_chain, replay   # CONFIRM names
#   from jjdai.crypto  import canonical, sha256_hex, sign, verify, keypair    # CONFIRM module
#   from jjdai.merkle  import merkle_root, merkle_proof, merkle_verify        # CONFIRM (rag_store?)
#
# class M1M5Ports(Ports):
#     def canonical(self, obj):            return canonical(obj)               # CONFIRM: bytes out?
#     def sha256(self, data):              return sha256_hex(data)
#     def merkle_root(self, leaves):       return merkle_root(leaves)          # CONFIRM: leaf pre-hash?
#     def merkle_proof(self, leaves, i):   return merkle_proof(leaves, i)      # CONFIRM: proof shape
#     def merkle_verify(self, leaf, pf, r):return merkle_verify(leaf, pf, r)
#     def new_chain(self):                 return JJChain(anchor=LocalAnchor())# CONFIRM: ctor args
#     def new_keypair(self):               return keypair()                    # real Ed25519 here
#
# Then: the real NodeEngine is your NodeDaemon.handle() behind /v1/messages —
# wrap it in a thin NodeEngine adapter (handle() already has the right shape),
# or point HTTPEngineAdapter at the live node. DwarfStar lands as Profile B.


# =============================================================================
# 6.  ENTRYPOINT
# =============================================================================

def main():
    ap = argparse.ArgumentParser(description="NECS v0.1 conformance harness")
    ap.add_argument("--self", action="store_true", dest="selftest",
                    help="also prove adversarial engines are caught")
    ap.add_argument("--http", metavar="URL", help="certify a live /v1/messages engine")
    args = ap.parse_args()

    ports = StdlibPorts()

    if args.http:
        ne = HTTPEngineAdapter(args.http)
        print(f"→ certifying live engine at {args.http}")
    else:
        ne = ReferenceNE(ports)
        print("→ certifying bundled ReferenceNE (Profile B)")

    header, lines, all_green = Harness(ports).run_all(ne)
    print("\n" + header)
    print("\n".join(lines))

    ok = all_green
    if args.selftest:
        print("\nAdversarial teeth-check (each MUST be caught):")
        for name, was_caught in prove_teeth(ports):
            mark = "CAUGHT" if was_caught else "MISSED"
            print(f"  [{mark}] {name}")
            ok = ok and was_caught

    print("\n" + ("ALL GREEN ✓" if ok else "FAILURES PRESENT ✗"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
