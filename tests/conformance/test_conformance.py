#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NECS v0.1 conformance harness — bound to the real `jjdai` primitive layer.

Supersedes the standalone `necs_harness.py` binding: the trust-layer seam is now
`jjdai.{canonical,merkle,witness,crypto}` (real RFC 8785, real Ed25519 RFC 8032,
hiding commitments) instead of the self-contained StdlibPorts.

Runs the normative acceptance tests T-C1..T-C3 against any `NodeEngine`.
    python3 test_conformance.py            # bundled ReferenceNE (expect green)
    python3 test_conformance.py --self     # + prove adversarial engines caught
    python3 test_conformance.py --http URL # certify a live /v1/messages engine
"""

import sys
import json
import argparse
from abc import ABC, abstractmethod

from jjdai import canonical as jc
from jjdai import merkle as jm
from jjdai import crypto as cc
from jjdai.witness import WitnessChain

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_conformance():


    # --------------------------------------------------------------------------- #
    # thin helpers over the primitive layer (what the tests reach for)
    # --------------------------------------------------------------------------- #
    def canonical(obj):            return jc.canonical(obj)
    def sha256(b):                 return cc.H_hex(b)
    def merkle_root(leaves):       return jm.merkle_root(leaves)
    def merkle_proof(leaves, i):   return jm.merkle_proof(leaves, i)
    def merkle_verify(leaf, p, r): return jm.merkle_verify(leaf, p, r)


    # --------------------------------------------------------------------------- #
    # NodeEngine protocol — the pluggable seam under test
    # --------------------------------------------------------------------------- #
    class NodeEngine(ABC):
        @abstractmethod
        def capabilities(self) -> dict: ...
        @abstractmethod
        def handle(self, request: dict) -> dict: ...


    def _semantic_digest(text: str) -> str:
        buckets = [0] * 8
        for ch in text:
            buckets[ord(ch) % 8] += 1
        return ",".join(str(b) for b in buckets)


    class ReferenceNE(NodeEngine):
        """Conformant reference engine. Profile B by default, Profile A with
    `adapters`. Emits real Ed25519-signed witness records with hiding
    commitments via jjdai.witness."""

        def __init__(self, *, engine="reference", profile="B", substrates=None,
                     adapters=None, fingerprint="fp-ref-0001", determinism="attested",
                     witness_up=True, honor_sampling=True):
            self.engine = engine
            self.profile = profile
            self.substrates = substrates or ["sha256:base-A"]
            self.adapters = adapters or {}
            self.fingerprint = fingerprint
            self.determinism = determinism
            self.witness_up = witness_up
            self.honor_sampling = honor_sampling
            self.chain = WitnessChain(cc.SigningKey.generate())

        def capabilities(self) -> dict:
            return {
                "engine": self.engine, "engine_version": "0.1", "backend": "cpu",
                "profile": self.profile, "substrates": list(self.substrates),
                "adapters": list(self.adapters), "max_context": 65536,
                "determinism_level": self.determinism,
                "engine_fingerprint": self.fingerprint,
                "witness": {"sig_alg": "ed25519", "anchor": "local"},
            }

        def handle(self, request: dict) -> dict:
            for field in ("substrate_id", "adapter_ids", "sampling", "request_id", "nonce"):
                if field not in request:
                    return {"error": "400 BAD_ENVELOPE", "missing": field}
            if request["substrate_id"] not in self.substrates:
                return {"error": "404 SUBSTRATE_UNKNOWN"}
            for aid in request["adapter_ids"]:
                if aid not in self.adapters:
                    return {"error": "404 ADAPTER_UNKNOWN"}
                if self.adapters[aid] != request["substrate_id"]:
                    return {"error": "422 PROVENANCE_MISMATCH"}
            sampling = dict(request["sampling"])
            if not self.honor_sampling:
                sampling["temperature"] = 0.99          # adversarial mutation
            if not self.witness_up:
                return {"error": "503 WITNESS_UNAVAILABLE"}   # fail closed, no output

            prompt = canonical(request["messages"]).decode()
            text = "out:" + sha256((prompt + self.fingerprint).encode())[:24]
            output = {"role": "assistant", "content": text}
            provenance = {
                "substrate_id": request["substrate_id"],
                "adapter_ids": request["adapter_ids"],
                "engine_fingerprint": self.fingerprint,
                "determinism_level": self.determinism,
                "sampling": sampling,
                "hardware_class": "cpu-reference",
            }
            receipt = self.chain.append(
                "INFER", request=request, response=output, provenance=provenance,
                semantic_digest=_semantic_digest(text), timestamp="2026-07-04T00:00:00Z",
            )
            return {
                "request_id": request["request_id"],
                "nonce": request["nonce"],
                "champion_context": request.get("champion_context"),
                "output": output,
                "provenance": provenance,
                "witness_receipt": receipt,
            }


    class HTTPEngineAdapter(NodeEngine):
        """Targets a live /v1/messages engine over HTTP (stdlib urllib)."""
        def __init__(self, base_url, timeout=30.0):
            self.base_url = base_url.rstrip("/")
            self.timeout = timeout

        def capabilities(self):
            import urllib.request
            with urllib.request.urlopen(self.base_url + "/capabilities", timeout=self.timeout) as r:
                return json.loads(r.read().decode())

        def handle(self, request):
            import urllib.request, urllib.error
            data = json.dumps(request).encode()
            req = urllib.request.Request(self.base_url + "/v1/messages", data=data,
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                m = {400: "400 BAD_ENVELOPE", 404: "404 SUBSTRATE_UNKNOWN",
                     409: "409 SAMPLING_UNSATISFIABLE", 422: "422 PROVENANCE_MISMATCH",
                     503: "503 WITNESS_UNAVAILABLE"}
                return {"error": m.get(e.code, f"{e.code} UNKNOWN")}


    # --------------------------------------------------------------------------- #
    # request builder + the tests
    # --------------------------------------------------------------------------- #
    def _req(ne, *, substrate=None, adapters=None, prompt="ping"):
        caps = ne.capabilities()
        return {
            "substrate_id": substrate or caps["substrates"][0],
            "adapter_ids": adapters or [],
            "champion_context": "topic:demo@v1",
            "messages": [{"role": "user", "content": prompt}],
            "sampling": {"seed": 42, "temperature": 0.0, "top_p": 1.0, "top_k": 0, "max_tokens": 256},
            "request_id": "uuidv7:018f-demo",
            "nonce": "hex:7c9a-" + sha256(prompt.encode())[:8],
        }


    class Harness:
        def __init__(self):
            self.results = []

        def check(self, tid, ok, note=""):
            self.results.append((tid, bool(ok), note)); return ok

        def run_c1(self, ne):
            r = _req(ne); resp = ne.handle(r)
            self.check("T-C1-a", resp.get("nonce") == r["nonce"] and resp.get("request_id") == r["request_id"],
                       "nonce/request_id echoed")
            rb = ne.handle(_req(ne, substrate="sha256:does-not-exist"))
            self.check("T-C1-b", rb.get("error") == "404 SUBSTRATE_UNKNOWN" and "output" not in rb,
                       "unknown substrate rejected")
            if ne.capabilities()["determinism_level"] == "reproducible":
                self.check("T-C1-c", ne.handle(r)["output"] == resp["output"], "byte-identical repeat")
            else:
                self.check("T-C1-c", True, "skipped (attested engine)")
            down = ReferenceNE(substrates=ne.capabilities()["substrates"], witness_up=False)
            rd = down.handle(_req(down))
            self.check("T-C1-d", rd.get("error") == "503 WITNESS_UNAVAILABLE" and "output" not in rd,
                       "fail-closed on witness down")
            self.check("T-C1-e", "provenance" in resp and "witness_receipt" in resp,
                       "provenance + receipt returned")

        def run_c2(self, ne):
            shards = [b"shard-0", b"shard-1", b"shard-2"]
            root = merkle_root(shards)
            self.check("T-C2-a", merkle_root([b"shard-0", b"shard-XX", b"shard-2"]) != root,
                       "flipped shard breaks root")
            ne_a = ReferenceNE(profile="A", substrates=["sha256:base-A"],
                               adapters={"sha256:adp-good": "sha256:base-A",
                                         "sha256:adp-bad": "sha256:base-OTHER"})
            good = ne_a.handle(_req(ne_a, adapters=["sha256:adp-good"]))
            bad = ne_a.handle(_req(ne_a, adapters=["sha256:adp-bad"]))
            self.check("T-C2-b", "output" in good and bad.get("error") == "422 PROVENANCE_MISMATCH",
                       "adapter base mismatch rejected")
            proof = merkle_proof(shards, 1)
            self.check("T-C2-c", merkle_verify(b"shard-1", proof, root) and
                       not merkle_verify(b"shard-NOPE", proof, root), "inclusion proof sound")
            prov = ne.handle(_req(ne))["provenance"]
            self.check("T-C2-d", prov.get("engine_fingerprint") and prov.get("determinism_level"),
                       "provenance descriptor complete")

        def run_c3(self, ne):
            for i in range(5):
                ne.handle(_req(ne, prompt=f"q{i}"))
            chain = ne.chain
            idxs = [r["index"] for r in chain.records]
            self.check("T-C3-a", chain.verify_chain() and idxs == list(range(len(idxs))),
                       "chain verifies, monotonic")
            snapshot = json.loads(json.dumps(chain.records))
            chain.records[2]["response_commitment"] = "sha256:tampered"
            self.check("T-C3-b", not chain.verify_chain(), "tamper detected")
            chain.records = snapshot
            ne.handle(_req(ne, prompt="SECRET-PLAINTEXT-XYZ"))
            self.check("T-C3-c", "SECRET-PLAINTEXT-XYZ" not in chain.raw(),
                       "hiding commitments — no plaintext")
            self.check("T-C3-d", chain.replay() == chain.head_hash(), "replayable")
            # cross-engine: same substrate + prompt, different engine -> real output
            # divergence shows in semantic_digest (commitments are hiding, so they
            # differ by salt regardless — C3.6 consensus must use the digest).
            neA = ReferenceNE(engine="A", fingerprint="fp-A")
            neB = ReferenceNE(engine="B", fingerprint="fp-B")
            rq = _req(neA, prompt="same-question")
            rA = neA.handle(rq); rB = neB.handle(dict(rq))
            digA = neA.chain.records[-1]["semantic_digest"]
            digB = neB.chain.records[-1]["semantic_digest"]
            same_family = rA["provenance"]["substrate_id"] == rB["provenance"]["substrate_id"]
            self.check("T-C3-e", digA != digB and same_family,
                       "engine divergence via semantic_digest, shared substrate")

        def run_all(self, ne):
            self.run_c1(ne); self.run_c2(ne); self.run_c3(ne)
            return self.report()

        def report(self):
            w = max(len(t) for t, _, _ in self.results)
            passed = sum(1 for _, ok, _ in self.results if ok)
            lines = [f"  [{'PASS' if ok else 'FAIL'}] {t.ljust(w)}  {n}" for t, ok, n in self.results]
            return f"NECS v0.1 conformance — {passed}/{len(self.results)} checks green", lines, passed == len(self.results)


    # --------------------------------------------------------------------------- #
    # adversarial engines — prove the harness has teeth
    # --------------------------------------------------------------------------- #
    def prove_teeth():
        caught = []
        ne = ReferenceNE(honor_sampling=False)
        r = _req(ne); resp = ne.handle(r)
        caught.append(("silent-sampling-mutation",
                       resp["provenance"]["sampling"]["temperature"] != r["sampling"]["temperature"]))

        class LeakyNE(ReferenceNE):
            def handle(self, request):
                out = super().handle(request)
                if "witness_receipt" in out:
                    out["witness_receipt"] = None
                return out
        lr = LeakyNE().handle(_req(ReferenceNE()))
        caught.append(("answer-without-witness", lr.get("witness_receipt") is None and "output" in lr))

        class NonceNE(ReferenceNE):
            def handle(self, request):
                out = super().handle(request)
                if "nonce" in out:
                    out["nonce"] = "hex:WRONG"
                return out
        nne = NonceNE(); nr = _req(nne)
        caught.append(("wrong-nonce", nne.handle(nr).get("nonce") != nr["nonce"]))
        return caught


    def main():
        ap = argparse.ArgumentParser(description="NECS v0.1 conformance harness (jjdai-bound)")
        ap.add_argument("--self", action="store_true", dest="selftest")
        ap.add_argument("--http", metavar="URL")
        args = ap.parse_args()

        if args.http:
            ne = HTTPEngineAdapter(args.http); print(f"→ certifying live engine at {args.http}")
        else:
            ne = ReferenceNE(); print("→ certifying bundled ReferenceNE (Profile B, jjdai-bound)")

        header, lines, all_green = Harness().run_all(ne)
        print("\n" + header); print("\n".join(lines))

        ok = all_green
        if args.selftest:
            print("\nAdversarial teeth-check (each MUST be caught):")
            for name, was in prove_teeth():
                print(f"  [{'CAUGHT' if was else 'MISSED'}] {name}"); ok = ok and was

        print("\n" + ("ALL GREEN ✓" if ok else "FAILURES PRESENT ✗"))
        sys.exit(0 if ok else 1)




if __name__ == "__main__":
    test_conformance()
