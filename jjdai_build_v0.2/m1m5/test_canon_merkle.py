"""JJ DAI v0.1 — domain-Merkle + versioned-canonical acceptance tests.

Proves the deferred grafts:
  (a) domain separation: leaf and node digests live in disjoint domains, so an
      internal node can never masquerade as a leaf (second-preimage safety);
  (b) the scheme re-baselines vs the old plain-concat root (intended);
  (c) proofs remain sound (valid verifies; swapped leaf / root fails);
  (d) RFC 8785 canonical makes 1.0 and 1 hash identically (cross-node
      determinism) where the legacy compact-json does not;
  (e) canonical is versioned + backward-compatible: a legacy record and a jcs
      record coexist in one log and both verify via per-record dispatch.

Run:  python3 test_canon_merkle.py
"""
from __future__ import annotations
import os
import json
import tempfile

from proto import sha256_text
from rag_store import RagStore
from witness import WitnessLog, _rec_hash

WORK = tempfile.mkdtemp(prefix="jjdai_cm_")
results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


# ---- build a namespace with several chunks ----
rag = RagStore(os.path.join(WORK, "rag.db"))
cids = [rag.add("ns", "d", t)[0] for t in
        ["alpha", "beta", "gamma", "delta", "epsilon"]]
root = rag.merkle_root("ns")

# (a) domain disjointness: leaf-domain and node-domain never collide
v = sha256_text("anything")                     # a 32-byte value in hex
check("(a) leaf vs node domains are disjoint",
      RagStore._leaf(v) != RagStore._parent(v, v),
      "0x00-leaf can never equal 0x01-node")

# (b) re-baseline vs old plain-concat scheme
def plain_root(hashes):
    lvl = list(hashes)
    while len(lvl) > 1:
        if len(lvl) % 2:
            lvl.append(lvl[-1])
        lvl = [sha256_text(lvl[i] + lvl[i + 1]) for i in range(0, len(lvl), 2)]
    return lvl[0]
old = plain_root([h for _, h in rag._leaves("ns")])
check("(b) domain root differs from old plain root (re-baselined)", old != root,
      f"{old[:10]}… -> {root[:10]}…")

# (c) proof soundness
p = rag.prove("ns", cids[2])
check("(c1) valid proof verifies", RagStore.verify_proof(p) and p["scheme"] == "domain-v2")
bad_leaf = dict(p); bad_leaf["leaf"] = sha256_text("delta")   # a different chunk
check("(c2) swapped leaf fails", not RagStore.verify_proof(bad_leaf))
bad_root = dict(p); bad_root["root"] = sha256_text("x")
check("(c3) swapped root fails", not RagStore.verify_proof(bad_root))

# (d) canonical determinism: 1.0 == 1 under jcs, but not under legacy
check("(d1) jcs: 1.0 and 1 hash identically",
      _rec_hash({"t": 1.0}, "jcs") == _rec_hash({"t": 1}, "jcs"))
check("(d2) legacy: 1.0 and 1 hash differently (the bug jcs fixes)",
      _rec_hash({"t": 1.0}, "legacy") != _rec_hash({"t": 1}, "legacy"))

# (e) versioned canonical is backward-compatible in one log
LOG = os.path.join(WORK, "mixed.jsonl")
WitnessLog(LOG, canon="legacy").emit_infer({"i": 0})   # legacy record (no cv)
WitnessLog(LOG).emit_infer({"i": 1})                   # jcs record (cv=jcs)
recs = [json.loads(l) for l in open(LOG) if l.strip()]
check("(e1) legacy record carries no cv", "cv" not in recs[0])
check("(e2) jcs record self-labels cv=jcs", recs[1].get("cv") == "jcs")
n, _ = WitnessLog.verify_chain(LOG)
check("(e3) mixed-canon chain verifies via per-record dispatch", n == 2)

failed = sum(1 for _, ok in results if not ok)
print(f"\nsummary: {len(results) - failed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
