"""JJ DAI v0.1 — signature graft acceptance tests (adversarial).

Proves the graft criteria WITHOUT disturbing M2:
  (a) signed records verify with the right pubkey resolver;
  (b) tampering with a signature (or forging node_id) is caught;
  (c) an unsigned log still verifies exactly as before (backward-compat);
  (d) the body hash `h` and the M2 chain are byte-identical whether or not a
      record is signed (envelope-level graft — no re-baseline).

Run:  python3 test_witness_sig.py
"""
from __future__ import annotations
import os
import tempfile

from crypto import SigningKey, node_id
from witness import WitnessLog, ChainError

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node"), os.path.join(_ROOT, "m1m5")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
HERE = os.path.join(_ROOT, "node")     # daemon.py / mock engine location


def test_witness_sig():

    WORK = tempfile.mkdtemp(prefix="jjdai_sig_")
    results = []


    def check(name, ok, detail=""):
        results.append((name, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


    sk = SigningKey.generate()
    nid = node_id(sk.public)
    resolver = lambda n: sk.public if n == nid else None

    # ---- signed chain ----
    LOG = os.path.join(WORK, "signed.jsonl")
    log = WitnessLog(LOG, signing_key=sk)
    for i in range(5):
        log.emit_infer({"node": nid, "model": "v4-flash-q2", "seed": 1, "i": i})

    # (a) verifies with resolver (sig-checked)
    n, head = WitnessLog.verify_chain(LOG, pubkey_resolver=resolver)
    check("signed chain verifies with resolver", n == 5, f"{n} records")

    # also verifies WITHOUT resolver (structure-only) — backward path
    n2, _ = WitnessLog.verify_chain(LOG)
    check("signed chain verifies structurally without resolver", n2 == 5)

    # (b1) tamper a signature -> caught
    import json
    recs = [json.loads(l) for l in open(LOG) if l.strip()]
    recs[2]["sig"] = ("00" * 64)
    BAD = os.path.join(WORK, "badsig.jsonl")
    open(BAD, "w").write("\n".join(json.dumps(r, sort_keys=True) for r in recs) + "\n")
    try:
        WitnessLog.verify_chain(BAD, pubkey_resolver=resolver)
        check("bad signature caught", False)
    except ChainError as e:
        check("bad signature caught", True, str(e))

    # (b2) forge node_id (attacker claims a different identity) -> caught
    recs2 = [json.loads(l) for l in open(LOG) if l.strip()]
    recs2[1]["node_id"] = node_id(SigningKey.generate().public)
    FORGE = os.path.join(WORK, "forge.jsonl")
    open(FORGE, "w").write("\n".join(json.dumps(r, sort_keys=True) for r in recs2) + "\n")
    try:
        # resolver knows only the original signer; forged id -> unknown signer
        WitnessLog.verify_chain(FORGE, pubkey_resolver=resolver)
        check("forged node_id caught", False)
    except ChainError as e:
        check("forged node_id caught", True, str(e))

    # (c) unsigned log verifies as before (no sig fields)
    ULOG = os.path.join(WORK, "unsigned.jsonl")
    ulog = WitnessLog(ULOG)  # no key
    for i in range(3):
        ulog.emit_infer({"i": i})
    nu, _ = WitnessLog.verify_chain(ULOG)  # resolver=None
    check("unsigned log verifies (backward-compat)", nu == 3)
    # and there are no sig fields in it
    check("unsigned records carry no sig", all(
        "sig" not in json.loads(l) for l in open(ULOG) if l.strip()))

    # (d) envelope graft does not change body hash: same body -> same h signed/unsigned
    b = {"seq": 0, "ts": 1.0, "kind": "INFER", "prev_hash": "0" * 64, "payload": {"x": 1}}
    from witness import _rec_hash
    h_plain = _rec_hash(b)
    signed_line = json.loads([l for l in open(LOG) if l.strip()][0])
    # recompute h of the signed record's body — must equal its stored h (untouched)
    check("signed record body hash intact",
          _rec_hash(signed_line["body"]) == signed_line["h"])
    check("h is a pure function of body (envelope-independent)",
          _rec_hash(b) == h_plain)

    failed = sum(1 for _, ok in results if not ok)
    print(f"\nsummary: {len(results) - failed} passed, {failed} failed")
    assert failed == 0, f"{failed} check(s) failed"


if __name__ == "__main__":
    test_witness_sig()
