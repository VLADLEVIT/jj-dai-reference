"""Sanity tests for the reconstructed canary_store (eval/RAG separation guard)."""
import os, tempfile
from proto import Canary, sha256_text
from canary_store import CanaryStore, EvalRagOverlapError, _overlaps
from rag_store import RagStore

W = tempfile.mkdtemp(prefix="jjdai_cs_"); results = []
def check(name, ok):
    results.append(ok); print(f"  [{'PASS' if ok else 'FAIL'}] {name}")

ev, rg = os.path.join(W, "eval"), os.path.join(W, "rag")
store = CanaryStore(eval_dir=ev, rag_dir=rg)
c = Canary(id="add-2-3", stdin="2 3\n", expected_out_hash=sha256_text("5\n"))
store.add(c)
check("add/get round-trip", store.get("add-2-3") == c)
check("ids listing", store.ids() == ["add-2-3"])

try:
    CanaryStore(eval_dir=os.path.join(rg, "canaries"), rag_dir=rg)
    check("eval-inside-RAG rejected", False)
except EvalRagOverlapError:
    check("eval-inside-RAG rejected", True)
try:
    CanaryStore(eval_dir=ev, rag_dir=os.path.join(ev, "sub"))
    check("RAG-inside-eval rejected", False)
except EvalRagOverlapError:
    check("RAG-inside-eval rejected", True)
check("sibling prefix NOT a false positive",
      not _overlaps(os.path.join(W, "rag"), os.path.join(W, "rag_evals")))

try:
    RagStore(os.path.join(ev, "rag.db"), eval_dir=ev)
    check("RagStore mirror guard fires", False)
except EvalRagOverlapError:
    check("RagStore mirror guard fires", True)
os.makedirs(rg, exist_ok=True)
ok_store = RagStore(os.path.join(rg, "rag.db"), eval_dir=ev)  # separated: fine
check("separated RagStore constructs", ok_store is not None)

failed = results.count(False)
print(f"\nsummary: {len(results)-failed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
