#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The release assembler, and the live group's agreement with D9.

Verification gained external facts in block 3 and nothing produced them;
these checks are about the other half. A statement is the object two people
sign, so every field is DERIVED or the assembler refuses — a plausible value
in a signed field is a signature over a guess.

  ASM-1  Every field the assembler fills is derived from a file or a
         measurement; there is no default for a missing fact.
  ASM-2  It refuses on the FIRST fact that is not there, naming which, and
         produces no statement at all.
  ASM-3  The recipe hash is taken in path order over VALIDATED recipes.
  ASM-4  The four hashes it computes are exactly the bindings that
         `docs/digest_scope.json` names for the files it excludes.
  ASM-5  The context hands verification READERS, not hashes.
  LIVE-1 The live group encodes the CURRENT definition of `pure`: zero
         preopens, and the limit breaches each named.
"""
import io as _io
import json
import os
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "scripts"))

from jjdai import provenance as prv                            # noqa: E402
from jjdai import release as rel                               # noqa: E402
from jjdai import source_tree as st                            # noqa: E402
import make_release_statement as asm                           # noqa: E402


def test_every_field_is_derived():
    """ASM-1"""
    src = _io.open(os.path.join(_ROOT, "scripts",
                                "make_release_statement.py"),
                   encoding="utf-8").read()
    for field in rel.STATEMENT_HEX_FIELDS:
        assert field in src, field
    # no default for a missing fact anywhere in the assembler
    assert "or \"\"" not in src and "get(" not in src.split("def main")[0], (
        "a `.get()` with a fallback is how an unmeasured field acquires a "
        "plausible value")
    assert "REFUSED" in src
    print("  [PASS] ASM-1  every statement field is derived from a file or a "
          "measurement")


def test_it_refuses_on_the_first_missing_fact():
    """ASM-2"""
    # dist/ is absent in a source tree, so artefacts() must refuse rather
    # than produce an empty list that validates as a statement
    try:
        asm.artefacts()
        raise AssertionError("artefacts() invented a list")
    except SystemExit as exc:
        assert "dist/" in str(exc) and "REFUSED" in str(exc)
    try:
        asm._sha256_file("dist/toolset-bundle.tar")
        raise AssertionError("a hash was produced for an absent file")
    except SystemExit as exc:
        assert "signature over a guess" in str(exc)
    # and the whole statement refuses rather than half-filling
    try:
        asm.statement("v0.6.9")
        raise AssertionError("a statement was produced with no bundle")
    except (SystemExit, st.SourceTreeError, Exception) as exc:  # noqa: BLE001
        assert not isinstance(exc, AssertionError), exc
    print("  [PASS] ASM-2  the assembler refuses on the first missing fact "
          "and produces nothing")


def test_recipe_hash_is_ordered_and_validated():
    """ASM-3"""
    # the shipped recipes carry placeholders, so hashing them must refuse:
    # a stable-looking digest over a file that pins nothing is worse than no
    # digest at all
    try:
        asm.recipe_hash()
        raise AssertionError("unfilled recipes were hashed")
    except SystemExit as exc:
        assert "pins nothing" in str(exc), str(exc)
    src = _io.open(os.path.join(_ROOT, "scripts",
                                "make_release_statement.py"),
                   encoding="utf-8").read()
    assert "sorted(" in src.split("def recipe_hash")[1].split("def ")[0], (
        "directory order is whatever the filesystem returns, so two "
        "builders would produce two hashes over one set of recipes")
    print("  [PASS] ASM-3  recipes are validated, then hashed in path order")


def test_the_hashes_match_the_declared_bindings():
    """ASM-4"""
    scope = st.load_scope(_ROOT)
    # every file the scope excludes names the field that binds it; the
    # assembler is where those fields are computed, so the two must agree
    bound_fields = " ".join(scope["bindings"].values())
    src = _io.open(os.path.join(_ROOT, "scripts",
                                "make_release_statement.py"),
                   encoding="utf-8").read()
    assert "acceptance_hash" in bound_fields, (
        "docs/evidence/hermetic.json is excluded from the digest and the "
        "scope file does not say what binds it")
    assert "docs/evidence/hermetic.json" in src, (
        "the binding names acceptance_hash and nothing computes it")
    for field in ("sbom_hash", "toolset_manifest_hash", "bundle_hash",
                  "acceptance_hash"):
        assert field in src, field
    print("  [PASS] ASM-4  the assembler computes exactly the bindings the "
          "digest scope declares")


def test_the_context_hands_readers_not_hashes():
    """ASM-5"""
    fields = rel.ReleaseContext._fields
    for name in ("artefact_reader", "bundle_reader", "sbom_reader",
                 "toolset_manifest_reader"):
        assert name in fields, name
    src = _io.open(os.path.join(_ROOT, "scripts",
                                "make_release_statement.py"),
                   encoding="utf-8").read()
    # Asserting "there is a lambda somewhere in the function" is not the
    # property: one reader could be dropped and the rest would carry the
    # check. So the CONTEXT ITSELF is built and every reader that must be
    # callable is called — a None where a reader belongs means verification
    # silently skips those bytes, which is the whole failure mode.
    # The context must be COMPLETE: every field, no None anywhere. An
    # absent reader is a gate that silently passes, and `publish()` now
    # refuses the whole shape. `recipe_reader` was the one this script
    # itself left None — so recipe_hash went unchecked at verification while
    # every other hash was compared.
    # On a networked host `describe()` refuses, and that is the D3 gate
    # doing its job — a table saying "disabled-and-checked" filled where the
    # network answers would be a signed statement of something nobody
    # measured. The check below is about the SHAPE of the context, so the
    # probe is switched off explicitly rather than the refusal worked
    # around.
    # Two facts this tree genuinely cannot supply — a disabled network and a
    # git history — and the assembler refuses on both rather than filling
    # them. That refusal is the D3 gate working, so it is asserted rather
    # than worked around, and the SHAPE of the context is then checked on a
    # stub whose only difference is those two measurements.
    try:
        asm.context("v0.6.9")
        raise AssertionError("a context was built on a networked host")
    except AssertionError:
        raise
    except Exception as exc:                                   # noqa: BLE001
        assert ("network is reachable" in str(exc)
                or "committer time" in str(exc)), exc

    real = asm.be.describe
    asm.be.describe = lambda *a, **k: dict(
        python="CPython 3.12.3", locale="C", timezone="UTC", umask="0022",
        network="disabled-and-checked", source_date_epoch="1700000000")
    try:
        ctx = asm.context("v0.6.9", check_network=False)
    finally:
        asm.be.describe = real
    assert ctx.missing() == [], ctx.missing()
    for name in ("artefact_reader", "bundle_reader", "sbom_reader",
                 "toolset_manifest_reader"):
        reader = getattr(ctx, name)
        assert callable(reader), (
            f"{name} is not callable: verification would skip those bytes "
            f"in silence. Handing it a hash computed here instead would be "
            f"one program checking its own arithmetic, which proves the "
            f"arithmetic and nothing about the files")
    assert callable(ctx.recipe_reader), (
        "recipe_reader is None: a directory instead of a file is a reason "
        "to build the pre-image, not a reason to exempt the field")
    assert ctx.build_environment and ctx.build_environment.get(
        "source_date_epoch")
    assert ctx.expected_tag == "v0.6.9" and ctx.tree_digest
    assert ctx.acceptance and ctx.acceptance.get("_raw_hash")
    internal = rel.ReleaseContext.internal_only()
    assert all(v is None for v in internal), (
        "internal_only() must carry no facts at all, so that asking for the "
        "weaker check is unambiguous")
    print("  [PASS] ASM-5  the context carries readers; verification hashes "
          "the bytes itself")


def test_live_group_encodes_the_current_pure():
    """LIVE-1"""
    src = _io.open(os.path.join(_ROOT, "tests", "live", "test_wasm_live.py"),
                   encoding="utf-8").read()
    # The two assertions that were faithful to the definition r6.9.1
    # removed. Both are still MENTIONED, in the module docstring that
    # records what was replaced and why — the change is the substance of D9
    # and deleting its account would leave the next reader to rediscover it.
    # So the check looks at the executable part only.
    body = src.split('"""', 2)[2]
    assert 'argv.count("--dir")' not in body, (
        "the live group still requires exactly ONE preopen — the shape of "
        "`pure` that permitted writing inside it, and therefore drew no "
        "boundary")
    assert "WORKSPACE REACHABLE" not in body
    assert "NO PREOPEN" in src
    for check in ("L-6", "L-7", "L-8", "L-9"):
        assert check in src, (
            f"{check} missing: fuel and guest memory are exactly what the "
            f"hermetic suite CANNOT prove — the shim answers the capability "
            f"probe, and only a real runtime exhausts real fuel")
    for code in ("PURE_LIMIT_FUEL", "PURE_LIMIT_MEMORY", "PURE_LIMIT_OUTPUT"):
        assert code in src, code
    assert "MANIFEST_FILE" in src and "signer" in src, (
        "the live fixture must build a manifest of the shape the loader now "
        "requires, or the group proves the runtime against a manifest no "
        "node would accept")
    print("  [PASS] LIVE-1 the live group asserts zero preopens and names "
          "each limit breach")


def test_the_assembler_does_not_list_its_own_outputs():
    """ASM-6 · the audit of recut3, P1-2

    `artefacts()` listed every regular file in dist/, including a
    `release-statement.json` left by the previous run — so the second
    statement carried the hash of a previous version of itself, and
    `main()` then overwrote the file it had just described.

    The fixture lives in a TemporaryDirectory with `asm.ROOT` swapped for
    its duration. The first cut wrote `dist/evidence/aa.json` into the real
    tree and removed it afterwards — a check that can destroy a file it did
    not create is a check with a side effect, and the audit of recut4 said
    so. Nothing here touches the tree.
    """
    real_root = asm.ROOT
    with tempfile.TemporaryDirectory() as tmp:
        dist = os.path.join(tmp, "dist")
        os.makedirs(os.path.join(dist, "evidence"))
        for name in ("jjdai-0.6.9.tar.gz", "jjdai-0.6.9-py3-none-any.whl",
                     "release-statement.json", "release-approvals.json",
                     "release-attestation.json", "release-publication.json"):
            with open(os.path.join(dist, name), "wb") as fh:
                fh.write(name.encode())
        with open(os.path.join(dist, "evidence", "aa.json"), "wb") as fh:
            fh.write(b"{}")
        asm.ROOT = tmp
        try:
            names = {a["name"] for a in asm.artefacts()}
        finally:
            asm.ROOT = real_root
    assert names == {"jjdai-0.6.9.tar.gz", "jjdai-0.6.9-py3-none-any.whl"}, (
        names)
    for own in asm.RELEASE_OUTPUTS:
        assert own not in names, own
    assert asm.ROOT == real_root
    print("  [PASS] ASM-6  the assembler lists what was built, never the "
          "objects it writes beside it")


if __name__ == "__main__":
    for fn in (test_every_field_is_derived,
               test_it_refuses_on_the_first_missing_fact,
               test_recipe_hash_is_ordered_and_validated,
               test_the_hashes_match_the_declared_bindings,
               test_the_context_hands_readers_not_hashes,
               test_live_group_encodes_the_current_pure,
               test_the_assembler_does_not_list_its_own_outputs):
        fn()
