#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Assemble a `ReleaseStatement` from the tree, and the context that checks it.

    python3 scripts/make_release_statement.py --version v0.6.9

Until now every field of a statement could be typed by hand. That is the
gap the audit named as P0-4 of block 3 from the other side: verification
gained external facts, and nothing produced them. This script is where the
facts come from, and it will REFUSE rather than fill a field with something
plausible — a statement is the object two people sign, and a field nobody
measured is a signature over a guess.

Each value is derived, never asserted:

    tree_digest             jjdai.source-tree/v2 over the committed tree
    acceptance_hash         sha256 of docs/evidence/hermetic.json AS BYTES
    sbom_hash               sha256 of docs/sbom.cdx.json
    toolset_manifest_hash   sha256 of the signed toolset manifest
    recipe_hash             sha256 over the recipe files, in path order
    bundle_hash             sha256 of the release bundle
    artefacts               name, sha256 and length of every file in dist/
    build_environment       measured by jjdai.build_env

The four hashes above are exactly the bindings `docs/digest_scope.json`
names for the files it excludes from the digest. That is not a coincidence
and is the reason this script and that file must agree: an exclusion is
always matched by a binding somewhere else, and this is the somewhere else.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from jjdai import build_env as be                              # noqa: E402
from jjdai import provenance as prv                            # noqa: E402
from jjdai import release as rel                               # noqa: E402
from jjdai import source_tree as st                            # noqa: E402
from kernel import toolset as ts                               # noqa: E402

BUNDLE = os.path.join("dist", "toolset-bundle.tar")
RECIPE_DIR = os.path.join("deploy", "wasm-toolset", "recipe")


class MissingFact(SystemExit):
    """A field could not be derived, so no statement is produced."""


def _sha256_file(rel_path: str) -> str:
    path = os.path.join(ROOT, *rel_path.split("/"))
    if not os.path.exists(path):
        raise MissingFact(
            f"REFUSED: {rel_path} is absent, so its hash cannot be measured. "
            f"A statement with a plausible value in this field is a "
            f"signature over a guess.")
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def recipe_hash() -> str:
    """One hash over all recipes, in path order.

    Path order rather than directory order: the latter is whatever the
    filesystem returns, and two builders would then produce two hashes over
    one set of recipes. Each recipe is VALIDATED first — hashing an unfilled
    recipe would pin a file that pins nothing.
    """
    directory = os.path.join(ROOT, RECIPE_DIR)
    names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    if not names:
        raise MissingFact(f"REFUSED: no recipes under {RECIPE_DIR}")
    for name in names:
        try:
            ts.load_recipe(os.path.join(directory, name))
        except ts.ToolsetError as exc:
            raise MissingFact(
                f"REFUSED: {RECIPE_DIR}/{name} does not validate "
                f"[{exc.code}] {exc}\n"
                f"The pins are filled on a build host. Hashing an unfilled "
                f"recipe would put a stable-looking digest over a file that "
                f"pins nothing.") from None
    return hashlib.sha256(_recipe_stream()).hexdigest()


def _recipe_preimage() -> bytes:
    """Bytes whose sha256 IS `recipe_hash()`.

    The recipe hash is a digest over a set of files, so there is no single
    file to hand a reader. Rather than exempt it from verification — the
    exemption that let it go unchecked — the pre-image is reconstructed the
    same way the hash is built, and re-validated on the way. If a recipe has
    changed since the statement was made, this refuses here.
    """
    import binascii
    return binascii.unhexlify(recipe_hash())[:0] + _recipe_stream()


def _recipe_stream() -> bytes:
    directory = os.path.join(ROOT, RECIPE_DIR)
    names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    out = bytearray()
    for name in names:
        path = os.path.join(directory, name)
        ts.load_recipe(path)
        out += name.encode("utf-8") + b"\0"
        with open(path, "rb") as f:
            out += hashlib.sha256(f.read()).digest()
    return bytes(out)


#: What this script and the ceremony WRITE into dist/, and therefore what
#: `artefacts()` must not read back as a thing that was built. Named as a
#: set rather than filtered by extension: a future `.tar.gz` bundle of the
#: attestation would slip past an extension rule and not past this one.
RELEASE_OUTPUTS = frozenset({
    "release-statement.json", "release-approvals.json",
    "release-attestation.json", "release-publication.json",
})


def artefacts() -> list:
    dist = os.path.join(ROOT, "dist")
    if not os.path.isdir(dist):
        raise MissingFact(
            "REFUSED: dist/ is absent. Run scripts/build_release.py --build "
            "first; a statement listing artefacts nobody built names files "
            "that do not exist.")
    out = []
    for name in sorted(os.listdir(dist)):
        path = os.path.join(dist, name)
        if not os.path.isfile(path):
            continue
        if name in RELEASE_OUTPUTS:
            # NOT AN ARTEFACT — an output of this very script. The audit of
            # recut3 ran the assembler twice and the second statement
            # listed the first one as an artefact, so a statement carried
            # the hash of a previous version of itself, and `main()` then
            # overwrote the file it had just described. The release objects
            # live in dist/ beside the wheels; they are not the wheels.
            continue
        with open(path, "rb") as f:
            body = f.read()
        out.append({"name": name,
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "length": len(body)})
    if not out:
        raise MissingFact("REFUSED: dist/ holds no artefacts")
    return out


def statement(version: str, *, scope: str = prv.SCOPE_SAME_HOST_CLASS,
              control: dict = None, check_network: bool = True) -> dict:
    """Build the statement, refusing on the first fact that is not there."""
    digest, source, _count = st.digest(ROOT, require_clean=True)
    if source != st.SOURCE_GIT:
        raise MissingFact(
            f"REFUSED: the digest came from {source!r}. A release addresses "
            f"the COMMITTED tree of the tag target (ADR-022 D11); a working "
            f"copy can hold what no commit contains.")
    doc = {
        "schema": prv.SCHEMA_RELEASE_STATEMENT,
        "version": version,
        "tree_digest": digest,
        "tree_digest_algo": prv.TREE_DIGEST_ALGO,
        "artefacts": artefacts(),
        "bundle_hash": _sha256_file(BUNDLE),
        "toolset_manifest_hash": _sha256_file(
            f"deploy/wasm-toolset/{ts.MANIFEST_FILE}"),
        "sbom_hash": _sha256_file("docs/sbom.cdx.json"),
        "acceptance_hash": _sha256_file("docs/evidence/hermetic.json"),
        "recipe_hash": recipe_hash(),
        "build_environment": be.describe(ROOT,
                                        check_network=check_network),
        "reproducibility_scope": scope,
        "control": control or {"signature_threshold": 2, "distinct_keys": 2,
                               "distinct_devices": 2,
                               "distinct_principals": 1,
                               "device_binding": prv.DEVICE_BINDING_ASSERTED},
    }
    return rel.validate_statement(doc)


def context(version: str, *, check_network: bool = True):
    """The external facts a verifier compares the statement against.

    Readers rather than values: verification must hash the bytes ITSELF.
    Handing it a hash computed here would mean one program checking its own
    arithmetic, which proves the arithmetic and nothing about the files.
    """
    acceptance = json.load(io.open(
        os.path.join(ROOT, "docs", "evidence", "hermetic.json"),
        encoding="utf-8"))
    acceptance["_raw_hash"] = _sha256_file("docs/evidence/hermetic.json")

    def read(rel_path):
        with open(os.path.join(ROOT, *rel_path.split("/")), "rb") as f:
            return f.read()

    return rel.ReleaseContext(
        expected_tag=version,
        tree_digest=st.digest(ROOT, require_clean=True)[0],
        acceptance=acceptance,
        build_environment=be.describe(ROOT, check_network=check_network),
        artefact_reader=lambda name: read(f"dist/{name}"),
        bundle_reader=lambda: read(BUNDLE),
        # A reader, not None. The first cut passed None here on the reasoning
        # that recipes are a directory rather than a file — and the effect
        # was that `recipe_hash` went unchecked at verification while every
        # other hash was compared. `recipe_hash()` recomputes the same
        # ordered digest over the same files, so the verifier compares the
        # statement against the recipes rather than against this script's
        # memory of them.
        recipe_reader=lambda: _recipe_preimage(),
        sbom_reader=lambda: read("docs/sbom.cdx.json"),
        toolset_manifest_reader=lambda: read(
            f"deploy/wasm-toolset/{ts.MANIFEST_FILE}"),
        # Readers, not None, for the same reason `recipe_reader` is one. The
        # rebuild evidence a verifier names is a `jjdai.rebuild-evidence/v1`
        # (ADR-022 rev 2.3) — his own signed record of his own run, never a
        # statement — looked up by digest under dist/evidence/; and the
        # debt ledger is read from the tree being released, which is the
        # file the gates project.
        evidence_reader=lambda digest: _evidence_bytes(digest),
        debt_reader=lambda: json.load(io.open(
            os.path.join(ROOT, "docs", "architecture_status.json"),
            encoding="utf-8")),
        # rev 2.4: the signed body behind a RELEASE_REVOKED record, looked
        # up by the record's provenance_hash under dist/revocations/. A
        # record found in the chain whose body is absent here REFUSES the
        # release rather than lifting the revocation.
        revocation_reader=lambda digest: _read_named(REVOCATION_DIR, digest))


#: WHERE A VERIFIER'S REBUILD STATEMENT IS LOOKED FOR. One directory, named
#: rather than searched: `dist/evidence/<sha256>.json`. The verifier hands
#: over the bytes his own run produced, they are stored under their digest,
#: and the approval names that digest. Nothing here mints evidence — a
#: builder who could produce the verifier's object would be both roles.
EVIDENCE_DIR = os.path.join("dist", "evidence")
REVOCATION_DIR = os.path.join("dist", "revocations")


def _read_named(directory: str, digest: str) -> bytes:
    path = os.path.join(ROOT, directory, f"{digest}.json")
    if not os.path.exists(path):
        return b""
    with open(path, "rb") as fh:
        return fh.read()


def _evidence_bytes(digest: str) -> bytes:
    return _read_named(EVIDENCE_DIR, digest)


def main(argv) -> int:
    if "--version" not in argv:
        print(__doc__)
        return 2
    version = argv[argv.index("--version") + 1]
    doc = statement(version)
    out = os.path.join(ROOT, "dist", "release-statement.json")
    io.open(out, "w", encoding="utf-8", newline="\n").write(
        json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"  wrote {os.path.relpath(out, ROOT)}")
    print(f"  statement_hash {rel.statement_hash(doc)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (st.SourceTreeError, be.BuildEnvError, rel.ReleaseError) as exc:
        print(f"REFUSED [{exc.code}] {exc}")
        raise SystemExit(1) from None
