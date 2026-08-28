#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/gen_sbom.py — software bill of materials, generated from the tree
=========================================================================

    python3 scripts/gen_sbom.py            # write docs/sbom.cdx.json
    python3 scripts/gen_sbom.py --check    # regenerate and DIFF (CI mode)

WHAT THIS IS AND IS NOT
-----------------------
This produces a CycloneDX 1.5 document describing what a consumer of this
repository actually receives. It is one of the four parts of the supply-chain
debt named in the roadmap; the other three — reproducible build, signed
artefacts and two-person release approval — are **not** closed by this file
and are not claimed here. An SBOM says *what is in the box*. It says nothing
about who sealed it.

WHY GENERATED RATHER THAN WRITTEN
---------------------------------
A hand-written SBOM is accurate exactly once. This project has already been
bitten twice by a hand-maintained list that drifted from the tree: the
`packages = [...]` list in `pyproject.toml` silently dropped
`jjdai.adapters` from every wheel, and the CHANGELOG attribution map pointed
at test IDs a reader could not find. `--check` in CI is what stops the third
instance: it fails if the committed document does not match what the tree
generates right now.

DETERMINISM
-----------
Two runs over the same bytes must produce the same document, or `--check` is
noise. Everything variable is therefore excluded or derived:

  * no timestamp, no serial number, no tool version string;
  * components sorted by name, files sorted by path;
  * hashes over raw bytes, never over decoded text.

The one number that is allowed to move is the version in `pyproject.toml`.

SCOPE OF THE FILE INVENTORY
---------------------------
The same set `source_digest()` hashes — the shipped tree minus the four
badge-bearing surfaces that would prevent convergence. This is deliberate:
an SBOM covering a different set of files from the tree digest would let a
file be attested by one and unattested by the other, and nobody would notice
which.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "docs", "sbom.cdx.json")

sys.path.insert(0, os.path.join(ROOT, "scripts"))
from run_acceptance import digest_files  # noqa: E402

#: This document is INSIDE the set it describes, and that is a deliberate
#: choice with one consequence to handle. Excluding it from `source_digest()`
#: — the way README and the generated surfaces are excluded — would mean a
#: tampered SBOM leaves `tree_digest` unchanged, which is precisely the hole
#: the exclusion list is otherwise careful about. So it stays hashed.
#:
#: What it cannot do is contain its own hash. Writing the file changes the
#: file, so a self-referential inventory would never converge — the same
#: convergence problem the acceptance badge already has, solved the other way
#: round. This generator therefore describes the tree MINUS itself, and says
#: so in a property, so a reader knows which set the numbers refer to.
_SELF = "docs/sbom.cdx.json"


def _inventory_paths() -> list:
    return [p for p in digest_files() if p != _SELF]


def _supply_chain_open():
    """Open supply-chain positions, PROJECTED from the debt ledger.

    ADR-022/D14 makes `architecture_status.json :: release_debt` the single
    source of truth. Status is a projection over append-only events, so a
    position that was cancelled (`two-person-approval`) leaves the list
    without leaving the record: the ledger still carries why it went and
    which decision took it.

    CLA is excluded deliberately. It blocks acceptance of an outside
    contribution, never a release tag, and listing it here would put a
    governance question inside a provenance claim.
    """

    path = os.path.join(ROOT, "docs", "architecture_status.json")
    with io.open(path, encoding="utf-8") as fh:
        ledger = json.load(fh)["release_debt"]
    projection = ledger["projection"]
    status, blocks = {}, {}
    for row in ledger["events"]:               # append-only: last write wins
        status[row["id"]] = projection[row["event"]]
        if "blocks" in row:
            blocks[row["id"]] = row["blocks"]
    return sorted(
        ident for ident, state in status.items()
        if state == "open"
        and blocks.get(ident) != "acceptance-of-outside-contribution")


def _inventory_digest() -> str:
    """Content address over the inventoried set — the tree minus this file.

    Same construction as `run_acceptance.source_digest()`: raw bytes, path
    included, sorted. Deliberately NOT the same VALUE, and named differently
    so the two are never mistaken for each other.
    """
    h = hashlib.sha256()
    for rel in _inventory_paths():
        f = os.path.join(ROOT, rel)
        if not os.path.isfile(f):
            continue
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        with open(f, "rb") as fh:
            h.update(hashlib.sha256(fh.read()).digest())
    return h.hexdigest()

#: The runtime core takes no third-party dependency and this generator does
#: not invent one. Anything that appears in `components` below is either
#: this project or a declared TOOLCHAIN pin.
_REQ = os.path.join(ROOT, "requirements-dev.txt")

_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)==(?P<ver>[^\s;]+)\s*"
    r"(?:;\s*(?P<marker>[^\\\n]+?)\s*)?\\?\s*$"
)
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def _project_version() -> str:
    txt = io.open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    m = re.search(r'^version\s*=\s*"([^"]+)"', txt, re.M)
    if not m:
        raise SystemExit("gen_sbom: no version in pyproject.toml")
    return m.group(1)


def _toolchain() -> list:
    """Parse the hash-pinned toolchain file into CycloneDX components.

    Parsed, not duplicated. A second copy of these versions in this file
    would be a second answer to the same question, and the two would drift
    the first time somebody bumped one of them.
    """
    if not os.path.exists(_REQ):
        return []
    out, cur = [], None
    for raw in io.open(_REQ, encoding="utf-8"):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _PIN.match(line.strip())
        if m:
            cur = {
                "type": "library",
                "bom-ref": "pkg:pypi/%s@%s" % (m.group("name").lower(),
                                               m.group("ver")),
                "name": m.group("name"),
                "version": m.group("ver"),
                "purl": "pkg:pypi/%s@%s" % (m.group("name").lower(),
                                            m.group("ver")),
                "scope": "excluded",  # build/test only, never shipped
                "hashes": [],
            }
            if m.group("marker"):
                cur["description"] = "toolchain, applies when: %s" % m.group("marker")
            out.append(cur)
        for h in _HASH.findall(line):
            if cur is not None:
                cur["hashes"].append({"alg": "SHA-256", "content": h})
    for c in out:
        if not c["hashes"]:
            # ValueError, not SystemExit. This module is imported by
            # tests/unit/test_tree_is_its_own_plan.py, and a SystemExit
            # raised during import kills the acceptance RUNNER rather than
            # failing one check — found in the mutation round for PIN-1,
            # where the deliberate defect took the whole unit module down
            # instead of producing the one red the mutation was testing for.
            # A library refuses by raising; only main() may exit.
            raise ValueError("gen_sbom: %s is pinned by version but not by "
                             "hash — refusing to record an unverifiable "
                             "component" % c["name"])
    return sorted(out, key=lambda c: c["name"].lower())


_ACTION = re.compile(r"uses:\s*([\w.-]+/[\w.-]+)@([0-9a-f]{40})"
                     r"(?:\s*#\s*(\S+))?")


def _actions() -> list:
    """The workflow's GitHub Actions, read out of the workflow.

    They are as much an input to a CI result as pytest is, and an audit
    round pointed out that an SBOM listing only the Python packages reads
    as the whole dependency surface when it is not. Parsed, never
    duplicated: a second copy of these digests here would drift from the
    workflow the first time one was bumped.

    Only SHA-pinned entries are recognised. A `@v4` would not match the
    pattern and would fall through to the completeness check below, which
    refuses rather than recording an unpinned component — the same rule
    already applied to an unhashed Python pin.
    """
    wf = os.path.join(ROOT, ".github", "workflows", "ci.yml")
    if not os.path.exists(wf):
        return []
    text = io.open(wf, encoding="utf-8").read()
    used = len(re.findall(r"uses:", text))
    out = []
    for name, sha, note in _ACTION.findall(text):
        c = {"type": "library",
             "bom-ref": "pkg:github/%s@%s" % (name, sha),
             "name": name,
             "version": sha,
             "purl": "pkg:github/%s@%s" % (name, sha),
             "scope": "excluded",
             "hashes": [{"alg": "SHA-1", "content": sha}]}
        if note:
            c["description"] = "GitHub Action, pinned by commit; %s at pin time" % note
        out.append(c)
    if len(out) != used:
        raise ValueError(
            "gen_sbom: the workflow has %d `uses:` entries and %d are pinned "
            "by commit SHA. An action on a moving tag is not a component this "
            "bill of materials can honestly record." % (used, len(out)))
    return sorted(out, key=lambda c: c["name"])


def _build_backend() -> list:
    """`setuptools` from [build-system].requires — version-pinned only.

    Recorded WITH a property saying it carries no hash, rather than left
    out. Omitting it would make the SBOM silent about the one build input
    that is still resolved by name, and silence in an inventory reads as
    absence.
    """
    txt = io.open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    m = re.search(r'requires\s*=\s*\[\s*"setuptools==([^"]+)"', txt)
    if not m:
        raise ValueError("gen_sbom: [build-system].requires does not pin "
                         "setuptools to an exact version")
    ver = m.group(1)
    return [{"type": "library",
             "bom-ref": "pkg:pypi/setuptools@%s" % ver,
             "name": "setuptools",
             "version": ver,
             "purl": "pkg:pypi/setuptools@%s" % ver,
             "scope": "excluded",
             "description": "PEP 517 build backend",
             "properties": [{"name": "jjdai:pin-strength",
                             "value": "version-only — PEP 517 `requires` has "
                                      "no field for a hash"}],
             "hashes": []}]


def _files() -> list:
    out = []
    for rel in _inventory_paths():
        p = os.path.join(ROOT, rel)
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        out.append({
            "type": "file",
            "bom-ref": "file:%s" % rel,
            "name": rel,
            "hashes": [{"alg": "SHA-256", "content": h}],
        })
    return sorted(out, key=lambda c: c["name"])


def _licences() -> list:
    """The two licences actually in the tree, each with its own pinned bytes.

    `necs/` is Apache-2.0 and the rest is AGPL-3.0-only. An SBOM that
    reported one licence for the whole repository would be wrong in the
    direction that matters to a downstream consumer.
    """
    out = []
    for rel, spdx in (("LICENSES/AGPL-3.0.txt", "AGPL-3.0-only"),
                      ("LICENSES/Apache-2.0.txt", "Apache-2.0")):
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            continue
        with open(p, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        out.append({"license": {"id": spdx},
                    "properties": [{"name": "jjdai:text-sha256", "value": h},
                                   {"name": "jjdai:text-path", "value": rel}]})
    return out


def build() -> dict:
    version = _project_version()
    files = _files()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        # No serialNumber and no timestamp ON PURPOSE. Both are recommended
        # by the spec and both are nondeterministic, which would make
        # `--check` fail on every run for reasons that say nothing about the
        # tree. The tree digest below is the identity that matters here.
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "pkg:generic/jjdai@%s" % version,
                "name": "jjdai",
                "version": version,
                "description": ("JJ DAI reference trust, governance and agent "
                                "kernel. Runtime core is stdlib-only."),
                "licenses": _licences(),
                "purl": "pkg:generic/jjdai@%s" % version,
            },
            "properties": [
                {"name": "jjdai:inventory-digest",
                 "value": _inventory_digest()},
                {"name": "jjdai:inventory-scope",
                 "value": "source_digest() file set, minus docs/sbom.cdx.json"},
                {"name": "jjdai:file-count", "value": str(len(files))},
                {"name": "jjdai:runtime-dependencies", "value": "0"},
                {"name": "jjdai:generated-by", "value": "scripts/gen_sbom.py"},
                # Named here rather than left to be assumed. An SBOM in a
                # repository with no signing and no independent rebuild is an
                # inventory, not a provenance claim, and saying so inside the
                # artefact is cheaper than correcting a reader later.
                #
                # The list is DERIVED from the debt ledger in
                # architecture_status.json, not written here by hand
                # (ADR-022/D14). A hand-kept second copy is how a position
                # comes to be open in one surface and closed in another; that
                # is the defect this project has paid for twice.
                {"name": "jjdai:supply-chain-open",
                 "value": ", ".join(_supply_chain_open())},
                {"name": "jjdai:supply-chain-open-source",
                 "value": "docs/architecture_status.json :: release_debt "
                          "(projection over append-only events)"},
                # The SCOPE of the pin, stated so the component list is not
                # read as a stronger claim than it is. An audit round asked
                # for exactly this after finding the workflow's actions and
                # the build backend absent from a bill of materials that
                # described itself as covering a pinned toolchain.
                {"name": "jjdai:pinned-scope",
                 "value": "python-test-deps hash-pinned; github-actions "
                          "commit-pinned; build-backend version-pinned only"},
            ],
        },
        "components": (_toolchain() + _actions() + _build_backend()
                       + files),
    }


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True,
                      ensure_ascii=False) + "\n"


def main(argv) -> int:
    try:
        text = render()
    except ValueError as exc:
        print(str(exc))
        return 2
    if "--check" in argv:
        if not os.path.exists(OUT):
            print("SBOM MISSING: %s — run scripts/gen_sbom.py"
                  % os.path.relpath(OUT, ROOT))
            return 1
        have = io.open(OUT, encoding="utf-8").read()
        if have != text:
            print("SBOM DRIFT: docs/sbom.cdx.json does not match the tree.")
            print("Run scripts/gen_sbom.py and commit the result.")
            return 1
        print("SBOM ok — matches the tree")
        return 0
    io.open(OUT, "w", encoding="utf-8").write(text)
    print("wrote %s" % os.path.relpath(OUT, ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
