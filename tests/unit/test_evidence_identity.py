#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_evidence_identity — v0.6.7-recut3: what the digest covers, and whose
run the artefact is
=========================================================================
Two defects from the recut2 audit, and they are the same mistake twice.

**An inclusion list where an exclusion list was needed.** `source_digest`
hashed `.py` files only. The auditor granted anonymous access to `/v1/tasks`
in `deploy/authz.testnet.json`, and the digest and the green badge both
stayed exactly as they were. The reasoning that produced that list was about
EXCLUDING the generated surfaces; it was written as an inclusion list, and
an inclusion list silently loses every file type nobody thought of.

**A shared path where an identity was needed.** Every invocation wrote
`docs/acceptance_result.json`, so `run_acceptance.py live` overwrote the
hermetic result with a five-check wasm run. One artefact cannot be evidence
of a hermetic suite, of the wasm live group, and of a run on a particular
target host at once.

  EVID-1  the digest covers the shipped tree, not one language: authz
          policy, systemd and launchd units, shell scripts, the toolset
          manifest, pyproject, licences, CI and the normative documents are
          all named and all present. Fails against recut2.
  EVID-2  a file type nobody anticipated is covered BY DEFAULT — the list
          excludes, it does not admit.
  EVID-3  only what the run and its generator produce is excluded, and each
          exclusion is justified by the convergence argument, not by taste.
  EVID-4  a suite writes to its own file: a live run cannot overwrite the
          hermetic evidence, and the badge reads the hermetic suite.
  EVID-5  the artefact names its suite, its host and its engine slot, and
          its self-digest still refuses a hand-edited body.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import run_acceptance as RA                                   # noqa: E402
from run_acceptance import (digest_files, read_result,        # noqa: E402
                            result_path, source_digest)

#: Release-relevant files that are NOT Python. Each one can change what a
#: node does or what it is licensed as, and none of them was inside the
#: recut2 digest.
_MUST_COVER = (
    "deploy/authz.testnet.json",
    "deploy/wasm-toolset/toolset.json",
    "pyproject.toml",
    "LICENSES/AGPL-3.0.txt",
    "LICENSE",
    "CHANGELOG.md",
    "docs/architecture_status.json",
)


def test_digest_covers_the_shipped_tree():
    files = set(digest_files())
    missing = [f for f in _MUST_COVER if f not in files]
    assert not missing, (
        f"EVID-1: release-relevant files outside the digest: {missing}. "
        f"Changing one of these changes what a node does and left the "
        f"badge green.")
    # whole families, found by extension rather than by name, so a renamed
    # unit file does not quietly drop out of this check
    for label, suffix in (("systemd/launchd", (".service", ".plist")),
                          ("shell", (".sh",)),
                          ("CI", (".yml", ".yaml"))):
        hits = [f for f in files if f.endswith(suffix)]
        assert hits, f"EVID-1: no {label} file is covered by the digest"
    # and the content really participates
    before = source_digest()
    target = os.path.join(_ROOT, "deploy", "authz.testnet.json")
    raw = io.open(target, encoding="utf-8").read()
    try:
        io.open(target, "w", encoding="utf-8").write(raw + "\n")
        assert source_digest() != before, (
            "EVID-1: editing the authz policy left the digest unchanged — "
            "the exact hole the audit walked through")
    finally:
        io.open(target, "w", encoding="utf-8").write(raw)
    assert source_digest() == before
    print(f"  [PASS] EVID-1  {len(files)} shipped files covered, not just "
          f"Python")


def test_unanticipated_file_types_are_covered_by_default():
    with tempfile.TemporaryDirectory() as tmp:
        io.open(os.path.join(tmp, "a.py"), "w").write("x = 1\n")
        base = source_digest(tmp)
        for name in ("policy.rego", "node.service", "rules.prometheus",
                     "weights.safetensors.meta", "Makefile", "noext"):
            path = os.path.join(tmp, name)
            io.open(path, "w").write("content\n")
            assert source_digest(tmp) != base, (
                f"EVID-2: {name} is outside the digest. The list must "
                f"EXCLUDE by name, so that a file type nobody predicted is "
                f"covered without anyone remembering to add it.")
            os.remove(path)
            assert source_digest(tmp) == base
    print("  [PASS] EVID-2  unforeseen file types are covered by default")


def test_only_generated_surfaces_are_excluded():
    files = set(digest_files())
    # each exclusion exists because the file carries the badge, so hashing
    # it would let writing a result invalidate the run it describes
    assert "README.md" not in files
    assert not any(f.startswith("docs/evidence/") for f in files)
    assert not any(f.startswith("docs/JJDAI_Code_Architecture_Map_v")
                   for f in files)
    assert not any(f.startswith("docs/site/JJDAI_Architecture_Status_v")
                   for f in files)
    # nothing ELSE under docs/ is excluded: the ADRs and the roadmap are
    # normative and shipped
    assert any(f.startswith("docs/adr/") for f in files), \
        "EVID-3: the ADRs are outside the evidence"
    assert any(f.startswith("docs/roadmap/") for f in files), \
        "EVID-3: the roadmap is outside the evidence"
    # and the excluded surfaces are not unverified — they regenerate from a
    # file that IS hashed
    assert "docs/architecture_status.json" in files, (
        "EVID-3: the generator's SOURCE is excluded too, which would leave "
        "the generated surfaces genuinely unverified rather than verified "
        "elsewhere")
    print("  [PASS] EVID-3  only the badge-bearing surfaces are excluded")


def test_a_suite_cannot_overwrite_another():
    assert RA._suite_name(RA.GROUPS) == "hermetic"
    assert RA._suite_name(["live"]) == "live-live"
    assert RA._suite_name(["unit", "live"]).startswith("mixed-")
    assert result_path("hermetic") != result_path("live-live")

    hermetic = result_path("hermetic")
    assert os.path.exists(hermetic), "EVID-4: no hermetic evidence recorded"
    before = io.open(hermetic, encoding="utf-8").read()
    try:
        RA.write_result(5, 5, ["live"], 0, 1.0)
        after = io.open(hermetic, encoding="utf-8").read()
        assert after == before, (
            "EVID-4: a live run overwrote the hermetic evidence — the recut2 "
            "defect, where five wasm checks replaced a hundred and fifty-six")
        live = read_result("live-live")
        assert live is not None and live["suite"] == "live-live"
        assert live["groups"] == ["live"]
    finally:
        stray = result_path("live-live")
        if os.path.exists(stray):
            os.remove(stray)
    # the badge reads the hermetic suite and nothing else
    assert read_result()["suite"] == "hermetic"
    print("  [PASS] EVID-4  one file per suite; live cannot clobber hermetic")


def test_artefact_names_suite_host_and_engine():
    res = read_result()
    assert res["suite"] == "hermetic"
    for field in ("system", "release", "machine", "node"):
        assert res["host"].get(field), f"EVID-5: host.{field} is empty"
    assert "engine" in res, (
        "EVID-5: the engine slot is not declared. It is null here because "
        "the runner cannot know it; declaring it is what lets a live engine "
        "run say which engine it proved.")
    assert res["tree_digest"] == source_digest()
    # The self-digest still refuses a doctored body. The edit must change
    # the body in EVERY state of the tree: `passed=total` is not an edit at
    # all on a fully green run, which made the first cut of this check pass
    # for the wrong reason and flake between runs.
    doctored = dict(res, passed=res["passed"] + 1, total=res["total"] + 2)
    assert doctored != res
    path = result_path("tampered")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with io.open(path, "w", encoding="utf-8") as fh:
            json.dump(doctored, fh, indent=2, sort_keys=True)
        assert read_result("tampered") is None, (
            "EVID-5: a hand-edited result was accepted")
    finally:
        if os.path.exists(path):
            os.remove(path)
    print("  [PASS] EVID-5  the artefact says which suite, which host, "
          "which engine")


if __name__ == "__main__":
    for t in (test_digest_covers_the_shipped_tree,
              test_unanticipated_file_types_are_covered_by_default,
              test_only_generated_surfaces_are_excluded,
              test_a_suite_cannot_overwrite_another,
              test_artefact_names_suite_host_and_engine):
        t()
    print("\nevidence identity — 5/5 checks green")
