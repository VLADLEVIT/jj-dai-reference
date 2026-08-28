# -*- coding: utf-8 -*-
"""
v0.6.8 remediation unit acceptance — the tree is its own plan of record

The v0.6.8 drop was code-complete, 206/206, and its `tree_digest` proved the
code against the r6.7 roadmap and ADR-014 through 019 — while the normative
documents for that same code were already r6.8.2, the ADR-017 amendment,
ADR-020 and ADR-021, none of which were in the tree.

(This docstring names no roadmap FILENAME on purpose. SYNC-3 below scans the
tree for pointers at a roadmap file that is not present, and it does not
exempt itself — the first run of this check flagged its own docstring, which
is the behaviour wanted.) Nothing was
wrong with the code. What was wrong is that the evidence bound it to a plan
the tree did not contain, and no check could see that, because no check
looked at the DOCUMENTS.

These do. Six groups:

  SYNC-1  every ADR the docs index names exists in docs/adr/
  SYNC-2  exactly one roadmap revision is present, and README, the docs
          index and the roadmap README all name THAT file
  SYNC-3  no surviving pointer at a roadmap file that is not in the tree
  SYNC-4  ADR-017's A-1 amendment is present in the document and reachable
          from the index (it is INLINE, so a missing file cannot flag it)
  SYNC-5  every markdown ADR's own header status equals the status the docs
          index publishes for it, and nothing rests on an unadopted document
  ENTRY-1 pytest and run_acceptance.py agree on the DEFAULT group set
  ENTRY-2 nothing in the tree still claims they collect identical functions
  ENTRY-3 the recorded artefact is internally consistent about how it
          was produced, AND this host collects what README documents
  SBOM-1  docs/sbom.cdx.json regenerates byte-identically from the tree
  SBOM-2  every component the SBOM records as a library carries a hash
  SBOM-3  the SBOM does not claim the supply chain is closed
  SYNC-7  deliverable->drop has one machine source of truth
  SYNC-7-MUT the check is proved to fire on broken copies
  SYNC-8  one acceptance TOTAL across roadmap, recorded evidence and
          the generated surfaces
  LEDGER-1..3 the debt ledger is append-only and says why a position left
  PIN-1   requirements-dev.txt pins every requirement by version AND hash
  PIN-2   every build input is pinned as strongly as its format allows, and
          the one that cannot carry a hash is declared rather than implied
  ATTR-1  .gitattributes exists and disables EOL conversion tree-wide
  SYNC-6  the roadmap PDF was typeset from the markdown now in the tree

Each was verified to go RED against the tree it replaced — SYNC-1/2/3/4,
SBOM-*, PIN-1 and ATTR-1 against v0.6.8 because the artefacts did not exist;
ENTRY-1/2 because pyproject collected tests/live and three documents asserted
parity.

SYNC-5 and ENTRY-3 were added in recut2 and go red against recut1. SYNC-5 is
there because SYNC-1 checked that a file EXISTS and stopped: ADR-020 shipped
in recut1 carrying `Status: Proposed` and a closing paragraph saying that
until it is Accepted it authorises neither the ADR-017 amendment nor the
reserve — while the roadmap, this index, the CHANGELOG and ADR-017's own
K4-bis all treated it as Accepted. Presence is not status.
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "scripts"))


def _read(*parts):
    return io.open(os.path.join(_ROOT, *parts), encoding="utf-8").read()


# --------------------------------------------------------------------- SYNC
def test_normative_documents_are_in_the_tree():
    """SYNC-1…4 — the plan the code is proved against is inside the tree."""
    index = _read("docs", "README.md")
    adr_dir = os.path.join(_ROOT, "docs", "adr")
    present = set(os.listdir(adr_dir))

    # SYNC-1: every ADR the index links must be openable.
    linked = set(re.findall(r"\(adr/([^)]+)\)", index))
    assert linked, "SYNC-1: the docs index links no ADR at all"
    missing = sorted(f for f in linked if f not in present)
    assert not missing, (
        "SYNC-1: docs/README.md links ADRs that are not in docs/adr/: %s. "
        "An index naming a document the tree does not carry is the defect "
        "this check exists for." % missing)

    # ...and every ADR in the tree must be in the index, or a reader can
    # miss a decision that is nonetheless normative.
    unindexed = sorted(f for f in present
                       if f.startswith("ADR-") and f not in linked)
    assert not unindexed, (
        "SYNC-1: docs/adr/ carries ADRs the index does not name: %s"
        % unindexed)

    # SYNC-2: exactly one roadmap revision, named consistently everywhere.
    rm_dir = os.path.join(_ROOT, "docs", "roadmap")
    mds = sorted(f for f in os.listdir(rm_dir)
                 if f.startswith("JJ_DAI_Roadmap_") and f.endswith(".md"))
    assert len(mds) == 1, (
        "SYNC-2: expected exactly one roadmap markdown in docs/roadmap/, "
        "found %s. Each revision contains the previous one whole, so two "
        "self-contained roadmaps side by side let an implementation read "
        "the wrong one." % mds)
    canonical = mds[0]
    pdf = canonical[:-3] + ".pdf"
    assert os.path.exists(os.path.join(rm_dir, pdf)), (
        "SYNC-2: %s has no typeset PDF beside it" % canonical)

    for doc, path in (("README.md", ("README.md",)),
                      ("docs/README.md", ("docs", "README.md")),
                      ("docs/roadmap/README.md",
                       ("docs", "roadmap", "README.md"))):
        txt = _read(*path)
        assert canonical in txt, (
            "SYNC-2: %s does not name the roadmap that is actually in the "
            "tree (%s)" % (doc, canonical))

    # SYNC-3: no dangling pointer at a superseded revision anywhere.
    stale = []
    for base, dirs, names in os.walk(_ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for n in names:
            if not n.endswith((".md", ".py", ".json", ".yml", ".toml")):
                continue
            rel = os.path.relpath(os.path.join(base, n), _ROOT)
            # The CHANGELOG is a historical record and MUST keep naming the
            # revisions that were current at the time.
            if rel == "CHANGELOG.md" or rel.startswith("docs/roadmap/"):
                continue
            try:
                txt = io.open(os.path.join(base, n), encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            for hit in re.findall(r"JJ_DAI_Roadmap_r[0-9_]+\.(?:md|pdf)", txt):
                if hit not in (canonical, pdf):
                    stale.append((rel, hit))
    assert not stale, (
        "SYNC-3: pointers at a roadmap file that is not in the tree: %s"
        % sorted(set(stale)))

    # SYNC-4: ADR-017's amendment is INLINE. A missing separate file cannot
    # betray its absence, so the check reads the document itself.
    adr017 = _read("docs", "adr", "ADR-017-Key-Plane.md")
    assert "K4-bis" in adr017 and "A-1" in adr017, (
        "SYNC-4: ADR-017 carries no A-1 amendment. ADR-020 rev 4.1 A9-bis "
        "requires it, and without it ADR-017's own header still forbids all "
        "runtime in Ф0 while ADR-020 requires an object DEK there.")
    assert "GUARDIAN_PRIVATE" in adr017, (
        "SYNC-4: ADR-017 A-1 does not name the access class it is scoped "
        "to. An amendment without a named boundary is an amendment that "
        "spreads.")
    assert "K4-bis" in index, (
        "SYNC-4: docs/README.md does not point a reader at K4-bis. The "
        "amendment is inside the document; an index that does not say so "
        "leaves a reader of K4 with the revoked model.")
    print("  [PASS] SYNC-1..4 ADRs, roadmap and the A-1 amendment are all in "
          "the tree and named consistently")


_STATUS_WORDS = ("Accepted", "Proposed", "Superseded")


def _doc_status(text: str) -> str:
    """The status word from an ADR's own header line.

    Read from the FIRST status line only. Every one of these documents also
    discusses the statuses of its neighbours further down, and a scan of the
    whole file would find whichever word appears first anywhere.
    """
    for line in text.splitlines()[:40]:
        low = line.lower()
        if "статус" in low or line.strip().lower().startswith("**status"):
            # `Статус поправки:` counts — ADR-014's A-1 is a document in its
            # own right and carries its own adoption state.
            found = [w for w in _STATUS_WORDS if w in line]
            if found:
                return found[0]
    return ""


def test_adr_statuses_agree_between_document_and_index():
    """SYNC-5 — presence is not status.

    recut1 shipped ADR-020 as `Proposed` while four other places in the tree
    relied on it being `Accepted`, including the ADR-017 amendment whose own
    text says it took effect on that adoption. Nothing caught it, because
    SYNC-1 asks whether a file is there.
    """
    index = _read("docs", "README.md")
    adr_dir = os.path.join(_ROOT, "docs", "adr")

    # index rows: | [ADR-0NN ...](adr/FILE) | subject | STATUS |
    rows = re.findall(r"\|\s*\[([^\]]+)\]\(adr/([^)]+)\)\s*\|([^|]*)\|([^|]*)\|",
                      index)
    assert rows, "SYNC-5: could not parse the ADR index table"

    checked = 0
    for label, fname, _subject, status_cell in rows:
        if not fname.endswith(".md"):
            # ADR-014 ships as the PDF it was issued as and cannot be
            # patched; its status is carried by the index and by the
            # separate A-1 file, and the index warns about it in prose.
            continue
        published = [w for w in _STATUS_WORDS if w in status_cell]
        assert published, (
            "SYNC-5: the index publishes no recognisable status for %s"
            % label)
        published = published[0]

        doc = _doc_status(io.open(os.path.join(adr_dir, fname),
                                  encoding="utf-8").read())
        assert doc, (
            "SYNC-5: %s carries no status line of its own. A decision whose "
            "own document does not say whether it has been made is not a "
            "decision an implementation may rely on." % fname)
        assert doc == published, (
            "SYNC-5: %s says %r in its own header while docs/README.md "
            "publishes %r. An implementation reads the document, a reviewer "
            "reads the index, and they get different answers about whether "
            "the decision has been made." % (fname, doc, published))
        checked += 1

    assert checked >= 5, (
        "SYNC-5: only %d markdown ADRs were checked — the index parse is "
        "probably broken rather than the tree clean" % checked)

    # The coordinated set rests on ADR-020 specifically: ADR-017's K4-bis
    # says the amendment took effect on its adoption, and the roadmap makes
    # it a precondition of cutting v0.6.9. That dependency is named here so
    # a future edit cannot quietly return it to Proposed while the
    # dependents stay put.
    adr020 = io.open(os.path.join(adr_dir, "ADR-020-Agent-Alpha.md"),
                     encoding="utf-8").read()
    assert _doc_status(adr020) == "Accepted", (
        "SYNC-5: ADR-020 is not Accepted, but ADR-017's A-1 amendment, the "
        "roadmap's v0.6.9 precondition and the docs index all depend on its "
        "adoption. Either adopt it or withdraw the dependants — the one "
        "state that must not exist is this one.")
    print("  [PASS] SYNC-5   %d ADR statuses agree between document and "
          "index; ADR-020 Accepted, so the coordinated set has a basis"
          % checked)


# -------------------------------------------------------------------- ENTRY
def test_entrypoints_agree_on_the_default_set():
    """ENTRY-1/2 — pytest and the stdlib runner collect the same default."""
    from run_acceptance import GROUPS, OPT_IN

    pyproject = _read("pyproject.toml")

    # The default set must be declared POSITIVELY. `testpaths = ["tests"]`
    # made it a subtraction, so a new directory under tests/ joined the
    # default run before anyone decided it should.
    tp = re.search(r"testpaths\s*=\s*\[(.*?)\]", pyproject, re.S)
    assert tp, "ENTRY-1: pyproject.toml declares no testpaths"
    declared = set(re.findall(r'"tests/([a-z_]+)"', tp.group(1)))
    assert declared == set(GROUPS), (
        "ENTRY-1: testpaths declares %s, the runner's hermetic groups are "
        "%s. The two entrypoints would report different numbers for the "
        "same tree." % (sorted(declared), sorted(GROUPS)))

    for group in OPT_IN:
        assert '"tests/%s"' % group not in tp.group(1), (
            "ENTRY-1: testpaths names opt-in group %r, which would put it in "
            "a bare `pytest` run" % group)
        assert "--ignore=tests/%s" % group in pyproject, (
            "ENTRY-1: run_acceptance.py holds group %r out of the default "
            "run but pytest still collects it. `pytest tests/` then reports "
            "a different suite from the runner on the same tree, and on a "
            "host without the group's prerequisites it fails where the "
            "runner is green." % group)
    for group in GROUPS:
        assert "--ignore=tests/%s" % group not in pyproject, (
            "ENTRY-1: pytest ignores %r, which the runner counts. The badge "
            "would then be higher than what pytest proves." % group)

    # ENTRY-2: the retired parity claim must not come back.
    for path in (("scripts", "run_acceptance.py"), ("README.md",),
                 ("CONTRIBUTING.md",)):
        txt = _read(*path)
        assert "exact same functions" not in txt, (
            "ENTRY-2: %s claims the two entrypoints collect the exact same "
            "functions. They collect the same DEFAULT groups; selecting "
            "`live` in either changes what runs, so the stronger claim is "
            "false." % "/".join(path))
    print("  [PASS] ENTRY-1/2 pytest and run_acceptance.py agree on the five "
          "hermetic groups; no parity overclaim survives")


def test_documented_pytest_commands_collect_what_readme_says():
    """ENTRY-3 — the three documented invocations, RUN, not reasoned about.

    `--ignore` prunes during recursion; a path named explicitly on the
    command line is still collected. That is documented pytest behaviour and
    it is also exactly the kind of subtlety a reader gets wrong: an audit
    round read `addopts = "-q --ignore=tests/live"` as blocking
    `pytest tests/live` and filed it as a defect. It does not block it —
    but "it does not, I checked once" is not evidence a later pytest release
    still behaves that way. So this runs the commands.

    Where pytest is absent the check does NOT skip — skipping would make the
    evidence depend on the host. It asserts the configuration instead.

    An audit round reported that fallback as a way for ENTRY-3 to read green
    without pytest ever running, and it was right about the CONSEQUENCE even
    though the fallback itself is correct: the recorded artefact said nothing
    about which mode had happened, so a reader of the evidence could not tell
    an exercised claim from an asserted one. Schema `/v4` carries
    `collector.pytest` and `collector.entrypoint_probe_mode` for that reason.

    TWO SEPARATE QUESTIONS, and recut3 conflated them into a defect that made
    CI fail by construction. It asserted that the RECORDED artefact described
    the CURRENT host — so a tree whose evidence was recorded on a bare
    interpreter (`configuration-only`) failed the moment CI installed pytest
    and ran the suite, which is precisely what the workflow does. Re-recording
    in `collection` mode only moves the failure to the bare interpreter the
    stdlib runner exists to serve. There is no value of the field that
    satisfies a check written that way, because the question was wrong.

    An artefact describes the run that PRODUCED it. It is not a claim about
    whoever reads it later, and coupling the two makes evidence expire on
    contact with a different host. So:

      * the artefact is validated STRUCTURALLY — it must be internally
        consistent and say which mode it recorded;
      * the CURRENT environment is probed on its own terms — with pytest,
        the three documented commands are actually run; without it, the
        configuration is asserted.
    """
    import json

    try:
        import pytest as _pytest  # noqa: F401
        have_pytest = getattr(_pytest, "__version__", "unknown")
    except ImportError:
        have_pytest = None

    # --- (1) the artefact, on its own terms. No reference to this host.
    ev = os.path.join(_ROOT, "docs", "evidence", "hermetic.json")
    if os.path.exists(ev):
        rec = json.loads(io.open(ev, encoding="utf-8").read())
        coll = rec.get("collector")
        assert coll is not None, (
            "ENTRY-3: the recorded run carries no `collector`. Schema /v4 "
            "records it precisely so an exercised entrypoint claim can be "
            "told from an asserted one after the fact.")
        assert coll.get("runner") == "scripts/run_acceptance.py", (
            "ENTRY-3: the artefact names an unexpected runner %r"
            % coll.get("runner"))
        mode = coll.get("entrypoint_probe_mode")
        assert mode in ("collection", "configuration-only"), (
            "ENTRY-3: unrecognised entrypoint_probe_mode %r" % mode)
        # The one binding between the two fields: a run that had no pytest
        # cannot have collected, and a run that collected must name the
        # collector it used. This is what makes the field evidence rather
        # than decoration — and it is checkable from the artefact alone,
        # on any host, forever.
        if mode == "configuration-only":
            assert coll.get("pytest") is None, (
                "ENTRY-3: the artefact records probe mode %r while naming "
                "pytest %r. A run that fell back to asserting configuration "
                "did so because pytest was absent." % (mode, coll.get("pytest")))
        else:
            assert coll.get("pytest"), (
                "ENTRY-3: the artefact records probe mode `collection` but "
                "names no pytest version. A collection probe that cannot say "
                "what collected is not evidence of a collection.")

    # --- (2) this host, on its own terms.
    if have_pytest is None:
        pyproject = _read("pyproject.toml")
        assert "--ignore=tests/live" in pyproject and "testpaths" in pyproject
        print("  [PASS] ENTRY-3  pytest absent HERE — configuration "
              "asserted, collection NOT exercised on this host; the "
              "artefact is checked for internal consistency, not against "
              "this host")
        return

    def _collect(args):
        p = subprocess.run(
            # -v because addopts carries -q, and under -q the trailing
            # "N tests collected" summary is not printed. The verbosity is
            # about READING the result, not about which files are collected.
            [sys.executable, "-m", "pytest", "--collect-only", "-v"] + args,
            cwd=_ROOT, capture_output=True, text=True)
        m = re.search(r"(\d+)\s+tests? collected", p.stdout + p.stderr)
        assert m, ("ENTRY-3: could not read a collection count from "
                   "`pytest %s`:\n%s" % (" ".join(args),
                                         (p.stdout + p.stderr)[-800:]))
        return int(m.group(1))

    bare = _collect([])
    tests_dir = _collect(["tests"])
    live = _collect(["tests/live"])

    assert bare == tests_dir, (
        "ENTRY-3: `pytest` collects %d and `pytest tests/` collects %d. "
        "README documents both as the hermetic suite." % (bare, tests_dir))
    assert live > 0, (
        "ENTRY-3: `pytest tests/live` collects nothing. README documents it "
        "as the way to run the opt-in group; if --ignore now prunes an "
        "explicitly named path, that command is a lie and the group is "
        "unreachable through pytest.")
    assert live not in (bare, bare + live), (
        "ENTRY-3: the live group appears to be inside the default count")
    print("  [PASS] ENTRY-3  pytest %s HERE: %d / tests %d / tests/live %d "
          "— all three documented commands collect what README claims"
          % (have_pytest, bare, tests_dir, live))


# --------------------------------------------------------------------- SBOM
def test_sbom_regenerates_and_claims_only_what_it_proves():
    """SBOM-1/2/3 — the inventory matches the tree and is honest about scope."""
    out = os.path.join(_ROOT, "docs", "sbom.cdx.json")
    assert os.path.exists(out), "SBOM-1: docs/sbom.cdx.json is absent"

    # SBOM-1: regenerate in-process and compare. A hand-maintained
    # inventory is accurate exactly once; this is what stops the third
    # instance of that defect in this repository.
    import gen_sbom
    assert gen_sbom.render() == io.open(out, encoding="utf-8").read(), (
        "SBOM-1: docs/sbom.cdx.json does not match what the tree generates. "
        "Run scripts/gen_sbom.py and commit the result.")

    import json
    doc = json.loads(io.open(out, encoding="utf-8").read())

    # SBOM-2: a component recorded without a hash is a name, not evidence.
    def props_open(d):
        return {p["name"]: p["value"]
                for p in d["metadata"]["properties"]}.get(
                    "jjdai:supply-chain-open", "")

    libs = [c for c in doc["components"] if c.get("type") == "library"]
    assert libs, "SBOM-2: the SBOM records no toolchain components at all"
    for c in libs:
        if c.get("hashes"):
            continue
        # One exception, and it must DECLARE itself. The PEP 517 build
        # backend is pinned to an exact version and cannot carry a hash,
        # because `[build-system].requires` has no field for one. A
        # component may sit here without a hash only if it says why and the
        # gap is named among the open supply-chain items — otherwise this
        # exception becomes the door every unpinned thing walks through.
        strength = {p["name"]: p["value"] for p in c.get("properties", [])}
        assert "jjdai:pin-strength" in strength, (
            "SBOM-2: component %s carries no hash and does not declare why. "
            "A name without bytes behind it is not evidence." % c.get("name"))
        assert "build-backend-unhashed" in props_open(doc), (
            "SBOM-2: %s is recorded without a hash but the gap is not named "
            "among the open supply-chain items" % c.get("name"))

    # SBOM-3: an SBOM in a repository with no signing and no two-person
    # approval is an inventory. It must not read as a provenance claim.
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props.get("jjdai:pinned-scope"), (
        "SBOM-3: the SBOM does not declare the SCOPE of its pinning. An "
        "inventory silent about its own boundary reads as complete.")
    # The list is no longer a literal kept here. ADR-022/D14 makes the debt
    # ledger the single source of truth, so this check compares the SBOM
    # against the PROJECTION over that ledger. A literal was what made the
    # cancellation of `two-person-approval` turn this check red instead of
    # turning the roadmap red — a check that fires when a decision is
    # recorded, rather than when a claim outruns its evidence, trains
    # people to edit the check.
    ledger = _ledger()
    projection = ledger["projection"]
    state, blocks = {}, {}
    for row in ledger["events"]:
        state[row["id"]] = projection[row["event"]]
        if "blocks" in row:
            blocks[row["id"]] = row["blocks"]
    expect = sorted(
        i for i, st in state.items()
        if st == "open"
        and blocks.get(i) != "acceptance-of-outside-contribution")
    open_items = [x.strip()
                  for x in props.get("jjdai:supply-chain-open", "").split(",")
                  if x.strip()]
    assert open_items == expect, (
        "SBOM-3: the SBOM's open supply-chain list %r does not match the "
        "projection over the debt ledger %r. The SBOM does not get its own "
        "copy of what is owed." % (open_items, expect))
    assert props.get("jjdai:supply-chain-open-source"), (
        "SBOM-3: the SBOM does not say where its open list comes from. A "
        "derived list that does not name its source reads as hand-kept.")
    assert open_items, (
        "SBOM-3: the SBOM names NOTHING as open. An inventory silent about "
        "what is still owed reads as a release attestation.")
    print("  [PASS] SBOM-1..3 %d components, %s regenerates byte-identically, "
          "open supply-chain items still named"
          % (len(doc["components"]), os.path.relpath(out, _ROOT)))


def test_roadmap_count_agrees_with_evidence_and_surfaces():
    """SYNC-8 — one acceptance TOTAL, in every surface that states one.

    The roadmap said 215 while the tree held 217, then 217 while the tree
    held 218 — twice in two days, both times because a test was added and
    the plan was not told. The generated surfaces never drifted, because
    they are generated; the roadmap drifted because it is written.

    TOTALS are compared, not passed counts. The passed count is a property
    of a run and belongs in the evidence file and in the badge rendered from
    it; the total is a property of the tree, so it can be checked without
    making the check depend on its own result. Comparing passed counts here
    would make this test change the number it verifies.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "genarch", os.path.join(_ROOT, "scripts", "gen_architecture_docs.py"))
    genarch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(genarch)
    collected = genarch.count_acceptance()

    sys.path.insert(0, os.path.join(_ROOT, "scripts"))
    from run_acceptance import read_result
    res = read_result()
    assert res is not None, (
        "SYNC-8: no recorded run — nothing to compare the plan against")
    assert res["total"] == collected, (
        "SYNC-8: the recorded run counts %d, the runner collects %d"
        % (res["total"], collected))

    rm_dir = os.path.join(_ROOT, "docs", "roadmap")
    mds = [f for f in os.listdir(rm_dir) if f.startswith("JJ_DAI_Roadmap_r")
           and f.endswith(".md")]
    assert len(mds) == 1, "SYNC-8: expected one roadmap markdown, found %s" % mds
    road = _read("docs", "roadmap", mds[0])

    # Only CURRENT claims. The revision journal quotes what earlier revisions
    # said, and rewriting history to satisfy a check would be the very defect
    # this project refuses everywhere else.
    claims = re.findall(r"(\d+)/(\d+) recorded", road)
    assert claims, ("SYNC-8: the roadmap states no acceptance count at all — "
                    "a plan that never states one cannot be checked against "
                    "the tree")
    wrong = sorted({"%s/%s" % c for c in claims if int(c[1]) != collected})
    assert not wrong, (
        "SYNC-8: the roadmap states %s while the runner collects %d. A test "
        "was added and the plan was not told — the same drift twice in two "
        "days." % (", ".join(wrong), collected))

    mapdoc = _read("docs", os.path.basename(genarch.MAP))
    m = re.search(r"Acceptance:\s*(\d+)/(\d+)", mapdoc)
    assert m and int(m.group(2)) == collected, (
        "SYNC-8: the architecture map states a total of %s, the runner "
        "collects %d" % (m.group(2) if m else "none", collected))
    print("  [PASS] SYNC-8   acceptance total %d agrees across roadmap, "
          "evidence and generated surfaces" % collected)


def _drop_plan():
    with io.open(os.path.join(_ROOT, "docs", "architecture_status.json"),
                 encoding="utf-8") as fh:
        return json.load(fh)["drop_plan"]


def _sync7_violations(text, fname, plan):
    """Every place `text` attaches a deliverable to a drop, checked.

    Returns a list of human-readable violations. Factored out of the test so
    the mutation self-test below can call it on DELIBERATELY BROKEN copies
    and prove the check would actually fire. A checker that has never been
    seen to fail is a checker nobody has tested.
    """
    drops, keywords = plan["drops"], plan["keywords"]
    bad = []

    # 1. The `Drop:` line is normative and unambiguous — no heuristics.
    m = re.search(r"^\*\*Drop:\*\*\s*(v0\.6\.\d+)", text, re.M)
    subject = None
    for key, spec in drops.items():
        if spec.get("adr") and spec["adr"] in fname:
            subject, declared_drop = spec["deliverable"], key
    if subject is not None:
        if not m:
            bad.append("%s carries no `Drop:` line; the registry expects %s"
                       % (fname, declared_drop))
        elif m.group(1) != declared_drop:
            bad.append("%s declares Drop: %s, the registry assigns %s to %s"
                       % (fname, m.group(1), declared_drop, subject))

    # 2. Body scan, deliberately simple so that its behaviour is obvious.
    #
    #    A CLAUSE that names exactly one deliverable and one or more drop
    #    numbers is a claim: every drop it names must be the drop the
    #    registry gives that deliverable. A clause naming no deliverable, or
    #    two, is ambiguous and is left alone — a checker that guesses at
    #    ambiguity produces false positives, and a check that cries wolf gets
    #    edited rather than obeyed.
    #
    #    Scope matters and cost two wrong attempts. The historical exemption
    #    is judged per SENTENCE, because the marker ("before r6.9 this read
    #    ...") and the quotation it introduces sit in different clauses. The
    #    claim is judged per CLAUSE, because one sentence routinely carries
    #    two ("v0.6.9 carries the toolset, v0.6.10 carries Alpha") and at
    #    sentence scope each half poisons the other. Nothing is skipped for
    #    carrying two drop numbers: that exemption is precisely how a
    #    swapped pair survived the first implementation.
    for sentence in re.split(r"(?<=\.)\s+|\n", text):
        if any(k in sentence for k in ("до r6", "историч", "читалась")):
            continue
        for clause in re.split(r"[;()«»]|,\s", sentence):
            found = sorted({deliv for deliv, words in keywords.items()
                            if any(w in clause for w in words)})
            if len(found) != 1:
                continue
            deliv = found[0]
            for dm in re.finditer(r"v0\.6\.\d+", clause):
                drop = dm.group(0)
                if drop in drops and drops[drop]["deliverable"] != deliv:
                    bad.append(
                        "%s attaches %r to %s; the registry gives %s to %r"
                        "\n    clause: %s"
                        % (fname, deliv, drop, drop,
                           drops[drop]["deliverable"],
                           " ".join(clause.split())[:140]))
    return bad


def test_no_adr_names_a_drop_that_disagrees_with_the_registry():
    """SYNC-7 — deliverable→drop has one source of truth, and it is machine-read.

    Owed after ADR-020 spent a day split-brain: its header said the Alpha drop
    was v0.6.10 while twelve places in the body still said v0.6.9. SYNC-5
    compares an ADR's STATUS to the index; nothing compared an ADR's CONTENT
    to the plan, and nothing compared a document to itself.

    The first implementation was heuristic and a reviewer's mutation test
    walked straight through it: it skipped sentences carrying two drop
    numbers, skipped anything mentioning a revision, and only looked at
    sentences containing certain words. All three exemptions are gone. The
    registry in `architecture_status.json :: drop_plan` is now the source of
    truth, each ADR carries a normative `Drop:` line, and the roadmap's drop
    table is checked against the same registry.
    """
    plan = _drop_plan()
    bad = []
    adr_dir = os.path.join(_ROOT, "docs", "adr")
    for name in sorted(f for f in os.listdir(adr_dir) if f.endswith(".md")):
        bad += _sync7_violations(_read("docs", "adr", name), name, plan)

    # the roadmap's drop table must agree with the same registry
    rm_dir = os.path.join(_ROOT, "docs", "roadmap")
    mds = [f for f in os.listdir(rm_dir) if f.startswith("JJ_DAI_Roadmap_r")
           and f.endswith(".md")]
    assert len(mds) == 1, "SYNC-7: expected one roadmap markdown, found %s" % mds
    road = _read("docs", "roadmap", mds[0])
    seen = 0
    for m in re.finditer(r"^\|\s*\*\*(v0\.6\.\d+)\*\*\s*\|(.+?)\|", road, re.M):
        drop, body = m.group(1), m.group(2)
        if drop not in plan["drops"]:
            continue
        want = plan["drops"][drop]["deliverable"]
        for deliv, words in plan["keywords"].items():
            if deliv == want:
                continue
            if any(w in body for w in words) and not any(
                    w in body for w in plan["keywords"][want]):
                bad.append("roadmap drop table gives %s to %r, registry says %r"
                           % (drop, deliv, want))
        seen += 1
    assert seen >= 2, ("SYNC-7: the roadmap drop table parsed %d rows — the "
                       "parse is probably broken rather than the tree clean" % seen)
    assert not bad, "SYNC-7:\n  " + "\n  ".join(bad)
    print("  [PASS] SYNC-7   %d roadmap row(s) and every ADR drop mention agree "
          "with drop_plan" % seen)


def test_sync7_would_actually_fire():
    """SYNC-7-MUT — the check is proved to fail on deliberately broken copies.

    A reviewer mutation-tested the previous implementation and it passed a
    document that named the wrong drop. So the check now carries its own
    mutation tests: four known-bad inputs that MUST be rejected, and one
    known-good historical reference that must NOT be. Without this, "SYNC-7
    passes" says nothing about whether SYNC-7 can fail.
    """
    plan = _drop_plan()
    fname = "ADR-020-Agent-Alpha.md"
    good = _read("docs", "adr", fname)

    mutants = {
        "wrong drop in the header":
            good.replace("**Drop:** v0.6.10", "**Drop:** v0.6.9", 1),
        "wrong drop in the normative body":
            good.replace("Обязательный объём Agent Alpha в v0.6.10:",
                         "Обязательный объём Agent Alpha в v0.6.9:", 1),
        "deliverables swapped in one sentence":
            good + "\n\nAgent Alpha едет дропом v0.6.9, а T-TOOLSET в v0.6.10.\n",
    }
    for label, text in mutants.items():
        assert _sync7_violations(text, fname, plan), (
            "SYNC-7-MUT: mutation %r SURVIVED. The check passed a document "
            "that names the wrong drop, which is the exact class of defect "
            "it exists to catch." % label)

    # and the permitted case must stay permitted, or the check gets edited
    hist = good + ("\n\nДо r6.9 строка читалась «дроп v0.6.9», это историческая "
                   "ссылка на Agent Alpha.\n")
    assert _sync7_violations(hist, fname, plan) == _sync7_violations(good, fname, plan), (
        "SYNC-7-MUT: an explicit historical reference was flagged. A check "
        "that cries wolf on honest text gets edited rather than obeyed.")
    print("  [PASS] SYNC-7-MUT %d mutation(s) rejected, historical reference "
          "permitted" % len(mutants))


def _ledger():
    """The release-debt ledger — the single source of truth for what is owed."""
    with io.open(os.path.join(_ROOT, "docs", "architecture_status.json"),
                 encoding="utf-8") as fh:
        return json.load(fh)["release_debt"]


def test_debt_ledger_is_append_only_and_says_why():
    """LEDGER-1..3 — a position leaves the list without leaving the record.

    ADR-022/D14. Deleting a debt line leaves nothing by which to check why it
    is gone; this project has twice found a position open in one surface and
    closed in another. So status is a projection over append-only events, a
    cancellation must name the decision that cancelled it, and a closure must
    name the evidence that closed it. The difference between the two is the
    whole point: one was decided away, the other was built.
    """
    ledger = _ledger()
    seen, seqs = set(), []
    for row in ledger["events"]:
        seqs.append(row["seq"])
        # LEDGER-1: every position is opened before it is closed or cancelled
        if row["event"] == "DEBT_OPENED":
            seen.add(row["id"])
        else:
            assert row["id"] in seen, (
                "LEDGER-1: %r is %s without ever having been opened. An "
                "append-only ledger that starts mid-story is a list."
                % (row["id"], row["event"]))
        # LEDGER-2: leaving the list requires saying which kind of exit it was
        if row["event"] == "DEBT_CANCELLED":
            assert row.get("decision_ref"), (
                "LEDGER-2: %r was cancelled without naming the decision that "
                "cancelled it. A requirement that vanishes without a "
                "decision_ref is indistinguishable from one that was quietly "
                "dropped." % row["id"])
        if row["event"] == "DEBT_CLOSED":
            assert row.get("evidence_ref"), (
                "LEDGER-2: %r was closed without naming the evidence that "
                "closed it. Closed means proved, not asserted." % row["id"])
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs), (
        "LEDGER-3: event sequence numbers are not strictly ordered and "
        "unique. Append-only is an ordering claim, not a file mode.")
    print("  [PASS] LEDGER-1..3 %d events, %d positions; cancellations name a "
          "decision, closures name evidence"
          % (len(ledger["events"]), len(seen)))


# ---------------------------------------------------------------------- PIN
def test_toolchain_is_pinned_by_hash():
    """PIN-1 — a version pin binds a name to a number; a hash binds bytes."""
    req = _read("requirements-dev.txt")
    lines = [ln for ln in req.splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]
    assert lines, "PIN-1: requirements-dev.txt declares nothing"

    blocks, cur = [], []
    for ln in lines:
        cur.append(ln)
        if not ln.rstrip().endswith("\\"):
            blocks.append("\n".join(cur))
            cur = []
    if cur:
        blocks.append("\n".join(cur))

    for b in blocks:
        name = b.strip().split("==")[0].strip()
        assert "==" in b, (
            "PIN-1: %r is not pinned to an exact version" % name)
        assert "--hash=sha256:" in b, (
            "PIN-1: %s is pinned by version but not by hash. "
            "--require-hashes in CI would refuse this file, so the pin would "
            "silently not be in force." % name)

    ci = _read(".github", "workflows", "ci.yml")
    assert "--require-hashes" in ci and "requirements-dev.txt" in ci, (
        "PIN-1: the workflow does not install from the hash-pinned file. A "
        "pinned requirements file nothing installs from pins nothing.")
    print("  [PASS] PIN-1   %d toolchain requirements, all pinned by version "
          "and hash, CI installs with --require-hashes" % len(blocks))


# --------------------------------------------------------------------- ATTR
def test_gitattributes_disables_eol_conversion():
    """ATTR-1 — source_digest() reads raw bytes; normalisation breaks it."""
    p = os.path.join(_ROOT, ".gitattributes")
    assert os.path.exists(p), (
        "ATTR-1: .gitattributes is absent. source_digest() hashes the raw "
        "bytes of 200+ paths including the sha256-pinned AGPL text, so a "
        "checkout that normalises line endings yields a different "
        "tree_digest AND a different licence hash — reported as ACC-TREE-1 "
        "'a different tree' and R-LICENSE, neither of which says 'line "
        "endings'.")
    txt = io.open(p, encoding="utf-8").read()
    rules = [ln.split("#")[0].strip() for ln in txt.splitlines()]
    assert "* -text" in rules, (
        "ATTR-1: .gitattributes does not carry `* -text`. A narrower rule "
        "leaves whatever path nobody thought of subject to conversion — the "
        "same failure mode as the inclusion list source_digest() was "
        "rewritten away from.")
    print("  [PASS] ATTR-1  .gitattributes present with tree-wide `* -text`")


def test_roadmap_pdf_was_typeset_from_the_markdown_in_the_tree():
    """SYNC-6 — `docs/roadmap/README.md` says the PDF is the same document.

    In recut2 that sentence was false. The markdown said 213/213 in three
    places and the PDF, built from an earlier draft, said 211/211 in the
    same three places — current state, the numbering rules, and
    where-we-are. `check_docs_drift.py` reported clean throughout: it
    verifies the surfaces generated from `architecture_status.json`, and the
    roadmap PDF is not one of them. Nothing in the tree could see it.

    The sha256 of the source markdown is stamped INSIDE the PDF's metadata
    by `scripts/typeset_roadmap.py`, so the pairing travels with the
    artefact. A sidecar file recording which markdown the PDF came from
    would be a third thing to keep in sync — and a claim about an artefact
    kept beside the artefact is exactly what went stale here.

    What this proves: the PDF was stamped against the markdown that is in
    the tree now. What it does NOT prove: that the rendering is faithful. A
    stamp is not a comparison of glyphs and would not catch a typesetter
    that silently dropped a table. It catches the failure that happened.
    """
    import typeset_roadmap as TR

    md = TR.source_markdown()
    pdf = os.path.join(_ROOT, "docs", "roadmap", md[:-3] + ".pdf")
    assert os.path.exists(pdf), (
        "SYNC-6: %s has no typeset PDF beside it, while "
        "docs/roadmap/README.md promises one" % md)

    want = TR.source_sha256(md)
    have = TR.stamped_sha256(pdf)
    assert have is not None, (
        "SYNC-6: the roadmap PDF carries no source stamp. An unstamped PDF "
        "cannot be shown to correspond to any particular text — the state "
        "recut2 shipped in.")
    assert have == want, (
        "SYNC-6: the roadmap PDF was typeset from a different text.\n"
        "  markdown now: %s\n  pdf stamped : %s\n"
        "Rebuild with scripts/typeset_roadmap.py." % (want, have))

    readme = _read("docs", "roadmap", "README.md")
    assert "typeset" in readme.lower(), (
        "SYNC-6: docs/roadmap/README.md no longer states the PDF/markdown "
        "relationship this check enforces")
    print("  [PASS] SYNC-6   roadmap PDF stamped %s — typeset from the "
          "markdown in this tree" % have[:12])


def test_every_build_input_is_pinned_as_strongly_as_its_format_allows():
    """PIN-2 — a partial pin described as a whole one stops anyone looking.

    An audit round found documents claiming a hash-pinned CI toolchain while
    `actions/checkout@v4` and `actions/setup-python@v5` were moving major
    tags — branches in all but name — and `setuptools>=68` was a floor. Two
    closures were available: pin them, or narrow the claim. This tree pins
    them, because the digests are resolvable and verifiable; what is left is
    the one input whose FORMAT cannot carry a hash, and that one is declared
    rather than implied.
    """
    import json

    ci = _read(".github", "workflows", "ci.yml")
    uses = re.findall(r"uses:\s*([\w.-]+/[\w.-]+)@(\S+)", ci)
    assert uses, "PIN-2: the workflow declares no actions at all"
    moving = [(a, ref) for a, ref in uses
              if not re.fullmatch(r"[0-9a-f]{40}", ref)]
    assert not moving, (
        "PIN-2: %s used by moving reference. A `@v4` tag is a branch: the "
        "same workflow file runs different code over time, so a green run "
        "last month says nothing about what ran today. Resolve the tag with "
        "`git ls-remote --tags --refs` and pin the commit." % moving)

    # The build backend is pinned exactly but cannot be hashed. That gap is
    # allowed to exist and is NOT allowed to be silent.
    pyproject = _read("pyproject.toml")
    assert re.search(r'requires\s*=\s*\[\s*"setuptools==', pyproject), (
        "PIN-2: [build-system].requires does not pin setuptools to an exact "
        "version. A floor resolves to whatever the index served that day, "
        "which makes the wheel a function of the calendar.")

    sbom = json.loads(_read("docs", "sbom.cdx.json"))
    props = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
    scope = props.get("jjdai:pinned-scope", "")
    assert "build-backend" in scope, (
        "PIN-2: the SBOM does not state where the pin stops. An inventory "
        "silent about its own boundary reads as complete.")
    assert "build-backend-unhashed" in props.get("jjdai:supply-chain-open", ""), (
        "PIN-2: the unhashable build backend is not named among the open "
        "supply-chain items")

    names = {c["name"] for c in sbom["components"]
             if c.get("type") == "library"}
    for owed in ("actions/checkout", "actions/setup-python", "setuptools"):
        assert owed in names, (
            "PIN-2: %s is an input to a build and does not appear in the "
            "bill of materials. An SBOM listing only the Python test "
            "packages reads as the whole dependency surface." % owed)
    print("  [PASS] PIN-2   %d action(s) pinned by commit SHA, build backend "
          "pinned by exact version with the unhashable gap declared"
          % len(uses))
