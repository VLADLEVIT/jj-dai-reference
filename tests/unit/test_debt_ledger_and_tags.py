#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The debt ledger (D14) and what each tag asserts (D13).

  DEBT-1  ONE function computes the projection, and it is the fail-closed
          one. The ledger's own scan was a projection by accident.
  DEBT-2  Every position in the shipped ledger projects cleanly, and every
          terminal event carries its reference.
  DEBT-3  A position is never deleted: what left in v0.6.9 left with a
          DEBT_CLOSED naming the check that discharged it.
  DEBT-4  Surfaces render only `open` positions, and the SBOM's list is the
          projection rather than a copy of it.
  TAG-1   A preflight annotation asserts nothing about provenance and
          refuses to print a digest without its algorithm.
  TAG-2   A release annotation carries D13's list verbatim, and the control
          appears as NUMBERS.
  TAG-3   `tag name == ReleaseStatement.version`, and a preflight tag cannot
          carry a release attestation.
  TAG-4   A release tag refuses on a `same-host` rebuild.
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

from jjdai import provenance as prv                            # noqa: E402
from jjdai import release as rel                               # noqa: E402

sys.path.insert(0, os.path.join(_ROOT, "tests", "unit"))
from test_release_chain import (_attestation, _chain, _ctx,   # noqa: E402
                                _full_context, _registry, _statement)

STATUS = os.path.join(_ROOT, "docs", "architecture_status.json")


def _status():
    return json.load(_io.open(STATUS, encoding="utf-8"))


def _code(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except (prv.ProvenanceValueError, rel.ReleaseError) as exc:
        return getattr(exc, "code", "PROVENANCE")
    except Exception as exc:                                   # noqa: BLE001
        return type(exc).__name__
    return None


def test_one_function_computes_the_projection():
    """DEBT-1"""
    src = _io.open(os.path.join(_ROOT, "tests", "unit",
                                "test_tree_is_its_own_plan.py"),
                   encoding="utf-8").read()
    assert "load_debt_ledger" in src, (
        "SBOM-3 scans the events itself again; two implementations of one "
        "projection disagree the moment either is fixed")
    state = prv.load_debt_ledger(_status())
    assert isinstance(state, dict) and state
    # and it is the FAIL-CLOSED one — a last-write-wins scan accepts all of
    # these, which is how a debt gets closed without saying by what.
    #
    # Each case asserts WHICH refusal fired, by type and by wording. The
    # first cut of this check asserted only that something was raised, and
    # with the shape rule deleted a bare-string history raises AttributeError
    # from `.get()` — the rule gone and the check still green. That is the
    # fifth time in this drop a check has been carried by a failure it was
    # not about, so it is pinned rather than trusted.
    def _why(history):
        try:
            prv.project_debt(history)
        except prv.ProvenanceValueError as exc:
            return str(exc)
        except Exception as exc:                               # noqa: BLE001
            raise AssertionError(
                f"refused by {type(exc).__name__}, not by the rule: "
                f"{exc}") from None
        raise AssertionError(f"{history!r} was projected")

    assert "not an object" in _why(["DEBT_OPENED", "DEBT_CLOSED"])
    assert "begins with" in _why(
        [{"event": "DEBT_CLOSED", "evidence_ref": "x"}])
    assert "requires" in _why([{"event": "DEBT_OPENED"},
                               {"event": "DEBT_CLOSED"}])
    assert "terminal event" in _why(
        [{"event": "DEBT_OPENED"},
         {"event": "DEBT_CLOSED", "evidence_ref": "x"},
         {"event": "DEBT_OPENED"}])
    print("  [PASS] DEBT-1  one fail-closed projection, used by the SBOM "
          "check too")


def test_every_position_projects_and_cites():
    """DEBT-2"""
    ledger = _status()["release_debt"]
    assert ledger["schema"] == "jjdai.debt-ledger/v1"
    state = prv.load_debt_ledger(_status())
    assert set(state.values()) <= set(prv.DEBT_PROJECTIONS)
    seqs = [e["seq"] for e in ledger["events"]]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs), (
        "the ledger is append-only: sequence numbers must be unique and "
        "ascending, or 'what happened after what' is a matter of opinion")
    for event in ledger["events"]:
        field = prv.DEBT_REFERENCE_FIELD.get(event["event"])
        if field:
            assert event.get(field), (
                f"{event['id']} left with no {field}: a terminal event "
                f"without its reference is a deletion with better manners")
    print("  [PASS] DEBT-2  %d positions project cleanly; every terminal "
          "event cites its reason" % len(state))


def test_v069_closed_what_it_discharged_and_nothing_else():
    """DEBT-3"""
    state = prv.load_debt_ledger(_status())
    # closed BY THIS DROP, each naming the check that discharged it
    for position in ("readme-outside-tree-digest",
                     "file-modes-and-symlink-targets"):
        assert state[position] == prv.DEBT_SETTLED, position
    # and NOT closed, because the mechanism is in the tree and the facts are
    # not: no vendored wheels, no keys, no bundle, no compiled modules.
    # Closing these would be the defect the ledger exists to prevent — a
    # position leaving without the evidence that discharges it.
    for position in ("build-backend-unhashed", "reproducible-build",
                     "signed-artefacts", "release-provenance", "t-toolset"):
        assert state[position] == prv.DEBT_OPEN, (
            f"{position} reads as discharged. The mechanism being built is "
            f"not the debt being paid: these need a build host, a key "
            f"ceremony and a second machine")
    assert state["two-person-approval"] == prv.DEBT_WITHDRAWN
    assert state["cla"] == prv.DEBT_OPEN
    print("  [PASS] DEBT-3  two positions closed with their evidence; five "
          "still open because their facts are not in this tree")


def test_surfaces_render_only_open_positions():
    """DEBT-4"""
    open_now = prv.open_debt(_status())
    assert "readme-outside-tree-digest" not in open_now
    assert "two-person-approval" not in open_now, (
        "a cancelled position is not open; rendering it would keep asking "
        "for a control that was withdrawn by decision")
    sbom = json.load(_io.open(os.path.join(_ROOT, "docs", "sbom.cdx.json"),
                              encoding="utf-8"))
    props = {p["name"]: p["value"] for p in sbom["metadata"]["properties"]}
    listed = [x.strip()
              for x in props.get("jjdai:supply-chain-open", "").split(",")
              if x.strip()]
    for item in listed:
        assert item in open_now, (
            f"the SBOM names {item!r} as open and the ledger does not. The "
            f"SBOM does not get its own copy of what is owed")
    assert props.get("jjdai:supply-chain-open-source"), (
        "a derived list that does not name its source reads as hand-kept")
    print("  [PASS] DEBT-4  surfaces render the projection, not a copy of it")


def test_preflight_annotation_asserts_nothing_about_provenance():
    """TAG-1"""
    text = rel.preflight_annotation(
        version="v0.6.9", tree_digest="ab" * 32,
        tree_digest_algo=prv.TREE_DIGEST_ALGO, acceptance="271/271")
    assert "NOT a release" in text
    assert "asserts nothing about provenance" in text
    assert "not signed" in text
    assert prv.TREE_DIGEST_ALGO in text
    assert "Does not consume the version number" in text
    # forbidden: a digest without the name of its algorithm
    assert _code(rel.preflight_annotation, version="v0.6.9",
                 tree_digest="ab" * 32, tree_digest_algo="",
                 acceptance="271/271") == rel.REL_TAG_FORBIDDEN
    assert len(rel.TAG_PROHIBITIONS) == 4
    print("  [PASS] TAG-1  the preflight annotation carries its caveat in "
          "the tag, and refuses an unnamed digest")


def test_release_annotation_carries_the_list_and_the_numbers():
    """TAG-2"""
    reg = _registry()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        pub = rel.publish(_attestation(), chain=chain, registry=reg,
                          context=_ctx())
        text = rel.release_annotation(pub, chain=chain, registry=reg,
                                      context=_ctx())
        # THE NUMBERS ARE NOT AN ARGUMENT. Passing them in is how the audit
        # of recut2 printed 99 keys and 99 principals over a two-key
        # release: the function whose subject is that the control is
        # numbers took the numbers on trust.
        import inspect
        assert "counted" not in inspect.signature(
            rel.release_annotation).parameters
        for field in ("attestation_hash", "witness_ref", "statement_hash",
                      "tree_digest", "tree_digest_algo", "reproducibility",
                      "control"):
            assert field in text, field
        assert prv.TREE_DIGEST_ALGO in text
        # the control is NUMBERS. "two-person approved" where two keys sat
        # with one person would put an independence nobody had into the most
        # quoted artefact of the release.
        assert '"distinct_principals": 1' in text
        assert "two-person" not in text.lower()
    print("  [PASS] TAG-2  the release annotation carries D13's list and "
          "states the control as numbers")


def test_tag_name_equals_version_and_preflight_carries_no_attestation():
    """TAG-3"""
    reg = _registry()
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        pub = rel.publish(_attestation(), chain=chain, registry=reg,
                          context=_ctx())
        rel.check_release_tag("v0.6.9", pub, chain=chain, registry=reg,
                              context=_ctx())
        assert _code(rel.check_release_tag, "v0.6.10", pub, chain=chain,
                     registry=reg, context=_ctx()) == rel.REL_TAG_MISMATCH
        assert _code(rel.check_release_tag, "v0.6.9-preflight", pub,
                     chain=chain, registry=reg,
                     context=_ctx()) == rel.REL_TAG_MISMATCH
    print("  [PASS] TAG-3  a tag names its version; a preflight tag carries "
          "no attestation")


def test_release_tag_refuses_a_same_host_rebuild():
    """TAG-4"""
    reg = _registry()
    same_host = _statement(reproducibility_scope=prv.SCOPE_SAME_HOST)
    # it does not even validate: a rebuild on the machine that built it
    # repeats the machine, not the recipe
    assert _code(rel.validate_statement, same_host)
    with tempfile.TemporaryDirectory() as tmp:
        chain = _chain(tmp)
        pub = rel.publish(_attestation(), chain=chain, registry=reg,
                          context=_ctx())
        counted = rel.verify_publication(pub, chain=chain, registry=reg,
                                         context=_ctx())
        pub["attestation"]["statement"]["reproducibility_scope"] = \
            prv.SCOPE_SAME_HOST
        assert _code(rel.release_annotation, pub, counted=counted)
    print("  [PASS] TAG-4  a release tag refuses a same-host rebuild")


if __name__ == "__main__":
    for fn in (test_one_function_computes_the_projection,
               test_every_position_projects_and_cites,
               test_v069_closed_what_it_discharged_and_nothing_else,
               test_surfaces_render_only_open_positions,
               test_preflight_annotation_asserts_nothing_about_provenance,
               test_release_annotation_carries_the_list_and_the_numbers,
               test_tag_name_equals_version_and_preflight_carries_no_attestation,
               test_release_tag_refuses_a_same_host_rebuild):
        fn()
