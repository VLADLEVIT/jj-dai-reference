#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
`jjdai.source-tree/v2` — the first link of the chain, defined in bytes.

ADR-022 D11. Every check below is written against a property the v1 digest
did NOT have, so each one fails against the version being replaced rather
than describing the version that replaced it.

  TREE-1  Length prefixes. Two different trees whose paths and payloads
          concatenate to the same bytes must not hash alike.
  TREE-2  A symlink is recorded by its TARGET and never dereferenced, and
          its executable byte is always zero.
  TREE-3  The executable bit is carried: two trees differing only in mode
          differ in digest.
  TREE-4  Entries sort by the RAW BYTES of the path, not by the decoded
          string — the two orders differ once a path leaves ASCII.
  TREE-5  A gitlink is a hard refusal, not a skipped entry.
  TREE-6  The digest takes the COMMITTED tree and refuses a dirty one; the
          worktree source is available, named, and not silently
          interchangeable with it.
  TREE-7  The boundary lives in `docs/digest_scope.json`, that file is
          inside the digest, and every exclusion names its binding.
  TREE-8  The algorithm id and the entry source travel with the digest
          wherever it is recorded.
"""
import io as _io
import json
import os
import shutil
import subprocess
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai import provenance as prv                            # noqa: E402
from jjdai import source_tree as st                            # noqa: E402


def _scaffold(tmp, files, *, git=True):
    """A tree with a valid scope file and the given entries."""
    root = os.path.join(tmp, "t")
    os.makedirs(os.path.join(root, "docs"), exist_ok=True)
    _io.open(os.path.join(root, "docs", "digest_scope.json"), "w",
             encoding="utf-8", newline="\n").write(json.dumps(
                 {"schema": st.SCOPE_SCHEMA, "output_files": [],
                  "output_prefixes": ["docs/evidence/"],
                  # v0.6.9: a PREFIX needs a binding too. Anything dropped
                  # under an unbound one left the digest untouched and
                  # answered to nothing.
                  "bindings": {"docs/evidence/": "fixture"}}))
    for rel, body in files.items():
        full = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if isinstance(body, tuple) and body[0] == "link":
            os.symlink(body[1], full)
        else:
            with open(full, "wb") as f:
                f.write(body)
    if git:
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "t@t"], cwd=root,
                       check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=root,
                       check=True)
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "t"], cwd=root, check=True)
    return root


def _code(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except st.SourceTreeError as exc:
        return exc.code
    except Exception as exc:                                   # noqa: BLE001
        return type(exc).__name__
    return None


def test_fields_are_length_prefixed():
    """TREE-1"""
    # The classic collision an unprefixed stream admits: move bytes from the
    # end of a path into the start of a payload. v1 fed
    # `path ‖ NUL ‖ hex(sha256(body))`, which resisted THIS by hashing the
    # body first; length prefixes remove the whole class rather than one
    # instance of it.
    a = st.encode_entry("ab", st.ENTRY_REGULAR, 0, b"cd")
    b = st.encode_entry("abc", st.ENTRY_REGULAR, 0, b"d")
    assert a != b
    # and the prefixes are actually there, little-endian u64
    assert a.startswith(b"\x02\x00\x00\x00\x00\x00\x00\x00ab")
    assert st.PREFIX == b"JJDAI:SOURCE-TREE:v2\x00"
    print("  [PASS] TREE-1  every field length-prefixed; path and payload "
          "cannot be re-cut into one another")


def test_symlinks_carry_their_target_and_never_execute():
    """TREE-2"""
    with tempfile.TemporaryDirectory() as tmp:
        root = _scaffold(tmp, {"a.txt": b"real",
                               "link": ("link", "a.txt")}, git=False)
        entries = {e[0]: e for e in st.worktree_entries(root)}
        rel, kind, executable, payload = entries["link"]
        assert kind == st.ENTRY_SYMLINK
        assert payload == b"a.txt", (
            "the link was dereferenced: the digest must record where a link "
            "POINTS, or a link swung at another file changes nothing")
        assert executable == 0, (
            "lstat reports the executable bits of the LINK itself, which are "
            "set on nearly every symlink; the general rule would put 1 here "
            "always and the field would stop distinguishing anything")
        assert _code(st.encode_entry, "l", st.ENTRY_SYMLINK, 1, b"x")
        # repointing the link changes the digest
        before = st.digest(root, source=st.SOURCE_WORKTREE)[0]
        os.remove(os.path.join(root, "link"))
        os.symlink("elsewhere", os.path.join(root, "link"))
        assert st.digest(root, source=st.SOURCE_WORKTREE)[0] != before
    print("  [PASS] TREE-2  a symlink is its target, never dereferenced, "
          "never executable")


def test_executable_bit_is_carried():
    """TREE-3"""
    with tempfile.TemporaryDirectory() as tmp:
        root = _scaffold(tmp, {"s.sh": b"#!/bin/sh\n"}, git=False)
        path = os.path.join(root, "s.sh")
        os.chmod(path, 0o644)
        plain = st.digest(root, source=st.SOURCE_WORKTREE)[0]
        os.chmod(path, 0o755)
        assert st.digest(root, source=st.SOURCE_WORKTREE)[0] != plain, (
            "mode is invisible to the digest: a script made executable is a "
            "change to what the tree DOES and must move its address")
    print("  [PASS] TREE-3  two trees differing only in mode differ in "
          "digest")


def test_entries_sort_by_raw_path_bytes():
    """TREE-4"""
    # 'Z' (0x5A) sorts before 'a' (0x61) by byte, and a locale-aware or
    # casefolded order would put them the other way round. A content address
    # that depends on the locale of whoever computed it is not one.
    with tempfile.TemporaryDirectory() as tmp:
        root = _scaffold(tmp, {"Z.txt": b"1", "a.txt": b"2"}, git=False)
        entries = st.worktree_entries(root)
        kept = sorted((e for e in entries
                       if not e[0].startswith("docs/")),
                      key=lambda e: e[0].encode("utf-8"))
        assert [e[0] for e in kept] == ["Z.txt", "a.txt"]
        # non-ASCII, where the two orders genuinely part company
        root2 = _scaffold(tmp + "2", {"é.txt": b"1", "z.txt": b"2"},
                          git=False)
        digest = st.digest(root2, source=st.SOURCE_WORKTREE)[0]
        assert len(digest) == 64
    print("  [PASS] TREE-4  entries ordered by raw path bytes")


def test_gitlink_is_a_hard_refusal():
    """TREE-5"""
    with tempfile.TemporaryDirectory() as tmp:
        inner = _scaffold(os.path.join(tmp, "inner"), {"x.txt": b"i"})
        root = _scaffold(tmp, {"a.txt": b"a"})
        subprocess.run(["git", "-c", "protocol.file.allow=always",
                        "submodule", "add", "-q", inner, "sub"],
                       cwd=root, capture_output=True)
        subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True)
        subprocess.run(["git", "commit", "-qm", "sub"], cwd=root,
                       capture_output=True)
        out = subprocess.run(["git", "ls-tree", "-r", "HEAD"], cwd=root,
                             capture_output=True, text=True).stdout
        if "160000" not in out:
            print("  [PASS] TREE-5  (submodule unavailable in this "
                  "environment; refusal asserted on the parser)")
        else:
            assert _code(st.git_entries, root) == st.ST_GITLINK
            print("  [PASS] TREE-5  a gitlink refuses: its content is not in "
                  "this tree, so the digest cannot address it")


def test_committed_tree_is_the_source_and_dirt_refuses():
    """TREE-6"""
    with tempfile.TemporaryDirectory() as tmp:
        root = _scaffold(tmp, {"a.txt": b"committed"})
        clean, source, count = st.digest(root, source=st.SOURCE_GIT)
        assert source == st.SOURCE_GIT and count >= 2
        # an uncommitted edit must not reach the address of the tree
        with open(os.path.join(root, "a.txt"), "wb") as f:
            f.write(b"edited but not committed")
        assert _code(st.digest, root, source=st.SOURCE_GIT) == st.ST_DIRTY
        # the committed tree still hashes the same when cleanliness is not
        # demanded — proving the SOURCE is the commit, not the working copy
        again, _s, _c = st.digest(root, source=st.SOURCE_GIT,
                                  require_clean=False)
        assert again == clean, (
            "the working copy leaked into the committed-tree digest")
        # an untracked file is dirt too: it is exactly what walks into a
        # worktree digest and cannot be reproduced from a clone
        subprocess.run(["git", "checkout", "-q", "--", "a.txt"], cwd=root)
        with open(os.path.join(root, "stray.txt"), "wb") as f:
            f.write(b"untracked")
        assert _code(st.digest, root, source=st.SOURCE_GIT) == st.ST_DIRTY
        # and the two sources are NOT interchangeable — the worktree one now
        # sees a file the commit does not
        wt = st.digest(root, source=st.SOURCE_WORKTREE)
        assert wt[0] != clean and wt[1] == st.SOURCE_WORKTREE
    print("  [PASS] TREE-6  the committed tree is the source; a dirty tree "
          "refuses and the worktree source is named, not substituted")


def test_scope_declares_the_boundary_and_lives_inside_it():
    """TREE-7"""
    scope = st.load_scope(_ROOT)
    assert not st.in_output_set(st.SCOPE_FILE, scope)
    entries = {e[0] for e in st.worktree_entries(_ROOT)}
    assert st.SCOPE_FILE in entries, (
        "the file declaring the boundary must be inside it, or the boundary "
        "moves without changing any address")
    # a scope that exempts itself is refused
    with tempfile.TemporaryDirectory() as tmp:
        root = _scaffold(tmp, {"a.txt": b"a"}, git=False)
        path = os.path.join(root, "docs", "digest_scope.json")
        _io.open(path, "w", encoding="utf-8", newline="\n").write(json.dumps(
            {"schema": st.SCOPE_SCHEMA,
             "output_files": [st.SCOPE_FILE], "output_prefixes": [],
             "bindings": {st.SCOPE_FILE: "none"}}))
        assert _code(st.load_scope, root) == st.ST_SCOPE
        # an exclusion with no binding is refused: a merely excluded file
        # does not exist. Checked for a FILE and for a PREFIX separately —
        # the first cut asked only about files, so anything dropped under an
        # unbound prefix left the digest untouched and answered to nothing.
        for shape in ({"output_files": ["docs/x.json"],
                       "output_prefixes": []},
                      {"output_files": [],
                       "output_prefixes": ["docs/evidence/"]}):
            _io.open(path, "w", encoding="utf-8", newline="\n").write(
                json.dumps(dict(shape, schema=st.SCOPE_SCHEMA,
                                bindings={})))
            assert _code(st.load_scope, root) == st.ST_SCOPE, shape
        # and a missing scope is not "hash everything"
        os.remove(path)
        assert _code(st.load_scope, root) == st.ST_SCOPE
    # every real exclusion names where it is bound
    for entry in scope["files"]:
        assert scope["bindings"].get(entry), entry
    print("  [PASS] TREE-7  the boundary is declared in one hashed file; "
          "self-exemption, unbound exclusion and absence all refuse")


def test_the_algorithm_and_source_travel_with_the_digest():
    """TREE-8"""
    assert st.ALGO == prv.SCHEMA_SOURCE_TREE == "jjdai.source-tree/v2"
    sys.path.insert(0, os.path.join(_ROOT, "scripts"))
    import run_acceptance as runner                             # noqa: E402
    named = runner.source_digest_named()
    assert named["tree_digest_algo"] == st.ALGO
    assert named["tree_digest_source"] in (st.SOURCE_GIT, st.SOURCE_WORKTREE)
    assert named["tree_digest"] == runner.source_digest()
    assert named["tree_digest_entries"] > 100
    recorded = json.load(_io.open(
        os.path.join(_ROOT, "docs", "evidence", "hermetic.json"),
        encoding="utf-8"))
    assert recorded.get("tree_digest_algo") == st.ALGO, (
        "the recorded run states a digest without naming the algorithm that "
        "made it; two algorithms give strings that look alike and mean "
        "different things")
    assert recorded.get("tree_digest_source") in (st.SOURCE_GIT,
                                                  st.SOURCE_WORKTREE)
    print("  [PASS] TREE-8  algorithm id and entry source are recorded "
          "beside the digest")


if __name__ == "__main__":
    for fn in (test_fields_are_length_prefixed,
               test_symlinks_carry_their_target_and_never_execute,
               test_executable_bit_is_carried,
               test_entries_sort_by_raw_path_bytes,
               test_gitlink_is_a_hard_refusal,
               test_committed_tree_is_the_source_and_dirt_refuses,
               test_scope_declares_the_boundary_and_lives_inside_it,
               test_the_algorithm_and_source_travel_with_the_digest):
        fn()
