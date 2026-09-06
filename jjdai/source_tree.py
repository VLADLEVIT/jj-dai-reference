# -*- coding: utf-8 -*-
"""
jjdai.source_tree — `jjdai.source-tree/v2`, defined in bytes
============================================================
ADR-022 D11. The first link of the evidential chain: WHICH TREE. Broken
here, nothing downstream means anything, so the encoding is spelled out
rather than left to whatever `os.walk` and `read()` happened to do.

WHAT IS HASHED, AND FROM WHERE. The digest takes the **committed tree of
the commit the tag is placed on**, after the worktree and the index are
verified clean. Not the working copy, not the index, and not "whichever of
the two we happen to be looking at". A run on a dirty tree REFUSES: without
that, untracked files and local modes that depend on umask and clone
settings walk into the address of the tree.

The v1 digest, still in `scripts/run_acceptance.py`, hashed the working
copy and fed `path ‖ NUL ‖ hex(sha256(body)) ‖ LF` into one stream. It was
honest work and it has two properties this one does not: it dereferenced
symlinks, so the target of a link was invisible, and its fields were not
length-prefixed, so a path ending in the right bytes could in principle be
confused with a payload. v2 is length-prefixed throughout and never
dereferences.

SUBJECT TREE AGAINST OUTPUT SET. Everything shipped is hashed — that is the
subject tree. The evidence artefacts a run PRODUCES are the output set, and
they are listed in `docs/digest_scope.json`, which is itself in the subject
tree. So the boundary cannot be moved quietly: widening the exclusion list
changes the digest of the file that declares it.

    An exclusion is always matched by a binding somewhere else. A merely
    excluded file does not exist.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess

from . import provenance as _prv

#: Imported, not spelt again: `jjdai.provenance` is the one home of the
#: ADR-022 vocabulary, and a serialized value written twice is how one
#: value quietly becomes two. PROV-1 caught this file doing it.
ALGO = _prv.SCHEMA_SOURCE_TREE
PREFIX = b"JJDAI:SOURCE-TREE:v2\x00"

ENTRY_REGULAR = 0x01
ENTRY_SYMLINK = 0x02

SCOPE_FILE = "docs/digest_scope.json"
SCOPE_SCHEMA = "jjdai.digest-scope/v1"

#: Where the entries came from. Recorded beside the digest, because the two
#: sources are not interchangeable and a reader must not have to guess.
SOURCE_GIT = "git-committed-tree"
SOURCE_WORKTREE = "worktree"


class SourceTreeError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


ST_DIRTY = "TREE_DIRTY"
ST_NOT_GIT = "NOT_A_GIT_TREE"
ST_GITLINK = "GITLINK_PRESENT"
ST_SCOPE = "SCOPE_INVALID"
ST_MISSING = "ENTRY_MISSING"


def _fail(code, message):
    return SourceTreeError(code, message)


Entry = None  # placeholder kept out of the namedtuple export surface


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #

def load_scope(root: str) -> dict:
    """Read `docs/digest_scope.json` — the output set, and nothing else.

    Fail-closed on absence. The scope file is what makes the boundary
    auditable, and a missing one would mean the boundary is wherever the
    code says it is this week.
    """
    path = os.path.join(root, *SCOPE_FILE.split("/"))
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise _fail(ST_SCOPE, f"{SCOPE_FILE} unreadable: {e}") from None
    if doc.get("schema") != SCOPE_SCHEMA:
        raise _fail(ST_SCOPE, f"{SCOPE_FILE} must declare {SCOPE_SCHEMA!r}")
    files = doc.get("output_files")
    prefixes = doc.get("output_prefixes")
    if not isinstance(files, list) or not isinstance(prefixes, list):
        raise _fail(ST_SCOPE,
                    f"{SCOPE_FILE} must list output_files and "
                    f"output_prefixes")
    for declared in list(files) + list(prefixes):
        if not isinstance(declared, str) or not declared:
            raise _fail(ST_SCOPE,
                        f"{SCOPE_FILE}: {declared!r} is not a path")
    # The scope file describes the OUTPUT set, so it must not exclude
    # itself: a boundary that can be moved by the file it lives in, without
    # changing that file's own contribution, is not a boundary.
    if SCOPE_FILE in files or any(SCOPE_FILE.startswith(p)
                                  for p in prefixes):
        raise _fail(
            ST_SCOPE,
            f"{SCOPE_FILE} excludes itself. It is in the SUBJECT tree by "
            f"construction (ADR-022 D11): the boundary cannot be moved "
            f"silently, and it could be if the declaration were outside "
            f"what the digest covers.")
    bindings = doc.get("bindings")
    if not isinstance(bindings, dict):
        raise _fail(ST_SCOPE, f"{SCOPE_FILE} must map every output to the "
                              f"field that binds it elsewhere")
    for entry in list(files) + list(prefixes):
        if not bindings.get(entry):
            raise _fail(
                ST_SCOPE,
                f"{entry!r} is excluded from the digest and bound nowhere. "
                f"A merely excluded file does not exist: `hermetic.json` is "
                f"held by `acceptance_hash`, the SBOM by `sbom_hash`, the "
                f"bundle by `bundle_hash`. An exclusion without a binding "
                f"is a hole.")
    return {"files": tuple(files), "prefixes": tuple(prefixes),
            "bindings": dict(bindings)}


def in_output_set(rel: str, scope: dict) -> bool:
    return rel in scope["files"] or rel.startswith(tuple(scope["prefixes"]))


# --------------------------------------------------------------------------- #
# Entries
# --------------------------------------------------------------------------- #

def _git(root: str, *args) -> str:
    proc = subprocess.run(("git",) + args, cwd=root, capture_output=True,
                          text=True)
    if proc.returncode != 0:
        raise _fail(ST_NOT_GIT,
                    f"git {' '.join(args)} failed: "
                    f"{(proc.stderr or '').strip()}")
    return proc.stdout


def assert_clean(root: str) -> None:
    """Refuse a dirty worktree or index.

    `--porcelain` reports both, and untracked files with it. A digest taken
    over a dirty tree names something no one else can reconstruct, which is
    the one thing a content address must never do.
    """
    status = _git(root, "status", "--porcelain", "--untracked-files=all")
    if status.strip():
        raise _fail(
            ST_DIRTY,
            "the worktree or index is dirty:\n" +
            "\n".join("  " + line for line in status.strip().splitlines()[:20]) +
            "\nThe digest takes the COMMITTED tree of the tag target "
            "(ADR-022 D11); on a dirty tree it would address something "
            "nobody can reproduce.")


def git_entries(root: str, rev: str = "HEAD"):
    """(path, entry_type, executable, payload) from the committed tree."""
    out = _git(root, "ls-tree", "-r", "-z", rev)
    entries = []
    for record in out.split("\0"):
        if not record:
            continue
        meta, path = record.split("\t", 1)
        mode, obj_type, sha = meta.split()
        if obj_type == "commit" or mode == "160000":
            raise _fail(
                ST_GITLINK,
                f"gitlink/submodule at {path!r}: its content is not in this "
                f"tree, so a digest over this tree cannot address it. "
                f"Presence is a hard refusal (ADR-022 D11), not a skip.")
        payload = subprocess.run(("git", "cat-file", "blob", sha), cwd=root,
                                 capture_output=True).stdout
        if mode == "120000":
            entries.append((path, ENTRY_SYMLINK, 0, payload))
        else:
            executable = 1 if int(mode, 8) & 0o111 else 0
            entries.append((path, ENTRY_REGULAR, executable, payload))
    return entries


def worktree_entries(root: str):
    """The same shape, read from files on disk.

    A fallback for a tree that is not a git checkout — an unpacked archive,
    for instance. It is NOT the normative source and the caller records
    which one produced a digest, because a worktree can hold what no commit
    contains.
    """
    entries = []
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(names + [d for d in dirs
                                    if os.path.islink(os.path.join(base, d))]):
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                entries.append((rel, ENTRY_SYMLINK, 0,
                                os.readlink(full).encode("utf-8")))
                continue
            if not os.path.isfile(full):
                continue
            mode = os.lstat(full).st_mode
            with open(full, "rb") as fh:
                payload = fh.read()
            entries.append((rel, ENTRY_REGULAR,
                            1 if mode & 0o111 else 0, payload))
    return entries


_SKIP_DIRS = ("__pycache__", ".git", ".pytest_cache", ".typeset", "build",
              "dist", ".eggs", ".mypy_cache", ".ruff_cache", "node_modules",
              ".idea", ".vscode")


# --------------------------------------------------------------------------- #
# The digest
# --------------------------------------------------------------------------- #

def encode_entry(path: str, entry_type: int, executable: int,
                 payload: bytes) -> bytes:
    """One block, every field length-prefixed.

    Length prefixes are the point: without them a path ending in the bytes
    of a payload and a payload beginning with the bytes of a path can be
    rearranged into the same stream, and two different trees hash alike.
    """
    raw = path.encode("utf-8")
    if entry_type == ENTRY_SYMLINK and executable:
        # `lstat` reports the executable bits of the LINK, which are set on
        # every symlink on most systems. Applying the general rule would put
        # 1 here always and the field would stop distinguishing anything.
        raise _fail(ST_SCOPE, "a symlink entry is never executable")
    return (struct.pack("<Q", len(raw)) + raw +
            bytes([entry_type, executable]) +
            struct.pack("<Q", len(payload)) + payload)


def digest(root: str, *, source: str = None, rev: str = "HEAD",
           require_clean: bool = True) -> tuple:
    """Return `(digest_hex, source, entry_count)`.

    `source` is returned rather than assumed, and written beside the digest
    wherever it is recorded — `hermetic.json`, the `ReleaseStatement`, the
    tag annotation. A digest without the name of the algorithm and the
    origin of its entries compares to nothing.
    """
    scope = load_scope(root)
    if source is None:
        source = SOURCE_GIT if os.path.isdir(os.path.join(root, ".git")) \
            else SOURCE_WORKTREE
    if source == SOURCE_GIT:
        if require_clean:
            assert_clean(root)
        entries = git_entries(root, rev)
    elif source == SOURCE_WORKTREE:
        entries = worktree_entries(root)
    else:
        raise _fail(ST_SCOPE, f"unknown entry source {source!r}")

    kept = [e for e in entries if not in_output_set(e[0], scope)]
    # Sorted by the RAW BYTES of the path, not by the decoded string: the
    # two orders differ once a path leaves ASCII, and a digest that depends
    # on the locale of whoever computed it is not a content address.
    kept.sort(key=lambda e: e[0].encode("utf-8"))
    h = hashlib.sha256()
    h.update(PREFIX)
    for path, entry_type, executable, payload in kept:
        h.update(encode_entry(path, entry_type, executable, payload))
    return h.hexdigest(), source, len(kept)
