#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T-TOOLSET, part one — the `pure` boundary and the manifest that declares it.

ADR-022 D7, D8, D9, D10. Until this drop `pure` was a sentence: "no writes
outside one preopen directory", which permits writing inside it and so was
never a boundary. r6.9.1 replaced the definition; these checks are what make
the replacement executable, and every one of them is written against the
formulation being replaced rather than against the code that implements it.

  PURE-1  The allowlist is exactly what D9 names, and a module importing
          anything else does not instantiate — checked on module BYTES, so
          the answer does not depend on the input reaching the call.
  PURE-2  Clocks, entropy, sockets and path_open are refused with the clause
          that refuses them, not with a generic message.
  PURE-3  Malformed and non-wasm input fails CLOSED: an unreadable module is
          never read as importing nothing.
  PURE-4  Zero preopens: every spelling of the flag is refused, and the
          invocation the profile builds carries none.
  PURE-5  Limits are declared per tool; a missing limit is a refusal and not
          "unlimited by default".
  TSET-1  Manifest v2 requires an effect class, a recipe hash and limits per
          tool, and refuses the classes whose reversal machinery is Ф2.
  TSET-2  The manifest is signed under the TOOLSET domain by a
          `toolset_authorization` key — not under the release domain, and
          not by a release key.
  TSET-3  The interim authorization form refuses to load once the Gauntlet
          capability is registered.
  TSET-4  The loader hashes real bytes against the MANIFEST; the
          materialization file is never a source of truth.
  TSET-5  The tree holds recipes and no binaries, and an unfilled recipe
          refuses by its placeholder instead of validating.
"""
import io as _io
import json
import os
import struct
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai import provenance as prv                           # noqa: E402
from jjdai.crypto import H_hex, SigningKey                    # noqa: E402
from kernel import isolation                                  # noqa: E402
from kernel import toolset as ts                              # noqa: E402
from kernel import wasm_pure as wp                            # noqa: E402


# --------------------------------------------------------------------------- #
# Hand-built modules. The parser must be exercised on real bytes: a parser
# checked only against its own output proves nothing about a compiler's.
# --------------------------------------------------------------------------- #

_SK = SigningKey(b"\x31" * 32)
_KEY_ID = "toolset-boundary-key"


def _resolver(key_id):
    if key_id != _KEY_ID:
        return None
    return {"public": _SK.public.hex(),
            "key_domain": prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
            "revoked": False}


def _uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _nm(s):
    b = s.encode("utf-8")
    return _uleb(len(b)) + b


def _module(imports):
    body = _uleb(len(imports))
    for mod, name in imports:
        body += _nm(mod) + _nm(name) + b"\x00" + _uleb(0)
    section = b"\x02" + _uleb(len(body)) + body
    return wp.WASM_MAGIC + struct.pack("<I", 1) + section


_W = wp.WASI_MODULE
PURE_MODULE = _module([(_W, "fd_read"), (_W, "fd_write"), (_W, "proc_exit")])


def _code(fn, *args):
    try:
        fn(*args)
    except (wp.PureBoundaryError, ts.ToolsetError) as exc:
        return exc.code, str(exc)
    return None, ""


def test_allowlist_is_checked_on_bytes():
    """PURE-1"""
    assert wp.PURE_IMPORT_ALLOWLIST == frozenset({
        (_W, "fd_read"), (_W, "fd_write"), (_W, "proc_exit")})
    assert [i.name for i in wp.check_pure_imports(PURE_MODULE)] == \
        ["fd_read", "fd_write", "proc_exit"]
    # a module with no imports at all is pure
    assert wp.check_pure_imports(
        wp.WASM_MAGIC + struct.pack("<I", 1)) == ()
    # an unnamed WASI call is refused by the allowlist, not by the named list
    code, _ = _code(wp.check_pure_imports, _module([(_W, "fd_seek")]))
    assert code == wp.PURE_IMPORT_DENIED
    # the same NAME from another module must not ride in on the allowlist
    code, _ = _code(wp.check_pure_imports, _module([("env", "fd_write")]))
    assert code == wp.PURE_IMPORT_DENIED
    print("  [PASS] PURE-1  allowlist is exactly three imports, matched on "
          "module AND name, read from bytes")


def test_clocks_entropy_and_paths_refuse_by_clause():
    """PURE-2"""
    for name in ("clock_time_get", "random_get", "path_open",
                 "fd_prestat_get", "sock_send"):
        code, why = _code(wp.check_pure_imports,
                          _module([(_W, "fd_write"), (_W, name)]))
        assert code == wp.PURE_IMPORT_DENIED
        assert wp.PURE_DENIED_BY_NAME[name].split(":")[0] in why, (
            f"{name} was refused generically; the refusal must cite the "
            f"clause, or an operator cannot tell a denied clock from a "
            f"denied socket")
    # the consequence D9 states in advance: full wasi-libc does not link
    code, _ = _code(wp.check_pure_imports,
                    _module([(_W, "fd_prestat_get"),
                             (_W, "fd_prestat_dir_name"), (_W, "fd_write")]))
    assert code == wp.PURE_IMPORT_DENIED
    print("  [PASS] PURE-2  clocks, entropy, sockets and paths refuse with "
          "the clause that refuses them")


def test_unreadable_module_fails_closed():
    """PURE-3"""
    good = _module([(_W, "fd_read")])
    cases = ((b"", wp.PURE_NOT_WASM),
             (b"#!/bin/sh\n", wp.PURE_NOT_WASM),
             (wp.WASM_MAGIC + struct.pack("<I", 2), wp.PURE_NOT_WASM),
             (good[:-2], wp.PURE_MALFORMED),
             (wp.WASM_MAGIC + struct.pack("<I", 1) + b"\x02" + _uleb(99) +
              b"\x00", wp.PURE_MALFORMED))
    for data, want in cases:
        code, _ = _code(wp.check_pure_imports, data)
        assert code == want, (
            f"expected {want}, got {code!r}: a module that cannot be parsed "
            f"must never read as importing nothing")
    print("  [PASS] PURE-3  five unreadable inputs fail closed, none reads "
          "as importing nothing")


def test_zero_preopens():
    """PURE-4"""
    for flag in (["--dir", "/tmp::/work"], ["--dir=/tmp::/work"],
                 ["--mapdir", "/tmp::/work"], ["--mapdir=/tmp::/work"]):
        code, why = _code(wp.check_no_preopens,
                          ["wasmtime", "run"] + flag + ["m.wasm"])
        assert code == wp.PURE_PREOPEN_PRESENT
        assert "ZERO preopen" in why
    wp.check_no_preopens(["wasmtime", "run", "m.wasm"])
    # and the profile's own invocation carries none. Built through the real
    # resolver so the check covers the line that used to add the flag.
    with tempfile.TemporaryDirectory() as tmp:
        tools = os.path.join(tmp, "wasm-toolset")
        os.makedirs(tools)
        mod = os.path.join(tools, "t.wasm")
        with open(mod, "wb") as f:
            f.write(PURE_MODULE)
        _write_manifest(tools, sha256=H_hex(PURE_MODULE))
        prof = isolation.WasmWasiProfile(tmp, tools_dir=tools,
                                         key_resolver=_resolver)
        cmd = prof.wasm_argv(["t", "-n"], os.path.join(tmp, "work"))
        assert "--dir" not in cmd and not any(
            str(c).startswith("--dir") for c in cmd), cmd
        assert cmd[-2:] == ["--", "-n"]
    print("  [PASS] PURE-4  four preopen spellings refused; the profile's "
          "own invocation carries none")


def test_limits_are_declared_not_defaulted():
    """PURE-5"""
    assert wp.Limits._fields == ("fuel", "guest_memory_bytes",
                                 "host_memory_bytes", "output_bytes")
    got = wp.check_limits_declared({"fuel": 1, "guest_memory_bytes": 1 << 20,
                                    "output_bytes": 3})
    # the guest bound and the host bound are TWO numbers. One number for
    # both was applied as RLIMIT_AS over the whole runtime, so a guest cap
    # small enough to mean anything killed wasmtime before the guest ran.
    assert got.host_memory_bytes > got.guest_memory_bytes
    for bad in ({}, {"fuel": 5},
                {"fuel": 0, "guest_memory_bytes": 1, "output_bytes": 1},
                {"fuel": True, "guest_memory_bytes": 1, "output_bytes": 1},
                {"fuel": 1, "guest_memory_bytes": 1 << 20,
                 "host_memory_bytes": 1 << 10, "output_bytes": 1}):
        code, why = _code(wp.check_limits_declared, bad)
        assert code == wp.PURE_MALFORMED, (bad, code)
        assert ("unlimited by default" in why or
                "must exceed guest_memory_bytes" in why), why
    # a breach names a code; it never truncates the output, because a
    # truncated output is a wrong answer that looks like an answer
    assert wp.breach_code("fuel") == wp.PURE_LIMIT_FUEL
    assert wp.breach_code("output_bytes") == wp.PURE_LIMIT_OUTPUT
    print("  [PASS] PURE-5  three limits required per tool; absence refuses")


# --------------------------------------------------------------------------- #
# Manifest
# --------------------------------------------------------------------------- #

def _lax(key_id):
    """A resolver that accepts the fixture key. Signature verification has
    its own checks (TSET-2); these fixtures are about the SHAPE rules, and
    re-signing every mutated document would test the signer instead."""
    return {"public": _SK.public.hex(),
            "key_domain": prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
            "revoked": False, "_lax": True}


def _signed(doc):
    """Sign a fixture document so the SHAPE rules can be exercised without
    each mutation having to be hand-signed. Signature VALIDITY has its own
    subject in TSET-2; here a valid signature is only the price of reaching
    the rule under test."""
    body = {k: v for k, v in doc.items() if k != "signature"}
    doc.setdefault("signer", {"key_id": _KEY_ID,
                              "key_domain": prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
                              "domain": prv.DOMAIN_TOOLSET_MANIFEST})
    doc["signer"]["key_id"] = _KEY_ID
    body = {k: v for k, v in doc.items() if k != "signature"}
    doc["signature"] = _SK.sign(ts.signing_bytes(body)).hex()
    return doc


def _manifest_doc(**over):
    doc = {
        "schema": prv.SCHEMA_TOOLSET_MANIFEST,
        "authorization_form": prv.AUTHORIZATION_FORM_INTERIM,
        "sunset_condition": prv.SUNSET_CONDITION_GAUNTLET,
        "signer": {"key_id": "k1",
                   "key_domain": prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
                   "domain": prv.DOMAIN_TOOLSET_MANIFEST},
        "signature": "ab" * 32,
        "tools": {"t": {"module": "t.wasm", "sha256": "cd" * 32,
                        "effect_class": "pure", "recipe_hash": "ef" * 32,
                        "limits": {"fuel": 10 ** 8, "guest_memory_bytes": 1 << 24,
                                   "output_bytes": 1 << 20}}},
    }
    doc.update(over)
    return _signed(doc)


def _write_manifest(tools_dir, sha256):
    doc = _manifest_doc()
    doc["tools"]["t"]["sha256"] = sha256
    doc["signer"]["key_id"] = _KEY_ID
    body = {k: v for k, v in doc.items() if k != "signature"}
    doc["signature"] = _SK.sign(ts.signing_bytes(body)).hex()
    with _io.open(os.path.join(tools_dir, ts.MANIFEST_FILE), "w",
                  encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2)
    return doc


def test_manifest_v2_requires_class_recipe_and_limits():
    """TSET-1"""
    ts.validate_manifest(_manifest_doc(), resolver=_lax)
    doc = _manifest_doc()
    del doc["tools"]["t"]["effect_class"]
    code, why = _code(lambda d: ts.validate_manifest(_signed(d), resolver=_lax), doc)
    assert code == ts.MANIFEST_NO_EFFECT_CLASS and "custody" in why
    doc = _manifest_doc()
    del doc["tools"]["t"]["recipe_hash"]
    assert _code(lambda d: ts.validate_manifest(_signed(d), resolver=_lax), doc)[0] == ts.MANIFEST_NO_RECIPE
    doc = _manifest_doc()
    del doc["tools"]["t"]["limits"]
    assert _code(lambda d: ts.validate_manifest(_signed(d), resolver=_lax), doc)[0] == ts.MANIFEST_BAD_SCHEMA
    # the classes above `pure` are refused until their reversal machinery
    # exists, and `unknown` is refused permanently and for another reason
    for cls in ("local_transactional", "external", "unknown"):
        doc = _manifest_doc()
        doc["tools"]["t"]["effect_class"] = cls
        try:
            ts.validate_manifest(_signed(doc), resolver=_lax)
            raise AssertionError(f"{cls} admitted by a v0.6.9 manifest")
        except ValueError:
            pass
    # v1 is not loadable: it has no effect class to declare
    doc = _manifest_doc(schema="jjdai.toolset/v1")
    assert _code(lambda d: ts.validate_manifest(_signed(d), resolver=_lax), doc)[0] == ts.MANIFEST_BAD_SCHEMA
    print("  [PASS] TSET-1  manifest v2 demands class, recipe and limits; "
          "only `pure` is admitted in this drop")


def test_manifest_domain_and_key_are_the_toolset_ones():
    """TSET-2"""
    doc = _manifest_doc()
    doc["signer"]["domain"] = prv.DOMAIN_RELEASE_APPROVAL
    code, why = _code(lambda d: ts.validate_manifest(_signed(d), resolver=_lax), doc)
    assert code == ts.MANIFEST_UNSIGNED and "separate powers" in why
    # the hash prefix must not serve as a signing domain here either
    doc = _manifest_doc()
    doc["signer"]["domain"] = prv.PREFIX_RELEASE_ATTESTATION
    assert _code(lambda d: ts.validate_manifest(_signed(d), resolver=_lax), doc)[0] == ts.MANIFEST_UNSIGNED
    # a release key must not sanction an L2 mutation
    doc = _manifest_doc()
    doc["signer"]["key_domain"] = prv.KEY_DOMAIN_RELEASE_SIGNING
    try:
        ts.validate_manifest(_signed(doc), resolver=_lax)
        raise AssertionError("a release key sanctioned a toolset mutation")
    except prv.ProvenanceValueError:
        pass
    # unsigned refuses: absence of a verifier is not permission
    doc = _manifest_doc()
    doc["signature"] = ""
    assert _code(lambda d: ts.validate_manifest(d, resolver=_lax),
                 doc)[0] == ts.MANIFEST_UNSIGNED
    doc = _manifest_doc()
    del doc["signer"]
    assert _code(lambda d: ts.validate_manifest(d, resolver=_lax),
                 doc)[0] == ts.MANIFEST_UNSIGNED
    # THE defect the audit found: the signer's identity must be INSIDE the
    # signed bytes. Swapping `key_id` for another registered id holding the
    # same public key used to leave the bytes unchanged and the signature
    # valid, so the manifest read as signed by someone else.
    doc = _manifest_doc()
    before = ts.signing_bytes(doc)
    doc["signer"]["key_id"] = "someone-else"
    assert ts.signing_bytes(doc) != before, (
        "the signer's identity is outside the signed bytes: a signature "
        "that does not cover who signed attributes itself to whoever the "
        "file says")
    assert _code(lambda d: ts.validate_manifest(d, resolver=_lax),
                 doc)[0] == ts.MANIFEST_BAD_SIGNATURE
    print("  [PASS] TSET-2  manifest signed under the toolset domain by a "
          "toolset_authorization key, or not loaded")


def test_interim_form_does_not_outlive_its_justification():
    """TSET-3"""
    ts.validate_manifest(_manifest_doc(), resolver=_lax,
                         gauntlet_available=False)
    code, why = _code(lambda d: ts.validate_manifest(
        d, resolver=_lax, gauntlet_available=True), _manifest_doc())
    assert code == ts.MANIFEST_SUNSET
    assert "L2" in why and "Gauntlet" in why
    # the sunset condition must be NAMED; an interim form with no stated end
    # is a permanent form with better manners
    doc = _manifest_doc(sunset_condition="someday")
    assert _code(lambda d: ts.validate_manifest(_signed(d), resolver=_lax), doc)[0] == ts.MANIFEST_UNSIGNED
    print("  [PASS] TSET-3  interim authorization refuses to load once the "
          "Gauntlet capability is registered")


def test_loader_hashes_real_bytes_against_the_manifest():
    """TSET-4"""
    entry = _manifest_doc()["tools"]["t"]
    entry["sha256"] = H_hex(PURE_MODULE)
    ts.check_module_against_manifest("t", entry, PURE_MODULE)
    # drift is reported as drift, before the boundary is even asked
    other = _module([(_W, "fd_write")])
    code, why = _code(ts.check_module_against_manifest, "t", entry, other)
    assert code == ts.MATERIALIZATION_DRIFT
    assert "materialization file is not consulted" in why
    # a module that IS the pinned one is still asked about its imports
    impure = _module([(_W, "clock_time_get")])
    entry2 = dict(entry, sha256=H_hex(impure))
    code, _ = _code(ts.check_module_against_manifest, "t", entry2, impure)
    assert code == wp.PURE_IMPORT_DENIED
    assert ts.MATERIALIZATION_FILE == "toolset-materialization.json"
    print("  [PASS] TSET-4  loader hashes real bytes against the signed "
          "manifest, then checks the boundary")


def _raw(doc) -> bytes:
    """The bytes a manifest ships as. One address, and it is this one."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def test_the_profile_hands_authorization_to_the_door():
    """TSET-7 · the audit of recut2, P0-2

    `toolset_authorizer()` was built, tested and never given to the door it
    guards: `WasmWasiProfile.toolset()` called `load_verified_manifest`
    with the resolver and the gauntlet flag and no `authorization`. The
    third time in this drop a checker stood BESIDE the boundary instead of
    being it — the shape the audit has now named in `environment_matches`,
    in `check_lifecycle_witnessed` and here.
    """
    seen = {}

    def _spy(path, *, resolver, gauntlet_available=False, authorization=None):
        seen["authorization"] = authorization
        raise ts.ToolsetError(ts.MANIFEST_BAD_SCHEMA, "spy")

    with tempfile.TemporaryDirectory() as tmp:
        tools = os.path.join(tmp, "tools")
        os.makedirs(tools)
        marker = object()
        prof = isolation.WasmWasiProfile(tmp, tools_dir=tools,
                                         toolset_authorization=marker)
        real = isolation.toolset_mod.load_verified_manifest
        isolation.toolset_mod.load_verified_manifest = _spy
        try:
            assert prof.toolset() == {}
        finally:
            isolation.toolset_mod.load_verified_manifest = real
        assert seen["authorization"] is marker, (
            "the resolver must reach the door; built and not handed over, "
            "it protects nothing")
        # and a profile given none defaults to none rather than to a
        # permissive value: for a registry that records a key lifecycle the
        # manifest then refuses, which is the fail-closed direction
        assert isolation.WasmWasiProfile(
            tmp, tools_dir=tools).toolset_authorization is None
    print("  [PASS] TSET-7 the profile hands the authorization resolver to "
          "the door it is supposed to guard")


def test_authorization_position_is_resolved_not_declared():
    """TSET-6

    A key valid on [0, 10) signed a manifest declaring
    `authorized_at_witness_seq: 0`, and it loaded — the manifest dated
    itself into the window where its signer was still valid, and the
    signature made that date immutable rather than true. It is the same
    backdating ADR-022 rev 2.1 removed from `ReleaseStatement`, arriving
    through a field instead of an argument, and here it buys more: the
    manifest is what sanctions an L2 mutation, so a false date widens a
    being's hand under a signature that verifies.
    """
    def _lifecycle(key_id):
        key = _lax(key_id)
        key["activated_at_witness_seq"] = 0
        key["revoked_at_witness_seq"] = 10
        return key

    dated = _manifest_doc()
    dated["signer"]["authorized_at_witness_seq"] = 0
    dated = _signed(dated)

    # 1. WITH A LIFECYCLE AND NO RESOLVED POSITION: refused. recut1 read the
    #    manifest's own number here and loaded.
    code, why = _code(lambda d: ts.validate_manifest(d, resolver=_lifecycle),
                      dated)
    assert code == ts.MANIFEST_AUTHZ_UNRESOLVED, (code, why)
    assert "holding the chain" in why

    # 2. A DECLARED POSITION THAT DISAGREES WITH THE RESOLVED ONE: refused.
    #    The manifest may carry the field; it may not be believed by it.
    code, _ = _code(
        lambda d: ts.validate_manifest(d, resolver=_lifecycle,
                                       authorization=lambda h: 7,
                                       raw=_raw(d)), dated)
    assert code == ts.MANIFEST_AUTHZ_UNRESOLVED

    # 3. agreeing, and inside the key's window: loads
    ts.validate_manifest(dated, resolver=_lifecycle,
                         authorization=lambda h: 0, raw=_raw(dated))

    # 4. the resolved position is judged against the registry, so a manifest
    #    authorized at or after the revocation still refuses
    plain = _manifest_doc()
    ts.validate_manifest(plain, resolver=_lifecycle,
                         authorization=lambda h: 9, raw=_raw(plain))
    code, _ = _code(
        lambda d: ts.validate_manifest(d, resolver=_lifecycle,
                                       authorization=lambda h: 10,
                                       raw=_raw(d)), plain)
    assert code == ts.MANIFEST_KEY_REVOKED

    # 5. what is handed to the resolver is the address of THIS document,
    #    whole — the same thing a ReleaseStatement names in
    #    `toolset_manifest_hash`. Anything narrower and the release would
    #    authorize a body, not the bytes that shipped.
    seen = []

    def _watch(digest):
        seen.append(digest)
        return 0

    ts.validate_manifest(plain, resolver=_lifecycle, authorization=_watch,
                         raw=_raw(plain))
    assert seen == [ts.manifest_address(_raw(plain))]
    assert ts.manifest_address(_raw(plain)) != ts.manifest_address(_raw(dated))
    # 6. ONE ADDRESS, and it is the FILE. The assembler writes
    #    `toolset_manifest_hash` as sha256 of the file; recomputing it from
    #    the parsed document gave a different digest for any formatted JSON,
    #    so the two sides addressed different objects and no real manifest
    #    could ever have matched its release.
    pretty = json.dumps(plain, indent=2).encode()
    assert ts.manifest_address(pretty) != ts.manifest_address(_raw(plain))
    assert not hasattr(ts, "manifest_hash")
    code, why = _code(
        lambda d: ts.validate_manifest(d, resolver=_lifecycle,
                                       authorization=lambda h: 0), plain)
    assert code == ts.MANIFEST_AUTHZ_UNRESOLVED and "raw" in why
    # 7. THE BYTES AND THE DOCUMENT ARE ONE OBJECT. The audit of recut3
    #    signed document B and authorized bytes A through the direct API,
    #    and it loaded — signature over one, authorization for the other.
    code, why = _code(
        lambda d: ts.validate_manifest(d, resolver=_lifecycle,
                                       authorization=lambda h: 0,
                                       raw=_raw(dated)), plain)
    assert code == ts.MANIFEST_AUTHZ_UNRESOLVED and "two different" in why
    code, _ = _code(
        lambda d: ts.validate_manifest(d, resolver=_lifecycle,
                                       authorization=lambda h: 0,
                                       raw=b"not json"), plain)
    assert code == ts.MANIFEST_BAD_SCHEMA
    print("  [PASS] TSET-6 the authorization position is resolved from the "
          "release that names the manifest, never declared by it")


def test_tree_holds_recipes_and_no_binaries():
    """TSET-5"""
    root = os.path.join(_ROOT, "deploy", "wasm-toolset")
    recipes = sorted(n for n in os.listdir(os.path.join(root, "recipe"))
                     if n.endswith(".json"))
    assert recipes == ["bc.json", "fmt.json", "jq.json", "jsonschema.json"], \
        recipes
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            assert not name.endswith(".wasm"), (
                f"{name} is a built module in the source tree; recipes live "
                f"in git and binaries travel in the signed release bundle "
                f"(ADR-022 D7)")
    for name in recipes:
        path = os.path.join(root, "recipe", name)
        code, why = _code(ts.load_recipe, path)
        assert code == ts.RECIPE_PLACEHOLDER, (
            f"{name} validated with unfilled pins: a placeholder that passes "
            f"is worse than a missing file, because the missing file is "
            f"noticed (got {code!r})")
        assert "build host" in why
        doc = json.load(_io.open(path, encoding="utf-8"))
        assert doc["format"] == ts.RECIPE_FORMAT
        assert doc["effect_class"] == "pure"
        assert set(ts.RECIPE_FIELDS) <= set(doc)
    # the recipe format is deliberately NOT one of the six frozen schemas:
    # only its hash crosses into a signed object, and reserving a name that
    # never enters the vocabulary would make the reserve mean two things
    assert ts.RECIPE_FORMAT not in prv.SCHEMAS
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "r.json")
        _io.open(p, "w", encoding="utf-8").write('{"format": "wrong"}')
        assert _code(ts.load_recipe, p)[0] == ts.RECIPE_INCOMPLETE
        _io.open(p, "w", encoding="utf-8").write("not json")
        assert _code(ts.load_recipe, p)[0] == ts.RECIPE_INCOMPLETE
        # the hash is over raw bytes, so two encodings of one document are
        # two recipes and cannot share a pin
        _io.open(p, "w", encoding="utf-8", newline="\n").write('{"a": 1}')
        h1 = ts.recipe_hash(p)
        _io.open(p, "w", encoding="utf-8", newline="\n").write('{"a":1}')
        assert ts.recipe_hash(p) != h1
    print("  [PASS] TSET-5  four recipes, zero binaries; unfilled pins "
          "refuse instead of validating")


if __name__ == "__main__":
    for fn in (test_allowlist_is_checked_on_bytes,
               test_clocks_entropy_and_paths_refuse_by_clause,
               test_unreadable_module_fails_closed,
               test_zero_preopens,
               test_limits_are_declared_not_defaulted,
               test_manifest_v2_requires_class_recipe_and_limits,
               test_manifest_domain_and_key_are_the_toolset_ones,
               test_interim_form_does_not_outlive_its_justification,
               test_loader_hashes_real_bytes_against_the_manifest,
               test_tree_holds_recipes_and_no_binaries,
               test_authorization_position_is_resolved_not_declared,
               test_the_profile_hands_authorization_to_the_door):
        fn()
