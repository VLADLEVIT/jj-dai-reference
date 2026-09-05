#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The seven P0 findings of the ADR-022 Block-2 audit, closed and pinned.

Every check here is written as the AUDIT ran it: the same input, through the
same door. Five of the seven were found by feeding the tree values nobody
had thought to try, and the sixth and seventh by asking what the runtime
actually does rather than what the manifest says — so these are written
against the defect, not against the fix.

  RP0-1  `check_effect_class` is TOTAL. It used to refuse the names it knew
         and return None for everything else, so "made_up", "PURE", "", None
         and 42 all passed — into the loader, which trusts it as its one
         door.
  RP0-2  A debt event is an object. A bare-string history closed a position
         with no `evidence_ref`, because the reference was only checked when
         the event happened to be a mapping.
  RP0-3  RELEASE_ATTESTED carries its four fields or does not exist. An
         emittable kind with no required content is worse than a reserved
         one: the reserve at least refuses.
  RP0-4  ONE DOOR. `kernel.isolation` used to read the manifest itself and
         never call the validator, so an unsigned manifest with no
         authorization form, no sunset, no recipe hash and no limits
         reported `available = (True, "")` and executed.
  RP0-5  The signature is VERIFIED, not merely present. `{"key_id":
         "nonexistent", "signature": "not-a-signature"}` used to load.
         Without a resolver the profile is unavailable — absence of a
         checker is not permission.
  RP0-6  A limit is ENFORCED. Exceeding the declared output gives a named
         refusal with NO output; the truncated success the baseline sandbox
         returns is a wrong answer that looks like an answer.
  RP0-7  stdin is an explicit pipe this process writes and closes. It used
         to be unset, so the guest saw EOF or INHERITED the host's stdin
         depending on how the daemon was started.
  RP0-8  Fuel and guest memory carry their OWN reason codes; two of D9's
         three limits used to come back as a bare exit code. Guest and host
         memory are separate numbers.
  RP0-9  The output limit is the TOTAL of both streams: `max(out, err)` let
         40 + 40 bytes past a 64-byte cap.
  RP0-10 A guest that talks before it listens does not deadlock — stdin is
         fed inside the same selector loop as the output streams.
"""
import io as _io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from jjdai import provenance as prv                           # noqa: E402
from jjdai import witness as wit                              # noqa: E402
from jjdai.crypto import H_hex, SigningKey                    # noqa: E402
from jjdai.custody import check_effect_class                  # noqa: E402
from kernel import isolation as ISO                           # noqa: E402
from kernel import toolset as ts                              # noqa: E402
from kernel import wasm_pure as wp                            # noqa: E402

_SK = SigningKey(b"\x41" * 32)
_KEY_ID = "p0-closure-key"


def _resolver(key_id, *, revoked=False, domain=None):
    if key_id != _KEY_ID:
        return None
    return {"public": _SK.public.hex(),
            "key_domain": domain or prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
            "revoked": revoked}


def _module(tag=b"OK"):
    payload = bytes([len(tag)]) + tag
    return (b"\0asm" + struct.pack("<I", 1) + b"\x00" +
            bytes([len(payload)]) + payload)


def _shim(dirpath, body):
    path = os.path.join(dirpath, "wasmtime")
    with _io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("#!/bin/sh\n"
                'case "$2" in --help) printf %s "fuel=N max-memory-size=N";'
                " exit 0;; esac\n" + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP |
             stat.S_IXOTH)
    return path


def _toolset_dir(tmp, *, limits=None, shim_body='cat\n', signed=True):
    tools = os.path.join(tmp, "tools")
    os.makedirs(tools, exist_ok=True)
    rt = _shim(tools, shim_body)
    mod = os.path.join(tools, "t.wasm")
    with open(mod, "wb") as f:
        f.write(_module())
    doc = {
        "schema": prv.SCHEMA_TOOLSET_MANIFEST,
        "authorization_form": prv.AUTHORIZATION_FORM_INTERIM,
        "sunset_condition": prv.SUNSET_CONDITION_GAUNTLET,
        "tools": {"t": {"module": "t.wasm", "sha256": H_hex(_module()),
                        "effect_class": "pure", "recipe_hash": "ef" * 32,
                        "limits": limits or {"fuel": 10 ** 8,
                                             "guest_memory_bytes": 1 << 26,
                                             "output_bytes": 1 << 16}}},
    }
    if signed:
        body = {k: v for k, v in doc.items() if k != "signature"}
        doc["signer"] = {"key_id": _KEY_ID,
                         "key_domain": prv.KEY_DOMAIN_TOOLSET_AUTHORIZATION,
                         "domain": prv.DOMAIN_TOOLSET_MANIFEST}
        body = {k: v for k, v in doc.items() if k != "signature"}
        doc["signature"] = _SK.sign(ts.signing_bytes(body)).hex()
    with _io.open(os.path.join(tools, ts.MANIFEST_FILE), "w",
                  encoding="utf-8", newline="\n") as f:
        json.dump(doc, f)
    return tools, rt, doc


def _refuses(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except Exception:
        return True
    return False


def test_effect_class_checker_is_total():
    """RP0-1"""
    check_effect_class("pure")
    for value in ("made_up", "PURE", "", None, 42, b"pure", ["pure"],
                  " pure", "pure "):
        assert _refuses(check_effect_class, value), (
            f"{value!r} passed the one door the loader trusts; a checker "
            f"with a fall-through is fail-closed only on the cases somebody "
            f"remembered")
    print("  [PASS] RP0-1  effect-class checker is total; nine non-classes "
          "refused, exact match only")


def test_debt_event_is_an_object():
    """RP0-2"""
    # The refusal must be the SHAPE rule and must be a ProvenanceValueError.
    # Asserting only "something was raised" would pass on an AttributeError
    # from calling .get() on a string — the rule deleted, the check still
    # green. That is the third time in this drop a check has been carried by
    # a failure it was not about, so it is pinned by type AND by message.
    def _why(history):
        try:
            prv.project_debt(history)
        except prv.ProvenanceValueError as exc:
            return str(exc)
        except Exception as exc:                       # noqa: BLE001
            raise AssertionError(
                f"refused by {type(exc).__name__} rather than by the rule: "
                f"{exc}") from None
        raise AssertionError(f"{history!r} was projected")

    for history in (["DEBT_OPENED", "DEBT_CLOSED"], ["DEBT_OPENED"],
                    [{"event": "DEBT_OPENED"}, "DEBT_CANCELLED"]):
        assert "is not an object" in _why(history), history
    assert prv.project_debt(
        [{"event": "DEBT_OPENED"},
         {"event": "DEBT_CLOSED", "evidence_ref": "tests/x"}]) == \
        prv.DEBT_SETTLED
    print("  [PASS] RP0-2  a debt event is an object; no shape of argument "
          "reaches a terminal state without its reference")


def test_release_attested_carries_its_four_fields():
    """RP0-3"""
    with tempfile.TemporaryDirectory() as tmp:
        chain = wit.WitnessChain(SigningKey.generate(),
                                 anchor=wit.LocalAnchor(),
                                 log_path=os.path.join(tmp, "w.jsonl"))
        for provenance in (None, {}, {"attestation_hash": "a"},
                           {"attestation_hash": "a", "statement_hash": "b",
                            "version": "v0.6.9"}):
            assert _refuses(chain.append, prv.KIND_RELEASE_ATTESTED,
                            provenance=provenance,
                            semantic_digest="ab" * 16), provenance
        assert not chain.records, "an incomplete attestation reached the chain"
        chain.append(prv.KIND_RELEASE_ATTESTED, semantic_digest="ab" * 16,
                     provenance={"attestation_hash": "a",
                                 "statement_hash": "b", "version": "v0.6.9",
                                 "tree_digest": "c"})
        assert chain.records[-1]["kind"] == prv.KIND_RELEASE_ATTESTED
    print("  [PASS] RP0-3  an incomplete RELEASE_ATTESTED never reaches the "
          "chain; four empty shapes refused")


def test_the_validator_is_the_door():
    """RP0-4"""
    with tempfile.TemporaryDirectory() as tmp:
        tools, rt, _doc = _toolset_dir(tmp)
        # the audit's manifest: v2 schema, and nothing else
        with _io.open(os.path.join(tools, ts.MANIFEST_FILE), "w",
                      encoding="utf-8", newline="\n") as f:
            json.dump({"schema": prv.SCHEMA_TOOLSET_MANIFEST,
                       "tools": {"t": {"module": "t.wasm",
                                       "sha256": H_hex(_module())}}}, f)
        prof = ISO.WasmWasiProfile(tmp, tools_dir=tools, wasmtime=rt,
                                   key_resolver=_resolver)
        assert prof.toolset() == {}, "an unvalidated manifest was loaded"
        assert prof.available()[0] is False
        assert prof.manifest_error(), "the profile could not say why"
        assert _refuses(prof.run, ["t"]), "execution went round the door"
        # and one filename, not two
        assert ts.MANIFEST_FILE == "toolset-manifest.json"
        assert ISO.LEGACY_MANIFEST_FILE == "toolset.json"
    print("  [PASS] RP0-4  availability, capabilities and execution all "
          "arrive through load_verified_manifest")


def test_the_signature_is_verified():
    """RP0-5"""
    with tempfile.TemporaryDirectory() as tmp:
        tools, rt, doc = _toolset_dir(tmp)
        path = os.path.join(tools, ts.MANIFEST_FILE)
        assert sorted(ts.load_verified_manifest(
            path, resolver=_resolver)["tools"]) == ["t"]
        # no resolver at all: unavailable, not permissive
        code, _ = _err(lambda: ts.load_verified_manifest(path, resolver=None))
        assert code == ts.MANIFEST_NO_RESOLVER
        # the audit's own probe
        forged = json.loads(json.dumps(doc))
        forged["signer"]["key_id"] = "nonexistent"
        forged["signature"] = "not-a-signature"
        with _io.open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(forged, f)
        code, _ = _err(lambda: ts.load_verified_manifest(
            path, resolver=_resolver))
        assert code == ts.MANIFEST_UNKNOWN_KEY, code
        # and the substitution the audit ran: a DIFFERENT registered key_id
        # holding the same public key. It used to leave the signed bytes
        # untouched and the signature valid.
        swapped = json.loads(json.dumps(doc))
        swapped["signer"]["key_id"] = "twin-of-" + _KEY_ID
        with _io.open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(swapped, f)
        code, _ = _err(lambda: ts.load_verified_manifest(
            path, resolver=lambda k: _resolver(_KEY_ID)))
        assert code == ts.MANIFEST_BAD_SIGNATURE, code
        # a body changed after signing
        tampered = json.loads(json.dumps(doc))
        tampered["tools"]["t"]["sha256"] = "aa" * 32
        with _io.open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(tampered, f)
        code, _ = _err(lambda: ts.load_verified_manifest(
            path, resolver=_resolver))
        assert code == ts.MANIFEST_BAD_SIGNATURE, code
        # a revoked key, and a key the REGISTRY records under another domain
        with _io.open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f)
        code, _ = _err(lambda: ts.load_verified_manifest(
            path, resolver=lambda k: _resolver(k, revoked=True)))
        assert code == ts.MANIFEST_KEY_REVOKED, code
        code, _ = _err(lambda: ts.load_verified_manifest(
            path, resolver=lambda k: _resolver(
                k, domain=prv.KEY_DOMAIN_RELEASE_SIGNING)))
        assert code == ts.MANIFEST_UNKNOWN_KEY, code
    print("  [PASS] RP0-5  signature verified over the canonical body; "
          "forged, tampered, revoked and mis-domained keys all refuse")


def _err(fn):
    try:
        fn()
    except ts.ToolsetError as exc:
        return exc.code, str(exc)
    except Exception as exc:                       # noqa: BLE001
        return type(exc).__name__, str(exc)
    return None, ""


def test_output_limit_refuses_instead_of_truncating():
    """RP0-6"""
    with tempfile.TemporaryDirectory() as tmp:
        # a runtime that floods far past the declared output limit
        tools, rt, _doc = _toolset_dir(
            tmp, limits={"fuel": 10 ** 8, "guest_memory_bytes": 1 << 26,
                         "output_bytes": 64},
            shim_body='i=0\nwhile [ $i -lt 200 ]; do '
                      'echo "0123456789012345678901234567890123456789"; '
                      'i=$((i+1)); done\n')
        prof = ISO.WasmWasiProfile(tmp, tools_dir=tools, wasmtime=rt,
                                   key_resolver=_resolver)
        r = prof.run(["t"])
        assert r.ok is False, "a flood was reported as success"
        assert r.stdout == "", (
            "a partial output was returned: a truncated result from a "
            "deterministic tool cannot be told apart from a complete one")
        assert r.detail.get("verdict") == wp.PURE_LIMIT_OUTPUT, r.detail
        assert r.detail.get("limit") == 64, r.detail
        assert r.truncated is False, (
            "the refusal must not be dressed as a truncation")
    print("  [PASS] RP0-6  exceeding the declared output is a named refusal "
          "with no output, not a truncated success")


def test_stdin_is_an_explicit_pipe():
    """RP0-7"""
    with tempfile.TemporaryDirectory() as tmp:
        tools, rt, _doc = _toolset_dir(tmp, shim_body='cat\n')
        prof = ISO.WasmWasiProfile(tmp, tools_dir=tools, wasmtime=rt,
                                   key_resolver=_resolver)
        r = prof.run(["t"], input_bytes=b"hello stdin")
        assert r.ok and r.stdout == "hello stdin", r.as_dict()
        # no input means EOF, never the host's descriptor
        r = prof.run(["t"])
        assert r.ok and r.stdout == "", r.as_dict()
        # proven by giving THIS process a readable stdin the child must not
        # see: if the descriptor were inherited, `cat` would echo it
        with tempfile.NamedTemporaryFile("w+", delete=False) as host_in:
            host_in.write("HOST-STDIN-LEAK")
            host_in.flush()
            leaked = subprocess.run(
                [sys.executable, "-c",
                 "import sys, os;"
                 "sys.path.insert(0, %r);" % _ROOT +
                 "from kernel import isolation as I;"
                 "p = I.WasmWasiProfile(%r, tools_dir=%r, wasmtime=%r,"
                 % (tmp, tools, rt) +
                 " key_resolver=lambda k: {'public': %r,"
                 % _SK.public.hex() +
                 " 'key_domain': 'toolset_authorization', 'revoked': False});"
                 "print(repr(p.run(['t']).stdout))"],
                stdin=open(host_in.name), capture_output=True, text=True)
        assert "HOST-STDIN-LEAK" not in leaked.stdout, leaked.stdout
        assert leaked.returncode == 0, leaked.stderr[-400:]
    print("  [PASS] RP0-7  stdin is written and closed by this process; the "
          "host's descriptor does not reach the guest")




def test_fuel_and_memory_get_their_own_reason_codes():
    """RP0-8 — two of D9's three limits used to return a bare exit code."""
    for said, want in (("Error: all fuel consumed by WebAssembly",
                        wp.PURE_LIMIT_FUEL),
                       ("error: failed to grow memory", wp.PURE_LIMIT_MEMORY),
                       ("Error: module trapped: unreachable", "")):
        assert ISO.classify_runtime_breach(said) == want, said
    with tempfile.TemporaryDirectory() as tmp:
        tools, rt, _d = _toolset_dir(
            tmp, shim_body='echo "Error: all fuel consumed by WebAssembly" '
                           '1>&2\nexit 128\n')
        prof = ISO.WasmWasiProfile(tmp, tools_dir=tools, wasmtime=rt,
                                   key_resolver=_resolver)
        r = prof.run(["t"])
        assert r.ok is False and r.detail["verdict"] == wp.PURE_LIMIT_FUEL, \
            r.detail
        assert r.stdout == ""
    # the guest bound and the host bound are two numbers, and the host one
    # must have room above the guest for the runtime itself
    lim = wp.check_limits_declared({"fuel": 1, "guest_memory_bytes": 1 << 20,
                                    "output_bytes": 8})
    assert lim.host_memory_bytes > lim.guest_memory_bytes
    print("  [PASS] RP0-8  fuel and memory breaches carry their own reason "
          "codes; guest and host bounds are separate numbers")


def test_output_limit_counts_both_streams():
    """RP0-9 — max(stdout, stderr) let 40 + 40 bytes past a 64-byte cap."""
    with tempfile.TemporaryDirectory() as tmp:
        forty = "0123456789" * 4
        tools, rt, _d = _toolset_dir(
            tmp, limits={"fuel": 10 ** 8, "guest_memory_bytes": 1 << 26,
                         "output_bytes": 64},
            shim_body=f'echo "{forty}"\necho "{forty}" 1>&2\n')
        prof = ISO.WasmWasiProfile(tmp, tools_dir=tools, wasmtime=rt,
                                   key_resolver=_resolver)
        r = prof.run(["t"])
        assert r.ok is False, "80 bytes passed a 64-byte total limit"
        assert r.detail["verdict"] == wp.PURE_LIMIT_OUTPUT, r.detail
    print("  [PASS] RP0-9  the output limit is the TOTAL of both streams, "
          "not the larger of the two")


def test_stdin_does_not_deadlock_against_a_talkative_guest():
    """RP0-10 — the audit hung a probe here past the wall timeout."""
    with tempfile.TemporaryDirectory() as tmp:
        # a guest that emits far more than a pipe buffer BEFORE reading its
        # input. Writing stdin to completion first blocks both processes and
        # neither wall timeout has begun.
        tools, rt, _d = _toolset_dir(
            tmp, limits={"fuel": 10 ** 8, "guest_memory_bytes": 1 << 26,
                         "output_bytes": 4 << 20},
            shim_body='i=0\nwhile [ $i -lt 4000 ]; do '
                      'echo "0123456789012345678901234567890123456789012345"; '
                      'i=$((i+1)); done\ncat > /dev/null\n')
        prof = ISO.WasmWasiProfile(tmp, tools_dir=tools, wasmtime=rt,
                                   key_resolver=_resolver)
        t0 = time.time()
        r = prof.run(["t"], input_bytes=b"x" * (1 << 20))
        elapsed = time.time() - t0
        assert elapsed < prof.timeout_s + 5, (
            f"the call took {elapsed:.1f}s: stdin and stdout deadlocked")
        assert r.ok, r.as_dict()
    print("  [PASS] RP0-10 a guest that talks before it listens does not "
          "deadlock: stdin is fed inside the same selector loop")


if __name__ == "__main__":
    for fn in (test_effect_class_checker_is_total,
               test_debt_event_is_an_object,
               test_release_attested_carries_its_four_fields,
               test_the_validator_is_the_door,
               test_the_signature_is_verified,
               test_output_limit_refuses_instead_of_truncating,
               test_stdin_is_an_explicit_pipe,
               test_fuel_and_memory_get_their_own_reason_codes,
               test_output_limit_counts_both_streams,
               test_stdin_does_not_deadlock_against_a_talkative_guest):
        fn()
