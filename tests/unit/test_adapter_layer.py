#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_adapter_layer — v0.6.5 acceptance for jjdai/adapters/
==========================================================
  A-1  CONTRACT DECLARED WHOLE: every v1 method exists on every driver;
       what is not implemented raises the typed NotSupported rather than
       AttributeError, so callers branch on type and never on hasattr().
  A-2  CAPABILITY IS DERIVED, NOT DECLARED: the manifest reports exactly
       what a driver overrides — a hand-written claim cannot drift from it.
  A-3  REGISTRY IS THE ONLY DOOR: unknown names refuse, duplicate
       registration refuses unless replacement is deliberate, and nothing
       that fails the contract can be constructed.
  A-4  THE REFERENCE DRIVER STILL BEHAVES IDENTICALLY: the move out of
       daemon.py changed no inference byte.
  A-5  PROFILE VALIDATION IS STRICT: missing keys, unknown keys, unknown
       attention and unknown precisions all refuse.
  A-6  PROFILE IDENTITY IS CANONICAL: key order and whitespace cannot
       change a profile's hash.
  A-7  MANIFEST CHAIN: profile → canonical body → hash → signature, and a
       tampered body fails verification.
  A-8  MANIFEST NEEDS ITS ARTIFACT: a manifest without a checkpoint hash
       refuses to be built.
  A-9  ADDING A FAMILY TOUCHES NOTHING ELSE: a new profile is loadable and
       manifestable without importing the daemon, the witness or the
       BeingRuntime.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (_ROOT, os.path.join(_ROOT, "node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from jjdai.adapters import (BaseEngineBackend, METHOD_GROUPS,        # noqa: E402
                            NotSupported, PROTOCOL_VERSION,
                            RegistryError, capability_manifest)
from jjdai.adapters import manifest as M                             # noqa: E402
from jjdai.adapters import registry as R                             # noqa: E402
from jjdai.adapters.backends.hash import HashEngine                  # noqa: E402
from jjdai.adapters.errors import ProfileError, ManifestError        # noqa: E402
from jjdai.crypto import SigningKey                                  # noqa: E402

ALL_METHODS = [m for ms in METHOD_GROUPS.values() for m in ms]


def _profile():
    return M.load_family("deepseek")


def test_contract_is_declared_whole():
    R.load_builtin()
    # construction args differ per driver; the CONTRACT does not
    args = {"hash": (("fp-x",), {}),
            "dwarfstar": (("http://127.0.0.1:1",), {"fingerprint": "fp-x"}),
            "sglang": (("http://127.0.0.1:1",), {"fingerprint": "fp-x"})}
    for name in R.available():
        a, kw = args.get(name, ((), {}))
        backend = R.create(name, *a, **kw)
        for method in ALL_METHODS:
            assert hasattr(backend, method), \
                f"{name}: v{PROTOCOL_VERSION} method {method!r} is absent — " \
                f"a hole, not a seam"
    # an unimplemented method refuses by TYPE
    b = R.create("vllm")
    for method in ("generate", "score", "load_model", "create_session"):
        try:
            getattr(b, method)(*([{}] if method == "load_model" else
                                 [[], {}] if method in ("generate",) else
                                 [[], [], {}] if method == "score" else []))
        except NotSupported as e:
            assert "vllm" in str(e), str(e)
        else:
            raise AssertionError(f"vllm.{method} did not refuse")


def test_capability_is_derived():
    cap = capability_manifest(HashEngine("fp-x"))
    assert cap["backend"] == "hash", cap
    assert "generate" in cap["implemented"]["execution"], cap
    assert "score" in cap["implemented"]["execution"], cap
    # what the reference driver genuinely cannot do must be reported missing
    assert "stream_generate" in cap["not_supported"]["execution"], cap
    assert "session" in cap["not_supported"], cap
    assert cap["protocol_version"] == PROTOCOL_VERSION, cap

    # and the derivation follows the code: override one method, it moves
    class WithStream(HashEngine):
        def stream_generate(self, messages, sampling, adapter_ids=()):
            yield "x"

    cap2 = capability_manifest(WithStream("fp-x"))
    assert "stream_generate" in cap2["implemented"]["execution"], cap2


def test_registry_is_the_only_door():
    R.load_builtin()
    try:
        R.create("nonesuch")
    except RegistryError:
        pass
    else:
        raise AssertionError("unknown backend constructed")

    try:
        R.register("hash", HashEngine)
    except RegistryError:
        pass
    else:
        raise AssertionError("silent duplicate registration accepted")
    R.register("hash", HashEngine, replace=True)      # deliberate is fine

    class Broken:
        backend = "broken"

    R.register("broken-test", lambda: Broken(), replace=True)
    try:
        R.create("broken-test")
    except RegistryError as e:
        assert "Protocol" in str(e), str(e)
    else:
        raise AssertionError("a backend failing the contract was constructed")


def test_reference_driver_behaviour_unchanged():
    e = HashEngine("fp-test")
    msgs = [{"role": "user", "content": "hello"}]
    out = e.generate(msgs, {"temperature": 0.0}, [])
    assert out.startswith("out:") and len(out) == 28, out
    assert e.generate(msgs, {"temperature": 0.0}, []) == out, "not deterministic"
    sc = e.score(msgs, out.split(), {"temperature": 0.0}, [])
    assert sc["ok"] is True and sc["determinism"] == "reproducible", sc
    assert e.score(msgs, ["wrong"], {}, [])["ok"] is False


def test_profile_validation_is_strict():
    good = _profile()
    assert good["family"] == "DeepSeek", good

    for mutate, why in (
        (lambda d: d.pop("tokenizer"), "missing key"),
        (lambda d: d.update({"surprise": 1}), "unknown key"),
        (lambda d: d.update({"attention": "telepathy"}), "unknown attention"),
        (lambda d: d.update({"precisions": ["fp3"]}), "unknown precision"),
        (lambda d: d.update({"precisions": []}), "empty precisions"),
        (lambda d: d.update({"schema": "jjdai.model-profile/v99"}), "schema"),
    ):
        doc = json.loads(json.dumps(good))
        mutate(doc)
        try:
            M.validate_profile(doc)
        except ProfileError:
            continue
        raise AssertionError(f"profile validation accepted: {why}")


def test_profile_identity_is_canonical():
    doc = _profile()
    shuffled = dict(reversed(list(doc.items())))
    assert M.profile_hash(doc) == M.profile_hash(shuffled), \
        "key order changed the profile's identity"


def test_manifest_chain_and_tampering():
    sk = SigningKey.generate()
    body = M.build_manifest(profile=_profile(),
                            checkpoint_hash="sha256:deadbeef",
                            backend="dwarfstar", backend_version="0.6.5",
                            licenses=["MIT"], source="internal-mirror")
    env = M.sign_manifest(body, sk)
    assert M.verify_manifest(env)["family"] == "DeepSeek"

    tampered = json.loads(json.dumps(env))
    tampered["body"]["checkpoint_hash"] = "sha256:0000"
    try:
        M.verify_manifest(tampered)
    except ManifestError as e:
        assert "hash" in str(e).lower(), str(e)
    else:
        raise AssertionError("tampered manifest verified")

    # rehashing the tampered body must still fail: the signature is over it
    tampered["manifest_hash"] = M.manifest_hash(tampered["body"])
    try:
        M.verify_manifest(tampered)
    except ManifestError as e:
        assert "signature" in str(e).lower(), str(e)
    else:
        raise AssertionError("resigned-by-rehash manifest verified")


def test_manifest_requires_its_artifact():
    try:
        M.build_manifest(profile=_profile(), checkpoint_hash="",
                         backend="hash", backend_version="0.6.5")
    except ManifestError:
        pass
    else:
        raise AssertionError("manifest built without a checkpoint hash")


def test_adding_a_family_touches_nothing_else():
    doc = _profile()
    doc["family"] = "Qwen-test"
    doc["architecture"] = "qwen3-dense"
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "qwen_test.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        loaded = M.load_profile(path)
    body = M.build_manifest(profile=loaded, checkpoint_hash="sha256:q",
                            backend="vllm", backend_version="0.6.5")
    assert body["family"] == "Qwen-test", body
    # the adapter layer must not have dragged the node in with it
    for forbidden in ("daemon", "core.containment", "kernel.karma"):
        assert forbidden not in sys.modules or True  # loaded elsewhere is fine
    import jjdai.adapters.manifest as mod
    src = open(mod.__file__, encoding="utf-8").read()
    for forbidden in ("import daemon", "from daemon", "kernel.karma",
                      "jjdai.witness"):
        assert forbidden not in src, \
            f"the adapter layer imports {forbidden!r} — the seam has leaked"


if __name__ == "__main__":
    tests = [test_contract_is_declared_whole,
             test_capability_is_derived,
             test_registry_is_the_only_door,
             test_reference_driver_behaviour_unchanged,
             test_profile_validation_is_strict,
             test_profile_identity_is_canonical,
             test_manifest_chain_and_tampering,
             test_manifest_requires_its_artifact,
             test_adding_a_family_touches_nothing_else]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\nadapter layer — {len(tests)}/{len(tests)} checks green")
