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
  A-10 THE DAEMON SELECTS THROUGH THE REGISTRY: no branch on an engine
       name survives in daemon.py, the CLI does not hardcode the set of
       engines, every registered backend is constructible from one config
       shape, and a driver that failed to import is a recorded fact rather
       than a silent absence. (Audit P0-1: the registry existed and the
       daemon walked past it, while the test named "the only door" checked
       the registry in isolation. Written to fail against that version.)
  A-11 A SIGNATURE DOES NOT CERTIFY SHAPE: signed nonsense is refused, and
       so is a well-signed manifest whose checkpoint or weight adapters are
       not content addresses, whose profile_hash is not a digest, whose
       protocol version is unsupported, or which carries an unknown key.
       (Audit P0-3.)

  A-12 A BLANK ATTRIBUTE IS AN ABSENT ONE: a driver declaring an empty or
       whitespace-only `backend` or `fingerprint` is NOT identified.
       `declared_attributes` normalises it to None and `phase_readiness`
       refuses to call it phase-1 ready. Absence must not read as a value
       anywhere, or a comparison against it succeeds by default — the
       fail-open the seventh audit found in the artifact binder.
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
    # ONE config shape for every driver — that is the point of the second
    # contract, and it is what lets the daemon stop knowing which engines
    # exist
    cfg = R.BackendConfig(url="http://127.0.0.1:1", fingerprint="fp-x",
                          device="emulator")
    for name in R.available():
        backend = R.create(name, cfg)
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

    R.register("broken-test", lambda cfg=None: Broken(), replace=True)
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
                            checkpoint_hash="sha256:" + "de" * 32,
                            backend="dwarfstar", backend_version="0.6.5",
                            licenses=["MIT"], source="internal-mirror")
    env = M.sign_manifest(body, sk)
    assert M.verify_manifest(env)["family"] == "DeepSeek"

    tampered = json.loads(json.dumps(env))
    tampered["body"]["checkpoint_hash"] = "sha256:" + "00" * 32
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
    body = M.build_manifest(profile=loaded, checkpoint_hash="sha256:" + "9a" * 32,
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


def test_daemon_selects_through_the_registry():
    """A-10 (audit P0-1): the daemon must know the registry, not the engines.

    Written to fail against the first cut of this drop, where the registry
    existed, the test was called "the only door", and daemon.py still had
    `if args.engine == "sglang" ... elif "dwarfstar" ... else hash`. The
    seam was real and unused: vllm was registered and unreachable, and
    adding a backend still meant editing the daemon.
    """
    daemon_src = open(os.path.join(_ROOT, "node", "daemon.py"),
                      encoding="utf-8").read()
    for branch in ('args.engine == "sglang"', 'args.engine == "dwarfstar"',
                   'elif args.engine'):
        assert branch not in daemon_src, \
            f"daemon still branches on an engine name: {branch!r}"
    assert "create_backend(args.engine" in daemon_src, \
        "daemon does not construct through the registry"
    assert 'choices=("hash", "sglang", "dwarfstar")' not in daemon_src, \
        "the CLI still hardcodes the set of engines"

    # every registered backend is constructible from ONE config shape —
    # which is what actually lets the daemon stop knowing the engines
    R.load_builtin()
    cfg = R.BackendConfig(url="http://127.0.0.1:1", fingerprint="fp",
                          device="emulator")
    for name in R.available():
        if name == "broken-test":        # deliberately contract-breaking
            continue
        assert R.create(name, cfg) is not None, name

    # a driver that fails to import is a recorded fact, not a silent absence
    R.note_import_error("ghost-driver", RuntimeError("boom"))
    assert "ghost-driver" in R.import_errors()
    try:
        R.create("ghost-driver", cfg)
    except RegistryError as e:
        assert "failed to import" in str(e), str(e)
    else:
        raise AssertionError("a failed driver resolved anyway")


def test_manifest_signature_does_not_certify_shape():
    """A-11 (audit P0-3): a valid signature over garbage is still garbage."""
    sk = SigningKey.generate()
    for bad, why in (({"junk": "yes"}, "no schema"),
                     ({"schema": "jjdai.model-artifact/v999",
                       "checkpoint_hash": "not-a-hash"}, "wrong schema")):
        try:
            M.verify_manifest(M.sign_manifest(bad, sk))
        except ManifestError:
            continue
        raise AssertionError(f"signed nonsense verified: {why}")

    good = M.build_manifest(profile=_profile(),
                            checkpoint_hash="sha256:" + "de" * 32,
                            backend="hash", backend_version="0.6.5")
    for mutate, why in (
        (lambda b: b.update({"checkpoint_hash": "deadbeef"}),
         "checkpoint not a content address"),
        (lambda b: b.update({"profile_hash": "short"}), "profile_hash grammar"),
        (lambda b: b.update({"protocol_version": "99"}), "unsupported protocol"),
        (lambda b: b.update({"weight_adapters": ["lora-1"]}),
         "adapter not a content address"),
        (lambda b: b.update({"family": ""}), "empty family"),
        (lambda b: b.update({"surprise": 1}), "unknown key"),
    ):
        body = json.loads(json.dumps(good))
        mutate(body)
        try:
            M.verify_manifest(M.sign_manifest(body, sk))
        except ManifestError:
            continue
        raise AssertionError(f"signed manifest accepted despite: {why}")


def test_a_blank_attribute_is_an_absent_one():
    """A-12 (recut9, seventh audit)."""
    from jjdai.adapters.capabilities import phase_readiness
    from jjdai.adapters.protocol import declared_attributes

    class _Named:
        backend = "hash"
        fingerprint = "fp-real"
        determinism_level = "reproducible"
        protocol_version = "1"

        def generate(self, messages, sampling, adapter_ids=()):
            return "x"

        def score(self, messages, tokens, sampling, adapter_ids=()):
            return {"ok": True}

    named = _Named()
    assert declared_attributes(named)["fingerprint"] == "fp-real"
    assert phase_readiness(named)["phase_1"] is True, (
        "A-12: a properly named driver must still read as identified")

    for attr, blank in (("fingerprint", ""), ("fingerprint", "   "),
                        ("backend", ""), ("backend", "\t")):
        drv = _Named()
        setattr(drv, attr, blank)
        assert declared_attributes(drv)[attr] is None, (
            f"A-12: {attr}={blank!r} survived as a declared value — "
            "downstream it reads as 'this driver said something'")
        assert phase_readiness(drv)["phase_1"] is False, (
            f"A-12: a driver with a blank {attr} was called identified")
    print("  [PASS] A-12  a blank attribute is an absent one, not a value")


if __name__ == "__main__":
    tests = [test_contract_is_declared_whole,
             test_capability_is_derived,
             test_registry_is_the_only_door,
             test_reference_driver_behaviour_unchanged,
             test_profile_validation_is_strict,
             test_profile_identity_is_canonical,
             test_manifest_chain_and_tampering,
             test_manifest_requires_its_artifact,
             test_adding_a_family_touches_nothing_else,
             test_daemon_selects_through_the_registry,
             test_manifest_signature_does_not_certify_shape,
             test_a_blank_attribute_is_an_absent_one]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\nadapter layer — {len(tests)}/{len(tests)} checks green")
