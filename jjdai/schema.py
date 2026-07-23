# -*- coding: utf-8 -*-
"""
jjdai.schema — typed protocol boundaries (v0.3.1 #5).

WHY: until now the wire contract was "the field is present." That is not a
contract. A `sampling.temperature` of "hot", a `top_p` of 47, a 10 MB prompt,
an `adapter_ids` list of 10 000 entries, an `ok` verdict of the string "true"
— all passed. Typed boundaries turn the protocol into something a node can
REFUSE precisely, at the edge, before any organ sees it.

DESIGN (Pydantic pattern, zero dependencies — stdlib only, like the rest of
the primitive layer):

  * a Schema is a declarative map {field: Field(...)};
  * Field validates TYPE, RANGE (min/max), SIZE (min_len/max_len), ENUM
    (allowed values), PATTERN (regex), nested Schemas and typed list items;
  * STRICT BY DEFAULT: unknown fields are REJECTED, not ignored — an
    unexpected field is either an attack, a version skew, or a bug, and
    silently dropping it is how confused-deputy bugs are born;
  * bool is NOT an int here (Python says True == 1; a protocol must not);
  * errors carry a dotted PATH ("sampling.top_p") and a machine-readable code,
    so a daemon can answer 400 with a precise, non-leaky reason.

THE NINE TYPES (the full protocol surface):
  NodeDescriptor · BeingDescriptor · SubstrateManifest · AdapterManifest ·
  InferenceRequest · InferenceReceipt · VerdictEnvelope · ContainmentOrder ·
  RegistryEvent

Limits are stated as CONSTANTS, not magic numbers, so a deployment can tune
them once and every boundary inherits the change.
"""
from __future__ import annotations

import re

# --------------------------------------------------------------------------- #
# Deployment limits — single source of truth
# --------------------------------------------------------------------------- #
MAX_ID_LEN = 128
MAX_TEXT_LEN = 32_768          # a single message's content
MAX_MESSAGES = 256
MAX_ADAPTERS = 8               # composition beyond this is a NECS open item
MAX_TOKENS_HARD = 131_072
MAX_LIST = 1024
MAX_REASON_LEN = 512
MAX_EVIDENCE_REFS = 64

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX_ANY = re.compile(r"^[0-9a-f]+$")
SHA_ID = re.compile(r"^sha256:[0-9A-Za-z._\-]{1,96}$")
NODE_ID = re.compile(r"^node:[0-9A-Za-z._\-]{4,96}$")
BEING_ID = re.compile(r"^being:[0-9A-Za-z._\-]{1,96}$")
TOPIC = re.compile(r"^[a-z0-9][a-z0-9._\-]{0,63}$")
SCOPE = re.compile(r"^[a-z0-9][a-z0-9._:\-]{0,95}$")

ROLES = ("system", "user", "assistant", "tool")
PROFILES = ("A", "B")
DETERMINISM = ("attested", "reproducible")
REG_EVENTS = ("verdict", "slash", "stake")
CONT_EVENTS = ("contain", "verify", "challenge", "resolve_challenge",
               "corroborate", "release", "rehabilitate", "propose_erasure")


class ValidationError(ValueError):
    """A typed-boundary rejection. Carries path + code for precise 4xx."""

    def __init__(self, path: str, code: str, detail: str):
        self.path, self.code, self.detail = path, code, detail
        super().__init__(f"{path}: {detail} [{code}]")

    def as_dict(self) -> dict:
        return {"path": self.path, "code": self.code, "detail": self.detail}


# --------------------------------------------------------------------------- #
# Field spec
# --------------------------------------------------------------------------- #

class Field:
    def __init__(self, type_, *, required: bool = True, default=None,
                 min_len: int = None, max_len: int = None,
                 min_val=None, max_val=None, enum=None, pattern=None,
                 schema: "Schema" = None, item: "Field" = None,
                 nullable: bool = False):
        self.type = type_
        self.required = required
        self.default = default
        self.min_len, self.max_len = min_len, max_len
        self.min_val, self.max_val = min_val, max_val
        self.enum = tuple(enum) if enum else None
        self.pattern = pattern
        self.schema = schema
        self.item = item
        self.nullable = nullable

    def validate(self, value, path: str):
        if value is None:
            if self.nullable:
                return None
            raise ValidationError(path, "null", "value may not be null")

        # bool must never satisfy int (Python's True == 1 is a protocol hazard)
        if self.type in (int, float) and isinstance(value, bool):
            raise ValidationError(path, "type",
                                  f"expected {self.type.__name__}, got bool")
        if self.type is float and isinstance(value, int):
            value = float(value)          # ints are valid floats on the wire
        if not isinstance(value, self.type):
            raise ValidationError(
                path, "type",
                f"expected {self.type.__name__}, got {type(value).__name__}")

        if self.enum is not None and value not in self.enum:
            raise ValidationError(path, "enum",
                                  f"must be one of {list(self.enum)}")
        if isinstance(value, str):
            if self.min_len is not None and len(value) < self.min_len:
                raise ValidationError(path, "min_len",
                                      f"shorter than {self.min_len} chars")
            if self.max_len is not None and len(value) > self.max_len:
                raise ValidationError(path, "max_len",
                                      f"longer than {self.max_len} chars "
                                      f"(got {len(value)})")
            if self.pattern is not None and not self.pattern.match(value):
                raise ValidationError(path, "pattern",
                                      f"does not match {self.pattern.pattern}")
        if isinstance(value, (int, float)):
            if self.min_val is not None and value < self.min_val:
                raise ValidationError(path, "min_val", f"below {self.min_val}")
            if self.max_val is not None and value > self.max_val:
                raise ValidationError(path, "max_val", f"above {self.max_val}")
        if isinstance(value, list):
            if self.min_len is not None and len(value) < self.min_len:
                raise ValidationError(path, "min_items",
                                      f"fewer than {self.min_len} items")
            if self.max_len is not None and len(value) > self.max_len:
                raise ValidationError(path, "max_items",
                                      f"more than {self.max_len} items "
                                      f"(got {len(value)})")
            if self.item is not None:
                value = [self.item.validate(v, f"{path}[{i}]")
                         for i, v in enumerate(value)]
        if isinstance(value, dict) and self.schema is not None:
            value = self.schema.validate(value, path)
        return value


class Schema:
    """A named, strict object schema."""

    def __init__(self, name: str, fields: dict, *, strict: bool = True):
        self.name = name
        self.fields = fields
        self.strict = strict

    def validate(self, obj, path: str = "") -> dict:
        p = path or self.name
        if not isinstance(obj, dict):
            raise ValidationError(p, "type",
                                  f"expected object, got {type(obj).__name__}")
        if self.strict:
            unknown = set(obj) - set(self.fields)
            if unknown:
                raise ValidationError(f"{p}.{sorted(unknown)[0]}", "unknown",
                                      "unknown field (strict schema)")
        out = {}
        for name, f in self.fields.items():
            fp = f"{p}.{name}" if p else name
            if name not in obj:
                if f.required:
                    raise ValidationError(fp, "missing", "required field absent")
                if f.default is not None:
                    out[name] = f.default
                continue
            out[name] = f.validate(obj[name], fp)
        return out


# --------------------------------------------------------------------------- #
# Shared sub-schemas
# --------------------------------------------------------------------------- #

Message = Schema("Message", {
    "role": Field(str, enum=ROLES),
    "content": Field(str, max_len=MAX_TEXT_LEN),
})

Sampling = Schema("Sampling", {
    "seed": Field(int, required=False, min_val=0, max_val=2**63 - 1),
    "temperature": Field(float, min_val=0.0, max_val=2.0),
    "top_p": Field(float, min_val=0.0, max_val=1.0),
    "top_k": Field(int, required=False, min_val=0, max_val=100_000),
    "max_tokens": Field(int, min_val=1, max_val=MAX_TOKENS_HARD),
})

Provenance = Schema("Provenance", {
    "substrate_id": Field(str, pattern=SHA_ID, required=False),
    "adapter_ids": Field(list, required=False, max_len=MAX_ADAPTERS,
                         item=Field(str, pattern=SHA_ID)),
    "engine_fingerprint": Field(str, min_len=1, max_len=MAX_ID_LEN),
    "determinism_level": Field(str, enum=DETERMINISM),
    "sampling": Field(dict, required=False, schema=Sampling),
    "hardware_class": Field(str, required=False, max_len=64),
    "role": Field(str, required=False, max_len=32),
})

# --------------------------------------------------------------------------- #
# THE NINE PROTOCOL TYPES
# --------------------------------------------------------------------------- #

NodeDescriptor = Schema("NodeDescriptor", {
    "kind": Field(str, enum=("NodeDescriptor",)),
    "node_id": Field(str, pattern=NODE_ID),
    "pubkey": Field(str, pattern=HEX64),
    "version": Field(str, max_len=16),
})

BeingDescriptor = Schema("BeingDescriptor", {
    "kind": Field(str, enum=("BeingManifest", "BeingDescriptor")),
    "being_id": Field(str, pattern=BEING_ID),
    "pubkey": Field(str, pattern=HEX64),
    "genesis_node_id": Field(str, pattern=NODE_ID),
    "genesis_ts": Field(float, min_val=0.0),
    "version": Field(str, max_len=16),
    "sig": Field(str, pattern=HEX_ANY, min_len=128, max_len=128),
})

SubstrateManifest = Schema("SubstrateManifest", {
    "substrate_id": Field(str, pattern=SHA_ID),
    "weights_hash": Field(str, pattern=HEX64),
    "profile": Field(str, enum=PROFILES),
    "params": Field(int, required=False, min_val=1),
    "quantization": Field(str, required=False, max_len=32),
    "license": Field(str, required=False, max_len=64),
    "provenance": Field(list, required=False, max_len=MAX_LIST,
                        item=Field(str, max_len=MAX_ID_LEN)),
})

AdapterManifest = Schema("AdapterManifest", {
    "adapter_id": Field(str, pattern=SHA_ID),
    "base_compat_tag": Field(str, pattern=SHA_ID),
    "weights_hash": Field(str, pattern=HEX64),
    "method": Field(str, enum=("lora", "dora", "prefix", "baked")),
    "rank": Field(int, required=False, min_val=1, max_val=1024),
    "topic": Field(str, required=False, pattern=TOPIC),
    "merkle_root": Field(str, required=False, pattern=HEX64),
})

InferenceRequest = Schema("InferenceRequest", {
    "substrate_id": Field(str, pattern=SHA_ID),
    "adapter_ids": Field(list, max_len=MAX_ADAPTERS,
                         item=Field(str, pattern=SHA_ID)),
    "messages": Field(list, min_len=1, max_len=MAX_MESSAGES,
                      item=Field(dict, schema=Message)),
    "sampling": Field(dict, schema=Sampling),
    "request_id": Field(str, min_len=1, max_len=MAX_ID_LEN),
    "nonce": Field(str, min_len=8, max_len=MAX_ID_LEN),
    "champion_context": Field(str, required=False, nullable=True,
                              max_len=MAX_ID_LEN),
    "tokens": Field(list, required=False, max_len=MAX_LIST,
                    item=Field(str, max_len=256)),      # verifier role
})

InferenceReceipt = Schema("InferenceReceipt", {
    "request_id": Field(str, min_len=1, max_len=MAX_ID_LEN),
    "nonce": Field(str, min_len=8, max_len=MAX_ID_LEN),
    "champion_context": Field(str, required=False, nullable=True,
                              max_len=MAX_ID_LEN),
    "output": Field(dict, schema=Message),
    "provenance": Field(dict, schema=Provenance),
    "witness_receipt": Field(dict, required=False, schema=Schema(
        "WitnessReceipt", {
            "index": Field(int, min_val=0),
            "this_hash": Field(str, pattern=HEX64),
            "prev_hash": Field(str, pattern=HEX64),
            "node_id": Field(str, max_len=MAX_ID_LEN, required=False),
            "sig": Field(str, pattern=HEX_ANY, required=False,
                         min_len=128, max_len=128),
        }, strict=False)),
})

VerdictEnvelope = Schema("VerdictEnvelope", {
    "ok": Field(bool),
    "reachable": Field(list, max_len=MAX_LIST, item=Field(bool)),
    "min_margin": Field(float, min_val=0.0, max_val=1.0),
    "verifier_fp": Field(str, min_len=1, max_len=MAX_ID_LEN),
    "determinism": Field(str, enum=DETERMINISM),
    "note": Field(str, required=False, max_len=MAX_REASON_LEN),
    # binding fields (v0.3.2 Full Verdict Binding will require these)
    "verifier_node_id": Field(str, required=False, pattern=NODE_ID),
    "context_hash": Field(str, required=False, pattern=HEX64),
    "nonce": Field(str, required=False, min_len=8, max_len=MAX_ID_LEN),
    "sig": Field(str, required=False, pattern=HEX_ANY,
                 min_len=128, max_len=128),
})

ContainmentOrder = Schema("ContainmentOrder", {
    "ev": Field(str, enum=CONT_EVENTS),
    "t": Field(float, min_val=0.0),
    "being_id": Field(str, pattern=BEING_ID),
    "initiator": Field(str, required=False, max_len=MAX_ID_LEN),
    "evidence_refs": Field(list, required=False, max_len=MAX_EVIDENCE_REFS,
                           item=Field(str, min_len=1, max_len=MAX_ID_LEN)),
    "reason": Field(str, required=False, max_len=MAX_REASON_LEN),
    "topic": Field(str, required=False, pattern=TOPIC),
    "initiator_qualified": Field(bool, required=False),
    "provisional_low_trust": Field(bool, required=False),
}, strict=False)   # verify/challenge/release carry event-specific extras

RegistryEvent = Schema("RegistryEvent", {
    "ev": Field(str, enum=REG_EVENTS),
    "t": Field(float, min_val=0.0),
    "object_id": Field(str, min_len=1, max_len=MAX_ID_LEN),
    "topic": Field(str, required=False, pattern=TOPIC),
    "scope": Field(str, required=False, pattern=SCOPE),
    "ok": Field(bool, required=False),
    "margin": Field(float, required=False, nullable=True,
                    min_val=-1.0, max_val=1.0),
    "difficulty": Field(float, required=False, min_val=0.0, max_val=100.0),
    "reason": Field(str, required=False, max_len=MAX_REASON_LEN),
    "penalty_mult": Field(float, required=False, min_val=0.0, max_val=10.0),
    "stake": Field(float, required=False, min_val=0.0),
})

ALL_SCHEMAS = {
    s.name: s for s in (NodeDescriptor, BeingDescriptor, SubstrateManifest,
                        AdapterManifest, InferenceRequest, InferenceReceipt,
                        VerdictEnvelope, ContainmentOrder, RegistryEvent)
}


def validate(schema_name: str, obj) -> dict:
    """Validate `obj` against one of the nine protocol types by name."""
    if schema_name not in ALL_SCHEMAS:
        raise KeyError(f"unknown protocol type {schema_name!r}")
    return ALL_SCHEMAS[schema_name].validate(obj)
