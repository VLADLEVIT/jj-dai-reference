# -*- coding: utf-8 -*-
"""
jjdai.reserved — one door for both pre-genesis reserves
=======================================================
Track V (ADR-018 rev 2, `jjdai.cognitive`) and deferred verification
(ADR-019 rev 3.1, `jjdai.custody`) each declare a vocabulary that nothing
may use yet. This module holds what is common to both: the union, and the
VALUE-LEVEL refusal.

WHAT THIS FIXES (v0.6.8 P0-1). The first cut of the track V reserve refused
every reserved token as a FUNCTION ARGUMENT — a reserved kind passed to
`append()`, a reserved namespace passed to Plane H, a reserved access class
passed to its checker. It did not refuse them as VALUES. So an ordinary
`INFER` record could carry `ADMITTED`, `RESOLVED`,
`CONTESTED_EXTERNAL_CHALLENGE`, `PREDICTION_SEALED`, `JJDAI:PREDICTION:v1`
or `hypothesis_retrieval` in its body and the chain stayed validly signed —
which is exactly the thing the reserve exists to prevent, since what a later
reader trusts is the value in the record, not the name of the parameter it
arrived through. The v0.6.8 CHANGELOG said that every entry point refused,
fail closed; that sentence was wider than the code, and this module is what
makes it true. The reproduction the audit ran was an ordinary INFER record
carrying six reserved tokens in its body — a KriyaGate outcome, a prediction
resolution status, a CONTESTED reason code, the sealed prediction lifecycle
state, the prediction commitment domain separator and the hypothesis
retrieval mode — with the chain still validly signed. No literal spelling of
any of them appears in this file: they are imported, because a second
spelling of a serialized value is how one value becomes two.

WHERE THE LINE IS DRAWN, AND WHY IT IS NOT DRAWN FURTHER. The scan runs on
the fields a NODE authors and that reach the chain as content:
`semantic_digest` (verbatim in the hashed body), `provenance` (the pre-image
of `provenance_hash`, recomputed by the deliberation verifier, and the field
that names the organ and the being) and `entanglement`. It deliberately does
NOT run on `request` and `response`. Those enter the chain as hiding
commitments over caller-supplied data: a task whose text happens to contain
one of these English words is not a node making a claim in a reserved
vocabulary, and refusing it would fail closed on ordinary work while adding
nothing — no serialized reserved value reaches a peer through a commitment.

SEGMENTS, NOT ONLY WHOLE STRINGS. A `semantic_digest` is routinely a
colon-compound of run, step, node and state hash, so a reserved token would
be smuggled as one segment of a longer string rather than as the whole
value. Both are checked. Dict KEYS are checked too — a key is as good a
place to write a name as a value.

WHAT IS RESERVED BUT NOT SCANNED FOR. `jjdai.custody.AMBIGUOUS_TOKENS` —
the tool effect classes and the two node profiles — are ordinary lowercase
English words, one of which already occurs about twenty times in this tree
in unrelated senses. They
stay reserved and their own checkers refuse them, but scanning record bodies
for them would refuse honest records. Stated here rather than left to be
found: for those two groups the reserve is a declaration plus an argument
check, and not a body-content check.
"""
from __future__ import annotations

from . import cognitive as _cog
from . import custody as _cus

ReservedValueError = _cog.ReservedValueError

#: The union of both reserves, for drift checks and for reporting.
ALL_RESERVED_VALUES = tuple(_cog.ALL_RESERVED_VALUES) + \
    tuple(_cus.ALL_RESERVED_VALUES)

#: Namespace prefixes from both ADRs. Matched by prefix, so a path BELOW a
#: reserved namespace is refused with it.
RESERVED_NAMESPACES = tuple(_cog.NAMESPACES) + tuple(_cus.NAMESPACES)

#: Exactly the tokens the value scan matches on. Namespaces are handled by
#: the prefix rule below instead of by exact match, and the ambiguous groups
#: are excluded — see the module docstring.
SCANNED_VALUES = frozenset(
    tuple(v for v in _cog.ALL_RESERVED_VALUES if v not in _cog.NAMESPACES) +
    tuple(_cus.SCANNABLE_VALUES))

#: Reserved, and knowingly outside the scan.
UNSCANNED_VALUES = frozenset(_cus.AMBIGUOUS_TOKENS)

#: Fields of a witness record that the scan covers. Named as data so a test
#: can assert the set rather than trusting a call site.
SCANNED_FIELDS = ("semantic_digest", "provenance", "entanglement")

MAX_SCAN_NODES = 4096


def check_namespace_free(ns: str, *, op: str = "write") -> None:
    """Refuse a namespace reserved by EITHER ADR.

    One door, so a call site cannot pick up one reserve and miss the other:
    `core.plane_h` calls this and not the two modules separately.
    """
    _cog.check_namespace_free(ns, op=op)
    _cus.check_namespace_free(ns, op=op)


def owning_adr(value: str) -> str:
    """Which reserve a token belongs to. Used only in refusal messages."""
    if value in _cus.ALL_RESERVED_VALUES:
        return "ADR-019 rev 3.1 (deferred verification)"
    return "ADR-018 rev 2 (cross-cutting track V)"


def _hits(text) -> str | None:
    """Return the reserved token this string carries, or None."""
    if not isinstance(text, str) or not text:
        return None
    if text in SCANNED_VALUES:
        return text
    probe = text if text.endswith("/") else text + "/"
    for ns in RESERVED_NAMESPACES:
        if probe == ns or probe.startswith(ns):
            return ns
    if ":" in text:
        for part in text.split(":"):
            if part in SCANNED_VALUES:
                return part
    return None


def check_no_reserved_values(field: str, value, _seen=None) -> None:
    """Refuse a reserved token appearing anywhere inside `value`.

    Fail closed and recursive, over the same shapes `check_plane_value`
    admits: mappings, sequences and scalars.
    """
    seen = _seen if _seen is not None else [0]
    seen[0] += 1
    if seen[0] > MAX_SCAN_NODES:
        raise ReservedValueError(
            f"{field}: structure too large to scan for reserved values; the "
            f"witness plane bounds a record's size for the same reason")
    if isinstance(value, dict):
        for k, v in value.items():
            hit = _hits(k)
            if hit is not None:
                _refuse(f"{field}.{k}", hit, "key")
            check_no_reserved_values(f"{field}.{k}", v, seen)
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            check_no_reserved_values(f"{field}[{i}]", item, seen)
        return
    hit = _hits(value)
    if hit is not None:
        _refuse(field, hit, "value")


def _refuse(field: str, token: str, where: str) -> None:
    raise ReservedValueError(
        f"{field}: {where} {token!r} is RESERVED by {owning_adr(token)} and "
        f"may not be written. A reserve that only guards parameter names "
        f"guards nothing: what a later reader trusts is the value in the "
        f"record. The name is frozen before genesis precisely so that no "
        f"record carries it while its meaning is still undefined.")
