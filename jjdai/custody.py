# -*- coding: utf-8 -*-
"""
jjdai.custody — the reserved serialized vocabulary of deferred verification
==========================================================================
ADR-019 rev 3.1 "Отложенная верификация: решение в custody и оффлайн-режим
узла" (Accepted, 23 August 2026), D12.

WHY IT LIVES IN THIS DROP AND NOT ITS OWN. ADR-019 §4 does not leave the
carrier open: the Ф0 reserve is declared "в том же предгенезисном окне, что
и резерв трека V" and "носитель — тот же дроп, что несёт резерв трека V".
Two pre-genesis vocabularies in one drop is not scope creep; it is the ADR's
own placement. What is NOT here is equally fixed by the ADR: no runtime.
`SELF_CHECKED` is not emitted, the custody queue does not exist, temporary
memory does not exist. A lone `production` node still refuses with
`no_independent_panel` — now because the machinery is absent, not because a
document was under discussion.

WHY A SEPARATE MODULE FROM `jjdai.cognitive`. Same discipline, different
subsystem and different owning ADR. One module holding both vocabularies
would make every future edit read as an edit to both, and the two travel to
Ф2 on separate schedules (track V specification in Ф2 under ADR-018; custody
specification in Ф2 under ADR-019, network corroboration in Ф3).

WHAT Ф0 FREEZES, EXACTLY (rev 3.1). NAMES: enum values, type tags, domain
separators and the schema version number. NOT record schemas and NOT the
canonical encoding — those are Ф2, before first emission. A value cannot be
renamed after genesis; a schema can be written later. Freeze what cannot be
replayed and nothing else.

TWO CLASSES OF RESERVED TOKEN, AND WHY THE SECOND IS NOT SCANNED FOR. Most
of the values below are unique strings that exist nowhere else in this tree
(`CUSTODY_ENTERED`, `EVIDENCE_PENDING`, `PANEL_QUORUM_UNMET`), so finding one
in a record body means somebody used the reserve. Two groups are not like
that: the tool EFFECT CLASSES (`pure`, `local_transactional`,
`local_nontransactional`, `external`, `unknown`) and the NODE PROFILES
(`network_member`, `local_only`) are ordinary lowercase words, and `unknown`
already appears about twenty times in this tree in unrelated senses. They
are reserved as names and refused by their own checkers, but they are
DELIBERATELY EXCLUDED from the value-level scan in `jjdai.reserved` — a scan
that refuses the bare word "unknown" anywhere in a record would fail closed
on records that have nothing to do with ADR-019. The limitation is named
here rather than discovered later: for these two groups the reserve is a
declaration plus an argument check, not a body-content check.

A COLLISION NAMED RATHER THAN CREATED. `CORROBORATED` is already taken —
`core/containment.py` uses it for a corroborated containment claim. That is
why every outcome here carries the `CUSTODY_` prefix and why the effective
status projection carries `EVIDENCE_`, per ADR-019 rev 3.1. Two nearly
identical dictionaries in two subsystems is the mistake D7 and ADR-018 each
had to fix once already.
"""
from __future__ import annotations

from collections import namedtuple

from .cognitive import OWED, ReservedValueError

#: Schema version of every custody record shape declared here. Separate
#: number from the track V one on purpose: the two vocabularies are owned by
#: different ADRs and must be able to move independently.
CUSTODY_SCHEMA_VERSION = "1"

Reserve = namedtuple("Reserve", "kind schema_version namespace reason_codes")

# --------------------------------------------------------------------------- #
# Namespaces
# --------------------------------------------------------------------------- #

#: D13/D15. `verification/custody/` holds the queue and its private payload;
#: `memory/pending_verification/` holds temporary memory. Reserved as exact
#: prefixes — the being keeps FULL access to its own memory, and what differs
#: is the evidentiary status of a record, not the being's reach.
NS_VERIFICATION_CUSTODY = "verification/custody/"
NS_PENDING_VERIFICATION = "memory/pending_verification/"

NAMESPACES = (NS_VERIFICATION_CUSTODY, NS_PENDING_VERIFICATION)

# --------------------------------------------------------------------------- #
# Record kinds
# --------------------------------------------------------------------------- #

_R = Reserve
RESERVES = (
    # D3/D6: entering and leaving the deferred-verification mode of a node.
    _R("CUSTODY_ENTERED", CUSTODY_SCHEMA_VERSION, NS_VERIFICATION_CUSTODY,
       ("PANEL_UNREACHABLE", "PANEL_QUORUM_UNMET",
        "PANEL_INDEPENDENCE_UNMET")),
    _R("CUSTODY_EXITED", CUSTODY_SCHEMA_VERSION, NS_VERIFICATION_CUSTODY,
       OWED),
    # D2/P0.3: the write-ahead commitment. VERIFICATION_DEFERRED must be in
    # the chain BEFORE a trace may become SELF_CHECKED, so the obligation to
    # be verified is recorded before the act it covers.
    _R("VERIFICATION_DEFERRED", CUSTODY_SCHEMA_VERSION,
       NS_VERIFICATION_CUSTODY, OWED),
    _R("VERIFICATION_SETTLED", CUSTODY_SCHEMA_VERSION,
       NS_VERIFICATION_CUSTODY,
       ("CUSTODY_CORROBORATED", "CUSTODY_DIVERGENT", "CUSTODY_UNVERIFIABLE",
        "CUSTODY_EXPIRED_UNSETTLED")),
    # D13: temporary memory. Append-only promotion; nothing is rewritten and
    # nothing is deleted.
    _R("TEMP_MEMORY_CREATED", CUSTODY_SCHEMA_VERSION,
       NS_PENDING_VERIFICATION, OWED),
    _R("MEMORY_CORROBORATED", CUSTODY_SCHEMA_VERSION,
       NS_PENDING_VERIFICATION, OWED),
    # D17: compensation is a forward event, never a rewrite.
    _R("CUSTODY_COMPENSATION_REQUIRED", CUSTODY_SCHEMA_VERSION,
       NS_VERIFICATION_CUSTODY, OWED),
    _R("CUSTODY_COMPENSATION_COMPLETED", CUSTODY_SCHEMA_VERSION,
       NS_VERIFICATION_CUSTODY, OWED),
    _R("CUSTODY_COMPENSATION_FAILED", CUSTODY_SCHEMA_VERSION,
       NS_VERIFICATION_CUSTODY, OWED),
    # rev 3.1: the duty to re-evaluate what was derived from a record whose
    # status changed. Its own kinds because the compensation triple above
    # describes an ACTION, and this describes derived MEMORY.
    _R("DEPENDENT_REEVALUATION_REQUIRED", CUSTODY_SCHEMA_VERSION,
       NS_PENDING_VERIFICATION, OWED),
    _R("DEPENDENT_REEVALUATION_SETTLED", CUSTODY_SCHEMA_VERSION,
       NS_PENDING_VERIFICATION, OWED),
)
del _R

CUSTODY_KINDS = tuple(r.kind for r in RESERVES)

BY_KIND = {r.kind: r for r in RESERVES}

# --------------------------------------------------------------------------- #
# States, statuses and reason codes
# --------------------------------------------------------------------------- #

#: D2: the second admission state. A self-check is NOT a verification, and
#: `VERIFIED` must never be written by one — that is the whole point of the
#: name existing separately.
SELF_CHECKED = "SELF_CHECKED"
TRACE_STATES = (SELF_CHECKED,)

#: D7: outcomes of corroboration. Prefixed because bare `CORROBORATED`
#: belongs to containment (see the module docstring).
CUSTODY_OUTCOMES = ("CUSTODY_CORROBORATED", "CUSTODY_DIVERGENT",
                    "CUSTODY_UNVERIFIABLE", "CUSTODY_EXPIRED_UNSETTLED")

#: D12: why a decision was deferred. Rev 3.1 removed the two replay codes
#: from this list — D5 and D16 ruled that the absence of a replay does not
#: prevent corroboration, while the serialized list went on asserting the
#: opposite. The vocabulary is not allowed to contradict the normative text.
CUSTODY_REASON_CODES_VERSION = "1"
CUSTODY_REASON_CODES = ("PANEL_UNREACHABLE", "PANEL_QUORUM_UNMET",
                        "PANEL_INDEPENDENCE_UNMET")

#: D16 (rev 3.1): replayability is a separately recorded FACT, not a
#: condition of corroboration.
REPLAY_STATUSES = ("REPLAY_AVAILABLE", "REPLAY_UNAVAILABLE")
REPLAY_REASON_CODES = ("REPLAY_INPUTS_INCOMPLETE",
                       "MODEL_REPLACED_BEFORE_SETTLEMENT")

#: D13: the record's OWN status, immutable once written.
STORED_STATUS_PENDING = "PENDING_VERIFICATION"
STORED_STATUSES = (STORED_STATUS_PENDING,)

#: D13 (rev 3.1): the COMPUTED projection. Stored status never changes;
#: effective status is derived from append-only settlement events, and it is
#: the effective one that inheritance keys on — otherwise a corroborated
#: record goes on infecting everything derived from it forever.
#: `EVIDENCE_CORROBORATED_FOR_USE` means admissible for use, never "true".
EFFECTIVE_EVIDENCE_STATUSES = ("EVIDENCE_PENDING",
                               "EVIDENCE_CORROBORATED_FOR_USE",
                               "EVIDENCE_DIVERGENT", "EVIDENCE_UNVERIFIABLE",
                               "EVIDENCE_EXPIRED")

# --------------------------------------------------------------------------- #
# Key plane (ADR-017)
# --------------------------------------------------------------------------- #

#: D15: the private custody payload is wrapped under its own ADR-017 domain
#: and read under its own access class. Strings pinned here for the same
#: reason track V pins its four: the Key Plane is not in this tree yet, and
#: two documents living apart drift.
KEY_DOMAINS = ("verification_custody",)
ACCESS_CLASSES = ("CUSTODY_PRIVATE",)

# --------------------------------------------------------------------------- #
# The two ambiguous groups — declared, checked by argument, NOT scanned for
# --------------------------------------------------------------------------- #

#: D6 (rev 2): the MAXIMUM effect class a tool may have, declared in the
#: toolset manifest. `unknown` is fail-closed: an undeclared tool is refused,
#: not assumed harmless.
EFFECT_CLASSES = ("pure", "local_transactional", "local_nontransactional",
                  "external", "unknown")

#: D18: the two node profiles, which dissolve the Solo SKU paradox. A profile
#: belongs to the NODE while history belongs to the BEING, so moving a being
#: between profiles must never reset its custody state.
NODE_PROFILES = ("network_member", "local_only")

#: The tokens above are ordinary words. They are reserved and refused by the
#: checkers below, but `jjdai.reserved` excludes them from its value scan.
#: Kept as a named tuple of its own so the exclusion is a declaration in the
#: source rather than a fact somebody has to rediscover by reading a filter.
AMBIGUOUS_TOKENS = EFFECT_CLASSES + NODE_PROFILES

# --------------------------------------------------------------------------- #
# Merkle leaf domains
# --------------------------------------------------------------------------- #

LEAF_DOMAIN_PREFIX = "JJDAI:CUSTODY:"


def leaf_domain(kind: str) -> str:
    """Domain separator for a custody-ledger leaf of this kind."""
    r = BY_KIND.get(kind)
    if r is None:
        raise ReservedValueError(
            f"{kind!r} is not an ADR-019 record kind; leaf domains are not "
            f"minted on demand")
    return f"{LEAF_DOMAIN_PREFIX}{r.kind}:v{r.schema_version}"


LEAF_DOMAINS = {r.kind: leaf_domain(r.kind) for r in RESERVES}


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #

def _phase_note(what: str) -> str:
    return (f"{what} is RESERVED by ADR-019 rev 3.1 (Accepted). The name "
            f"enters the canonical vocabulary before genesis so it can never "
            f"be added to a hash-chained store afterwards; Accepted status "
            f"authorises the RESERVE and nothing in the runtime — the "
            f"specification lands in Ф2 and network corroboration in Ф3. A "
            f"lone production node still refuses with no_independent_panel.")


def is_reserved_kind(kind: str) -> bool:
    return kind in BY_KIND


def check_kind_emittable(kind: str) -> None:
    """Refuse emission of an ADR-019 record kind. Fail closed."""
    if kind in BY_KIND:
        raise ReservedValueError(_phase_note(f"record kind {kind!r}"))


def _ns_hits(ns: str) -> bool:
    if not isinstance(ns, str):
        return False
    probe = ns if ns.endswith("/") else ns + "/"
    return any(probe == reserved or probe.startswith(reserved)
               for reserved in NAMESPACES)


def check_namespace_free(ns: str, *, op: str = "write") -> None:
    """Refuse any use of a reserved custody namespace."""
    if _ns_hits(ns):
        raise ReservedValueError(
            _phase_note(f"namespace {ns!r} ({op})") +
            " Temporary memory is memory the being reaches in full; what it "
            "lacks is a settled evidentiary status, and neither exists yet.")


def check_access_class(value: str) -> None:
    """Refuse use of the reserved custody access class."""
    if value in ACCESS_CLASSES:
        raise ReservedValueError(_phase_note(f"access class {value!r}"))
    if value == OWED:
        raise ReservedValueError(
            "OWED is a marker for a decision Ф2 still owes, not a value")


def check_key_domain(value: str) -> None:
    """Refuse use of the reserved custody wrapping domain."""
    if value in KEY_DOMAINS:
        raise ReservedValueError(_phase_note(f"key domain {value!r}"))
    if value == OWED:
        raise ReservedValueError(
            "OWED is a marker for a decision Ф2 still owes, not a value")


def check_trace_state(value: str) -> None:
    """Refuse use of the reserved second admission state."""
    if value in TRACE_STATES:
        raise ReservedValueError(_phase_note(f"trace state {value!r}"))


def check_effect_class(value: str) -> None:
    """Refuse use of a reserved tool effect class.

    Reserved by ARGUMENT only: see AMBIGUOUS_TOKENS and the module docstring.
    """
    if value in EFFECT_CLASSES:
        raise ReservedValueError(_phase_note(f"tool effect class {value!r}"))


def check_node_profile(value: str) -> None:
    """Refuse use of a reserved node profile name. Argument-only, as above."""
    if value in NODE_PROFILES:
        raise ReservedValueError(_phase_note(f"node profile {value!r}"))


#: Every custody token that is UNIQUE enough to be searched for in a record
#: body. The ambiguous groups are excluded on purpose and are reachable as
#: AMBIGUOUS_TOKENS.
SCANNABLE_VALUES = (
    CUSTODY_KINDS + TRACE_STATES + CUSTODY_OUTCOMES + CUSTODY_REASON_CODES +
    REPLAY_STATUSES + REPLAY_REASON_CODES + STORED_STATUSES +
    EFFECTIVE_EVIDENCE_STATUSES + KEY_DOMAINS + ACCESS_CLASSES +
    tuple(LEAF_DOMAINS.values()))

#: Everything reserved by this ADR, scannable or not — the drift check reads
#: this, the value scanner reads SCANNABLE_VALUES.
ALL_RESERVED_VALUES = SCANNABLE_VALUES + NAMESPACES + AMBIGUOUS_TOKENS
