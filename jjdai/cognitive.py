# -*- coding: utf-8 -*-
"""
jjdai.cognitive — the reserved serialized vocabulary of cross-cutting track V
============================================================================
Chitta and reflexive cognition (ADR-018 rev 2, Accepted 22 August 2026).

WHAT THIS MODULE IS: a DECLARATION, not an implementation. Nothing here
thinks, reflects, predicts or stores anything. It holds the names that
track V will serialize — record kinds, namespaces, access classes, key
domains, status enums, gate outcomes and domain separators — and it refuses
every attempt to use them, fail closed, until the phase that defines their
meaning arrives (specification in Ф2, runtime in Ф3).

WHY A NAME MUST EXIST BEFORE IT MEANS ANYTHING. Witness records are
canonicalized under RFC 8785 and hash-chained; a cognitive-ledger event
becomes a Merkle leaf under a domain separator. A value that has entered a
chain cannot afterwards be added, renamed or re-domained without breaking
every hash after it. Before genesis testnet-0 the name costs one line. After
genesis it costs a schema migration of a replicated append-only store that
nobody can rewrite. This is the same discipline that closed the guardian
terminology window in v0.6.5 and reserved track IV in the same drop.

WHY THE RESERVE IS ALSO A REFUSAL. A reserved name that quietly accepts a
value is worse than no reserve: it puts an undefined shape into the chain
under a name readers will later trust. So every entry point below refuses,
and the refusal names the phase that owes the semantics.

WHAT THIS MODULE DELIBERATELY DOES NOT DO. It does not enumerate reason
codes that ADR-018 has not fixed — those are marked ``OWED`` rather than
invented, because a plausible enumeration written here would be indis-
tinguishable, later, from one that was actually decided. It does not
implement the Key Plane: ADR-017 owns the wrapping domains and the full
Object Security Matrix. ADR-017 landed in this tree in the same drop as this
rebase and was flipped to Accepted before the reserve was built, but the Key
Plane itself is still Ф2-Ф3 work — nothing here wraps, unwraps or holds a
key. What is pinned are the four domain NAMES that ADR-018 rev 2 requires
ADR-017 to carry, so the strings cannot drift between two documents.

A NAMING COLLISION, NAMED RATHER THAN CREATED. ``core.plane_h`` already has
``ACCESS_LEVELS = ("public", "internal", "restricted")`` — a RANKED, chunk-
level retrieval policy. The access classes here (``REFLEXIVE``,
``CONTEST_SCOPED``) are UNRANKED key-plane classes over whole objects. Two
different things, one English word. They are kept disjoint on purpose and
``ACCESS_CLASSES`` must never be offered to Plane H (pinned by test): one
term meaning two things is exactly how ``Viveka`` came to mean both
"cognitive discrimination" and "forbid a syscall".
"""
from __future__ import annotations

from collections import namedtuple

#: Schema version carried by every track V record shape declared here. One
#: number today; the per-kind table below exists so a kind can move alone
#: later without dragging the other fourteen with it.
COGNITIVE_SCHEMA_VERSION = "1"

#: Marker for a field ADR-018 deliberately leaves to Ф2. It is NOT a value:
#: offering it to any checker below refuses, so the gap cannot serialize by
#: being forgotten. Spelled loudly for the same reason.
OWED = "__OWED_PHASE_2__"


class ReservedValueError(ValueError):
    """A reserved track V value was used before its phase.

    ValueError, not a new base, because the witness chain already refuses
    reserved kinds with ValueError and callers that catch one should catch
    both.
    """


# --------------------------------------------------------------------------- #
# Record kinds
# --------------------------------------------------------------------------- #
#
# Fifteen kinds, in the order ADR-018 §3 lists them. Some of these will only
# ever live in the local cognitive ledger (a private REFLECTION never crosses
# a trust boundary; only an anchored Merkle root does). They are reserved in
# the SHARED canonical enum anyway, because over-reserving costs a line and
# under-reserving costs a post-genesis migration — and because which of them
# ends up witnessed is a Ф2 decision this drop must not pre-empt.

Reserve = namedtuple("Reserve", "kind schema_version namespace reason_codes")

#: cognitive namespaces reserved by ADR-018 §3. Exactly three: the ADR's
#: list, not a wider `cognitive/` land grab. A namespace nobody has reserved
#: is still free, and saying so is part of the reserve.
NS_REFLECTION_DRAFT = "cognitive/reflection/draft/"
NS_REFLECTION_VALIDATED = "cognitive/reflection/validated/"
NS_SELF_MODEL = "cognitive/self_model/"

NAMESPACES = (NS_REFLECTION_DRAFT, NS_REFLECTION_VALIDATED, NS_SELF_MODEL)

_R = Reserve
RESERVES = (
    _R("INTENTION_COMMITMENT", COGNITIVE_SCHEMA_VERSION, OWED, OWED),
    _R("COVERAGE_COMMITMENT", COGNITIVE_SCHEMA_VERSION, OWED, OWED),
    _R("PREDICTION_COMMITMENT", COGNITIVE_SCHEMA_VERSION, OWED, OWED),
    # the only abstention codes ADR-018 fixes are "the ones the profile's
    # coverage_policy allows" — an enumeration owned by a policy record, not
    # by this reserve.
    _R("PREDICTION_ABSTENTION", COGNITIVE_SCHEMA_VERSION, OWED, OWED),
    _R("PREDICTION_REVEAL", COGNITIVE_SCHEMA_VERSION, OWED, OWED),
    # OUTCOME_RESOLUTION is the one kind whose codes the ADR does fix.
    _R("OUTCOME_RESOLUTION", COGNITIVE_SCHEMA_VERSION, OWED,
       ("RESOLVED", "UNRESOLVED_EXTERNAL", "UNRESOLVED_UNOBSERVED",
        "EXPIRED_BY_DESIGN", "CENSORED", "INVALID_OUTCOME_SCHEMA")),
    _R("REFLECTION_DRAFT_COMMITMENT", COGNITIVE_SCHEMA_VERSION,
       NS_REFLECTION_DRAFT, OWED),
    _R("REFLECTION", COGNITIVE_SCHEMA_VERSION, NS_REFLECTION_VALIDATED, OWED),
    _R("REFLECTION_EXPIRED", COGNITIVE_SCHEMA_VERSION,
       NS_REFLECTION_DRAFT, OWED),
    _R("SELF_MODEL_SNAPSHOT", COGNITIVE_SCHEMA_VERSION, NS_SELF_MODEL, OWED),
    # the projection is derived FROM the self-model namespace but lives for
    # the length of a round; where it is stored is a Ф2 decision.
    _R("SELF_MODEL_EVAL_PROJECTION", COGNITIVE_SCHEMA_VERSION, OWED, OWED),
    _R("IMPROVEMENT_HYPOTHESIS", COGNITIVE_SCHEMA_VERSION, OWED, OWED),
    _R("HYPOTHESIS_LINEAGE", COGNITIVE_SCHEMA_VERSION, OWED, OWED),
    _R("HYPOTHESIS_REJECTION", COGNITIVE_SCHEMA_VERSION, OWED, OWED),
    _R("HYPOTHESIS_ESCALATION", COGNITIVE_SCHEMA_VERSION, OWED, OWED),
)
del _R

#: The kinds alone, in declaration order. `jjdai.witness` folds these into
#: its canonical enum and into RESERVED_KINDS, so there is exactly one list.
COGNITIVE_KINDS = tuple(r.kind for r in RESERVES)

BY_KIND = {r.kind: r for r in RESERVES}


# --------------------------------------------------------------------------- #
# Access classes, key domains, status and outcome enums
# --------------------------------------------------------------------------- #

#: Key-plane access classes introduced by ADR-018 (D12 / C12). REFLEXIVE is
#: the class that tariff declassification does NOT reach: abandonment,
#: insolvency, passivation and economic freeze do not open it, and after the
#: final death of a Being the rule is fail-closed (FINAL_DEATH → SEALED)
#: until a final-disposition policy exists. That rule is an AUTHORIZATION
#: rule and not cryptographic impossibility — the domain committee can still
#: unwrap at threshold — and ADR-018 says so out loud rather than implying
#: more protection than exists.
ACCESS_REFLEXIVE = "REFLEXIVE"
ACCESS_CONTEST_SCOPED = "CONTEST_SCOPED"
ACCESS_CLASSES = (ACCESS_REFLEXIVE, ACCESS_CONTEST_SCOPED)

#: Wrapping domains owned by ADR-017. Reserved here so the strings are fixed
#: before genesis even though the Key Plane itself is not in this tree.
#: `round_ephemeral` is the K9 ephemeral round domain used by
#: SELF_MODEL_EVAL_PROJECTION; it was missing from the rev 1 reserve list and
#: added in rev 2 (B-10).
KEY_DOMAINS = ("reflexive_recovery", "prediction_round",
               "prediction_resolution", "round_ephemeral")

#: Resolution statuses of a prediction. `valid_until` never removes a
#: prediction from the denominator — on expiry it takes one of these.
#: UNRESOLVED_UNOBSERVED is the load-bearing one: it is the status that says
#: the being may have failed to seek an available refutation.
PREDICTION_STATUSES = BY_KIND["OUTCOME_RESOLUTION"].reason_codes

#: A lifecycle STATE of PREDICTION_REVEAL — deliberately not a status, not a
#: record kind, not an access class and not a key domain (ADR-018 rev 2,
#: B-5). Reserved separately so the distinction survives implementation.
PREDICTION_SEALED = "PREDICTION_SEALED"
PREDICTION_LIFECYCLE_STATES = (PREDICTION_SEALED,)

#: KriyaGate outcomes. The organ is deterministic and non-cognitive: it does
#: not think, does not evaluate truth, does not form decisions and never
#: alters the content of an intention. It admits or it refuses.
KRIYA_GATE_OUTCOMES = ("ADMITTED", "DENIED", "DEFERRED", "BUDGET_EXHAUSTED",
                       "CHECKPOINT_REQUIRED", "AUTHORITY_EXCEEDED",
                       "ARTICLE_25_BLOCKED")

#: CONTESTED is ONE state with two grounds, separated by reason code rather
#: than by two states (rev 2, B-7): an external challenge and an internal
#: Viveka discrimination lift differently but act on the candidate the same.
CONTESTED_REASON_CODES_VERSION = "1"
CONTESTED_REASON_CODES = ("CONTESTED_EXTERNAL_CHALLENGE",
                          "CONTESTED_INTERNAL_DISCRIMINATION")

#: The named retrieval mode through which a DRAFT_REFLECTION is reachable at
#: all. It is reserved because it crosses an API boundary and lands in
#: records — not merely because it is a nice name. Ordinary retrieval must
#: never return a draft, and until Ф3 nothing may use this mode either.
HYPOTHESIS_RETRIEVAL = "hypothesis_retrieval"
RESERVED_RETRIEVAL_MODES = (HYPOTHESIS_RETRIEVAL,)

#: Commitment domain separators. A commitment without a domain separator can
#: be replayed into another context that hashes the same bytes.
PREDICTION_COMMITMENT_DOMAIN = "JJDAI:PREDICTION:v1"
INTENTION_COMMITMENT_DOMAIN = "JJDAI:INTENTION:v1"
COMMITMENT_DOMAINS = (PREDICTION_COMMITMENT_DOMAIN,
                      INTENTION_COMMITMENT_DOMAIN)

#: Merkle leaf domain separator for a cognitive-ledger event, per kind.
#: The ledger is Ф3; the STRINGS are fixed now, because a leaf domain is
#: hashed into the tree and re-domaining it later invalidates every proof
#: already issued. Derivation is canonical (kind and schema version, nothing
#: else) and the resulting table is pinned literally by test — a canonical
#: rule that nobody compares against fixed values can still be edited.
LEAF_DOMAIN_PREFIX = "JJDAI:LEDGER:"


def leaf_domain(kind: str) -> str:
    """Domain separator for a cognitive-ledger leaf of this kind."""
    r = BY_KIND.get(kind)
    if r is None:
        raise ReservedValueError(
            f"{kind!r} is not a track V record kind; leaf domains are not "
            f"minted on demand")
    return f"{LEAF_DOMAIN_PREFIX}{r.kind}:v{r.schema_version}"


LEAF_DOMAINS = {r.kind: leaf_domain(r.kind) for r in RESERVES}


# --------------------------------------------------------------------------- #
# The organ of execution control: one serialized name, not two
# --------------------------------------------------------------------------- #
#
# ADR-018 closes open question 10 of ADR-016 rev 2 by splitting a word that
# had come to mean two unrelated things:
#
#   Viveka     — cognitive discrimination INSIDE Chitta; forms distinctions,
#                authorizes nothing;
#   KriyaGate  — the deterministic, NON-cognitive control of the passage of
#                an intention into an executable action.
#
# `kernel/viveka.py` implements the second and was named after the first.
# The MODULE rename is Ф2 (roadmap r6.8.3, phase table). What moves here is
# only what a hash chain freezes: the organ label in provenance, the digest
# prefix, and the committed event field name. Records written before this
# drop carry `viveka:` and must keep verifying — the prefix is a label, not
# a security property, and rejecting historical records to tidy a name would
# destroy evidence to improve a word.
KRIYA_GATE_ORGAN = "kriya_gate"
KRIYA_GATE_DIGEST_PREFIX = "kriya_gate"
KRIYA_GATE_EVENT_FIELD = "kriya_gate_event"

#: Accepted on READ, never emitted again. Pre-v0.6.8 chains are full of it.
LEGACY_VIVEKA_ORGAN = "viveka"
LEGACY_VIVEKA_DIGEST_PREFIX = "viveka"
LEGACY_VIVEKA_EVENT_FIELD = "viveka_event"


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #

def _phase_note(what: str) -> str:
    return (f"{what} is RESERVED by cross-cutting track V (ADR-018 rev 2, "
            f"Accepted). The name enters the canonical vocabulary before "
            f"genesis so it can never be added to a hash-chained store "
            f"afterwards; the meaning arrives with the specification in Ф2 "
            f"and the runtime in Ф3. Nothing may use it until then.")


def is_reserved_kind(kind: str) -> bool:
    return kind in BY_KIND


def check_kind_emittable(kind: str) -> None:
    """Refuse emission of a track V record kind. Fail closed."""
    if kind in BY_KIND:
        raise ReservedValueError(_phase_note(f"record kind {kind!r}"))


def _ns_hits(ns: str) -> bool:
    if not isinstance(ns, str):
        return False
    probe = ns if ns.endswith("/") else ns + "/"
    return any(probe == reserved or probe.startswith(reserved)
               for reserved in NAMESPACES)


def check_namespace_free(ns: str, *, op: str = "write") -> None:
    """Refuse any use of a reserved cognitive namespace.

    Both a write and an ordinary read are refused, and for different
    reasons. Writing there would create records whose grammar does not
    exist. Reading there ordinarily is the rule ADR-018 states directly: a
    DRAFT_REFLECTION is excluded from ordinary retrieval and is reachable
    only through the `hypothesis_retrieval` mode, marked UNVALIDATED, and
    can never be cited as evidence. Until that mode exists, no path in.
    """
    if _ns_hits(ns):
        raise ReservedValueError(
            _phase_note(f"namespace {ns!r} ({op})") +
            f" A draft reflection may help explore a hypothesis but must "
            f"not masquerade as memory of a fact.")


def check_access_class(value: str) -> None:
    """Refuse use of a reserved key-plane access class."""
    if value in ACCESS_CLASSES:
        raise ReservedValueError(_phase_note(f"access class {value!r}"))
    if value == OWED:
        raise ReservedValueError(
            "OWED is a marker for a decision Ф2 still owes, not a value")


def check_key_domain(value: str) -> None:
    """Refuse use of a reserved key-plane wrapping domain."""
    if value in KEY_DOMAINS:
        raise ReservedValueError(_phase_note(f"key domain {value!r}"))
    if value == OWED:
        raise ReservedValueError(
            "OWED is a marker for a decision Ф2 still owes, not a value")


def check_retrieval_mode(mode: str) -> None:
    """Refuse use of a reserved retrieval mode."""
    if mode in RESERVED_RETRIEVAL_MODES:
        raise ReservedValueError(_phase_note(f"retrieval mode {mode!r}"))


#: Every reserved token in one place, for the drift check that no other
#: spelling of these values exists anywhere in the tree.
ALL_RESERVED_VALUES = (
    COGNITIVE_KINDS + NAMESPACES + ACCESS_CLASSES + KEY_DOMAINS +
    tuple(PREDICTION_STATUSES) + PREDICTION_LIFECYCLE_STATES +
    KRIYA_GATE_OUTCOMES + CONTESTED_REASON_CODES +
    RESERVED_RETRIEVAL_MODES + COMMITMENT_DOMAINS +
    tuple(LEAF_DOMAINS.values()))
