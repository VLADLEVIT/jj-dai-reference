# JJ DAI — CHANGELOG

Chronological, oldest first: the LATEST release is the LAST entry
in this file (its header must match `jjdai.__version__` — enforced
by the release-integrity test). Historical entries below are kept
verbatim as the project's memory.

---

# JJ DAI v0.4.1-dev — P0 hardening (work in progress)

Scope: fixes only, per the v0.4 external review. No new codebase growth.

## Closed in this drop

**P0-1 — Persistent NodeIdentity wired into the live daemon.**
`node/daemon.py` now accepts `--node-keystore` and
`--keystore-passphrase-env` (default `JJDAI_KEYSTORE_PASSPHRASE`; the
passphrase is never passed on the CLI). The daemon's signer IS the
persistent `core.identity.NodeIdentity`; `verify_startup()` runs at boot.

**P0-2 — Refuse-to-start on signer/witness mismatch.**
Boot gate in `Node.__init__`: if a loaded witness log contains records
signed by a different node identity, the daemon raises `IdentityError`
and exits 2. `main()` additionally refuses an ephemeral (dev) identity
over any existing non-empty witness log. Ephemeral mode prints a loud
warning and is only reachable on fresh/absent logs.

**P0-3 — True streaming output cap in Karma.**
`kernel/karma.py` `Sandbox.run()` no longer buffers unbounded
`communicate()` output. Streams are read non-blocking via selectors;
the parent retains at most `max_output` bytes per stream; emitted bytes
beyond `max(1 MiB, 8 × max_output)` kill the whole process group and
return verdict `OUTPUT_LIMIT_EXCEEDED`. A-9 semantics (modest overflow
→ truncate, not kill) preserved.

**P0-4 — Deterministic Karma child environment.**
`PYTHONNOUSERSITE=1`, `PYTHONSAFEPATH=1`, `PYTHONDONTWRITEBYTECODE=1`,
`PYTHONHASHSEED=0`, single-threaded BLAS/OMP/MKL/NUMEXPR/VECLIB,
`TMPDIR` inside the sandbox root, `TZ=UTC`, `LC_ALL=C.UTF-8`. No host
sitecustomize side doors; compatible with RLIMIT_NPROC/RLIMIT_AS on
any host.

**P0-11 (partial) — Admin test hooks restricted.**
`--allow-test-hooks` now refuses any non-loopback `--host` at startup.
(Full authenticated admin surface remains P1.)

## New tests

- `node/test_identity_continuity.py` — 5 checks: restart continuity,
  foreign-signer refusal, ephemeral-over-log refusal, missing-passphrase
  refusal, test-hooks-off-loopback refusal.
- `test_karma_flood.py` — 3 checks: flood kill + OUTPUT_LIMIT_EXCEEDED,
  legitimate overflow truncation, deterministic child env.

## Regression status (this environment)

- kernel karma: 16/16 (incl. previously failing A-9/A-10/A-12)
- two-node smoke: 14/14 · governor: 8/8 · crossverify: 6/6
- primitives, vectors, schema, identity, durable, registry, verdict,
  containment, migration, smriti, viveka, conformance: all green

## Still open for the v0.4.1 tag

P0-5 pytest layout · P0-6 GitHub Actions · P0-7 LICENSE ·
P0-8 public README · P0-9 architecture map v0.4 · P0-10 explicit
local-anchor labeling · P0-11 (full) · P0-12 site Appendix A + GitHub link.

## Drop 2 — P0-5 / P0-6 (16 July 2026)

**P0-5 — pytest layout (variant A: full restructure).**
All suites migrated into `tests/{unit,integration,conformance,adversarial,legacy}/`
with a shared `tests/conftest.py` (sys.path: repo root, node/, m1m5/).
Script-style harnesses converted to importable pytest functions; sequential
scenario suites (e.g. Karma A-1..A-16) preserved as single narrative test
functions, multiline string payloads kept byte-identical. Terminal
`raise SystemExit` replaced with asserts. `node/smoke_two_nodes.py` remains
the canonical helper library + CLI (get/post/wait_up/jii/spawn are shared by
other live suites); `tests/integration/test_smoke_two_nodes.py` is a thin
wrapper. Originals removed from root/node/m1m5. `scripts/run_acceptance.py`
added: stdlib runner following the pytest protocol (clean import -> collect
-> run) for environments without pytest.

**P0-6 — GitHub Actions.**
`.github/workflows/ci.yml`: Python 3.10/3.11/3.12 matrix; staged unit ->
integration -> conformance runs plus a stdlib-runner parity job.

**Repo scaffolding.**
`pyproject.toml` (version single-sourced with `jjdai.__version__ =
"0.4.1.dev0"`; license field intentionally deferred to P0-7) and
`.gitignore` (keystores and witness logs are never committed).

**Status:** 34/34 acceptance checks green across all five groups.
Remaining for the tag: P0-7 LICENSE (decision: AGPL-3.0 core /
Apache-2.0 NECS — pending confirmation), P0-8 README, P0-9 architecture
map v0.4, P0-10 anchor labeling, P0-11 full admin auth note, P0-12 site.

## Drop 3 — P0-7 / P0-8 / P0-9 / P0-10 / P0-12 draft (16 July 2026)

**P0-7 — Licensing structure (decision confirmed).**
Two-license split: AGPL-3.0-only for the trust/governance core
(jjdai/, core/, kernel/, node/, m1m5/, tests/, scripts/) — network
copyleft matches the node-serves-network model; Apache-2.0 for the NECS
specification and harness (necs/) — spec adoption must be copyleft-free.
`LICENSE` (structure + rationale), `LICENSES/Apache-2.0.txt` (full text),
`necs/LICENSE` pointer, pyproject license field.
RESIDUAL (one mechanical step before the tag): replace
`LICENSES/AGPL-3.0.txt` placeholder with the canonical verbatim text from
https://www.gnu.org/licenses/agpl-3.0.txt (byte-exact; GitHub's license
template does this automatically). CLA note added to CONTRIBUTING.md to
preserve the dual-license option. Final structure to be reviewed by counsel.

**P0-8 — Public README.md.** Ten sections per review: what JJ DAI is,
what is/is not in the release, quickstart (persistent-identity boot),
architecture diagram, security model, tests, roadmap, license,
responsible disclosure. `README_BUILD.md` moved to
`docs/README_BUILD_v0.4.md` with a deprecation note (stale-date issue
resolved: versions single-sourced from `jjdai.__version__`).

**P0-9 — Architecture map v0.4.1.** `docs/JJDAI_Code_Architecture_Map_v0.4.md`
replaces v0.1; every component classified as Implemented / Prototype /
Interface only / Planned / Constitutional specification only.

**P0-10 — Local-only anchor labeled.** `LocalAnchor` docstring now states
explicitly: no replication, no quorum, no external timestamp; single-disk
witness is not inextinguishable. Same statement in README §6, SECURITY.md
and the architecture map.

**P0-12 (draft) — Site update.** `docs/site/Appendix_A_v0.4.1_draft.md`:
full replacement text for Appendix A with the five-status classification
and the GitHub-link correction note (kernel repo, not the DwarfStar repo).

**Also:** SECURITY.md (responsible disclosure + explicit non-goals),
CONTRIBUTING.md (test-group rules, stdlib-only policy, CLA).

**Status: 11 of 12 P0 closed.** Open: the AGPL text paste (P0-7 residual,
pre-tag) and publishing the site changes (P0-12, jj-dai.org side).

# v0.5 (in development) — P1: growing the codebase

## Drop 1 — Witness replication + quorum anchoring (P1 item 2, 16 July 2026)

**`core/replication.py`** — the M6 protocol, stdlib-only, fully
offline-verifiable envelopes (JCS + Ed25519, domain-separated):
`local append -> signed root -> peer replication -> signed acks ->
quorum receipt -> ANCHOR_QUORUM chain record -> reconciliation`.
Components: `make_signed_root`/`verify_signed_root`,
`make_ack`/`verify_ack`, `ReplicaStore` (durable, append-only store of
peer roots; outcomes stored/duplicate/stale/divergence/rejected),
`QuorumTracker` + `verify_quorum_receipt` (k distinct receivers,
self-acks refused), `reconcile` (lag/divergence report).

**Equivocation is evidence.** Two validly-signed roots from the same
origin for the same count are captured as durable
`DIVERGENCE_EVIDENCE` — the envelopes themselves are the proof,
admissible without trusting the reporter. Endpoint returns 409.

**Daemon wiring.** New CLI: `--peers`, `--quorum` (default 2),
`--replica-store`, `--receipt-store`, `--replicate-interval`
(0 = manual). New endpoints: `GET /witness/root`,
`GET /replicate/status`, `POST /replicate/root` (store + ack),
`POST /replicate/push`. Optional background push loop.
INV-9 honored: replication is an act of the NODE; the chain only
receives records about achieved quorum.

**Anchor recursion guard.** The ANCHOR_QUORUM record itself grows the
chain; anchoring is suppressed unless substantive (non-anchor) records
appeared since the last covered count. Public auditable summary lives
in `semantic_digest`; the full receipt is held under a hiding
commitment in `response`. `ANCHOR_QUORUM` added to witness KINDS.

**Tests.** `tests/integration/test_witness_replication.py`: 10 groups,
live 3-node run (persistent keystores) — signed-root offline verify,
store+ack, offline quorum receipt, single anchor per count,
idempotent re-push, 409 equivocation with self-proving evidence,
stale handling, durable reload, self-ack refusal.

**Status: 35/35 acceptance green.** Remaining honest caveat (documented
in module docstring): prefix-consistency proofs between honest roots at
different counts (CT-style) are the follow-up item; external timestamp
anchoring (OpenTimestamps) remains a seam.

## Drop 2 — Governed Plane H: signed RAG writes (P1 item 3, 16 July 2026)

**`core/plane_h.py`** — the governed knowledge lifecycle, layered over the
M5 RagStore by composition (continuity component untouched except a
NULL-text guard in retrieve):

`proposal (signed) -> validation -> authorization (per-ns ACL, fail
closed) -> append -> Merkle commitment -> MEMORY witness record`.

Records now carry the full metadata set from the review: author identity
+ Ed25519 signature (domain-separated, JCS), source provenance,
created_at, supersedes/version, access policy (public/internal/
restricted), retention policy, redaction status, jurisdiction,
confidence, evidence references.

**Design decisions.**
- Authors sign the CONTENT HASH, not the text — so redaction removes
  content without invalidating historical envelopes.
- REDACT is a content-addressed tombstone: text deleted, hash retained
  as the Merkle leaf. Namespace roots are provably UNCHANGED by
  redaction — history integrity survives content removal (G-7).
- SUPERSEDE is append-only versioning: the old chunk stays, points
  forward via superseded_by, and leaves retrieval.
- Governed retrieval filters redacted / superseded / retention-expired /
  above-access chunks and surfaces provenance in every hit.
- Witness binding: full proposal envelope under a hiding commitment,
  public digest (op, ns, chunk, author, authorized_by, ns_root) in
  semantic_digest.
- Write endpoints are deliberately NOT exposed on the daemon yet:
  that belongs to the authenticated node-to-node protocol (P1 item 6).

**Tests.** `tests/integration/test_plane_h_governed.py` — 12 groups:
add + witness + proof, tamper rejection, forged-author rejection,
fail-closed authorization, supersede semantics, double-supersede
refusal, root-preserving redaction with surviving envelopes,
privileged redact, access filtering, retention expiry, provenance
surfacing, persistence + end-to-end chain verification.

**Status: 36/36 acceptance green.**

## Drop 3 — Signed manifests + diversity model (P1 items 1+4, 16 July 2026)

**`core/manifests.py`** — the identity layer for MODELS, mirroring
core.identity for nodes. SubstrateManifest (content-addressed frozen
weights: lineage with base family and training-data families,
architecture family, profile, operator domain, jurisdiction, license) and
AdapterManifest (bound to a substrate compat tag, task domain, own data
families, acceptance reference) — JCS-canonical, Ed25519-signed,
domain-separated, offline-verifiable. ManifestRegistry: durable JSONL,
verifies before holding, manifests are IMMUTABLE (conflicting
re-registration refused, supersession = new id; identical registration
idempotent), optional publisher ACL fails closed.
ProvenanceManifest is COMPOSED, not asserted: lineage/architecture derive
from the registered substrate, data families are the union across
substrate+adapters, deployment may override operator/jurisdiction;
mismatched adapter-substrate bindings are refused.

**`core/diversity.py`** — diversity-constrained verifier selection.
Weighted pairwise correlation over provenance (base_family 0.35,
architecture 0.20, data-family Jaccard 0.20, operator 0.15,
jurisdiction 0.10); independence = 1 − correlation. Selection is greedy
by reputation UNDER constraints: min pairwise independence against every
selected member, per-dimension correlation-group caps, and generator
exclusion (a model never verifies itself; its full clones are refused).
FAIL HONEST: an insufficient pool returns a SHORT panel with named
per-candidate rejection reasons — constraints are never relaxed silently.

**Tests.** `tests/unit/test_manifests_diversity.py` — 12 groups
(M-1..M-6, D-1..D-6): tamper rejection, binding refusal, immutability,
ACL fail-closed, disk reload, derived provenance, correlation extremes,
independence enforcement with named reasons, group caps, honest short
panels, reputation ordering, generator/clone exclusion.

**Status: 37/37 acceptance green.** Next wiring step: feed
ProvenanceManifests into router/cross-verification so live verifier
panels are diversity-constrained (currently leaderboard-champion).

## Drop 4 — IFF + cross-chain entanglement (P1 items 6+7 + salt, 16 July 2026)

**`core/entanglement.py`** — witnessed salt issuance (idea: V.L.).
A node draws a pseudorandom salt from a neighbor; the ISSUER witnesses
the issuance on its own chain (SALT_ISSUE) BEFORE releasing the signed
envelope, which binds the issuer's chain state (index + head). A record
embedding the beacon provably could not exist before the issuance
("not-before"); root replication provides "not-after" — every record's
creation is sandwiched between externally witnessed events. This is
distributed Haber-Stornetta linked timestamping: the Sākṣī witness each
other. Beacons support MULTIPLE issuers (m-of-n collusion resistance).
`judge_divergence` resolves the drop-1 gap: given two same-key histories
and an issuer export, the side whose "historical" records embed salts
issued after the agreed count is flagged as anachronistic.
NOTE (corrected in drop 5 after external audit): this is EXPERIMENTAL
EVIDENCE FOR TEMPORAL ATTRIBUTION of divergent histories, not a proof.
A higher issuer index does not by itself prove the salt post-dates the
agreed origin root; a sound proof needs a cryptographic cross-link
(origin agreed root <-> issuer chain checkpoint <-> salt issuance).
The earlier claim "the forgery dates itself" overstated the guarantee.

**`core/peers.py`** — the friend-or-foe system, four layers: transport
(TLS/mTLS — deployment, documented), message (signed request envelopes:
JCS+Ed25519, path binding, payload hash, ±window timestamp, single-use
nonce replay cache), membership (durable PeerRegistry: self-certifying
node identity + steward-countersigned admission, key pinning, statuses,
fail closed), behavioral (NECS/reputation/containment — existing).

**Witness.** `append(..., entanglement=)`: beacon included in the hashed
body (unswappable after signing), omitted entirely when absent so
pre-v0.5 records stay byte-identical. SALT_ISSUE added to KINDS.

**Daemon.** New CLI: `--peer-registry`, `--admission-key`,
`--require-admission`, `--salt-peers`, `--entangle-min`,
`--entangle-strict`, `--entangle-max-age`. New endpoints: POST
/peers/hello (admission bundle), GET /peers, POST /entangle/salt
(gated by IFF when admission required), POST /entangle/pull. INFER
appends embed the current fresh beacon; strict mode refuses inference
without one (503 ENTANGLEMENT_REQUIRED). /replicate/root refuses
non-admitted origins under --require-admission.

**Tests.** `tests/integration/test_entanglement_iff.py` — 8 groups:
signed-request validity/replay/staleness/path-binding/foe (I-1), live
admission + 403 for unrecognized bundles (I-2), salt gating (I-3),
replication gating (I-4), 2-issuer pull with witnessed issuance (E-1),
offline anteriority of embedded beacons (E-2), strict-mode refusal and
recovery (E-3), divergence judgment of a same-key rewrite (E-4).

**Status: 39/39 acceptance green.**

## Drop 5 — Cryptographic & Transactional Integrity (17 July 2026)

Closes the external audit of v0.5-dev.4. Priority order as recommended.

**STOP-SHIP FIXED — Ed25519 accepted keyless identities.** `verify()`
did not validate curve points: the identity/neutral point and the other
small-order (torsion) points were accepted as public keys, making a
zero-signature valid for ANY message. This did not forge honest keys, but
allowed a self-certifying identity WITH NO SECRET — and the auditor drove
it through the whole IFF chain (degenerate pubkey -> self-signed peer
record -> honest countersignature -> admitted peer -> authenticated
requests). Fix: `_decompress_checked()` rejects the torsion subgroup for
BOTH the public key and R ([8]P == identity test), plus cofactored
verification ([8]sB == [8]R + [8]kA). Verified: 0 acceptances across all
eight canonical small-order encodings x 4 messages x 3 signature shapes;
honest keys unaffected.

**Canonical NodeID unified.** One key had two identities: raw 64-hex in
the network layer vs `node:`+128-bit in identity/verdicts.
`crypto.canonical_node_id()` / `canonical_being_id()` are now THE single
derivation ("node:" + full 256-bit digest), used by NodeIdentity,
WitnessChain, verdicts, replication, peers, entanglement, manifests and
Plane H. Legacy M1-M5 records keep the legacy form by design — the
migration path must read history as it was written.

**Atomic witness append.** Was: `records.append()` then `_persist()` — a
failed fsync left a phantom record in RAM that the next append chained
onto. Now: durable persist FIRST, expose in memory only on success, with
commitment-salt rollback on failure.

**Atomic Plane H writes.** A witness failure previously left knowledge
committed in SQLite with no witness record — a direct violation of "no
unwitnessed mutable knowledge". `apply()` now owns one explicit
transaction: store mutations + Merkle + witness append commit together or
roll back together. `RagStore.add(commit=False)` added for transactional
callers (M5 default behavior unchanged).

**Journals fail closed on reload.** PeerRegistry, ReplicaStore and
ManifestRegistry re-verify every persisted entry (signatures, authority,
ACL) at startup and refuse to boot on the first invalid record. Forged
journal lines can no longer smuggle peers, roots or manifests past a
reboot.

**IFF hardening.** Signature is verified BEFORE the nonce cache is
touched (unauthenticated senders could previously grow it without
limit); atomic locked check-and-insert (ThreadingHTTPServer is
concurrent); hard capacity with refusal; malformed timestamps return a
controlled refusal instead of raising; re-registration is idempotent and
can no longer resurrect a SUSPENDED peer (reactivation requires an
explicit governance action).

**Entanglement corrections.** Freshness now derives from the SIGNED
`issued_at` (an ancient salt can no longer be re-wrapped as fresh);
salts are bound to their recipient (`beacon_from(recipient_node=)`);
the strict-mode gate moved BEFORE `engine.generate()` (it previously ran
inference and refused afterwards).

**Overclaim corrected.** "The forgery dates itself" is withdrawn.
`judge_divergence` now returns `a_anachronistic`/`b_anachronistic` with
`confidence: "evidential"`, and the module documents that sound
attribution needs a cryptographic cross-link (origin agreed root <->
issuer chain checkpoint <-> salt issuance). It is an investigative signal
for Stewards, never an automatic verdict.

**Keystore.** 0600 permissions and atomic temp+fsync+rename.

**Docs.** README version/repo/scope corrected; SECURITY.md non-goals
rewritten (replication = ROOT CHECKPOINTS ONLY: proves deletion/rewrite,
cannot restore history; entanglement experimental; manifest ids declared
not attested; no transport security); architecture map -> v0.5.0-dev5
with the new modules and honest statuses; pyproject declares LIBRARY
scope explicitly (node/, necs/, scripts/ run from a checkout).

**Tests.** `tests/adversarial/test_drop5_hardening.py` — 8 groups,
each verified to FAIL against the pre-fix code: ED-NEG-1..5 + ED-POS-1,
ID-1, J-1..J-3, A-1..A-2, N-1..N-3, T-1..T-2.

**Status: 49/49 acceptance green.** Build status remains
`v0.5.0-dev5 — experimental distributed trust fabric`: dev branch and
internal review only. NOT a public security-alpha; no production or
public-network deployment.

**Still open (next drop):** witness SEGMENT replication + recovery and
CT-style consistency proofs; entanglement cryptographic cross-link and
verified issuer chain exports; weight attestation + signed
DeploymentManifest; diversity wiring into the live router; unknown
provenance must lower confidence rather than read as independence;
generator_provenance passed explicitly; quorum receipts + _anchor_covered
restored on restart; signed_root() under the node lock; TLS/mTLS.

## Drop 6 — Replication Soundness (17 July 2026)

The Witness can now be RESTORED, not only avenged. Closes six of the nine
drop-5 tail items.

**RFC 6962 tree (`jjdai/merkle.py`).** CT-style Merkle Tree Hash alongside
the legacy padding tree: `mth_root`, `mth_inclusion`/`mth_verify_inclusion`
(position-bound audit paths), `consistency_proof`/`verify_consistency`
(§2.1.4.2). Same 0x00/0x01 domain prefixes as the RFC; only the tree shape
differs from the legacy tree. Exhaustively property-tested: every (n,
index) and (m, n) pair through n=24, forged leaves/prefix roots/truncated
paths rejected (600 checks).

**CT-style consistency (`core/replication.py`).** Signed roots are now
RFC 6962 heads (`root_alg: "rfc6962"`); legacy v1 envelopes still verify
as signatures but carry no consistency power (cross-alg same-count pairs
are explicitly NOT divergence). `make_consistency` produces the origin's
SIGNED prefix claim with the proof attached — so a failing proof is not
noise but durable INCONSISTENCY_EVIDENCE (the origin signed a false
claim); an unsigned mutation is "rejected" and carries no evidential
weight. ReplicaStore: `consistency_wanted` (consecutive-checkpoint
linkage; transitivity covers the full history), `record_consistency`,
`verified_prefix`, all fail-closed on reload.

**Segment replication + recovery (`core/segments.py`, new).**
`make_segment`/`verify_segment`: signed envelopes over records [start,
end) — envelope signature, per-record body hashes, per-record signatures,
internal continuity, GENESIS binding at 0. SegmentStore: durable coverage
maps, gap listing, and self-proving SEGMENT_DIVERGENCE (two validly
signed records, same origin, same index, different hash). `recover_records`
verifies a full reconstruction against a TRUSTED quorum-anchored root
(gaps NAMED, wrong root refused, seams re-checked) and
`write_recovered_log` emits a JSONL the live chain reloads and RESUMES
appending to. Honest limits documented: recovery restores what the origin
replicated; hiding-commitment salts are local-only and die with the disk.

**Entanglement cryptographic cross-link (`core/entanglement.py`).**
Closes the drop-5 overclaim correction with the actual mechanism:
`pull_salts` sends the recipient's SIGNED root; the issuer verifies it,
embeds it in the salt body and witnesses it in the SALT_ISSUE digest;
stored peer roots are witnessed as PEER_ROOT records (new witness KIND).
`find_issuer_checkpoint` locates the issuer record witnessing the
origin's chain at >= agreed_count; `judge_divergence` then convicts with
`confidence: "cryptographic"` and a per-record proof bundle — the proof
rests on (1) the origin's own signature on the agreed root, (2) the
issuer chain's hash ordering, (3) the salt inside the record's signed
body; stated assumption: issuer chain honest/anchored (use m-of-n).
Without the link, output degrades honestly to "evidential". Verified
issuer exports: `issuance_inclusion`/`verify_issuance_inclusion` prove a
SALT_ISSUE under the issuer's signed root without shipping the full chain.

**Daemon wiring.** New endpoints: `GET /witness/segment?start=&end=`,
`GET /witness/consistency?old=`, `POST /replicate/segment`,
`POST /replicate/consistency`. `receive_root` witnesses PEER_ROOT and
names what it wants next (`consistency_wanted`, `segments_wanted`);
`push_to_peers` serves both on demand (bounded 8-chunk catch-up per
cycle). `/replicate/status` now reports `anchor_covered`,
`verified_prefix` and `segment_coverage`. New CLI `--segment-store`
(default `<log>.segments.jsonl`). ANTI-PING-PONG: the background push
loop keys on the SUBSTANTIVE head — PEER_ROOT/ANCHOR_QUORUM bookkeeping
rides along with the next substantive push instead of triggering one
(two idle nodes no longer grow each other's chains forever).

**Tail fixes (drop-5 audit).**
- Quorum receipts + `_anchor_covered` restored on restart from the
  durable receipt journal; every persisted receipt RE-VERIFIED before
  trust (fail closed) — covered history is never re-anchored.
- `signed_root()` under the node lock (count/head/root are three reads of
  one chain); the ANCHOR_QUORUM append is under the lock too (it raced
  INFER appends). Race-tested: readers hammering signed_root against a
  concurrent writer — every envelope internally consistent.
- `core/diversity.py`: UNKNOWN IS NOT INDEPENDENT — a dimension missing
  on either side contributes its FULL weight to correlation; two silent
  manifests correlate at 1.0; rejections NAME the undeclared dimensions;
  silence cannot demonstrate independence from the generator. Fully
  declared disjoint manifests are unaffected.

**Tests.** `tests/unit/test_drop6_primitives.py` (RFC 6962 exhaustive +
diversity-unknown), `tests/integration/test_replication_soundness.py`
(S-1..3, C-1..3, live L-1..3 incl. recovery-from-peer and restart
restoration, T-1 lock race), `tests/integration/
test_entanglement_crosslink.py` (X-1..6 incl. live cross-linked pull).
New live suites save/restore the passphrase env (cross-suite hygiene).

**Status: 57/57 acceptance green.** Build `v0.5.0-dev6`. Remaining from
the drop-5 tail (next drop): weight attestation + signed
DeploymentManifest; diversity wiring into the live router with explicit
generator_provenance; external anchoring; TLS/mTLS.

## v0.5.1 — Drop 7: Closing P1 (17 July 2026)

The four remaining P1 tail items land in one release. Nothing here is a
new promise — each closes an already-documented gap with the mechanism
the gap called for.

**Weight attestation + DeploymentManifest (`core/attestation.py`, new).**
`measure_artifact` streams SHA-256 over the real weight file;
`make_weight_attestation` binds manifest_id <-> measured hash with two
HONEST binding classes: "content" (id is a true content address — a
mismatching binding cannot even be signed) and "declared" (symbolic ids:
the measurement pins the bytes, the id<->bytes link rests on the
operator's signature). `make_deployment_manifest` is FIRST-PERSON only
(signer == described node) and embeds hash-bound, pre-verified
attestations; `AttestationStore` is durable and fail-closed, and a
DIFFERING re-attestation is refused as a governance event, not accepted
as an update. Daemon: `--substrate-artifacts` measures at boot
(content-address mismatch refuses the boot, exit 2),
`--require-attestation` refuses unattested substrates, the manifest is
witnessed (new ATTESTATION kind) and served at `GET /attestation`.
`ManifestRegistry.provenance(deployment=...)` now derives
operator/jurisdiction from the VERIFIED deployment and labels its source
("signed-deployment" / "asserted" / "substrate-default") — a verifier can
tell signed facts from claims. Stated plainly: without TEE this proves
the operator measured and signed, not what the engine loaded into memory.

**Diversity → live router (`core/router.py`, `core/diversity.py`).**
Router accepts `provenance` (object_id -> ProvenanceManifest) plus panel
constraints; verification then runs through a diversity-constrained PANEL
instead of the generator's own node. `select_verifiers` gains
`generator_provenance` passed EXPLICITLY — closing the dev-5 hole where a
generator absent from the candidate pool silently disabled the clone
check (the unit suite demonstrates the hole first, then its closure).
Panels are witnessed (route.panel: selected / rejected-by-name /
constraints), verdicts are unanimous-fail-closed, the registry records
the WORST margin across the panel, short panels FAIL HONEST
(`allow_degraded_panel` proceeds only with degraded=true in the witness),
an unmanifested generator is refused rather than guessed, and the legacy
path labels itself mode="self" — the downgrade is visible, never silent.

**External anchoring (`core/anchoring.py`, new).** Durable AnchorLog
(fail-closed reload); backends: LocalFileAnchor (labeled single-host),
PeerQuorumAnchor (bridges replication quorum receipts — k peers hold this
exact root), OtsCalendarAnchor (POSTs the 32-byte RFC 6962 root to an
OpenTimestamps calendar and takes CUSTODY of the returned proof bytes,
status "pending-attestation" — Bitcoin inclusion is verified with
standard ots tooling against the stored proof, never claimed locally).
AnchorScheduler anchors the same RFC 6962 root the replication layer
signs — one root, all layers — through every backend, appends ONE
ANCHOR_EXTERNAL record (new kind), and ratchets: bookkeeping-only growth
is skipped. Daemon: `--anchor-backends local,peer-quorum,ots`,
`--ots-calendar`, `POST /witness/anchor` runs the scheduler,
`GET /witness/anchors` serves durable receipts.

**TLS/mTLS (daemon + `scripts/gen_dev_certs.py`, new).** The daemon
serves HTTPS with `--tls-cert/--tls-key` (TLS >= 1.2); `--tls-ca` +
`--tls-require-client-cert` enforce mTLS FAIL-CLOSED (certless handshakes
refused). Every peer-facing client path (root push, acks, segments,
consistency, salt pull) goes through one TLS-aware helper honoring
`--peer-ca` / `--client-cert` / `--client-key`; an https peer without
client TLS material is a configuration error, not a silent plaintext
fallback. `gen_dev_certs.py` issues a dev CA + per-node ed25519 leaf
certificates (SAN localhost/127.0.0.1, 30-day default) via the system
openssl — dev material by design; production PKI belongs to the operator.
Message-layer request signing (IFF) now LAYERS UNDER transport security
instead of substituting for it.

**Tests.** `tests/unit/test_v051_primitives.py` (A-1..4, P-1, N-1..3,
G-1), `tests/integration/test_router_diversity.py` (R-1..6, incl. the
shared-frozen-substrate panel model), `tests/integration/
test_tls_attest_anchor.py` (T-1..3 live TLS/mTLS incl. replication over
mTLS, W-1/W-1b/W-2 attestation boot gates, N-1 external anchoring with a
live mock OTS calendar and exact proof-custody round-trip).

**Status: 62/62 acceptance green.** Build `v0.5.1`. P1 remaining: full
Plane B canary protocol, GPU acceptance runs, rate limiting. P2 next:
DIIP, training federation, TEE/runtime attestation, multi-jurisdiction
witness network.

## v0.5.2 — Drop 8: the Monero anchor (17 July 2026)

One focused addition: a second EXTERNAL anchor with a different failure
mode than Bitcoin/OTS — and a different philosophy.

**Monero hash-as-spend-key anchoring (`core/anchoring_xmr.py`, new).**
Monero deliberately resists arbitrary on-chain payloads (tx_extra is
contested territory), so the root is not WRITTEN anywhere — it BECOMES a
key: spend scalar = sc_reduce32(root), view scalar =
hash_to_scalar(spend) per CryptoNote deterministic wallets, and one
piconero to the derived standard address is the timestamp. Zero on-chain
footprint; independent of the tx_extra policy debate by construction; the
payer is private (nobody maps JJ DAI nodes by their anchoring wallets —
something direct Bitcoin transactions could never offer).

Implemented stdlib-only: legacy Keccak-256 (0x01 padding, explicitly
tested against NIST SHA-3 divergence), CryptoNote key and address
derivation reusing the codebase's own ed25519 group math, varint network
prefixes (mainnet/testnet/stagenet), Monero block-wise base58. The whole
pipeline is pinned by ONE end-to-end vector: the spend key from the
monero-timestamp reference reproduces the exact 95-character mainnet
address `monero-wallet-cli --generate-from-spend-key` prints — keccak,
reduction, view-key derivation, scalarmult, checksum and base58 validated
in a single assertion. Derivation tag `jjdai-xmr-spendkey-v1` (legacy
CryptoNote v1 addresses — the format the network keeps honoring through
the FCMP++/CARROT era) is written into every receipt so future formats
can coexist.

**Backend + daemon.** `XmrAnchor` speaks monero-wallet-rpc (`transfer`,
one piconero, get_tx_key); receipts carry tx_hash + tx_key + the derived
address in custody, status "pending-confirmation" (hardens with the
10-block convention). `verify_receipt_binding` proves root->address
offline; full proof is honestly a chain operation with root-derived keys.
Daemon: `--anchor-backends …,xmr`, `--xmr-wallet-rpc`, `--xmr-network`;
missing wallet-rpc URL refuses the boot. Live suite runs a mock
wallet-rpc, re-derives the address from the anchored root independently,
and proves DEFENSE IN DEPTH: with the wallet-rpc dead the xmr receipt
fails NAMED and durable while the local backend still records — one dead
anchor never silences the round.

**Honest limits (also in SECURITY.md):** anyone who learns a revealed
root can sweep the anchoring piconero — dust by design, the timestamp is
the block, not the balance; the funding wallet must hold anchoring dust
only; absolute PoW rewrite cost is below Bitcoin's — which is exactly why
this is the FAST anchor (2-minute blocks) beside the DEEP one (OTS/BTC),
not a replacement for it.

**Tests.** `tests/unit/test_xmr_anchor.py` (X-K/X-B/X-D/X-R/X-S) and
`tests/integration/test_xmr_anchor_live.py` (M-1..M-5).

**Status: 68/68 acceptance green.** Build `v0.5.2`. Next on this track:
the VXXL m2m anchor + hierarchical anchoring design (Sākṣī → VXXL every
N minutes; VXXL state root → XMR hourly / BTC daily) once the VXXL
network has independent validators.

## v0.5.3 — Drop 9: the Being Composition Runtime (18 July 2026)

The v0.5.2 external audit named the central truth: JJ DAI had almost
every organ and no organism. This drop is the organism.

**runtime/ (new package).** `BeingRuntime` — ONE long-lived composition
owning one identity (the node's signer), ONE witness chain for every
organ, Smriti, governed Plane H, Viveka, the diversity Router, Karma and
the Article-25 gate. `runtime/state_machine.py` +
`runtime/decision_trace.py` drive every task through the witnessed
lifecycle RECEIVED → GROUNDED → PLANNED → GENERATED → VERIFIED →
AUTHORIZED → ACTED → RECORDED with first-class honest endings: REFUSED,
FAILED, FATE_UNKNOWN, CONTAINED. Transitions are validated against a
legal map (one step forward, any branch, nothing after terminal),
witnessed under the chain lock, then journaled; an illegal move writes
NOTHING. `runtime/recovery.py` restores MEANING after a restart — every
trace rebuilt with citations, plan and receipts — and resolves in-flight
fates honestly: an orphaned Karma intent (witnessed intent, no outcome)
closes as FATE_UNKNOWN; anything interrupted earlier closes as FAILED.

**Profiles (audit gate 2).** production: provenance and a full
independent panel are mandatory, self-verification is refused, degraded
panels never pass, and there is no flag to relax any of it (a production
boot without provenance exits 2). dev: the labeled mode=self path runs
and every trace visibly carries the label.

**Containment semantics (gate 3).** A contained Being still grounds,
plans, generates and verifies; only at the AUTHORIZED gate does a task
with an executive action turn CONTAINED — the hand is severed, the mind
is not. Proven in unit and three-node live tests: the file is never
written; a pure answer still ends RECORDED.

**Daemon.** `POST /v1/tasks` returns a full DecisionTrace — states,
citations (Plane H chunk hashes + namespace merkle root + Smriti recall),
plan hash, generator and panel provenance, containment decision, Karma
receipt, witness span — and `GET /v1/tasks/<id>` serves it across
restarts. New flags: `--being-profile production|dev`,
`--being-workspace`, `--being-journals`, `--being-provenance`.

**One-chain concurrency.** The witness chain now guards its own append
(chain-internal RLock); daemon root signing and the anchor scheduler
read under the same lock, so organ appends from handler threads can
never tear a signed root. The Being processes tasks strictly serially —
one mind, one lifecycle at a time, by design.

**Docs become code (audit drift fixes).** `docs/architecture_status.json`
is the single source of truth; `scripts/gen_architecture_docs.py`
generates the README status table, the architecture map and the HTML
status page from it; `scripts/check_docs_drift.py` + a CI acceptance
test fail the build if any surface drifts, any referenced path is
missing, or any fossil phrase of a past drift reappears. All four
concrete contradictions found by the audit are fixed and now
structurally impossible to reintroduce silently.

**Gate 7 (operator-run).** `scripts/live_engine_acceptance.py` runs the
full lifecycle against a real SGLang/DwarfStar endpoint and prints —
honestly — whether the panel was physically independent or degraded to
one endpoint.

**Tests.** `tests/unit/test_being_lifecycle.py` (B-SM/B-RT/B-PROF/
B-CONT/B-REC), `tests/integration/test_being_runtime.py` (G-1..G-5:
three real daemons over mTLS — full trace, evidence replication to two
peers, restart with meaning restored, containment hand-stop, profile
refusal), `tests/unit/test_docs_integrity.py` (DOC-1).

**Status: 75/75 acceptance green.** Build `v0.5.3`. Next: v0.5.4 —
adversarial challenge round (VRF sampling, commit-reveal, fraud proofs,
rate limiting), then the security-alpha operational boundary and the
Ubuntu testnet-0 deployment kit.

## v0.5.4 — Drop 10: the adversarial challenge round (18 July 2026)

Verification must survive adversarial verifiers. This drop gives
verdicts four properties they did not have: unbiasable seats, blind
verdicts, named silence, and fraud that convicts itself.

**Real VRF (`jjdai/crypto.py`).** The reserved `vrf_prove`/`vrf_verify`
seams are now RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI, stdlib-only over
the codebase's own curve arithmetic — and pinned to ALL THREE official
B.3 test vectors (pi and beta, byte-for-byte, matched on the first
run). Verification runs with validate_key semantics: small-order and
malformed keys, tampered proofs, out-of-range scalars all fail closed.
This buys full uniqueness — even the keyholder cannot grind a second
beta for the same input — which is exactly the property sortition
needs. `multisig_verify` also graduates from seam to code: naive m-of-n
with dedupe and outsider rejection (aggregate FROST signing stays
deferred, and says so).

**The round (`core/challenge.py`, new).** `ChallengeRound` on the ONE
witness chain: `open` fixes transcript-bound sortition parameters
publicly before any seat is claimed; `claim_seat` verifies each
verifier's VRF proof against the round alpha and the public threshold
rule (losing claims are witnessed too — nobody shops for unrecorded
losses); `commit` seals verdicts blind, one per seat, with double
commits refused AND witnessed; `reveal` opens them against the sealed
hash — a mismatch becomes a durable CHALLENGE_FRAUD proof carrying the
witnessed commitment index, verifiable OFFLINE by anyone with the chain
(`verify_fraud_proof`), slashing via the registry and excluding the
verdict; `resolve` tallies after the deadline — majority of valid
reveals, silence resolved as ABSTAINED, zero valid reveals resolved as
UNRESOLVED, never an invented verdict. Every phase is a witnessed
CHALLENGE record. Stated honestly: this is the in-process reference
protocol; the network transport (peers claiming seats over mTLS) rides
on IFF + crossverify and lands with the security-alpha.

**Rate limiting (`node/daemon.py`).** The first operational boundary:
per-identity, per-class token windows (`--rate-limit
"infer=30/60,task=10/60,write=60/60,read=120/60"`), enforced before any
heavy work. Over budget = 429 + Retry-After; one exhausted class never
silences another; the window is a budget, not a ban. Systematic abuse
becomes evidence: past the abuse threshold, exactly ONE witnessed
RATE_LIMIT record per offender per window (the limiter must never
become a witness-flooding vector) with the key hash and rejection
count. Malformed specs refuse the boot.

**Tests.** `tests/unit/test_challenge_round.py` (V-RFC/V-MS/C-SORT/
C-RND/C-FRD/C-ABS) and `tests/integration/test_rate_limit_live.py`
(R-1..R-4, live daemon).

**Status: 81/81 acceptance green.** Build `v0.5.4`. Next, as agreed:
the security-alpha operational boundary + the Ubuntu testnet-0
deployment kit (authorization policy, production PKI, challenge-round
transport, TPM-sealed keystore option, node bootstrap, runbooks).

## v0.5.5 — Drop 11: security-alpha + testnet-0 deployment kit (19 July 2026)

The boundary that turns a reference organism into something you can
operate among known operators.

**Authorization (`node/authz.py`, new).** Rate limiting bounds how much;
authz decides who may call what. Principals derive from the mTLS layer,
never from request bodies: `anonymous` (no client cert), `peer` (cert
chains to the CA), `admin` (peer whose CN is in `admin_cns`). A JSON
policy with default-deny and longest-matching-prefix rules; a specific
rule beats a broad one regardless of order; a malformed policy refuses
the boot. Denials are 403 with the matched rule named.

**Certificate revocation.** `--revoked-serials` (inline or `@file`) is
checked BEFORE authz: a revoked cert is 401 CERT_REVOKED on every path,
whatever its CN — revoked is nobody. Reloadable with a restart.

**Observability.** `GET /healthz` (open) and `GET /metrics` (Prometheus
text, peer/admin only) exposing witnessed counters: requests, authz
denials, rate-limit rejections, revoked rejections, witness records,
tasks, challenge rounds, uptime.

**Challenge round over the network (`node/daemon.py`).** The v0.5.4
adversarial protocol now runs across mTLS: `/challenge/open` (admin),
`/challenge/seat` · `/commit` · `/reveal` (peers), `/challenge/resolve`
(admin), with `--challenge-windows` for commit/reveal timing. Verifiers
claim seats with real VRF proofs, commit blind, reveal, and resolve to a
witnessed majority — verification is now adversarial AND distributed.

**Production PKI (`deploy/gen_pki.py`).** An offline root CA (key goes to
cold storage), per-node leaf certs with correct SANs and recorded
serials, admin client certs, and a revocation list — openssl-shelled, no
Python x509 dependency. Every issued leaf verifies to the root.

**Deployment kit (`deploy/`).** A hardened `jjdai-node@.service`
(NoNewPrivileges, ProtectSystem=strict, seccomp `@system-service`,
MemoryDenyWriteExecute, minimal ReadWritePaths); `bootstrap_node.sh`
(system user, dirs, keystore-backup discipline, systemd install);
optional `tpm_seal.py` (TPM 2.0 sealing of the keystore passphrase to
PCRs 0/2/4 — the agreed ladder's first rung); a default `authz.testnet.json`;
and `RUNBOOK.md` covering PKI, bootstrap, the un-skippable keystore
backup, health/metrics, rotation/revocation, restart/recovery, and
DIVERGENCE_EVIDENCE response.

**Tests.** `tests/unit/test_authz_policy.py` (A-DEF/A-LP/A-FC/A-KIT —
including a check that the shipped unit references only real daemon
flags) and `tests/integration/test_security_alpha_live.py` (S-1..S-5:
two daemons under a real PKI — authz by role, revocation beating
identity, metrics, the networked challenge round, PKI chain verification).

**Status: 86/86 acceptance green.** Build `v0.5.5`. testnet-0 is now
buildable on Ubuntu 24. Next on the roadmap: hardened Karma isolation
(wasm/microvm), Plane B canary lifecycle, then the knowledge-graph
semantics above Plane H — and DIIP only once the runtime it would govern
is stable.

# JJ DAI v0.6.1 — INV-9 v1.1 propagation

INV-9 wording clarified (non-executive, not causally inert); executive
prohibition unchanged; reflexive loop (J-Lens → Viveka → Chitta,
pre-finalization) sanctioned; direct output mutation remains forbidden.
Runtime deliverable: Ф3 (roadmap r5).

No behavioral change is implied in this build: the reflexive loop is a
Ф3 deliverable, and until it ships the runtime remains archive-only —
which is compliant with INV-9 v1.1. No enforcement code path was
touched; the invariant ID and its position in the invariant table are
unchanged. Charter Core invariants I–VIII are untouched (INV-9 is a
codebase invariant, not a Charter article).

Propagated per `INV-9_v1_1_propagation.md` to: `README.md` (five-layer
line, architecture diagram, canonical EN text + fail-closed and
reflexive clauses in §5), `docs/architecture_status.json` → regenerated
`docs/JJDAI_Code_Architecture_Map_v0.5.md` and site status page
(fail-closed clause added where persist-before-expose is described),
docstrings in `jjdai/witness.py`, `core/replication.py`,
`core/segments.py`, `node/daemon.py`.

**Status: acceptance re-run on v0.6.1 (no code paths changed).**

# JJ DAI v0.6.2 — macOS deployment kit (roadmap Ф0)

The Ф0 code deliverable: the testnet-0 deployment kit is ported to
macOS for the Apple Silicon node (MacBook Pro 128 GB / 2 TB) that will
carry DeepSeek4Flash + DwarfStar inference.

**`deploy/macos/org.jjdai.node.plist`.** A launchd daemon template
(bootstrap substitutes the node name): runs as the hidden `_jjdai` role
account, `KeepAlive` on failure with a 5 s throttle (safe — the Witness
is persist-before-expose), `ProcessType Interactive` so the trust plane
is never background-throttled on an inference host, logs under
`/var/lib/jjdai/log/`. The keystore passphrase is never present in the
plist.

**`deploy/macos/keychain_seal.py`.** The macOS counterpart of
`tpm_seal.py`: seals `JJDAI_KEYSTORE_PASSPHRASE` into the System
keychain (LaunchDaemons run pre-login) with an ACL restricted to
`/usr/bin/security`, refuses to overwrite an existing item, and refuses
non-macOS hosts with a clear message. Explicitly the roadmap's
**macOS Keychain degraded profile (non-SE-resident)** — stated, not hidden: the CLI
cannot create Secure-Enclave-resident keys; the protection boundary is
the OS, not the boot state; the chosen profile is recorded in the ops
log and fixed in the witness at bootstrap.

**`deploy/macos/jjdai_node_launcher.sh`.** Keychain unseal → daemon
environment → exec, with the SAME daemon flag set as the systemd unit;
fails closed on a missing or empty passphrase.

**`deploy/macos/bootstrap_node_macos.sh`.** Mirror of
`bootstrap_node.sh`: `_jjdai` role account via dscl, dirs, PKI install,
env file, plist render + `plutil -lint`, and the 24/7 power profile
(`pmset sleep 0 / powernap 0 / standby 0 / disablesleep 1`) so a laptop
chassis behaves like a server. Never overwrites an existing keystore.

**`deploy/RUNBOOK-macOS.md`.** Operator runbook for the Mac node:
systemd→launchd command map, Keychain sealing and its honest limits,
the un-skippable keystore backup, clamshell/UPS discipline, the ≥72 h
no-sleep-gap Ф1 gate, and §6 "What this host is NOT" (no
seccomp/MDWE/ProtectSystem parity; inference-plane separation is a Ф1
deliverable). Main RUNBOOK bumped to v0.6.2 with a cross-link and a
third passphrase option.

**SECURITY.md (Ф0).** Triage/report template (component, class, impact,
repro, P0–P3 severity ladder, disclosure preference); P0 wired to the
Emergency Security Procedure (Ф2); macOS degraded profile added to the
documented non-goals.

**Tests — `tests/unit/test_macos_kit.py`.** M-KIT (kit completeness),
M-PLIST (template renders and parses via stdlib plistlib; no secret in
the plist), M-FLAGS (launcher uses only real daemon flags AND matches
the systemd unit flag-for-flag — the kits cannot drift silently),
M-SEC (no embedded secrets, `bash -n` clean, fail-closed launcher,
honest non-macOS refusal).

Remaining Ф0 code items tracked for the next drops: Karma
wasm/microvm isolation start, Prometheus alert rules, canonical AGPL
finalization. Organizational Ф0 (Audit 0, root ceremony, operator
agreements, SLO owners) proceeds outside the codebase.

# JJ DAI v0.6.3 — audit response: deployment blockers + release integrity

Answers the external audit of v0.6.2 (two deployment blockers, doc
drift, kit hygiene). Daemon code intentionally untouched.

**Blocker #1 — systemd watchdog.** `WatchdogSec=60` removed from
`jjdai-node@.service`: the daemon has no `sd_notify(WATCHDOG=1)`, so
systemd would have killed a healthy node every interval, making the Ф1
"72 h green" gate unpassable. A stdlib NOTIFY_SOCKET heartbeat and
`WatchdogSec` return together in the observability drop.

**Blocker #2 — code ownership.** The daemon must never own its own
executable code. Both bootstraps now install `/opt/jjdai` as root-owned
(`root:root` on Linux, `root:wheel` on macOS; dirs 0755, files 0644,
launcher scripts 0755), leaving `/etc/jjdai` root:group and
`/var/lib/jjdai` daemon-owned. Ownership model documented in both
RUNBOOKs.

**macOS bootstrap hygiene (audit §5).** NODE_NAME validated
(`[a-z0-9-]`, no leading/trailing dash); UID/GID 399 collision guard
via `dscl -search`; group created before user; `_jjdai` no longer owns
`/opt/jjdai`.

**Profile renamed (audit §5).** "degraded/secure-enclave profile" was
ambiguous; it is now the **macOS Keychain degraded profile
(non-SE-resident)** everywhere (kit, RUNBOOKs, SECURITY, status JSON).
A true **Secure Enclave-backed profile** is reserved as a separate
future attestation profile. RUNBOOK-macOS gains an **M-LIVE** checklist
naming the operational evidence the unit tests do NOT prove (pre-login
unseal, cold reboot, ACL under the service account, FileVault/OS
update, 72 h no-sleep) for the Ф0 target-host acceptance run.

**Doc drift (audit §3).** README version line synced to
`jjdai.__version__` (was 0.5.2); both stale "no rate limits" claims
replaced with the accurate statement (token-bucket per endpoint class
since v0.5.4, currently IP-keyed); SECURITY.md contradiction removed
and the challenge round correctly described as networked over mTLS;
CHANGELOG gains a file-level header stating chronological order.

**New CI — `tests/unit/test_release_integrity.py`.** R-VER (README /
pyproject / SECURITY / last CHANGELOG header == `jjdai.__version__`),
R-PHRASES (outgrown claims forbidden in README/SECURITY), R-ACCEPT
(acceptance badge == actually collected tests), R-LICENSE (AGPL
placeholder must be loudly marked as a publication blocker until the
canonical text lands).

**AGPL (audit §4) — still open, now loud.** The canonical byte-exact
text could not be inserted in this environment (no network); the
placeholder is rewritten as an explicit PUBLICATION BLOCKER and
reported by R-LICENSE on every run. Insert the canonical text before
any distribution.

**Scheduled next (per audit):** Karma isolation seam + ingress
hardening (body caps, timeouts, concurrency semaphore,
certificate-identity rate-limit keying); then /readyz split, Prometheus
rules, sd_notify watchdog, Mac sleep/reboot alerts.

# JJ DAI v0.6.4 — Karma isolation seam + ingress hardening

Roadmap Ф0, drop v0.6.4 (r6.6.2 ordering). Two boundaries that had to
exist before testnet-0 carries traffic from anyone who is not us: the
boundary an action executes *inside*, and the boundary a request must
cross to reach the node at all.

## 1. Isolation profiles — `kernel/isolation.py`

Karma had exactly one way to execute: a real OS process fenced by path
confinement, rlimits, an environment scrub and a wall clock. That fence
is honest, but it is a DENY-LIST — the child holds the kernel's full
system-call surface and we subtract from it. Anything we did not think
to subtract remains.

`reference` — the v0.6.3 sandbox, unchanged, now a *named* profile.
It stays the default and the baseline every node can run.

`wasm-wasi` — execution inside a WebAssembly module under WASI. The
module cannot EXPRESS a system call it was not granted: no filesystem
beyond the directories the host preopens (exactly one — the workspace),
no sockets, no fork, no exec. An allow-list enforced by the runtime
rather than subtracted from the kernel.

Stated plainly, because it is the cost of the profile and not a gap in
the implementation: **arbitrary shell does not exist here.** The profile
executes a FIXED SET of precompiled tools, each pinned by digest in
`deploy/wasm-toolset/toolset.json`, and the digest is verified on every
execution. A narrower action surface is the point.

`microvm` — reserved in the registry, deliberately unimplemented.
Declaring a profile we cannot enforce would be exactly the silent
downgrade this module exists to prevent.

**Fail closed.** A declared profile whose runtime is absent REFUSES the
action. It is never downgraded to a weaker profile. A downgrade would
let a node believe it is acting inside a boundary it is not inside, and
the witness plane cannot save it: by INV-9 the witness observes and does
not intervene, so a record written after the fact restores nothing.

**Both paths are witnessed.** Refusal and execution alike emit intent
and outcome; the outcome of a refusal carries the refusal class and the
profile. The record does not make the refusal safe — not acting does
that. The record makes it accountable, which is the witness plane's only
job.

**Declared, not discovered.** `capabilities()` and `/healthz` report
which profiles this node can honour, so work needing a boundary is never
routed to a node that cannot provide it. Refusing the work is the honest
form of a fallback; doing the work in a weaker box is not. The
declaration moves to `/readyz` when the liveness split lands (v0.6.6).

**Dependency posture.** `wasmtime` is invoked as a SYSTEM BINARY through
the existing fence, not as a Python binding: the codebase stays
stdlib-only and the runtime becomes a declared host requirement entering
the SBOM through the ordinary supply-chain stream (v0.6.7).

New flag: `--isolation-profiles` (default `reference`).

## 2. Ingress hardening — `node/daemon.py`

Four defects, each paid for *before* authorization was ever reached.

**Body ceiling.** `Content-Length` was read as an integer and the body
read in full. Now the framing gate runs before the first byte of body:
over the cap → `413`, non-integer or negative → `400`, and chunked
encoding → `411`, because a length that is not declared cannot be capped
before it is read. The reader then consumes at most the validated
length, in bounded chunks, so a lying `Content-Length` cannot smuggle a
larger body past the parser.

**Concurrency ceiling.** A thread-per-connection server with no ceiling
converts a burst into memory exhaustion, and the witness contour shares
the process. Admission is now bounded and non-blocking: over the
ceiling the node answers `503` and closes rather than queueing work it
has not agreed to hold. Refusing early is a service to the caller too —
a fast "come back" beats a slow nothing.

**Connection clock.** Every connection now carries a timeout, so a
client that opens and then stalls mid-header or mid-body releases its
thread instead of holding it indefinitely — the cheapest denial of
service there is.

**The budget belongs to an identity, not to an address.** Rate limiting
was keyed by client IP. That charged everyone behind one NAT to a single
bucket, and let one certificate holder reset their own budget by moving
address. The mTLS chain is already verified at that point, so the key is
now `cert:<CN>:<serial>`; a namespaced `ip:` key is used only where no
client certificate was presented, and the two key spaces cannot collide.

New flags: `--max-body-bytes` (1 MiB), `--max-concurrency` (64),
`--request-timeout-s` (15). New metrics: `body_too_large_total`,
`bad_framing_total`, `overloaded_total`.

## Audit response (same drop, before tagging)

The external review of the first cut found one real blocker and three
smaller items. All four are closed here.

**P0 — the concurrency ceiling did not bound threads.** The admission
slot was taken inside the handler, which is to say inside a worker
thread that already existed. It bounded how many requests were
*processed* at once and did nothing about how many threads were
*created*: `ThreadingMixIn` spawns in `process_request`, before the
handler runs at all. Forty stalled connections against a ceiling of one
produced forty-two threads. The mechanism claimed a property it did not
have, and — worse — the acceptance check for it tested the semaphore's
semantics rather than the claim, so it passed.

Admission now sits in `BoundedThreadingHTTPServer.process_request`, on
the accept loop, before anything is spawned. Over the ceiling the socket
receives a 503 and a half-close on the accept thread itself: no worker,
no stack. The half-close is deliberate — a bare close with the peer
still sending resets the connection, and a caller that gets a reset
cannot tell "overloaded, retry" from "node is dead", which is the
distinction the 503 exists to carry. `--max-concurrency` now bounds
connections rather than in-flight requests.

G-6 is replaced: one hundred stalled connections against a ceiling of
four, asserting the worker-thread count never exceeds it — with a long
connection clock on purpose, so that timeout expiry cannot be what saves
the test.

**P1 — declared readiness was not executable readiness.** The wasm
profile checked that a runtime and a manifest existed, not that the
modules the manifest names exist and match their digests. A manifest
naming a ghost module reported READY and then refused at execution —
precisely the failure the declaration exists to prevent, since the
network routes work on the strength of it. Readiness is now computed per
tool: `toolset_status()` resolves and hashes every declared module,
`capabilities()` publishes `toolset_ready` and `toolset_broken`, and the
profile is ready when at least one tool can actually run. One drifted
entry no longer takes the whole boundary dark, and host conditions
(missing runtime) stay distinct from tool conditions (missing module,
drifted digest) so a refusal names the right cause.

**P1 — the boundary was proven only against a shim.** The hermetic suite
proves the mapping and the refusals; it cannot prove the boundary. A new
opt-in group `tests/live/` exercises the profile against a real
`wasmtime`: workspace reachable, external filesystem unreachable, no
network capability granted, no host binary launchable, and digest
tampering fail-closed. It is excluded from the default run and from the
published badge, and it FAILS LOUDLY without a runtime rather than
skipping quietly — a check that skips itself is not evidence. Required
by the Ф0 gate on each target host.

**P2 — a hand-written badge had drifted** (`68/68` in the README while
the generated one said `109/109`), and `kernel/isolation.py` described
the toolset manifest as "signed-in-place" when nothing signs or verifies
it. The badge is corrected and R-ACCEPT now checks hand-written badges
too, not only generated surfaces. The overclaim is replaced by what is
actually true, plus what is owed: by ADR-015 adding an executable tool is
an L2 capability mutation belonging in a Profile Gauntlet; until that
gate exists the toolset digest travels in `capabilities()` so a change is
at least visible even though it is not yet governed.

## Acceptance

94 → 111 in the default groups, plus five opt-in live checks. Each new
check is written to fail against v0.6.3, and G-6 and I-9 are written to
fail against the first cut of this drop: I-1…I-9
(`tests/unit/test_isolation_profiles.py`), G-1…G-8
(`tests/adversarial/test_ingress_hardening.py`), L-1…L-5
(`tests/live/test_wasm_live.py`, opt-in). The wasm runtime is stood in
for by a shim in the hermetic groups, so a clean checkout proves the
seam on any host.

## Still open after this drop

`/readyz` and the liveness split, `sd_notify` with the `WatchdogSec`
return, Prometheus alert rules, the `jjdai/adapters/` restructure, and
the canonical AGPL text (PUBLICATION BLOCKER). The wasm toolset ships as
mechanism only: no node in this build carries compiled modules, so in
practice execution is still the reference fence.

# JJ DAI v0.6.5 — adapter layer, and a vocabulary for the witness plane

Roadmap Ф0, drop v0.6.5. Two pieces of work that look unrelated and are
not: both are about closing a window that shuts at genesis. Serialized
shapes — the adapter contract, the record enum, the field set of a
witness record — are cheap to fix now and become schema migrations
afterwards.

## 1. `jjdai/adapters/` — the engine seam becomes a package

The architectural decision this encodes: **JJ DAI does not integrate each
LLM with its own adapter.** Engines integrate through one stable backend
protocol, model families arrive as declarative profiles, and a single
conformance suite proves compatibility. That is what keeps the daemon
from becoming a switch over vendor names.

Three terms that used to share the word "adapter" now have separate
names — **backend driver** (our code, connecting to an engine), **model
profile** (a declarative description of a family), **weight adapter**
(LoRA/DoRA over a checkpoint, the same word §8 of the ASIC spec uses).

**EngineBackend Protocol v1 is declared WHOLE, today.** The prototype
seam was enough for the current code and not for production serving or an
ASIC runtime. The temptation is to add methods as they are implemented —
but if a method is simply absent, every caller grows its own `hasattr`
probe and its own quiet fallback, and a quiet fallback is exactly how a
node ends up believing it has a capability it does not have. So the whole
v1 method set exists on every driver, and what is unimplemented raises
the typed `NotSupported`. Fail closed, the same posture the isolation
profiles took in v0.6.4.

**Capability is derived, never declared.** `capability_manifest()`
reports what a driver actually overrides. A hand-written capability list
is a claim, and claims drift from code; a derived one cannot.

Drivers: `hash` (the deterministic reference, moved out of `daemon.py` —
it was never node-specific), `dwarfstar` and `sglang` (moved from
`node/`), and `vllm`, `llama_cpp`, `mlx`, `asic` declared and refusing by
type so the registry, the conformance suite and the compatibility matrix
have real objects to interrogate rather than names in a document.

**Model profiles and ModelArtifactManifest.** A profile is written for
humans and is therefore *not* a cryptographic object of truth. The chain
is: profile → validation against a versioned schema → JCS → manifest →
hash → signature → witness record. Validation is strict and unknown keys
are refused: a field this build ignores is a claim nobody checks, and the
manifest would sign the disagreement.

`--engine` selection now goes through the registry, and the registry
admits nothing that fails the contract. Adding a driver never edits the
daemon. **Inference behaviour is unchanged by the move**, and A-4 checks
exactly that.

## 2. A vocabulary for the witness plane

An honest correction first, because the problem was narrower than it was
described when this work was scoped. `request` and `response` already
entered the chain as hiding COMMITMENTS and `provenance` as a hash, so
being-chosen bytes never reached a peer. `semantic_digest` is the one
field placed in the hashed body verbatim — and that is the one this drop
closes.

The plane now takes a **vocabulary**: enum tokens, integers, hex digests,
and one named exception for the fixed numeric histogram. Nested
node-authored structure is allowed, because that shape is authored by our
own schema; leaves are constrained, and depth and value count are
bounded. Prose is refused with the remedy named — pass `H(x)`, not `x`.

Not because today's callers misused the field. They didn't. But "no
caller does that" is a habit, and a habit is not an invariant. An
append-only, replicated, undeletable store that accepts free text is both
a covert channel and an unbounded write.

**Refusal reasons became codes.** The challenge round carried sentences
like "no valid reveals — the round refuses to invent a verdict" into the
chain; the rate limiter carried an explanatory note with every abuse
record. Both are now versioned codes with an optional evidence hash,
which is what the roadmap already required of refusal reasons in general.
The sentences still exist — they go to the caller and the local log,
where they neither replicate nor persist forever.

## 3. Reserved before genesis (cross-cutting track IV)

Declared now, emittable only in Ф2–Ф3:

- record kinds `SESSION_OPEN`, `SESSION_CLOSE`, `LEDGER_ANCHOR`,
  `SNAPSHOT`;
- nullable fields `session_id` and `ir_schema_version`, omitted entirely
  when absent so a record that does not use them is byte-identical to a
  v0.6.4 record.

Emitting a reserved kind refuses: reserving a NAME is cheap, emitting a
record whose semantics are undefined is not. The reasoning is the same
one that closes the guardian-terminology window — witness records are
JCS-canonicalized and hash-chained, so a value that has entered the chain
cannot be added or renamed afterwards without breaking every hash after
it. One line before genesis; a schema migration after.

## Audit response (same drop, before tagging)

Three blockers and three smaller items, all closed here. Two of the three
blockers were invisible to acceptance — and in both cases the test that
should have caught them was named after the claim while checking
something adjacent to it. That is the same failure mode as G-6 in v0.6.4,
and it is worth naming as a pattern rather than as two incidents.

**P0-1 — the registry existed and the daemon walked past it.** The
CHANGELOG said engine selection went through the registry; the test was
called "the registry is the only door"; `node/daemon.py` still read `if
args.engine == "sglang" ... elif "dwarfstar" ... else hash`, and
`create_backend` was imported and never called. The test checked the
registry in isolation, which passed, while the door it was named for
stood open. `vllm` was registered and unreachable, and adding a backend
still meant editing the daemon — the one thing the seam exists to
prevent.

The deeper cause was a missing second contract: factories with different
signatures do not remove the branch, they relocate it, because the caller
must still know that DwarfStar takes a URL and the reference driver does
not. So drivers now take **one** `BackendConfig`. What a driver does not
use it ignores; what it requires and does not find it refuses by name, so
an operator reads "dwarfstar requires url" rather than a `TypeError` from
three frames down. `--engine` has no hardcoded choices any more: the set
of engines is whatever the registry carries. New check A-10 reads
`daemon.py` for the branch and fails if it returns.

**P0-2 — the reserved fields re-opened the channel the vocabulary had
just closed.** `session_id` and `ir_schema_version` bypassed
`check_plane_value` entirely and were emittable on an ordinary INFER
record, so free text reached the replicated chain through the new door
while the old one was being bolted. Worse, W-6 as written asserted that
they COULD be set — the test enshrined the hole. Reserved now means
reserved on both axes: populating either field refuses, exactly as
emitting a reserved KIND does, until their grammar lands in Ф2–Ф3. W-6 is
rewritten to attempt precisely the free text the auditor used.

**P0-3 — a valid signature was being read as a valid manifest.**
`verify_manifest()` recomputed the hash and checked the signature, and
stopped. A signature proves who wrote a thing, never that the thing is
well formed, so a buggy or hostile signer could emit cryptographically
perfect nonsense — `{"junk": "yes"}` verified — and every verifier would
accept it. For a provenance object that admits a model to the decision
path, shape is part of what must be true. `validate_manifest_body()` now
runs FIRST: exact schema version, required fields, unknown keys refused,
`checkpoint_hash` and every weight adapter in `<algo>:<hex>` content-
address form, `profile_hash` a 64-hex digest, protocol version supported.

**P1 — the capability manifest contradicted itself.** `METHOD_GROUPS`
mixed methods with attributes, so `fingerprint` was reported
`not_supported` on a driver that plainly had one, and `capabilities()`
counted as an unimplemented backend capability when it is supplied by the
framework for every driver. Three kinds are now kept apart: driver
METHODS, required ATTRIBUTES, and FRAMEWORK methods. The workaround this
had forced in `phase_readiness()` is gone with it.

**P1 — Steward → Guardian is now swept** through current code, comments
and docs, including the serialized state value `PENDING_STEWARD` →
`PENDING_GUARDIAN`. CHANGELOG history is left alone: it records what was
true when it was written. Zero current occurrences remain.

**P1 carry-over from v0.6.4 — the record named the boundary but not the
hand.** Karma's provenance carried `isolation_profile` and nothing about
which executable could run there. It now carries `toolset_hash` and the
runtime, so a witness record can prove not merely "the being acted inside
wasm-wasi" but which toolset its hand could reach.

**P2 — a driver's import error no longer disappears.**
`except Exception: pass` in `backends/__init__.py` meant a driver with a
syntax error simply vanished from the registry: the node reported one
fewer capability and nobody could ask why. Failures are recorded, exposed
through `import_errors()`, named in `--engine` help, and quoted when an
unknown backend is requested.

## 4. README ownership — the build stops touching the prose

Requested by whoever pushes to the repository, and correct: the intro must
either be left alone by the build or live somewhere the build cannot
reach.

It was already half true — `gen_architecture_docs.py` spliced only
between the STATUS markers. But the version line and the acceptance badge
were hand-written text that build steps edited anyway with a `sed`, which
is how a maintainer's wording gets silently replaced by the next
generated README, or turns into a merge conflict for a one-word change.
The repository had already corrected "3-layer" to "3-tier" in section 1;
nothing stopped a build from putting "3-layer" back.

Ownership is now explicit and enforced rather than agreed:

- the build owns exactly three fenced blocks — `VERSION`, `STATUS`,
  `ACCEPT` — and the version line and acceptance badge moved INSIDE them,
  so no build step has any reason to edit prose;
- everything else, including the title and section 1 "What is JJ DAI",
  belongs to the repository. The sentence that explains the project to
  someone who has not met it is not something a generator that knows only
  a status file should be writing;
- `tests/unit/test_readme_ownership.py` copies the tree, plants a
  sentinel inside section 1, runs the generator, and fails if a single
  byte outside the marker blocks changed. It also checks idempotence, so
  a build never hands the repository a diff it did not ask for;
- a build that needs to say something new gets a NEW marker block. It
  does not reach into the prose.

## Acceptance

111 → 133. Twenty-two new checks: A-1…A-11
(`tests/unit/test_adapter_layer.py`), W-1…W-7
(`tests/unit/test_plane_schema.py`), R-OWN-1…R-OWN-4
(`tests/unit/test_readme_ownership.py`) and X-1…X-3
(`tests/unit/test_changelog_attribution.py`), plus the five opt-in live
checks from v0.6.4.

**A correction, and a check for it.** The first cut of this entry claimed
A-1…A-11 for `test_adapter_layer.py` while that file's own header still
documented A-1…A-9: the two checks added during the audit response went
in as functions and never into the description. Someone looking up A-10
in the file the CHANGELOG named would have found nothing, and the next
zip would have carried the wrong map back into the repository.

Prose was checked by nobody, so nothing caught it. X-1…X-3 now read every
`ID-N…ID-M (path)` attribution in this file and verify that the path
exists, that every ID in the range is documented in that file's own
header, and that a file's IDs are contiguous. On its first run it
immediately found a second instance of the same defect, in v0.6.4:
`test_ingress_hardening.py` had a `G-6b` where the CHANGELOG counted
through `G-8`. Renumbered — there is no `G-6b` any more.

## Still open after this drop

`/readyz` and the liveness split, `sd_notify` with the `WatchdogSec`
return, Prometheus alert rules (v0.6.6), and the canonical AGPL text
(PUBLICATION BLOCKER, v0.6.7). The dead-drop analysis leaves a bounded
metadata channel — record counts, kinds, timing — which this drop does
not address. And the deeper form of the same rule, where the runtime
keeps the local chain and the witness plane does the anchoring so no
organ of a being calls `append` at all, remains Ф3 work under ADR-015.

---

# JJ DAI v0.6.6 — observability: the difference between running and serving

Scope: the observability drop the v0.6.3 audit deferred. `/healthz` becomes
liveness alone, `/readyz` arrives beside it, `sd_notify` returns `WatchdogSec`
to the systemd unit, host suspension becomes visible, and the isolation
toolset stops reporting two different events under one word. Inference
behaviour is unchanged; no serialized witness value is added or renamed, so
nothing in this drop touches the pre-genesis window.

## The split, and why the obvious design was rejected

Until now a node answered exactly one health question and answered it with
`ok: true` for as long as the process could form a reply. The v0.6.3 audit
recorded the consequence plainly: `/healthz` is liveness-only. Anything that
reads a liveness answer as permission to send work will send work to a node
that is running and cannot serve.

The obvious readiness design — one boolean — was rejected on arithmetic
rather than taste. **This build ships no compiled wasm modules.** A freshly
deployed node therefore has an unprovisioned toolset by construction. Under a
single flag no node would ever report ready, and the flag would be switched
off in the field within a week, which is worse than not having it. Meanwhile
the witness contour, which is what actually makes a node a participant, does
not depend on wasm at all.

So readiness is reported **per subsystem**, and the aggregate is red only for
the subsystems without which the node is not a participant:

    CORE      identity · witness · anchoring
    NON-CORE  engine · isolation · being

Four states, not two: `ready`, `degraded`, `not_ready`, `not_configured`.
The fourth matters. A testnet node with no anchor backends is not a broken
node, and reporting it as `not_ready` trains operators to ignore the field.
Absence of a feature and failure of a feature are different facts and are
kept apart here as everywhere else in this codebase.

Two consequences worth naming because they are policy, not implementation:

- **an ephemeral (dev) identity is `degraded`, not `ready`.** The node
  functions, but nothing it signs carries continuity across a restart, and an
  operator who cannot see that difference on a dashboard discovers it at the
  worst possible moment.
- **a contained being is `degraded`, never a fault.** Under Article 25
  containment is a state of the identity with due process attached. A
  monitoring stack that pages the operator for it turns a governance event
  into an incident.

`/readyz` answers **503** when the aggregate is red, so an orchestrator that
reads only the status code behaves correctly without parsing the body. The
mapping is a named function (`readiness.http_status`) rather than an inline
conditional, so it is checked directly — an untested contract is a comment.

**Authorization.** `/healthz` stays anonymous and now leaks nothing: the
isolation fields that rode there since v0.6.4 have moved to `/readyz` as that
drop promised. `/readyz` is `peer` and `admin` only. It names which engines
are loaded, what is broken and how far anchoring has fallen behind — together
a usable map for whoever is choosing where to push.

## The watchdog returns, gated

v0.6.3 removed `WatchdogSec=60` for the right reason: the daemon could not
answer it, and an unanswered watchdog would have killed a healthy node every
interval. It returns here at 90s, together with the `sd_notify` heartbeat it
was waiting for, and the unit becomes `Type=notify` — `READY=1` is sent once
the listener is actually bound, so units ordered after this one start against
a node that can be reached rather than a process that has been forked.

**The heartbeat is gated on a beacon refreshed by the accept loop.** A
heartbeat firing unconditionally from its own timer thread is theatre: the
failure a watchdog exists to catch is a process that is alive and stuck — a
deadlocked accept loop, an organ holding a lock forever, a thread pool with
no free worker — and a dedicated timer survives all of them and keeps
pinging, so systemd concludes the node is fine precisely when it is not. Here
the watchdog reports *the part of the process that answers the network is
moving*, and reports a wedged one by **silence**.

The beacon is touched in `process_request`, on the accept loop, before
admission — not inside a handler, where it would stay fresh while the accept
loop was wedged. Staleness tolerance is three intervals, because a node under
heavy inference is legitimately slow to come round and a watchdog that
restarts a busy node is a load amplifier.

**The heartbeat is deliberately NOT gated on readiness.** A node whose anchor
lag exceeds policy must stop receiving work, but killing and restarting it
would not fix an anchor backend and would destroy a node holding its chain
correctly. Feeding readiness into the watchdog turns every upstream outage
into a fleet-wide restart loop.

## Host suspension is now visible

The Ф1 gate requires `/healthz` green for 72 consecutive hours on every node
including the Mac node, and says so with an explicit parenthesis: without
sleep breaks. A laptop-class host is in the topology on purpose — it carries
the inference path — and a host that suspends does not crash, does not log an
error and does not fail a health check. It comes back with its uptime intact
and its replication behind, and nothing notices.

`node/clockwatch.py` compares wall time against monotonic time every two
seconds. Both `CLOCK_MONOTONIC` on Linux and `mach_absolute_time` on Darwin
stop while the machine is suspended; wall time does not. The divergence is
the suspension, and detecting it needs no platform API and no privileges.

A **backwards** divergence is an NTP step, not a suspension, and is counted
as a separate series. Folding the two together would fire the sleep alert on
every clock correction and get it muted within a month.

Nothing here is written to the witness plane. A host suspending is an
operational fact about a machine, not an act of a being.

## "Broken" was one word for two different events

The isolation toolset previously reported a per-tool failure as a string. Two
of those strings meant very different things:

- a module that is **absent** is an operations fact — someone shipped the
  manifest without the artifact, and on this build it is the *expected* state
  of a fresh node;
- a module whose digest has **drifted** from its pin is a security fact — the
  artifact under the pin is not the artifact that was pinned.

The first is common and the second is rare, and merging them guarantees the
rare one is read as the first. Failures now carry a machine-readable cause
(`MODULE_MISSING`, `DIGEST_DRIFT`, `UNPINNED`, `NOT_PERMITTED`,
`OUTSIDE_ROOT`), the metric set counts them separately, and the shipped alert
rules page **security at critical** for drift while a missing module is
**info** and pages nobody.

`UNPINNED` was split out in the same pass: a manifest entry carrying no
`sha256` is a manifest defect, not evidence of tampering. Both refuse
execution; only one of them should wake anybody up at 3am.

`toolset_status()` is unchanged and `toolset_report()` sits beside it.
Changing a return shape to add a field is how a build acquires a regression
it did not need.

## Shipped

- `node/readiness.py` — the rules, evaluating a plain snapshot dict, importing
  nothing from the daemon. `node/daemon.py` gathers the facts. Keeping the
  claim and the measurement in different modules is the direct answer to the
  v0.6.5 finding that a check named after a claim while measuring something
  adjacent to it is worse than no check.
- `node/sdnotify.py` — stdlib `sd_notify` over an AF_UNIX datagram socket,
  abstract namespace included; `Beacon`; `Watchdog` with a testable `tick()`.
  No systemd required to import: on macOS `available()` is false and every
  call is a no-op.
- `node/clockwatch.py` — suspension and clock-step detection.
- `deploy/prometheus/jjdai-alerts.yml` — 16 alerts, each naming one fact with
  one owner. `deploy/prometheus/README.md` documents the mTLS scrape.
- `deploy/grafana/jjdai-node-dashboard.json` — starter dashboard.
- `deploy/jjdai-node@.service` — `Type=notify`, `NotifyAccess=main`,
  `WatchdogSec=90`, `WatchdogSignal=SIGABRT`, readiness policy flags.
- `deploy/authz.testnet.json` — `/readyz` for `peer` and `admin`.
- new flags: `--anchor-lag-max-s`, `--unanchored-depth-max`, `--no-watchdog`,
  `--sleep-gap-threshold-s`.

Acceptance 133 → 140. New checks: R-1..R-9 (readiness rules and the status
contract), S-1..S-6 (notify and the beacon gate), C-1..C-4 (suspension versus
clock step), T-0..T-5 (fault codes), A-1..A-5 (the alert rules as a
deliverable), H-1..H-6 (the live split, including that `/healthz` leaks
nothing and that the shipped policy keeps anonymous out of `/readyz`).

## Found by the build's own checks

**M-FLAGS** caught the macOS launcher drifting from the systemd unit the
moment the two readiness flags were added to the unit and not to the
launcher. The flag-parity test earns its place again; the launcher now
carries both.

**One assertion was written from the implementation rather than the
requirement** and was corrected before the cut: a check asserted that one
good tool keeps the wasm profile available, which is false on a host without
`wasmtime` — availability depends on the host runtime as well as the tools.
The corrected check pins what the v0.6.4 audit actually required: a refusal
must name the *right* cause, so on a runtime-less host the profile reports a
host reason and must not report a tool fault it does not have. This is the
same failure mode as G-6 in v0.6.4 and W-6 in v0.6.5, caught in the drop that
introduced it rather than in the audit after it.

## Still open after this drop

- `jjdai/adapters/` restructure landed in v0.6.5; the **canonical AGPL text**
  remains a PUBLICATION BLOCKER and is v0.6.7 together with the supply-chain
  stream.
- **No compiled wasm modules ship.** Execution in practice is still the
  reference fence, and the live group (`tests/live/`) still requires a real
  runtime on the host.
- **SLO values remain TBD.** The alert thresholds in the shipped rules are
  starting points, not the SLO table: r6.6.2 assigns SLO owners in Ф0 and
  leaves the values open until the end of Ф3. No recording rules ship, for
  the same reason — shipping thresholds now would mean shipping guesses with
  the authority of a config file.
- **`readiness_snapshot()` reports `chain_broken` as empty and
  `signer_mismatch` as false** rather than re-verifying the chain on every
  scrape. The boot gate already refuses to start on a foreign identity, and a
  full chain verification per request would be a self-inflicted denial of
  service. A cheap periodic re-verification with its result cached belongs in
  the same phase as the cognitive ledger, and is named here rather than
  implied.
- **Anchoring lag reads optimistically** when the scheduler exposes no
  timestamp: a node that has never anchored reports `null` lag rather than
  infinite. The metric is honest about not knowing; the alert cannot fire on
  it. Closing this needs the anchoring scheduler to publish its own last
  successful anchor, which is a change to that component and not to this one.

## v0.6.6 — audit response (recut)

External audit REJECTED the first cut of v0.6.6 with three reproducible P0s,
none of which the 140 acceptance checks caught. The number is unchanged: a
build number is spent by a tag, and v0.6.6 was never tagged or published.

Two of the three P0s were introduced by this drop, and both are the same
mistake in different clothing — **a claim was implemented and the thing it
claimed was never measured**.

| Finding | Root cause | Changed | Evidence |
|---|---|---|---|
| P0-1 idle node restarted by systemd | beacon touched in `process_request`, which runs only when a connection ARRIVES; an idle node aged out, went silent and was killed | `node/daemon.py`, `node/sdnotify.py`, unit, RUNBOOK, alerts | `OBS-WD-1..6` |
| P0-2 failed anchor counted as covered | `_covered = count` after submitting, whatever the receipts said; restart rebuilt coverage from any receipt | `core/anchoring.py` | `ANCH-RETRY-1..6` |
| P0-3 `/readyz` blind to anchoring | read `last_anchor_at` / `unanchored_depth`, neither of which existed; `getattr` defaults made an absent measurement green | `core/anchoring.py`, `node/daemon.py`, `node/readiness.py` | `READY-ANCH-1..5` |
| P1 engine readiness false positive | `engine is not None` answered "does an object exist" | `node/daemon.py` | `R-*`, live |
| P1 synthetic witness/identity facts | `chain_broken=""`, `signer_mismatch=False` hard-coded | `node/daemon.py` | `R-*` |
| P1 `/healthz` leaked | published node id, uptime and record count while claiming to publish nothing | `node/daemon.py` | `H-1` |
| P1 gauges named `_total` | recomputed from state, can go down; a Prometheus `_total` must be monotonic | `node/daemon.py`, alerts | `A-6` |
| P1 forward clock step read as sleep | wall-vs-monotonic cannot tell a forward NTP correction from a suspension | `node/clockwatch.py` | `CLOCK-1..5` |
| P1 wheel lost the adapter layer | hand-written package list | `pyproject.toml` | `WHEEL-PKG-1..3` |

### The watchdog measures the accept loop, not the traffic

The beacon now moves in `service_actions()`, which `serve_forever()` calls on
every loop iteration whether or not anyone is talking to us. The first cut's
own CHANGELOG explained why the beacon must track the accept loop — and then
attached it to an event that does not happen on an idle node.

`should_ping()` (policy) is split from `tick()` (policy **plus** delivery),
because a test that cannot tell "the node is healthy" from "systemd heard us"
proves neither. A ping now counts only once `sd_notify` has succeeded;
failures get their own metric. `Thread._stop` was renamed `_stop_event`: the
old name shadows a `threading.Thread` internal and breaks `join()`.

One number, `DEFAULT_STALE_AFTER_S = 30`, is now quoted by the unit, the
alert rule and the runbook, and `OBS-WD-6` fails if any of them drifts. The
first cut had three different numbers in three places and none of them was
the one in force.

### Coverage is per backend, and only success is coverage

`recorded` is coverage. `pending` and `pending-attestation` are attempts.
`failed` is an attempt that is known not to have worked. A restart rebuilds
coverage only from receipts that succeeded.

A **local file is not external anchoring** and cannot discharge an external
policy, so `required_backends` defaults to everything that is not local. A
required backend that is behind is reason enough to run — waiting for
unrelated cognition before retrying meant that on a quiet node a failed
anchor was never retried at all. Retries contact only the backends that are
behind, are spaced by backoff, and **write no chain record when nothing
changed**, or every failed retry becomes an event and the node writes
bookkeeping to itself forever.

Two subtleties that only appeared under test, both the same shape: the "is
there news" question and the "is this backend behind" question must be
measured against what has been **attempted**, not against what is
**confirmed**. Measured against coverage, a single `pending` backend froze
the ratchet at zero, made every old record look new forever, and re-anchored
the node on every tick.

`anchored` keeps its established meaning — a round was submitted and one
`ANCHOR_EXTERNAL` was appended. Whether every required backend holds the
range is a different question and got its own field, `fully_covered`, rather
than quietly redefining an old one.

### Facts, not assertions

`anchor_status()` publishes what readiness reads. `_engine_readiness()` asks
the backend and reports **UNKNOWN as not-ready** where no probe exists.
`_chain_verdict()` verifies at most once per interval and caches — verifying
per scrape would be a self-inflicted denial of service, and asserting `""`
is not a measurement. `_signer_mismatch()` checks the recent chain instead of
returning a constant on the grounds that the boot gate would have caught it:
the gate runs once, readiness is continuous.

Unknown is not green. A required backend that has never succeeded, with
substantive records unanchored, reads `NOT_READY`.

### Smaller things

`/healthz` now returns `{"ok": true}` and nothing else. `node.beacon` became
`node.liveness_beacon` — the same object already carried `beacon_source` and
`current_beacon` for entanglement, and one word for two unrelated things is
the defect this project keeps finding under other names.

Suspension is measured against a suspend-inclusive clock (`CLOCK_BOOTTIME`)
where one exists, so a forward NTP correction can no longer be counted as a
sleep — and could no longer fail the 72-hour Ф1 gate. Where no such clock
exists the detector degrades to the old comparison and **says so** in
`clock_source`.

Evidence IDs for new and rewritten checks are namespaced (`OBS-WD-*`,
`ANCH-RETRY-*`, `READY-ANCH-*`, `CLOCK-*`, `WHEEL-PKG-*`). Retrofitting the
whole suite and adding a machine-checked catalogue with duplicate refusal in
CI is a separate Ф0 drop by decision: it is a repo-wide change and does not
belong in an audit-response cut.

Acceptance 140 → 144, all green. Docs drift clean.

### Accepted deferred debt

- **evidence-ID catalogue** (`evidence_id → test → requirement → gate`, CI
  refusing duplicates) — own Ф0 drop, before the Ф0 gate. Owner: protocol.
- **Guardian Action Envelope** — admin-mTLS alone does not prove a guardian
  acted; a compromised daemon could record consent that was never signed.
  Belongs with G-GUI, not here. Owner: protocol, Ф0.
- **cognitive-ledger recovery** — "not replicated" and "snapshot plus
  subsequent events restores the Being" cannot both hold when the disk dies.
  Needs encrypted off-host backup or a stated continuity RPO. Owner:
  runtime, Ф3.
- **Object Security Matrix as a normative dependency of v0.6.8** — it exists
  in ADR-018 rev 2 and must be confirmed separately before the reserve is
  frozen. Owner: architecture.
- **`/readyz` witness verification depth** — the cached verdict is
  structural, not a full replay. Owner: runtime, Ф3, with the ledger.

---

# JJ DAI v0.6.7 — repo hygiene, a CI-visible flake, and a documentation entry point

**INCOMPLETE DROP — DO NOT TAG.** v0.6.7 still owes the supply-chain stream
and T-TOOLSET. The canonical AGPL text landed in the second audit response
below, closing the PUBLICATION BLOCKER that had stood since v0.6.3.

## Hygiene: five of the six items accepted 26 July

**The generated map's filename tracks the version.** `MAP` was a constant
naming v0.5 while the title *inside* the file tracked the version correctly,
so the name rode three months of drops — the file was regenerated every build
and only its name was frozen. It derives from `architecture_status.json` now;
the generator writes the version-named file and removes the stale one; drift
check 5 asserts exactly one map exists and its NAME matches the declared
version. Verified to fail on all three shapes: name behind the version, two
maps at once, no map at all. Checks 2 and 3 had to be guarded against a
missing file first — a gate whose contract is "every finding is named" must
not exit through a traceback.

`docs/README_BUILD_v0.4.md` → `docs/history/`. `tests/legacy` →
`tests/compatibility`, with `GROUPS`, the CI invocation and CONTRIBUTING's
group list following, and `run_acceptance` now **refuses an unknown group**
instead of running everything: typing the retired name printed a full green
count, which reads as a pass for a group that no longer exists.

`cv="legacy"` in `jjdai/witness.py` and `m1m5/witness.py` is a canonicalization
version that has entered the chain. Unrelated, deliberately untouched.

`experimental/plane_b/` stays undone, as a decision rather than a gap: both
files it names are load-bearing for the frozen m1m5 lineage, and Plane B
canary lifecycle is still Planned, so the folder would contain nothing that is
actually Plane B. It arrives with the canary-protocol drop.

## The recut reddened CI on Python 3.10, and the recut's own check was why

`tests/conformance/test_wheel_pkg_recut.py` imported `tomllib` unguarded.
`tomllib` arrived in **3.11**; the project declares `requires-python = ">=3.10"`
and CI runs 3.10, so the new check left that job with an import error rather
than a verdict. It uses `tomllib` where it exists and reads the two literal
arrays it needs directly where it does not.

Skipping on 3.10 would have been worse: a check that does not run on the
oldest supported version is not evidence about that version, and this one
guards a wheel that precisely those users would install. Both paths verified
to return identical values, package data included.

## The challenge-round flake was real

CI went red on 3.10 with `only 2 seats; rerun-worthy`. `_verifiers()` built
keys with `SigningKey.generate()`, so every run drew fresh ones. Sortition is
deterministic *given* the keys — which is what C-SORT asserts — but the NUMBER
of seats was a fresh binomial draw. At n=12 with k=6 it lands under the 3
seats C-RND needs about 2% of the time: roughly one CI run in seventeen across
a three-job matrix, on nothing. Keys derive from a fixed seed now, pinned to a
fixture drawing 6 of 12 — the expected value, with margin. A fixture that
merely cleared the threshold would trade a flake for a cliff.

## SECURITY.md was describing a node we no longer ship

The scope-notes paragraph still said rate limiting was keyed by client IP and
that there were no body-size or concurrency caps. Both stopped being true in
**v0.6.4**: the budget moved to certificate identity, the body ceiling is
enforced before the body is read, and the connection ceiling is admitted on
the accept loop. For a security document, describing absent defences that are
in fact present is not a harmless lag — it invites a reporter to spend time on
a finding that is already closed, and it makes every other claim in the
document less trustworthy.

The corrected paragraph also states what is genuinely still open: the
wasm-wasi profile ships as a mechanism with no compiled toolset, so execution
in practice remains the reference process fence.

Both operator runbooks were titled v0.6.3 while their contents had been
updated through v0.6.6. Retitled.

## A documentation entry point

External onboarding review scored the repository around 5.5/10 for a newcomer:
strong quick start and test discipline, but no architectural source of truth
in the tree, and no path from a diagram to the decision behind it. `docs/`
gains a map, an ADR index, the roadmap and the architecture diagrams.

Three points of discipline in it:

- **the diagrams are labelled explanatory, not normative**, with the solid /
  dashed convention stated on the page rather than only in the image. The
  diagrams show `ChittaRuntime`, the cognitive ledger, Self-Model and the
  Skill Gate — none of which exist in code today;
- **the ADR index names what is missing.** ADR-014, ADR-015 and ADR-017 are
  referenced by the roadmap and by ADR-018 but are not in this tree yet. An
  index that silently omits its own gaps is worse than no index;
- **the diagrams' divergences from this build are listed, not silently
  corrected**: the merged `Health / Readiness` block, the engine placed inside
  the deterministic action boundary, the complete absence of anchoring from
  both diagrams, `Vector DB · Qdrant` against a sqlite-vec Smriti and a
  stdlib-only core, and key-plane domain names that do not match the reserved
  values. The last is a serialized-value drift and must be resolved before
  genesis.

Acceptance 145/145, docs drift clean, retired group name refused with exit 2.

## Still owed by this drop

Canonical AGPL text byte-for-byte plus CLA; SBOM, pinned dependencies, signed
artefacts, two-person release approval; T-TOOLSET — the starter wasm toolset
with a reproducible build, an operator-signed manifest and a witness record on
tool addition.

*(The AGPL half of that line is closed below. The rest stands.)*

## v0.6.7 — audit response: four false greens

The external audit rejected both the v0.6.6 recut and the first v0.6.7 tree.
Its finding is one sentence: **readiness kept reporting states that were not
true, and anchoring did not serialize concurrent rounds.** Four defects, three
of them mine, and all four share a shape — a probe written from a guess about
an API, or a policy with a state missing from it.

| Finding | Root cause | Evidence |
|---|---|---|
| a corrupted witness chain read READY | `_chain_verdict()` probed `verify_head` (does not exist) then `verify` (exists, returns a **tuple**, takes a resolver) — so the tuple matched neither branch and every chain read clean | `WIT-VERIFY-1..2` |
| healthy DwarfStar/SGLang read NOT READY | Protocol v1 declares the contract whole, so every driver HAS `readiness()` and unimplemented ones raise `NotSupported`; the loop caught it as a failure and never reached the working `healthy()` | `ENG-READY-1..2` |
| two concurrent anchor rounds | the chain lock guards snapshot and append, not the scheduler's own state; both callers saw the same range, both submitted, both appended | `ANCH-LOCK-1` |
| local-only READY, working OTS NOT_READY forever | one policy with two states where four are needed | `ANCH-POLICY-1..2` |

### The witness probe is the same mistake as the anchor attributes

The first recut fixed `/readyz` reading `last_anchor_at` and
`unanchored_depth`, which did not exist — and in the same change introduced a
verifier probe under two names, one of which does not exist and one of which
has a different signature and return type. Both were written from memory of
what the API probably looked like. The lesson is not "check names"; it is that
a probe must be tested against **the real object**, which is why every check
in `test_recut2_false_greens.py` corrupts or configures something real instead
of feeding a hand-built dict to the rule engine. The first recut's readiness
tests proved the rules and nothing about whether the daemon could gather the
facts. It could not.

### Anchoring needed four states, not two

`recorded` counts. `failed` does not. That leaves no room for the ordinary,
correct, steady-state answer of an OpenTimestamps calendar —
`pending-attestation` — which means *the submission was accepted and a proof
is held, settlement is not yet final*. Under two states it fell in with
`failed`, so a node whose calendar was working perfectly stayed NOT_READY
forever and resubmitted the same range every backoff interval, spamming the
calendar with proofs it had already issued.

The states are now: **settled** (`recorded`, `confirmed`) · **custody**
(`pending-attestation`, `pending-confirmation`) · **pending** · **failed**.
Custody discharges the duty to submit — so it clears `behind` and stops the
resubmission — without discharging the settlement claim, so readiness reads
DEGRADED, never green.

The opposite error sat in the same function. With no external backend
configured the local one was promoted to "required", so a node with nothing
but a local file reported anchoring READY — while the code's own comment said
a local file is not external anchoring. `required_backends` no longer falls
back to local, and a local-only node reports external anchoring
**NOT_CONFIGURED**: not set up is a different statement from fine, and the
whole point of that fourth state is to be able to say so.

### The badge now means something

`gen_architecture_docs` counted `def test_*` declarations and published
"N/N green" — the same string whether anything had run, and the same string
on a host where a check errored out. The audit reproduced exactly that: a red
run under a green badge.

`run_acceptance` writes `docs/acceptance_result.json` at the end of **every**
run, green or red, digested over its own counts. The generator reads it and
refuses to claim green without it; if the collected count no longer matches
the recorded one it says the tree has moved; if the recorded run was red it
publishes the red numbers and the words NOT GREEN. Recording only green runs
was rejected — that would leave the last green artefact standing after a red
run, which is worse than no artefact.

This exposed a circular dependency worth naming: `R-ACCEPT` demanded the
literal phrase "N/N green" in the map, which an honest badge cannot produce
during a red run — so the check that goes red could never go green again. It
now compares the badge against the recorded run and asserts the wording and
the result agree, in both directions.

### Also in this drop

`__pycache__` shipped inside the v0.6.6-recut archive: 143 files, 1.7 MB.
Cleaned before packaging, then re-created by the verification run that ran
after the clean. Packaging now happens from a tree that is cleaned last.

README: the newcomer entry point the onboarding review asked for — the
architecture diagram with the solid/dashed convention stated beside it, a
quick-links table, a direct link to Roadmap r6.7 and to `docs/README.md`. The
stale citation of the map by its versioned filename now points at
`architecture_status.json`; the retired `legacy` group is gone from the
commands; the rate-limiting paragraph no longer describes a pre-v0.6.4 node.

Roadmap r6.7 no longer says v0.6.6 is both closed and not closed. It records
what is true: v0.6.6 was rejected, its fixes were absorbed here, and v0.6.7 is
itself incomplete.

Acceptance 145 → 146, green from a recorded run.

### Still owed

Canonical AGPL text plus CLA; SBOM, pinned dependencies, signed artefacts,
two-person release approval; T-TOOLSET. And from the audit, unchanged as
accepted debt: the evidence-ID catalogue (v0.6.9), the Guardian Action
Envelope, the cognitive-ledger recovery contradiction, ADR-017 absent from the
tree, and guardian outcome labels needing an explicit UNKNOWN.

**ClockWatch on macOS remains unproven.** `CLOCK_BOOTTIME` settles it on
Linux; on Darwin the code falls back to wall-versus-monotonic, which can still
mistake a forward correction for a sleep — and the Ф1 gate names the Mac node
explicitly. `CLOCK-2` is evidence about the boottime seam, not about every
target host. Named here rather than left to be discovered.


## v0.6.7 — audit response 2: the audit baseline

Two findings, one licence, and one check of mine that measured the wrong
thing. The two findings share a shape with everything this codebase has
gotten wrong in readiness so far: **an aggregate stood in for a per-item
fact, and the aggregate was greener than any of its parts.**

### P0-1 — a proof in custody made another backend's failure invisible

`anchor_status()` published `never_succeeded` as ONE boolean over all
required backends, while `in_custody` was per backend — and the NOT_READY
branch was gated on `not custody`. So an OpenTimestamps proof sitting in
perfectly ordinary custody suppressed the verdict about a DIFFERENT required
backend that had never anchored at all. The same node, the same five
thousand unanchored records, answered **503 without** the custody proof and
**200 with** it.

No better boolean fixes that, because a node-wide boolean cannot carry a
per-backend fact. So:

- `AnchorScheduler.anchor_status()` publishes `per_backend` — required,
  never, in_custody, behind, last success and its own unanchored depth —
  plus `configured_backends` and `shadow_backends`;
- `readiness.anchor_facts()` is now the ONE converter from scheduler state
  to rule input. It lives with the rules and imports nothing from the
  daemon. Before this, the shape was assembled twice — once in the daemon
  and once by hand in every test — and the two could disagree with nothing
  failing. `READY-ANCH-5` and `ANCH-POLICY-2` now go through the converter
  the daemon uses, which is what they always claimed to be doing;
- `evaluate_anchoring` evaluates **each required backend**, takes the worst
  state, and names every failing backend in the reason. Order of checks:
  policy breach → never anchored → custody → behind. Custody now covers
  neither another backend's failure nor its own breach;
- a required backend with **no measurement** is NOT_READY, not skipped.
  An absent fact has become a green light twice in this codebase already.

### Shadow backends, and why the fix needed a flag

`required_backends` already existed as an `AnchorScheduler` parameter, and
the daemon never passed it — so every configured backend was automatically
required, and running one before its phase was impossible without lying
about readiness. `--required-anchor-backends` closes that: a backend that is
configured but not required anchors, is reported under `shadow`, and cannot
make `/readyz` answer 503. Naming an unconfigured backend refuses at
startup, because the scheduler drops unknown names and the node would
otherwise report green on a policy nobody serves.

This is the mechanism a backend needs in order to be operated before the
phase that makes it mandatory. It changes no default: omit the flag and
every non-local backend is required, exactly as before.

### P0-2 — a green badge about which code?

The first recut fixed half of this: the badge stopped being a count of
`def test_*` and started coming from a recorded run. What it never recorded
is the TREE that run happened against. `total` moves only when the NUMBER of
checks moves, so any defect introduced without adding or removing a test
function left the recorded result matching and the badge green about code
that no longer existed.

Demonstrated rather than argued: on the v0.6.8 tree an entire reserve was
short-circuited to accept everything it exists to refuse, no test function
changed, and the generator printed **158/158 green** with a clean drift
check.

The run now records `tree_digest` — a content address over every `.py` file,
tests included, sorted by relative path (artefact schema `/v2`). The
generator refuses to print green for a different tree and names both
digests. `docs/` is excluded on purpose: it holds the generated surfaces
*and the result artefact itself*, so a digest covering it would invalidate
the run the badge describes and the two could never converge.

Known limit, stated rather than discovered later: the digest is over file
bytes, so a checkout that rewrites line endings produces a different tree
than the one the recorded run names. That is a true statement about the
checkout and the badge is right to say so, but on such a host the first
action is a fresh run.

### The licence

`LICENSES/AGPL-3.0.txt` now holds the canonical text from
`https://www.gnu.org/licenses/agpl-3.0.txt` — 34 523 bytes, 661 lines,
fetched twice and compared before use. `pyproject.toml` has declared
`AGPL-3.0-only` since v0.4, so this file is a legal instrument and the
requirement is byte-exactness.

`R-LICENSE` was rewritten with it. The old check asked whether a placeholder
was loudly marked — right while the text was missing, wrong the moment it
landed, because "contains the title and is over 30000 bytes" is satisfied by
the canonical text and equally by a truncated, reformatted or wrong-version
copy. It now pins sha256
`0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0`.

A CLA is still owed and the build cannot produce one: it names a legal
entity. `README` §8 says so instead of listing the licence as open.

### Acceptance

| Check | What it pins |
|---|---|
| `ANCH-REQ-1…ANCH-REQ-6` (`tests/unit/test_anchor_required_backends.py`) | the audited scenario against a real scheduler; every failing backend named; a shadow backend reported and never blocking; an absent measurement not green; custody covering submission but never a breach; the flag reaching the scheduler and refusing an unconfigured name |
| `ACC-TREE-1…ACC-TREE-4` (`tests/unit/test_acceptance_provenance.py`) | the recorded run names this tree; the digest follows content and path; a stale digest costs the badge its green and both digests are printed; generated surfaces and byte-caches stay outside the digest |

Three existing files were rewritten rather than patched, because they
encoded the defective rule: `test_readiness_rules.py`,
`test_ready_anch_recut.py` and the anchoring half of
`test_recut2_false_greens.py`.

### Two of my own errors, named here rather than found later

**The first cut of `ACC-TREE-3` asserted that the current badge is green
before breaking it.** That is a circular dependency and this project has
already shipped it once — `R-ACCEPT` demanded the literal phrase "N/N
green", which an honest badge cannot produce during a red run, so the check
that goes red could never go green again. Rewritten as two synthetic runs
differing only in the tree they name, so the check about the rule does not
depend on the state of the tree it runs in.

**`ANCH-REQ-1` passed under the mutation that disabled the branch it is
named after.** With the depth ceiling on, the policy breach produced
NOT_READY and the never-anchored branch never ran — a check named after a
claim while measuring something adjacent to it, written in the drop whose
subject is that exact defect. Both ceilings are switched off in that check
now, leaving one path to the verdict, and a mirror case asserts that the
same "never" state with nothing waiting is only DEGRADED.

Every new check was run against a deliberately broken tree: the
never-anchored branch disabled, the custody gate restored to its old global
form, a shadow backend forced back to required, a missing measurement
treated as green, custody moved ahead of the policy breach, the badge's tree
comparison disabled, and the digest removed from the recorded result. All
went red — the first only after `ANCH-REQ-1` was repaired.

Acceptance 156/156, docs drift clean.

### Still owed for a v0.6.7 tag

Supply chain — SBOM, pinned dependencies, signed artefacts, two-person
release approval — and T-TOOLSET. A CLA, which needs a named entity.


## v0.6.7 — audit response 3: what the evidence covers, and whose act it was

Three findings from the recut2 audit. Two of them are mine, both introduced
in recut2, and they are the same mistake twice: **an inclusion list where an
exclusion list was needed, and a shared path where an identity was needed.**
The third is older and worse.

### C — whose deliberation was it?

`verify_deliberation_against_chain(events, records, being_id)` accepted a
being and never used it. It compared one string — the semantic digest — and
nothing else.

The audit built a chain **signed by a different node**, attributed in its
provenance to a different being through a different organ, carrying a
completely unrelated request, and the auditor accepted it as a correct
binding for another being's events. Reproduced here before any code moved.

The digest binds run, step, node and resulting state: WHAT HAPPENED. It is
silent about WHO, and that silence was being read as attribution — which is
the one thing a witness plane exists to make impossible. Every act in this
system is an act by a named being; a record that cannot say whose act it was
is not evidence of an act at all.

Three bindings are checked now, and a fourth is honestly declined:

- the digest, as before;
- the **organ**, resolved from the digest prefix through a new
  `ORGAN_BINDINGS` table. A table rather than three loose constants, because
  the prefix, the organ name and the committed event field are ONE fact
  about one organ and must never be checked independently — a record cannot
  wear one spelling in its digest and another in its provenance;
- the **being**, by recomputing the provenance hash this record would carry
  if it were this being acting through that organ. Provenance is hashed into
  the record, so this needs nothing but the record;
- the committed request opens only when a `chain` is passed. That commitment
  is HIDING and its salt is held off-chain by the writer, so without the
  writer's chain there is no honest way to know which event was committed.
  The function no longer implies there is. When opening IS asked for and the
  salt is absent, it refuses rather than passing — an unopenable commitment
  is not evidence.

The table also happens to be the shape the track V rebase needs: adding the
`kriya_gate` spelling is one row, not a rewrite of the verifier.

### A — the digest covered one language, not the tree

`source_digest` hashed `.py` files only. The auditor granted anonymous
access to `/v1/tasks` in `deploy/authz.testnet.json`; the digest did not
move and the badge stayed green. Reproduced on both the recut2 and the
v0.6.8 trees.

The reasoning that produced that list was about EXCLUDING the generated
surfaces. It was written as an inclusion list, and an inclusion list
silently loses every file type nobody thought of. It now excludes by name
and covers everything else: 187 shipped files instead of Python alone —
authz policy, systemd and launchd units, shell scripts, the toolset
manifest, model profiles, Prometheus rules, pyproject, the licences, CI
workflows, the ADRs and the roadmap.

Four exclusions remain, and each is justified by convergence rather than by
taste: `README.md`, the generated architecture map, the generated status
page and the evidence directory all carry the badge itself, so hashing them
would let writing a result invalidate the run that result describes. They
are not thereby unverified — `check_docs_drift` proves each regenerates from
`docs/architecture_status.json`, which IS hashed.

### B — one artefact cannot be evidence of two runs

Every invocation wrote `docs/acceptance_result.json`, so
`run_acceptance.py live` overwrote a hundred and fifty-six hermetic checks
with a five-check wasm run. Evidence is now keyed by **suite**, one file per
suite under `docs/evidence/`, and the artefact (schema `/v3`) names its
suite, its host — system, release, machine, node — and an `engine` slot that
stays null unless the caller names one, because the runner cannot know it by
itself. An opt-in group's result is a claim about a machine, and it now says
which.

### Acceptance

| Check | What it pins |
|---|---|
| `ATTR-1…ATTR-5` (`tests/unit/test_deliberation_attribution.py`) | an honest run verifies at both levels; the audit's forgery is refused; wrong being and wrong organ each refuse ALONE, so the check cannot pass for one reason while claiming two; an unknown prefix is not an organ; a missing salt refuses rather than skipping, and a commitment opening to a different event is caught |
| `EVID-1…EVID-5` (`tests/unit/test_evidence_identity.py`) | named release-relevant non-Python files are inside the digest and editing the authz policy moves it; unforeseen file types are covered by default; only badge-bearing surfaces are excluded while the ADRs and roadmap are not; a live run cannot overwrite hermetic evidence; the artefact names suite, host and engine and still refuses a hand-edited body |

Each new check was run against a deliberately broken tree: the provenance
comparison removed, the organ dropped from the expected provenance, a
missing salt silently skipped, the digest returned to `.py` only, and all
suites pointed back at one path. All went red.

`ACC-TREE-4` was rewritten rather than kept: it used to prove that writing
under `docs/` left the digest alone, which is now false and ought to be —
the ADRs and the roadmap are normative. It proves the convergence exclusion
against the evidence directory, and separately that a new file under
`docs/adr/` DOES move the digest.

Acceptance 166/166, docs drift clean.

### Scope, and what is deliberately not here

This recut is release integrity and attribution. The audit's larger P0 — the
three testing paths that never meet, where `/v1/tasks` runs the full
BeingRuntime on `core.router._mk_node` reference engines while the real
configured engine serves only `/v1/messages`, readiness and attestation — is
NOT addressed here. It needs the vertical: a real backend inside
BeingRuntime, a separate Being keystore with a canonical `being:<hash>`,
DecisionTrace bound to a signed manifest, and one end-to-end test through
mTLS and a restart. That is a drop of its own and mixing it in would put two
rollbacks behind one tag.

Still owed for a v0.6.7 tag: supply chain, T-TOOLSET, a CLA — and the
vertical above, which is what stands between this tree and manual alpha
testing of an actual agent.

## v0.6.7 — the vertical: one path, one engine, one identity

Three ways of making this node think existed, and none went through the
whole organism. `/v1/messages` used the real engine without a DecisionTrace.
`live_engine_acceptance.py` had both but went around the daemon, mTLS and
attestation. And `/v1/tasks` ran the full BeingRuntime on **three synthetic
engines** built by `core.router._mk_node` — a helper declared inside the
router's own acceptance-test section, one of the three carrying
`noise=0.05`.

The middle row was not untidiness. Weight attestation and `/capabilities`
described the real configured backend while the signed `DecisionTrace` that
entered the witness chain came from a test fixture: **the node witnessed the
work of an engine that was never attested and is not a model.**

### The fixtures are gone, and nothing clever replaces them

`_BeingEngineSeat` presents the node's real `EngineBackend` as one router
seat. Two properties are refusals rather than features:

- the descriptor carries the backend's **own** fingerprint and determinism
  level, and a driver that states neither cannot describe itself — the seat
  refuses to be routed to rather than inventing a label;
- `score` has **no fallback**. A backend without forced-continuation
  scoring has no verifier role, read from `capabilities().implemented`,
  which is derived from what the driver overrides rather than from a
  hand-written list. The consequence is that verification is unavailable —
  not that a substitute verdict appears.

One engine is one place, and one place is not a panel. That is not worked
around: a lone node in `production` **refuses**, and manufacturing a panel
from one engine with different seeds is forbidden by name in ADR-019 D1,
because imitated independence would enter a signed trace indistinguishable
from the real thing.

### The defect the vertical uncovered: the honest refusal could not record

`move(trace, REFUSED, detail={"reason": str(e)})` put an exception message
into `semantic_digest.detail.reason`. The witness-plane vocabulary has
refused free text since v0.6.5 — replicated prose is both a covert channel
and an unbounded write into a store nobody can delete from — so the refusal
raised `PlaneSchemaError` instead of recording a REFUSED trace. **The system
could not write down why it had refused**, which is the one thing a refusal
is for.

Nobody had seen it because until now nothing on a single node ever refused:
three fixtures always produced a panel.

Fixed in the shape already used for challenge rounds and the rate limiter: a
versioned `OUTCOME_CODES` enumeration, classified **once** at the boundary
by `classify_refusal`, with `outcome_detail()` putting code, version and a
`detail_hash` into the plane while the full human text stays on the trace
returned to the caller and in the local journal.

### The being has its own identity

`being:` plus the first sixteen characters of the node id was wrong three
ways at once: not the canonical `being:<sha256(pubkey)>`, so nothing could
bind it to a key; it made the being an artefact of its host, inverting
Operator → Node → Being; and the being then signed with the NODE's key, so
"witnessed under the being's identity" was a sentence with no cryptography
behind it.

`--being-keystore` (with its own passphrase variable) gives the being a key
of its own, and requires `--node-keystore`, because a hosting binding signed
by an ephemeral node key is worthless after the next restart. A node without
one still gets a **canonical** id from a fresh key — ephemeral, and readiness
says so. A stable-looking id that no key backs would be the dishonest
option; an honest ephemeral one can at least be told apart.

`make_hosting_binding` is the two-signature statement that this node hosts
this being. Both signatures are load-bearing for different reasons: the
being signs because hosting is pull-by-choice (Invariant IV — a node cannot
acquire the right to speak for a mind by announcing that it has), and the
node signs because it accepts responsibility for what it witnesses under
that name. Both ids are checked against the keys that signed them, so a
genuine pair of signatures cannot be copied under another id. The binding is
re-derived at boot rather than trusted from disk — one read from a file is a
claim, one signed at boot is a fact — keeping the original `since_ts`.

Readiness now reports the being separately from the node: an ephemeral being
is DEGRADED (no continuity across restart), an unbound being is DEGRADED for
a different reason (nothing proves this node may witness for it, so its
records top out below IDENTITY_BOUND).

### Acceptance

| Check | What it pins |
|---|---|
| `VERT-1…VERT-6` (`tests/integration/test_vertical.py`) | the seat is the configured backend and no call to the fixture helper remains; the verifier role is read from the driver; a lone production node refuses in a reason code with no free text and a chain that still verifies; the labelled path completes on the real engine and admits `mode: "self"`; the being carries a canonical id from its own key and survives restart with a keystore; entitlement comes from the binding and readiness degrades honestly without one |
| `G-1…G-6` (`tests/integration/test_being_runtime.py`) | rewritten from the requirement: G-1…G-4 exercise the organism over mTLS on the REAL backend through a restart and a containment stop, and the new G-6 spawns a lone `production` node with a well-formed provenance manifest and pins its refusal |

Four deliberate mutations went red: free text back in the refusal detail, the
verifier role assumed, the being id back to a slice of the node id, and an
unbound being reported ready.

`test_being_runtime.py` was rewritten rather than patched, because it
asserted that a single node reaches RECORDED under `production` — true only
while the panel was three copies of a fixture. It now pins both truths the
old version could not tell apart: the organism works end to end on the real
engine, and a lone node refuses instead of pretending.

Acceptance 173/173, docs drift clean.

### Owed next, named rather than left to be found

The recut3 residual is NOT in this drop: `README.md` is still outside the
tree digest (its manual sections can be edited without moving it — the
justification that it regenerates wholly from `architecture_status.json` was
wrong, and the ownership test proves the generator does not touch that
prose), and the digest still ignores file modes and symlink targets, so
removing an executable bit changes shipped behaviour without changing a
hash. Both are release integrity and belong together in their own pass.

Also owed for a v0.6.7 tag: supply chain, T-TOOLSET, a CLA. And the
provenance map is keyed by ROUTE OBJECT id (`m:self`), not by seat id, with
`model_id` required in each entry — a manifest missing it surfaces as
FAILED/`internal_error` rather than a clean refusal, which belongs in the
runbook before an operator meets it.

---

## v0.6.7-recut5 — the identity vertical (23 August 2026)

recut4 closed the ENGINE vertical: the Being thinks with the backend this
node actually serves, `core.router._mk_node` is gone from the daemon, and a
lone `production` node refuses honestly instead of manufacturing a panel out
of one engine. The fourth audit accepted that and rejected the drop for a
different reason: the IDENTITY and PROVENANCE vertical was open, and four of
its holes were load-bearing. All four are closed here, together with the
deployment artefacts that would have re-opened the first one on every real
host.

### P0.1 — a restart silently changed the Being

`--being-keystore` existed in `node/daemon.py` and appeared in no test and in
no deployment artefact. So the end-to-end restart check spawned its node
WITHOUT it, minted a fresh key and a fresh `being:<hash>`, then loaded the
previous Being's traces out of the journal it inherited and served them as
its own. Nothing was corrupt; every signature verified. Two lives had been
merged, which is precisely what continuity is supposed to prevent and the
one thing nothing compared.

The node has had the matching rule since v0.4.1 — an ephemeral identity is
refused over a non-empty witness log — and the Being simply never got it.
Now:

* `runtime.recovery.recover_traces(..., expect_being_id=...)` refuses to
  rebuild a journal written by another being, raising the new
  `BeingContinuityError`. It is kept separate from `IdentityError` because
  the two answer different questions: `IdentityError` says a key does not
  match an id, this says a key and an id are both fine and belong to
  somebody else's history;
* `journal_being_ids()` reads the `open` entries, which have carried
  `being_id` since the journal existed — so the check works on journals
  written before it;
* `main()` refuses to start a being profile without `--being-keystore` when
  the journal already holds a history;
* the refusal is fail-closed in EVERY profile, not only `production`.
  Moving a Being to another identity is a MIGRATION — a witnessed act with
  the being key's consent — and never a side effect of a restart.

### P0.2 — the hosting binding was not a runtime gate

Readiness computed `being_bound = bool(hosting_binding)` and nothing else.
`verify_hosting_binding()` ran only in `main()`, and only when reusing a
binding already on disk. `kernel/viveka.py` treated a binding as optional:
absent, the proof simply capped at `COMMITMENT_OPENED`. The audit confirmed
by execution that `{"garbage": true}` read READY and that a `being_id` naming
one being with the key of another passed unexamined.

Two of these were one defect: **identity was carried, not derived.**
`self.being_id = being_id or self.being_identity.being_id` let a caller name
one being while holding another's key, and nothing compared the two. An id
that is not the hash of the key that signs for it is a label, not an
identity. Now `being_id` is always derived and a supplied one is an
EXPECTATION that refuses on mismatch — which closes the same door P0.1 came
through.

`Node.__init__` additionally verifies any supplied binding and checks it
against BOTH ids, mints one when it holds both keys (the rule `main()`
already followed: a binding read from disk is a claim, one signed at boot is
a fact), and in `production` refuses to start without a persistent being, a
persistent node identity and a valid binding. Readiness reports
`entitled_to_witness(...)` rather than a non-empty dict.

Found while wiring it: **`entitled_to_witness` was not imported in
`node/daemon.py` at all.** The helper the audit described as "tested but not
applied by the daemon" was not merely unapplied — it was not in scope.

### P0.3 — the Being key signed nothing the Being said

`BeingRuntime(sk=self.sk, ...)` handed the runtime the NODE key, so the being
keystore was used for the manifest and the hosting binding — statements
ABOUT the being, made at boot — and for nothing the being itself authored.
Even a Plane H knowledge proposal was node-signed.

The split now follows INV-9 exactly:

| Key | Signs |
|---|---|
| BEING | what the being AUTHORS: its decision commitment, its knowledge proposals |
| NODE | the WitnessChain, network receipts, and the witnessing of what the being did |

* `core/plane_h.py` gains `AUTHOR_DOMAIN` and an optional `being_sk`. The
  body names `author_being`; the envelope carries that being's signature
  over the same payload. `verify_write_proposal` is fail-closed both ways: a
  body that NAMES an author without the signature is refused (it reads as
  authored), and a signature without a named author is refused too;
* `runtime/decision_trace.py` gains `being_attestation`, `being_commitment()`,
  `attest_decision()` and `verify_decision_attestation()`. The being signs a
  commitment over the task, plan, answer and generator — deliberately NOT
  `trace_hash()`, since the attestation lives inside the trace and signing
  the whole trace would mean signing a value that changes the moment the
  signature is attached;
* `production` refuses to construct a runtime without the being key: a
  decision nobody signed is attributed to a being by the node's word about
  itself.

The being's signature sits INSIDE what the node then witnesses. The witness
plane is still never signed by the being.

### P0.4 — the DecisionTrace was not bound to an artifact

The trace carried `object_id` and a `provenance_model` string read out of an
external JSON file: a declaration checkable against nothing. And
`_BeingEngineSeat.describe()` hardcoded `quantization="int4"` for every
backend regardless of the model — which was not only untrue but made ONE
backend describe itself two different ways, because `/capabilities`
published no quantization at all and a remote descriptor built by
`core.router.RemoteNode.describe()` therefore read `"n/a"`.

* `_BeingEngineSeat.artifact_refs()` reports `model_artifact_manifest_hash`,
  `deployment_manifest_hash`, `engine_fingerprint`, the real quantization and
  whether anything is attested — all from the signed manifest and the
  measured deployment, or `unknown`;
* `unknown` is a VALUE, not an absence. The reference backend honestly has
  nothing to attest and says so; inventing a precision was the defect;
* `/capabilities` publishes `quantization`, so both paths describe the same
  engine the same way;
* `BeingRuntime._artifact_refs()` asks the SEAT that generated, never the
  route table — a binding read from configuration would be the same
  declaration this replaces;
* `production` refuses with the new `no_model_artifact_binding` when the
  decision cannot be bound to the weights that produced it.

### Deployment — where P0.1 would have come back

`--being-keystore` was in no unit, no plist, no bootstrap script and neither
runbook. Fixed in code, every deployed node would still have been ephemeral,
with a green suite. The systemd unit and the macOS launcher now pass the
being keystore and refuse to start without `JJDAI_BEING_PASSPHRASE`;
`keychain_seal.py` gains `--kind node|being` so the two secrets are separate
keychain items with separate lifetimes — a being outlives the host it runs
on. Both runbooks document the second secret, and RUNBOOK.md §2b finally
records that the provenance map is keyed by ROUTE OBJECT id (`m:self`) with
`model_id` required, closing a debt named in recut4.

### Acceptance

| Check | What it pins |
|---|---|
| `VERT-7` | the daemon ENFORCES the binding: a non-verifying binding, a valid binding between two OTHER parties, a `being_id` the keystore does not derive, and an ephemeral being in `production` are all refusals; readiness reports a verified entitlement |
| `VERT-8` | a being's history is its own — the same key gets it back, a different key over the same journal is refused |
| `VERT-9` | the being signs what it authored, the attestation cannot be re-attributed or opened against a changed answer, a proposal naming an author without that author's signature is refused, and the chain stays node-signed |
| `VERT-10` | the trace names the artifact behind it; a backend with nothing to attest reports `unknown`; `/capabilities` and the local seat agree; no precision is hardcoded in the daemon |
| `G-3` | rewritten into an actual continuity check: the node restarts over mTLS on the same NODE and BEING keystores and the `being_id` is compared before and after |
| `LV-1…LV-6` (`tests/live/test_vertical_live.py`, opt-in `live`) | the same vertical against a REAL backend on a target host: the seat is the live engine, the artifact is genuinely named, one backend has one description, the decision is being-signed, continuity holds on a real model, and one seat is still not a panel |

Eight deliberate mutations went red, each in the check named for it:
`being_id` carried again; `bool(hosting_binding)` restored; the binding
verification removed; `expect_being_id` dropped; the decision attestation
skipped; `"int4"` hardcoded again; the author-signature branch disabled; the
answer removed from the commitment.

`VERT-6` is kept as the helper check and is no longer mistaken for
enforcement — that separation is the point. The first cut of `VERT-10`
asserted the artifact refusal through a lone `production` node, where the
PANEL gate fires first; it would have carried on the wrong branch. This is
the recurring defect of this project — a check named for one thing measuring
its neighbour — caught once more inside the drop that produced it, and
rewritten to classify the code directly and to assert the panel refusal as a
panel refusal.

The lifecycle unit fixtures supply a STUB artifact binding through a
`_BoundSeat` wrapper and say so: their subject is the lifecycle, and the
artifact gate is proven where it belongs, in `VERT-10` and `LV-2`.

Acceptance 177/177, docs drift clean.

### Owed next, unchanged and still named

The recut3 residual is NOT in this drop: `README.md` is still outside the
tree digest, and the digest still ignores file modes and symlink targets.
Both are release integrity and belong together in their own pass. Also owed
for a v0.6.7 tag: supply chain (SBOM, pinned deps, signed artefacts,
two-person release approval), T-TOOLSET, and a CLA — which requires a named
legal entity and cannot be produced by a build.

`tests/live/test_vertical_live.py` has NOT been run: this build host has no
DwarfStar or SGLang. It raises rather than skipping, and it is evidence about
a target host only once a target host runs it.

---

## v0.6.7-recut6 — the artifact chain, and a commitment that opens (23 August 2026)

The fifth audit closed P0.1–P0.3 of the fourth and rejected recut5 on two
counts: the ModelArtifactManifest binding was still a false green, and the
RECORDED transition committed to a trace nobody receives. Both are closed
here. Neither was subtle once named, and both had been green for a drop.

### P0.1 — the artifact binding was a false green four ways over

Each of the four is a different way to fake provenance, so all four are
written down:

1. **the seat asked the DRIVER.** `attestation_manifest()` is implemented by
   exactly one backend — the reference `hash` engine. DwarfStar, SGLang,
   vLLM, llama.cpp and MLX all return `NotSupported`, so the field was empty
   precisely on the hosts where provenance matters;
2. **only the SCHEMA was checked.** `artifact_refs()` called
   `validate_manifest_body()` and never `verify_manifest()`. A well-formed
   manifest anybody could write passed;
3. **the gate tested for a non-empty string.** A test fixture handing over
   `"0" * 64` with `attested: False` satisfied `production` — which is how
   the audit found the gate, by reading what a fixture got away with;
4. **it ran after generation.** A node whose provenance was unprovable
   served, thought and only then refused, per task, forever.

New `core/artifact_binding.py` builds the binding ONCE, at boot, as a chain:

```
signed ModelArtifactManifest   (verify_manifest: schema + hash + SIGNATURE)
    → checkpoint_hash  ==  a verified WeightAttestation.artifact_hash
    → engine_fingerprint  ==  the DeploymentManifest's fingerprint
    → backend  ==  the driver actually loaded
    → quantization read FROM the verified body, never asserted
```

Every link is checked and any break refuses. The result is a FROZEN
`ArtifactRefs`; a seat reports it and cannot compose it. `verified` is set
by that module and nowhere else, so a fixture that wants to look bound must
produce a genuinely signed chain.

New flag `--model-artifact-manifest`, required by `--being-profile
production`. A BROKEN chain refuses the boot in any profile — the operator
said these are the weights and they are not. An INCOMPLETE one (a signed
manifest with nothing measured) is honestly unbound, and `production` then
refuses with the reason attached. A signed description of weights is not
evidence that those weights are here.

`tests/artifact_fixtures.py` replaces the stub with the real article: a real
profile, a real file whose bytes are measured, a real `WeightAttestation`, a
real `DeploymentManifest` signed by the node it describes, and a manifest
signed with a real key — verified by the same `bind_artifact` the daemon
uses. Every production harness in the suite now supplies the manifest AND
the weights, and the node measures them for itself.

### P0.2 — the witnessed hash was of a trace nobody receives

`RECORDED.detail.trace_hash` was computed BEFORE the RECORDED transition was
appended. The transition then changed the trace, so `detail.trace_hash !=
trace.trace_hash()` — reproducibly, every task, since the state machine
existed. The chain testified to an object that never left the process.

A hash of an object must never sit inside that object. `trace_hash()` is
**removed** rather than left as a trap for the next caller, and
`content_digest()` / `recompute_commitment()` take a projection that
excludes everything self-referential or appended afterwards: transitions,
witness span, timestamps, the being's attestation (which carries this
digest), and the state itself, which advances as the record is written.

Transitions are deliberately NOT folded in. Every transition is already its
own witnessed TASK record, so the chain covers the sequence by construction;
re-hashing it here would prove nothing further while forcing the commitment
to change at the instant it is written — the very defect being fixed. What
the chain cannot cover by itself is the CONTENT, and that is what this
binds. VERT-11 checks the sequence the other way instead: every transition
must name a record whose state matches.

One commitment now serves both signatures: the being signs the content it
authored, the node witnesses the same value. `being_commitment()` is
`content_digest()`.

### Also closed

`BeingRuntime` now checks `canonical_being_id(being_sk.public) == being_id`
itself. The Node derives the id from the key, but a caller constructing a
runtime directly could still pair one being's id with another's key, and
everything that "being" signed would be attributed to a name it cannot hold.

`tests/live/test_vertical_live.py` was **broken and could not run**: it set
`BackendConfig.endpoint`, a field that does not exist on a `__slots__`
object whose URL field is `url`. It raised AttributeError before the first
check. Rewritten: the node under test is now a REAL DAEMON spawned over
mTLS with both keystores, the manifest and the weights, restarted in place —
constructing a `Node` in-process skipped exactly what a live test exists to
cover. It requires `JJDAI_LIVE_BACKEND`, `JJDAI_LIVE_URL`,
`JJDAI_LIVE_MANIFEST` and `JJDAI_LIVE_WEIGHTS`, and refuses loudly without
them.

### Acceptance

| Check | What it pins |
|---|---|
| `VERT-10` (rewritten) | the binding is a verified CHAIN: a bad signature does not bind, a manifest naming a checkpoint this node never measured does not bind, a signed manifest with nothing measured does not bind, a fingerprint disagreement does not bind, and an unverified binding refuses the BOOT rather than each task |
| `VERT-11` | the witnessed commitment opens to the trace the caller received AND to the one recovered from the journal; it covers answer, action, outcome, citations, plan and generator; every transition names a record whose state matches; `trace_hash()` has not returned |
| `VERT-9` (extended) | a runtime built directly cannot hold one being's id with another's key |
| `LV-1…LV-7` (opt-in `live`) | the same, through a real daemon over mTLS against a real model |

Four mutations were run and **two of them passed on the first attempt**,
which is the finding worth keeping from this drop:

* removing the signature check left VERT-10 green. The forged-manifest
  branch had `raise AssertionError(...)` inside a `try` whose `except
  Exception` asserted that the word "signature" appeared in the message —
  and the AssertionError's own text contained it. The check passed by
  catching itself. The assertion now sits outside the `try`;
* removing the being-id check left everything green, because nothing
  constructed a runtime directly with a mismatched pair. VERT-9 now does.

This is the project's recurring defect for the fifth drop running — a check
named for one thing measuring its neighbour — and it is the reason mutations
are run at all. A third near-miss was caught while writing VERT-11: the
`citations` mutation set `[]` over a value that was already `[]`, a no-op on
a first task, exactly the EVID-5 shape from recut3. Every mutated value is
now asserted to differ from what the trace holds before it is used.

Acceptance 178/178, docs drift clean.

### Owed next, unchanged

The recut3 residual (`README.md` outside the tree digest; file modes and
symlink targets), supply chain, T-TOOLSET, CLA. `tests/live/test_vertical_live.py`
still has not been RUN — this build host has no DwarfStar or SGLang, and it
is evidence about a target host only once a target host runs it.

---

## v0.6.7-recut7 — the last link of the artifact chain (23 August 2026)

The sixth audit accepted recut6's two P0s — the stable `content_commitment`
and the verified manifest — and blocked release on one remaining gap, which
was the worse kind: four of five links were checked and the fifth was not,
while `VERT-10` asserted the whole chain. A check that claims more than the
code does is not a weaker check, it is a false one.

### What was missing

`bind_artifact()` read `engine_fingerprint` out of the DeploymentManifest
and hashed its body — and never called `verify_deployment_manifest()`.
Reproduced exactly as the audit did: a deployment with a zeroed signature
bound clean, and so did one signing for entirely different weights. The
daemon was partly shielded because it BUILDS its own deployment and passes
it through `AttestationStore.hold_deployment()` first, but the public binder
and any directly-constructed runtime were not, and the difference between
"the caller happens to be safe" and "the function is safe" is the whole
point of having the function.

The second half was a docstring lying about its own code:
`require_attestation=False` returned `verified=True, attested=False` while
the comment said production would refuse it — production reads only
`verified`, so it did not.

### The chain now, in full

```
signed ModelArtifactManifest      verify_manifest: schema + hash + signature
signed DeploymentManifest         verify_deployment_manifest: signature,
                                  every embedded attestation, and their
                                  hash binding into the signed body
checkpoint present                the checkpoint the manifest names must
                                  appear among the substrates that
                                  deployment SIGNED for
attestations from the bundle      taken from the verified deployment, never
                                  from beside it; an externally supplied set
                                  must be byte-identical or it is a second,
                                  unsigned opinion
engine agreement                  deployment fingerprint == loaded driver,
                                  manifest backend == loaded driver
quantization                      read from the verified body
```

`require_attestation` is **removed** rather than defaulted safely: a flag
that relaxes a chain is a flag somebody will pass. A deployment is required;
there is no partial mode. `verified` means the whole chain held.

`ArtifactRefs` gains `manifest_verified` beside `verified`, because "the
description is genuine but nothing measured it" is a real state and a
different one from "nothing verified at all" — recut6 conflated them and
returned the strong flag for the weak case. Only `verified` admits
production, and it is now set in exactly one place.

### Acceptance

`VERT-10` gains the four negatives the audit named, each written so the
assertion sits OUTSIDE the `try` — the trap that let a check catch itself in
recut6:

| Negative | Expected |
|---|---|
| forged DeploymentManifest signature | reject |
| valid deployment that does not carry this checkpoint | reject |
| attestation supplied outside the signed deployment | reject |
| no deployment at all | reject |

Three mutations, three reds: dropping the deployment verification, dropping
the checkpoint-membership check, dropping the byte-binding of an external
attestation set. Each went red in the branch named for it.

Acceptance 178/178, docs drift clean. The count is unchanged because the
new negatives strengthen an existing check rather than adding one — the
guarantee moved, not the arithmetic.

### Owed next, unchanged

The recut3 residual (`README.md` outside the tree digest; file modes and
symlink targets), supply chain, T-TOOLSET, CLA.
`tests/live/test_vertical_live.py` still has not been RUN on a host with a
real model.

---

## v0.6.7-recut8 — a link the refactor dropped (23 August 2026)

The sixth audit confirmed recut7 closed the DeploymentManifest gap and then
found something worse in kind: **recut6 had checked that the
WeightAttestation was taken under the running engine, and the recut7 rewrite
silently lost it.** Not a gap never closed — a guarantee that existed, was
removed while the surrounding code was being strengthened, and left
`VERT-10` still claiming it.

Reproduced exactly as reported:

```
running engine       fp-running
DeploymentManifest   fp-running
WeightAttestation    fp-different
bind_artifact()      verified=True
```

and the same break in its other form, a deployment from one node embedding
an attestation signed by another. Every signature valid; the bundle
meaningless. Each part verifying is not the same as the parts describing the
same thing.

### Closed at three levels, as the audit asked

1. **`make_deployment_manifest()` will not BUILD one.** An attestation whose
   `attester_node` is not this node, or whose `engine_fingerprint` is not
   the one the deployment declares, is refused before signing. A deployment
   manifest is a first-person statement; a node cannot vouch for somebody
   else's measurement.
2. **`verify_deployment_manifest()` will not VERIFY one offline.** A
   verifier that reports `ok` on a self-contradictory bundle is telling a
   reader something untrue, whatever the signatures say.
3. **`bind_artifact()` checks against the engine actually LOADED**, which
   neither of the other two can see.

### The non-blocking finding, also fixed

`manifest_verified` was introduced in recut7 and then thrown away at the
daemon boundary: `unbound()` was called without it, so the flag was true
only when `verified` already was, and the distinction it existed to draw
never appeared. `ArtifactBindingError` now carries `manifest_verified`, every
post-manifest failure sets it, and the daemon records it.

### Acceptance

`VERT-10` gains all three levels. The bundles are forged BY HAND in the
test, because since this drop `make_deployment_manifest` refuses to produce
one — so the only way such a bundle reaches a verifier is from an adversary
or an older builder, which is exactly who it must be checked against.

Level 3 needed care. It is UNREACHABLE while levels 1 and 2 hold: the
deployment's own fingerprint is compared with the driver first, so a normal
path assertion would have been carried by the level-2 failure — this
project's recurring defect, a check named for one thing measuring its
neighbour. The verifier is therefore stubbed out for the length of that
block, the same technique that exposed ATTR-5, leaving the third layer as
the only thing that can catch the contradiction. It also needed a manifest
for the forged checkpoint, or the checkpoint-membership gate would have
carried the assertion instead.

Five mutations, five reds: the builder guard, the verifier consistency
check, and both branches of the binder's own comparison, each in the level
named for it — plus a compound mutation removing levels 1 and 2 together,
which the level-2 assertion catches first, as it should.

One existing fixture had to change and the reason is worth recording: A-3 in
`tests/unit/test_v051_primitives.py` built a deployment from an attestation
created with no `engine_fingerprint` at all. Under the new rule that is a
contradiction, and correctly so — an attestation with `engine_fingerprint:
None` is not "unspecified", it is a measurement nobody can say which engine
produced. The fixture now names the engine it means.

Acceptance 178/178, docs drift clean.

### Owed next, unchanged

The recut3 residual (`README.md` outside the tree digest; file modes and
symlink targets), supply chain, T-TOOLSET, CLA, and the live vertical still
un-run on a host with a real model.

---

## v0.6.7-recut9 — an unnamed identity is not a match (23 August 2026)

The seventh audit confirmed recut8 closed both of its findings and then
found a third instance of the same invariant failing open, in the most
uncomfortable way available: **recut8's own CHANGELOG states the rule that
recut8's code does not follow.** It says, correctly, that
`engine_fingerprint: None` is not "unspecified" but a measurement nobody can
attribute — while every comparison in the binder was guarded by truthiness:

```python
if dep_fp and fp and dep_fp != fp:
```

With both sides empty no mismatch arises, so the whole chain returned
`verified=True`. Reproduced:

```
blank_fingerprint_accepted=True    engine.fingerprint=''
missing_backend_accepted=True      engine.backend=''
```

Absence was being read as agreement. That is the same shape as
`bool(hosting_binding)` in recut5 and the same shape as the truthiness guard
in the anchoring policy before recut2 — a value-or-nothing test standing in
for a comparison.

### The rule, applied where identity is established rather than compared

An identity is a **non-empty string**. `None`, `""` and `"  "` are not three
shades of unspecified; they are one absence, and an absence is refused
before any comparison happens, not compared leniently:

* `bind_artifact()` requires a named `backend` and `fingerprint` on the
  LOADED engine, then compares with strict equality and no truthiness. The
  deployment's fingerprint and each attestation's fingerprint must likewise
  be named before they are matched;
* `make_weight_attestation()` refuses to SIGN an attestation that names no
  engine. An unattributable measurement should not exist as an artefact, let
  alone be compared later;
* `make_deployment_manifest()` and `verify_deployment_manifest()` refuse a
  manifest naming no engine or no node;
* `declared_attributes()` normalises blank and whitespace-only attributes to
  `None` — `" "` used to survive and read downstream as "the driver declared
  something";
* `phase_readiness()` calls a backend identified only when `backend` and
  `fingerprint` are both non-empty strings, rather than merely `is not
  None`.

### Acceptance

`VERT-10` gains the three negatives the audit named — blank runtime
fingerprint, whitespace fingerprint, missing runtime backend — plus the
signing-side refusal for `""`, `"   "` and `None`. New `A-12` in
`tests/unit/test_adapter_layer.py` pins the attribute rule where it lives:
a driver with a blank `backend` or `fingerprint` is not identified, and a
properly named one still is.

Five mutations, five reds: restoring the truthiness guard on the
fingerprint, restoring it on the backend, removing the signing-side refusal,
restoring `value not in (None,)` in `declared_attributes`, and weakening
`identified` back to a presence test.

Two existing fixtures changed for the same reason as recut8's A-3: they
built attestations naming no engine. The binding class of a manifest id
(content vs declared) is about the ID, not about the engine — that case
still exists, it simply has to say who measured, like every other.

Acceptance 179/179, docs drift clean.

### Owed next, unchanged

The recut3 residual (`README.md` outside the tree digest; file modes and
symlink targets), supply chain, T-TOOLSET, CLA, and the live vertical still
un-run on a host with a real model.

---

# JJ DAI v0.6.8 — two pre-genesis reserves, and a reserve that is actually a refusal

Scope: the cross-cutting track V vocabulary (ADR-018 rev 2) rebased from
v0.6.7-recut2 onto the accepted **v0.6.7-recut9**, the ADR-019 rev 3.1
reserve that the ADR itself assigns to this drop, the audit's P0-1 against
the first v0.6.8 cut, and the five missing ADRs placed in the tree.

**The number stands, and the reason is now on the record.** The auditor's
r6.8 re-prioritisation — v0.6.8 becomes "Agent Alpha", the track V reserve
moves to v0.6.9 — was ruled on and **not adopted for this drop**. Two of
Agent Alpha's three parts already shipped inside the v0.6.7 line (a real
engine inside `BeingRuntime`, a separate Being keystore, continuity across
an mTLS restart), and the third — guardian GOOD/BAD/UNKNOWN marking — is
G-GUI, a Ф0 deliverable with its own guardian keystore and not a code drop
at all. "Agent Alpha" becomes the named goal of roadmap r6.8, carried by
**v0.6.9** as G-GUI plus the live run on a target host.

## The rebase was a MERGE, not a copy

The note carried forward from the first rebase — "no file is touched by both
drops" — was true only against recut2. That is the tree the track V archive
was still built on, and recut3 through recut9 changed **three of the four**
files track V touches. Copying them across would have silently reverted the
whole identity and artifact-binding vertical that seven recuts built.

* `jjdai/cognitive.py`, `tests/unit/test_track_v_reserve.py`,
  `tests/unit/test_kriya_gate_naming.py` and `docs/adr/ADR-018-Chitta-Loop.md`
  carried over as they were;
* `jjdai/witness.py` — both vocabularies folded into **one** canonical enum
  rather than re-declared, with `RESERVED_TRACK_IV_KINDS` named separately so
  the three declaration sites stay legible;
* `core/plane_h.py` — the namespace refusal at grant, apply and ordinary
  retrieve, added around recut5's `AUTHOR_DOMAIN` and `being_sk` author
  signature, which are untouched;
* `kernel/viveka.py` — **a row, not a rewrite.** `ORGAN_BINDINGS` became a
  table in recut3 for exactly this case: v0.6.8 adds `kriya_gate` and
  **keeps** `viveka`, because records written before this drop are
  hash-chained and must go on verifying forever. The v0.6.8 copy of this
  file was not usable — it predates `ORGAN_BINDINGS`, `DeliberationProof`
  and the `entitled_to_witness` check.

`KRIYA-1` and `KRIYA-2` were rewritten for the same reason: they asserted a
COUNT, and recut5 replaced the count with `DeliberationProof(level,
records)`. They now assert the proof LEVEL as well — a legacy record that
still verifies but proves less than it used to would be a silent
downgrade, and a test comparing an integer could not see it.

## P0-1 — the reserve was bypassable

The audit's finding against the first cut, reproduced here before it was
fixed: an ordinary `INFER` record accepted six reserved tokens **in its
body** — a KriyaGate outcome, a prediction resolution status, a CONTESTED
reason code, the sealed lifecycle state, the prediction commitment domain
separator and the hypothesis retrieval mode — and the chain stayed validly
signed. Only function ARGUMENTS were refused. The v0.6.8 CHANGELOG had said
"every entry point refuses, fail closed", and that sentence was wider than
the code.

New `jjdai/reserved.py` is one door over both vocabularies and refuses a
reserved token as a VALUE: whole strings, **segments of a colon-compound
digest**, mapping keys, and any path below a reserved namespace. It runs on
the node-authored fields that reach the chain as content —
`semantic_digest`, `provenance`, `entanglement`.

**Where the line is drawn, and why not further.** `request` and `response`
are NOT scanned. They enter the chain as hiding commitments over
caller-supplied data; a task whose text contains one of these English words
is not a node making a claim in a reserved vocabulary, and no serialized
reserved value reaches a peer through a commitment. `RSV-5` asserts the
exclusion so it is a decision on the record rather than an omission.

## ADR-019 rev 3.1 reserve — same drop, because the ADR says so

`jjdai/custody.py` holds the deferred-verification vocabulary: eleven record
kinds, `SELF_CHECKED`, the `CUSTODY_*` outcomes, the rev 3.1 split of
`custody_reason` from `replay_status`/`replay_reason`, the immutable
`stored_status`, the computed `EVIDENCE_*` projection, the
`verification_custody` key domain, the `CUSTODY_PRIVATE` access class, two
namespaces and eleven leaf domains. §4 of the ADR names the carrier: the
same drop as the track V reserve. Ф0 freezes **names**; schemas and canonical
encoding are Ф2, before first emission.

Accepted authorises the reserve and **nothing in the runtime**. A lone
`production` node still refuses with `no_independent_panel` — now because
the custody machinery does not exist, not because a document was under
discussion.

**A limitation named rather than discovered.** Two of the reserved groups —
the tool effect classes (`pure` … `unknown`) and the two node profiles — are
ordinary lowercase English words, and one of them already occurs about
twenty times in this tree in unrelated senses. They are reserved and refused
by their own checkers, but they are **excluded from the value scan**: a scan
that refuses the bare word "unknown" anywhere in a record fails closed on
honest records. This was not theoretical — widening `TRKV-8` to both
vocabularies reported six legitimate files until the exclusion was applied.
For these two groups the reserve is a declaration plus an argument check,
and not a body-content check.

## The ADRs are in the tree

`docs/adr/` now holds 014 (as issued, PDF), amendment A-1, 015, 016, 017,
018 and 019. Audit 0's documentary blocker is closed.

**ADR-017 was flipped to Accepted before the reserve was built** — the same
rule applied to ADR-018 in the first cut. A pre-genesis reserve must not rest
on a Proposed decision, and four of its wrapping domains were already frozen
in `jjdai/cognitive.py` while the document said Proposed.

**ADR-014 arrives as a PDF and cannot be patched**, and its D6 is partly
revoked by A-1.1: the round runs on replicas in two symmetric cells, not by
direct attested participation. The ADR index states that above the table, so
a reader does not implement a revoked mechanic on the strength of the
document's own text.

ADR-016 rev 2 remains **Proposed** and is now the only one; the index says so.

## Acceptance

New `RSV-1…7` (`tests/unit/test_reserved_values.py`) and `CUST-1…8`
(`tests/unit/test_custody_reserve.py`). `TRKV-8` widened from one vocabulary
to two. `KRIYA-1` and `KRIYA-2` rewritten onto `DeliberationProof`.

Ten mutations, ten reds: the scan removed from `append()`; whole-string
matching with no segment check; `provenance` dropped from the scanned
fields; mapping keys not scanned; custody kinds not folded into
`RESERVED_KINDS`; the namespace check dropped from `retrieve()`; the
`EVIDENCE_*` projection reverted to the bare names review had proposed; the
legacy `viveka` row removed from `ORGAN_BINDINGS`; `EMITTED_PREFIX` reverted
to the legacy spelling; and the ambiguous tokens pulled INTO the scan.

## Owed next, unchanged

The recut3 residual (`README.md` outside the tree digest; file modes and
symlink targets), supply chain (SBOM, pinned dependencies, signed artefacts,
two-person release approval), T-TOOLSET, a CLA — which needs a named legal
entity and cannot be produced by a build — and `tests/live/test_vertical_live.py`,
still never run on a host with a real model.

Drop order from here, to be fixed in r6.8: **v0.6.9** Agent Alpha (G-GUI plus
the live run on the target hosts), **v0.6.10** T-TOOLSET together with supply
chain, since a reproducible build, an SBOM entry, a signed manifest and a
witnessed tool addition are one concern and the Ф0 gate depends on all four,
**v0.6.11** the evidence-ID catalogue.

---

## v0.6.8 remediation — the tree becomes its own plan of record

**Not a new version.** A number is spent by a TAG, and v0.6.8 has none. This
is the same drop with its documentary and release debt reduced; the acceptance
counter moves **206/206 → 211/211** because five checks were added, not because
any behaviour changed. No production code path was touched.

### Why

The external audit of the pair «v0.6.8 archive + roadmap r6.8.2» found no P0
in the shipped code and one P0 in the roadmap. The finding underneath both was
the same: **the tree did not contain the plan its own evidence bound it to.**
`tree_digest 7c797da15523` proved the code against the r6.7 roadmap and
ADR-014…019, while the normative documents for that code were already r6.8.2,
the ADR-017 amendment, ADR-020 and ADR-021. Nothing said so, because nothing
looked at the documents.

### Roadmap r6.8.2 → r6.8.3

* **P0 closed** — the fourth reserve window carried the **ADR-020 rev 2**
  composition: two domain separators of five, and no body-erasure reason,
  while the document above it declared rev 4.1 Accepted. Replaced with the
  verbatim §3 list from rev 4.1: five separators (`BINDING:v1`,
  `BINDING:REVOKE:v1`, `FEEDBACK:BODY:v1` were the missing three),
  `GUARDIAN_REQUEST` / `RETENTION_POLICY`, and the full binding lifecycle.
* The **coordinated change set is named as four parts** — ADR-020 rev 4.1, the
  ADR-017 / A-1 amendment, manifest schema `jjdai.model-artifact/v2`, and the
  reserve — with the rule that none acts alone, and a precondition on the tree
  before v0.6.9 may be cut.
* The clause requiring "ADR-020 rev 2 Accepted before cutting v0.6.9" is
  satisfied and replaced by the tree condition.
* v0.6.8's status is one formula in all four places it appears. The changes
  table said "closed (206/206)" against three other places saying untagged with
  debt open.
* **CLA removed from the reasons a tag is absent.** It was simultaneously named
  as a tag blocker and, forty lines later, as having nothing to do with the tag.
  The second is correct: CLA governs external contribution.
* Recorded-run path corrected to `docs/evidence/hermetic.json`.
* **Fourth precondition added to the preflight tag:** normative documents
  synchronous with the tree.
* SBOM, dependency pinning and `.gitattributes` moved out of v0.6.10 and into
  this remediation; v0.6.10 keeps T-TOOLSET, reproducible build, signed
  artefacts and two-person approval.

### Into the tree

* `docs/adr/ADR-020-Agent-Alpha.md` (rev 4.1, Accepted) and
  `docs/adr/ADR-021-Memory-Inheritance.md` (rev 4, **Proposed** — the index
  says so).
* **ADR-017 / A-1 is INLINE, at a new `K4-bis`,** not a separate file. ADR-014's
  A-1 is separate only because ADR-014 is a PDF and cannot be patched; ADR-017
  is markdown, so the amendment sits where a reader of K4 will hit it. It names
  a principal-local wrapping key for access class `GUARDIAN_PRIVATE` and only
  that class, splits `guardian_sign` from `guardian_wrap`, and records the
  resulting loss mode rather than leaving it to be discovered. The document
  header no longer forbids all runtime in Ф0 without naming the exception.
* **r6.7 removed, r6.8.3 added** (md + typeset PDF). Only the current revision
  lives in `docs/roadmap/`: each revision contains the previous one whole, and
  two self-contained roadmaps side by side is the "correct text beside a stale
  table" defect this project has already paid for.
* Every pointer at the departed r6.7 file was chased down — README, the docs
  index, the roadmap README, and prose references inside `jjdai/cognitive.py`,
  `kernel/viveka.py` and a test docstring.

### Release and build hygiene

* **`.gitattributes` with `* -text`.** `source_digest()` reads raw bytes over
  200+ paths including the sha256-pinned AGPL text. A checkout that normalises
  line endings breaks both the tree digest and the licence pin, and reports
  itself as ACC-TREE-1 "a different tree" — which does not say "line endings",
  so the cause is not discoverable from the symptom. **This must be the first
  commit, before any clone exists.**
* **`requirements-dev.txt`, pinned by version AND hash**, installed in CI with
  `--require-hashes`. The runtime core remains stdlib-only; what is pinned is
  the collector that produces the evidence. `pip install pytest` made a green
  run mean "passed under an unknown version of an unknown collector".
* **`scripts/gen_sbom.py` → `docs/sbom.cdx.json`** (CycloneDX 1.5), generated
  and re-checked in CI rather than written by hand — this repository has twice
  shipped a hand-maintained list that drifted from the tree. Deterministic by
  construction: no timestamp, no serial number, sorted throughout. The document
  describes the tree MINUS itself and says so, because a file containing its own
  hash never converges; it stays inside `source_digest()` so tampering with it
  still breaks the tree digest. Its metadata names what remains open, and a
  check refuses to let that list quietly empty.

### Two entrypoints, one suite

`run_acceptance.py` claimed it and `pytest tests/` collected "the exact same
functions". False: the runner's default is the five hermetic groups (211);
`tests/live` is a sixth needing a real wasm runtime and a real model, and a bare
`pytest tests/` collected it and failed on any host without them, while the
runner reported clean. `pyproject.toml` now carries `--ignore=tests/live`, the
claim is withdrawn in all three documents that made it, and README explains
which number the badge is.

### Two stale constants for `docs/acceptance_result.json`

The artefact moved to `docs/evidence/<suite>.json` in v0.6.7-recut3 and nothing
has written the old path since. It survived as a dead `RESULT` constant in
`gen_architecture_docs.py` and — worse — as an entry in the tree-digest
EXCLUSION list, where a leftover reads as a deliberate exemption and silently
un-hashes any file that later takes the name.

### New checks — `tests/unit/test_tree_is_its_own_plan.py`

`SYNC-1…4` (every indexed ADR exists and every present ADR is indexed; exactly
one roadmap revision, named identically in three documents; no surviving pointer
at an absent roadmap; ADR-017's inline A-1 present and reachable from the index),
`ENTRY-1/2`, `SBOM-1…3`, `PIN-1`, `ATTR-1`.

**Thirteen mutations, thirteen reds.** One of them found a defect in this drop's
own code: `gen_sbom` refused an unhashed pin by raising `SystemExit`, which
killed the acceptance runner during import instead of failing one check. A
library refuses by raising; only `main()` may exit.

`SYNC-3` also went red against its own docstring on first run — it scans for
pointers at absent roadmap files and does not exempt itself. The docstring was
reworded rather than the check narrowed.

### Status unchanged where it matters

`code-complete · 211/211 recorded · untagged · release debt open`. The SBOM does
not unlock the release tag: what makes a release tag mean anything is signed
artefacts and two-person approval, both still owed by v0.6.10. What this drop
does unlock is the **preflight tag** — the tree now satisfies the fourth
precondition it did not satisfy before.

---

## v0.6.8-recut2 — a status is not a presence

Still v0.6.8, still untagged. **211/211 → 213/213**: two checks added, nothing
behavioural changed.

### P0 — ADR-020 was Proposed and Accepted at the same time

recut1 put ADR-020 rev 4.1 into the tree carrying `Status: Proposed`, and its
own closing paragraph said that until it is Accepted it authorises neither the
ADR-017 amendment nor the pre-genesis reserve. Meanwhile the roadmap, the docs
index, the CHANGELOG and **ADR-017's own K4-bis** — whose text says the
amendment took effect on ADR-020's adoption — all treated it as Accepted. The
coordinated set was resting on a document that declared itself unadopted.

* ADR-020 header → **Accepted · rev 4.1 · 25 August 2026**.
* Its closing paragraph rewritten. The old sentence drew the line at "until
  Accepted, nothing is authorised", which is the wrong line now: adoption
  authorises the coordinated IMPLEMENTATION, and what stays closed is
  EMISSION — new record kinds, the `guardian_feedback` key domain, the
  `GUARDIAN_PRIVATE` access class, `GuardianBinding`, `JaiGuruDev` — until all
  four parts of the set are in the tree. Acceptance moves the boundary from
  "the document is not adopted" to "the set is not built"; it does not remove
  it.
* K4-bis in ADR-017 now says on what it rests and when that became true.

**SYNC-5 added.** SYNC-1 asked whether a file EXISTS and stopped there, which
is exactly how this passed. SYNC-5 parses the status word out of every markdown
ADR's own header and compares it with the status the docs index publishes for
it — eight documents — and additionally pins ADR-020 to Accepted by name,
because K4-bis and the roadmap's v0.6.9 precondition both depend on it.
ADR-014 is skipped: it ships as the PDF it was issued as, and the index carries
its status in prose with a warning.

### The pytest finding — the diagnosis was wrong, the fix was right

The audit read `addopts = "-q --ignore=tests/live"` as blocking an explicit
`pytest tests/live`, leaving the opt-in group unreachable. **Verified against
the tree, and it does not:** `--ignore` prunes during RECURSION, so a path named
on the command line is still collected. Measured on pytest 9.1.1 — bare 211,
`pytest tests/` 211, `pytest tests/live` 6.

The proposed change went in anyway, on a different and better argument.
`testpaths = ["tests"]` made the default set a SUBTRACTION: everything under
`tests/`, minus whatever `--ignore` removed. A subtractive default silently
adopts the next directory somebody adds. `testpaths` now names the five
hermetic groups positively, and `--ignore` stays, because the two cover
different commands — `testpaths` governs a bare `pytest`, `--ignore` governs
`pytest tests/`, where an explicit directory argument makes `testpaths`
irrelevant.

**ENTRY-3 added**, and it RUNS the three documented commands rather than
reasoning about them, because a reading this subtle is one a later pytest
release could change and one a careful reader already got wrong. Where pytest
is absent it asserts the configuration and says which mode it ran in, rather
than skipping — a check that skips itself quietly is not evidence.

### Roadmap r6.8.3 → r6.8.4 — four blocks describing the tree before the work

The revision that closes a P0 by citing "correct text beside a stale table is
worse than one wrong text" left four instances of exactly that:

1. § byte-precision still said the repository has no `.gitattributes`;
2. the Ф0 exit criteria still listed CLA, SBOM and pinning as release debt,
   forty lines after establishing that CLA does not block a tag and that the
   other two were done;
3. the preflight tag annotation still required the words "SBOM absent";
4. § where-we-are listed four items as absent, of which one actually is.

All four corrected, and the release debt rewritten as a list of what is open
rather than a mix of closed, non-blocking and open: reproducible build, signed
artefacts, release provenance, two-person approval, T-TOOLSET, README outside
`tree_digest`, file modes and symlink targets. "Three conditions" for the
preflight tag became four — the fourth was added in r6.8.3 and the heading was
not.

### Editorial, ADR-021 rev 4 (still Proposed)

Two instances of the project's own named defect, in a document a pre-genesis
reserve will be read off:

* the domain-separator list has three entries and the sentence under it said
  "two separators, not one" — `SOURCE-ROOT:v1` arrived in rev 4 with
  `proof_mode` and the count stayed at rev 3;
* the envelope schema declares `root_attestation` / `root_attestation_signature`
  while the prose two hundred lines earlier called the same fields
  `source_being_root_attestation` / `source_being_signature`. Not synonymy —
  two names for one field in one document. **A field that is not in the
  canonicalised structure does not exist**, so the schema wins and the prose
  was corrected to it.

### One more stale evidence path

`acceptance_badge()`'s docstring in `gen_architecture_docs.py` still described
the runner as writing `docs/acceptance_result.json`. The constant above it was
fixed in the previous recut and the docstring below it was not — the same file,
two truths, which is the shape of the defect rather than an instance of bad
luck.

---

## v0.6.8-recut3 — the artefact answers for itself

Still v0.6.8, still untagged. **213/213 → 215/215**: two checks added.

### Provenance note, recorded because it is the kind of thing that must be

The working tree this recut was cut from was found to contain changes with no
author in this session — coherent, on-topic work responding to the recut2
audit, timestamped after the previous recut had been packaged and delivered.
It was not built on. The base was re-taken from the SHIPPED recut2 archive
(`tree_digest ef19874a8424`), whose digest an external audit had independently
confirmed against a clean unpack, and every change below was read, decided on
and re-applied deliberately, with its own mutation round.

Two of the decisions differ from what was found, and one is a straight
reversal — see the pinning section. The precedent is v0.6.5, where a
ready-made `jjdai/adapters/` skeleton appeared in a copied tree and the
response was to discard the working tree and rebuild from the shipped
artefact. A tree of unknown provenance defeats the entire purpose of a
`tree_digest`.

### P0 — the roadmap PDF disagreed with its own markdown

recut2 shipped `JJ_DAI_Roadmap_r6_8_4.pdf` saying **211/211** beside
`JJ_DAI_Roadmap_r6_8_4.md` saying **213/213**, in the same three places:
current state, the numbering rules, and where-we-are. The PDF was typeset
before the counter edit and never rebuilt. `docs/roadmap/README.md` says the
PDF is the same document typeset; that sentence was false.

Nothing in the tree could see it. `check_docs_drift.py` verifies the surfaces
generated from `architecture_status.json`, and the roadmap PDF is not one of
them, so it reported clean throughout.

`scripts/typeset_roadmap.py` now builds the PDF and stamps the **sha256 of
the source markdown into the PDF's own metadata**, as a literal ASCII marker
so a stdlib check can find it in the raw bytes without a PDF parser. The
object streams are deliberately left unpacked for the same reason. A sidecar
file recording which markdown a PDF came from was rejected: a sidecar is a
third thing to keep in sync, and a claim about an artefact kept beside the
artefact is exactly what went stale here.

**SYNC-6** verifies the stamp. CI runs the same check. What it proves is that
the PDF was typeset from the markdown in the tree now; what it does not prove
is that the rendering is faithful — a stamp is not a comparison of glyphs and
would not catch a typesetter that dropped a table. It catches the failure that
actually happened, and says so rather than letting a reader assume more.

### The pinning claim was wider than the pin — closed by pinning, not by narrowing

Documents said "hash-pinned CI toolchain" while `actions/checkout@v4` and
`actions/setup-python@v5` were moving major tags — branches in all but name —
and `[build-system].requires` carried `setuptools>=68`, a floor. Two closures
were available. **The actions are now pinned by full commit SHA**, resolved
with `git ls-remote --tags --refs` and cross-checked against the exact release
tag pointing at the same commit (`v4.4.0`, `v5.6.0`); `setuptools` is pinned to
an exact version.

What remains is one gap and it is declared rather than implied: PEP 517 gives
`[build-system].requires` no field for a hash, so the build backend is
version-pinned only. It is named in the SBOM as `build-backend-unhashed`,
carried as open debt under v0.6.10, and **SBOM-2 now permits a hashless
component only if it declares why AND the gap appears among the open items** —
otherwise that exception becomes the door every unpinned thing walks through.

The SBOM also grew the components an audit round found missing: both Actions
(with their commit as the hash) and the build backend. An inventory listing
only the Python packages read as the whole dependency surface. **PIN-2** now
fails if any `uses:` is not a 40-hex SHA.

### ENTRY-3 could read green without pytest, and the evidence did not say so

The fallback itself is correct — the hermetic suite must run on a bare
interpreter, so a check that needs pytest must assert configuration when
pytest is absent rather than skip. What was wrong is that the recorded
artefact said nothing about which of the two modes had happened, so an audit
reading `docs/evidence/hermetic.json` could not tell an exercised claim from
an asserted one, and reported it as green-without-running.

Schema **`jjdai.acceptance_result/v4`** adds `collector`:
`{runner, pytest, entrypoint_probe_mode}` where the mode is `collection` or
`configuration-only`. ENTRY-3 verifies the artefact describes the host it is
running on, before branching, so it holds in both modes. `ACC-TREE-1`'s schema
pin moved to `/v4` — on an exact version, not a prefix, which is what forces a
shape change to be acknowledged rather than absorbed.

### Roadmap r6.8.4 → r6.8.5

* **`.gitattributes` operational norm rewritten.** "First commit, before any
  clone" described a repository that does not exist yet; for one that does it
  is retroactively impossible, and a requirement nobody can satisfy is a
  requirement nobody checks. The norm is now: the file is in the commit the
  preflight tag names; evidence is re-taken from a clean clone of that commit;
  copies made earlier are re-cloned or separately validated against
  `tree_digest`.
* Pinning boundaries stated across all three build inputs.
* PDF freshness recorded as a checkable property.

### README

"five cross-cutting tracks" against six, and SBOM and dependency pinning still
listed in remaining debt after both were done. The same defect class r6.8.4
was issued to close — correct status beside stale text.

### `.typeset`

Added to `_DIGEST_SKIP_DIRS` and `.gitignore`. Build scratch belongs outside
the digest for the same reason `__pycache__` does: it is not shipped, and
whether it happens to exist when a run is recorded must not decide whether a
later clean unpack reads the same tree.

---

## v0.6.8-recut4 — an artefact describes the run that produced it

Still v0.6.8, still untagged, still **215/215**. No check added; one check
corrected, and a CI job added that proves something no existing job did.

### P0 — ENTRY-3 made CI fail by construction

recut3 asserted that the RECORDED artefact described the CURRENT host:

    expected = "collection" if have_pytest else "configuration-only"
    assert mode == expected

The shipped tree's evidence was recorded on a bare interpreter, so it carries
`configuration-only`. The workflow installs `pytest==8.3.5` and then runs the
suite. Evidence says `configuration-only`, host is `collection`, assertion
fails — every time, on every push.

**No value of the field fixes it.** Re-recording in `collection` mode moves
the failure to the bare interpreter the stdlib runner exists to serve. The
question was wrong, not the answer: an artefact describes the run that
produced it, and coupling it to whoever reads it later makes evidence expire
on contact with a different machine. That is the opposite of what a recorded
run is for.

Split into the two questions it always was:

* **the artefact, on its own terms** — `runner` is this repository's runner,
  `entrypoint_probe_mode` is one of the two known values, and the single
  binding between the fields holds: `configuration-only` implies
  `pytest: null` (a run that fell back did so because pytest was absent), and
  `collection` implies a named pytest version (a collection probe that cannot
  say what collected is not evidence of a collection). Checkable from the
  artefact alone, on any host, forever;
* **this host, on its own terms** — with pytest, the three documented
  commands are actually run; without it, the configuration is asserted.

Verified against one unchanged artefact in both environments: green on a bare
interpreter, green with pytest 9.1.1 present.

**This was visible and was misread.** The previous recut demonstrated exactly
this assertion firing when the tree was checked with pytest against evidence
recorded without it, and reported it as proof that the field discriminated
between hosts. It was the defect, presented as the feature.

### CI — a step named for something it was not doing

`Stdlib runner parity (no-pytest environments)` ran in a job that pip-installs
pytest before reaching it. It proves the stdlib runner and pytest agree on a
host that has both, which is worth proving and is not what the name said. It
is now `Stdlib runner agrees with pytest on this host`, with a comment saying
what it does not prove.

The claim that the runtime core is stdlib-only is made in the README, in
`requirements-dev.txt` and in the SBOM as `runtime-dependencies: 0`. Nothing
tested it. New job **`bare-interpreter`** installs nothing, refuses to run if
`import pytest` succeeds, and runs the full hermetic suite. If any import in
the suite grows a third-party dependency, that job goes red on the import
rather than three drops later on a machine with no package index.

It also runs the same tree with the same evidence file in the opposite
environment from the matrix job — which is the property recut3 broke: whichever
mode the evidence carried, one of the two jobs was guaranteed to fail.

# JJ DAI v0.6.9 — the provenance of executable code, as one chain

Scope: **ADR-022 rev 2.2 (Accepted, 27 Aug 2026)** end to end — D2 through
D14 — plus T-TOOLSET. One concern, not seven: which tree, by which recipe,
into which artefacts, checked by whom and by what independent act. The chain
breaks the same way at every link, which is why it was built as one drop and
not split across three.

Acceptance **295 checks** (219 at the start of this drop). The count is
recorded in `docs/evidence/hermetic.json` and rendered from there;
`docs/status_badge.md` is generated whole and no longer lives inside the
README.

## What this drop does NOT close, and why the debt ledger says so

Five positions stay `open` and one check pins them there (DEBT-3):
`build-backend-unhashed`, `reproducible-build`, `signed-artefacts`,
`release-provenance`, `t-toolset`. **The mechanism being built is not the
debt being paid.** Every one of them needs something a build cannot produce:
vendored wheels fetched on a host with index access, a key ceremony on two
physical devices, a second machine of the same class for the independent
rebuild, and a real `wasmtime` on both target host classes. The tree ships
the machinery and refuses to act without the facts — `BUILD_PIN_MISSING`,
`RECIPE_PLACEHOLDER`, `REL_UNKNOWN_KEY`, `MANIFEST_NO_RESOLVER` — which is
the honest state rather than a gap.

Two positions DID close, each with the check that discharged it:
`readme-outside-tree-digest` (R-OWN-3) and `file-modes-and-symlink-targets`
(TREE-2 · TREE-3).

## `pure` stopped being a sentence and became a boundary

The roadmap used to define it as "no writes outside one preopen directory",
which permits writing INSIDE that directory and therefore drew no boundary
at all. r6.9.1 replaced the definition; this drop makes the replacement
executable:

* **zero preopen directories**, and the assembled command is checked rather
  than trusted — the preopen that mattered arrived as a flag on exactly that
  line;
* the WASI import allowlist — `fd_read`, `fd_write`, `proc_exit` — is
  checked **on the module's bytes before the runtime is invoked**. A refusal
  that fires when execution reaches a forbidden call depends on the input
  reaching it, so two runs of one module would differ in whether the
  boundary held;
* clocks, entropy, sockets and `path_open` each refuse with the clause that
  refuses them;
* fuel, guest memory and TOTAL output are enforced, each breach a named
  refusal with the partial output **discarded** — a truncated result from a
  deterministic tool cannot be told apart from a complete one;
* a runtime that does not accept the limit flags makes the profile
  unavailable: a limit a runtime ignores is not a limit.

Stated in advance rather than discovered: a module linked against the full
`wasi-libc` imports more than the allowlist and will not instantiate. The
starter set must be built against a narrowed target, and whether the chosen
toolchain gives that AND a byte-for-byte repeat is ADR-022 O-3, answered on
a host.

## One door, and a signature that covers who signed

`kernel/isolation.py` used to read `toolset.json` itself and never call the
validator, so a manifest with no signature, no authorization form, no sunset
and no limits reported `available = (True, "")` and executed. The validator
sat beside the door instead of being it. There is now one door,
`load_verified_manifest()`, and availability, capabilities, module
resolution and execution all arrive through it.

The signature is verified, not counted. Without a resolver for the signing
key the profile is **unavailable** — absence of a checker is not permission,
and a manifest is what sanctions an L2 mutation. The signer's identity lives
INSIDE the signed body: the first cut excluded the whole signature block,
which carried `key_id`, so swapping it for another registered id holding the
same public key left the bytes unchanged and the signature valid.

## Four release objects, and a hashed object that stops growing

`ReleaseStatement` · `ApprovalStatement` · `ReleaseAttestation` ·
`ReleasePublication`. The attestation is immutable and addressed by its
hash; the publication is a SECOND object carrying it byte for byte plus
`witness_ref`. An earlier revision kept the reference inside the hashed
envelope, so adding it changed the hash and the record bound to the previous
version of the object.

* **no self-declared position**: a statement carrying `witness_seq` refuses,
  because such a field could be pointed back into a revoked key's validity
  window. Validity is judged at the ACTUAL position of the
  `RELEASE_ATTESTED` record, and a release recorded before a later
  revocation stays valid;
* **the control block is counted**: `distinct_keys`, `distinct_devices` and
  `distinct_principals` are derived from valid approvals through the
  registry and compared with what the statement records. Two-key drawn as
  two-person would enter a signed artefact as an independence nobody had;
* `verification_evidence_hash` has ONE shape — required for a verifier,
  forbidden for a builder. The field on a builder is how a builder becomes a
  verifier without rebuilding anything;
* `publish()` holds the chain lock across read-position → verify → append,
  and abandons the publication if the record lands elsewhere. Without it a
  release is published as valid at one position and verified as invalid at
  its real one;
* `verify_publication` verifies the CHAIN cryptographically. Comparing one
  hash against a value taken from the reference under examination accepted a
  chain whose signed fields had been edited.

`docs/release_keys.json` ships valid and **empty**: two keys on two physical
devices are a ceremony and a Ф0 gate item, not something a build produces.
With it empty nothing can be attested, and REL-10 pins that.

## `jjdai.source-tree/v2`, and the README that could finally be hashed

The digest takes the **committed tree of the tag target** after a clean
check, and a dirty tree refuses. Every field is length-prefixed; symlinks
are recorded by their TARGET and never dereferenced, with the executable
byte forced to zero because `lstat` reports the link's own bits; the
executable bit is carried; entries sort by RAW PATH BYTES, because an order
that depends on the locale of whoever computed it is not a content address;
a gitlink is a hard refusal.

`docs/digest_scope.json` declares subject tree against output set **and is
itself in the subject tree**, so the boundary cannot be moved silently. It
refuses self-exemption, an exclusion with no binding, and its own absence —
absence is not "hash everything".

D12 followed from that: README held the one exclusion bound nowhere else,
which is precisely the shape D11 forbids. The three generated blocks moved
to `docs/status_badge.md`; the build now writes no byte of the README and
the README joined the digest. A normalised hash over it was the alternative
and is rejected — it trades byte exactness for exactness by agreement, and
agreements drift.

## The build backend, pinned where PEP 517 cannot pin it

`setuptools==80.9.0` promises a LABEL, not bytes: `[build-system].requires`
has no field for a digest. The backend and every one of its dependencies are
vendored under `vendor/build-backend/` and pinned by sha256 in a file of
their own, verified **before** installation — verifying afterwards verifies
a decision already taken. `SOURCE_DATE_EPOCH` is the COMMITTER time (`%ct`),
because author time survives a rebase while the tree moves on. The network
is measured, not assumed. The wheel is built from the already-checked sdist.
`--no-build-isolation` cleans nothing by itself and the caveat is written
where the flag is used.

## Attribution

New checks, in the form `X-1…X-N (path)` that
`tests/unit/test_changelog_attribution.py` parses — the form matters,
because an attribution the parser does not recognise is an attribution
nobody verifies:

* PROV-1…PROV-9 (`tests/unit/test_release_provenance.py`) — the ADR-022
  vocabulary; `RELEASE_ATTESTED` emittable and not reserved, debt events not
  witness kinds, two signing domains and one hash prefix refusing each
  other's role, the `pure` effect-class split.
* PURE-1…PURE-5 (`tests/unit/test_toolset_pure_boundary.py`) — the
  allowlist read from module bytes, clocks and entropy refused by clause,
  malformed modules failing closed, zero preopens, limits declared per tool.
* TSET-1…TSET-5 (`tests/unit/test_toolset_pure_boundary.py`) — manifest v2,
  the toolset signing domain, the interim authorization sunset, the loader's
  duty, recipes in git and no binaries.
* RP0-1…RP0-10 (`tests/unit/test_adr022_p0_closures.py`) — the seven P0
  closures of the first audit round and three of the second, each written as
  the audit ran it: same input, same door.
* REL-1…REL-16 (`tests/unit/test_release_chain.py`) — the four objects, the
  counted control, key validity at the real position, the atomic publish,
  the chain verified cryptographically, mandatory physical binding.
* TREE-1…TREE-8 (`tests/unit/test_source_tree_digest.py`) — length
  prefixes, symlink targets, the executable bit, raw-byte ordering, gitlink
  refusal, the committed tree, the declared boundary, the algorithm id.
* R-OWN-1…R-OWN-5 (`tests/unit/test_readme_ownership.py`) — the generator
  changes no byte of the README, which is why the README can be hashed; and
  the hand-written prose agrees with the debt ledger, which nothing checked
  until §8 had described a cancelled control as owed for a drop and a half.
* BLD-1…BLD-7 (`tests/unit/test_build_environment.py`) — pins outside
  `pyproject`, hashes before installation, committer time, measured network,
  sdist-then-wheel, the environment table compared field by field.
* DEBT-1…DEBT-4 (`tests/unit/test_debt_ledger_and_tags.py`) — one
  fail-closed projection, every terminal event citing its reason, what this
  drop closed and what it deliberately did not.
* TAG-1…TAG-4 (`tests/unit/test_debt_ledger_and_tags.py`) — what each tag
  asserts and the four things D13 forbids.
* ASM-1…ASM-5 (`tests/unit/test_release_assembler.py`) — every statement
  field derived, refusal on the first missing fact, readers rather than
  hashes.
* LIVE-1…LIVE-1 (`tests/unit/test_release_assembler.py`) — the live group
  encodes the current `pure`, not the definition r6.9.1 removed.
* L-1…L-9 (`tests/live/test_wasm_live.py`) — opt-in, on each target host
  class. L-6 and L-7 are what the hermetic suite cannot prove: only a real
  runtime exhausts real fuel.

Every check above was verified RED against a deliberate mutation of the
thing it names; the harnesses are not shipped, and the mutations are
recorded in this entry's review trail.

**Five checks first passed for the wrong reason and were caught by those
mutations rather than by reading** — PROV-3, PROV-8, RP0-2, REL-7 and
DEBT-1. In each the assertion was satisfied by a neighbouring guard or by an
unrelated exception type, so deleting the rule under test left the check
green. All five now assert WHICH refusal fired, by type and by wording. The
rule this drop leaves behind: never assert that something raised, assert
what raised and why.


## Recut, by audit of the cut itself

Nine P0s, every one confirmed against the tree before it was fixed.

**`WitnessChain.append` never took the lock it was documented to hold.** The
comment has read "guards append" since v0.5.3; two threads both read
`next_index()`, both built a body at index 0, both persisted, and
`verify_chain()` went False. A defect of the chain itself, not of the
release code — the release code only made it visible. `next_index`,
`head_hash`, the salts, the signature, the persist and the in-memory append
are now one critical section.

**A refused publication left its record behind.** `publish()` verified,
appended, and raised if the index had moved — by which time the
`RELEASE_ATTESTED` record was in the chain and on disk. An append-only store
has no undo, so the position is re-read INSIDE the hold and the refusal
happens BEFORE the write. REL-13 was green for the wrong reason: it asserted
the error code and never that nothing was written.

**`internal_only()` published releases.** Passing it to `publish()` turned
every external gate off at once — no tag, tree, acceptance, bundle, recipe,
SBOM, manifest or artefact ever compared. It now refuses in `publish()` and
`check_release_tag()`, and any single absent reader refuses with it. The
assembler's own `context()` passed `recipe_reader=None`, so `recipe_hash`
went unchecked while every other hash was compared.

**A red run stood behind a release.** `{"passed": 1, "total": 1,
"import_errors": 1}` with no tree digest was accepted. A recorded run must
now declare the acceptance schema, be of the hermetic suite, carry zero
import errors, and name THIS tree with the algorithm that addressed it.

**The build environment was validated and never verified.**
`environment_matches()` existed and no verifier called it — the third
appearance in this drop of a validator standing beside the boundary instead
of being it. The whole D3 table is now required and compared field by field
against what was measured.

**The digest scope excluded by prefix.** Fourteen historical status pages
sat under `docs/site/JJDAI_Architecture_Status_v`, regenerated by nothing
and bound to nothing, and anything at all could be dropped under
`docs/evidence/`. A prefix is the wrong shape for this: an exclusion is
justified by a file being DERIVED from something hashed, and derivation is a
property of a particular file. The boundary now lists the four files a run
of this tree writes, and the historical pages are hashed like what they are.

**Toolset key validity was current-only**, so a rotation would have taken
down every manifest the key ever signed. Manifests now declare the position
they were authorized at, and validity is judged there.

**Key lifecycle positions were numbers in a file.** They must now resolve to
a record in the chain: a registry that can move an activation earlier by
editing a digit can make a signature valid that was not.

**Named release revocation is OWED and is not implemented.** An earlier cut
of this recut answered it with a function looking for a `revoked_marker`
field that nothing writes — a mechanism shaped like one, which is the defect
this drop has been audited for four times. Doing it properly needs a
`RELEASE_REVOKED` record kind that window 6 of the pre-genesis reserve does
not hold, and adding a serialized value to a frozen reserve is an ADR
decision. It is in the ledger as `release-revocation-by-name`.

Also: `verification_evidence_hash` is checked as a digest rather than
accepted as the token `"x"`; an artefact's recorded LENGTH is compared with
the bytes read, not only its hash; and README §2 was empty while §8 listed a
control ADR-022/D2 had cancelled — prose no drift check covered, now covered
by R-OWN-5.

---

## v0.6.9 · recut 2 — the five P0 of the recut1 audit

Cut against the audit of `jjdai_v0.6.9-recut1.zip` (`f25d3bab…`), which
returned HOLD: five P0 and one documentary defect. Acceptance **295 → 300**.
Four of the five close in the tree; the parts no code can prove are named in
the debt ledger rather than depicted, and the ledger now BLOCKS instead of
describing.

**P0-1 — REL-16 was a false green, and the strongest kind.**
`check_lifecycle_witnessed()` promised in its docstring that "the record's
provenance pre-image must name this key and this transition", did an index
lookup and threw the record away; no production path called it; and
`KEY_ACTIVATED` / `KEY_REVOKED` were string constants `witness.KINDS` has
never held, so no such record can be appended at all. Its own check appended
six `INFER` records and accepted one of them as a key activation. A check
that confirms a property the code does not implement is worse than a missing
check, because the missing one is visible.

What the tree does now is exactly what it can: a declared position may not
name a future the chain has not reached — `revoked_at_witness_seq: 999999`
is a key that stays valid for every release anyone cuts — with position `0`
on an empty chain allowed as the genesis convention. The check is called
from `publish()` and `verify_publication()`. The overclaim is closed at its
source: `load_registry()` refuses `lifecycle_binding: "witnessed"` and
`docs/release_keys.json` declares `asserted`. The gap is
`release-key-lifecycle-witnessing`, blocking the meaning of a release tag.

**P0-2 — a toolset manifest dated its own authorization.**
`authorized_at_witness_seq` was read out of the signed manifest, with a
fallback to a caller-supplied integer no caller supplied. A key valid on
`[0, 10)` signed a manifest claiming position 0 and it loaded: the signature
made the false date immutable rather than true, which is the backdating
ADR-022 rev 2.1 removed from `ReleaseStatement`, arriving through a field
instead of an argument — and here it buys the widening of a being's hand.
`jjdai.release.toolset_authorizer()` now builds a resolver from a VERIFIED
`ReleasePublication` and answers with the actual index of its
`RELEASE_ATTESTED`; a manifest declaring any other position refuses.

**P0-3 — rebuild evidence resolved to nothing.**
`verification_evidence_hash` was checked for shape only, so a release
naming `9a9a…9a` published. The evidence is now the verifier's OWN
`ReleaseStatement` from his own run of the recipe: no new schema is
invented, because window 6 froze the names this drop emits and reuse is
also the stronger object — reproducibility IS the claim that two
independent runs produce the same artefact hashes. `ReleaseContext` gains
`evidence_reader`; bytes must hash to the named digest, validate as a
statement, and agree on the eight fields a rebuild reproduces.

**P0-4 — the tag gate ignored the canonical debt ledger.**
`check_release_tag()` never opened `architecture_status.json`, so a tag was
accepted with four positions open under `blocks: meaning-of-a-release-tag`
— the one thing D13 forbids outright. Both gates now project the ledger
through `provenance.load_debt_ledger` (one projection, not a second scan):
`publish()` on `publication`, `check_release_tag()` on
`meaning-of-a-release-tag`, which today finds seven open and refuses. Two
holes found alongside: `release-revocation-by-name` carried no `blocks` at
all, and an unknown boundary would have blocked nothing while reading as
though it blocked something — both refused at the projection now.

**P0-5 — `--prepare` prepared nothing.**
It ran `pip install --force-reinstall` into the current interpreter:
no environment created, nothing extraneous removed, the build hook isolated
from nothing. It now builds a one-shot venv `--without-pip`, populated from
outside with `--prefix` so `ensurepip` cannot seed two unpinned
distributions where a build hook can import them, and `assert_no_extraneous`
requires the prepared set to be EXACTLY the pinned set. `build()` refuses to
run on the ambient interpreter.

The other half of D3 cannot be done in code: a process cannot deny its own
egress. The probe is widened from two endpoints to six across three
networks, and — the part that matters — the environment table carries
`network_enforcement`, always prefixed `asserted`, in the vocabulary D2 uses
for `device_binding`. Real enforcement is a namespace, a firewall or an air
gap; the debt is `build-egress-enforcement`.

**Documentary — `219/219` in the numbering rules, beside a correct
`295/295` in the status formula.** The third appearance of «правильный
текст рядом с устаревшим» in a document that names the defect in its own
crosscutting principles. `SYNC-8` did not see it because it matched one
phrasing, `N/M recorded`; a check narrowed to one phrasing polices one
sentence, not a document. It now checks every counter pair in normative
prose and exempts two classes as history: the blockquoted revision journal
and the drop table.

**New checks (5).** `REL-17` rebuild evidence resolves, validates and
agrees; `REL-18` both gates project the ledger and an absent reader refuses
rather than passing; `REL-19` the toolset position comes from the release
that names the manifest; `TSET-6` the manifest cannot date itself and the
resolved position is judged against the registry; `BLD-8` the build
environment is ephemeral and exactly the pinned set. `REL-16` is rewritten
rather than added — it now tests what the code does and asserts that the
tree claims nothing more anywhere else. Each was run against a mutation of
the fix it covers and went red.

Roadmap **r6.9.8** carries the counter, the two new debt positions and the
widened `SYNC-8`.

---

## v0.6.9 · recut 3 — the six P0 of the recut2 audit, and ADR-022 rev 2.3

Cut against the audit of `jjdai_v0_6_9-recut2.zip` (`2b062cd7…`), which
returned HOLD with six P0. Acceptance **300 → 304**. Two of the six could
not be closed by code at all and are closed by an ADR amendment taken while
the amendment is still free: nothing has been emitted — no tag, no release
keys, no `RELEASE_ATTESTED` record — and by this project's own rule the
schemas of window 6 are frozen before first emission, not before
implementation. After the ceremony the same change would be a migration.

**P0-1 — the evidence could be the statement itself.** This one was mine.
recut2 required the rebuild evidence to resolve and to be a
`ReleaseStatement` agreeing with this one; the audit handed it THE PRIMARY
STATEMENT, identical to itself in every compared field, and the comparison
passed trivially. Resolvability proved, independence not — the exact
substitution this drop has been audited for four times, committed by the fix
for the previous round of it.

ADR-022 rev 2.3 introduces `jjdai.rebuild-evidence/v1` with its own signing
domain `JJDAI:REBUILD:EVIDENCE:v1`. The object carries the run that produced
it, the verifier's key, device and principal, a host class, its own measured
environment table and its own outputs. It must resolve by hash, declare that
schema (so the statement can no longer be evidence about itself), name this
release, match the approval that names it, verify under that approval's
registered key, carry a `build_run_id` different from the builder's — and
still agree, byte for byte, on everything a rebuild reproduces.

**P0-2 — `reproducibility_scope` was self-declared.** The audit placed a tag
claiming `cross-host-class` with no fact about either host anywhere in the
release: the code accepted the stronger proof and the evidence did not offer
it. Every approval now carries `build_run_id` and `host_class`, and the scope
is DERIVED from the two and compared with the recorded value. Equal run ids
give `same-host`, which carries no release tag: one run signed twice is not
two builds, whatever the key count says. `host_class` remains a declaration,
and says so — the standing of `device_binding: "asserted"`, not more.

**P0-3 — the authorizer never reached the door.** `toolset_authorizer()` was
built, tested, and `kernel/isolation.py` called `load_verified_manifest`
without it. The third appearance in this drop of a checker standing beside
the boundary instead of being it. `WasmWasiProfile` now takes
`toolset_authorization` and forwards it; absent, a registry that records a
key lifecycle refuses, which is the fail-closed direction.

**P0-4 — two addresses for one manifest.** The assembler wrote
`toolset_manifest_hash` as sha256 of the FILE while the loader handed the
authorizer sha256 of JCS of the parsed document. For any formatted JSON
those differ, so the two sides addressed different objects and no real
manifest could ever have matched its release. There is one address now and
it is the bytes: `manifest_address(raw)`, with the raw bytes travelling from
the loader, and `authorization` without them refused rather than recomputed.

**P0-5 — an untaggable release could still authorize.** The lifecycle debt
blocked the tag and not the publication, so a `RELEASE_ATTESTED` record built
on editable registry positions already served as the authorization time of an
L2 mutation while the tag itself was refused. `release-key-lifecycle-
witnessing` now blocks `publication`, which is strictly stronger: no record,
no position to authorize at.

**P0-6 — the clean venv inherited a dirty environment.** `child =
dict(os.environ, …)` handed both build processes whatever the ambient shell
held; an external `PYTHONPATH` reached `python -m build` itself and could
replace the frontend the pins verify. The child environment is now built from
an allowlist, with the refused variables named individually so a reader sees
what was excluded rather than trusting that a list is complete.

**P1.** `release_annotation()` took the counted control as an argument and
printed 99 keys and 99 principals over a two-key release; it now verifies the
publication itself and counts what it prints. `architecture_status.json` still
described "exactly one directory preopened" against D9's zero. The isolation
docstring still explained a missing toolset as an unsigned manifest.
`manifest_signed` was hardcoded `False` even after a signature verified. The
toolset README claimed a debt position the ledger did not hold — the position
`toolset-module-path-toctou` now exists, because a claim about a register has
to be in the register to be true.

**New checks (4).** `REL-20` the evidence is a separate signed act by the
verifier over a different run; `REL-21` the scope is computed from the two
runs and compared; `TSET-7` the profile hands the resolver to the door;
`BLD-9` the child environment is built, not inherited. Roadmap **r6.9.9**
carries the counter, the new reserve entry and the moved boundary.

---

## v0.6.9 · recut 4 — the three blockers and four P1 of the recut3 audit

Cut against the audit of `jjdai_v0_6_9-recut3.zip` (`d128ae95…`), which
accepted the ADR-022 rev 2.3 model on substance and returned HOLD on three
boundaries that consume it. Acceptance **304 → 306**. No architectural
change; every fix is at a seam the audit named.

**Blocker 1 — authorization without evidence.** `toolset_authorizer()`
called `verify_publication` with whatever context it was given, and a
context with `evidence_reader=None` SKIPPED the evidence check: a
publication whose rebuild evidence did not exist yielded a callback
answering 0. Two fixes. The `continue` on an absent reader is now a refusal
— an approval names evidence, and a verifier who cannot read it has not
verified the approval. And the authorizer, being a permitting boundary, gets
the boundary's checks: `require_complete`, then the `publication` boundary
of the ledger — a CONSUMED publication is judged by the same ledger as a
produced one, or the debt blocks only the honest path — and only then the
verification. Diagnostic partial verification still exists; it no longer
hands out permissions.

**Blocker 2 — a permission that followed the dict.** The callback kept a
reference to the statement, so editing `toolset_manifest_hash` in the
publication after the callback was built changed what it permitted. It now
captures `expected` as a str and `index` as an int at creation; REL-22 edits
the publication afterwards and checks the permission did not move.

**Blocker 3 — the environment was cleaned one step too late.** recut3
cleaned the two build processes and left `python -m venv` and
`pip install --prefix` inheriting the shell; the audit's `PYTHONPATH` and
`PIP_CONFIG_FILE` reached both. There is now one way to start a process in
`build_release.py`, `_run()`, which begins from the allowlist, and BLD-9
counts `subprocess.run(` in the file: exactly one, inside `_run`.

**P1.** `validate_manifest(doc, raw=…)` accepted two different objects —
signature over `doc`, authorization for `raw` — and the file loader never
produced that pair, so the seam was the direct API's; `raw` is now parsed and
must canonicalise to `doc`. The assembler listed its own previous
`release-statement.json` as an artefact and then overwrote it; `artefacts()`
now excludes the named set `RELEASE_OUTPUTS`. The roadmap's window-6
separators, windows table, cut requirement and Audit 0 scope still named
rev 2.2 as current; synced. The isolation module docstring still said the
manifest was not signed in this build; it is, and the docstring says what is
and is not yet true. The assembler's comment still called the evidence a
statement; it is a `jjdai.rebuild-evidence/v1`.

**Handoff corrections, stated here so they are in the tree:** the recut3
handoff said "all six P1 closed" while listing the ceremony CLI as open,
and counted eight open debt positions where the projection holds ten —
`cla` and `t-toolset` are open and block their own boundaries.

**New checks (2).** `REL-22` a permitting callback needs the full context,
meets the publication boundary, and permits what was verified rather than
what the dict says later; `ASM-6` the assembler never lists its own
outputs. TSET-6 and BLD-9 extended for the doc/raw binding and the
single call site. Each new assertion was run against a mutation of the fix
it covers and went red. Roadmap **r6.9.10**.

---

## v0.6.9 · recut 5 — one test, no code

The audit of recut4 lifted the HOLD on the recut3 findings and left one
non-blocking P1: ASM-6 wrote `dist/evidence/aa.json` into the real tree and
removed it afterwards, so a file that existed before the check would have
been lost. A check that can destroy a file it did not create is a check with
a side effect. The fixture now lives in a TemporaryDirectory with `asm.ROOT`
swapped for its duration and asserts the swap was undone; the assembler is
unchanged. Acceptance stays **306/306**. Roadmap unchanged at r6.9.10 — a
test fixture is not a plan change.

---

## v0.6.9 · recut 6 — ADR-022 rev 2.4: the two debts of D6, paid in software

The audit of recut5 lifted the HOLD and corrected one sentence of the
handoff: "the next step lies outside the tree" was premature. Two ledger
positions — `release-key-lifecycle-witnessing` and
`release-revocation-by-name` — were software-and-normative debts; a
ceremony on hardware would not have closed them, and the order was the
reverse of the one written: decisions, code and acceptance first, then the
build and the release. The owner authorised ADR-022 rev 2.4, taken while the
amendment is still free — before the first `RELEASE_ATTESTED`, after which a
new record kind in a hash-linked chain is a migration. Acceptance
**306 → 307**.

**Window 6 gains three emittable record kinds** — `KEY_ACTIVATED`,
`KEY_REVOKED`, `RELEASE_REVOKED` — two hash-prefixes
(`JJDAI:RELEASE:KEYLIFECYCLE:v1`, `JJDAI:RELEASE:REVOKED:v1`), one signing
domain (`JJDAI:RELEASE:REVOKE:v1`) and one schema
(`jjdai.release-revocation/v1`). The chain refuses to write a lifecycle or
revocation record without a 64-hex `semantic_digest`: a bare `KEY_ACTIVATED`
is a position with nothing at it.

**Witnessed key lifecycle.** `check_lifecycle_witnessed`, third version,
and the first that does what its name says. recut1 promised to read the
record's pre-image and threw the record away; recut2 said so honestly and
checked only that the position was not past the end. Now every registry
position must resolve to a record of the declared kind whose digest is
`key_lifecycle_digest(key_id, transition, public)`. REL-16 replays the
original false green — six INFER records, a registry pointing at one — and
adds the cases that isolate each check: the right kind naming the wrong key,
the right key with the wrong transition, and the right DIGEST on the wrong
kind. The registry must say `lifecycle_binding: witnessed`; `asserted`, the
only honest value until today, is now a request to be believed where it
could be checked, and is refused. Position 0 on an empty chain is no longer
a convention: a key's activation is witnessed before the key signs
anything, so every fixture chain now opens with two activation records and
the first release of a node sits at index 2.

**Named release revocation.** `revoke_release()` writes a signed
`RevocationStatement` — checked under the registry key valid at that
position BEFORE the record is written — and a `RELEASE_REVOKED` record
binding the release by statement hash. `verify_publication`,
`check_release_tag` and `toolset_authorizer` refuse a revoked release as
`REL_REVOKED`; the attestation itself still verifies, because a revocation
is a later signed fact about a release, not an edit of it. A revocation
whose body is absent, mismatched, unregistered or unsigned by the key it
names refuses as `REL_REVOKED_UNRESOLVED` — an unverifiable revocation is a
revocation, because the alternative is a chain where the way to lift one is
to lose its body. REL-23 covers all of it, including a rogue record written
past `revoke_release()` straight into the chain.

**Ledger.** Both positions closed by `DEBT_CLOSED` with evidence
references. The publication boundary is clear; eight positions remain open,
six on the tag. `ReleaseContext` gains `revocation_reader` (twelve fields);
the assembler reads revocation bodies from `dist/revocations/`.

**Mutations.** Kind check, digest check, revocation signature check, the
revocation gate on the verification path, and the chain's refusal of a bare
lifecycle record — five, all red. Two of them were GREEN on the first pass
and exposed cases the tests had not isolated; those cases were added before
the round was called done. Roadmap **r6.9.11**.

---

## v0.6.9 · recut 7 — the five defects of the rev 2.4 mechanism

The audit of recut6 accepted the rev 2.4 step as necessary and in the right
place and returned HOLD on its mechanism: five defects in `jjdai/release.py`,
all reproduced, all confirmed against the tree, all closed here. Acceptance
**307 → 308**. The two `DEBT_CLOSED` events of recut6 stand — the ledger is
append-only and has no reopen event — and this entry records that the
evidence they cited was insufficient for one recut. The tests they cite now
cover what the audit reproduced.

1. **`revoke_release()` signed and appended without verifying.** The
   docstring promised verification under the registry key before the
   append; the body had `key_valid_at` and no signature check. A body
   signed by the verifier's key under `key_id="kb"` went into the
   append-only chain and, by the fail-closed rule, blocked the release
   forever. Now verified under the registered public key first; refusal
   writes nothing, and REL-23 asserts the chain length.
2. **A witnessed revocation could be hidden by the registry.**
   `check_lifecycle_witnessed` verified only the positions the registry
   presented, so `revoked: None` beside a real `KEY_REVOKED` record passed.
   `lifecycle_projection()` now reads every lifecycle record naming the key
   out of the chain and the registry must show the first activation and
   first revocation at those positions; omission or a later position
   substituted for the first refuses as `REL_LIFECYCLE_HIDDEN`. Releases
   before the revocation stay valid — history is not re-signed.
3. **The signed body was not checked against the target release.** A
   signed revocation of B under a record whose digest named A had A verify
   as revoked. Three values must agree now: the target statement, the
   body's `statement_hash`, and the record digest recomputed from the body.
4. **An authorizer outlived the revocation.** Currency was judged at
   creation; the callback compared only the stored hash. It now deep-copies
   the publication at creation — the caller's dict still cannot move it —
   and re-verifies that snapshot against the LIVE chain on every use.
5. **A revocation could land between the checks and the append.**
   `publish()` ran lifecycle and revocation checks before taking the chain
   lock. Both now run under the hold the record is written under, and
   `revoke_release()` judges key validity at the position its record
   actually takes. REL-24 observes the RLock from inside the checks.

**P1.** `witness.append`'s "64-hex" guard checked type and length;
`"z" * 64` passed. The alphabet is checked now.

**New check (1).** `REL-24`; REL-16 and REL-23 extended with the exact
scenarios the audit ran. Eight mutations, all red — one on the first pass
was green because the mutation duplicated the checks instead of moving
them; redone faithfully. Roadmap **r6.9.12**.

---

## v0.6.9 · recut 8 — integrity and lifecycle as PRECONDITIONS of a write

The audit of recut7 confirmed the five fixes and found two scenarios that
still put an inadmissible event into the append-only chain. Acceptance
stays **308/308**: both regressions extend `REL-24` rather than add a check.

1. **P0 — a revoked key could revoke a release.** `revoke_release()`
   verified the signature and judged the position, but `key_valid_at`
   reads the fields of the registry it is handed, and a stale registry
   saying `revoked: None` beside a real `KEY_REVOKED` record passed. The
   chain's own lifecycle projection is now checked against the registry
   under the hold, before the key is judged and before anything is written:
   a hidden revocation refuses as `REL_LIFECYCLE_HIDDEN`, a declared one as
   `REL_KEY_REVOKED`, an unwitnessed activation as
   `REL_LIFECYCLE_UNWITNESSED` — and the record count and the log size are
   asserted unchanged in each case.
2. **P1 — a publication was written into a chain that did not verify.**
   Detection worked one record too late for a history that cannot take a
   record back. `_chain_is_sound_or_refuse()` now runs under the hold in
   both `publish()` and `revoke_release()` before any other check: a chain
   whose hashes, links or node signatures are broken takes nothing.

Three mutations, all red. Roadmap **r6.9.13** (journal only).

---

## v0.6.9 · recut 9 — the repository's README, from the source

No code, no ADR, no roadmap change. The archive had shipped a 295-line
README placeholder since the tree was first packaged; the repository has
carried 676 lines of the owner's prose since v0.6.5, and under ADR-022 D12
the README is INSIDE the subject tree — which is right, and which means the
real file must travel from the build source rather than be restored on the
repository side over every cut. The owner's landing report put the choice
plainly: a real README at the source, or a branch whose digest never
matches the audited one. This is the first.

The prose was adapted to this tree by the repository side, with three
edits each forced by a check: the three generated blocks removed and §3
rewritten as a pointer to `docs/status_badge.md` (R-OWN-1; an empty §3 is
caught by R-OWN-5); "two-person release approval" no longer listed as open,
because the ledger projects it CANCELLED (R-OWN-5); the roadmap link moved
to r6.9.13 (SYNC-2). Independently reproduced here from a clean recut8
unpack: the patch applies, and after regeneration the tree converges to
**`7e4ca3d7…`** — the digest the landing report predicted. Acceptance
**308/308** twice in a row; evidence re-recorded against the new digest.

Also fixed in the landing procedure (`GIT-LANDING`, outside the tree): its
step 3 measured HEAD, not the worktree, inside a non-empty clone —
`digest(require_clean=False)` picks its source by the presence of `.git`.
The step now asks for the worktree digest explicitly.

---

## v0.6.9 · recut 10 — a probe of what is on disk names the worktree

Found by the repository side on the first git clone this tree has ever had
(`RECUT9-LANDING-REPORT.md`): steps 0–5 of the landing matched byte for
byte, and step 6 — acceptance in the clean clone — came back 306/308. The
two red checks, ACC-TREE-4 and EVID-1, edit a file in the REAL tree and
require the digest to notice. `source_digest()` lets D11 choose the source,
and inside a checkout that is the committed tree — which, correctly, does not
see an uncommitted edit or an untracked file. Green in every unpack, red in
every clone: the property those checks exist to prove was false wherever
`.git` was present, and this tree had been verified only from unpacks.

The right fix is in the two checks, not in the digest helper: forcing the
worktree source in `_tree_digest()` would make `hermetic.json` unable to say
`git-committed-tree` from a clean clone, which D11 and the landing procedure
require. `source_digest()` gains an explicit `source=`; both probes name
`SOURCE_WORKTREE` for what they edit on disk; and EVID-1 now states the other
half of D11 outright — inside a checkout, the committed-tree digest must NOT
move on an uncommitted edit, while the worktree digest must. Reproduced here
in a `git init` copy of the tree before the fix (two red) and after (green),
and the full suite is now verified from a clean unpack AND from a git
checkout. Two test files changed, no production code; acceptance stays
**308/308**; the landing procedure's step 4 loses a line that assumed an
empty repository.

**The second property, from the auditor's confirmation on recut9.** Fixing
the two probes was not enough: after editing the working copy the default
helper still answered the OLD digest under the `git-committed-tree` label —
a recorded run that would attribute tests executed on modified files to a
commit they did not come from. The committed label is now EARNED: inside a
checkout `_tree_digest()` computes both, and returns the committed digest
only when the worktree digest equals it; otherwise it returns what actually
executed, labelled `worktree`. EVID-1 states it — dirty checkout attributes
as worktree with a moved digest, restored checkout attributes as the commit
again — and a mutation removing the equality gate goes red. Verified in a
`git init` copy, not only in an unpack.

**README.** The auditor read the new prose against ADR-016: the deep form
of the append rule — organs lose their reference to the chain — was called
"the Ф3 form"; ADR-016 D2 and §4.2 place it in Ф2 (process separation), with
ledger and anchoring in Ф3. The sentence now says what the ADR says.

---

## v0.6.9 · recut 11 — one check stops measuring the room

The audit of recut10 accepted the attribution fix within the verified diff
and could not confirm "308/308 independently reproduced": ASM-5 failed on
the auditor's host. The check asserted that the AMBIENT host cannot build a
release context — true in the container it was written in (no git history,
network answering) and false on a host with a git checkout and a refusing
network, where the context builds and the check fails for no defect of the
tree. A check that depends on where it runs measures the room, not the
code. ASM-5 now stubs the network probe to answer and requires the D3 gate
to refuse on exactly that; verified on both host shapes (an unpack with the
network answering; a git checkout with the network refusing) and against a
mutation that makes the gate never refuse. One test file; production code
untouched; acceptance stays **308/308**.

Recorded here, outside the tree, for the landing procedure (now v5): the
post-regeneration digest check in step 6 read HEAD instead of the worktree
and must name `SOURCE_WORKTREE` and compare the full digest (the SBOM is in
the hashed set); the final push in a `git clone jjdai-land jjdai-clean` has
the local directory as origin and needs the GitHub remote set explicitly;
and the self-digest note was wrong in one detail — `duration_s` is covered
by the digest, `completed_at` is added after it is computed.
