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
