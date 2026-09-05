# wasm toolset — recipes in git, modules in the signed release bundle

ADR-022 D7, D8, D9.

## What lives here

* `recipe/<tool>.json` — how a module is built: upstream by commit and
  source archive sha256, build environment by digest, the build command
  verbatim, the expected sha256 of the output. Format
  `jjdai.toolset-recipe/v1`.
* `toolset-manifest.json` — the **immutable, signed** manifest
  (`jjdai.toolset-manifest/v2`): which tools, which effect class, which
  expected hashes, which limits, which authorization form. Signed under
  `JJDAI:TOOLSET:MANIFEST:v1` by a key of ADR-017 domain
  `toolset_authorization`.

## What does NOT live here

**Built `.wasm` modules.** They travel in the release bundle, signed with
the release, and `bundle_hash` sits in the `ReleaseStatement`. A production
node receives the signed bundle, checks hashes and executes — it does not
compile and does not reach upstream. Otherwise every node grows a compiler
and a supply-chain surface of its own, and one provenance problem is solved
by creating a second.

The pre-v0.6.9 text of this file said the opposite: it told operators to
compile or drop a module on the node. That instruction is withdrawn.

## Two files, one of them trusted

`toolset-materialization.json` is local and unsigned: what is actually
installed here. The loader hashes the **real bytes** of a module and
compares them with the **manifest**. A disagreement is a refusal, never an
auto-reinstall — trusting the materialization's hash would mean the signed
manifest is bypassed by editing an unsigned file.

## The `pure` class

Every tool declares an effect class and the starter set is entirely `pure`,
which in this build is a boundary and not a description:

* zero preopen directories, read or write;
* WASI imports checked against an allowlist — `fd_read`, `fd_write`,
  `proc_exit` — **on the module's bytes, at instantiation**, not when a call
  is reached;
* clocks and entropy denied;
* empty `environ`, fixed `argv` and locale;
* fuel, memory and output limits per tool, each breach a named refusal with
  no output.

A module linked against full `wasi-libc` imports more than the allowlist and
will not instantiate. The starter set must be built against a narrowed
target; whether the chosen toolchain gives that **and** a byte-for-byte
repeat is ADR-022 O-3, answered by building on a host.

## Known limit, stated rather than left to be found

Between hashing a module and executing it the runtime re-opens the file **by
path**, so a sufficiently privileged local attacker can swap it in between.
Closing this needs execution against the descriptor that was hashed, which
the wasmtime CLI seam does not offer. Recorded as debt rather than implied — the position is
`toolset-module-path-toctou` in `docs/architecture_status.json`, which
is where a claim of this kind has to be to be true
away.

## Without a key registry this profile is unavailable

The manifest sanctions an L2 mutation — the widening of a being's hand — so
with no way to resolve its signing key it is not accepted. That is the state
of every node in this tree today, and it is the honest one: an object that
looks signed is not a signature.
