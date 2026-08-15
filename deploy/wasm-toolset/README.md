# wasm-wasi toolset

The `wasm-wasi` isolation profile (build v0.6.4) executes a **fixed set of
precompiled WebAssembly modules** under WASI. It does not execute arbitrary
argv, and that is the point of the profile rather than a limitation of the
implementation: a WASI module cannot express a system call the host did not
grant it, so the boundary is an allow-list enforced by the runtime instead of
a deny-list subtracted from the kernel.

## Host requirement

`wasmtime` must be present on the node as a **system binary** on PATH. The
codebase stays stdlib-only; the runtime is a declared host requirement and
enters the SBOM through the ordinary supply-chain stream (drop v0.6.7).

If `wasmtime` is absent, the profile **fails closed**: actions are refused,
never downgraded to the reference profile. The node declares the
unavailability in `capabilities()` so that work needing this boundary is not
routed to it.

## Adding a tool

1. Compile the tool to a WASI module (`*.wasm`) and place it in this
   directory.
2. Record it in `toolset.json`:

```json
{
  "schema": "jjdai.toolset/v1",
  "tools": {
    "wc": {"module": "wc.wasm", "sha256": "<sha256 of the module bytes>"}
  }
}
```

3. The digest is verified on **every** execution. A mismatch is a refusal,
   not a warning.

Adding a tool widens what the being's hand can do. Treat it as a capability
change, not a configuration change.
