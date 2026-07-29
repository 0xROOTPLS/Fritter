# Function-Granular Dispatch — Prototype

Standalone proof-of-concept for the design in
[`../function_granular_dispatch.md`](../function_granular_dispatch.md).
Demonstrates the four-crypt-op cycle in isolation, without touching the
real loader.

## What it does

Two "protected" functions live in the harness's `.text`:

- `proto_fn_A(x)` — calls `proto_fn_B(x+1)` via `dispatch()`
- `proto_fn_B(x)` — returns `x * 2` (leaf, no dispatch calls)

At startup: the pages containing both functions are marked RWX, then
each function's bytes are XOR-encrypted in place. From that point on
neither is directly callable — every invocation goes through
`dispatch(caller_id, callee_id, arg)`, which performs:

1. **Encrypt caller** in place
2. **Decrypt callee** in place
3. **Call callee**
4. **Encrypt callee, decrypt caller**

Between calls only one function is plaintext at a time. The harness
tracks the maximum concurrent-plaintext count across the whole run
and reports it — the invariant `max == 1` is what the prototype
proves.

No VEH is registered. No `VirtualProtect` is called during dispatch
(only once at startup, which the real loader replaces with
`VirtualAlloc(..., PAGE_EXECUTE_READWRITE)`). No exceptions raised.

## Build

**MSVC** (from a vcvars64 prompt):

    cl /Od /nologo dispatch_proto.c

**gcc/mingw** (from WSL):

    x86_64-w64-mingw32-gcc -O0 -fno-toplevel-reorder dispatch_proto.c \
      -o dispatch_proto_gcc.exe

`/Od` and `-O0 -fno-toplevel-reorder` preserve source-order function
layout so the harness can compute function sizes as
`(next_fn_addr - this_fn_addr)`. A production integration would use
the compiled `.obj` section table (which the `LOADER_FN_SECTION`
mechanism produces) instead, but source-order works for a two-function
prototype.

## Expected output

    === Function-Granular Dispatch Prototype ===
    ...
      dispatch(caller=(none) callee=A arg=5)
        [entry                 ]  fn_A=cipher  fn_B=cipher
        [after decrypt-callee  ]  fn_A=PLAIN   fn_B=cipher
      dispatch(caller=A callee=B arg=6)
        [entry                 ]  fn_A=PLAIN   fn_B=cipher
        [after encrypt-caller  ]  fn_A=cipher  fn_B=cipher
        [after decrypt-callee  ]  fn_A=cipher  fn_B=PLAIN
        [after callee returns  ]  fn_A=cipher  fn_B=PLAIN
        [after re-encrypt      ]  fn_A=PLAIN   fn_B=cipher
        [after callee returns  ]  fn_A=PLAIN   fn_B=cipher
        [after re-encrypt      ]  fn_A=cipher  fn_B=cipher

    Return value:                 12 (expected 12)
    Max concurrent plaintext:     1 function(s) (expected 1)
    Final state:                  fn_A=cipher fn_B=cipher
    PASS

Both toolchains produce identical trace behavior; only the function
sizes differ (gcc emits tighter code than MSVC's `/Od`).

## Measured (2026-07-29)

| Toolchain | fn_A bytes | fn_B bytes | Result |
|-----------|-----------:|-----------:|--------|
| MSVC 14.44 (/Od)        | 48 | 32 | PASS |
| gcc mingw-w64 (-O0)     | 41 | 14 | PASS |

## What this does NOT demonstrate

Everything the design doc's "Open questions" section names is out of
scope:

- **Copy-and-fixup** (RIP-relative displacements when the code is
  relocated). Prototype sidesteps by keeping functions at their
  `.text` addresses. Real loader delivery uses `pack.h`'s displacement
  rewriter or an equivalent.
- **Concurrency** across the three loader threads (shim, host,
  MainProc). Prototype is single-threaded.
- **Recursion.** Same reason — the two functions don't call
  themselves.
- **Indirect calls that bypass thunks** (TLS callbacks, thread starts,
  CRT continuations for the embedded PE). None here.
- **Per-output / per-build randomization axes.** Fixed keys, fixed
  function layout.
- **Metadata inlining** at call sites. Prototype uses a plain global
  table.
- **Performance measurement.** Left for phase 2 with real loader
  functions; the design-doc numbers (`<1μs` per crypt event, ~40,000×
  win on maru→Memset) are estimates awaiting confirmation.

Any of those can invalidate the mechanics — the prototype's PASS says
only that the four-op cycle itself is sound and that the exposure
invariant holds under it. Phase 2 (real-loader integration) has to
solve the rest.
