# Function-Granular Dispatch — Design Proposal

**Status:** proposal / draft
**Date:** 2026-07-29
**Supersedes if adopted:** the VEH sliding window in `loader/veh_shim.c`

## Motivation

Fritter's loader currently protects itself with a page-granular scheme:
a vectored exception handler catches access violations on encrypted
pages, decrypts one page at a time, and re-encrypts pages as the
sliding window advances. This works, and MSVC builds run in ~0.4s.
Three costs scale together because they share one underlying event:

1. **Latency per page transition.** Each fault is a full kernel round
   trip (hardware exception → dispatch → user-mode handler →
   `VirtualProtect` → resume). ~100μs each on typical hardware. When a
   hot loop straddles a page, this is billions of iterations × 100μs =
   the multi-second execution time we see on gcc builds.

2. **A registered vectored handler.** `RtlAddVectoredExceptionHandler`
   links into ntdll's `LdrpVectorHandlerList`. Anything walking that
   list sees a handler pointing into a private RWX region — a static
   fingerprint at zero frequency.

3. **Traffic pattern.** Thousands of first-chance access violations
   plus continuous single-region `VirtualProtect` reprotection.

The gcc/MSVC 16× execution-time gap and the "loud on the machine"
observation are the same phenomenon at different granularities. One
design change can retire both.

## Model

**Unit of protection is the function, not the page.**

Cross-function calls route through a dispatcher. Each call edge
performs four crypt operations:

1. Encrypt the caller (in place, RWX region — no syscall)
2. Decrypt the callee
3. Callee runs
4. On return: encrypt callee, decrypt caller

**Exposure at any moment: exactly one function.** The rest of the
loader is ciphertext.

No exceptions raised. No handler registered. Memory protection is set
once at load (RWX) and never changes. XOR remains the crypto layer —
same as the sliding window; speed matters more than crypto strength
per the existing design target (per-output byte uniqueness, not
cryptographic resistance).

## Sizing measurements (MSVC seed=42, 2026-07-29)

Function sizes from per-function PE sections in the compiled `.obj`
files:

| Function                       | Bytes  | Role     |
|--------------------------------|-------:|----------|
| ansi2unicode                   |     39 | protect  |
| PEB-walk chain (avg of 5)      |   ~286 | protect  |
| FritterLoader                  |    310 | protect  |
| hash_cipher / maru (avg)       |   ~410 | protect  |
| aP_depack                      |    505 | protect  |
| block_cipher / fritter_encrypt |   ~600 | protect  |
| MainProc                       |    926 | protect  |
| Memcpy / Memset / Memcmp (avg) |   ~290 | resident |

Exposure per moment: **39–926 bytes** depending on which function is
running. Compared to today's fixed 4096-byte page: 4–10× less
plaintext at an arbitrary sampling moment.

## Residency policy

Not every function should be protected. The rule:

> Encrypt what's identifiable. Leave resident what's generic.

A byte-copy loop looks like every other byte-copy loop — no signature
value. Encrypting it costs speed (crypt on every call) and gains
nothing. So `Memcpy` / `Memset` / `Memcmp` stay resident.

Concretely: **anything currently tagged with `LOADER_FN_SECTION`
becomes a protected function.** `loader/clib.c` helpers stay resident.

### Why residency matters for hot loops

Under the current design, `maru`'s inner loop calling `Memset` in a
different page pays a page-fault pair per call: 1600 iterations ×
200μs ≈ 320ms.

Under function-granular dispatch with `Memset` resident: `maru` is
decrypted once on entry, runs its full inner loop against a resident
`Memset` (indirect call only, ~5ns), and is re-encrypted once on
return. 1600 × ~5ns ≈ 8μs. Roughly **40,000× faster** on this specific
case.

The gcc/MSVC gap collapses. Both compilers converge because
page-boundary layout luck no longer matters.

## Randomization axes

The current per-output / per-build split maps cleanly onto this
design.

### Per-output (fritter patches the blob at generation time)

- Per-function encryption keys, derived from a master
- Thunk-table ordering (Fisher-Yates, same shape as `gen_api_shuffle`)
- **Novel:** randomize the resident/protected partition per output.
  Two outputs of the same build protect different subsets of
  functions. A scanner learning "this family always has X in the
  clear" learns nothing transferable to the next sample.

### Per-build (`tools/gen_poly` at compile time)

Compile-time because these are baked into machine code:

- Thunk instruction form (call vs jmp-with-return, register choice)
- Junk sites within the thunk
- Dispatch table encoding (linear vs hashed vs computed-offset)

## Performance model

| Event                             | Current        | Proposed              |
|-----------------------------------|----------------|-----------------------|
| Per crypt event                   | ~100μs (fault) | <1μs (XOR only)       |
| maru → Memset hot loop (1600×)    | ~320ms         | ~8μs (Memset resident)|
| Cross-page loop in ANY function   | multi-second   | N/A                   |

## Open questions

Each needs an answer before implementation.

### Dispatch metadata: format and placement

Every call edge needs the callee address, key, and size. Options:

- **Fixed table** — simple, but its size and layout are a signature
  anchor.
- **Inlined at call site** — each call gets the metadata as immediate
  operands, patched by fritter at generation. Metadata disappears into
  the code stream.

`pack.h` already walks every REL32 and RIP-relative disp32 crossing a
section boundary and rewrites them. It could plausibly be repurposed
to rewrite these into thunk-with-inline-metadata sequences. Needs a
close read of `pack.h` before committing to this path.

### Concurrency

The current architecture has multiple threads live in the loader
region simultaneously (shim, host, MainProc — see the Site B writeup).
If Thread A has function X decrypted and Thread B tries to call
function Y that's also currently decrypted, ordering matters. Three
plausible answers:

- **Serialize** all cross-function dispatch through a lock. Simplest;
  probably fine since dispatch itself is fast.
- **Per-thread crypt state.** Each thread has its own currently-
  decrypted function. No lock, more RAM.
- **Refcount decryption.** Multiple concurrent runs of the same
  function share; different functions serialize on the crypt op.

### Recursion

A function that calls itself: the caller-encrypt step would re-encrypt
the function about to be entered. Needs either detection (skip the
crypt when caller == callee) or a stack of crypt states per thread.
Refcounting handles this cleanly.

### Indirect calls that bypass thunks

Function pointers handed to Windows APIs (TLS callbacks, thread start
routines, CRT continuations for the embedded PE) execute without going
through a dispatcher. Those either stay resident regardless of the
general policy, or need wrapper thunks that enter dispatch on their
behalf.

### pack.h reusability

Design assumes `pack.h`'s displacement rewriter can retarget
inter-function calls to a dispatcher. Confirm before committing — if
it can't, generator-side rewrite is a bigger lift.

### The current single-.text merge (orthogonal but relevant)

`loader_peb1.exe` currently has one `.text` section despite the
sources tagging per-function sections correctly in the `.obj` files.
The linker is merging them somewhere. Function-granular dispatch
doesn't strictly require per-function sections at runtime (it needs
function boundaries, which can come from `.obj` files directly or
debug info), but understanding this regression sharpens either path.

## What this replaces

If adopted, this retires:

- `loader/veh_shim.c` and its `.veh$z` placement work
- `RtlAddVectoredExceptionHandler` / `RtlRemoveVectoredExceptionHandler`
- `VirtualProtect` calls on loader pages
- Per-page master key + salt scheme
- The 1-page sliding window (all `SENTINEL_LOADER_*` machinery)
- Most layout-planning work in `pack.h`, unless repurposed for thunks
- The MSVC/gcc execution-time divergence

## What this preserves

- Per-output / per-build polymorphism approach and the generator tools
  (`gen_poly`, `gen_api_shuffle`)
- `LOADER_FN_SECTION` tagging — same tags mark what's protected
- Build pipeline: exe2h extraction, orchestrator-side blob building,
  format emitter
- `TheWover/Odzhan`'s PE→shellcode foundation (untouched under this
  design too)

## What comes next

Not implementation. The right next step is:

1. Read `pack.h` carefully to answer the reusability question
2. Enumerate all indirect-call sites (function pointers handed out to
   the OS) and decide their residency
3. Decide the concurrency model
4. Prototype in a branch — git is available now, experiments are safe

Estimated size: a several-week rework, not a weekend project. Broad
but shallow: touches loader, shim, exe2h, and `fritter.c`, but mostly
by replacing rather than editing.
