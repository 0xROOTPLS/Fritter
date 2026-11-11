# Changelog

All notable changes to Fritter since the v1.0 public release. (*Categorized by area*)

## v1.4

Major release. Three themes: what the shellcode looks like in memory while the payload runs, what is constant between outputs, and how many real-world payloads load correctly.

### In-memory footprint
v1.4 - **Loader mask.** While a payload of any type runs, the shim, the loader and the decrypted instance are encrypted and read/write. One stub page, generated per output, is the only executable page of the shellcode, and no page is writable and executable. About 13 KB of loader code used to stay readable, identical per build. Outputs grow by one page.
v1.4 - **Mask coverage.** Script-engine callbacks enter through per-output thunks on the stub page and nest on a small return stack; `WScript.Sleep` sleeps masked; the .NET runtime start, domain creation, assembly load and domain unload run masked, not only the invoke; the final block of `-x 3` is masked for .NET and script payloads too.
v1.4 - **Fallback.** A load that does not start on a page boundary is parked instead: instance pages read/write, code pages read/execute.
v1.4 - **Instance decrypted in place.** No second allocation, no copy, no ciphertext left behind; three API lookups before decryption are gone.
v1.4 - **Payload copies.** The payload file is wiped once the image is built (or the assembly or script handed over) and the compressed copy is destroyed after decompression, so the payload exists only as the running image.
v1.4 - **Payload image.** Mapped as one view per section, each with its final protection (Windows 10 1803+; single view kept as fallback), so the allocation protection is no longer RWX. Mapping, imports and views are three protected functions (all of `RunPE` used to stay readable).
v1.4 - **DLLs by payload type.** Only the DLLs and APIs a payload type calls are loaded and resolved: native loads nothing beyond kernel32/kernelbase/ntdll, .NET adds oleaut32, mscoree and shell32, scripts ole32 and oleaut32. Every payload used to pull ole32, oleaut32, mscoree and shell32 into the host.
v1.4 - **Exit path.** A generated exit stub tail-jumps into `VirtualProtect`; no executable page of the shellcode remains after a clean exit.
v1.4 - **Dispatcher keystream.** Protected sections are XORed with a 32-bit xorshift keystream, shift triple and direction per output, seed per section (was one key byte per section).
v1.4 - **N>1 per-function dispatch on gcc/mingw.** Linux builds emit the same per-section layout as MSVC; the MinGW slowness of v1.2 is gone.

### Per-output signature surface
v1.4 - **Outer decoder.** Shim and loader are encoded dword-wise with a 32-bit xorshift keystream, seed and shift triple compiled into the generated decoder (was a repeating 4/8/16-byte XOR whose key followed the stub). Stack-alignment prologue varies its alignment and frame size.
v1.4 - **Instance header.** Unused API-hash slots are random-filled and the unencrypted words are stored masked (44 bytes were identical in every output).
v1.4 - **Generated stubs.** The C++ exception stub and the exit stubs written into the payload image are generated per output and placed at a random offset (the former was a fixed 41-byte sequence).
v1.4 - **Output formats.** C, Ruby, Python, PowerShell and C# outputs draw their variable name and line width per output; Python output is a bytes literal; C# output is wrapped; `-f 4` emits Ruby (was C syntax).
v1.4 - **.NET AppDomain name.** The default is a pronounceable word of varying length (was 8 random characters); `-d` names are no longer truncated to 8.
v1.4 - **Result.** No 8-byte sequence is common to all outputs of a build or repeated inside one (`-e 1` excepted by design).

### Instance key and integrity
v1.4 - **`--key-brute <bits>`** (default 22). That many bits of the instance key are left out of the output and found by trial at load, about 0.1 s; `0` stores the key whole.
v1.4 - **`--key-host`, `--key-domain`, `--key-user`, `--key-env NAME=VALUE`.** Mix an environment variable of the target into the key. Elsewhere the instance cannot be decrypted and the shellcode returns to the host.
v1.4 - **Integrity.** One value covers the whole instance, configuration and module, encrypted or not (it covered one string). A per-build checksum is verified after decompression and the unpacker is bounded on input and output. A damaged output is refused instead of run.

### Native payloads (`RunPE`)
v1.4 - **Exceptions.** Unwind data is registered: SEH and GCC C++ exceptions work, and MSVC C++ exceptions work in statically linked (`/MT`) payloads. `/MD` payloads still cannot catch.
v1.4 - **Static CRT.** `/MT` payloads no longer abort at startup (the image view was copy-on-write).
v1.4 - **TLS.** TLS callbacks run (they were skipped). Payloads using static thread-local storage are rejected unless `-l <dll>` lends them the slot of a donor DLL or `-a` overrides (they silently used the host's TLS).
v1.4 - **Exit.** In every mode except `-x 2`, exit APIs resume the loader on its own thread, which cleans up and returns to the host, and end only the calling thread elsewhere. Covers `TerminateProcess` on the current process, `abort`, and exit functions looked up through `GetProcAddress`.
v1.4 - **`-b` / `--imagebase`.** The EXE becomes the process image while it runs, so `GetModuleHandle(NULL)` and resource lookups resolve to it (use with `-k 2`).
v1.4 - **Mapping.** Image relocated for the address it ends up at and rebased if that is taken; writable+executable sections stay executable; a missing import DLL or unresolved import aborts the load; DLLs without an entry point supported; relocation table bounds-checked; handles and buffers released on every path.
v1.4 - **Command line.** No patching with uninitialised strings when the kernelbase command-line variables are not found.

### .NET and scripts
v1.4 - **.NET runtime.** `CorBindToRuntime` fallback when the runtime is not loadable (NULL dereference), requesting the assembly's runtime version (was the oldest installed).
v1.4 - **.NET arguments.** `Main(string[] args)` receives an empty array without `-p` (was one empty string); argument strings are wiped and freed instead of left in the host heap; failed parsing or allocation is no longer dereferenced.
v1.4 - **VBS/JS.** Script buffer sized from the decompressed length (overflow).

### Decoy (`-j`)
v1.4 - The payload is checked against the decoy's mapped image size (was its file size, which could pass a decoy too small and write past it).
v1.4 - Only the pages the payload occupies are replaced; the rest of the decoy keeps the file's contents and protections (the whole image was zeroed). With `-k 1` the decoy's headers are restored at their own size.
v1.4 - A CFG-built decoy is skipped in a host that enforces CFG (the first callback into the payload ended the host). An over-long decoy path is rejected.

### `-y` / `--fork`
v1.4 - Fork APIs are resolved before `CreateThread` (two threads raced on the dispatcher), and the host entry point is resumed with the stack aligned as after a `CALL` (the host crashed on its first aligned SSE store).

### Command line and generator
v1.4 - **Options.** Long options match whole names only; a value starting with `-` is not parsed as a switch; over-long values and unknown switches are errors.
v1.4 - **Input checks.** PE headers, sections and export table bounds-checked; `mmap`, RNG, `fwrite` and `fclose` failures reported; double free on a failed build fixed.
v1.4 - **API resolution.** One pass over the loaded modules instead of one export walk per API; DLL-name, forwarder and ordinal bounds checked; the build fails when the API list exceeds the 64 instance slots.
v1.4 - **Maru.** Input scan bound raised from 64 to 1024 bytes (longer names were truncated before hashing).

### Loader and build internals
v1.4 - **Dispatcher.** Stack arguments 5-8 are forwarded to protected functions.
v1.4 - **Entry stub.** Decoder and trampoline use volatile registers only (RBX/RSI/RDI were clobbered).
v1.4 - **Cleanup.** The shim wipes exactly the loader bytes, including dispatcher and thunks, and is safe at unaligned bases; `VirtualFree` is called with `MEM_RELEASE` and size 0 (every free was failing); the instance is wiped on every failure path.
v1.4 - **`exe2h` and packer.** A failed pack fails the build instead of emitting an invalid blob; unknown opcodes, references leaving the code sections and too many code sections are fatal; fn/ref tables and the loader section count are validated by `fritter`.

### Removed
v1.4 - **HTTP staging (`-s` / `-n`).** The module is always embedded. ABI break: `server`, `auth`, `modname`, `inst_type` removed from `FRITTER_CONFIG`.
v1.4 - **Clipboard copy.** `-f 2` no longer copies the base64 text to the Windows clipboard.
v1.4 - `loader/veh_shim.c`, `/std:clatest`, 32-bit branches in the loader; `RunPE` rejects non-x64 images; `-g` hidden from help (still accepted).

### Tooling
v1.4 - **`inject64` test host** leaves target memory RWX (it was flipped to RX, which crashed every target).

## Function-granular dispatch (retires VEH)

v1.3 - The VEH-based sliding-window model has been replaced end-to-end by a function-granular dispatch system. Each protected loader function has its own PE section, XOR key, and dispatcher. The dispatcher decrypts on entry and wipes on return. No VEH handler, no per-page key material.

### Architectural retrofit
v1.3 - **`loader/dispatch_shim.c`** replaces `loader/veh_shim.c` in the PIC blob. Different semantics from prior.  
v1.3 - **N=1 v1 shipped** as the safety net. Single entry covers the entire loader with one XOR key.  
v1.3 - **N>1 per-function dispatch shipped for MSVC.** Each hot routine is emitted into its own thunk + dispatcher pair. `MainProcEntry` wrapper added for `MainProc`.  
v1.3 - **`exe2h` emits `fn_table` + `ref_table` companion headers** for per-function metadata and cross-function references.  
v1.3 - **MSVC/gcc runtime parity achieved.** The prior VEH cross-page fault penalty on MSVC is gone. (gcc still runs N=1 due to single-`.text` limitation.)  
v1.3 - **`-g` / `--chunked` flag is deprecated.** Retained for CLI compatibility, no effect.

### Dispatcher polymorphism
Per-build variation of the emitted dispatcher opcodes. No fixed byte sequence longer than a few bytes remains in the dispatcher.

v1.3 - **fn_table marker scramble.** The build-time marker used to locate the table is scrambled after patching.  
v1.3 - **Thunk mov ordering randomized per call site.** The two setup `mov`s before the dispatcher call are emitted in either order.  
v1.3 - **Pre-dispatcher random padding.** 0-63 bytes of true-random NOPs precede each dispatcher.  
v1.3 - **r10/r11 semantic swap per build.** The two volatile scratch registers used in the thunk-to-dispatcher handoff swap roles per build.  
v1.3 - **Dispatcher push/pop shuffle.** The nonvolatile-register save/restore order in each dispatcher's prologue/epilogue is Fisher-Yates permuted per build.  
v1.3 - **Prologue/epilogue junk NOPs.** True-random NOPs inserted between every push and every pop.  
v1.3 - **True-random dispatcher junk pool.** The prior fixed 4-entry pool replaced with `emit_rnd_nop`, which sources `0F 1F /r` disp bytes from `CryptGenRandom`.  
v1.3 - **True-random loader-entry prefix.** The 14-entry `pfx_pool` at the loader entry replaced with the same true-random NOP emitter.  
v1.3 - **XOR loop shape variation.** The per-function decrypt/encrypt loop varies across three axes: helper register, direction, and loop shape. Junk-NOP gaps at 4 sites, 50% skip.  
v1.3 - **Address-based termination as XOR shape variant.** Alternative loop termination chosen per-build.  
v1.3 - **Middle-section junk at instruction boundaries.** `EMIT_JUNK()` sites at every safe instruction boundary through the dispatcher middle-section, each emitting 0 or 1 true-random NOPs.  
v1.3 - **Nonvolatile state register rotation.** The four dispatcher state roles (PTR, OFFSET, SIZE, KEY) are Fisher-Yates permuted across `{r12, r13, r14, r15}` per build.

## Per-output polymorphism - module-by-module deep dive

v1.1 - A 5 module audit and rewrite of every randomized region in the generated PIC. Each module was validated by deterministic seed smoke tests with manual injection runs (Default is non-deterministic).

### Entry stub
v1.1 - Junk fallthrough prefix replaced the previous `EB <len>` jump->skip->junk pattern. Multi-byte safe instruction pool used (NOPs, flag ops, register-form NOPs, `xchg rax,rax`); random target length;. Resulting in no fixed opcode at offset 0.  
v1.1 - Generative RSP alignment routine replaced the three fixed templates. Save-register chosen from a pool, save-form (mov vs lea) and restore-form chosen independently, junk in both prologue and epilogue. CALL displacement computed dynamically from emitted epilogue size.  
v1.1 - Generative decoder shim trampoline replaced the fixed `48 8D 15 ?? ?? ?? ?? E9 ?? ?? ?? ??` byte pattern. Target-register pool, optional MOV-RDX-from-target, junk slots, choice between rel32 JMP and indirect `FF E2`.

### Poly XOR decoder
v1.1 - Variable key length picked per output from a small set, propagated to: AND-mask immediate, JMP-SHORT skip immediate, trailing key byte count, AND host-side XOR encode mask. (collapses three previously-fixed anchors (`AND ?? 07`, `EB 08`, fixed-len key tail)).  
v1.1 - The movable instruction groups in the decode loop are emitted in one of three valid orderings now (Remedies the canonical fixed opcode chain in the loop body)  
v1.1 - Zero init opcode swap for the key-index initialization (XOR vs SUB).  
v1.1 - Leading junk before the `push rcx` so byte 0 of the decoder stub is no longer always `0x51`.  
v1.1 - Junk between `pop rcx` and the `EB` skip-jump to break the canonical 3-byte sequence.  

### VEH shim
v1.1 - Per-build string scrambling of the stack built API/DLL strings & now key is forced into a range that avoids zero-byte collisions with printable ASCII.  
v1.1 - Per-build PEB list pick for the shim's DLL resolution. (should have been v1, missed)  
v1.1 - Salt site placement diversification fixed. The previous 'volatile-temp-then-discard' was replaced with XOR-cancel pairs against existing volatile struct fields. Now will appear as immediate operands in real load/store sequences.

### Loader
v1.1 - Per-build wipe byte for the post-execution `Memset` of the instance, replacing zeroing.  
v1.1 - Per-build PEB walk direction randomized to either be flink or blink.  
v1.1 - Structural salt sites in `MainProc` changed to XOR-cancel pairs against volatile mirrors of `inst->len` and `inst->api_cnt`, gated on per-build salt bits, placing per-build immediate operands into the live execution path.  
v1.1 - GET_PEB hardcoded to a TEB-indirect varient instead of the canonical `gs:[0x60]`.  
v1.1 - **Banner correction**: previous "ChaCha20" claim was inaccurate. The cipher is *similar to ChaCha* but not exact. Banner now reflects this.  
v1.2 - **Per-function PE sections for hot routines.** `hash_cipher`, `maru`, `block_cipher`, `fritter_encrypt`, `MainProc`, `ansi2unicode`, and `aP_depack` are now placed in their own named PE sections via a new `LOADER_FN_SECTION` macro (`__declspec(code_seg)` under MSVC; no-op under MinGW). Each section is small enough to fit on a single page so the hot inner loops no longer straddle a page boundary inside the VEH sliding window. `FritterLoader` is pinned to `.text$a` so it remains at blob offset 0 after extraction.

### Cleanup
v1.1 - Per-build wipe byte for the shim's loader-page wipe loop instead of just zeroing.  
v1.1 - Per-build VEH context scrub pattern has been updated. The `g_ctx` struct fields are scrubbed with a per-build value pattern derived from the wipe byte, replicated to each field's width. Pointer fields scrub to non-zero..  
v1.1 - The 6 `g_ctx` fields are scrubbed in one of four fixed orderings, picked from per-build salt bits.  
v1.2 - **Loader blob NOP-fill eliminated.** The previous single-section extractor produced a loader.bin with ~46% of its bytes as `0x90` NOP sleds (longest contiguous run 3750 bytes) - linker padding between page-aligned `__declspec(code_seg)` sections that the extractor preserved. The new pack-on-extract path concatenates sections back to back, dropping loader.bin from ~25 KB to ~13.5 KB and the longest NOP run from 3750 to 1. Removes a large fixed-pattern YARA anchor.  
v1.2 - **Deterministic-random fallback fill.** When the packer cannot apply (single-section loader, e.g. the default MinGW path), the RVA-preserving fallback now fills inter-section gaps with deterministic-LCG random bytes instead of `0x90`. Defence-in-depth - covers both extractor paths uniformly.  

## Per-build polymorphism infrastructure

Per-build axes are emitted by two -new- build-time tools and consumed by the source via `__has_include`-guarded includes plus X-macro expansion.

v1.1 - **`tools/gen_poly`** - emits `include/poly_seed.h` with cipher rotation constants, hash rotation constants, round counts, multi-purpose 32-bit salt values, wipe bytes, PEB walk direction picks, string-scrambling keys, and so on. Seeded by `FRITTER_BUILD_SEED` env (or time-mixed default for fresh randomization on every `make`).  
v1.1 - **`tools/gen_api_shuffle`** - reads a canonical API list (`include/api_master.h`, an X-macro file) and emits a per-build Fisher-Yates-shuffled version (`include/api_shuffle.h`). Slot 0 is pinned. Both `fritter.h` (the typed function-pointer view) and `fritter.c` (the API hash table) expand the same shuffled X-macro list, so the typed view and the hash array are guaranteed to stay in lockstep by construction.  
v1.1 - **`FRITTER_BUILD_SEED` environment variable** - set to a 32-bit value for reproducible builds; **omit for fresh per-make randomization.**  
v1.1 - **All three Makefiles** updated to build and run the generators before any compile step.  
v1.2 - **Multi-section `exe2h` with pack-on-extract.** The extractor now walks every `IMAGE_SCN_CNT_CODE` section in the loader exe, brute-force searches permutations of section ordering for a layout where every `single_page`-marked hot section sits entirely within one 4096-byte page in the output blob, then rewrites every cross-section CALL / JMP / Jcc / LEA REL32 displacement via an in-tree x86-64 length disassembler. Adjacent sections are concatenated with no gap, eliminating linker-inserted alignment padding from the blob entirely.  
v1.2 - **`loader/exe2h/pack.h`** (new ~330-line file) - LDE opcode tables, `pack_search` / `pack_apply` / `pack_extract` pipeline, deterministic-LCG random-fill helper.  

## Cross-platform build

v1.1 - **Linux static-musl ELF cross-compile.** New `Makefile.linux` produces a self-contained `fritter` ELF binary on Linux with no runtime libc dependency, using `musl-gcc` for the orchestrator and `mingw-w64` for the Windows-side loader/shim payload. `lib/aplib_linux64.a` provides the aPLib decompression interface. The orchestrator runs on any modern x86_64 Linux distro without further setup.  
v1.1 - **Reproducible builds** via `FRITTER_BUILD_SEED`. Output bytes are deterministic given a fixed seed, modulo `__DATE__` / `__TIME__` macro expansions still present in source (couldn't be bothered).

## Bug fixes

A 9-module audit produced a list of user-facing bugs that were addressed:

v1.1 - **`-y` / `--fork` crash** in the loader's `FritterLoader` path - `_GetModuleHandleA` was used before being resolved. Resolution moved before first use.  
v1.1 - **`Makefile.msvc` cleanup** - dropped a stale reference to a long-removed `order.txt` file.  
v1.1 - **`#pragma section` on MSVC** - the shim's `.text`-placed VEH context struct was missing the MSVC section pragma; now correctly placed via `#pragma section` + `__declspec(allocate)`, with the GCC `__attribute__((section, used))` form preserved on the other branch.  
v1.1 - **`format.c` clipboard rewrite** - five distinct issues in the clipboard output path were fixed in one pass (handle leak, missing global lock release, wrong format constant, mis-sized allocation, return-value ignored).  
v1.1 - **`format.c` Python template typo** - `buf` vs `buff` inconsistency leading to a generated Python module that wouldn't run.  
v1.1 - **Hash-loop bounds check** in `fritter.c` - could read one element past the array end on certain inputs.  
v1.1 - **`main()` exit code** - returned 0 on error paths; now returns 1.  
v1.1 - **`validate_format` UUID case-handling** - accepted only lowercase hex; now case-insensitive.  
v1.1 - **`gen_random` short-read loop** - single-read could return fewer bytes than requested without retry; now loops until full request satisfied.  
v1.1 - **API table swap** - pre-existing `InternetCloseHandle` / `InternetQueryDataAvailable` slot swap in the HTTP staging path was fixed as a side effect of consolidating the API list into a single source-of-truth X-macro file.  
v1.1 - **Trampoline displacement coupling** - when the decoder -> shim trampoline became variable-size, the decoder's RIP-relative displacement to the encode  d data still used the old hardcoded constant. Fixed; now derived from the actual emitted trampoline size.  
v1.2 - **MSVC shim cross-page-loop fault storm.** MSVC builds were producing shellcode that ran an order of magnitude slower than expected. Root cause: hot loops in `block_cipher` / `hash_cipher` straddled a page boundary inside the loader's default `.text`, so the VEH sliding window faulted on every loop iteration during instance decrypt and API hash. Resolved by the per-function PE section system + multi-section `exe2h`; each hot routine now sits within its own single-page section. 1-page residual RWX exposure budget preserved.

## Known caveats

v1.1 - `volatile` on auto-storage-duration local variables is not a 100% reliable barrier under -O1 with mingw-w64 GCC. The compiler may place the variable in a register, where the "memory" loads/stores become register reads/writes and the optimizer may fold a salt-XOR-cancel pair. New salt-cancel sites should target variables that are **used downstream** (forces stack spill in functions with high register pressure) and should be validated with deterministic-seed smoke runs covering enough combinations to expose any latent fold.  
v1.1 - Compression fallback when aPLib doesn't help is deferred. Builds where the input is incompressible may produce slightly larger shellcode than necessary.  
v1.1 - `__DATE__` / `__TIME__` are still present in the orchestrator source. Reproducible builds require a fixed timezone in the build environment, or a future cleanup that removes the macros.  
v1.2 - **MinGW build runtime is ~10x slower than MSVC.** Seed-controlled measurement on the bundled calc.exe target: MSVC ~0.6s vs MinGW ~5-7s. Root cause is cross-page hot loops in *untagged* code (`RunPE`, `LoadAssembly`, et al.) inside default `.text` - the per-function-section system covers the explicitly-tagged hash/cipher routines but not the untagged PE-loader machinery, and MinGW's layout of that machinery happens to place hot loops on page boundaries where MSVC's layout doesn't. Both lanes produce OPSEC-equivalent output (no NOP fill on either side); MSVC is the recommended fast lane.
v1.4 - The v1.2 MinGW runtime caveat above no longer applies: gcc builds use the same per-function layout as MSVC.
v1.4 - The shellcode still decodes itself in place, so the memory it is given must be writable and executable.
v1.4 - With `-j`, the loader thread's return address points at the stub page, which is private memory; without a decoy the payload image itself is not file-backed.
v1.4 - Under the loader mask, a script host method called from a second thread while the first is inside one is not supported.
v1.4 - `-e 1` outputs share about 20 KB: the instance is unencrypted by design.
v1.4 - An undecryptable or damaged output generated with `-x 2` still ends the host process.
