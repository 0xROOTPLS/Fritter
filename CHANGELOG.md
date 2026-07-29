# Changelog

All notable changes to Fritter since the v1.0 public release. (*Categorized by area*)

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
