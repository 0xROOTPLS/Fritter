/* dispatch_proto.c, function-granular dispatch prototype
 *
 * See docs/design/function_granular_dispatch.md for the full design.
 * This file demonstrates the four-crypt-op cycle in isolation:
 *
 *   dispatch(caller_id, callee_id, arg):
 *     1. encrypt caller  (in place, XOR)
 *     2. decrypt callee
 *     3. call callee
 *     4. encrypt callee, decrypt caller
 *     return callee's result
 *
 * Invariant: exactly one function is plaintext at any moment.
 * No VEH, no VirtualProtect at runtime (one-time RWX marking at
 * startup only), no exceptions raised.
 *
 * Scope: proves the mechanics. Out of scope: integration into the
 * loader, concurrency across the three loader threads, recursion,
 * indirect calls that bypass thunks, PIC delivery / displacement
 * fixups (pack.h's problem, orthogonal to the cycle).
 *
 * Approach: functions stay at their .text addresses (avoids the
 * copy-and-fixup problem, since relative calls remain valid). A
 * one-time VirtualProtect at startup marks the containing pages
 * RWX so XOR-in-place works. The real loader will run in an RWX
 * region by construction (VirtualAlloc), so this is not a delivery
 * simplification that hides a real cost.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

#ifdef _MSC_VER
#  define NOINLINE __declspec(noinline)
#else
#  define NOINLINE __attribute__((noinline))
#endif

#define FN_ID_A     0
#define FN_ID_B     1
#define FN_ID_MAX   2
#define FN_ID_NONE  0xFFFFu

typedef struct {
    uint8_t *base;
    size_t   size;
    uint8_t  key;
    uint8_t  first_pt;  /* first plaintext byte, for exposure verification */
} fn_meta_t;

static fn_meta_t g_fns[FN_ID_MAX];

/* dispatch lives in the harness's regular .text, never crypted. */
static NOINLINE uint32_t dispatch(uint16_t caller_id, uint16_t callee_id, uint32_t arg);

/* -------- Protected functions --------
 * Must appear in source order (A, B, sentinel) so setup can compute
 * sizes as (next - this). Build flags below enforce ordering. */

static NOINLINE uint32_t proto_fn_A(uint32_t x);
static NOINLINE uint32_t proto_fn_B(uint32_t x);
static NOINLINE void     proto_fn_end_sentinel(void);

static NOINLINE uint32_t proto_fn_A(uint32_t x) {
    /* Enters dispatch to invoke fn_B(x+1). While B runs, A is
     * ciphertext (including the return address inside A). Dispatch
     * decrypts A before returning here. */
    return dispatch(FN_ID_A, FN_ID_B, x + 1);
}

static NOINLINE uint32_t proto_fn_B(uint32_t x) {
    return x * 2;
}

static NOINLINE void proto_fn_end_sentinel(void) {
    /* Boundary marker for computing proto_fn_B's size. */
}

/* -------- Crypt primitive -------- */

static void xor_region(uint8_t *base, size_t size, uint8_t key) {
    for (size_t i = 0; i < size; i++) base[i] ^= key;
}

/* -------- Exposure verification --------
 * Cheap check: if first byte matches recorded plaintext value, we're
 * plaintext; otherwise ciphertext. Keys are non-zero so the two
 * states differ deterministically. */

static void report_exposure(const char *step) {
    printf("    [%-22s]", step);
    for (int i = 0; i < FN_ID_MAX; i++) {
        int is_pt = (g_fns[i].base[0] == g_fns[i].first_pt);
        printf("  fn_%c=%s", 'A' + i, is_pt ? "PLAIN " : "cipher");
    }
    printf("\n");
}

/* Count how many functions are currently plaintext. Should be 0 or 1. */
static int count_plaintext(void) {
    int n = 0;
    for (int i = 0; i < FN_ID_MAX; i++)
        if (g_fns[i].base[0] == g_fns[i].first_pt) n++;
    return n;
}

/* -------- Dispatcher -------- */

static int g_max_concurrent_plain = 0;

static NOINLINE uint32_t dispatch(uint16_t caller_id, uint16_t callee_id, uint32_t arg) {
    typedef uint32_t (*fn_t)(uint32_t);
    uint32_t result;

    printf("  dispatch(caller=%s callee=%c arg=%u)\n",
           caller_id == FN_ID_NONE ? "(none)" :
             (caller_id == FN_ID_A ? "A" : "B"),
           'A' + callee_id, arg);

    report_exposure("entry");

    /* Step 1, encrypt caller. */
    if (caller_id != FN_ID_NONE) {
        xor_region(g_fns[caller_id].base, g_fns[caller_id].size,
                   g_fns[caller_id].key);
        report_exposure("after encrypt-caller");
    }

    /* Step 2, decrypt callee. */
    xor_region(g_fns[callee_id].base, g_fns[callee_id].size,
               g_fns[callee_id].key);
    report_exposure("after decrypt-callee");

    /* Track peak exposure across the whole run (must never exceed 1). */
    {
        int n = count_plaintext();
        if (n > g_max_concurrent_plain) g_max_concurrent_plain = n;
    }

    /* Step 3, call the callee. */
    fn_t callee_fn = (fn_t)g_fns[callee_id].base;
    result = callee_fn(arg);
    report_exposure("after callee returns");

    /* Step 4, encrypt callee, decrypt caller. */
    xor_region(g_fns[callee_id].base, g_fns[callee_id].size,
               g_fns[callee_id].key);
    if (caller_id != FN_ID_NONE) {
        xor_region(g_fns[caller_id].base, g_fns[caller_id].size,
                   g_fns[caller_id].key);
    }
    report_exposure("after re-encrypt");

    return result;
}

/* -------- Setup -------- */

static int setup_function(int id, void *fn_start, void *fn_end, uint8_t key) {
    size_t size = (uintptr_t)fn_end - (uintptr_t)fn_start;
    if ((intptr_t)size <= 0 || size > 0x1000) {
        fprintf(stderr, "unexpected size for fn_%c: %zd\n", 'A' + id, (intptr_t)size);
        return -1;
    }

    g_fns[id].base     = (uint8_t*)fn_start;
    g_fns[id].size     = size;
    g_fns[id].key      = key;
    g_fns[id].first_pt = ((uint8_t*)fn_start)[0];

    printf("fn_%c: %4zu bytes at %p, first plaintext byte 0x%02X, key 0x%02X\n",
           'A' + id, size, fn_start, g_fns[id].first_pt, key);

    xor_region(g_fns[id].base, g_fns[id].size, g_fns[id].key);
    return 0;
}

static int make_rwx(void *start, void *end) {
    uintptr_t page_size = 0x1000;
    uintptr_t base = (uintptr_t)start & ~(page_size - 1);
    uintptr_t top  = ((uintptr_t)end + page_size - 1) & ~(page_size - 1);
    DWORD old;
    if (!VirtualProtect((void*)base, top - base, PAGE_EXECUTE_READWRITE, &old)) {
        fprintf(stderr, "VirtualProtect failed: %lu\n", (unsigned long)GetLastError());
        return -1;
    }
    printf("Made 0x%llX..0x%llX RWX (was 0x%08lX)\n",
           (unsigned long long)base, (unsigned long long)top, (unsigned long)old);
    return 0;
}

int main(void) {
    printf("=== Function-Granular Dispatch Prototype ===\n\n");
    printf("proto_fn_A: %p\n", (void*)(uintptr_t)proto_fn_A);
    printf("proto_fn_B: %p\n", (void*)(uintptr_t)proto_fn_B);
    printf("sentinel:   %p\n\n", (void*)(uintptr_t)proto_fn_end_sentinel);

    if (make_rwx((void*)proto_fn_A, (void*)proto_fn_end_sentinel) < 0)
        return 1;

    printf("\nSetup (functions encrypted in place):\n");
    if (setup_function(FN_ID_A, (void*)proto_fn_A, (void*)proto_fn_B, 0xA5) < 0)
        return 1;
    if (setup_function(FN_ID_B, (void*)proto_fn_B, (void*)proto_fn_end_sentinel, 0x5A) < 0)
        return 1;

    printf("\nInvoking dispatch (initial entry to fn_A with arg=5):\n\n");
    uint32_t result = dispatch(FN_ID_NONE, FN_ID_A, 5);

    printf("\n--- Results ---\n");
    printf("Return value:                 %u (expected 12)\n", result);
    printf("Max concurrent plaintext:     %d function(s) (expected 1)\n",
           g_max_concurrent_plain);
    printf("Final state:                  fn_A=%s fn_B=%s (expected cipher, cipher)\n",
           g_fns[0].base[0] == g_fns[0].first_pt ? "PLAIN" : "cipher",
           g_fns[1].base[0] == g_fns[1].first_pt ? "PLAIN" : "cipher");

    int pass = (result == 12)
            && (g_max_concurrent_plain == 1)
            && (g_fns[0].base[0] != g_fns[0].first_pt)
            && (g_fns[1].base[0] != g_fns[1].first_pt);
    printf("\n%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
