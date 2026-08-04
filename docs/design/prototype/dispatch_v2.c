/* dispatch_v2.c, expanded function-granular dispatch prototype
 *
 * Follow-up to dispatch_proto.c. Adds the mechanics that v1 skipped
 * so phase 3 (real-loader integration) has fewer unknowns:
 *
 *   1. Five protected functions, not two
 *   2. Deeper call chain (A -> B -> C) and branching (A -> D)
 *   3. Resident partition, some functions never get encrypted
 *      (models Memcpy/Memset/Memcmp and the dispatcher itself)
 *   4. Wrapper pattern, resident entry_wrapper() calls dispatch
 *      to invoke a protected fn_A. Demonstrates the fix for the
 *      MainProc-as-CreateThread-callback problem (loader.c:77):
 *      hand Windows the resident wrapper, not the encrypted target.
 *   5. Function table built by an init pass (models what fritter
 *      will patch into the blob at generation time)
 *   6. Invariant checks: max concurrent plaintext of non-resident
 *      functions must remain 1 through arbitrary call chains
 *
 * Deliberately still in scope for a prototype: uses explicit
 * caller_id in the dispatch signature (real integration will
 * derive it from _ReturnAddress() and a sorted-address table).
 * Single-threaded (matches the loader's actual runtime model
 * per loader.c:77-128). No pack.h rewriting yet.
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

/* Function IDs. Layout order must match source order below because
 * setup computes sizes as (next_fn - this_fn). */
enum {
    FN_ID_A = 0,   /* protected, calls B and D */
    FN_ID_B,       /* protected, calls C */
    FN_ID_C,       /* protected, leaf */
    FN_ID_D,       /* RESIDENT, hot leaf, no dispatch overhead */
    FN_ID_E,       /* protected, leaf, called only from wrapper direct test */
    FN_ID_MAX,
    FN_ID_NONE = 0xFFFFu
};

typedef struct {
    uint8_t *base;
    size_t   size;
    uint8_t  key;
    uint8_t  first_pt;
    uint8_t  resident;   /* 1 = never encrypted, dispatch is a no-op */
    uint8_t  _pad;
    const char *name;
} fn_meta_t;

static fn_meta_t g_fns[FN_ID_MAX];

static NOINLINE uint64_t dispatch(uint16_t caller_id, uint16_t callee_id,
                                   uint64_t a, uint64_t b, uint64_t c, uint64_t d);

/* -------- Protected functions -------- */

static NOINLINE uint64_t proto_fn_A(uint64_t x, uint64_t y, uint64_t z, uint64_t w);
static NOINLINE uint64_t proto_fn_B(uint64_t x, uint64_t y, uint64_t z, uint64_t w);
static NOINLINE uint64_t proto_fn_C(uint64_t x, uint64_t y, uint64_t z, uint64_t w);
static NOINLINE uint64_t proto_fn_D(uint64_t x, uint64_t y, uint64_t z, uint64_t w);
static NOINLINE uint64_t proto_fn_E(uint64_t x, uint64_t y, uint64_t z, uint64_t w);
static NOINLINE void     proto_fn_end_sentinel(void);

/* fn_A: exercises both branching AND depth.
 *   Returns (B(x) + D(x))  where B(x) = C(x*3) and D(x) = x+100 (resident). */
static NOINLINE uint64_t proto_fn_A(uint64_t x, uint64_t y, uint64_t z, uint64_t w) {
    uint64_t bres = dispatch(FN_ID_A, FN_ID_B, x, 0, 0, 0);
    uint64_t dres = dispatch(FN_ID_A, FN_ID_D, x, 0, 0, 0);
    (void)y; (void)z; (void)w;
    return bres + dres;
}

/* fn_B: calls fn_C. Returns C(x*3). */
static NOINLINE uint64_t proto_fn_B(uint64_t x, uint64_t y, uint64_t z, uint64_t w) {
    (void)y; (void)z; (void)w;
    return dispatch(FN_ID_B, FN_ID_C, x * 3, 0, 0, 0);
}

/* fn_C: leaf. Returns x + 1. */
static NOINLINE uint64_t proto_fn_C(uint64_t x, uint64_t y, uint64_t z, uint64_t w) {
    (void)y; (void)z; (void)w;
    return x + 1;
}

/* fn_D: RESIDENT hot leaf. Returns x + 100. Called via dispatch but
 * dispatch short-circuits, no encrypt/decrypt for resident targets. */
static NOINLINE uint64_t proto_fn_D(uint64_t x, uint64_t y, uint64_t z, uint64_t w) {
    (void)y; (void)z; (void)w;
    return x + 100;
}

/* fn_E: another protected leaf, exercised via a separate direct-dispatch
 * test to verify per-function isolation. Returns x * 7. */
static NOINLINE uint64_t proto_fn_E(uint64_t x, uint64_t y, uint64_t z, uint64_t w) {
    (void)y; (void)z; (void)w;
    return x * 7;
}

static NOINLINE void proto_fn_end_sentinel(void) { }

/* -------- Wrapper pattern (models MainProc-as-CreateThread-callback fix) --
 * A resident stub that Windows can call directly as a thread routine.
 * All it does is enter dispatch to invoke the protected target.
 * This is what the phase-3 loader will hand to CreateThread instead
 * of MainProc's real address (loader.c:77). */

static NOINLINE uint64_t entry_wrapper_A(uint64_t inst_ptr) {
    return dispatch(FN_ID_NONE, FN_ID_A, inst_ptr, 0, 0, 0);
}

/* -------- Crypt + verification -------- */

static void xor_region(uint8_t *base, size_t size, uint8_t key) {
    for (size_t i = 0; i < size; i++) base[i] ^= key;
}

static int is_plaintext(int id) {
    return g_fns[id].base[0] == g_fns[id].first_pt;
}

/* Count non-resident functions currently plaintext. Should stay <= 1. */
static int count_protected_plaintext(void) {
    int n = 0;
    for (int i = 0; i < FN_ID_MAX; i++)
        if (!g_fns[i].resident && is_plaintext(i)) n++;
    return n;
}

static int g_max_concurrent_protected_plain = 0;
static int g_dispatch_calls = 0;
static int g_dispatch_shortcircuits = 0;   /* count of resident-target dispatches */

static void update_peak(void) {
    int n = count_protected_plaintext();
    if (n > g_max_concurrent_protected_plain) g_max_concurrent_protected_plain = n;
}

static void report(const char *step) {
    printf("      [%-24s]", step);
    for (int i = 0; i < FN_ID_MAX; i++) {
        printf("  %s=%s%s", g_fns[i].name,
               is_plaintext(i) ? "P" : "c",
               g_fns[i].resident ? "*" : " ");
    }
    printf("\n");
}

/* -------- Dispatcher --------
 * If callee is resident: call directly, no crypt work. This is the
 * fast path for hot leaves (Memcpy/Memset in the real loader).
 *
 * If caller is resident (or NONE): skip caller crypt work. Real
 * integration derives this from a resident-flag lookup on the
 * caller_id (or from _ReturnAddress falling in resident code). */
static NOINLINE uint64_t dispatch(uint16_t caller_id, uint16_t callee_id,
                                   uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    typedef uint64_t (*fn_t)(uint64_t, uint64_t, uint64_t, uint64_t);
    uint64_t result;
    int caller_active = (caller_id != FN_ID_NONE) && !g_fns[caller_id].resident;
    int callee_resident = g_fns[callee_id].resident;

    g_dispatch_calls++;

    printf("    dispatch(%s -> %s)\n",
           caller_id == FN_ID_NONE ? "(none)" : g_fns[caller_id].name,
           g_fns[callee_id].name);

    /* Fast path: resident target, no crypt work needed. */
    if (callee_resident) {
        g_dispatch_shortcircuits++;
        result = ((fn_t)g_fns[callee_id].base)(a, b, c, d);
        update_peak();
        return result;
    }

    report("dispatch entry");

    /* Step 1: encrypt caller (skip if caller resident or NONE). */
    if (caller_active) {
        xor_region(g_fns[caller_id].base, g_fns[caller_id].size,
                   g_fns[caller_id].key);
        report("after encrypt-caller");
    }

    /* Step 2: decrypt callee. */
    xor_region(g_fns[callee_id].base, g_fns[callee_id].size,
               g_fns[callee_id].key);
    report("after decrypt-callee");
    update_peak();

    /* Step 3: call the callee. */
    result = ((fn_t)g_fns[callee_id].base)(a, b, c, d);
    report("after callee returns");

    /* Step 4: encrypt callee, decrypt caller. */
    xor_region(g_fns[callee_id].base, g_fns[callee_id].size,
               g_fns[callee_id].key);
    if (caller_active) {
        xor_region(g_fns[caller_id].base, g_fns[caller_id].size,
                   g_fns[caller_id].key);
    }
    report("after re-encrypt");

    return result;
}

/* -------- Setup -------- */

static int setup_function(int id, const char *name, void *fn_start, void *fn_end,
                           uint8_t key, int resident)
{
    size_t size = (uintptr_t)fn_end - (uintptr_t)fn_start;
    if ((intptr_t)size <= 0 || size > 0x1000) {
        fprintf(stderr, "unexpected size for %s: %zd\n", name, (intptr_t)size);
        return -1;
    }
    g_fns[id].base     = (uint8_t*)fn_start;
    g_fns[id].size     = size;
    g_fns[id].key      = key;
    g_fns[id].first_pt = ((uint8_t*)fn_start)[0];
    g_fns[id].resident = (uint8_t)resident;
    g_fns[id].name     = name;

    printf("  %s: %4zu bytes @ %p key=0x%02X %s\n",
           name, size, fn_start, key, resident ? "RESIDENT" : "protected");

    if (!resident) {
        xor_region(g_fns[id].base, g_fns[id].size, g_fns[id].key);
    }
    return 0;
}

static int make_rwx(void *start, void *end) {
    uintptr_t ps = 0x1000;
    uintptr_t base = (uintptr_t)start & ~(ps - 1);
    uintptr_t top  = ((uintptr_t)end + ps - 1) & ~(ps - 1);
    DWORD old;
    if (!VirtualProtect((void*)base, top - base, PAGE_EXECUTE_READWRITE, &old))
        return -1;
    return 0;
}

/* -------- Tests -------- */

static int test_deep_and_branching(void) {
    /* fn_A(5) = fn_B(5) + fn_D(5)
     *         = fn_C(5*3) + (5+100)
     *         = (15+1) + 105
     *         = 121                                                */
    printf("\n--- Test 1: deep+branching call chain via entry_wrapper ---\n");
    printf("  entry_wrapper_A(5), models CreateThread(entry_wrapper_A, 5)\n\n");
    uint64_t result = entry_wrapper_A(5);
    int ok = (result == 121)
          && (count_protected_plaintext() == 0)
          && (is_plaintext(FN_ID_D));  /* resident stays plaintext */
    printf("\n  Result:              %llu (expected 121)\n", (unsigned long long)result);
    printf("  Final protected plain: %d (expected 0)\n", count_protected_plaintext());
    printf("  fn_D still plaintext:  %s (expected yes)\n",
           is_plaintext(FN_ID_D) ? "yes" : "NO");
    printf("  %s\n", ok ? "PASS" : "FAIL");
    return ok;
}

static int test_direct_dispatch_E(void) {
    /* fn_E(6) = 6 * 7 = 42, called directly from harness via dispatch. */
    printf("\n--- Test 2: direct dispatch to fn_E (independent target) ---\n");
    uint64_t result = dispatch(FN_ID_NONE, FN_ID_E, 6, 0, 0, 0);
    int ok = (result == 42)
          && (count_protected_plaintext() == 0);
    printf("\n  Result:                %llu (expected 42)\n", (unsigned long long)result);
    printf("  Final protected plain: %d (expected 0)\n", count_protected_plaintext());
    printf("  %s\n", ok ? "PASS" : "FAIL");
    return ok;
}

static int test_resident_shortcircuit(void) {
    /* Direct dispatch to fn_D. Should short-circuit (no crypt ops). */
    printf("\n--- Test 3: resident short-circuit for fn_D ---\n");
    int before = g_dispatch_shortcircuits;
    uint64_t result = dispatch(FN_ID_NONE, FN_ID_D, 10, 0, 0, 0);
    int after = g_dispatch_shortcircuits;
    int ok = (result == 110) && (after == before + 1);
    printf("  Result:            %llu (expected 110)\n", (unsigned long long)result);
    printf("  Short-circuited:   %s\n", (after == before + 1) ? "yes" : "NO");
    printf("  %s\n", ok ? "PASS" : "FAIL");
    return ok;
}

int main(void) {
    printf("=== Function-Granular Dispatch v2 ===\n\n");
    printf("Function addresses:\n");
    printf("  A=%p B=%p C=%p D=%p E=%p end=%p\n\n",
           (void*)(uintptr_t)proto_fn_A, (void*)(uintptr_t)proto_fn_B,
           (void*)(uintptr_t)proto_fn_C, (void*)(uintptr_t)proto_fn_D,
           (void*)(uintptr_t)proto_fn_E, (void*)(uintptr_t)proto_fn_end_sentinel);

    if (make_rwx((void*)proto_fn_A, (void*)proto_fn_end_sentinel) < 0) {
        fprintf(stderr, "make_rwx failed\n"); return 1;
    }

    printf("Setup:\n");
    /* Sizes computed from source-order layout. D is RESIDENT. */
    if (setup_function(FN_ID_A, "A", proto_fn_A, proto_fn_B, 0xA5, 0) < 0) return 1;
    if (setup_function(FN_ID_B, "B", proto_fn_B, proto_fn_C, 0xB5, 0) < 0) return 1;
    if (setup_function(FN_ID_C, "C", proto_fn_C, proto_fn_D, 0xC5, 0) < 0) return 1;
    if (setup_function(FN_ID_D, "D", proto_fn_D, proto_fn_E, 0xD5, 1) < 0) return 1;
    if (setup_function(FN_ID_E, "E", proto_fn_E, proto_fn_end_sentinel, 0xE5, 0) < 0) return 1;

    int pass = 1;
    pass &= test_deep_and_branching();
    pass &= test_direct_dispatch_E();
    pass &= test_resident_shortcircuit();

    printf("\n--- Overall ---\n");
    printf("  Dispatch calls total:              %d\n", g_dispatch_calls);
    printf("  Resident short-circuits:           %d\n", g_dispatch_shortcircuits);
    printf("  Max concurrent protected plaintext: %d (invariant: <= 1)\n",
           g_max_concurrent_protected_plain);

    int invariant = (g_max_concurrent_protected_plain <= 1);
    printf("\n%s\n", (pass && invariant) ? "PASS" : "FAIL");
    return (pass && invariant) ? 0 : 1;
}
