/* pack.h - multi-section blob packer for exe2h.
 *
 * When exe2h extracts a multi-section MSVC build (per-function PE
 * sections from loader/include/poly_section.h), the default
 * RVA-preserving extraction leaves large NOP runs between sections
 * (~46% of the blob for a typical loader). Those runs are a
 * distinctive YARA fingerprint.
 *
 * This packer:
 *   1. Walks each code section with a minimal x86-64 length decoder
 *      to find cross-section RIP-relative displacements (E8 CALL,
 *      E9 JMP, 0F 8x Jcc, and ModR/M mod=00 rm=101 [rip+disp32]).
 *   2. Plans a packed layout by trying all permutations of non-.text
 *      sections, choosing the smallest layout that keeps each per-
 *      function section entirely within a single 4 KiB page (so
 *      hot loops can't straddle page boundaries - preserves the
 *      cross-page-loop invariant established by per-function PE
 *      sections under MSVC).
 *   3. Copies each section to its new offset and rewrites every
 *      cross-section disp32.
 *
 * The LDE covers the subset MSVC /Os /O1 emits for our codebase.
 * Any undecodable byte aborts the pack and falls through to the
 * original RVA-preserving (NOP-fill) extraction.
 */

#ifndef FRITTER_EXE2H_PACK_H
#define FRITTER_EXE2H_PACK_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ============================================================
 * Minimal x86-64 length decoder
 * ============================================================ */

#define LDE_F_MODRM  0x01u  /* has ModR/M byte */
#define LDE_F_IB     0x02u  /* has 1-byte immediate */
#define LDE_F_IW     0x04u  /* has fixed 2-byte immediate */
#define LDE_F_IV     0x08u  /* var imm: 16 with 66 prefix, 32 otherwise */
#define LDE_F_IO     0x10u  /* op-size imm: 64 with REX.W, else like IV */
#define LDE_F_REL8   0x20u  /* 1-byte rel branch */
#define LDE_F_REL32  0x40u  /* var rel: 16 with 66, 32 otherwise (E8/E9) */
#define LDE_F_ESC0F  0x80u  /* 0F two-byte escape */

static uint8_t LDE_OP1[256];
static uint8_t LDE_OP2[256];
static int LDE_INITED = 0;

static void lde_init_tables(void) {
  int b;
  if(LDE_INITED) return;
  memset(LDE_OP1, 0, sizeof(LDE_OP1));
  memset(LDE_OP2, 0, sizeof(LDE_OP2));

  /* 00-3F ALU r/m + r forms repeat in 8-byte groups */
  for(b = 0; b < 0x40; b += 8) {
    LDE_OP1[b+0] = LDE_F_MODRM;
    LDE_OP1[b+1] = LDE_F_MODRM;
    LDE_OP1[b+2] = LDE_F_MODRM;
    LDE_OP1[b+3] = LDE_F_MODRM;
    LDE_OP1[b+4] = LDE_F_IB;
    LDE_OP1[b+5] = LDE_F_IV;
    /* +6, +7 = PUSH/POP seg - invalid in long mode (left 0) */
  }
  LDE_OP1[0x0F] = LDE_F_ESC0F;
  /* 50-5F PUSH/POP reg already 0 */
  LDE_OP1[0x63] = LDE_F_MODRM;
  LDE_OP1[0x68] = LDE_F_IV;
  LDE_OP1[0x69] = LDE_F_MODRM | LDE_F_IV;
  LDE_OP1[0x6A] = LDE_F_IB;
  LDE_OP1[0x6B] = LDE_F_MODRM | LDE_F_IB;
  for(b = 0x70; b <= 0x7F; b++) LDE_OP1[b] = LDE_F_REL8;
  LDE_OP1[0x80] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP1[0x81] = LDE_F_MODRM | LDE_F_IV;
  LDE_OP1[0x82] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP1[0x83] = LDE_F_MODRM | LDE_F_IB;
  for(b = 0x84; b <= 0x8F; b++) LDE_OP1[b] = LDE_F_MODRM;
  /* 0x90 NOP / 91-9F single-byte already 0 */
  /* A0-A7 already 0 */
  LDE_OP1[0xA8] = LDE_F_IB;
  LDE_OP1[0xA9] = LDE_F_IV;
  /* AA-AF already 0 */
  for(b = 0xB0; b <= 0xB7; b++) LDE_OP1[b] = LDE_F_IB;
  for(b = 0xB8; b <= 0xBF; b++) LDE_OP1[b] = LDE_F_IO;
  LDE_OP1[0xC0] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP1[0xC1] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP1[0xC2] = LDE_F_IW;
  /* 0xC3 RET already 0 */
  LDE_OP1[0xC6] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP1[0xC7] = LDE_F_MODRM | LDE_F_IV;
  LDE_OP1[0xC8] = LDE_F_IW | LDE_F_IB;
  /* 0xC9 LEAVE 0 */
  LDE_OP1[0xCA] = LDE_F_IW;
  /* CB-CC 0 */
  LDE_OP1[0xCD] = LDE_F_IB;
  /* CF 0 */
  for(b = 0xD0; b <= 0xD3; b++) LDE_OP1[b] = LDE_F_MODRM;
  /* D7 0 */
  for(b = 0xE0; b <= 0xE3; b++) LDE_OP1[b] = LDE_F_REL8;
  LDE_OP1[0xE4] = LDE_F_IB;
  LDE_OP1[0xE5] = LDE_F_IB;
  LDE_OP1[0xE6] = LDE_F_IB;
  LDE_OP1[0xE7] = LDE_F_IB;
  LDE_OP1[0xE8] = LDE_F_REL32;
  LDE_OP1[0xE9] = LDE_F_REL32;
  LDE_OP1[0xEB] = LDE_F_REL8;
  /* EC-EF already 0 */
  /* F1, F4-F5 already 0 */
  LDE_OP1[0xF6] = LDE_F_MODRM;  /* /0 /1 add IB, handled per-instruction */
  LDE_OP1[0xF7] = LDE_F_MODRM;  /* /0 /1 add IV */
  /* F8-FD already 0 */
  LDE_OP1[0xFE] = LDE_F_MODRM;
  LDE_OP1[0xFF] = LDE_F_MODRM;

  /* 0F escape table */
  LDE_OP2[0x00] = LDE_F_MODRM;
  LDE_OP2[0x01] = LDE_F_MODRM;
  /* 05-09, 0B 0E zero-operand */
  LDE_OP2[0x0D] = LDE_F_MODRM;
  for(b = 0x10; b <= 0x17; b++) LDE_OP2[b] = LDE_F_MODRM;
  for(b = 0x18; b <= 0x1F; b++) LDE_OP2[b] = LDE_F_MODRM;
  for(b = 0x20; b <= 0x23; b++) LDE_OP2[b] = LDE_F_MODRM;
  for(b = 0x28; b <= 0x2F; b++) LDE_OP2[b] = LDE_F_MODRM;
  /* 30-37 zero-operand */
  for(b = 0x40; b <= 0x4F; b++) LDE_OP2[b] = LDE_F_MODRM;
  for(b = 0x50; b <= 0x7F; b++) LDE_OP2[b] = LDE_F_MODRM;
  for(b = 0x80; b <= 0x8F; b++) LDE_OP2[b] = LDE_F_REL32;
  for(b = 0x90; b <= 0x9F; b++) LDE_OP2[b] = LDE_F_MODRM;
  /* A0-A2 zero-operand */
  LDE_OP2[0xA3] = LDE_F_MODRM;
  LDE_OP2[0xA4] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP2[0xA5] = LDE_F_MODRM;
  /* A8-A9 zero-operand */
  LDE_OP2[0xAB] = LDE_F_MODRM;
  LDE_OP2[0xAC] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP2[0xAD] = LDE_F_MODRM;
  LDE_OP2[0xAE] = LDE_F_MODRM;
  LDE_OP2[0xAF] = LDE_F_MODRM;
  LDE_OP2[0xB0] = LDE_F_MODRM;
  LDE_OP2[0xB1] = LDE_F_MODRM;
  for(b = 0xB2; b <= 0xBF; b++) LDE_OP2[b] = LDE_F_MODRM;
  LDE_OP2[0xBA] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP2[0xC0] = LDE_F_MODRM;
  LDE_OP2[0xC1] = LDE_F_MODRM;
  LDE_OP2[0xC2] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP2[0xC3] = LDE_F_MODRM;
  LDE_OP2[0xC4] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP2[0xC5] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP2[0xC6] = LDE_F_MODRM | LDE_F_IB;
  LDE_OP2[0xC7] = LDE_F_MODRM;
  /* C8-CF BSWAP zero-operand */
  for(b = 0xD0; b <= 0xFF; b++) LDE_OP2[b] = LDE_F_MODRM;

  LDE_INITED = 1;
}

typedef struct {
  int length;
  int rip_disp_off;    /* offset within instr of RIP-relative disp32, or -1 */
  int rel32_disp_off;  /* offset within instr of REL32 (E8/E9/0F 8x) disp, or -1 */
} lde_inst_t;

/* Decode one instruction. Returns 1 on success, 0 on undecodable. */
static int lde_decode(const uint8_t *p, size_t max, lde_inst_t *out) {
  size_t pos = 0;
  int op_size_16 = 0, addr_size_32 = 0, rex_w = 0;
  int prefix_count = 0;
  uint8_t op, op2 = 0, flags;
  int is_0f = 0;

  out->length = 0;
  out->rip_disp_off = -1;
  out->rel32_disp_off = -1;

  /* Legacy prefixes */
  while(pos < max && prefix_count < 4) {
    uint8_t b = p[pos];
    if(b == 0x66) { op_size_16 = 1; pos++; prefix_count++; }
    else if(b == 0x67) { addr_size_32 = 1; pos++; prefix_count++; }
    else if(b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
            b == 0x64 || b == 0x65 || b == 0xF0 || b == 0xF2 || b == 0xF3) {
      pos++; prefix_count++;
    }
    else break;
  }
  if(pos >= max) return 0;

  /* REX */
  if(p[pos] >= 0x40 && p[pos] <= 0x4F) {
    rex_w = (p[pos] & 0x08) != 0;
    pos++;
    if(pos >= max) return 0;
  }

  /* Opcode */
  op = p[pos++];
  flags = LDE_OP1[op];

  if(flags & LDE_F_ESC0F) {
    if(pos >= max) return 0;
    op2 = p[pos++];
    if(op2 == 0x38 || op2 == 0x3A) return 0;  /* 3-byte opcodes unsupported */
    is_0f = 1;
    flags = LDE_OP2[op2];
    op = op2;
  }

  /* ModR/M + SIB + disp */
  if(flags & LDE_F_MODRM) {
    uint8_t modrm;
    int mod, rm, reg;
    int disp_size = 0;
    int sib_consumed = 0;

    if(pos >= max) return 0;
    modrm = p[pos++];
    mod = (modrm >> 6) & 3;
    rm  = modrm & 7;
    reg = (modrm >> 3) & 7;

    /* Group 3 (F6/F7) /0,/1 has immediate */
    if(!is_0f && op == 0xF6 && (reg == 0 || reg == 1)) flags |= LDE_F_IB;
    if(!is_0f && op == 0xF7 && (reg == 0 || reg == 1)) flags |= LDE_F_IV;

    if(mod == 3) {
      /* register operand */
    } else if(mod == 0) {
      if(rm == 5) {
        /* [RIP+disp32] in 64-bit (or [disp32] with 67-prefix) */
        if(!addr_size_32) out->rip_disp_off = (int)pos;
        disp_size = 4;
      } else if(rm == 4) {
        uint8_t sib;
        int base;
        if(pos >= max) return 0;
        sib = p[pos++];
        sib_consumed = 1;
        base = sib & 7;
        if(base == 5) disp_size = 4;
      }
    } else if(mod == 1) {
      if(rm == 4) {
        if(pos >= max) return 0;
        pos++;
        sib_consumed = 1;
      }
      disp_size = 1;
    } else { /* mod == 2 */
      if(rm == 4) {
        if(pos >= max) return 0;
        pos++;
        sib_consumed = 1;
      }
      disp_size = 4;
    }
    (void)sib_consumed;

    /* RIP-rel disp begins immediately after ModR/M (no SIB for rm=5 mod=0) */
    if(out->rip_disp_off >= 0) out->rip_disp_off = (int)pos;

    pos += disp_size;
    if(pos > max) return 0;
  }

  /* Immediates */
  if(flags & LDE_F_IB) pos += 1;
  if(flags & LDE_F_IW) pos += 2;
  if(flags & LDE_F_IV) pos += op_size_16 ? 2 : 4;
  if(flags & LDE_F_IO) {
    if(rex_w) pos += 8;
    else if(op_size_16) pos += 2;
    else pos += 4;
  }
  if(flags & LDE_F_REL8) pos += 1;
  if(flags & LDE_F_REL32) {
    out->rel32_disp_off = (int)pos;
    pos += op_size_16 ? 2 : 4;
  }

  if(pos > max) return 0;
  out->length = (int)pos;
  return 1;
}

/* ============================================================
 * Deterministic-random byte fill for inter-section gaps.
 *
 * Used by both the packer and the RVA-preserving fallback in
 * exe2h.c. NOT a CSPRNG - just an LCG seeded from a fingerprint
 * of the first section's bytes. Properties we need:
 *
 *   1. Output is build-stable (same input -> same fill bytes),
 *      so repeated builds produce identical .h output - matches
 *      the per-build polymorphism model where variation comes
 *      from gen_poly's seed, not from extraction noise.
 *
 *   2. No 8-byte repeating pattern (defeats the post-XOR
 *      repeating-ciphertext signature; a NOP run XOR'd with a
 *      tiled per-page key produces a tell-tale 8-byte repeat).
 *
 *   3. No long runs of any single byte (defeats wildcard NOP
 *      sled rules even before the per-page XOR layer).
 *
 * The orchestrator's per-build per-page XOR over the loader
 * region produces the actual ciphertext entropy; this fill just
 * eliminates predictable plaintext in the gaps.
 * ============================================================ */
static void pack_random_fill_impl(uint8_t *out, uint32_t size,
                                  const uint8_t *seed_bytes, uint32_t n_seed_bytes)
{
  uint64_t seed = 0x9E3779B97F4A7C15ULL;
  uint32_t i, k;
  uint32_t n = (n_seed_bytes > 64) ? 64 : n_seed_bytes;
  for(i = 0; i < n; i++) {
    seed = (seed ^ seed_bytes[i]) * 0x100000001B3ULL;
  }
  for(k = 0; k < size; k++) {
    seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
    out[k] = (uint8_t)(seed >> 56);
  }
}

/* ============================================================
 * Packer
 * ============================================================ */

#define PACK_MAX_SECTIONS 16
#define PACK_PAGE         0x1000u

typedef struct {
  char     name[16];        /* PE section name (8 chars + null) */
  uint32_t vaddr;           /* original RVA */
  uint32_t vsize;           /* VirtualSize */
  uint32_t file_off;        /* PointerToRawData */
  uint32_t copy_size;       /* min(VirtualSize, SizeOfRawData) */
  uint32_t new_offset;      /* assigned offset in packed blob */
  int      single_page;     /* must fit in a single 4 KiB page */
} pack_sec_t;

typedef struct {
  uint32_t src_sec;         /* index into sections[] */
  uint32_t src_offset;      /* offset of instruction within source section */
  uint32_t inst_length;     /* total instruction length */
  uint32_t disp_offset;     /* offset of disp32 field within instruction */
  uint32_t target_rva;      /* original target RVA */
  uint32_t target_sec;      /* index into sections[] */
} pack_ref_t;

/* Public-facing wrapper used by the RVA-preserving fallback in
   exe2h.c. Seeds the LCG from the first section's bytes so the
   fill is deterministic per build. */
static void pack_random_fill(uint8_t *blob, uint32_t size,
                             const uint8_t *map, const pack_sec_t *first_sec)
{
  pack_random_fill_impl(blob, size,
                        map + first_sec->file_off, first_sec->copy_size);
}

/* Find section index for an RVA; returns -1 if not in any code section. */
static int pack_find_section(const pack_sec_t *sections, int n, uint32_t rva) {
  int i;
  for(i = 0; i < n; i++) {
    if(rva >= sections[i].vaddr && rva < sections[i].vaddr + sections[i].vsize)
      return i;
  }
  return -1;
}

/* Walk a section, collect cross-section RIP-rel / REL32 references.
   Returns 0 on undecodable byte (caller should fall back).  */
static int pack_find_refs(const uint8_t *map, pack_sec_t *sections, int n_sec,
                          int sec_idx, pack_ref_t **refs, int *n_refs, int *cap_refs)
{
  pack_sec_t *sec = &sections[sec_idx];
  const uint8_t *sb = map + sec->file_off;
  uint32_t L = sec->copy_size;
  uint32_t pos = 0;

  while(pos < L) {
    lde_inst_t inst;
    if(!lde_decode(sb + pos, L - pos, &inst)) {
      printf("  [   LDE: undecodable byte in '%s' at +0x%x (byte=0x%02x)\n",
             sec->name, pos, sb[pos]);
      return 0;
    }

    /* Inspect both RIP-relative and REL32 displacements */
    int disp_offs[2] = { inst.rip_disp_off, inst.rel32_disp_off };
    int k;
    for(k = 0; k < 2; k++) {
      int doff = disp_offs[k];
      if(doff < 0) continue;
      int32_t disp;
      memcpy(&disp, sb + pos + doff, 4);
      uint32_t inst_end_rva = sec->vaddr + pos + inst.length;
      uint32_t target_rva = inst_end_rva + (uint32_t)disp;
      int tgt_sec = pack_find_section(sections, n_sec, target_rva);
      if(tgt_sec < 0 || tgt_sec == sec_idx) continue;

      /* Cross-section ref */
      if(*n_refs == *cap_refs) {
        int new_cap = (*cap_refs) * 2;
        if(new_cap == 0) new_cap = 32;
        *refs = (pack_ref_t*)realloc(*refs, new_cap * sizeof(pack_ref_t));
        *cap_refs = new_cap;
      }
      pack_ref_t *r = &(*refs)[(*n_refs)++];
      r->src_sec = sec_idx;
      r->src_offset = pos;
      r->inst_length = inst.length;
      r->disp_offset = doff;
      r->target_rva = target_rva;
      r->target_sec = tgt_sec;
    }

    pos += inst.length;
  }
  return 1;
}

/* Plan layout: section 0 (the entry-point .text) is fixed at offset 0.
   Other sections are reordered to minimize total size while keeping
   each single_page section entirely within one 4 KiB page.
   Brute-force over permutations (n! - feasible for n <= 7). */
static uint32_t pack_eval_layout(const pack_sec_t *sections, const int *order, int n) {
  uint32_t offset = 0;
  int i;
  /* First section (index 0 in original order, the .text) at offset 0 */
  offset = sections[0].vsize;
  for(i = 1; i < n; i++) {
    const pack_sec_t *s = &sections[order[i]];
    uint32_t sz = s->vsize;
    if(s->single_page) {
      if((offset >> 12) != ((offset + sz - 1) >> 12)) {
        /* Would straddle a page boundary - bump */
        offset = (offset + 0xFFF) & ~0xFFFu;
      }
    }
    offset += sz;
  }
  return offset;
}

static void pack_apply_layout(pack_sec_t *sections, const int *order, int n) {
  uint32_t offset = 0;
  int i;
  sections[0].new_offset = 0;
  offset = sections[0].vsize;
  for(i = 1; i < n; i++) {
    pack_sec_t *s = &sections[order[i]];
    if(s->single_page) {
      if((offset >> 12) != ((offset + s->vsize - 1) >> 12))
        offset = (offset + 0xFFF) & ~0xFFFu;
    }
    s->new_offset = offset;
    offset += s->vsize;
  }
}

/* Recursive permutation search over indices [1..n-1] (index 0 fixed) */
static void pack_search(int *cur, int depth, int n, int *used,
                        const pack_sec_t *sections,
                        uint32_t *best_size, int *best_order)
{
  if(depth == n) {
    uint32_t sz = pack_eval_layout(sections, cur, n);
    if(sz < *best_size) {
      *best_size = sz;
      memcpy(best_order, cur, n * sizeof(int));
    }
    return;
  }
  int i;
  for(i = 1; i < n; i++) {
    if(used[i]) continue;
    used[i] = 1;
    cur[depth] = i;
    pack_search(cur, depth + 1, n, used, sections, best_size, best_order);
    used[i] = 0;
  }
}

/* Main packer entry. Returns malloced packed blob and sets *out_size,
   or NULL on failure (caller falls back to NOP-fill extraction). */
static uint8_t *pack_extract(const uint8_t *map, pack_sec_t *sections, int n_sec,
                             uint32_t *out_size)
{
  pack_ref_t *refs = NULL;
  int n_refs = 0, cap_refs = 0;
  uint8_t *blob = NULL;
  int order[PACK_MAX_SECTIONS];
  int best_order[PACK_MAX_SECTIONS];
  int used[PACK_MAX_SECTIONS] = {0};
  uint32_t best_size = 0xFFFFFFFFu;
  int i, j;

  lde_init_tables();

  /* Find all cross-section refs */
  printf("  [ packer: walking %d code section(s) for cross-section refs\n", n_sec);
  for(i = 0; i < n_sec; i++) {
    if(!pack_find_refs(map, sections, n_sec, i, &refs, &n_refs, &cap_refs)) {
      printf("  [ packer: LDE failed in section '%s' - falling back\n",
             sections[i].name);
      free(refs);
      return NULL;
    }
  }
  printf("  [ packer: %d cross-section reference(s) found\n", n_refs);

  /* Plan layout: enumerate permutations of indices [1..n-1] */
  order[0] = 0;
  for(i = 1; i < n_sec; i++) order[i] = i;
  used[0] = 1;
  pack_search(order, 1, n_sec, used, sections, &best_size, best_order);
  best_order[0] = 0;
  pack_apply_layout(sections, best_order, n_sec);

  uint32_t code_bytes = 0;
  for(i = 0; i < n_sec; i++) code_bytes += sections[i].vsize;
  uint32_t pad_bytes = best_size - code_bytes;
  printf("  [ packer: layout = %u bytes (%u code + %u pad, %.1f%%)\n",
         best_size, code_bytes, pad_bytes, 100.0 * pad_bytes / best_size);
  printf("  [ packer: section placement:\n");
  for(i = 0; i < n_sec; i++) {
    int oi = best_order[i];
    const pack_sec_t *s = &sections[oi];
    printf("  [     %-10s -> +0x%05x..0x%05x  (%u bytes%s)\n",
           s->name, s->new_offset, s->new_offset + s->vsize,
           s->vsize, s->single_page ? ", single-page" : "");
  }

  /* Allocate packed blob. Random-fill any padding so the post-XOR
     ciphertext doesn't expose a repeating-pattern signature. We use
     a simple LCG seeded from the binary's contents so the output is
     deterministic per build (matching gen_poly's "per-output" model).
     The orchestrator's per-page XOR encryption produces the final
     entropy; this filler just kills predictable plaintext. */
  blob = (uint8_t*)malloc(best_size);
  if(blob == NULL) {
    printf("  [ packer: allocation failed for %u-byte blob\n", best_size);
    free(refs);
    return NULL;
  }

  /* Random-fill the whole blob (then copy sections over it). */
  pack_random_fill_impl(blob, best_size,
                        map + sections[0].file_off, sections[0].copy_size);

  /* Copy each section to its new offset */
  for(i = 0; i < n_sec; i++) {
    pack_sec_t *s = &sections[i];
    memcpy(blob + s->new_offset, map + s->file_off, s->copy_size);
    /* If copy_size < vsize, the remainder stays as random fill (PE rule:
       beyond SizeOfRawData is zero-initialized in memory; here it's
       random-initialized which is fine for code that never reads it). */
  }

  /* Rewrite cross-section displacements */
  for(j = 0; j < n_refs; j++) {
    pack_ref_t *r = &refs[j];
    pack_sec_t *src = &sections[r->src_sec];
    pack_sec_t *tgt = &sections[r->target_sec];
    uint32_t target_off_in_tgt = r->target_rva - tgt->vaddr;
    uint32_t new_target_pos = tgt->new_offset + target_off_in_tgt;
    uint32_t new_inst_end   = src->new_offset + r->src_offset + r->inst_length;
    int32_t  new_disp = (int32_t)(new_target_pos - new_inst_end);
    memcpy(blob + src->new_offset + r->src_offset + r->disp_offset, &new_disp, 4);
  }

  *out_size = best_size;
  free(refs);
  return blob;
}

#endif /* FRITTER_EXE2H_PACK_H */
