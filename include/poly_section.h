/* poly_section.h - per-function PE section placement for the loader.
 *
 * Tagged functions land in their own page-aligned PE section. The
 * multi-section exe2h then assembles the PIC blob preserving RVA
 * deltas, so each function occupies its own 4 KiB page - no loop
 * body inside a tagged function can straddle a page boundary
 * (because the function itself doesn't).
 *
 * Multiple functions sharing a section name get concatenated into
 * one section. Use this to co-locate tight caller-callee chains so
 * the call doesn't cross a page boundary.
 *
 * MSVC only: under gcc/mingw the macro is a no-op (the single-.text
 * + -fno-toplevel-reorder layout produced by the existing build
 * has not exposed the cross-page-loop bug in practice). */

#ifndef FRITTER_POLY_SECTION_H
#define FRITTER_POLY_SECTION_H

#define SECTION_HASH_CHAIN ".hash_chain"
#define SECTION_CIPHER     ".cipher"

#ifdef _MSC_VER
#  define LOADER_FN_SECTION(name_str) __declspec(code_seg(name_str))
#else
#  define LOADER_FN_SECTION(name_str)
#endif

#endif /* FRITTER_POLY_SECTION_H */
