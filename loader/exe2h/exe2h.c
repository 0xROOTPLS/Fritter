/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#include <shlwapi.h>
#include "mmap.h"
#pragma comment(lib, "shlwapi.lib")
#else
#define NIX
#include <libgen.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pe.h>
#endif

#include "pack.h"

// return pointer to DOS header
PIMAGE_DOS_HEADER DosHdr(void *map) {
    return (PIMAGE_DOS_HEADER)map;
}

// return pointer to NT header
PIMAGE_NT_HEADERS NtHdr (void *map) {
    return (PIMAGE_NT_HEADERS) ((uint8_t*)map + DosHdr(map)->e_lfanew);
}

// return pointer to File header
PIMAGE_FILE_HEADER FileHdr (void *map) {
    return &NtHdr(map)->FileHeader;
}

// determines CPU architecture of binary
int is32 (void *map) {
    return FileHdr(map)->Machine == IMAGE_FILE_MACHINE_I386;
}

// determines CPU architecture of binary
int is64 (void *map) {
    return FileHdr(map)->Machine == IMAGE_FILE_MACHINE_AMD64;
}

// return pointer to Optional header
void* OptHdr (void *map) {
    return (void*)&NtHdr(map)->OptionalHeader;
}

// return pointer to first section header
PIMAGE_SECTION_HEADER SecHdr (void *map) {
    PIMAGE_NT_HEADERS nt = NtHdr(map);
  
    return (PIMAGE_SECTION_HEADER)((uint8_t*)&nt->OptionalHeader + 
    nt->FileHeader.SizeOfOptionalHeader);
}

uint32_t DirSize (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->NumberOfRvaAndSizes;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->NumberOfRvaAndSizes;
    }
}

uint32_t SecSize (void *map) {
    return NtHdr(map)->FileHeader.NumberOfSections;
}

PIMAGE_DATA_DIRECTORY Dirs (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->DataDirectory;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->DataDirectory;
    }
}

uint64_t ImgBase (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->ImageBase;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->ImageBase;
    }
}

// valid dos header?
int valid_dos_hdr (void *map) {
    PIMAGE_DOS_HEADER dos = DosHdr(map);
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    return (dos->e_lfanew != 0);
}

// valid nt headers
int valid_nt_hdr (void *map) {
    return NtHdr(map)->Signature == IMAGE_NT_SIGNATURE;
}

uint32_t rva2ofs (void *map, uint32_t rva) {
    int i;
    
    PIMAGE_SECTION_HEADER sh = SecHdr(map);
    
    for (i=0; i<SecSize(map); i++) {
      if (rva >= sh[i].VirtualAddress && rva < sh[i].VirtualAddress + sh[i].SizeOfRawData)
      return sh[i].PointerToRawData + (rva - sh[i].VirtualAddress);
    }
    return -1;
}

void bin2h(void *map, char *fname, void *bin, uint32_t len) {
    char      label[32], file[32], *str;
    uint32_t  i;
    uint8_t   *p=(uint8_t*)bin;
    FILE      *fd;
    
    memset(label, 0, sizeof(label));
    memset(file,  0, sizeof(file));
    
#if defined(WINDOWS)
    str = PathFindFileName(fname);
#else
    str = basename(fname);
#endif
    for(i=0; str[i] != 0 && i < 24;i++) {
      if(str[i] == '.') {
        file[i] = label[i] = '_';
      } else {
        label[i] = toupper(str[i]);
        file[i]  = tolower(str[i]);
      }
    }
    if(map != NULL) {
      strcat(label, is32(map) ? "_X86" : "_X64");
      strcat(file,  is32(map) ? "_x86" : "_x64");
    }
    strcat(file, ".h");
    
    fd = fopen(file, "wb");
    
    if(fd != NULL) {
      fprintf(fd, "\nunsigned char %s[] = {", label);
      
      for(i=0;i<len;i++) {
        if(!(i % 12)) fprintf(fd, "\n  ");
        fprintf(fd, "0x%02x", p[i]);
        if((i+1) != len) fprintf(fd, ", ");
      }
      fprintf(fd, "};\n\n");
      fclose(fd);
      printf("  [ saved code to %s\n", file);
    } else printf("  [ unable to create file : %s\n", file);
}

void bin2go(void* map, char* fname, void* bin, uint32_t len) {
	char      label[32], file[32], * str;
	uint32_t  i;
	uint8_t* p = (uint8_t*)bin;
	FILE* fd;

	memset(label, 0, sizeof(label));
	memset(file, 0, sizeof(file));

#if defined(WINDOWS)
	str = PathFindFileName(fname);
#else
	str = basename(fname);
#endif
	for (i = 0; str[i] != 0 && i < 24; i++) {
		if (str[i] == '.') {
			file[i] = label[i] = '_';
		}
		else {
			label[i] = toupper(str[i]);
			file[i] = tolower(str[i]);
		}
	}
	if (map != NULL) {
		strcat(label, is32(map) ? "_X86" : "_X64");
		strcat(file, is32(map) ? "_x86" : "_x64");
	}
	strcat(file, ".go");

	fd = fopen(file, "wb");

	if (fd != NULL) {
		fprintf(fd, "package fritter\n\n// %s - stub for EXE PE files\nvar %s = []byte{\n", label, label);
		
		for (i = 0; i < len; i++) {
			if (!(i % 12)) fprintf(fd, "\n  ");
			fprintf(fd, "0x%02x", p[i]);
			if ((i + 1) != len) fprintf(fd, ", ");
		}
		fprintf(fd, "};\n\n");
		fclose(fd);
		printf("  [ saved code to %s\n", file);
	}
	else printf("  [ unable to create file : %s\n", file);
}


/* Derive a base name from an input path like "loader_peb1.exe":
     out_lower gets "loader_peb1"  (lowercase, '.' -> '_' stripped)
     out_upper gets "LOADER_PEB1"  (uppercase equivalent)
   Bounded by 24 chars, matching bin2h's cap. */
static void exe2h_base_names(const char *fname, char *out_lower, char *out_upper) {
    const char *str;
    int i;
#if defined(WINDOWS)
    str = PathFindFileName((LPSTR)fname);
#else
    str = basename((char*)fname);
#endif
    for(i = 0; str[i] != 0 && i < 24; i++) {
        /* Strip at the extension dot so "loader_peb1.exe" -> "loader_peb1" */
        if(str[i] == '.') break;
        out_lower[i] = (char)tolower((unsigned char)str[i]);
        out_upper[i] = (char)toupper((unsigned char)str[i]);
    }
    out_lower[i] = 0;
    out_upper[i] = 0;
}

/* Emit companion header: fn_table describes each protected code section
   in blob-offset terms. Consumed by fritter's build_loader to populate
   the shim's fn_table_area and to XOR each protected slab with a random
   per-fn key. */
static void emit_fn_table_h(void *map, const char *fname,
                            const pack_sec_t *sections, int n_sec) {
    char base_lower[32], base_upper[32], out_file[64];
    FILE *fd;
    int i;

    exe2h_base_names(fname, base_lower, base_upper);
    snprintf(out_file, sizeof(out_file), "%s_fn_table_x64.h", base_lower);

    fd = fopen(out_file, "wb");
    if(fd == NULL) {
        printf("  [ unable to create file : %s\n", out_file);
        return;
    }

    fprintf(fd, "/* Auto-generated by exe2h. Do not edit. */\n");
    fprintf(fd, "#ifndef %s_FN_TABLE_X64_H\n", base_upper);
    fprintf(fd, "#define %s_FN_TABLE_X64_H\n\n", base_upper);
    fprintf(fd, "#include <stdint.h>\n\n");
    fprintf(fd, "#ifndef FRITTER_FN_META_T_DEFINED\n");
    fprintf(fd, "#define FRITTER_FN_META_T_DEFINED\n");
    fprintf(fd, "typedef struct {\n");
    fprintf(fd, "    uint32_t offset;     /* blob-relative start */\n");
    fprintf(fd, "    uint32_t size;       /* section VirtualSize */\n");
    fprintf(fd, "    uint8_t  single_page;/* section fits within one 4K page */\n");
    fprintf(fd, "    uint8_t  _pad[3];\n");
    fprintf(fd, "    char     name[16];   /* PE section name, NUL-padded */\n");
    fprintf(fd, "} fn_meta_t;\n");
    fprintf(fd, "#endif\n\n");
    fprintf(fd, "#define %s_FN_COUNT %d\n\n", base_upper, n_sec);
    fprintf(fd, "static const fn_meta_t %s_FNS[%s_FN_COUNT] = {\n",
            base_upper, base_upper);
    for(i = 0; i < n_sec; i++) {
        const pack_sec_t *s = &sections[i];
        fprintf(fd, "  { 0x%08x, 0x%08x, %u, {0,0,0}, \"%.8s\" },\n",
                s->new_offset, s->vsize, (unsigned)s->single_page, s->name);
    }
    fprintf(fd, "};\n\n");
    fprintf(fd, "#endif\n");
    fclose(fd);
    printf("  [ saved fn table to %s (%d sections)\n", out_file, n_sec);
    (void)map;
}

/* Emit companion header: ref_table describes each cross-section
   fixup already applied to the blob. Used by fritter to redirect
   those disp32 patches at generated thunks instead of the raw
   callee bytes (so a call from .text into .cipher becomes a call
   into a thunk that enters the dispatcher). Coordinates are in
   blob-absolute offsets so fritter doesn't need to know section
   geometry. */
static void emit_ref_table_h(void *map, const char *fname,
                             const pack_ref_t *refs, int n_refs,
                             const pack_sec_t *sections, int n_sec) {
    char base_lower[32], base_upper[32], out_file[64];
    FILE *fd;
    int i;

    exe2h_base_names(fname, base_lower, base_upper);
    snprintf(out_file, sizeof(out_file), "%s_ref_table_x64.h", base_lower);

    fd = fopen(out_file, "wb");
    if(fd == NULL) {
        printf("  [ unable to create file : %s\n", out_file);
        return;
    }

    fprintf(fd, "/* Auto-generated by exe2h. Do not edit. */\n");
    fprintf(fd, "#ifndef %s_REF_TABLE_X64_H\n", base_upper);
    fprintf(fd, "#define %s_REF_TABLE_X64_H\n\n", base_upper);
    fprintf(fd, "#include <stdint.h>\n\n");
    fprintf(fd, "#ifndef FRITTER_REF_T_DEFINED\n");
    fprintf(fd, "#define FRITTER_REF_T_DEFINED\n");
    fprintf(fd, "typedef struct {\n");
    fprintf(fd, "    uint32_t src_blob_off; /* start of source instruction */\n");
    fprintf(fd, "    uint16_t inst_length;  /* full instruction length */\n");
    fprintf(fd, "    uint16_t disp_offset;  /* offset of disp32 within inst */\n");
    fprintf(fd, "    uint16_t src_fn;       /* index into FNS[] (caller) */\n");
    fprintf(fd, "    uint16_t target_fn;    /* index into FNS[] (callee) */\n");
    fprintf(fd, "} ref_t;\n");
    fprintf(fd, "#endif\n\n");
    fprintf(fd, "#define %s_REF_COUNT %d\n\n", base_upper, n_refs);
    fprintf(fd, "static const ref_t %s_REFS[%s_REF_COUNT + 1] = {\n",
            base_upper, base_upper);
    for(i = 0; i < n_refs; i++) {
        const pack_ref_t *r = &refs[i];
        uint32_t blob_off = sections[r->src_sec].new_offset + r->src_offset;
        fprintf(fd, "  { 0x%08x, %u, %u, %u, %u },\n",
                blob_off, r->inst_length, r->disp_offset,
                r->src_sec, r->target_sec);
    }
    /* Trailing sentinel so the [+1] sizing keeps a valid element even
       when REF_COUNT is 0 (dispatch_shim.exe case). */
    fprintf(fd, "  { 0, 0, 0, 0, 0 }\n};\n\n");
    fprintf(fd, "#endif\n");
    fclose(fd);
    printf("  [ saved ref table to %s (%d refs)\n", out_file, n_refs);
    (void)map;
    (void)n_sec;
}

/**
void bin2array(void *map, char *fname, void *bin, uint32_t len) {
    char      label[32], file[32], *str;
    uint32_t  i;
    uint32_t  *p=(uint32_t*)bin;
    FILE      *fd;
    
    memset(label, 0, sizeof(label));
    memset(file,  0, sizeof(file));
    
#if defined(WINDOWS)
    str = PathFindFileName(fname);
#else
    str = basename(fname);
#endif
    for(i=0; str[i] != 0 && i < 24;i++) {
      if(str[i] == '.') {
        file[i] = label[i] = '_';
      } else {
        label[i] = toupper(str[i]);
        file[i]  = tolower(str[i]);
      }
    }
    
    strcat(file, ".h");
    
    fd = fopen(file, "wb");
    
    if(fd != NULL) {
      // align up by 4
      len = (len & -4) + 4;
      len >>= 2;
      
      // declare the array
      fprintf(fd, "\nunsigned int %s[%i];\n\n", label, len);
    
      // initialize array
      for(i=0; i<len; i++) {
        fprintf(fd, "%s[%i] = 0x%08" PRIX32 ";\n", label, i, p[i]);
      }
      fclose(fd);
      printf("  [ Saved array to %s\n", file);
    } else printf("  [ unable to create file : %s\n", file);    
}
*/
// structure of COFF (.obj) file

//--------------------------//
// IMAGE_FILE_HEADER        //
//--------------------------//
// IMAGE_SECTION_HEADER     //
//  * num sections          //
//--------------------------//
//                          //
//                          //
//                          //
// section data             //
//  * num sections          //
//                          //
//                          //
//--------------------------//
// IMAGE_SYMBOL             //
//  * num symbols           //
//--------------------------//
// string table             //
//--------------------------//

int main (int argc, char *argv[]) {
    int                        i;
    FILE                       *fp;
    struct stat                fs;
    uint8_t                    *map, *cs;
    PIMAGE_SECTION_HEADER      sh;
    //PIMAGE_FILE_HEADER         fh;
    //PIMAGE_COFF_SYMBOLS_HEADER csh;
    uint32_t                   ofs, len;
    
    if (argc != 2) {
      printf ("\n  [ usage: file2h <file.exe | file.bin>\n");
      return 0;
    }

    printf("  [ Opening file for reading: %s\n", argv[1]);
    
    // open file for reading
    fp = fopen(argv[1], "r");
    
    if(fp == NULL) {
      printf("  [ Unable to open %s\n", argv[1]);
      return 0;
    } else {
      printf("  [ File opened.\n");
    }

    // get file info
    fstat(fileno(fp), &fs);

    // if file has some data
    if(fs.st_size > 0) {
      printf("  [ Reading file: %s\n", argv[1]);
      // map into memory
      map = (uint8_t*)mmap(NULL, fs.st_size,
        PROT_READ, MAP_PRIVATE, fileno(fp), 0);
      if(map != NULL) {
        if(valid_dos_hdr(map) && valid_nt_hdr(map)) {
          printf("  [ Found valid DOS and NT header.\n");
          sh = SecHdr(map);
          if(sh != NULL) {
            /* Enumerate every code section (IMAGE_SCN_CNT_CODE). For
               multi-section MSVC builds (per-function PE sections via
               loader/include/poly_section.h), call pack_extract() to
               produce a tightly-packed blob: cross-section RIP-rel
               displacements are rewritten, hot per-function sections
               are kept page-aligned, and inter-section gaps are filled
               with random bytes (not 0x90) so the post-XOR ciphertext
               doesn't expose a repeating-pattern signature.

               Single-section builds (mingw/gcc) and the LDE-fallback
               path use the original RVA-preserving extraction. */
            pack_sec_t psecs[PACK_MAX_SECTIONS];
            int code_count = 0;
            int default_text_idx = -1;

            printf("  [ Scanning for code sections (IMAGE_SCN_CNT_CODE).\n");
            for(i=0; i<SecSize(map) && code_count < PACK_MAX_SECTIONS; i++) {
              if(sh[i].Characteristics & IMAGE_SCN_CNT_CODE) {
                pack_sec_t *ps = &psecs[code_count];
                memset(ps->name, 0, sizeof(ps->name));
                memcpy(ps->name, sh[i].Name, 8);
                ps->vaddr     = sh[i].VirtualAddress;
                ps->vsize     = sh[i].Misc.VirtualSize;
                ps->file_off  = sh[i].PointerToRawData;
                ps->copy_size = sh[i].Misc.VirtualSize;
                if(ps->copy_size > sh[i].SizeOfRawData)
                  ps->copy_size = sh[i].SizeOfRawData;
                ps->new_offset = 0;
                /* Default ".text" stays at offset 0 (it contains the
                   PE entry, e.g. FritterLoader pinned at .text$a, which
                   must be at blob+0). Other sections may be reordered. */
                if(strncmp((char*)sh[i].Name, ".text", 5) == 0 && default_text_idx < 0) {
                  default_text_idx = code_count;
                }
                /* Per-function sections (anything other than .text) are
                   tagged single-page: they contain backward-branch hot
                   loops (cipher, hash chain, depack) that must not
                   straddle a 4 KiB boundary at runtime under the VEH
                   sliding window. */
                ps->single_page = (strncmp((char*)sh[i].Name, ".text", 5) != 0);
                code_count++;
                printf("  [   section '%.8s' rva=0x%x size=0x%x\n",
                    sh[i].Name, sh[i].VirtualAddress, sh[i].Misc.VirtualSize);
              }
            }

            if(code_count == 0) {
              printf("  [ no code sections found.\n");
            } else {
              uint32_t blob_size = 0;
              uint8_t  *blob = NULL;
              pack_ref_t *refs = NULL;
              int n_refs = 0;

              /* Ensure .text (entry-point section) is at index 0 for the
                 packer's "first section fixed at offset 0" convention. */
              if(default_text_idx > 0) {
                pack_sec_t tmp = psecs[0];
                psecs[0] = psecs[default_text_idx];
                psecs[default_text_idx] = tmp;
              }

              if(code_count > 1) {
                blob = pack_extract(map, psecs, code_count, &blob_size,
                                    &refs, &n_refs);
              }

              if(blob == NULL) {
                /* Single section, or packer failed: RVA-preserving
                   extraction. Gaps between sections (if any) are
                   filled with the same deterministic-random byte
                   stream as the packer uses, NOT with 0x90 - long
                   NOP runs are a YARA-able fingerprint and the
                   per-page XOR encryption converts a NOP run into
                   a repeating-8-byte-ciphertext signature that's
                   even more distinctive. */
                uint32_t base_rva = 0xFFFFFFFFu, end_rva = 0u;
                for(i = 0; i < code_count; i++) {
                  uint32_t s_end = psecs[i].vaddr + psecs[i].vsize;
                  if(psecs[i].vaddr < base_rva) base_rva = psecs[i].vaddr;
                  if(s_end > end_rva) end_rva = s_end;
                }
                blob_size = end_rva - base_rva;
                blob = (uint8_t*)malloc(blob_size);
                if(blob != NULL) {
                  pack_random_fill(blob, blob_size, map, &psecs[0]);
                  for(i = 0; i < code_count; i++) {
                    uint32_t blob_ofs = psecs[i].vaddr - base_rva;
                    memcpy(blob + blob_ofs,
                           map + psecs[i].file_off,
                           psecs[i].copy_size);
                  }
                  printf("  [ assembled %d code section(s) into %u-byte blob (RVA-preserving, random fill).\n",
                      code_count, blob_size);
                }
              }

              if(blob != NULL) {
                bin2h(map, argv[1], blob, blob_size);
                bin2go(map, argv[1], blob, blob_size);
                /* Emit companion tables. Single-section path (packer skipped)
                   still gets a valid fn_table with one entry at offset 0 and
                   an empty ref_table, fritter's build_loader can then treat
                   both paths uniformly. */
                if(code_count == 1) {
                  psecs[0].new_offset = 0;
                }
                emit_fn_table_h(map, argv[1], psecs, code_count);
                emit_ref_table_h(map, argv[1], refs, n_refs, psecs, code_count);
                free(blob);
                if(refs) free(refs);
              } else {
                printf("  [ allocation failed for %u-byte blob.\n", blob_size);
                if(refs) free(refs);
              }
            }
            (void)ofs; (void)cs; (void)len;
          }
        } else {
          printf("  [ No valid DOS or NT header found.\n");
          // treat file as binary
          bin2h(NULL, argv[1], map, fs.st_size);
		  bin2go(NULL, argv[1], map, fs.st_size);
          //bin2array(NULL, argv[1], map, fs.st_size);
        }
        munmap(map, fs.st_size);
      }
    }
    fclose(fp);
    return 0;
}
