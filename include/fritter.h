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

#ifndef FRITTER_H
#define FRITTER_H

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>
#include <limits.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#ifndef LOADER_H
#include "mmap.h"
#endif
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#define strcasecmp stricmp
#endif
#else
#define LINUX
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "pe.h"
#endif

#ifndef LOADER_H

#if defined(DEBUG)
 #define DPRINT(...) { \
   fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
   fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT(...) // Don't do anything in release builds
#endif

#endif

#include "errors.h"      // Fritter errors
#include "hash.h"        // api hashing
#include "encrypt.h"     // symmetric encryption of instance+module
#include "format.h"      // output format for loader
#include "aplib.h"       // aPLib compression for both windows + linux

#ifndef MAX_PATH
 #define MAX_PATH 260
#endif

#if !defined(WINDOWS)
#define strnicmp(x,y,z) strncasecmp(x,y,z)
typedef uint64_t ULONG64, *PULONG64;
typedef uint32_t DWORD, *PDWORD;
typedef uint16_t WORD, *PWORD;
typedef uint8_t  BYTE, *PBYTE;

typedef char     CHAR, *PCHAR;
typedef size_t SIZE_T;

typedef struct _GUID {
  DWORD Data1;
  WORD  Data2;
  WORD  Data3;
  BYTE  Data4[8];
} GUID;
#endif

#define FRITTER_KEY_LEN                    16
#define FRITTER_BLK_LEN                    16

// target architecture
#define FRITTER_ARCH_X64                   2  // AMD64

// module type
#define FRITTER_MODULE_NET_DLL             1  // .NET DLL. Requires class and method
#define FRITTER_MODULE_NET_EXE             2  // .NET EXE. Executes Main if no class and method provided
#define FRITTER_MODULE_DLL                 3  // Unmanaged DLL, function is optional
#define FRITTER_MODULE_EXE                 4  // Unmanaged EXE
#define FRITTER_MODULE_VBS                 5  // VBScript
#define FRITTER_MODULE_JS                  6  // JavaScript or JScript

// format type
#define FRITTER_FORMAT_BINARY              1
#define FRITTER_FORMAT_BASE64              2
#define FRITTER_FORMAT_C                   3
#define FRITTER_FORMAT_RUBY                4
#define FRITTER_FORMAT_PYTHON              5
#define FRITTER_FORMAT_POWERSHELL          6
#define FRITTER_FORMAT_CSHARP              7
#define FRITTER_FORMAT_HEX                 8
#define FRITTER_FORMAT_UUID                9

// compression engine
#define FRITTER_COMPRESS_NONE              1
#define FRITTER_COMPRESS_APLIB             2

// entropy level
#define FRITTER_ENTROPY_NONE               1  // don't use any entropy
#define FRITTER_ENTROPY_RANDOM             2  // use random names
#define FRITTER_ENTROPY_DEFAULT            3  // use random names + symmetric encryption

// misc options
#define FRITTER_OPT_EXIT_THREAD            1  // after the main shellcode ends, return to the caller which eventually calls RtlExitUserThread
#define FRITTER_OPT_EXIT_PROCESS           2  // after the main shellcode ends, call RtlExitUserProcess to terminate host process
#define FRITTER_OPT_EXIT_BLOCK             3  // after the main shellcode ends, do not exit or cleanup and block indefinitely

// Preserve PE headers options
#define FRITTER_HEADERS_OVERWRITE          1  // Overwrite PE headers
#define FRITTER_HEADERS_KEEP               2  // Preserve PE headers

#define FRITTER_MAX_NAME                 256  // maximum length of string for domain, class, method and parameter names
#define FRITTER_MAX_DLL                    8  // maximum number of DLL supported by instance
#define FRITTER_SIG_LEN                    8  // 64-bit string to verify decryption ok
#define FRITTER_VER_LEN                   32
#define FRITTER_DOMAIN_LEN                 8

#define FRITTER_RUNTIME_NET2 "v2.0.50727"
#define FRITTER_RUNTIME_NET4 "v4.0.30319"

#define NTDLL_DLL    "ntdll.dll"
#define KERNEL32_DLL "kernel32.dll"
#define KERNELBASE_DLL "kernelbase.dll"
#define ADVAPI32_DLL "advapi32.dll"
#define CRYPT32_DLL  "crypt32.dll"
#define MSCOREE_DLL  "mscoree.dll"
#define OLE32_DLL    "ole32.dll"
#define OLEAUT32_DLL "oleaut32.dll"
#define COMBASE_DLL  "combase.dll"
#define USER32_DLL   "user32.dll"
#define SHLWAPI_DLL  "shlwapi.dll"
#define SHELL32_DLL  "shell32.dll"

// Per the ECMA spec, the section data looks like this:
// taken from https://github.com/dotnet/coreclr/
//
typedef struct tagMDSTORAGESIGNATURE {
    ULONG       lSignature;             // "Magic" signature.
    USHORT      iMajorVer;              // Major file version.
    USHORT      iMinorVer;              // Minor file version.
    ULONG       iExtraData;             // Offset to next structure of information 
    ULONG       iVersionString;         // Length of version string
    BYTE        pVersion[0];            // Version string
} MDSTORAGESIGNATURE, *PMDSTORAGESIGNATURE;

// 
typedef struct _file_info_t {
    int      fd;
    uint32_t len, zlen;
    uint8_t  *data, *zdata;
    
    // the following are set for unmanaged or .NET PE/DLL files
    int      type;    
    int      arch;
    char     ver[FRITTER_VER_LEN];       
} file_info;

typedef struct _API_IMPORT {
    const char *module;
    const char *name;
} API_IMPORT, *PAPI_IMPORT;

typedef struct _FRITTER_CRYPT {
    uint8_t  mk[FRITTER_KEY_LEN];   // master key
    uint8_t  ctr[FRITTER_BLK_LEN];  // counter + nonce
} FRITTER_CRYPT, *PFRITTER_CRYPT;

// everything required for a module goes in the following structure
typedef struct _FRITTER_MODULE {
    int      type;                            // EXE/DLL/JS/VBS
    int      thread;                          // run entrypoint of unmanaged EXE as a thread
    int      compress;                        // indicates engine used for compression
    
    char     runtime[FRITTER_MAX_NAME];         // runtime version for .NET EXE/DLL
    char     domain[FRITTER_MAX_NAME];          // domain name to use for .NET EXE/DLL
    char     cls[FRITTER_MAX_NAME];             // name of class and optional namespace for .NET EXE/DLL
    char     method[FRITTER_MAX_NAME];          // name of method to invoke for .NET DLL or api for unmanaged DLL
    
    char     args[FRITTER_MAX_NAME];            // string arguments for both managed and unmanaged DLL/EXE
    int      unicode;                         // convert param to unicode for unmanaged DLL function
    int      imgbase;                         // point PEB.ImageBaseAddress at an unmanaged EXE while it runs
    
    char     sig[FRITTER_SIG_LEN];              // string to verify decryption
    uint64_t mac;                             // hash of sig, to verify decryption was ok
    
    uint32_t zlen;                            // compressed size of EXE/DLL/JS/VBS file
    uint32_t len;                             // real size of EXE/DLL/JS/VBS file
    uint32_t sum;                             // checksum of the real file contents
    uint8_t  data[4];                         // data of EXE/DLL/JS/VBS file
} FRITTER_MODULE, *PFRITTER_MODULE;

// everything required for an instance goes into the following structure
// Mask stub page (last page of the shellcode): qword slots at its start.
// The first holds the offsets of its two entries (call, exit) as words.
#define FRITTER_MASK_TARGET  1   // function the call entry forwards to
#define FRITTER_MASK_VP      2   // VirtualProtect
#define FRITTER_MASK_PBASE   3   // first page that loses execute while masked
#define FRITTER_MASK_PLEN    4   // bytes from there to the stub page
#define FRITTER_MASK_HOOK    5   // exit entry: where the entering thread goes
#define FRITTER_MASK_TID     6   // exit entry: id of the entering thread
#define FRITTER_MASK_THREAD  7   // exit entry: where any other thread goes
#define FRITTER_MASK_RET     8   // stub's own: return address, four arguments, state
#define FRITTER_MASK_ARGS    9
#define FRITTER_MASK_FLAG    13
#define FRITTER_MASK_IBASE   14  // second masked range: the instance
#define FRITTER_MASK_ICNT    15  // its length in dwords (0: none)
#define FRITTER_MASK_SP      16  // return stack: entries in use
#define FRITTER_MASK_IRET    17  // inbound entry: where it returns to
#define FRITTER_MASK_NIN     18  // inbound thunks handed out
#define FRITTER_MASK_STK     19  // return stack (masked calls and inbound calls nest)
#define FRITTER_MASK_NSTK    8
#define FRITTER_MASK_TGT     27  // inbound thunk targets
#define FRITTER_MASK_NTGT    56
#define FRITTER_MASK_SLOTS   83

#define FRITTER_KEY_ENVS            4    // environment variables a key can depend on
#define FRITTER_KEY_BRUTE_DEFAULT   22   // key bits the loader has to find by trial unless told otherwise
#define FRITTER_KEY_BRUTE_MAX       32

// Integrity value of an instance: the hash of sig, combined with checksums
// of everything from api_cnt up to mac and of the module after it.
#define FRITTER_MAC(inst) (maru((inst)->sig, (inst)->iv) ^ \
    (uint64_t)mod_sum(&(inst)->api_cnt, (uint32_t)(offsetof(FRITTER_INSTANCE, mac) - offsetof(FRITTER_INSTANCE, api_cnt))) ^ \
    ((uint64_t)mod_sum(&(inst)->module, (inst)->len - (uint32_t)offsetof(FRITTER_INSTANCE, module)) << 32))

#define FRITTER_PLAIN_MASK(inst, n) ((uint32_t)((inst)->iv >> ((n) * 8)))

typedef struct _FRITTER_INSTANCE {
    uint32_t    len;                          // total size of instance
    FRITTER_CRYPT key;                          // decrypts instance if encryption enabled

    uint64_t    iv;                           // the 64-bit initial value for maru hash

    union {
      uint64_t  hash[64];                     // holds up to 64 api hashes
      void     *addr[64];                     // holds up to 64 api addresses
      // include prototypes only if header included from loader.h
      #ifdef LOADER_H
      // Typed function-pointer view of api[]. Field order is generated
      // per build by tools/gen_api_shuffle into include/api_shuffle.h
      // from the canonical list in include/api_master.h. Slot 0 is
      // pinned as LoadLibraryA (loader.c resolves it explicitly).
      struct {
        #define XAPI(dll, name, type, field) type field;
        #include "api_shuffle.h"
        #undef XAPI
      };
      #endif
    } api;
    
    // The five words below are read before the instance is decrypted. They
    // are stored xor a slice of the hash IV (FRITTER_PLAIN_MASK), so that
    // default settings do not leave the same bytes in every output.
    int         exit_opt;                     // 1 to call RtlExitUserProcess and terminate the host process, 2 to never exit or cleanup and block
    int         entropy;                      // indicates entropy level
    uint32_t    oep;                          // original entrypoint
    uint32_t    pic_off;                      // offset of this instance inside the shellcode
    uint32_t    pic_len;                      // total size of the shellcode
    uint64_t    hook;                         // exit hook block inside the shim (set by the loader)
    
    // Instance key options (--key-*). With any of them the key above is not
    // the key: kopt says what is missing (also stored xor FRITTER_PLAIN_MASK).
    uint16_t    kopt;                         // low byte: key bits left out; bits 8..11: kenv slots in use
    uint16_t    kpad[3];                      // random
    uint64_t    kchk;                         // check value of the real key
    uint64_t    kenv[FRITTER_KEY_ENVS];       // name hashes of the environment variables mixed into the key

    // everything from here is encrypted
    int         api_cnt;                      // the 64-bit hashes of API required for instance to work
    uint64_t    api_skip;                     // API slots this payload type does not use (left unresolved)
    char        dll_names[FRITTER_MAX_NAME];    // a list of DLL strings to load, separated by semi-colon
    
    char        dataname[8];                  // ".data"
    char        kernelbase[12];               // "kernelbase"
    
    char        cmd_syms[FRITTER_MAX_NAME];     // symbols related to command line
    char        exit_api[FRITTER_MAX_NAME];     // exit-related API
    
    int         headers;                      // indicates whether to overwrite PE headers
    uint64_t    pcfh_hash;                    // maru hash of "RtlPcToFileHeader" (import redirected for C++ EH)
    uint8_t     eh_stub[128];                 // generated stub that answers RtlPcToFileHeader for the payload image
    uint8_t     eh_len;                       // its length
    uint8_t     eh_base;                      // offset of the image base (imm64)
    uint8_t     eh_size;                      // offset of the image size (imm32)
    uint8_t     eh_real;                      // offset of the real function (imm64)
    uint32_t    eh_pos;                       // random draw for where the stub is placed
    uint64_t    eh_key[2];                    // the two imm64 values are stored xor these
    uint64_t    gpa_hash;                     // maru hash of "GetProcAddress"
    uint64_t    term_hash;                    // maru hash of "TerminateProcess"
    uint8_t     tp_stub[64];                  // generated stub that stands in for TerminateProcess
    uint8_t     tp_len;                       // its length
    uint8_t     tp_exit;                      // offset of the exit replacement (imm64)
    uint8_t     tp_real;                      // offset of the real function (imm64)
    uint8_t     gp_stub[128];                 // generated stub that stands in for GetProcAddress
    uint8_t     gp_len;                       // its length
    uint8_t     gp_real;                      // offset of the real function (imm64)
    uint8_t     gp_frame;                     // bytes of stack it allocates (for its unwind data)
    uint8_t     gp_from[3];                   // offsets of the results it swaps (imm64) ...
    uint8_t     gp_to[3];                     // ... and of what it returns instead (imm64)
    uint8_t     mask;                         // the shellcode ends with a mask stub page
    uint64_t    pic_base;                     // runtime address of the shellcode (set by the loader)
    
    char        wscript[8];                   // WScript
    char        wscript_exe[12];              // wscript.exe

    char        decoy[MAX_PATH * 2];            // path of decoy module
    char        tls_donor[FRITTER_MAX_NAME];    // DLL whose static TLS slot the payload borrows

    GUID        xIID_IUnknown;
    GUID        xIID_IDispatch;
    
    // GUID required to load .NET assemblies
    GUID        xCLSID_CLRMetaHost;
    GUID        xIID_ICLRMetaHost;  
    GUID        xIID_ICLRRuntimeInfo;
    GUID        xCLSID_CorRuntimeHost;
    GUID        xIID_ICorRuntimeHost;
    GUID        xIID_AppDomain;
    
    // GUID required to run VBS and JS files
    GUID        xCLSID_ScriptLanguage;         // vbs or js
    GUID        xIID_IHost;                    // wscript object
    GUID        xIID_IActiveScript;            // engine
    GUID        xIID_IActiveScriptSite;        // implementation
    GUID        xIID_IActiveScriptSiteWindow;  // basic GUI stuff
    GUID        xIID_IActiveScriptParse32;     // parser
    GUID        xIID_IActiveScriptParse64;
    
    uint8_t     sig[FRITTER_MAX_NAME];        // string to hash
    uint64_t    mac;                        // FRITTER_MAC: verifies decryption and every byte from api_cnt on

    // The module is always embedded at the tail of the instance and is
    // covered by the instance encryption. (HTTP staging was removed.)
    struct {
      FRITTER_MODULE  x;
    } module;
} FRITTER_INSTANCE, *PFRITTER_INSTANCE;

typedef struct _FRITTER_CONFIG {
    uint32_t        len, zlen;                // original length of input file and compressed length
    // general / misc options for loader
    int             arch;                     // target architecture
    int             headers;                  // preserve PE headers option
    int             entropy;                  // entropy/encryption level
    int             format;                   // output format for loader
    int             exit_opt;                 // return to caller, invoke RtlExitUserProcess to terminate the host process, or block indefinitely
    int             thread;                   // run entrypoint of unmanaged EXE as a thread. attempts to intercept calls to exit-related API
    uint32_t        oep;                      // original entrypoint of target host file
    
    // files in/out
    char            input[FRITTER_MAX_NAME];    // name of input file to read and load in-memory
    char            output[FRITTER_MAX_NAME];   // name of output file to save loader
    
    // .NET stuff
    char            runtime[FRITTER_MAX_NAME];  // runtime version to use for CLR
    char            domain[FRITTER_MAX_NAME];   // name of domain to create for .NET DLL/EXE
    char            cls[FRITTER_MAX_NAME];      // name of class with optional namespace for .NET DLL
    char            method[FRITTER_MAX_NAME];   // name of method or DLL function to invoke for .NET DLL and unmanaged DLL
    
    // command line for DLL/EXE
    char            args[FRITTER_MAX_NAME];    // command line to use for unmanaged DLL/EXE and .NET DLL/EXE
    int             unicode;                  // param is passed to DLL function without converting to unicode
    int             chunked;                  // 0=2-stage RW->RX, 1=VEH sliding window (default)
    int             imgbase;                  // point PEB.ImageBaseAddress at an unmanaged EXE while it runs
    int             allow_tls;                // accept a payload that uses static thread-local storage (unsupported by the loader)

    // module overloading stuff
    char            decoy[2056];                  // path of decoy module
    char            tls_donor[256];           // DLL whose static TLS slot the payload borrows
    int             key_brute;                // instance key bits left for the loader to find (0 = default, -1 = none)
    char            key_env[4][256];          // "NAME=VALUE": environment variables the instance key depends on
    
    // FRITTER_MODULE
    int             mod_type;                 // VBS/JS/DLL/EXE
    int             mod_len;                  // size of FRITTER_MODULE
    FRITTER_MODULE    *mod;                     // points to FRITTER_MODULE
    
    // FRITTER_INSTANCE
    int             inst_len;               // size of FRITTER_INSTANCE
    FRITTER_INSTANCE  *inst;                    // points to FRITTER_INSTANCE
    
    // shellcode generated from configuration
    int             pic_len;                  // size of loader/shellcode
    void*           pic;                      // points to loader/shellcode
} FRITTER_CONFIG, *PFRITTER_CONFIG;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DLL
#define EXPORT_FUNC __declspec(dllexport)
#else
#define EXPORT_FUNC
#endif

// public functions
EXPORT_FUNC int FritterCreate(PFRITTER_CONFIG);
EXPORT_FUNC int FritterDelete(PFRITTER_CONFIG);
EXPORT_FUNC const char* FritterError(int);

#ifdef __cplusplus
}
#endif

#endif
