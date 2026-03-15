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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#else
#define LINUX
#include <unistd.h>
#include <dlfcn.h>
#endif

// error codes
#define FRITTER_ERROR_OK                   0
#define FRITTER_ERROR_FILE_NOT_FOUND       1
#define FRITTER_ERROR_FILE_EMPTY           2
#define FRITTER_ERROR_FILE_ACCESS          3
#define FRITTER_ERROR_FILE_INVALID         4
#define FRITTER_ERROR_NET_PARAMS           5
#define FRITTER_ERROR_NO_MEMORY            6
#define FRITTER_ERROR_INVALID_ARCH         7
#define FRITTER_ERROR_INVALID_URL          8
#define FRITTER_ERROR_URL_LENGTH           9
#define FRITTER_ERROR_INVALID_PARAMETER   10
#define FRITTER_ERROR_RANDOM              11
#define FRITTER_ERROR_DLL_FUNCTION        12
#define FRITTER_ERROR_ARCH_MISMATCH       13
#define FRITTER_ERROR_DLL_PARAM           14
#define FRITTER_ERROR_RESERVED_15         15
#define FRITTER_ERROR_INVALID_FORMAT      16
#define FRITTER_ERROR_INVALID_ENGINE      17
#define FRITTER_ERROR_COMPRESSION         18
#define FRITTER_ERROR_INVALID_ENTROPY     19
#define FRITTER_ERROR_MIXED_ASSEMBLY      20
#define FRITTER_ERROR_HEADERS_INVALID     21
#define FRITTER_ERROR_DECOY_INVALID       22

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
#define FRITTER_OPT_EXIT_THREAD            1  // return to the caller which calls RtlExitUserThread
#define FRITTER_OPT_EXIT_PROCESS           2  // call RtlExitUserProcess to terminate host process
#define FRITTER_OPT_EXIT_BLOCK             3  // after the main shellcode ends, do not exit or cleanup and block indefinitely

// instance type
#define FRITTER_INSTANCE_EMBED             1  // Module is embedded
#define FRITTER_INSTANCE_HTTP              2  // Module is downloaded from remote HTTP/HTTPS server

// Preserve PE headers options
#define FRITTER_HEADERS_OVERWRITE          1  // Overwrite PE headers
#define FRITTER_HEADERS_KEEP               2  // Preserve PE headers

#define FRITTER_MAX_NAME                 256  // maximum length of string for domain, class, method and parameter names
#define FRITTER_MAX_DLL                    8  // maximum number of DLL supported by instance
#define FRITTER_MAX_MODNAME                8
#define FRITTER_SIG_LEN                    8  // 64-bit string to verify decryption ok
#define FRITTER_VER_LEN                   32
#define FRITTER_DOMAIN_LEN                 8

typedef struct _FRITTER_CONFIG {
    uint32_t        len, zlen;                // original length of input file and compressed length
    // general / misc options for loader
    int             arch;                     // target architecture
    int             headers;                  // preserve PE headers option
    int             entropy;                  // entropy/encryption level
    int             format;                   // output format for loader
    int             exit_opt;                 // return to caller or invoke RtlExitUserProcess to terminate the host process
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
    char            args[FRITTER_MAX_NAME];     // command line to use for unmanaged DLL/EXE and .NET DLL/EXE
    int             unicode;                  // param is passed to DLL function without converting to unicode
    int             chunked;                  // 0=2-stage RW->RX, 1=VEH sliding window (default)

    // module overloading stuff
    char            decoy[2056];              // path of decoy module

    // HTTP staging information
    char            server[FRITTER_MAX_NAME];   // points to root path of where module will be stored on remote HTTP server
    char            auth[FRITTER_MAX_NAME];     // username and password for web server
    char            modname[FRITTER_MAX_NAME];  // name of module written to disk for http stager

    // FRITTER_MODULE
    int             mod_type;                 // VBS/JS/DLL/EXE
    int             mod_len;                  // size of FRITTER_MODULE
    void            *mod;                     // points to FRITTER_MODULE

    // FRITTER_INSTANCE
    int             inst_type;                // FRITTER_INSTANCE_EMBED or FRITTER_INSTANCE_HTTP
    int             inst_len;                 // size of FRITTER_INSTANCE
    void            *inst;                    // points to FRITTER_INSTANCE

    // shellcode generated from configuration
    int             pic_len;                  // size of loader/shellcode
    void*           pic;                      // points to loader/shellcode
} FRITTER_CONFIG, *PFRITTER_CONFIG;

// function pointers
typedef int (__cdecl *FritterCreate_t)(PFRITTER_CONFIG);
typedef int (__cdecl *FritterDelete_t)(PFRITTER_CONFIG);
typedef const char* (__cdecl *FritterError_t)(int);

#ifdef __cplusplus
extern "C" {
#endif

// prototypes
int FritterCreate(PFRITTER_CONFIG);
int FritterDelete(PFRITTER_CONFIG);
const char* FritterError(int);

#ifdef __cplusplus
}
#endif

#endif
