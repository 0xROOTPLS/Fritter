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

#ifndef LOADER_H
#define LOADER_H

#if !defined(_MSC_VER)
#define __out_ecount_full(x)
#define __out_ecount_full_opt(x)
#include <inttypes.h>
#endif

#include <windows.h>
#include <wincrypt.h>
#include <oleauto.h>
#include <objbase.h>
#include <shlwapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#if defined(DEBUG)
#include <stdio.h>
#include <string.h>

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

 #define DPRINT(...) { \
   fprintf(stderr, "\nDEBUG: %s:%d:%s(): ", __FILENAME__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
 }
#else
 #define DPRINT(...) // Don't do anything in release builds
#endif

// Relative Virtual Address to Virtual Address
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

#define ADR(type, addr) (type)(addr)

void *Memset(void *ptr, int value, unsigned int num);
void *Memcpy(void *destination, const void *source, unsigned int num);
int Memcmp(const void *ptr1, const void *ptr2, unsigned int num);
int _strcmp(const char *s1, const char *s2);
NTSTATUS RtlUserThreadStart(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);

#if !defined(_MSC_VER)
#define memcmp(x,y,z) Memcmp(x,y,z)
#endif

#include "depack.h"
#include "peb.h"           // Process Environment Block
#include "winapi.h"        // Prototypes
#include "clr.h"           // Common Language Runtime Interface

#include "fritter.h"

#include "activescript.h"      // Interfaces for executing VBS/JS files
#include "wscript.h"           // Interfaces to support WScript object

typedef struct {
    IActiveScriptSite			  site;
    IActiveScriptSiteWindow siteWnd;
    IHost                   wscript;
    PFRITTER_INSTANCE         inst;      //  
} MyIActiveScriptSite;

// internal structure
typedef struct _FRITTER_ASSEMBLY {
    ICLRMetaHost    *icmh;
    ICLRRuntimeInfo *icri;
    ICorRuntimeHost *icrh;
    IUnknown        *iu;
    AppDomain       *ad;
    Assembly        *as;
    Type            *type;
    MethodInfo      *mi;
} FRITTER_ASSEMBLY, *PFRITTER_ASSEMBLY;

    // .NET DLL/EXE
    BOOL LoadAssembly(PFRITTER_INSTANCE, PFRITTER_MODULE, PFRITTER_ASSEMBLY);
    BOOL RunAssembly(PFRITTER_INSTANCE,  PFRITTER_MODULE, PFRITTER_ASSEMBLY);
    VOID FreeAssembly(PFRITTER_INSTANCE, PFRITTER_ASSEMBLY);

    // In-Memory execution of native DLL
    VOID RunPE(PFRITTER_INSTANCE, PFRITTER_MODULE);

// page protections of the shellcode's own memory
#define PARK_DATA 1   // instance pages -> RW (nothing executes there after entry)
#define PARK_CODE 2   // shim/loader pages -> RX while the payload runs
#define PARK_OFF  0   // shim/loader pages -> RWX again (dispatcher needs to write)
VOID ParkLoader(PFRITTER_INSTANCE, DWORD);
// Mask stub: MaskCall returns what to call instead of fn so that the whole
// loader is encrypted and non-executable until fn returns (fn itself when
// there is no stub; the caller then parks the loader instead).
PULONG64 MaskBase(PFRITTER_INSTANCE);
PVOID    MaskCall(PFRITTER_INSTANCE, PVOID);
// MaskIn returns what outside code should call instead of the loader
// function fn, so that the call works while the loader is masked.
PVOID    MaskIn(PFRITTER_INSTANCE, PVOID);
    
    // VBS / JS files
    VOID RunScript(PFRITTER_INSTANCE, PFRITTER_MODULE);
    
    LPVOID xGetProcAddressByHash(PFRITTER_INSTANCE, ULONGLONG, ULONGLONG);

    LPVOID xGetProcAddressByHash(PFRITTER_INSTANCE inst, ULONG64 ulHash, ULONG64 ulIV);
ULONG64 xResolveApis(PFRITTER_INSTANCE inst, DWORD count);

    LPVOID xGetLibAddress(PFRITTER_INSTANCE inst, PCHAR dll_name);

    LPVOID xGetProcAddress(PFRITTER_INSTANCE inst, LPVOID base, PCHAR api_name, DWORD ordinal);

#endif
