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

/*
 * PEB_WALK_ORDER selects which module list to traverse:
 *   0 = InLoadOrderModuleList (original fritter default)
 *   1 = InMemoryOrderModuleList
 *   2 = InInitializationOrderModuleList
 *
 * Default: 1 (InMemoryOrderModuleList)
 */
#ifndef PEB_WALK_ORDER
#define PEB_WALK_ORDER 1
#endif

/*
 * LOADER_PEB_DIR selects traversal direction within the chosen list:
 *   0 = Flink (forward)   1 = Blink (reverse)
 *
 * The PEB module lists are doubly-linked and circular; both directions
 * visit the full set and terminate at the head's sentinel DllBase==NULL.
 * Per-build pick from gen_poly diversifies the loader's PEB-walk byte
 * patterns without changing semantics.
 */
#ifndef LOADER_PEB_DIR
#define LOADER_PEB_DIR 0
#endif

#if LOADER_PEB_DIR
  #define PEB_LINK_FIELD Blink
#else
  #define PEB_LINK_FIELD Flink
#endif

/*
 * Helper macros to abstract the list + entry-to-LDR_DATA_TABLE_ENTRY conversion.
 *
 * InLoadOrderModuleList        links via offset 0  (InLoadOrderLinks)
 * InMemoryOrderModuleList      links via offset 1  (InMemoryOrderLinks)
 * InInitializationOrderModuleList links via offset 2 (InInitializationOrderLinks)
 *
 * Each list links at a different offset within LDR_DATA_TABLE_ENTRY.
 * We convert back to the base of the entry using CONTAINING_RECORD logic.
 */

#if PEB_WALK_ORDER == 0
  /* InLoadOrderModuleList */
  #define PEB_MODULE_LIST(ldr)   ((ldr)->InLoadOrderModuleList)
  #define PEB_ENTRY_TO_DTE(link) ((PLDR_DATA_TABLE_ENTRY)(link))
  #define PEB_NEXT_DTE(dte)      ((PLDR_DATA_TABLE_ENTRY)((dte)->InLoadOrderLinks.PEB_LINK_FIELD))
#elif PEB_WALK_ORDER == 1
  /* InMemoryOrderModuleList */
  #define PEB_MODULE_LIST(ldr)   ((ldr)->InMemoryOrderModuleList)
  #define PEB_ENTRY_TO_DTE(link) ((PLDR_DATA_TABLE_ENTRY)((PBYTE)(link) - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)))
  #define PEB_NEXT_DTE(dte)      ((PLDR_DATA_TABLE_ENTRY)((PBYTE)((dte)->InMemoryOrderLinks.PEB_LINK_FIELD) - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)))
#elif PEB_WALK_ORDER == 2
  /* InInitializationOrderModuleList */
  #define PEB_MODULE_LIST(ldr)   ((ldr)->InInitializationOrderModuleList)
  #define PEB_ENTRY_TO_DTE(link) ((PLDR_DATA_TABLE_ENTRY)((PBYTE)(link) - offsetof(LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks)))
  #define PEB_NEXT_DTE(dte)      ((PLDR_DATA_TABLE_ENTRY)((PBYTE)((dte)->InInitializationOrderLinks.PEB_LINK_FIELD) - offsetof(LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks)))
#else
  #error "PEB_WALK_ORDER must be 0, 1, or 2"
#endif

/* Head-link helper: yields the appropriate Flink/Blink of the chosen list head. */
#define PEB_HEAD_LINK(ldr) (PEB_MODULE_LIST(ldr).PEB_LINK_FIELD)

// find a DLL with a certain export, used by xGetProcAddress and FindExport
LOADER_FN_SECTION(SECTION_HASH_CHAIN)
LPVOID FindReference(PFRITTER_INSTANCE inst, LPVOID original_dll, PCHAR dll_name, PCHAR api_name) {
  PPEB                    peb;
  PPEB_LDR_DATA           ldr;
  PIMAGE_DOS_HEADER       dos;
  PIMAGE_NT_HEADERS       nt;
  PLDR_DATA_TABLE_ENTRY   dte;
  PIMAGE_DATA_DIRECTORY   dir;
  PIMAGE_EXPORT_DIRECTORY exp;
  LPVOID                  addr = NULL, base;
  DWORD                   rva, cnt;
  PDWORD                  adr;
  PDWORD                  sym;
  PWORD                   ord;
  PCHAR                   api;

  peb = GET_PEB();
  ldr = (PPEB_LDR_DATA)peb->Ldr;

  // for each DLL loaded
  for (dte = PEB_ENTRY_TO_DTE(PEB_HEAD_LINK(ldr));
       dte->DllBase != NULL && addr == NULL;
       dte = PEB_NEXT_DTE(dte))
  {
    base = dte->DllBase;
    // if this is the dll with the reference, continue
    if (base == original_dll) continue;

    addr = xGetProcAddress(inst, base, api_name, 0);
  }
  if (addr == NULL) {
    // we did not find the reference, use GetProcAddress
    HMODULE hModule = xGetLibAddress(inst, dll_name);

    if(hModule != NULL) {
      DPRINT("Calling GetProcAddress(%s)", api_name);
      addr = inst->api.GetProcAddress(hModule, api_name);
    } else addr = NULL;
  }

  return addr;
}

// If addr lies inside the export directory of base it is a forwarder
// string ("MODULE.Function"), not code: resolve what it names.
// Anything else is returned unchanged.
LOADER_FN_SECTION(SECTION_HASH_CHAIN)
static LPVOID ResolveForwarder(PFRITTER_INSTANCE inst, LPVOID base, PIMAGE_EXPORT_DIRECTORY exp, DWORD exp_size, LPVOID addr) {
  CHAR  dll_name[64];
  CHAR  api_name[128];
  DWORD i;
  PCHAR p;

  if ((PBYTE)addr <  (PBYTE)exp ||
      (PBYTE)addr >= (PBYTE)exp + exp_size) return addr;

  // copy DLL name to buffer
  p = (PCHAR)addr;

  for(i=0; p[i] != 0 && p[i] != '.' && i < sizeof(dll_name)-5; i++) {
    dll_name[i] = p[i];
  }
  // no separator, or the module name does not fit
  if(p[i] != '.') return NULL;

  dll_name[i]   = '.';
  dll_name[i+1] = 'd';
  dll_name[i+2] = 'l';
  dll_name[i+3] = 'l';
  dll_name[i+4] = 0;

  p += i + 1;

  // copy API name to buffer
  for(i=0; p[i] != 0 && i < sizeof(api_name)-1; i++) {
    api_name[i] = p[i];
  }
  api_name[i] = 0;

  return FindReference(inst, base, dll_name, api_name);
}

// search for an export in a DLL
LOADER_FN_SECTION(SECTION_HASH_CHAIN)
LPVOID xGetProcAddress(PFRITTER_INSTANCE inst, LPVOID base, PCHAR api_name, DWORD ordinal) {
  PIMAGE_DOS_HEADER       dos;
  PIMAGE_NT_HEADERS       nt;
  PIMAGE_DATA_DIRECTORY   dir;
  PIMAGE_EXPORT_DIRECTORY exp;
  LPVOID                  addr = NULL;
  DWORD                   rva, cnt;
  PDWORD                  adr;
  PDWORD                  sym;
  PWORD                   ord;
  PCHAR                   api;

  if (base == NULL) return NULL;

  dos = (PIMAGE_DOS_HEADER)base;
  nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
  dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
  rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

  // if no export table, return NULL
  if (rva==0) return NULL;

  exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
  adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
  sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
  ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);

  if (api_name != NULL) {
    // exported by name
    cnt = exp->NumberOfNames;
    // if no api names, return NULL
    if (cnt==0) return NULL;

    do {
      api = RVA2VA(PCHAR, base, sym[cnt-1]);
      // check if the export name matches the API we are looking for
      if (!_strcmp(api, api_name)) {
        // get the address of the API
        addr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
      }
    } while (--cnt && addr == NULL);
  } else {
    // exported by ordinal
    if (ordinal < exp->Base || ordinal - exp->Base >= exp->NumberOfFunctions) return NULL;
    rva = adr[ordinal - exp->Base];
    if (rva == 0) return NULL;
    addr = RVA2VA(PVOID, base, rva);
  }

  if (addr == NULL) return NULL;

  // is this a forward reference?
  addr = ResolveForwarder(inst, base, exp, dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size, addr);
  return addr;
}

// find a DLL by name, load it if not found
LOADER_FN_SECTION(SECTION_HASH_CHAIN)
LPVOID xGetLibAddress(PFRITTER_INSTANCE inst, PCHAR search) {
    PPEB                    peb;
    PPEB_LDR_DATA           ldr;
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    PLDR_DATA_TABLE_ENTRY   dte;
    PIMAGE_EXPORT_DIRECTORY exp;
    LPVOID                  addr = NULL, base;
    DWORD                   rva;
    PCHAR                   name;
    PCHAR                   lib = search;
    CHAR                    dll_name[64];
    DWORD                   i, len;
    int                     correct = -1;

    for(len=0; search[len] != 0; len++);
    if (len == 0) return NULL;

    // make sure the name ends with an extension; append '.dll' if not.
    // A name too long for the buffer is used as given.
    if ((len < 4 || search[len-4] != '.') && len + 5 <= sizeof(dll_name)) {
      Memcpy(dll_name, search, len);
      i = len;
      dll_name[i++] = '.';
      dll_name[i++] = 'd';
      dll_name[i++] = 'l';
      dll_name[i++] = 'l';
      dll_name[i]   = 0;
      lib = dll_name;
    }

    DPRINT("Searching for DLL in PEB: %s", lib);

    peb = GET_PEB();
    ldr = (PPEB_LDR_DATA)peb->Ldr;

    // for each DLL loaded
    for (dte = PEB_ENTRY_TO_DTE(PEB_HEAD_LINK(ldr));
         correct != 0 && dte->DllBase != NULL && addr == NULL;
         dte = PEB_NEXT_DTE(dte))
    {
      base = dte->DllBase;
      dos  = (PIMAGE_DOS_HEADER)base;
      nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
      rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      if (rva == 0) continue;

      exp  = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
      name = RVA2VA(PCHAR, base, exp->Name);

      correct = stricmp(lib, name);

      if (correct == 0) {
        addr = base;
      }
    }

    DPRINT("Address of DLL: %p", addr);

    // if the DLL was not found, load it
    if (addr == NULL) {
      addr = inst->api.LoadLibraryA(lib);
      DPRINT("Dll not found. Loaded %s via LoadLibrary at 0x%p", lib, addr);
    }
    return addr;
}

// locate address of API in export table using Maru hash function
LOADER_FN_SECTION(SECTION_HASH_CHAIN)
LPVOID FindExport(PFRITTER_INSTANCE inst, LPVOID base, ULONG64 api_hash, ULONG64 iv){
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    DWORD                   i, j, cnt, rva;
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD                  adr;
    PDWORD                  sym;
    PWORD                   ord;
    PCHAR                   api, dll;
    LPVOID                  addr=NULL;
    ULONG64                 dll_hash;
    CHAR                    buf[MAX_PATH];

    dos = (PIMAGE_DOS_HEADER)base;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // if no export table, return NULL
    if (rva==0) return NULL;

    exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
    cnt = exp->NumberOfNames;

    // if no api names, return NULL
    if (cnt==0) return NULL;

    adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
    sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
    ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);
    dll = RVA2VA(PCHAR, base, exp->Name);

    // get hash of DLL string converted to lowercase
    for(i=0;dll[i]!=0 && i<MAX_PATH-1;i++) {
      buf[i] = dll[i] | 0x20;
    }
    buf[i] = 0;
    dll_hash = maru(buf, iv);

    do {
      // calculate hash of api string
      api = RVA2VA(PCHAR, base, sym[cnt-1]);
      // xor with DLL hash and compare with hash to find
      if ((maru(api, iv) ^ dll_hash) == api_hash) {
        // return address of function
        addr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);

        // is this a forward reference?
        addr = ResolveForwarder(inst, base, exp, dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size, addr);
        return addr;
      }
    } while (--cnt && addr == NULL);

    return addr;
}

// search all modules in the PEB for API
LOADER_FN_SECTION(SECTION_HASH_CHAIN)
LPVOID xGetProcAddressByHash(PFRITTER_INSTANCE inst, ULONG64 ulHash, ULONG64 ulIV) {
    PPEB                  peb;
    PPEB_LDR_DATA         ldr;
    PLDR_DATA_TABLE_ENTRY dte;
    LPVOID                addr = NULL;

    peb = GET_PEB();
    ldr = (PPEB_LDR_DATA)peb->Ldr;

    // for each DLL loaded
    for (dte = PEB_ENTRY_TO_DTE(PEB_HEAD_LINK(ldr));
         dte->DllBase != NULL && addr == NULL;
         dte = PEB_NEXT_DTE(dte))
    {
      // search the export table for api
      addr = FindExport(inst, dte->DllBase, ulHash, ulIV);
    }
    return addr;
}

// Resolve inst->api slots [1, count) in a single pass: every export of
// every loaded module is hashed once and compared with all slots still
// open, instead of one full walk per API. Returns a bit mask of the
// slots that now hold an address; the others still hold their hash.
LOADER_FN_SECTION(SECTION_HASH_CHAIN)
ULONG64 xResolveApis(PFRITTER_INSTANCE inst, DWORD count) {
    PPEB                    peb;
    PPEB_LDR_DATA           ldr;
    PLDR_DATA_TABLE_ENTRY   dte;
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD                  adr, sym;
    PWORD                   ord;
    PCHAR                   dll;
    LPVOID                  base, addr;
    DWORD                   i, j, cnt, rva;
    ULONG64                 dll_hash, h, done = 0, want;
    CHAR                    buf[MAX_PATH];

    if (count > 64) count = 64;
    if (count < 2) return 0;

    // bits 1..count-1
    want = (count == 64) ? ~(ULONG64)1 : ((((ULONG64)1 << count) - 1) & ~(ULONG64)1);
    // slots this payload type does not use
    want &= ~inst->api_skip;

    peb = GET_PEB();
    ldr = (PPEB_LDR_DATA)peb->Ldr;

    for (dte = PEB_ENTRY_TO_DTE(PEB_HEAD_LINK(ldr));
         dte->DllBase != NULL && done != want;
         dte = PEB_NEXT_DTE(dte))
    {
      base = dte->DllBase;
      dos  = (PIMAGE_DOS_HEADER)base;
      nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
      dir  = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
      rva  = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      if (rva == 0) continue;

      exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
      cnt = exp->NumberOfNames;
      if (cnt == 0) continue;

      adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
      sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
      ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);
      dll = RVA2VA(PCHAR, base, exp->Name);

      // hash of the DLL name in lowercase, once per module
      for(i=0; dll[i]!=0 && i<MAX_PATH-1; i++) {
        buf[i] = dll[i] | 0x20;
      }
      buf[i] = 0;
      dll_hash = maru(buf, inst->iv);

      for (j=0; j<cnt && done != want; j++) {
        h = maru(RVA2VA(PCHAR, base, sym[j]), inst->iv) ^ dll_hash;

        for (i=1; i<count; i++) {
          if (((done | ~want) >> i) & 1) continue;
          if (inst->api.hash[i] != h) continue;

          addr = RVA2VA(LPVOID, base, adr[ord[j]]);
          addr = ResolveForwarder(inst, base, exp, dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size, addr);
          if (addr != NULL) {
            inst->api.addr[i] = addr;
            done |= (ULONG64)1 << i;
          }
          break;
        }
      }
    }
    return done;
}