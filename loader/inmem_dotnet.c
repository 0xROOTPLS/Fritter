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

// The host calls below that take time or load images (runtime start-up,
// domain creation, assembly load, domain unload) go through the mask stub
// when there is one: none of their arguments points into the loader or the
// instance. MaskCall returns the function itself otherwise.
typedef HRESULT (STDMETHODCALLTYPE *NetStart_t)(PVOID);
typedef HRESULT (STDMETHODCALLTYPE *NetCreateDomain_t)(PVOID, LPCWSTR, PVOID, PVOID);
typedef HRESULT (STDMETHODCALLTYPE *NetLoad_t)(PVOID, SAFEARRAY*, PVOID);
typedef HRESULT (STDMETHODCALLTYPE *NetUnload_t)(PVOID, PVOID);

// Wipe and free a string the loader allocated for an argument.
static VOID FreeBstr(PFRITTER_INSTANCE inst, BSTR b) {
    DWORD i;
    if(b == NULL) return;
    for(i=0; b[i] != 0; i++) b[i] = 0;
    inst->api.SysFreeString(b);
}

// Wipe and free what CommandLineToArgvW returned.
static VOID FreeArgv(PFRITTER_INSTANCE inst, WCHAR **argv, int argc) {
    int i, j;
    if(argv == NULL) return;
    for(i=0; i<argc; i++)
      for(j=0; argv[i][j] != 0; j++) argv[i][j] = 0;
    inst->api.LocalFree((HLOCAL)argv);
}

BOOL LoadAssembly(PFRITTER_INSTANCE inst, PFRITTER_MODULE mod, PFRITTER_ASSEMBLY pa) {
    HRESULT         hr = S_OK;
    BSTR            domain;
    SAFEARRAYBOUND  sab;
    SAFEARRAY       *sa;
    BOOL            loaded=FALSE, loadable;
    WCHAR           buf[FRITTER_MAX_NAME];
    
    if(inst->api.CLRCreateInstance != NULL) {
      DPRINT("CLRCreateInstance");
      
      hr = inst->api.CLRCreateInstance(
       (REFCLSID)&inst->xCLSID_CLRMetaHost, 
       (REFIID)&inst->xIID_ICLRMetaHost, 
       (LPVOID*)&pa->icmh);
      
      if(SUCCEEDED(hr)) {
        DPRINT("ICLRMetaHost::GetRuntime(\"%s\")", mod->runtime);
        ansi2unicode(inst, mod->runtime, buf);
        
        hr = pa->icmh->lpVtbl->GetRuntime(
          pa->icmh, buf, 
          (REFIID)&inst->xIID_ICLRRuntimeInfo, (LPVOID)&pa->icri);
        
        if(SUCCEEDED(hr)) {
          DPRINT("ICLRRuntimeInfo::IsLoadable");
          hr = pa->icri->lpVtbl->IsLoadable(pa->icri, &loadable);
        
          if(SUCCEEDED(hr) && loadable) {
            DPRINT("ICLRRuntimeInfo::GetInterface");
          
            hr = pa->icri->lpVtbl->GetInterface(
              pa->icri, 
              (REFCLSID)&inst->xCLSID_CorRuntimeHost, 
              (REFIID)&inst->xIID_ICorRuntimeHost, 
              (LPVOID)&pa->icrh);
              
            DPRINT("HRESULT: %08lx", hr);
          }
        } else pa->icri = NULL;
      } else pa->icmh = NULL;
    }
    // fall back on CorBindToRuntime when CLRCreateInstance isn't available
    // or for example when the above code failed.
    // pa->icrh == NULL also covers IsLoadable succeeding with loadable ==
    // FALSE, which leaves hr == S_OK without ever calling GetInterface.
    if(FAILED(hr) || inst->api.CLRCreateInstance == NULL || pa->icrh == NULL) {
      DPRINT("Trying CorBindToRuntime");

      // ask for the runtime the assembly was built for; with no version
      // the shim binds the oldest installed runtime (v2 if present)
      buf[0] = 0;
      if(mod->runtime[0] != 0) ansi2unicode(inst, mod->runtime, buf);
      
      hr = inst->api.CorBindToRuntime(
        buf[0] != 0 ? buf : NULL,
        NULL,  // load workstation build
        &inst->xCLSID_CorRuntimeHost,
        &inst->xIID_ICorRuntimeHost,
        (LPVOID*)&pa->icrh);
      
      DPRINT("HRESULT: %08lx", hr);
    }
    
    if(FAILED(hr) || pa->icrh == NULL) {
      pa->icrh = NULL;
      return FALSE;
    }
    DPRINT("ICorRuntimeHost::Start");
    
    hr = ((NetStart_t)MaskCall(inst, (PVOID)pa->icrh->lpVtbl->Start))(pa->icrh);
    
    if(SUCCEEDED(hr)) {     
      // if no domain name specified
      if(mod->domain[0] == 0) {
        DPRINT("ICorRuntimeHost::GetDefaultDomain()");
        // use the default
        hr = pa->icrh->lpVtbl->GetDefaultDomain(pa->icrh, &pa->iu);
      } else {
        // else create a new domain using the name
        DPRINT("Domain is %s", mod->domain);
        ansi2unicode(inst, mod->domain, buf);
        domain = inst->api.SysAllocString(buf);
      
        DPRINT("ICorRuntimeHost::CreateDomain(\"%ws\")", buf);
      
        hr = ((NetCreateDomain_t)MaskCall(inst, (PVOID)pa->icrh->lpVtbl->CreateDomain))(
          pa->icrh, domain, NULL, &pa->iu);
        
        inst->api.SysFreeString(domain);
      }
      
      if(SUCCEEDED(hr)) {
        DPRINT("IUnknown::QueryInterface");
        
        hr = pa->iu->lpVtbl->QueryInterface(
          pa->iu, (REFIID)&inst->xIID_AppDomain, (LPVOID)&pa->ad);
          
        if(SUCCEEDED(hr)) {
          sab.lLbound   = 0;
          sab.cElements = mod->len;
          sa = inst->api.SafeArrayCreate(VT_UI1, 1, &sab);
          
          if(sa != NULL) {
            DPRINT("Copying %" PRIi32 " bytes of assembly to safe array", mod->len);
            
            Memcpy(sa->pvData, mod->data, mod->len);

            DPRINT("AppDomain::Load_3");

            hr = ((NetLoad_t)MaskCall(inst, (PVOID)pa->ad->lpVtbl->Load_3))(
              pa->ad, sa, &pa->as);
            
            loaded = hr == S_OK;
            
            DPRINT("HRESULT : %08lx", hr);
            
            DPRINT("Erasing assembly from memory");
            
            Memset(sa->pvData, 0, mod->len);
            Memset(mod->data,  0, mod->len);
            
            DPRINT("SafeArrayDestroy");
            inst->api.SafeArrayDestroy(sa);
          }
        }
      }
    }
    return loaded;
}
    
BOOL RunAssembly(PFRITTER_INSTANCE inst, PFRITTER_MODULE mod, PFRITTER_ASSEMBLY pa) {
    SAFEARRAY     *sav=NULL, *args=NULL;
    VARIANT       arg, ret, vtPsa, v1={0}, v2;
    DWORD         i;
    HRESULT       hr;
    BOOL          mk;
    PVOID         im;
    BSTR          cls, method;
    ULONG         cnt;
    LONG          ucnt, lcnt;
    WCHAR         **argv, buf[FRITTER_MAX_NAME+1];
    int           argc;
    
    DPRINT("Type is %s", 
      mod->type == FRITTER_MODULE_NET_DLL ? "DLL" : "EXE");
    
    // if this is a program
    if(mod->type == FRITTER_MODULE_NET_EXE) {
      // get the entrypoint
      DPRINT("MethodInfo::EntryPoint");
      hr = pa->as->lpVtbl->EntryPoint(pa->as, &pa->mi);
      
      if(SUCCEEDED(hr)) {
        // get the parameters for entrypoint
        DPRINT("MethodInfo::GetParameters");
        hr = pa->mi->lpVtbl->GetParameters(pa->mi, &args);
        
        if(SUCCEEDED(hr)) {
          DPRINT("SafeArrayGetLBound");
          hr = inst->api.SafeArrayGetLBound(args, 1, &lcnt);
          
          DPRINT("SafeArrayGetUBound");
          hr = inst->api.SafeArrayGetUBound(args, 1, &ucnt);
          cnt = ucnt - lcnt + 1;
          DPRINT("Number of parameters for entrypoint : %i", cnt);
          
          inst->api.SafeArrayDestroy(args);   // only the count was needed
          vtPsa.parray = NULL;

          // does Main require string[] args?
          if(cnt != 0) {
            // create a 1 dimensional array for Main parameters
            sav = inst->api.SafeArrayCreateVector(VT_VARIANT, 0, 1);
            // if user specified their own parameters, add to string array
            if(mod->args[0] != 0) {
              ansi2unicode(inst, mod->args, buf);
              argv = inst->api.CommandLineToArgvW(buf, &argc);
              Memset(buf, 0, sizeof(buf));
              if(argv == NULL) argc = 0;
              // create 1 dimensional array for strings[] args
              vtPsa.vt     = (VT_ARRAY | VT_BSTR);
              vtPsa.parray = inst->api.SafeArrayCreateVector(VT_BSTR, 0, argc);

              // add each string parameter (the array takes a copy)
              for(i=0; vtPsa.parray != NULL && i<(DWORD)argc; i++) {
                DPRINT("Adding \"%ws\" as parameter %i", argv[i], (i + 1));
                cls = inst->api.SysAllocString(argv[i]);
                inst->api.SafeArrayPutElement(vtPsa.parray, &i, cls);
                FreeBstr(inst, cls);
              }
              FreeArgv(inst, argv, argc);
            } else {
              DPRINT("No parameters: passing an empty string[]");
              // Main(string[] args) with no arguments receives an empty
              // array, as it would from the command line
              vtPsa.vt     = (VT_ARRAY | VT_BSTR);
              vtPsa.parray = inst->api.SafeArrayCreateVector(VT_BSTR, 0, 0);
            }
            // add string array to list of parameters
            i=0;
            if(sav != NULL && vtPsa.parray != NULL)
              inst->api.SafeArrayPutElement(sav, &i, &vtPsa);
          }
          v1.vt    = VT_NULL;
          v1.plVal = NULL;

          DPRINT("MethodInfo::Invoke_3()\n");

          // nothing below needs a protected loader function until the
          // managed code returns
          if(cnt != 0 && (sav == NULL || vtPsa.parray == NULL)) {
            hr = E_OUTOFMEMORY;   // no arguments to call Main with
          } else if(MaskBase(inst) != NULL) {
            hr = ((HRESULT (STDMETHODCALLTYPE *)(MethodInfo*, VARIANT, SAFEARRAY*, VARIANT*))
                  MaskCall(inst, (PVOID)pa->mi->lpVtbl->Invoke_3))(pa->mi, v1, sav, &v2);
          } else {
            ParkLoader(inst, PARK_CODE);
            hr = pa->mi->lpVtbl->Invoke_3(pa->mi, v1, sav, &v2);
            ParkLoader(inst, PARK_OFF);
          }
          
          DPRINT("MethodInfo::Invoke_3 : %08lx : %s", 
            hr, SUCCEEDED(hr) ? "Success" : "Failed");
            
          if(vtPsa.parray != NULL) inst->api.SafeArrayDestroy(vtPsa.parray);
          if(sav != NULL)          inst->api.SafeArrayDestroy(sav);
        }
      } else pa->mi = NULL;
    } else {
      ansi2unicode(inst, mod->cls, buf);
      cls = inst->api.SysAllocString(buf);
      if(cls == NULL) return FALSE;
      DPRINT("Class: SysAllocString(\"%ws\")", buf);
      
      ansi2unicode(inst, mod->method, buf);
      method = inst->api.SysAllocString(buf);
      DPRINT("Method: SysAllocString(\"%ws\")", buf);
      
      if(method != NULL) {
        DPRINT("Assembly::GetType_2");
        hr = pa->as->lpVtbl->GetType_2(pa->as, cls, &pa->type);
        
        if(SUCCEEDED(hr)) {
          sav = NULL;
          DPRINT("Parameters: %s", mod->args);
          
          if(mod->args[0] != 0) {
            ansi2unicode(inst, mod->args, buf);
            argv = inst->api.CommandLineToArgvW(buf, &argc);
            Memset(buf, 0, sizeof(buf));
            if(argv == NULL) argc = 0;
            DPRINT("SafeArrayCreateVector(%li argument(s))", argc);

            sav = inst->api.SafeArrayCreateVector(VT_VARIANT, 0, argc);

            if(sav != NULL) {
              for(i=0; i<(DWORD)argc; i++) {
                DPRINT("Adding \"%ws\" as argument %i", argv[i], (i+1));

                V_BSTR(&arg) = inst->api.SysAllocString(argv[i]);
                V_VT(&arg)   = VT_BSTR;

                // the array takes a copy
                hr = inst->api.SafeArrayPutElement(sav, &i, &arg);
                FreeBstr(inst, V_BSTR(&arg));

                if(FAILED(hr)) {
                  DPRINT("SafeArrayPutElement failed.");
                  inst->api.SafeArrayDestroy(sav);
                  sav = NULL;
                  break;
                }
              }
            } else hr = E_OUTOFMEMORY;
            FreeArgv(inst, argv, argc);
          }
          if(SUCCEEDED(hr)) {
            DPRINT("Calling Type::InvokeMember_3");
            
            mk = (MaskBase(inst) != NULL);
            im = (PVOID)pa->type->lpVtbl->InvokeMember_3;
            if(mk) im = MaskCall(inst, im);
            else   ParkLoader(inst, PARK_CODE);
            hr = ((HRESULT (STDMETHODCALLTYPE *)(Type*, BSTR, BindingFlags, IBinder*, VARIANT, SAFEARRAY*, VARIANT*))im)(
                pa->type, 
                method,   // name of method 
                BindingFlags_InvokeMethod | 
                BindingFlags_Static       | 
                BindingFlags_Public,
                NULL, 
                v1,       // empty VARIANT
                sav,      // arguments to method
                &ret);    // return code from method
            if(!mk) ParkLoader(inst, PARK_OFF);

            DPRINT("Type::InvokeMember_3 : %08lx : %s", 
              hr, SUCCEEDED(hr) ? "Success" : "Failed");
              
            if(sav != NULL) {
              inst->api.SafeArrayDestroy(sav);
            }
          }
        }
        inst->api.SysFreeString(method);
      }
      inst->api.SysFreeString(cls);
    }
    return TRUE;
}
  
VOID FreeAssembly(PFRITTER_INSTANCE inst, PFRITTER_ASSEMBLY pa) {
    HRESULT hr;
    
    if(pa->type != NULL) {
      DPRINT("Type::Release");
      hr = pa->type->lpVtbl->Release(pa->type);
      pa->type = NULL;
      DPRINT("HRESULT : %08lX", hr);
    }

    if(pa->mi != NULL) {
      DPRINT("MethodInfo::Release");
      hr = pa->mi->lpVtbl->Release(pa->mi);
      pa->mi = NULL;
      DPRINT("HRESULT : %08lX", hr);
    }
    
    if(pa->as != NULL) {
      DPRINT("Assembly::Release");
      hr = pa->as->lpVtbl->Release(pa->as);
      pa->as = NULL;
      DPRINT("HRESULT : %08lX", hr);
    }
    
    if(pa->icrh != NULL) {
      DPRINT("ICorRuntimeHost::UnloadDomain");
      hr = ((NetUnload_t)MaskCall(inst, (PVOID)pa->icrh->lpVtbl->UnloadDomain))(pa->icrh, (IUnknown*)pa->ad);      
      DPRINT("HRESULT : %08lX", hr);
      
      DPRINT("ICorRuntimeHost::Stop");
      hr = pa->icrh->lpVtbl->Stop(pa->icrh);
      DPRINT("HRESULT : %08lX", hr);
      
      DPRINT("ICorRuntimeHost::Release");
      hr = pa->icrh->lpVtbl->Release(pa->icrh);
      pa->icrh = NULL;
      DPRINT("HRESULT : %08lX", hr);
    }
    
    if(pa->ad != NULL) {
      DPRINT("AppDomain::Release");
      hr = pa->ad->lpVtbl->Release(pa->ad);
      pa->ad = NULL;
      DPRINT("HRESULT : %08lX", hr);
    }

    if(pa->iu != NULL) {
      DPRINT("IUnknown::Release");
      hr = pa->iu->lpVtbl->Release(pa->iu);
      pa->iu = NULL;
      DPRINT("HRESULT : %08lX", hr);
    }
    
    if(pa->icri != NULL) {
      DPRINT("ICLRRuntimeInfo::Release");
      hr = pa->icri->lpVtbl->Release(pa->icri);
      pa->icri = NULL;
      DPRINT("HRESULT : %08lX", hr);
    }
    
    if(pa->icmh != NULL) {
      DPRINT("ICLRMetaHost::Release");
      hr = pa->icmh->lpVtbl->Release(pa->icmh);
      pa->icmh = NULL;
      DPRINT("HRESULT : %08lX", hr);
    }
}
