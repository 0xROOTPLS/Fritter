/*
 * Canonical master list of APIs Fritter resolves at runtime.
 *
 * Format: XAPI(dll, name, type, field)
 *   dll   = DLL constant (KERNEL32_DLL etc.)
 *   name  = export name string used for hash (must match Windows export)
 *   type  = function-pointer typedef from loader/winapi.h
 *   field = field name in FRITTER_INSTANCE.api typed struct
 *
 * Slot 0 (LoadLibraryA) MUST stay first — loader.c resolves it
 * explicitly before the DLL-loading loop. Everything else can be
 * shuffled per build by tools/gen_api_shuffle, which preserves the
 * pin and randomizes order 1..N.
 *
 * Adding an API: append a new XAPI line. Both fritter.h's typed
 * struct and fritter.c's api_imports[] are generated from this
 * file via the X-macro pattern, so they cannot disagree.
 */

XAPI(KERNEL32_DLL, "LoadLibraryA",                LoadLibraryA_t,                LoadLibraryA)
XAPI(KERNEL32_DLL, "GetProcAddress",              GetProcAddress_t,              GetProcAddress)
XAPI(KERNEL32_DLL, "GetModuleHandleA",            GetModuleHandleA_t,            GetModuleHandleA)
XAPI(KERNEL32_DLL, "VirtualAlloc",                VirtualAlloc_t,                VirtualAlloc)
XAPI(KERNEL32_DLL, "VirtualFree",                 VirtualFree_t,                 VirtualFree)
XAPI(KERNEL32_DLL, "VirtualQuery",                VirtualQuery_t,                VirtualQuery)
XAPI(KERNEL32_DLL, "VirtualProtect",              VirtualProtect_t,              VirtualProtect)
XAPI(KERNEL32_DLL, "Sleep",                       Sleep_t,                       Sleep)
XAPI(KERNEL32_DLL, "MultiByteToWideChar",         MultiByteToWideChar_t,         MultiByteToWideChar)
XAPI(KERNEL32_DLL, "GetUserDefaultLCID",          GetUserDefaultLCID_t,          GetUserDefaultLCID)
XAPI(KERNEL32_DLL, "WaitForSingleObject",         WaitForSingleObject_t,         WaitForSingleObject)
XAPI(KERNEL32_DLL, "CreateThread",                CreateThread_t,                CreateThread)
XAPI(KERNEL32_DLL, "CreateFileA",                 CreateFileA_t,                 CreateFileA)
XAPI(KERNEL32_DLL, "GetFileSizeEx",               GetFileSizeEx_t,               GetFileSizeEx)
XAPI(KERNEL32_DLL, "GetThreadContext",            GetThreadContext_t,            GetThreadContext)
XAPI(KERNEL32_DLL, "GetCurrentThread",            GetCurrentThread_t,            GetCurrentThread)
XAPI(KERNEL32_DLL, "GetCurrentProcess",           GetCurrentProcess_t,           GetCurrentProcess)
XAPI(KERNEL32_DLL, "GetCommandLineA",             GetCommandLineA_t,             GetCommandLineA)
XAPI(KERNEL32_DLL, "GetCommandLineW",             GetCommandLineW_t,             GetCommandLineW)
XAPI(KERNEL32_DLL, "HeapAlloc",                   HeapAlloc_t,                   HeapAlloc)
XAPI(KERNEL32_DLL, "HeapReAlloc",                 HeapReAlloc_t,                 HeapReAlloc)
XAPI(KERNEL32_DLL, "GetProcessHeap",              GetProcessHeap_t,              GetProcessHeap)
XAPI(KERNEL32_DLL, "HeapFree",                    HeapFree_t,                    HeapFree)
XAPI(KERNEL32_DLL, "GetLastError",                GetLastError_t,                GetLastError)
XAPI(KERNEL32_DLL, "CloseHandle",                 CloseHandle_t,                 CloseHandle)

XAPI(SHELL32_DLL,  "CommandLineToArgvW",          CommandLineToArgvW_t,          CommandLineToArgvW)

XAPI(OLEAUT32_DLL, "SafeArrayCreate",             SafeArrayCreate_t,             SafeArrayCreate)
XAPI(OLEAUT32_DLL, "SafeArrayCreateVector",       SafeArrayCreateVector_t,       SafeArrayCreateVector)
XAPI(OLEAUT32_DLL, "SafeArrayPutElement",         SafeArrayPutElement_t,         SafeArrayPutElement)
XAPI(OLEAUT32_DLL, "SafeArrayDestroy",            SafeArrayDestroy_t,            SafeArrayDestroy)
XAPI(OLEAUT32_DLL, "SafeArrayGetLBound",          SafeArrayGetLBound_t,          SafeArrayGetLBound)
XAPI(OLEAUT32_DLL, "SafeArrayGetUBound",          SafeArrayGetUBound_t,          SafeArrayGetUBound)
XAPI(OLEAUT32_DLL, "SysAllocString",              SysAllocString_t,              SysAllocString)
XAPI(OLEAUT32_DLL, "SysFreeString",               SysFreeString_t,               SysFreeString)
XAPI(OLEAUT32_DLL, "LoadTypeLib",                 LoadTypeLib_t,                 LoadTypeLib)

XAPI(WININET_DLL,  "InternetCrackUrlA",           InternetCrackUrl_t,            InternetCrackUrl)
XAPI(WININET_DLL,  "InternetOpenA",               InternetOpen_t,                InternetOpen)
XAPI(WININET_DLL,  "InternetConnectA",            InternetConnect_t,             InternetConnect)
XAPI(WININET_DLL,  "InternetSetOptionA",          InternetSetOption_t,           InternetSetOption)
XAPI(WININET_DLL,  "InternetReadFile",            InternetReadFile_t,            InternetReadFile)
XAPI(WININET_DLL,  "InternetCloseHandle",         InternetCloseHandle_t,         InternetCloseHandle)
XAPI(WININET_DLL,  "InternetQueryDataAvailable",  InternetQueryDataAvailable_t,  InternetQueryDataAvailable)
XAPI(WININET_DLL,  "HttpOpenRequestA",            HttpOpenRequest_t,             HttpOpenRequest)
XAPI(WININET_DLL,  "HttpSendRequestA",            HttpSendRequest_t,             HttpSendRequest)
XAPI(WININET_DLL,  "HttpQueryInfoA",              HttpQueryInfo_t,               HttpQueryInfo)

XAPI(MSCOREE_DLL,  "CorBindToRuntime",            CorBindToRuntime_t,            CorBindToRuntime)
XAPI(MSCOREE_DLL,  "CLRCreateInstance",           CLRCreateInstance_t,           CLRCreateInstance)

XAPI(OLE32_DLL,    "CoInitializeEx",              CoInitializeEx_t,              CoInitializeEx)
XAPI(OLE32_DLL,    "CoCreateInstance",            CoCreateInstance_t,            CoCreateInstance)
XAPI(OLE32_DLL,    "CoUninitialize",              CoUninitialize_t,              CoUninitialize)

XAPI(NTDLL_DLL,    "RtlEqualUnicodeString",       RtlEqualUnicodeString_t,       RtlEqualUnicodeString)
XAPI(NTDLL_DLL,    "RtlEqualString",              RtlEqualString_t,              RtlEqualString)
XAPI(NTDLL_DLL,    "RtlUnicodeStringToAnsiString",RtlUnicodeStringToAnsiString_t,RtlUnicodeStringToAnsiString)
XAPI(NTDLL_DLL,    "RtlInitUnicodeString",        RtlInitUnicodeString_t,        RtlInitUnicodeString)
XAPI(NTDLL_DLL,    "RtlExitUserThread",           RtlExitUserThread_t,           RtlExitUserThread)
XAPI(NTDLL_DLL,    "RtlExitUserProcess",          RtlExitUserProcess_t,          RtlExitUserProcess)
XAPI(NTDLL_DLL,    "RtlCreateUnicodeString",      RtlCreateUnicodeString_t,      RtlCreateUnicodeString)
XAPI(NTDLL_DLL,    "NtContinue",                  NtContinue_t,                  NtContinue)
XAPI(NTDLL_DLL,    "NtCreateSection",             NtCreateSection_t,             NtCreateSection)
XAPI(NTDLL_DLL,    "NtMapViewOfSection",          NtMapViewOfSection_t,          NtMapViewOfSection)
XAPI(NTDLL_DLL,    "NtUnmapViewOfSection",        NtUnmapViewOfSection_t,        NtUnmapViewOfSection)
