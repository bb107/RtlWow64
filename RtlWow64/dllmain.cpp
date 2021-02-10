#include "RtlNative.h"
#include "RtlWow64.h"

extern PVOID64 ntdll64;
extern PVOID64 LdrGetDllHandle;
extern PVOID64 LdrGetProcedureAddress;

extern HANDLE RtlpWow64ExecutableHeap;
 
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        BOOL success = FALSE;
        IsWow64Process(GetCurrentProcess(), &success);

        if (success) {
            RtlpWow64ExecutableHeap = RtlCreateHeap(HEAP_CREATE_ENABLE_EXECUTE | HEAP_GROWABLE, nullptr, 0, 0, nullptr, nullptr);
            if (NT_SUCCESS(RtlpGetModuleHandleWow64(&ntdll64, "ntdll.dll"))) {
                if (NT_SUCCESS(RtlpGetProcAddressWow64(&LdrGetDllHandle, ntdll64, "LdrGetDllHandle"))) {
                    if (NT_SUCCESS(RtlpGetProcAddressWow64(&LdrGetProcedureAddress, ntdll64, "LdrGetProcedureAddress"))) {
                        return TRUE;
                    }
                }
            }
        }

        if (RtlpWow64ExecutableHeap) {
            RtlDestroyHeap(RtlpWow64ExecutableHeap);
        }
        return FALSE;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
    {
        RtlDestroyHeap(RtlpWow64ExecutableHeap);
    }
    }
    return TRUE;
}

