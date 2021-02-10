// Copyright 2020 Boring
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

