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
extern PVOID64 LdrLoadDll;
extern PVOID64 LdrGetDllHandle;
extern PVOID64 LdrGetProcedureAddress;

extern HANDLE RtlpWow64ExecutableHeap;

NTSTATUS NTAPI RtlpInitialize() {
    NTSTATUS status = STATUS_SUCCESS;

    // ntdll 64bit handle
    status = RtlpGetModuleHandleWow64(&ntdll64, "ntdll.dll");
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // ntdll!LdrLoadDll
    status = RtlpGetProcAddressWow64(&LdrLoadDll, ntdll64, "LdrLoadDll");
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // ntdll!LdrGetDllHandle
    status = RtlpGetProcAddressWow64(&LdrGetDllHandle, ntdll64, "LdrGetDllHandle");
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // ntdll!LdrGetProcedureAddress
    status = RtlpGetProcAddressWow64(&LdrGetProcedureAddress, ntdll64, "LdrGetProcedureAddress");
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlpWow64ExecutableHeap = RtlCreateHeap(
        HEAP_CREATE_ENABLE_EXECUTE | HEAP_GROWABLE,
        nullptr,
        0,
        0,
        nullptr,
        nullptr
    );
    if (!RtlpWow64ExecutableHeap) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return status;
}
 
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        BOOL success = FALSE;
        IsWow64Process(GetCurrentProcess(), &success);

        if (success) {
            if (NT_SUCCESS(RtlpInitialize())) {
                return TRUE;
            }
        }

        if (RtlpWow64ExecutableHeap) {
            RtlDestroyHeap(RtlpWow64ExecutableHeap);
            RtlpWow64ExecutableHeap = nullptr;
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

