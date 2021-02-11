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

const static auto ntdll_base = GetModuleHandle(L"ntdll.dll");

NTSTATUS
NTAPI
NtWow64QueryInformationProcess64(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength) {
    static auto p = decltype(&NtWow64QueryInformationProcess64)(GetProcAddress(ntdll_base, "NtWow64QueryInformationProcess64"));
    return p(
        ProcessHandle,
        ProcessInformationClass,
        ProcessInformation,
        ProcessInformationLength,
        ReturnLength
    );
}

NTSTATUS
NTAPI
NtWow64ReadVirtualMemory64(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID64 BaseAddress,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG64 BufferSize,
    _Out_opt_ PULONG64 NumberOfBytesRead) {
    static auto p = decltype(&NtWow64ReadVirtualMemory64)(GetProcAddress(ntdll_base, "NtWow64ReadVirtualMemory64"));
    return p(
        ProcessHandle,
        BaseAddress,
        Buffer,
        BufferSize,
        NumberOfBytesRead
    );
}

NTSTATUS
NTAPI
NtWow64WriteVirtualMemory64(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID64 BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONGLONG BufferSize,
    _Out_opt_ PULONGLONG NumberOfBytesWritten) {
    static auto p = decltype(&NtWow64WriteVirtualMemory64)(GetProcAddress(ntdll_base, "NtWow64WriteVirtualMemory64"));
    return p(
        ProcessHandle,
        BaseAddress,
        Buffer,
        BufferSize,
        NumberOfBytesWritten
    );
}
