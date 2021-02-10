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
