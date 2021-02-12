#include "../RtlWow64/RtlWow64.h"
#include "../RtlWow64/RtlNative.h"
#include <cstdio>

extern "C" {
    NTSYSCALLAPI
    NTSTATUS
    NTAPI
    NtQueryInformationProcess(
        _In_ HANDLE ProcessHandle,
        _In_ PROCESSINFOCLASS ProcessInformationClass,
        _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
        _In_ ULONG ProcessInformationLength,
        _Out_opt_ PULONG ReturnLength
    );
}

BOOL CheckDebuggerNormal() {
    PVOID ptr = nullptr;
    NTSTATUS status = NtQueryInformationProcess(
        HANDLE(-1),
        PROCESSINFOCLASS::ProcessDebugPort,
        &ptr,
        sizeof(ptr),
        nullptr
    );

    return !(NT_SUCCESS(status) && ULONG(ptr) != -1);
}

BOOL CheckDebuggerWow64() {
    ULONG64 p[6]{ -1,ULONG64(PROCESSINFOCLASS::ProcessDebugPort),ULONG64(&p[5]),sizeof(p[5]),0 };
    PVOID64 _NtQueryInformationProcess;
    NTSTATUS status = RtlGetNativeProcAddressWow64(
        &_NtQueryInformationProcess,
        "NtQueryInformationProcess"
    );
    BOOL result = TRUE;

    if (NT_SUCCESS(status)) {
        status = RtlInvokeX64(nullptr, _NtQueryInformationProcess, &p[0], 5);
        result = !(NT_SUCCESS(status) && p[5] != -1);
    }

    return result;
}

int main() {
    printf("CheckDebugger:\n\tNormal:\t%s\n\tWow64:\t%s\n",
        CheckDebuggerNormal() ? "Debugger found" : "No debugger found",
        CheckDebuggerWow64() ? "Debugger found" : "No debugger found"
    );
	
	return 0;
}
