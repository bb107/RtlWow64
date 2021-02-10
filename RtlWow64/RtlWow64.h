#pragma once
#include <Windows.h>

#define AccessViolationExceptionFilter() (GetExceptionCode()==STATUS_ACCESS_VIOLATION?EXCEPTION_EXECUTE_HANDLER:EXCEPTION_CONTINUE_SEARCH)

NTSTATUS NTAPI RtlpGetModuleHandleWow64(
	_Out_ PVOID64* __ptr64 ModuleHandle,
	_In_ LPCSTR ModuleName
);

NTSTATUS NTAPI RtlpGetProcAddressWow64(
	_Out_ PVOID64* __ptr64 FunctionAddress,
	_In_ PVOID64 ModuleHandle,
	_In_ LPCSTR FunctionName
);


NTSTATUS NTAPI RtlGetModuleHandleWow64(
	_Out_ PVOID64* __ptr64 ModuleHandle,
	_In_ LPCSTR ModuleName
);

NTSTATUS NTAPI RtlGetProcAddressWow64(
	_Out_ PVOID64* __ptr64 FunctionAddress,
	_In_ PVOID64 ModuleHandle,
	_In_ LPCSTR FunctionName
);

NTSTATUS NTAPI RtlInvokeX64(
	_Out_opt_ PULONG64 Result,
	_In_ PVOID64 FunctionAddress,
	_In_ ULONG64* Parameters,
	_In_ DWORD ParameterCount
);
