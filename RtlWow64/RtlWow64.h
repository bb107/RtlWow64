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

NTSTATUS NTAPI RtlGetNativeProcAddressWow64(
	_Out_ PVOID64* __ptr64 FunctionAddress,
	_In_ LPCSTR FunctionName
);

NTSTATUS NTAPI RtlLoadLibraryWow64(
	_Out_ PVOID64* __ptr64 ModuleHandle,
	_In_ LPCWSTR ModuleName
);

NTSTATUS NTAPI RtlLoadKernel32X64(
	_Out_ PVOID64* __ptr64 ModuleHandle
);

NTSTATUS NTAPI RtlInvokeX64(
	_Out_opt_ PULONG64 Result,
	_In_ PVOID64 FunctionAddress,
	_In_opt_ ULONG64* Parameters,
	_In_ DWORD ParameterCount
);
