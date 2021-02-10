# RtlWow64
c++ implementation of windows heavens gate

``` c++
#include "../RtlWow64/RtlWow64.h"
#include "../RtlWow64/RtlNative.h"
#include <cstdio>

PVOID64 WINAPI LdrLoadDll64(LPCWSTR lpModuleName) {
	PVOID64 hModule;
	PVOID64 LdrLoadDll;
	NTSTATUS status = RtlGetModuleHandleWow64(&hModule, "ntdll.dll");
	RtlGetProcAddressWow64(&LdrLoadDll, hModule, "LdrLoadDll");

	PVOID64 module = nullptr;
	UNICODE_STRING64 str;
	ULONG64 p[5] = { ULONG64(L"C:\\Windows\\System32"),0,ULONG64(&str),ULONG64(&module) };
	RtlInitUnicodeString64(&str, lpModuleName);

	RtlInvokeX64(&p[4], LdrLoadDll, &p[0], 4);
	return module;
}

int main() {
	auto hModule = LdrLoadDll64(L"ntdll.dll");
	printf("%llx\n", ULONG64(hModule));

	return 0;
}
```
