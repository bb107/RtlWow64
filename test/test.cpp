#include "../RtlWow64/RtlWow64.h"
#include "../RtlWow64/RtlNative.h"
#include <cstdio>

int main() {
	PVOID64 hModule;
	if (NT_SUCCESS(RtlLoadKernel32X64(&hModule))) {
		printf("0x%016llx\n", ULONG64(hModule));

		PVOID64 _GetVersion = nullptr;
		if (NT_SUCCESS(RtlGetProcAddressWow64(&_GetVersion, hModule, "GetVersion"))) {
			ULONG64 p = 0;
			RtlInvokeX64(&p, _GetVersion, nullptr, 0);

            DWORD dwVersion = p;
            DWORD dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
            DWORD dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));
            DWORD dwBuild = dwVersion < 0x80000000 ? (DWORD)(HIWORD(dwVersion)) : 0;

            printf("Version is %d.%d (%d)\n", dwMajorVersion, dwMinorVersion, dwBuild);
		}
	}
	

	return 0;
}
