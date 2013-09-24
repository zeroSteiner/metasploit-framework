/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of the  nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "install_hook.h"

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>

typedef NTSTATUS (NTAPI *lNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

PEB *get_peb_addr(HANDLE hProcess) {
	HMODULE hNtdll = 0;
	FARPROC pNtQueryInformationProcess = NULL;
	PROCESS_BASIC_INFORMATION proc_info;

	hNtdll = LoadLibraryA("ntdll");
	if (!hNtdll) {
		return NULL;
	}

	pNtQueryInformationProcess = (lNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!pNtQueryInformationProcess) {
		FreeLibrary(hNtdll);
		return NULL;
	}

	if (pNtQueryInformationProcess(hProcess, 0, &proc_info, sizeof(proc_info), NULL) != STATUS_SUCCESS) {
		FreeLibrary(hNtdll);
		return NULL;
	}
	FreeLibrary(hNtdll);
	return proc_info.PebBaseAddress;
}

int local_install_inline_hook_by_name(const char *module_name, const char *function_name, unsigned char *shellcode, size_t shellcode_sz, void **new_address) {
	HMODULE h_mod = NULL;
	DWORD protect;
	MEMORY_BASIC_INFORMATION mbi_thunk;
	PBYTE buffer = NULL;
	void *old_address = NULL;

	if (!(h_mod = LoadLibrary(module_name))) {
		return 1;
	}

	if (!(old_address = GetProcAddress(h_mod, function_name))) {
		return 2;
	}

	if ((memcmp(old_address, "\x8b\xff\x55\x8b\xec", 5) != 0) && (memcmp(old_address, "\x89\xff\x55\x89\xe5", 5) != 0)) {
		return 3;
	}

	buffer = VirtualAlloc(NULL, shellcode_sz + 32, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (new_address) {
		*new_address = buffer;
	}

	*(DWORD *)(buffer) = 0x90e58960;     /* pushad; mov ebp, esp; nop */
	*(DWORD *)(buffer + 4) = 0x9020c583; /* add ebp, 0x20; nop */
	buffer += 8;
	memcpy(buffer, shellcode, shellcode_sz);
	buffer += shellcode_sz;
	*buffer = 0x61;                       /* popad */
	*(DWORD *)(buffer + 1) = 0xe9e58955;
	*(DWORD *)(buffer + 5) = (DWORD)old_address - ((DWORD)buffer + 4);
	buffer -= (shellcode_sz + 8);

	/* Fix protection */
	VirtualQuery(old_address, &mbi_thunk, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, PAGE_EXECUTE_READWRITE, &mbi_thunk.Protect);

	/* Insert jump */
	*(PBYTE)old_address = 0xe9;
	*(DWORD *)((PBYTE)old_address + 1) = (DWORD)buffer - ((DWORD)old_address + 5);

	/* Restore protection */
	VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, mbi_thunk.Protect, &protect);
	FlushInstructionCache((HANDLE)-1, mbi_thunk.BaseAddress, mbi_thunk.RegionSize);
	return 0;
}
