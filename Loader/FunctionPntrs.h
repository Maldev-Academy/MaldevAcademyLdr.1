#pragma once

#include <Windows.h>

// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
//
typedef HMODULE (WINAPI* fnLoadLibraryA)(IN LPCSTR lpLibFileName);


// https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-createthreadpooltimer
//
typedef PTP_TIMER (WINAPI* fnCreateThreadpoolTimer)(IN PTP_TIMER_CALLBACK pfnti, IN OUT OPTIONAL PVOID pv, IN OPTIONAL PTP_CALLBACK_ENVIRON pcbe);


// https://learn.microsoft.com/en-us/windows/win32/api/threadpoolapiset/nf-threadpoolapiset-setthreadpooltimer
//
typedef void (WINAPI* fnSetThreadpoolTimer)(IN OUT PTP_TIMER pti, IN OPTIONAL PFILETIME pftDueTime, IN DWORD msPeriod, IN DWORD msWindowLength);


// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
//
typedef DWORD (WINAPI* fnWaitForSingleObject)(IN HANDLE hHandle, IN DWORD dwMilliseconds);

