#pragma once


//
#define DEBUG


#ifdef DEBUG



VOID CreateDebugConsole();


#define ERROR_BUF_SIZE					(MAX_PATH * 2)
#define GET_FILENAME(path)				(strrchr(path, '\\') ? strrchr(path, '\\') + 1 : path)


#define PRINT( STR, ... )                                                                           \
    if (1) {                                                                                        \
        LPSTR cBuffer = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ERROR_BUF_SIZE);       \
        if (cBuffer){                                                                               \
            int iLength = wsprintfA(cBuffer, STR, __VA_ARGS__);                                     \
            WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), cBuffer, iLength, NULL, NULL);           \
            HeapFree(GetProcessHeap(), 0x00, cBuffer);                                              \
        }                                                                                           \
    }  

#endif // DEBUG
