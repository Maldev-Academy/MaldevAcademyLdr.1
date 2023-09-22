#include <Windows.h>

#include "Debug.h"



#ifdef DEBUG

BOOL g_bCreated = FALSE;

VOID CreateDebugConsole() {

    if (g_bCreated)
        return;

    if (!GetConsoleWindow() && AllocConsole())
        g_bCreated = TRUE;
}

#endif // DEBUG