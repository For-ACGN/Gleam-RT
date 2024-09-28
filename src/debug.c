#include "build.h"

#ifndef RELEASE_MODE

#include <stdio.h>
#include <stdarg.h>
#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "debug.h"

static CreateMutexA_t        dbg_CreateMutexA;
static ReleaseMutex_t        dbg_ReleaseMutex;
static WaitForSingleObject_t dbg_WaitForSingleObject;

static HANDLE dbg_hMutex;

__declspec(noinline)
bool InitDebugger()
{
    dbg_CreateMutexA        = FindAPI_A("kernel32.dll", "CreateMutexA");
    dbg_ReleaseMutex        = FindAPI_A("kernel32.dll", "ReleaseMutex");
    dbg_WaitForSingleObject = FindAPI_A("kernel32.dll", "WaitForSingleObject");

    dbg_hMutex = dbg_CreateMutexA(NULL, false, NULL);
    if (dbg_hMutex == NULL)
    {
        return false;
    }
    return true;
}

__declspec(noinline)
void dbg_log(char* mod, char* fmt, ...)
{
    if (dbg_WaitForSingleObject(dbg_hMutex, INFINITE) != WAIT_OBJECT_0)
    {
        return;
    }

    va_list args;
    va_start(args, fmt);

    printf_s("%s ", mod);
    vprintf_s(fmt, args);
    printf_s("\n");

    va_end(args);

    dbg_ReleaseMutex(dbg_hMutex);
}

#endif
