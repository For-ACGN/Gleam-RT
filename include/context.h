#ifndef CONTEXT_H
#define CONTEXT_H

#include "go_types.h"
#include "windows_t.h"
#include "hash_api.h"

typedef struct {
    // arguments for initialize runtime
    uintptr   EntryPoint;
    uint      SizeOfCode;
    FindAPI_t FindAPI;
    uintptr   StructMemPage;

    // context data about initialize runtime
    VirtualAlloc          VirtualAlloc;
    VirtualFree           VirtualFree;
    VirtualProtect        VirtualProtect;
    CreateThread          CreateThread;
    FlushInstructionCache FlushInstructionCache;
    CreateMutexA          CreateMutexA;
    ReleaseMutex          ReleaseMutex;
    WaitForSingleObject   WaitForSingleObject;
    CloseHandle           CloseHandle;

    // runtime context data
    HANDLE Mutex;
} Context;

#endif // CONTEXT_H
