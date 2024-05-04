#ifndef CONTEXT_H
#define CONTEXT_H

#include "go_types.h"
#include "windows_t.h"
#include "hash_api.h"

typedef struct {
    // arguments for initialize runtime
    FindAPI_t FindAPI;
    uintptr   MainMemPage;
    uintptr   TTMemPage;

    // context data about initialize runtime
    VirtualAlloc          VirtualAlloc;
    VirtualFree           VirtualFree;
    VirtualProtect        VirtualProtect;
    ReleaseMutex          ReleaseMutex;
    WaitForSingleObject   WaitForSingleObject;
    DuplicateHandle       DuplicateHandle;
    CloseHandle           CloseHandle;

    // runtime context data
    HANDLE Mutex;
} Context;

#endif // CONTEXT_H
