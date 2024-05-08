#ifndef CONTEXT_H
#define CONTEXT_H

#include "c_types.h"
#include "windows_t.h"

typedef struct {
    // arguments for initialize runtime
    uintptr   MainMemPage;
    uintptr   TTMemPage;

    // context data about initialize runtime
    VirtualAlloc_t        VirtualAlloc;
    VirtualFree_t         VirtualFree;
    VirtualProtect_t      VirtualProtect;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    DuplicateHandle_t     DuplicateHandle;
    CloseHandle_t         CloseHandle;

    // runtime context data
    HANDLE Mutex;
} Context;

#endif // CONTEXT_H
