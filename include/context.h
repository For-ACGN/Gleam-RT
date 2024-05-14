#ifndef CONTEXT_H
#define CONTEXT_H

#include "c_types.h"
#include "lib_memory.h"
#include "windows_t.h"

typedef struct {
    // arguments for initialize runtime
    uintptr MainMemPage;

    // context data about initialize runtime
    VirtualAlloc_t        VirtualAlloc;
    VirtualFree_t         VirtualFree;
    VirtualProtect_t      VirtualProtect;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    DuplicateHandle_t     DuplicateHandle;
    CloseHandle_t         CloseHandle;

    // runtime internal methods
    malloc_t  malloc;
    realloc_t realloc;
    free_t    free;

    // runtime context data
    HANDLE Mutex;
} Context;

#endif // CONTEXT_H
