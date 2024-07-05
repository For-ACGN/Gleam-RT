#ifndef CONTEXT_H
#define CONTEXT_H

#include "c_types.h"
#include "lib_memory.h"
#include "windows_t.h"

typedef struct {
    // runtime options
    bool TrackCurrentThread;

    // runtime context data
    uintptr MainMemPage;
    uint32  PageSize;

    // API about initialize submodules
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    CreateMutexA_t          CreateMutexA;
    ReleaseMutex_t          ReleaseMutex;
    WaitForSingleObject_t   WaitForSingleObject;
    FlushInstructionCache_t FlushInstructionCache;
    DuplicateHandle_t       DuplicateHandle;
    CloseHandle_t           CloseHandle;

    // runtime internal methods
    malloc_t  malloc;
    realloc_t realloc;
    free_t    free;
} Context;

#endif // CONTEXT_H
