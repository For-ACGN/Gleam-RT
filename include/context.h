#ifndef CONTEXT_H
#define CONTEXT_H

#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
#include "errno.h"

typedef errno (*rt_lock_t)();
typedef errno (*rt_unlock_t)();

typedef struct {
    // runtime options
    bool NotEraseInstruction;
    bool TrackCurrentThread;

    // runtime context data
    uintptr MainMemPage;
    uint32  PageSize;

    // for initialize submodules
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
    calloc_t  calloc;
    realloc_t realloc;
    free_t    free;

    rt_lock_t   lock;
    rt_unlock_t unlock;
} Context;

#endif // CONTEXT_H
