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

    // runtime internal methods
    malloc_t  malloc;
    calloc_t  calloc;
    realloc_t realloc;
    free_t    free;

    rt_lock_t   lock;
    rt_unlock_t unlock;

    // for initialize runtime submodules
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    CreateMutexA_t          CreateMutexA;
    ReleaseMutex_t          ReleaseMutex;
    WaitForSingleObject_t   WaitForSingleObject;
    FlushInstructionCache_t FlushInstructionCache;
    DuplicateHandle_t       DuplicateHandle;
    CloseHandle_t           CloseHandle;

    // for initialize high level modules
    malloc_t  mt_malloc;
    calloc_t  mt_calloc;
    realloc_t mt_realloc;
    free_t    mt_free;
} Context;

#endif // CONTEXT_H
