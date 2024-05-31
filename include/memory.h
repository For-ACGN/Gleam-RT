#ifndef MEMORY_H
#define MEMORY_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"
#include "errno.h"

typedef void* (*MemAlloc_t)(uint size);
typedef void* (*MemRealloc_t)(void* address, uint size);
typedef bool  (*MemFree_t)(void* address);
typedef errno (*MemEncrypt_t)();
typedef errno (*MemDecrypt_t)();
typedef errno (*MemClean_t)();

typedef struct {
    VirtualAlloc_t   VirtualAlloc;
    VirtualFree_t    VirtualFree;
    VirtualProtect_t VirtualProtect;

    MemAlloc_t   MemAlloc;
    MemRealloc_t MemRealloc;
    MemFree_t    MemFree;
    MemEncrypt_t MemEncrypt;
    MemDecrypt_t MemDecrypt;
    MemClean_t   MemClean;
} MemoryTracker_M;

MemoryTracker_M* InitMemoryTracker(Context* context);

#endif // MEMORY_H
