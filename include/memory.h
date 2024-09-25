#ifndef MEMORY_H
#define MEMORY_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"
#include "errno.h"

typedef void* (*MemAlloc_t)(uint size);
typedef void* (*MemCalloc_t)(uint num, uint size);
typedef void* (*MemRealloc_t)(void* ptr, uint size);
typedef void  (*MemFree_t)(void* ptr);
typedef bool  (*MemLock_t)();
typedef bool  (*MemUnlock_t)();
typedef errno (*MemEncrypt_t)();
typedef errno (*MemDecrypt_t)();
typedef errno (*MemFreeAll_t)();
typedef errno (*MemClean_t)();

typedef struct {
    VirtualAlloc_t   VirtualAlloc;
    VirtualFree_t    VirtualFree;
    VirtualProtect_t VirtualProtect;
    VirtualQuery_t   VirtualQuery;
    VirtualLock_t    VirtualLock;
    VirtualUnlock_t  VirtualUnlock;

    MemAlloc_t   Alloc;
    MemCalloc_t  Calloc;
    MemRealloc_t Realloc;
    MemFree_t    Free;
    MemLock_t    Lock;
    MemUnlock_t  Unlock;
    MemEncrypt_t Encrypt;
    MemDecrypt_t Decrypt;
    MemFreeAll_t FreeAll;
    MemClean_t   Clean;
} MemoryTracker_M;

MemoryTracker_M* InitMemoryTracker(Context* context);

#endif // MEMORY_H
