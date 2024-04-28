#ifndef MEMORY_H
#define MEMORY_H

#include "go_types.h"
#include "windows_t.h"
#include "context.h"

typedef void* (*MemAlloc_t)(uint size);
typedef bool  (*MemFree_t)(void* address);
typedef void  (*MemEncrypt_t)();
typedef void  (*MemDecrypt_t)();
typedef void  (*MemClean_t)();

typedef struct {
    VirtualAlloc   VirtualAlloc;
    VirtualFree    VirtualFree;
    VirtualProtect VirtualProtect;

    MemAlloc_t   MemAlloc;
    MemFree_t    MemFree;
    MemEncrypt_t MemEncrypt;
    MemDecrypt_t MemDecrypt;
    MemClean_t   MemClean;
} MemoryTracker_M;

MemoryTracker_M* InitMemoryTracker(Context* context);

#endif // MEMORY_H
