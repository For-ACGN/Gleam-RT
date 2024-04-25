#ifndef MEMORY_H
#define MEMORY_H

#include "go_types.h"
#include "windows_t.h"
#include "context.h"

typedef void* (*MemAlloc_t)(uint size);
typedef void  (*MemFree_t)(void* address);

typedef struct {
    MemAlloc_t   MemAlloc;
    MemFree_t    MemFree;
    VirtualAlloc VirtualAlloc;
    VirtualFree  VirtualFree;
} MemoryTracker_M;

MemoryTracker_M* InitMemoryTracker(Context* context);

#endif // MEMORY_H
