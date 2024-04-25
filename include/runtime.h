#ifndef RUNTIME_H
#define RUNTIME_H

#include "go_types.h"
#include "windows_t.h"

typedef void* (*MemAlloc_t)(uint size);
typedef void  (*MemFree_t)(void* address);

typedef void (*Hide_t)();
typedef void (*Recover_t)();
typedef void (*Stop_t)();

// Runtime_M contains exported methods for hijack.
typedef struct {
    MemAlloc_t   MemAlloc;
    MemFree_t    MemFree;
    VirtualAlloc VirtualAlloc;
    VirtualFree  VirtualFree;
    CreateThread CreateThread;

    Hide_t    Hide;
    Recover_t Recover;
    Stop_t    Stop;
} Runtime_M;

// InitRuntime is used to initialize runtime, and return module methods.
Runtime_M* InitRuntime(FindAPI_t findAPI);

#endif // RUNTIME_H