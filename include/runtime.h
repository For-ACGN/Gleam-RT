#ifndef RUNTIME_H
#define RUNTIME_H

#include "go_types.h"
#include "windows_t.h"
#include "hash_api.h"

typedef void* (*MemAlloc_t)(uint size);
typedef bool  (*MemFree_t)(void* address);
typedef bool  (*Hide_t)();
typedef bool  (*Recover_t)();
typedef void  (*Stop_t)();

typedef struct {
    FindAPI_t FindAPI;
    bool      NotAdjustProtect;
} Runtime_Args;

// Runtime_M contains exported runtime methods.
typedef struct {
    // for IAT hooks
    VirtualAlloc   VirtualAlloc;
    VirtualFree    VirtualFree;
    VirtualProtect VirtualProtect;
    CreateThread   CreateThread;

    // for general shellcode
    MemAlloc_t MemAlloc;
    MemFree_t  MemFree;

    // runtime core methods
    Hide_t    Hide;
    Recover_t Recover;
    Stop_t    Stop;
} Runtime_M;

// InitRuntime is used to initialize runtime and return module methods.
Runtime_M* InitRuntime(Runtime_Args* args);

#endif // RUNTIME_H
