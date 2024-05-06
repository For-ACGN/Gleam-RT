#ifndef RUNTIME_H
#define RUNTIME_H

#include "go_types.h"
#include "windows_t.h"

typedef void* (*Alloc_t)(uint size);
typedef bool  (*Free_t)(void* address);

typedef uintptr (*GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef uintptr (*GetProcAddressByName_t)(HMODULE hModule, LPCSTR lpProcName, bool hook);
typedef uintptr (*GetProcAddressByHash_t)(uint hash, uint key, bool hook);

typedef bool (*Sleep_t)(uint32 milliseconds);
typedef bool (*Hide_t)();
typedef bool (*Recover_t)();
typedef bool (*Stop_t)();

typedef struct {
    // not adjust current memory page protect
    bool NotAdjustProtect;
} Runtime_Opts;

// Runtime_M contains exported runtime methods.
typedef struct {
    // for shellcode
    Alloc_t Alloc;
    Free_t  Free;

    // for IAT hooks
    GetProcAddress_t       GetProcAddress;
    GetProcAddressByName_t GetProcAddressByName;
    GetProcAddressByHash_t GetProcAddressByHash;

    // runtime core methods
    Sleep_t   Sleep;
    Hide_t    Hide;
    Recover_t Recover;
    Stop_t    Stop;
} Runtime_M;

// InitRuntime is used to initialize runtime and return module methods.
Runtime_M* InitRuntime(Runtime_Opts* opts);

#endif // RUNTIME_H
