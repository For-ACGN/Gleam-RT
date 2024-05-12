#ifndef RUNTIME_H
#define RUNTIME_H

#include "c_types.h"
#include "windows_t.h"

// for common shellcode development.
typedef void* (*Alloc_t)(uint size);
typedef void* (*Realloc_t)(void* address, uint size);
typedef bool  (*Free_t)(void* address);

// GetProcAddress, GetProcAddressByName and GetProcAddressByHash
// are use Hash API module for implement original GetProcAddress.
// GetProcAddressOriginal is not recommend, usually use 
// GetProcAddressByName with hook OFF instead it.
// These methods are used for IAT hooks or common shellcode.
typedef uintptr (*GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef uintptr (*GetProcAddressByName_t)(HMODULE hModule, LPCSTR lpProcName, bool hook);
typedef uintptr (*GetProcAddressByHash_t)(uint hash, uint key, bool hook);
typedef uintptr (*GetProcAddressOriginal_t)(HMODULE hModule, LPCSTR lpProcName);

// runtime core methods
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
    Alloc_t   Alloc;
    Realloc_t Realloc;
    Free_t    Free;
    
    GetProcAddress_t         GetProcAddress;
    GetProcAddressByName_t   GetProcAddressByName;
    GetProcAddressByHash_t   GetProcAddressByHash;
    GetProcAddressOriginal_t GetProcAddressOriginal;
    
    Sleep_t   Sleep;
    Hide_t    Hide;
    Recover_t Recover;
    Stop_t    Stop;
} Runtime_M;

// InitRuntime is used to initialize runtime and return module methods.
Runtime_M* InitRuntime(Runtime_Opts* opts);

#endif // RUNTIME_H
