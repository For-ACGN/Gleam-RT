#ifndef RUNTIME_H
#define RUNTIME_H

#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "errno.h"

// for common shellcode development.
typedef void*  (*MemAlloc_t)(uint size);
typedef void*  (*MemRealloc_t)(void* address, uint size);
typedef bool   (*MemFree_t)(void* address);
typedef HANDLE (*ThdNew_t)(uintptr address, void* parameter);
typedef void   (*ThdExit_t)();
typedef void   (*Sleep_t)(uint32 milliseconds);

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
// it is NOT recommended use "Hide" and "Recover" these function
// are used to test and research, if use them, runtime will loss
// the shield protect and structure data encrypt.
typedef errno (*SleepHR_t)(uint32 milliseconds);
typedef errno (*Hide_t)();
typedef errno (*Recover_t)();
typedef errno (*Exit_t)();

typedef struct {
    // protect instructions like shellcode before runtime
    uintptr InstAddress;

    // not erase runtime instruction after call Stop
    bool NotEraseInst;

    // not adjust current memory page protect for change runtime data
    bool NotAdjustProtect;

    // track current thread for some special executable file like Go
    bool TrackCurrentThread;
} Runtime_Opts;

// Runtime_M contains exported runtime methods.
typedef struct {
    MemAlloc_t   MemAlloc;
    MemRealloc_t MemRealloc;
    MemFree_t    MemFree;
    ThdNew_t     NewThread;
    ThdExit_t    ExitThread;
    FindAPI_t    FindAPI;
    Sleep_t      Sleep;

    GetProcAddress_t         GetProcAddress;
    GetProcAddressByName_t   GetProcAddressByName;
    GetProcAddressByHash_t   GetProcAddressByHash;
    GetProcAddressOriginal_t GetProcAddressOriginal;
    
    SleepHR_t SleepHR;
    Hide_t    Hide;
    Recover_t Recover;
    Exit_t    Exit;
} Runtime_M;

// InitRuntime is used to initialize runtime and return module methods.
Runtime_M* InitRuntime(Runtime_Opts* opts);

#endif // RUNTIME_H
