#ifndef RUNTIME_H
#define RUNTIME_H

#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "errno.h"

// for generic shellcode development.
typedef void   (*Sleep_t)(uint32 milliseconds);
typedef void*  (*MemAlloc_t)(uint size);
typedef void*  (*MemRealloc_t)(void* address, uint size);
typedef bool   (*MemFree_t)(void* address);
typedef HANDLE (*ThdNew_t)(void* address, void* parameter, bool track);
typedef void   (*ThdExit_t)();
typedef bool   (*GetArgument_t)(uint index, void** data, uint32* size);
typedef bool   (*EraseArgument_t)(uint index);
typedef void   (*EraseAllArgs_t)();

// GetProcAddress, GetProcAddressByName and GetProcAddressByHash
// are use Hash API module for implement original GetProcAddress.
// GetProcAddressOriginal is not recommend, usually use
// GetProcAddressByName with hook OFF instead it.
// These methods are used for IAT hooks or common shellcode.
typedef void* (*GetProcAddressByName_t)(HMODULE hModule, LPCSTR lpProcName, bool hook);
typedef void* (*GetProcAddressByHash_t)(uint hash, uint key, bool hook);
typedef void* (*GetProcAddressOriginal_t)(HMODULE hModule, LPCSTR lpProcName);

// runtime core methods
// it is NOT recommended use "Hide" and "Recover", these functions
// are used to test and research, if use them, runtime will loss
// the shield protect and structure data encrypt.
typedef errno (*SleepHR_t)(uint32 milliseconds);
typedef errno (*Hide_t)();
typedef errno (*Recover_t)();
typedef errno (*Exit_t)();

typedef struct {
    // protect instructions like shellcode before Runtime,
    // if it is NULL, Runtime will only protect self.
    void* BootInstAddress;

    // not erase runtime instructions after call Runtime_M.Exit
    bool NotEraseInstruction;

    // not adjust current memory page protect for erase runtime
    bool NotAdjustProtect;

    // track current thread for some special executable file like Golang
    bool TrackCurrentThread;
} Runtime_Opts;

// Runtime_M contains exported runtime methods.
typedef struct {
    FindAPI_t FindAPI;
    Sleep_t   Sleep;

    MemAlloc_t      MemAlloc;
    MemRealloc_t    MemRealloc;
    MemFree_t       MemFree;
    ThdNew_t        NewThread;
    ThdExit_t       ExitThread;
    GetArgument_t   GetArgument;
    EraseArgument_t EraseArgument;
    EraseAllArgs_t  EraseAllArgs;

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
