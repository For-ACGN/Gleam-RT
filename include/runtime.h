#ifndef RUNTIME_H
#define RUNTIME_H

#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "errno.h"

// about runtime options at the shellcode tail.
#define OPTION_STUB_SIZE  64
#define OPTION_STUB_MAGIC 0xFC

#define OPT_OFFSET_NOT_ERASE_INSTRUCTION    1
#define OPT_OFFSET_NOT_ADJUST_PROTECT       2
#define OPT_OFFSET_NOT_TRACK_CURRENT_THREAD 3

// for generic shellcode development.
typedef void* (*MemAlloc_t)(uint size);
typedef void* (*MemCalloc_t)(uint num, uint size);
typedef void* (*MemRealloc_t)(void* ptr, uint size);
typedef void  (*MemFree_t)(void* ptr);

// about thread module
typedef HANDLE (*ThdNew_t)(void* address, void* parameter, bool track);
typedef void   (*ThdExit_t)();
typedef void   (*Sleep_t)(uint32 milliseconds);

// about argument store
typedef bool (*GetArgValue_t)(uint index, void* value, uint32* size);
typedef bool (*GetArgPointer_t)(uint index, void** pointer, uint32* size);
typedef bool (*EraseArgument_t)(uint index);
typedef void (*EraseAllArgs_t)();

// about Win File
typedef bool (*ReadFileA_t)(LPSTR path, byte** buf, int64* size);
typedef bool (*ReadFileW_t)(LPWSTR path, byte** buf, int64* size);
typedef bool (*WriteFileA_t)(LPSTR path, byte* buf, int64 size);
typedef bool (*WriteFileW_t)(LPWSTR path, byte* buf, int64 size);

// about random module
typedef void   (*RandBuf_t)(byte* buf, int64 size);
typedef bool   (*RandBool_t)(uint64 seed);
typedef int64  (*RandInt64_t)(uint64 seed);
typedef uint64 (*RandUint64_t)(uint64 seed);
typedef int64  (*RandInt64N_t)(uint64 seed, int64 n);
typedef uint64 (*RandUint64N_t)(uint64 seed, uint64 n);

// about crypto module
typedef void (*Encrypt_t)(byte* buf, uint size, byte* key, byte* iv);
typedef void (*Decrypt_t)(byte* buf, uint size, byte* key, byte* iv);

// about compress module
typedef uint (*Compress_t)(void* dst, void* src);
typedef uint (*Decompress_t)(void* dst, void* src);

// GetProcAddress, GetProcAddressByName and GetProcAddressByHash
// are use Hash API module for implement original GetProcAddress.
// GetProcAddressOriginal is not recommend, usually use
// GetProcAddressByName with hook FALSE instead it.
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

    // not adjust current memory page protect for erase runtime.
    bool NotAdjustProtect;

    // track current thread for test or debug mode.
    bool TrackCurrentThread;
} Runtime_Opts;

// Runtime_M contains exported runtime methods.
typedef struct {
    // about hash api
    FindAPI_t   FindAPI;
    FindAPI_A_t FindAPI_A;
    FindAPI_W_t FindAPI_W;

    // library tracker
    LoadLibraryA_t   LoadLibraryA;
    LoadLibraryW_t   LoadLibraryW;
    LoadLibraryExA_t LoadLibraryExA;
    LoadLibraryExW_t LoadLibraryExW;
    FreeLibrary_t    FreeLibrary;
    GetProcAddress_t GetProcAddress;

    // memory tracker
    MemAlloc_t   MemAlloc;
    MemCalloc_t  MemCalloc;
    MemRealloc_t MemRealloc;
    MemFree_t    MemFree;

    // thread tracker
    ThdNew_t  NewThread;
    ThdExit_t ExitThread;
    Sleep_t   Sleep;

    // argument store
    GetArgValue_t   GetArgValue;
    GetArgPointer_t GetArgPointer;
    EraseArgument_t EraseArgument;
    EraseAllArgs_t  EraseAllArgs;

    // WinFile
    ReadFileA_t  ReadFileA;
    ReadFileW_t  ReadFileW;
    WriteFileA_t WriteFileA;
    WriteFileW_t WriteFileW;

    // WinHTTP
    
    // random module
    RandBuf_t     RandBuf;
    RandBool_t    RandBool;
    RandInt64_t   RandInt64;
    RandUint64_t  RandUint64;
    RandInt64N_t  RandInt64N;
    RandUint64N_t RandUint64N;

    // crypto module
    Encrypt_t Encrypt;
    Decrypt_t Decrypt;

    // compress module
    Compress_t   Compress;
    Decompress_t Decompress;

    // runtime common methods
    GetProcAddressByName_t   GetProcAddressByName;
    GetProcAddressByHash_t   GetProcAddressByHash;
    GetProcAddressOriginal_t GetProcAddressOriginal;

    // runtime core methods
    SleepHR_t SleepHR;
    Hide_t    Hide;
    Recover_t Recover;
    Exit_t    Exit;
} Runtime_M;

// InitRuntime is used to initialize runtime and return module methods.
// If failed to initialize, use GetLastError to get error code.
Runtime_M* InitRuntime(Runtime_Opts* opts);

#endif // RUNTIME_H
