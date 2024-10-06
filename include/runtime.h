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
typedef errno (*ReadFileA_t)(LPSTR path, byte** buf, int64* size);
typedef errno (*ReadFileW_t)(LPWSTR path, byte** buf, int64* size);
typedef errno (*WriteFileA_t)(LPSTR path, byte* buf, int64 size);
typedef errno (*WriteFileW_t)(LPWSTR path, byte* buf, int64 size);

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
typedef void* (*GetProcByName_t)(HMODULE hModule, LPCSTR lpProcName, bool hook);
typedef void* (*GetProcByHash_t)(uint hash, uint key, bool hook);
typedef void* (*GetProcOriginal_t)(HMODULE hModule, LPCSTR lpProcName);

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
    struct HashAPI {
        FindAPI_t   FindAPI;
        FindAPI_A_t FindAPI_A;
        FindAPI_W_t FindAPI_W;
    } HashAPI;

    struct DLL {
        LoadLibraryA_t   LoadA;
        LoadLibraryW_t   LoadW;
        LoadLibraryExA_t LoadExA;
        LoadLibraryExW_t LoadExW;
        FreeLibrary_t    Free;
        GetProcAddress_t GetProc;
    } Library;

    struct Memory {
        MemAlloc_t   Alloc;
        MemCalloc_t  Calloc;
        MemRealloc_t Realloc;
        MemFree_t    Free;
    } Memory;

    struct Thread {
        ThdNew_t  New;
        ThdExit_t Exit;
        Sleep_t   Sleep;
    } Thread;

    struct Argument {
        GetArgValue_t   GetValue;
        GetArgPointer_t GetPointer;
        EraseArgument_t Erase;
        EraseAllArgs_t  EraseAll;
    } Argument;

    struct WinFile {
        ReadFileA_t  ReadFileA;
        ReadFileW_t  ReadFileW;
        WriteFileA_t WriteFileA;
        WriteFileW_t WriteFileW;
    } WinFile;
    
    struct Random {
        RandBuf_t     Buf;
        RandBool_t    Bool;
        RandInt64_t   Int64;
        RandUint64_t  Uint64;
        RandInt64N_t  Int64N;
        RandUint64N_t Uint64N;
    } Random;

    struct Crypto {
        Encrypt_t Encrypt;
        Decrypt_t Decrypt;
    } Crypto;

    struct Compressor {
        Compress_t   Compress;
        Decompress_t Decompress;
    } Compressor;

    struct IAT {
        GetProcByName_t   GetProcByName;
        GetProcByHash_t   GetProcByHash;
        GetProcOriginal_t GetProcOriginal;
    } IAT;

    struct Core {
        SleepHR_t Sleep;
        Hide_t    Hide;
        Recover_t Recover;
        Exit_t    Exit;
    } Core;
} Runtime_M;

// InitRuntime is used to initialize runtime and return module methods.
// If failed to initialize, use GetLastError to get error code.
Runtime_M* InitRuntime(Runtime_Opts* opts);

#endif // RUNTIME_H
