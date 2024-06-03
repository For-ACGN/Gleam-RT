#include <stdio.h>

#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "random.h"
#include "crypto.h"
#include "win_api.h"
#include "context.h"
#include "errno.h"
#include "library.h"
#include "memory.h"
#include "thread.h"
#include "runtime.h"
#include "shield.h"
#include "epilogue.h"

#define MAIN_MEM_PAGE_SIZE 8192

// for IAT hooks
typedef struct {
    uintptr Func;
    uintptr Hook;
} Hook;

typedef struct {
    Runtime_Opts* Options;

    // store options
    uintptr InstAddress;

    // store all structures
    uintptr MainMemPage;

    // API addresses
    GetSystemInfo_t         GetSystemInfo;
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    FlushInstructionCache_t FlushInstructionCache;
    CreateMutexA_t          CreateMutexA;
    ReleaseMutex_t          ReleaseMutex;
    WaitForSingleObject_t   WaitForSingleObject;
    DuplicateHandle_t       DuplicateHandle;
    CloseHandle_t           CloseHandle;
    GetProcAddress_t        GetProcAddress;

    // IAT hooks about GetProcAddress
    Hook Hooks[16];

    // runtime data
    uint32 PageSize; // memory management
    HANDLE hProcess; // for simulate Sleep
    HANDLE Mutex;    // global mutex

    // submodules
    LibraryTracker_M* LibraryTracker;
    MemoryTracker_M*  MemoryTracker;
    ThreadTracker_M*  ThreadTracker;
} Runtime;

// export methods about Runtime
uintptr RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
uintptr RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool hook);
uintptr RT_GetProcAddressByHash(uint hash, uint key, bool hook);
uintptr RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName);

errno RT_Sleep(uint32 milliseconds);
errno RT_Hide();
errno RT_Recover();
errno RT_Stop();

// internal methods for Runtime submodules
void* RT_malloc(uint size);
void* RT_realloc(void* address, uint size);
bool  RT_free(void* address);

// hard encoded address in getRuntimePointer for replacement
#ifdef _WIN64
    #define RUNTIME_POINTER 0x7FABCDEF111111FF
#elif _WIN32
    #define RUNTIME_POINTER 0x7FABCDFF
#endif
static Runtime* getRuntimePointer();

static uintptr allocateRuntimeMemory();
static bool  initRuntimeAPI(Runtime* runtime);
static bool  adjustPageProtect(Runtime* runtime);
static bool  flushInstructionCache(Runtime* runtime);
static bool  updateRuntimePointer(Runtime* runtime);
static errno initRuntimeEnvironment(Runtime* runtime);
static errno initLibraryTracker(Runtime* runtime, Context* context);
static errno initMemoryTracker(Runtime* runtime, Context* context);
static errno initThreadTracker(Runtime* runtime, Context* context);
static bool  initIATHooks(Runtime* runtime);
static void  cleanRuntime(Runtime* runtime);

static uintptr getRuntimeMethods(byte* module, LPCSTR lpProcName);
static uintptr replaceToHook(Runtime* runtime, uintptr proc);

static errno sleep(Runtime* runtime, uint32 milliseconds);
static errno hide(Runtime* runtime);
static errno recover(Runtime* runtime);

static bool rt_lock(Runtime* runtime);
static bool rt_unlock(Runtime* runtime);

__declspec(noinline)
Runtime_M* InitRuntime(Runtime_Opts* opts)
{
    uintptr address = allocateRuntimeMemory();
    if (address == NULL)
    {
        return NULL;
    }
    printf("main page: 0x%llX\n", address);
    // set structure address
    uintptr runtimeAddr = address + 100 + RandUint(address) % 128;
    uintptr moduleAddr  = address + 700 + RandUint(address) % 128;
    // initialize structure
    Runtime* runtime = (Runtime*)runtimeAddr;
    runtime->Options = opts;
    runtime->InstAddress = opts->InstAddress;
    runtime->MainMemPage = address;
    // initialize runtime
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initRuntimeAPI(runtime))
        {
            errno = ERR_RUNTIME_INIT_API;
            break;
        }
        if (!adjustPageProtect(runtime))
        {
            errno = ERR_RUNTIME_ADJUST_PROTECT;
            break;
        }
        if (!updateRuntimePointer(runtime))
        {
            errno = ERR_RUNTIME_UPDATE_PTR;
            break;
        }
        errno = initRuntimeEnvironment(runtime);
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!flushInstructionCache(runtime))
        {
            errno = ERR_RUNTIME_FLUSH_INST;
            break;
        }
        if (!initIATHooks(runtime))
        {
            errno = ERR_RUNTIME_INIT_IAT_HOOKS;
            break;
        }
        break;
    }
    if (errno != NO_ERROR)
    {
        cleanRuntime(runtime);
        return (Runtime_M*)errno;
    }
    // create methods for Runtime
    Runtime_M* module = (Runtime_M*)moduleAddr;
    // for develop shellcode
    module->MemAlloc   = runtime->MemoryTracker->MemAlloc;
    module->MemRealloc = runtime->MemoryTracker->MemRealloc;
    module->MemFree    = runtime->MemoryTracker->MemFree;
    // for IAT hooks
    module->GetProcAddress         = &RT_GetProcAddress;
    module->GetProcAddressByName   = &RT_GetProcAddressByName;
    module->GetProcAddressByHash   = &RT_GetProcAddressByHash;
    module->GetProcAddressOriginal = &RT_GetProcAddressOriginal;
    // runtime core methods
    module->Sleep   = &RT_Sleep;
    module->Hide    = &RT_Hide;
    module->Recover = &RT_Recover;
    module->Stop    = &RT_Stop;
    return module;
}

// allocate memory for store structures.
static uintptr allocateRuntimeMemory()
{
#ifdef _WIN64
    uint hash = 0xB6A1D0D4A275D4B6;
    uint key  = 0x64CB4D66EC0BEFD9;
#elif _WIN32
    uint hash = 0xC3DE112E;
    uint key  = 0x8D9EA74F;
#endif
    VirtualAlloc_t virtualAlloc = (VirtualAlloc_t)FindAPI(hash, key);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }
    uintptr addr = virtualAlloc(0, MAIN_MEM_PAGE_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    RandBuf((byte*)addr, MAIN_MEM_PAGE_SIZE);
    return addr;
}

static bool initRuntimeAPI(Runtime* runtime)
{
    typedef struct { 
        uint hash; uint key; uintptr address;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x2A9C7D79595F39B2, 0x11FB7144E3CF94BD }, // GetSystemInfo
        { 0x6AC498DF641A4FCB, 0xFF3BB21B9BA46CEA }, // VirtualAlloc
        { 0xAC150252A6CA3960, 0x12EFAEA421D60C3E }, // VirtualFree
        { 0xEA5B0C76C7946815, 0x8846C203C35DE586 }, // VirtualProtect
        { 0x8172B49F66E495BA, 0x8F0D0796223B56C2 }, // FlushInstructionCache
        { 0x31FE697F93D7510C, 0x77C8F05FE04ED22D }, // CreateMutexA
        { 0xEEFDEA7C0785B561, 0xA7B72CC8CD55C1D4 }, // ReleaseMutex
        { 0xA524CD56CF8DFF7F, 0x5519595458CD47C8 }, // WaitForSingleObject
        { 0xF7A5A49D19409FFC, 0x6F23FAA4C20FF4D3 }, // DuplicateHandle
        { 0xA25F7449D6939A01, 0x85D37F1D89B30D2E }, // CloseHandle
        { 0x7C1C9D36D30E0B75, 0x1ACD25CE8A87875A }, // GetProcAddress
    };
#elif _WIN32
    {
        { 0xD7792A53, 0x6DDE32BA }, // GetSystemInfo
        { 0xB47741D5, 0x8034C451 }, // VirtualAlloc
        { 0xF76A2ADE, 0x4D8938BD }, // VirtualFree
        { 0xB2AC456D, 0x2A690F63 }, // VirtualProtect
        { 0x87A2CEE8, 0x42A3C1AF }, // FlushInstructionCache
        { 0x8F5BAED2, 0x43487DC7 }, // CreateMutexA
        { 0xFA42E55C, 0xEA9F1081 }, // ReleaseMutex
        { 0xC21AB03D, 0xED3AAF22 }, // WaitForSingleObject
        { 0x0E7ED8B9, 0x025067E9 }, // DuplicateHandle
        { 0x60E108B2, 0x3C2DFF52 }, // CloseHandle
        { 0x1CE92A4E, 0xBFF4B241 }, // GetProcAddress
    };
#endif
    uintptr address;
    for (int i = 0; i < arrlen(list); i++)
    {
        address = FindAPI(list[i].hash, list[i].key);
        if (address == NULL)
        {
            return false;
        }
        list[i].address = address;
    }
    runtime->GetSystemInfo         = (GetSystemInfo_t        )(list[0x00].address);
    runtime->VirtualAlloc          = (VirtualAlloc_t         )(list[0x01].address);
    runtime->VirtualFree           = (VirtualFree_t          )(list[0x02].address);
    runtime->VirtualProtect        = (VirtualProtect_t       )(list[0x03].address);
    runtime->FlushInstructionCache = (FlushInstructionCache_t)(list[0x04].address);
    runtime->CreateMutexA          = (CreateMutexA_t         )(list[0x05].address);
    runtime->ReleaseMutex          = (ReleaseMutex_t         )(list[0x06].address);
    runtime->WaitForSingleObject   = (WaitForSingleObject_t  )(list[0x07].address);
    runtime->DuplicateHandle       = (DuplicateHandle_t      )(list[0x08].address);
    runtime->CloseHandle           = (CloseHandle_t          )(list[0x09].address);
    runtime->GetProcAddress        = (GetProcAddress_t       )(list[0x0A].address);
    return true;
}

// change memory protect for dynamic update pointer that hard encode.
static bool adjustPageProtect(Runtime* runtime)
{
    if (runtime->Options->NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    uint    size  = end - begin;
    uint32  old;
    return runtime->VirtualProtect(begin, size, PAGE_EXECUTE_READWRITE, &old);
}

static bool flushInstructionCache(Runtime* runtime)
{
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    uint    size  = end - begin;
    if (!runtime->FlushInstructionCache(CURRENT_PROCESS, begin, size))
    {
        return false;
    }
    // clean useless API functions in runtime structure
    RandBuf((byte*)(&runtime->VirtualProtect), sizeof(uintptr));
    RandBuf((byte*)(&runtime->FlushInstructionCache), sizeof(uintptr));
    return true;
}

static bool updateRuntimePointer(Runtime* runtime)
{
    bool success = false;
    uintptr target = (uintptr)(&getRuntimePointer);
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != RUNTIME_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)runtime;
        success = true;
        break;
    }
    return success;
}

static errno initRuntimeEnvironment(Runtime* runtime)
{
    // initialize structure fields
    runtime->hProcess = NULL;
    runtime->Mutex    = NULL;
    runtime->MemoryTracker = NULL;
    runtime->ThreadTracker = NULL;
    // get memory page size
    SYSTEM_INFO sys_info;
    runtime->GetSystemInfo(&sys_info);
    runtime->PageSize = sys_info.dwPageSize;
    // duplicate current process handle
    HANDLE dupHandle;
    if (!runtime->DuplicateHandle(
        CURRENT_PROCESS, CURRENT_PROCESS, CURRENT_PROCESS, &dupHandle,
        0, false, DUPLICATE_SAME_ACCESS
    ))
    {
        return ERR_RUNTIME_DUP_HANDLE;
    }
    runtime->hProcess = dupHandle;
    // create global mutex
    HANDLE hMutex = runtime->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return ERR_RUNTIME_CREATE_MUTEX;
    }
    runtime->Mutex = hMutex;
    // create context data for initialize other modules
    Context context = {
        .MainMemPage = runtime->MainMemPage,

        .TrackCurrentThread = runtime->Options->TrackCurrentThread,

        .VirtualAlloc        = runtime->VirtualAlloc,
        .VirtualFree         = runtime->VirtualFree,
        .VirtualProtect      = runtime->VirtualProtect,
        .ReleaseMutex        = runtime->ReleaseMutex,
        .WaitForSingleObject = runtime->WaitForSingleObject,
        .DuplicateHandle     = runtime->DuplicateHandle,
        .CloseHandle         = runtime->CloseHandle,

        .malloc  = &RT_malloc,
        .realloc = &RT_realloc,
        .free    = &RT_free,

        .PageSize = runtime->PageSize,
        .Mutex    = runtime->Mutex,
    };
    errno errno;
    errno = initLibraryTracker(runtime, &context);
    if (errno != NO_ERROR)
    {
        return errno;
    }
    errno = initMemoryTracker(runtime, &context);
    if (errno != NO_ERROR)
    {
        return errno;
    }
    errno = initThreadTracker(runtime, &context);
    if (errno != NO_ERROR)
    {
        return errno;
    }
    // clean useless API functions in runtime structure
    RandBuf((byte*)(&runtime->GetSystemInfo), sizeof(uintptr));
    RandBuf((byte*)(&runtime->CreateMutexA),  sizeof(uintptr));
    return NO_ERROR;
}

static errno initLibraryTracker(Runtime* runtime, Context* context)
{
    LibraryTracker_M* tracker = InitLibraryTracker(context);
    if (tracker < (LibraryTracker_M*)(MAX_ERROR))
    {
        return (errno)tracker;
    }
    runtime->LibraryTracker = tracker;
    return NO_ERROR;
}

static errno initMemoryTracker(Runtime* runtime, Context* context)
{
    MemoryTracker_M* tracker = InitMemoryTracker(context);
    if (tracker < (MemoryTracker_M*)(MAX_ERROR))
    {
        return (errno)tracker;
    }
    runtime->MemoryTracker = tracker;
    return NO_ERROR;
}

static errno initThreadTracker(Runtime* runtime, Context* context)
{
    ThreadTracker_M* tracker = InitThreadTracker(context);
    if (tracker < (ThreadTracker_M*)(MAX_ERROR))
    {
        return (errno)tracker;
    }
    runtime->ThreadTracker = tracker;
    return NO_ERROR;
}

static bool initIATHooks(Runtime* runtime)
{
    typedef struct {
        uint hash; uint key; void* hook;
    } item;
    item items[] =
#ifdef _WIN64
    {
        { 0xCAA4843E1FC90287, 0x2F19F60181B5BFE3, &RT_GetProcAddress },
        { 0xCED5CC955152CD43, 0xAA22C83C068CB037, &RT_Sleep },
        { 0xAF5FD54749244397, 0xA063C6DB28B3D3B2, runtime->LibraryTracker->LoadLibraryA },
        { 0xAA82C4918E0EC8EC, 0x939364E42EB5C6DC, runtime->LibraryTracker->LoadLibraryW },
        { 0xB5B6D8C97CA99911, 0xD38714745DA33718, runtime->LibraryTracker->LoadLibraryExA },
        { 0xADAA836A259BB790, 0x243E8C036C91259F, runtime->LibraryTracker->LoadLibraryExW },
        { 0xB1EA6C78485E0EBC, 0x4DB3B65B36C2C324, runtime->LibraryTracker->FreeLibrary },
        { 0xB3DDECBCA4D8369A, 0x9063BC5C04308424, runtime->LibraryTracker->FreeLibraryAndExitThread },
        { 0x18A3895F35B741C8, 0x96C9890F48D55E7E, runtime->MemoryTracker->VirtualAlloc },
        { 0xDB54AA6683574A8B, 0x3137DE2D71D3FF3E, runtime->MemoryTracker->VirtualFree },
        { 0xF5469C21B43D23E5, 0xF80028997F625A05, runtime->MemoryTracker->VirtualProtect },
        { 0x84AC57FA4D95DE2E, 0x5FF86AC14A334443, runtime->ThreadTracker->CreateThread },
        { 0xA6E10FF27A1085A8, 0x24815A68A9695B16, runtime->ThreadTracker->ExitThread },
        { 0x82ACE4B5AAEB22F1, 0xF3132FCE3AC7AD87, runtime->ThreadTracker->SuspendThread },
        { 0x226860209E13A99A, 0xE1BD9D8C64FAF97D, runtime->ThreadTracker->ResumeThread },
        { 0x248E1CDD11AB444F, 0x195932EA70030929, runtime->ThreadTracker->TerminateThread },
    };
#elif _WIN32
    {
        { 0x5E5065D4, 0x63CDAD01, &RT_GetProcAddress },
        { 0x705D4FAD, 0x94CF33BF, &RT_Sleep },
        { 0x17319CC6, 0x39074882, runtime->LibraryTracker->LoadLibraryA },
        { 0x6854E21B, 0xE5A72C07, runtime->LibraryTracker->LoadLibraryW },
        { 0x90509B56, 0x722D720C, runtime->LibraryTracker->LoadLibraryExA },
        { 0x0F3D82D4, 0xCF884A7E, runtime->LibraryTracker->LoadLibraryExW },
        { 0xB3C29256, 0x60CBB933, runtime->LibraryTracker->FreeLibrary },
        { 0x95A74E81, 0x4A567F10, runtime->LibraryTracker->FreeLibraryAndExitThread },
        { 0xD5B65767, 0xF3A27766, runtime->MemoryTracker->VirtualAlloc },
        { 0x4F0FC063, 0x182F3CC6, runtime->MemoryTracker->VirtualFree },
        { 0xEBD60441, 0x280A4A9F, runtime->MemoryTracker->VirtualProtect },
        { 0x20744CA1, 0x4FA1647D, runtime->ThreadTracker->CreateThread },
        { 0xED42C0F0, 0xC59EBA39, runtime->ThreadTracker->ExitThread },
        { 0x133B00D5, 0x48E02627, runtime->ThreadTracker->SuspendThread },
        { 0xA02B4251, 0x5287173F, runtime->ThreadTracker->ResumeThread },
        { 0x6EF0E2AA, 0xE014E29F, runtime->ThreadTracker->TerminateThread },
    };
#endif
    uintptr func;
    for (int i = 0; i < arrlen(items); i++)
    {
        func = FindAPI(items[i].hash, items[i].key);
        if (func == NULL)
        {
            return false;
        }
        runtime->Hooks[i].Func = func;
        runtime->Hooks[i].Hook = (uintptr)items[i].hook;
    }
    return true;
}

// updateRuntimePointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateRuntimePointer will fail.
#pragma optimize("", off)
static Runtime* getRuntimePointer()
{
    uint pointer = RUNTIME_POINTER;
    return (Runtime*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
uintptr RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    return RT_GetProcAddressByName(hModule, lpProcName, true);
}

__declspec(noinline)
uintptr RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool hook)
{
    // get module file name
    byte module[MAX_PATH];
    mem_clean(&module[0], sizeof(module));
    if (GetModuleFileName(hModule, &module[0], sizeof(module)) == 0)
    {
        return NULL;
    }
    // check is internal methods
    uintptr method = getRuntimeMethods(&module[0], lpProcName);
    if (method != NULL)
    {
        return method;
    }
    // generate key for calculate Windows API hash
    uint key  = RandUint((uint64)(hModule + lpProcName));
    uint hash = HashAPI_W(&module[0], lpProcName, key);
    return RT_GetProcAddressByHash(hash, key, hook);
}

__declspec(noinline)
uintptr RT_GetProcAddressByHash(uint hash, uint key, bool hook)
{
    Runtime* runtime = getRuntimePointer();

    uintptr proc = FindAPI(hash, key);
    if (proc == NULL)
    {
        return NULL;
    }
    if (!hook)
    {
        return proc;
    }
    return replaceToHook(runtime, proc);
}

static uintptr getRuntimeMethods(byte* module, LPCSTR lpProcName)
{
    typedef struct {
        uint hash; uint key; void* method;
    } method;
    method methods[] =
#ifdef _WIN64
    {
        { 0xA23FAC0E6398838A, 0xE4990D7D4933EE6A, &RT_GetProcAddressByName },
        { 0xABD1E8F0D28E9F46, 0xAF34F5979D300C70, &RT_GetProcAddressByHash },
        { 0xC9C5D350BB118FAE, 0x061A602F681F2636, &RT_GetProcAddressOriginal },
    };
#elif _WIN32
    {
        { 0xCF983018, 0x3ECBF2DF, &RT_GetProcAddressByName },
        { 0x40D5BD08, 0x302D5D2B, &RT_GetProcAddressByHash },
        { 0x45556AA5, 0xB3BEF31D, &RT_GetProcAddressOriginal },
    };
#endif
    for (int i = 0; i < arrlen(methods); i++)
    {
        uint hash = HashAPI_W(module, lpProcName, methods[i].key);
        if (hash != methods[i].hash)
        {
            continue;
        }
        return (uintptr)(methods[i].method);
    }
    return NULL;
}

static uintptr replaceToHook(Runtime* runtime, uintptr proc)
{
    for (int i = 0; i < arrlen(runtime->Hooks); i++)
    {
        if (proc != runtime->Hooks[i].Func)
        {
            continue;
        }
        return runtime->Hooks[i].Hook;
    }
    return proc;
}

// disable optimize for use call NOT jmp to runtime->GetProcAddress.
#pragma optimize("", off)
__declspec(noinline)
uintptr RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer();

    return runtime->GetProcAddress(hModule, lpProcName);
}
#pragma optimize("", on)

__declspec(noinline)
errno RT_Sleep(uint32 milliseconds)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }

    errno errno = NO_ERROR;
    for (;;)
    {
        errno = hide(runtime);
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = sleep(runtime, milliseconds);
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = recover(runtime);
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        break;
    }

    if (!rt_unlock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }
    return errno;
}

__declspec(noinline)
static errno sleep(Runtime* runtime, uint32 milliseconds)
{
    // build shield context
    uintptr runtimeAddr = (uintptr)(&InitRuntime);
    uintptr instAddress = runtime->InstAddress;
    if (instAddress == NULL || instAddress >= runtimeAddr)
    {
        instAddress = runtimeAddr;
    }
    if (milliseconds < 100)
    {
        milliseconds = 100;
    }
    Shield_Ctx ctx = {
        .InstAddress         = instAddress,
        .milliseconds        = milliseconds,
        .hProcess            = runtime->hProcess,
        .WaitForSingleObject = runtime->WaitForSingleObject,
    };
    // build crypto context
    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
    RandBuf(key, CRYPTO_KEY_SIZE);
    RandBuf(iv, CRYPTO_IV_SIZE);
    byte* buf = (byte*)(runtime->MainMemPage);
    // encrypt main page
    EncryptBuf(buf, MAIN_MEM_PAGE_SIZE, &key[0], &iv[0]);
    // call shield!!!
    if (!DefenseRT(&ctx))
    {
        return ERR_RUNTIME_DEFENSE_RT;
    }
    // decrypt main page
    DecryptBuf(buf, MAIN_MEM_PAGE_SIZE, &key[0], &iv[0]);
    return NO_ERROR;
}

__declspec(noinline)
errno RT_Hide()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errno = hide(runtime);
    if (!rt_unlock(runtime))
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
static errno hide(Runtime* runtime)
{
    errno errno = NO_ERROR;
    for (;;)
    {
        errno = runtime->ThreadTracker->ThdSuspend();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->MemoryTracker->MemEncrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->LibraryTracker->LibEncrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        break;
    }
    return errno;
}

__declspec(noinline)
errno RT_Recover()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }
    errno errno = recover(runtime);
    if (!rt_unlock(runtime))
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
static errno recover(Runtime* runtime)
{
    errno errno = NO_ERROR;
    for (;;)
    {
        errno = runtime->LibraryTracker->LibDecrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->MemoryTracker->MemDecrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->ThreadTracker->ThdResume();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        break;
    }
    return errno;
}

__declspec(noinline)
errno RT_Stop()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }

    errno errno = NO_ERROR;
    for (;;)
    {
        errno = runtime->ThreadTracker->ThdClean();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->MemoryTracker->MemClean();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->LibraryTracker->LibClean();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        break;
    }

    if (!rt_unlock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }
    return errno;
}

__declspec(noinline)
void* RT_malloc(uint size)
{
    Runtime* runtime = getRuntimePointer();

    // ensure the size is a multiple of memory page size.
    // it also for prevent track the special page size.
    uint pageSize = ((size / runtime->PageSize) + 1) * runtime->PageSize;
    uintptr addr = runtime->VirtualAlloc(0, pageSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }

    printf("rt_malloc: 0x%llX, %llu\n", addr, size);

    // store the size at the head of the memory page
    // ensure the memory address is 16 bytes aligned
    byte* address = (byte*)addr;
    RandBuf(address, 16);
    mem_copy(address, &size, sizeof(uint));
    return (void*)(addr+16);
}

__declspec(noinline)
void* RT_realloc(void* address, uint size)
{
    if (address == NULL)
    {
        return RT_malloc(size);
    }
    // allocate new memory
    void* newAddr = RT_malloc(size);
    if (newAddr == NULL)
    {
        return NULL;
    }
    // copy data to new memory
    uint oldSize = *(uint*)((uintptr)(address)-16);
    mem_copy(newAddr, address, oldSize);
    // free old memory
    if (!RT_free(address))
    {
        return NULL;
    }
    return newAddr;
}

__declspec(noinline)
bool RT_free(void* address)
{
    Runtime* runtime = getRuntimePointer();

    if (address == NULL)
    {
        return true;
    }

    printf("rt_free: 0x%llX\n", (uintptr)address);

    // clean the buffer data before call VirtualFree.
    uintptr addr = (uintptr)(address)-16;
    uint    size = *(uint*)addr;
    mem_clean((byte*)addr, size);
    return runtime->VirtualFree(addr, 0, MEM_RELEASE);
}

static bool rt_lock(Runtime* runtime)
{
    uint32 event = runtime->WaitForSingleObject(runtime->Mutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

static bool rt_unlock(Runtime* runtime)
{
    return runtime->ReleaseMutex(runtime->Mutex);
}

static void cleanRuntime(Runtime* runtime)
{
    CloseHandle_t closeHandle = runtime->CloseHandle;
    if (closeHandle != NULL && runtime->Mutex != NULL)
    {
        closeHandle(runtime->Mutex);
    }

    // TODO Protect ASM self
    // TODO Remove self

    // must copy api address before call RandBuf
    VirtualFree_t virtualFree = runtime->VirtualFree;
    RandBuf((byte*)runtime->MainMemPage, MAIN_MEM_PAGE_SIZE);
    if (virtualFree != NULL)
    {
        virtualFree(runtime->MainMemPage, 0, MEM_RELEASE);
    }
}
