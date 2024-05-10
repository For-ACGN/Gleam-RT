#include <stdio.h>

#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "memory.h"
#include "thread.h"
#include "runtime.h"
#include "epilogue.h"

// hard encoded address in methods for replace
#ifdef _WIN64
    #define METHOD_ADDR_GET_PROC_ADDRESS_BY_HASH  0x7FFFFFFFFFFFFFF0
    #define METHOD_ADDR_GET_PROC_ADDRESS_ORIGINAL 0x7FFFFFFFFFFFFFF1
    
    #define METHOD_ADDR_SLEEP   0x7FFFFFFFFFFFFFF3
    #define METHOD_ADDR_HIDE    0x7FFFFFFFFFFFFFF4
    #define METHOD_ADDR_RECOVER 0x7FFFFFFFFFFFFFF5
    #define METHOD_ADDR_STOP    0x7FFFFFFFFFFFFFF6

    #define METHOD_ADDR_MALLOC 0x7FFFFFFFFFFFFFF7
    #define METHOD_ADDR_FREE   0x7FFFFFFFFFFFFFF8
#elif _WIN32
    #define METHOD_ADDR_GET_PROC_ADDRESS_BY_HASH  0x7FFFFFF0
    #define METHOD_ADDR_GET_PROC_ADDRESS_ORIGINAL 0x7FFFFFF1

    #define METHOD_ADDR_SLEEP   0x7FFFFFF3
    #define METHOD_ADDR_HIDE    0x7FFFFFF4
    #define METHOD_ADDR_RECOVER 0x7FFFFFF5
    #define METHOD_ADDR_STOP    0x7FFFFFF6

    #define METHOD_ADDR_MALLOC 0x7FFFFFF7
    #define METHOD_ADDR_FREE   0x7FFFFFF8
#endif

// for IAT hooks
typedef struct {
    uintptr Original;
    uintptr Hook;
} Hook;

typedef struct {
    Runtime_Opts* Options;

    // store all structures
    uintptr MainMemPage;

    // API addresses
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
    Hook Hooks[10];

    // runtime data
    HANDLE hProcess; // for simulate Sleep
    HANDLE Mutex;    // global mutex

    // sub modules
    MemoryTracker_M* MemoryTracker;
    ThreadTracker_M* ThreadTracker;
} Runtime;

// export methods about Runtime
uintptr RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
uintptr RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool hook);
uintptr RT_GetProcAddressByHash(uint hash, uint key, bool hook);
uintptr RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName);

bool RT_Sleep(uint32 milliseconds);
bool RT_Hide();
bool RT_Recover();
bool RT_Stop();

// internal methods about Runtime
void* RT_malloc(uint size);
void* RT_realloc(void* address, uint size);
bool  RT_free(void* address);

static uintptr allocateRuntimeMemory();
static bool initRuntimeAPI(Runtime* runtime);
static bool adjustPageProtect(Runtime* runtime, uint32* old);
static bool recoverPageProtect(Runtime* runtime, uint32* old);
static bool updateRuntimePointers(Runtime* runtime);
static bool updateRuntimePointer(Runtime* runtime, void* method, uintptr address);
static uint initRuntimeEnvironment(Runtime* runtime);
static uint initMemoryTracker(Runtime* runtime, Context* context);
static uint initThreadTracker(Runtime* runtime, Context* context);
static bool initIATHooks(Runtime* runtime);
static void cleanRuntime(Runtime* runtime);

static uint32  getModuleFileNameW(HMODULE hModule, byte* name, uint32 size);
static uintptr replaceToHook(Runtime* runtime, uintptr proc);

static bool sleep(Runtime* runtime, uint32 milliseconds);
static bool hide(Runtime* runtime);
static bool recover(Runtime* runtime);

__declspec(noinline)
Runtime_M* InitRuntime(Runtime_Opts* opts)
{
    uintptr address = allocateRuntimeMemory();
    if (address == NULL)
    {
        return NULL;
    }
    // set structure address
    uintptr runtimeAddr = address + 300 + RandUint(address) % 256;
    uintptr moduleAddr  = address + 900 + RandUint(address) % 256;
    // initialize structure
    Runtime* runtime = (Runtime*)runtimeAddr;
    runtime->Options = opts;
    runtime->MainMemPage = address;
    // initialize runtime
    uint32 protect = 0;
    uint   errCode = 0;
    for (;;)
    {
        if (!initRuntimeAPI(runtime))
        {
            errCode = 0xF1;
            break;
        }
        if (!adjustPageProtect(runtime, &protect))
        {
            errCode = 0xF2;
            break;
        }
        if (!updateRuntimePointers(runtime))
        {
            errCode = 0xF3;
            break;
        }
        errCode = initRuntimeEnvironment(runtime);
        if (errCode != 0x00)
        {
            break;
        }
        if (!recoverPageProtect(runtime, &protect))
        {
            errCode = 0xFA;
            break;
        }
        if (!initIATHooks(runtime))
        {
            errCode = 0xFB;
            break;
        }
        break;
    }
    if (errCode != 0x00)
    {
        cleanRuntime(runtime);
        return (Runtime_M*)errCode;
    }
    // clean context data in structure
    uintptr ctxBegin = (uintptr)(&runtime->VirtualProtect);
    uintptr ctxSize  = (uintptr)(&runtime->ReleaseMutex) - ctxBegin;
    RandBuf((byte*)ctxBegin, (int64)ctxSize);
    // create methods for Runtime
    Runtime_M* module = (Runtime_M*)moduleAddr;
    // for develop shellcode
    module->Alloc = runtime->MemoryTracker->MemAlloc;
    module->Free  = runtime->MemoryTracker->MemFree;
    // for IAT hooks
    module->GetProcAddress         = &RT_GetProcAddress;
    module->GetProcAddressOriginal = &RT_GetProcAddressOriginal;
    module->GetProcAddressByName   = &RT_GetProcAddressByName;
    module->GetProcAddressByHash   = &RT_GetProcAddressByHash;
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
    uintptr address = virtualAlloc(0, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (address == NULL)
    {
        return NULL;
    }
    RandBuf((byte*)address, 4096);
    return address;
}

static bool initRuntimeAPI(Runtime* runtime)
{
    typedef struct { 
        uint hash; uint key; uintptr address;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
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
    
    runtime->VirtualAlloc          = (VirtualAlloc_t         )(list[0].address);
    runtime->VirtualFree           = (VirtualFree_t          )(list[1].address);
    runtime->VirtualProtect        = (VirtualProtect_t       )(list[2].address);
    runtime->FlushInstructionCache = (FlushInstructionCache_t)(list[3].address);
    runtime->CreateMutexA          = (CreateMutexA_t         )(list[4].address);
    runtime->ReleaseMutex          = (ReleaseMutex_t         )(list[5].address);
    runtime->WaitForSingleObject   = (WaitForSingleObject_t  )(list[6].address);
    runtime->DuplicateHandle       = (DuplicateHandle_t      )(list[7].address);
    runtime->CloseHandle           = (CloseHandle_t          )(list[8].address);
    runtime->GetProcAddress        = (GetProcAddress_t       )(list[9].address);
    return true;
}

// change memory protect for dynamic update pointer that hard encode.
static bool adjustPageProtect(Runtime* runtime, uint32* old)
{
    if (runtime->Options->NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    uint    size  = end - begin;
    return runtime->VirtualProtect(begin, size, PAGE_EXECUTE_READWRITE, old);
}

static bool recoverPageProtect(Runtime* runtime, uint32* old)
{
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    uint    size  = end - begin;
    if (!runtime->Options->NotAdjustProtect)
    {
        if (!runtime->VirtualProtect(begin, size, *old, old))
        {
            return false;
        }
    }
    return runtime->FlushInstructionCache(CURRENT_PROCESS, begin, size);
}

static bool updateRuntimePointers(Runtime* runtime)
{    
    typedef struct {
        void* address; uintptr pointer;
    } method;
    method methods[] = 
    {
        { &RT_GetProcAddressByHash,   METHOD_ADDR_GET_PROC_ADDRESS_BY_HASH },
        { &RT_GetProcAddressOriginal, METHOD_ADDR_GET_PROC_ADDRESS_ORIGINAL },

        { &RT_Sleep,   METHOD_ADDR_SLEEP },
        { &RT_Hide,    METHOD_ADDR_HIDE },
        { &RT_Recover, METHOD_ADDR_RECOVER },
        { &RT_Stop,    METHOD_ADDR_STOP },

        { &RT_malloc, METHOD_ADDR_MALLOC },
        { &RT_free,   METHOD_ADDR_FREE },
    };
    bool success = true;
    for (int i = 0; i < arrlen(methods); i++)
    {
        if (!updateRuntimePointer(runtime, methods[i].address, methods[i].pointer))
        {
            success = false;
            break;
        }
    }
    return success;
}

static bool updateRuntimePointer(Runtime* runtime, void* method, uintptr address)
{
    bool success = false;
    uintptr target = (uintptr)method;
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != address)
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

static uint initRuntimeEnvironment(Runtime* runtime)
{
    // initialize structure fields
    runtime->hProcess = NULL;
    runtime->Mutex    = NULL;
    runtime->MemoryTracker = NULL;
    runtime->ThreadTracker = NULL;
    // duplicate current process handle
    HANDLE dupHandle;
    if (!runtime->DuplicateHandle(
        CURRENT_PROCESS, CURRENT_PROCESS, CURRENT_PROCESS, &dupHandle,
        0, false, DUPLICATE_SAME_ACCESS
    ))
    {
        return 0xF4;
    }
    runtime->hProcess = dupHandle;
    // create global mutex
    HANDLE hMutex = runtime->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return 0xF5;
    }
    runtime->Mutex = hMutex;
    // create context data for initialize other modules
    Context context = {
        .MainMemPage = runtime->MainMemPage,

        .VirtualAlloc          = runtime->VirtualAlloc,
        .VirtualFree           = runtime->VirtualFree,
        .VirtualProtect        = runtime->VirtualProtect,
        .ReleaseMutex          = runtime->ReleaseMutex,
        .WaitForSingleObject   = runtime->WaitForSingleObject,
        .DuplicateHandle       = runtime->DuplicateHandle,
        .CloseHandle           = runtime->CloseHandle,

        .malloc  = &RT_malloc,
        .realloc = &RT_realloc,
        .free    = &RT_free,

        .Mutex = runtime->Mutex,
    };
    uint errCode;
    errCode = initMemoryTracker(runtime, &context);
    if (errCode != 0x00)
    {
        return errCode;
    }
    errCode = initThreadTracker(runtime, &context);
    if (errCode != 0x00)
    {
        return errCode;
    }
    return 0x00;
}

static uint initMemoryTracker(Runtime* runtime, Context* context)
{
    MemoryTracker_M* tracker = InitMemoryTracker(context);
    if (tracker < (MemoryTracker_M*)(0x10))
    {
        return (uint)tracker;
    }
    runtime->MemoryTracker = tracker;
    return 0x00;
}

static uint initThreadTracker(Runtime* runtime, Context* context)
{
    ThreadTracker_M* tracker = InitThreadTracker(context);
    if (tracker < (ThreadTracker_M*)(0x20))
    {
        return (uint)tracker;
    }
    runtime->ThreadTracker = tracker;
    return 0x00;
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
    uintptr proc;
    for (int i = 0; i < arrlen(items); i++)
    {
        proc = FindAPI(items[i].hash, items[i].key);
        if (proc == NULL)
        {
            return false;
        }
        runtime->Hooks[i].Original = proc;
        runtime->Hooks[i].Hook     = (uintptr)items[i].hook;
    }
    return true;
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
    RandBuf((byte*)runtime->MainMemPage, 4096);
    if (virtualFree != NULL)
    {
        virtualFree(runtime->MainMemPage, 0, MEM_RELEASE);
    }
}

// updateRuntimePointers will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateRuntimePointer will fail.
#pragma optimize("", off)
static Runtime* getRuntimePointer(uintptr pointer)
{
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
    if (getModuleFileNameW(hModule, &module[0], sizeof(module)) == 0)
    {
        return NULL;
    }
    // generate API hash
    uint key  = 0xFFFFFFFF;
    uint hash = HashAPI_W(&module[0], lpProcName, key);
    return RT_GetProcAddressByHash(hash, key, hook);
}

__declspec(noinline)
uintptr RT_GetProcAddressByHash(uint hash, uint key, bool hook)
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_GET_PROC_ADDRESS_BY_HASH);

    // TODO is kernel32.dll 
    // GetProcAddressByName
    // GetProcAddressByHash
    // GetProcAddressOriginal

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

static uint32 getModuleFileNameW(HMODULE hModule, byte* name, uint32 size)
{
#ifdef _WIN64
    uintptr peb = __readgsqword(96);
    uintptr ldr = *(uintptr*)(peb + 24);
    uintptr mod = *(uintptr*)(ldr + 32);
#elif _WIN32
    uintptr peb = __readfsdword(48);
    uintptr ldr = *(uintptr*)(peb + 12);
    uintptr mod = *(uintptr*)(ldr + 20);
#endif
    for (;; mod = *(uintptr*)(mod))
    {
    #ifdef _WIN64
        uintptr modName = *(uintptr*)(mod + 80);
    #elif _WIN32
        uintptr modName = *(uintptr*)(mod + 40);
    #endif    
        if (modName == 0x00)
        {
            break;
        }
    #ifdef _WIN64
        uintptr modBase = *(uintptr*)(mod + 32);
    #elif _WIN32
        uintptr modBase = *(uintptr*)(mod + 16);
    #endif
        if (modBase != hModule)
        {
            continue;
        }
    #ifdef _WIN64
        uint16 nameLen = *(uint16*)(mod + 74);
    #elif _WIN32
        uint16 nameLen = *(uint16*)(mod + 38);
    #endif
        if (nameLen > size)
        {
            nameLen = size;
        }
        mem_copy(name, (byte*)modName, nameLen);
        return nameLen;
    }
    return 0;
}

static uintptr replaceToHook(Runtime* runtime, uintptr proc)
{
    for (int i = 0; i < arrlen(runtime->Hooks); i++)
    {
        if (proc != runtime->Hooks[i].Original)
        {
            continue;
        }
        return runtime->Hooks[i].Hook;
    }
    return proc;
}

__declspec(noinline)
uintptr RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_GET_PROC_ADDRESS_ORIGINAL);

    return runtime->GetProcAddress(hModule, lpProcName);
}

__declspec(noinline)
bool RT_Sleep(uint32 milliseconds)
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_SLEEP);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    bool success = true;
    for (;;)
    {
        if (!hide(runtime))
        {
            success = false;
            break;
        }
        if (!sleep(runtime, milliseconds))
        {
            success = false;
        }
        if (!recover(runtime))
        {
            success = false;
            break;
        }
        break;
    }

    runtime->ReleaseMutex(runtime->Mutex);
    return success;
}

static bool sleep(Runtime* runtime, uint32 milliseconds)
{
    if (milliseconds < 100)
    {
        milliseconds = 100;
    }
    return runtime->WaitForSingleObject(runtime->hProcess, milliseconds);
}

__declspec(noinline)
bool RT_Hide()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_HIDE);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }
    bool success = hide(runtime);
    runtime->ReleaseMutex(runtime->Mutex);
    return success;
}

static bool hide(Runtime* runtime)
{
    bool success = true;
    for (;;)
    {
        if (!runtime->ThreadTracker->ThdSuspendAll())
        {
            success = false;
            break;
        }
        if (!runtime->MemoryTracker->MemEncrypt())
        {
            success = false;
            break;
        }
        break;
    }
    return success;
}

__declspec(noinline)
bool RT_Recover()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_RECOVER);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }
    bool success = recover(runtime);
    runtime->ReleaseMutex(runtime->Mutex);
    return success;
}

static bool recover(Runtime* runtime)
{
    bool success = true;
    for (;;)
    {
        if (!runtime->MemoryTracker->MemDecrypt())
        {
            success = false;
            break;
        }
        if (!runtime->ThreadTracker->ThdResumeAll())
        {
            success = false;
            break;
        }
        break;
    }
    return success;
}

__declspec(noinline)
bool RT_Stop()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_STOP);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    bool success = true;
    for (;;)
    {
        if (!runtime->ThreadTracker->ThdClean())
        {
            success = false;
            break;
        }
        if (!runtime->MemoryTracker->MemClean())
        {
            success = false;
            break;
        }
        break;
    }

    runtime->ReleaseMutex(runtime->Mutex);
    return success;
}

__declspec(noinline)
void* RT_malloc(uint size)
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_MALLOC);

    // ensure the size is a multiple of 4096(memory page size).
    size = ((size / 4096) + 1) * 4096;
    uintptr addr = runtime->VirtualAlloc(0, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
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
    uint oldSize = *(uint*)((uintptr)(address)-16) - 16;
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
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_FREE);

    // clean the buffer data before call VirtualFree.
    uintptr addr = (uintptr)(address)-16;
    uint    size = *(uint*)addr;
    mem_clean((byte*)addr, size);
    return runtime->VirtualFree(addr, 0, MEM_RELEASE);
}
