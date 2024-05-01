#include "go_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "memory.h"
#include "thread.h"
#include "runtime.h"

// hard encoded address in methods for replace
#ifdef _WIN64
    #define METHOD_ADDR_HIDE    0x7FFFFFFFFFFFFFF0
    #define METHOD_ADDR_RECOVER 0x7FFFFFFFFFFFFFF1
    #define METHOD_ADDR_STOP    0x7FFFFFFFFFFFFFF2
#elif _WIN32
    #define METHOD_ADDR_HIDE    0x7FFFFFF0
    #define METHOD_ADDR_RECOVER 0x7FFFFFF1
    #define METHOD_ADDR_STOP    0x7FFFFFF2
#endif

typedef struct {
    Runtime_Args* Args;

    // store all structures
    uintptr MainMemPage;

    // API addresses
    VirtualAlloc          VirtualAlloc;
    VirtualFree           VirtualFree;
    VirtualProtect        VirtualProtect;
    FlushInstructionCache FlushInstructionCache;
    CreateMutexA          CreateMutexA;
    ReleaseMutex          ReleaseMutex;
    WaitForSingleObject   WaitForSingleObject;
    CloseHandle           CloseHandle;

    // global mutex
    HANDLE Mutex;

    // sub modules
    MemoryTracker_M* MemoryTracker;
    ThreadTracker_M* ThreadTracker;
} Runtime;

// methods about Runtime
bool RT_Hide();
bool RT_Recover();
bool RT_Stop();

static uintptr allocateRuntimeMemory(FindAPI_t findAPI);
static bool initRuntimeAPI(Runtime* runtime);
static bool initRuntimeEnvironment(Runtime* runtime);
static bool initMemoryTracker(Runtime* runtime, Context* context);
static bool initThreadTracker(Runtime* runtime, Context* context);
static bool updateRuntimePointers(Runtime* runtime);
static bool updateRuntimePointer(Runtime* runtime, void* method, uintptr address);
static bool adjustPageProtect(Runtime* runtime, uint32* old);
static bool recoverPageProtect(Runtime* runtime, uint32* old);
static void cleanRuntime(Runtime* runtime);

__declspec(noinline)
Runtime_M* InitRuntime(Runtime_Args* args)
{
    uintptr address = allocateRuntimeMemory(args->FindAPI);
    if (address == NULL)
    {
        return NULL;
    }
    // set structure address
    uintptr runtimeAddr = address + 300 + RandUint(address) % 256;
    uintptr moduleAddr  = address + 600 + RandUint(address) % 256;
    // initialize structure
    Runtime* runtime = (Runtime*)runtimeAddr;
    runtime->Args = args;
    runtime->MainMemPage = address;
    // initialize runtime
    uint32 protect = 0;
    uint   errCode = 0;
    for (;;)
    {
        if (!initRuntimeAPI(runtime))
        {
            errCode = 1;
            break;
        }
        if (!adjustPageProtect(runtime, &protect))
        {
            errCode = 2;
            break;
        }
        if (!initRuntimeEnvironment(runtime))
        {
            errCode = 3;
            break;
        }
        if (!updateRuntimePointers(runtime))
        {
            errCode = 4;
            break;
        }
        if (!recoverPageProtect(runtime, &protect))
        {
            errCode = 5;
            break;
        }
        break;
    }
    if (errCode != 0)
    {
        cleanRuntime(runtime);
        return (Runtime_M*)errCode;
    }
    // clean context data in structure
    uintptr ctxBegin = (uintptr)(runtime);
    uintptr ctxSize  = (uintptr)(&runtime->ReleaseMutex) - ctxBegin;
    RandBuf((byte*)ctxBegin, (int64)ctxSize);
    // create methods for Runtime
    Runtime_M* module = (Runtime_M*)moduleAddr;
    // for IAT hooks
    module->VirtualAlloc   = runtime->MemoryTracker->VirtualAlloc;
    module->VirtualFree    = runtime->MemoryTracker->VirtualFree;
    module->VirtualProtect = runtime->MemoryTracker->VirtualProtect;
    // for general shellcode
    module->MemAlloc = runtime->MemoryTracker->MemAlloc;
    module->MemFree  = runtime->MemoryTracker->MemFree;
    // runtime core methods
    module->Hide    = &RT_Hide;
    module->Recover = &RT_Recover;
    module->Stop    = &RT_Stop;
    return module;
}

// allocate memory for store structures.
static uintptr allocateRuntimeMemory(FindAPI_t findAPI)
{
#ifdef _WIN64
    uint64 hash = 0xB6A1D0D4A275D4B6;
    uint64 key  = 0x64CB4D66EC0BEFD9;
#elif _WIN32
    uint32 hash = 0xC3DE112E;
    uint32 key  = 0x8D9EA74F;
#endif
    VirtualAlloc virtualAlloc = (VirtualAlloc)findAPI(hash, key);
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
#ifdef _WIN64
    typedef struct { 
        uint64 hash; uint64 key; uintptr address;
    } winapi;
    winapi list[] = 
    {
        { 0x6AC498DF641A4FCB, 0xFF3BB21B9BA46CEA }, // VirtualAlloc
        { 0xAC150252A6CA3960, 0x12EFAEA421D60C3E }, // VirtualFree
        { 0xEA5B0C76C7946815, 0x8846C203C35DE586 }, // VirtualProtect
        { 0x8172B49F66E495BA, 0x8F0D0796223B56C2 }, // FlushInstructionCache
        { 0x31FE697F93D7510C, 0x77C8F05FE04ED22D }, // CreateMutexA
        { 0xEEFDEA7C0785B561, 0xA7B72CC8CD55C1D4 }, // ReleaseMutex
        { 0xA524CD56CF8DFF7F, 0x5519595458CD47C8 }, // WaitForSingleObject
        { 0xA25F7449D6939A01, 0x85D37F1D89B30D2E }, // CloseHandle
    };
#elif _WIN32
    typedef struct { 
        uint32 hash; uint32 key; uintptr address;
    } winapi;
    winapi list[] = 
    {
        { 0xB47741D5, 0x8034C451 }, // VirtualAlloc
        { 0xF76A2ADE, 0x4D8938BD }, // VirtualFree
        { 0xB2AC456D, 0x2A690F63 }, // VirtualProtect
        { 0x87A2CEE8, 0x42A3C1AF }, // FlushInstructionCache
        { 0x8F5BAED2, 0x43487DC7 }, // CreateMutexA
        { 0xFA42E55C, 0xEA9F1081 }, // ReleaseMutex
        { 0xC21AB03D, 0xED3AAF22 }, // WaitForSingleObject
        { 0x60E108B2, 0x3C2DFF52 }, // CloseHandle
    };
#endif
    uintptr address;
    for (int i = 0; i < arrlen(list); i++)
    {
        address = runtime->Args->FindAPI(list[i].hash, list[i].key);
        if (address == NULL)
        {
            return false;
        }
        list[i].address = address;
    }
    runtime->VirtualAlloc          = (VirtualAlloc         )(list[0].address);
    runtime->VirtualFree           = (VirtualFree          )(list[1].address);
    runtime->VirtualProtect        = (VirtualProtect       )(list[2].address);
    runtime->FlushInstructionCache = (FlushInstructionCache)(list[3].address);
    runtime->CreateMutexA          = (CreateMutexA         )(list[4].address);
    runtime->ReleaseMutex          = (ReleaseMutex         )(list[5].address);
    runtime->WaitForSingleObject   = (WaitForSingleObject  )(list[6].address);
    runtime->CloseHandle           = (CloseHandle          )(list[7].address);
    return true;
}

static bool initRuntimeEnvironment(Runtime* runtime)
{
    // initialize structure fields
    runtime->Mutex = NULL;
    runtime->MemoryTracker = NULL;
    // create global mutex
    HANDLE hMutex = runtime->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    runtime->Mutex = hMutex;
    // create context data for initialize other modules
    Context context = 
    {
        .FindAPI     = runtime->Args->FindAPI,
        .MainMemPage = runtime->MainMemPage,

        .VirtualAlloc          = runtime->VirtualAlloc,
        .VirtualFree           = runtime->VirtualFree,
        .VirtualProtect        = runtime->VirtualProtect,
        .FlushInstructionCache = runtime->FlushInstructionCache,
        .CreateMutexA          = runtime->CreateMutexA,
        .ReleaseMutex          = runtime->ReleaseMutex,
        .WaitForSingleObject   = runtime->WaitForSingleObject,
        .CloseHandle           = runtime->CloseHandle,

        .Mutex = runtime->Mutex,
    };
    if (!initMemoryTracker(runtime, &context))
    {
        return false;
    }
    if (!initThreadTracker(runtime, &context))
    {
        return false;
    }
    return true;
}

static bool initMemoryTracker(Runtime* runtime, Context* context)
{
    MemoryTracker_M* tracker = InitMemoryTracker(context);
    if (tracker == NULL)
    {
        return false;
    }
    runtime->MemoryTracker = tracker;
    return true;
}

static bool initThreadTracker(Runtime* runtime, Context* context)
{
    ThreadTracker_M* tracker = InitThreadTracker(context);
    if (tracker == NULL)
    {
        return false;
    }
    runtime->ThreadTracker = tracker;
    return true;
}

static bool updateRuntimePointers(Runtime* runtime)
{    
    typedef struct {
        void* address; uintptr pointer;
    } method;
    method methods[] = 
    {
        { &RT_Hide,    METHOD_ADDR_HIDE },
        { &RT_Recover, METHOD_ADDR_RECOVER },
        { &RT_Stop,    METHOD_ADDR_STOP },
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

// change memory protect for dynamic update pointer that hard encode.
static bool adjustPageProtect(Runtime* runtime, uint32* old)
{
    if (runtime->Args->NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(&EncryptBuf);
    uintptr end   = (uintptr)(&RT_Stop);
    uint    size  = end - begin + 64;
    return runtime->VirtualProtect(begin, size, PAGE_EXECUTE_READWRITE, old);
}

static bool recoverPageProtect(Runtime* runtime, uint32* old)
{
    uintptr begin = (uintptr)(&EncryptBuf);
    uintptr end   = (uintptr)(&RT_Stop);
    uint    size  = end - begin + 64;
    if (!runtime->Args->NotAdjustProtect)
    {
        if (!runtime->VirtualProtect(begin, size, *old, old))
        {
            return false;
        }
    }
    return runtime->FlushInstructionCache(-1, begin, size);
}

static void cleanRuntime(Runtime* runtime)
{
    CloseHandle closeHandle = runtime->CloseHandle;
    if (closeHandle != NULL && runtime->Mutex != NULL)
    {
        closeHandle(runtime->Mutex);
    }

    // must copy api address before call RandBuf
    VirtualFree virtualFree = runtime->VirtualFree;
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
void RT_Sleep()
{

}

__declspec(noinline)
bool RT_Hide()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_HIDE);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    if (!runtime->MemoryTracker->MemEncrypt())
    {
        return false;
    }

    runtime->ReleaseMutex(runtime->Mutex);
    return true;
}

__declspec(noinline)
bool RT_Recover()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_RECOVER);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    if (!runtime->MemoryTracker->MemDecrypt())
    {
        return false;
    }

    runtime->ReleaseMutex(runtime->Mutex);
    return true;
}

__declspec(noinline)
bool RT_Stop()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_STOP);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    if (!runtime->MemoryTracker->MemClean())
    {
        return false;
    }

    runtime->ReleaseMutex(runtime->Mutex);
    return true;
}
