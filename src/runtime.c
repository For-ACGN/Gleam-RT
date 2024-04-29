#include "go_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "context.h"
#include "random.h"
#include "memory.h"
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
    // arguments
    uintptr   EntryPoint;
    uint      SizeOfCode;
    FindAPI_t FindAPI;
    uintptr   StructMemPage;

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
} Runtime;

// methods about Runtime
void RT_Hide();
void RT_Recover();
void RT_Stop();

static uintptr allocateRuntimeMemory(FindAPI_t findAPI);
static bool initRuntimeAPI(Runtime* runtime);
static bool initRuntimeEnvironment(Runtime* runtime);
static bool initMemoryTracker(Runtime* runtime);
static bool updateRuntimePointers(Runtime* runtime);
static bool updateRuntimePointer(Runtime* runtime, void* method, uintptr address);
static void cleanRuntime(Runtime* runtime);

__declspec(noinline)
Runtime_M* InitRuntime(uintptr entry, uint size, FindAPI_t findAPI)
{
    uintptr address = allocateRuntimeMemory(findAPI);
    if (address == NULL)
    {
        return NULL;
    }
    // set structure address
    uintptr runtimeAddr = address + 300 + RandUint(address) % 256;
    uintptr moduleAddr  = address + 600 + RandUint(address) % 256;
    // initialize runtime
    Runtime* runtime = (Runtime*)runtimeAddr;
    runtime->EntryPoint = entry;
    runtime->SizeOfCode = size; 
    runtime->FindAPI = findAPI;
    runtime->StructMemPage = address;
    runtime->Mutex = NULL;
    bool success = true;
    for (;;)
    {
        if (!initRuntimeAPI(runtime))
        {
            success = false;
            break;
        }
        if (!initRuntimeEnvironment(runtime))
        {
            success = false;
            break;
        }
        if (!updateRuntimePointers(runtime))
        {
            success = false;
            break;
        }
        break;
    }
    if (!success)
    {
        cleanRuntime(runtime);
    }
    // clean context data in runtime structure
    // runtime->FindAPI        = NULL; // TODO recover it
    // RandBuf((byte*)runtime + 8, sizeof(Runtime) - 8 - 16);
    
    // create methods about Runtime
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
    FindAPI_t findAPI = runtime->FindAPI;

#ifdef _WIN64
    uint64 hash = 0x6AC498DF641A4FCB;
    uint64 key  = 0xFF3BB21B9BA46CEA;
#elif _WIN32
    uint32 hash = 0xB47741D5;
    uint32 key  = 0x8034C451;
#endif
    VirtualAlloc virtualAlloc = (VirtualAlloc)findAPI(hash, key);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }

#ifdef _WIN64
    hash = 0xAC150252A6CA3960;
    key  = 0x12EFAEA421D60C3E;
#elif _WIN32
    hash = 0xF76A2ADE;
    key  = 0x4D8938BD;
#endif
    VirtualFree virtualFree = (VirtualFree)findAPI(hash, key);
    if (virtualFree == NULL)
    {
        return false;
    }

#ifdef _WIN64
     hash = 0xEA5B0C76C7946815;
     key  = 0x8846C203C35DE586;
#elif _WIN32
     hash = 0xB2AC456D;
     key  = 0x2A690F63;
#endif
    VirtualProtect virtualProtect = (VirtualProtect)findAPI(hash, key);
    if (virtualProtect == NULL)
    {
        return false;
    }

#ifdef _WIN64
    hash = 0x8172B49F66E495BA;
    key  = 0x8F0D0796223B56C2;
#elif _WIN32
    hash = 0x87A2CEE8;
    key  = 0x42A3C1AF;
#endif
    FlushInstructionCache flushInstructionCache = (FlushInstructionCache)findAPI(hash, key);
    if (flushInstructionCache == NULL)
    {
        return false;
    }

#ifdef _WIN64
     hash = 0x31FE697F93D7510C;
     key  = 0x77C8F05FE04ED22D;
#elif _WIN32
     hash = 0x8F5BAED2;
     key  = 0x43487DC7;
#endif
    CreateMutexA createMutexA = (CreateMutexA)findAPI(hash, key);
    if (createMutexA == NULL)
    {
        return NULL;
    }

#ifdef _WIN64
    hash = 0xEEFDEA7C0785B561;
    key  = 0xA7B72CC8CD55C1D4;
#elif _WIN32
    hash = 0xFA42E55C;
    key  = 0xEA9F1081;
#endif
    ReleaseMutex releaseMutex = (ReleaseMutex)findAPI(hash, key);
    if (releaseMutex == NULL)
    {
        return NULL;
    }

#ifdef _WIN64
    hash = 0xA524CD56CF8DFF7F;
    key  = 0x5519595458CD47C8;
#elif _WIN32
    hash = 0xC21AB03D;
    key  = 0xED3AAF22;
#endif
    WaitForSingleObject waitForSingleObject = (WaitForSingleObject)findAPI(hash, key);
    if (waitForSingleObject == NULL)
    {
        return NULL;
    }

#ifdef _WIN64
    hash = 0xA25F7449D6939A01;
    key  = 0x85D37F1D89B30D2E;
#elif _WIN32
    hash = 0x60E108B2;
    key  = 0x3C2DFF52;
#endif
    CloseHandle closeHandle = (CloseHandle)findAPI(hash, key);
    if (closeHandle == NULL)
    {
        return NULL;
    }

    runtime->VirtualAlloc          = virtualAlloc;
    runtime->VirtualFree           = virtualFree;
    runtime->VirtualProtect        = virtualProtect;
    runtime->FlushInstructionCache = flushInstructionCache;
    runtime->CreateMutexA          = createMutexA;
    runtime->ReleaseMutex          = releaseMutex;
    runtime->WaitForSingleObject   = waitForSingleObject;
    runtime->CloseHandle           = closeHandle;
    return true;
}

static bool initRuntimeEnvironment(Runtime* runtime)
{
    // create global mutex
    HANDLE hMutex = runtime->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    runtime->Mutex = hMutex;

    if (!initMemoryTracker(runtime))
    {
        return false;
    }
    return true;
}

static bool initMemoryTracker(Runtime* runtime)
{
    Context ctx = {
        .EntryPoint    = runtime->EntryPoint,
        .SizeOfCode    = runtime->SizeOfCode,
        .FindAPI       = runtime->FindAPI,
        .StructMemPage = runtime->StructMemPage,

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
    MemoryTracker_M* tracker = InitMemoryTracker(&ctx);
    if (tracker == NULL)
    {
        return false;
    }
    runtime->MemoryTracker = tracker;
    return true;
}

// change memory protect for dynamic update pointer that hard encode.
static bool updateRuntimePointers(Runtime* runtime)
{    
    uintptr memBegin = (uintptr)(&RT_Hide);
    uint    memSize  = 8192;
    // change memory protect
    uint32 old;
    if (!runtime->VirtualProtect(memBegin, memSize, PAGE_EXECUTE_READWRITE, &old))
    {
        return false;
    }
    // update pointer in methods
    typedef struct {
        void*   address;
        uintptr pointer;
    } method;
    method methods[] = {
        {&RT_Hide,    METHOD_ADDR_HIDE},
        {&RT_Recover, METHOD_ADDR_RECOVER},
        {&RT_Stop,    METHOD_ADDR_STOP},
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
    // recovery memory protect
    if (!runtime->VirtualProtect(memBegin, memSize, old, &old))
    {
        return false;
    }
    if (!success)
    {
        return false;
    }
    return runtime->FlushInstructionCache(-1, memBegin, memSize);
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

static void cleanRuntime(Runtime* runtime)
{
    CloseHandle closeHandle = runtime->CloseHandle;
    if (closeHandle != NULL && runtime->Mutex != NULL)
    {
        closeHandle(runtime->Mutex);
    }

    // must copy api address before call RandBuf
    VirtualFree virtualFree = runtime->VirtualFree;
    RandBuf((byte*)runtime->StructMemPage, 4096);
    if (virtualFree != NULL)
    {
        virtualFree(runtime->StructMemPage, 0, MEM_RELEASE);
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
void RT_Hide()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_HIDE);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return;
    }



    runtime->MemoryTracker->MemEncrypt();

    runtime->ReleaseMutex(runtime->Mutex);
}

__declspec(noinline)
void RT_Recover()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_RECOVER);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return;
    }

    runtime->ReleaseMutex(runtime->Mutex);
}

__declspec(noinline)
void RT_Stop()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_STOP);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return;
    }

    runtime->ReleaseMutex(runtime->Mutex);
}
