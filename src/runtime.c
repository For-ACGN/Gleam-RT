#include "go_types.h"
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
    FindAPI_t FindAPI;

    // memory page for store structures.
    uintptr MemoryPage;

    // API addresses
    VirtualAlloc   VirtualAlloc;
    VirtualFree    VirtualFree;
    VirtualProtect VirtualProtect;
    FlushInstCache FlushInstCache;

    // sub modules
    MemoryTracker_M* MemoryTracker;
} Runtime;

// methods about Runtime
void RT_Hide();
void RT_Recover();
void RT_Stop();

static uintptr allocateRuntimeMemory(FindAPI_t findAPI);
static bool initRuntimeAPI(Runtime* runtime);
static bool initMemoryTracker(Runtime* runtime);
static bool updateRuntimePointers(Runtime* runtime);
static bool updateRuntimePointer(Runtime* runtime, void* method, uintptr address);

Runtime_M* InitRuntime(FindAPI_t findAPI)
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
    runtime->FindAPI = findAPI;
    runtime->MemoryPage = address;
    bool success = true;
    for (;;)
    {
        if (!initRuntimeAPI(runtime))
        {
            success = false;
            break;
        }
        if (!initMemoryTracker(runtime))
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
        // must copy api address before call RandBuf
        VirtualFree virtualFree = runtime->VirtualFree;
        RandBuf((byte*)address, 4096);
        if (virtualFree != NULL)
        {
            virtualFree(address, 0, MEM_RELEASE);
        }
        return NULL;
    }
    // clean context data in runtime structure
    // runtime->FindAPI        = NULL; // TODO recover it
    RandBuf((byte*)runtime + 8, sizeof(Runtime) - 8 - 16);
    // create methods about Runtime
    Runtime_M* module = (Runtime_M*)moduleAddr;
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
    FlushInstCache flushInstCache = (FlushInstCache)findAPI(hash, key);
    if (flushInstCache == NULL)
    {
        return false;
    }

    runtime->VirtualAlloc   = virtualAlloc;
    runtime->VirtualFree    = virtualFree;
    runtime->VirtualProtect = virtualProtect;
    runtime->FlushInstCache = flushInstCache;
    return true;
}

static bool initMemoryTracker(Runtime* runtime)
{
    Context ctx = {
        .MemoryPage     = runtime->MemoryPage,
        .VirtualAlloc   = runtime->VirtualAlloc,
        .VirtualFree    = runtime->VirtualFree,
        .VirtualProtect = runtime->VirtualProtect,
        .FlushInstCache = runtime->FlushInstCache,
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
    return runtime->FlushInstCache(-1, memBegin, memSize);
}

static bool updateRuntimePointer(Runtime* runtime, void* method, uintptr address)
{
    bool success = false;
    uintptr target = (uintptr)method;
    for (uintptr i = 0; i < 32; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer == address)
        {
            *pointer = (uintptr)runtime;
            success = true;
            break;
        }
        target++;
    }
    return success;
}

__declspec(noinline) 
void RT_Hide()
{
    // updateRuntimePointers will replace it to the actual address
    Runtime* runtime = (Runtime*)(METHOD_ADDR_HIDE);

    runtime->FindAPI(0, 0);
}

__declspec(noinline)
void RT_Recover()
{
    // updateRuntimePointers will replace it to the actual address
    Runtime* runtime = (Runtime*)(METHOD_ADDR_RECOVER);

    runtime->FindAPI(0, 0);
}

__declspec(noinline)
void RT_Stop()
{
    // updateRuntimePointers will replace it to the actual address
    Runtime* runtime = (Runtime*)(METHOD_ADDR_STOP);

    runtime->FindAPI(0, 0);
}
