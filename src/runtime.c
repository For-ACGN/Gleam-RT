#include "go_types.h"
#include "hash_api.h"
#include "random.h"
#include "runtime.h"

// hard encoded address in methods for replace
#ifdef _WIN64
    #define METHOD_ADDR_HIDE    0x7FFFFFFFFFFFFFF0
    #define METHOD_ADDR_RECOVER 0x7FFFFFFFFFFFFFF1
    #define METHOD_ADDR_CLEAN   0x7FFFFFFFFFFFFFF2
#elif _WIN32
    #define METHOD_ADDR_HIDE    0x7FFFFFF0
    #define METHOD_ADDR_RECOVER 0x7FFFFFF1
    #define METHOD_ADDR_CLEAN   0x7FFFFFF2
#endif

typedef struct {
    FindAPI_t FindAPI;

    // *MemoryMgr MemoryMgr
    // *ThreadMgr ThreadMgr
} Runtime;

void Hide();
void Recover();
void Clean();

static bool updateRuntimePointers(Runtime* runtime);
static bool updateRuntimePointer(Runtime* runtime, void* method, uintptr address);

Runtime_M* InitRuntime(FindAPI_t findAPI)
{
    // allocate memory for store structures.
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
    // initialize runtime
    Runtime* runtime = (Runtime*)(address + 128);
    runtime->FindAPI = findAPI;
    bool success = true;
    for (;;)
    {




        if (!updateRuntimePointers(runtime))
        {
            success = false;
            break;
        }
        break;
    }
    if (!success)
    {
        RandBuf((byte*)address, 4096);
    #ifdef _WIN64
        uint64 hash = 0x04989F7862AEABA4;
        uint64 key  = 0xC7825C3DB35EE20E;
    #elif _WIN32
        uint32 hash = 0xF76A2ADE;
        uint32 key  = 0x4D8938BD;
    #endif
        VirtualFree virtualFree = (VirtualFree)findAPI(hash, key);
        if (virtualFree == NULL)
        {
            return NULL;
        }
        virtualFree(address, 0, MEM_RELEASE);
        return NULL;
    }
    // create methods about Runtime
    Runtime_M* module = (Runtime_M*)(address + 2048);
    module->Hide    = &Hide;
    module->Recover = &Recover;
    module->Clean   = &Clean;
    return module;
}

// change memory protect for dynamic update pointer that hard encode.
static bool updateRuntimePointers(Runtime* runtime)
{    
    FindAPI_t findAPI = runtime->FindAPI;
#ifdef _WIN64
    uint64 hash = 0xEA5B0C76C7946815;
    uint64 key  = 0x8846C203C35DE586;
#elif _WIN32
    uint32 hash = 0xB2AC456D;
    uint32 key  = 0x2A690F63;
#endif
    VirtualProtect virtualProtect = (VirtualProtect)findAPI(hash, key);
    if (virtualProtect == NULL)
    {
        return false;
    }
    uintptr memBegin = (uintptr)(&Hide);
    uintptr memSize  = 8192;
    // change memory protect
    uint32 old;
    if (!virtualProtect(memBegin, memSize, PAGE_EXECUTE_READWRITE, &old))
    {
        return false;
    }
    bool success = true;
    for(;;)
    {
        if (!updateRuntimePointer(runtime, &Hide, METHOD_ADDR_HIDE))
        {
            success =  false;
            break;
        }
        if (!updateRuntimePointer(runtime, &Recover, METHOD_ADDR_RECOVER))
        {
            success = false;
            break;
        }
        if (!updateRuntimePointer(runtime, &Clean, METHOD_ADDR_CLEAN))
        {
            success = false;
            break;
        }
        break;
    }
    // recovery memory protect
    if (!virtualProtect(memBegin, memSize, old, &old))
    {
        return false;
    }
    return success;
}

static bool updateRuntimePointer(Runtime* runtime, void* method, uintptr address)
{
    bool success = false;
    uintptr target = (uintptr)method;
    uintptr* pointer;
    for (uintptr i = 0; i < 32; i++)
    {
        pointer = (uintptr*)(target);
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

__declspec(noinline) void Hide()
{
    // updatePointer will replace it to the actual address
    Runtime* runtime = (Runtime*)(METHOD_ADDR_HIDE);

    runtime->FindAPI(0,0);
}

__declspec(noinline) void Recover()
{
    // updatePointer will replace it to the actual address
    Runtime* runtime = (Runtime*)(METHOD_ADDR_RECOVER);

    runtime->FindAPI(0, 0);
}

__declspec(noinline) void Clean()
{
    // updatePointer will replace it to the actual address
    Runtime* runtime = (Runtime*)(METHOD_ADDR_CLEAN);

    runtime->FindAPI(0, 0);
}
