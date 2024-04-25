#include "go_types.h"
#include "hash_api.h"
#include "random.h"
#include "runtime.h"

typedef struct {
    FindAPI_t FindAPI;

    // *MemoryMgr MemoryMgr
    // *ThreadMgr ThreadMgr
} Runtime;

void Hide();

static bool updatePointers(Runtime* runtime, FindAPI_t findAPI);

RuntimeM* NewRuntime(FindAPI_t findAPI)
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

    Runtime* runtime = (Runtime*)(address + 128);
    runtime->FindAPI = findAPI;


    if (!updatePointers(runtime, findAPI))
    {
        // clean 
        return NULL;
    } else {
        // return 123;
    }

    RuntimeM* runtimeM = (RuntimeM*)(address+2048);
    runtimeM->Hide = &Hide;
    return runtimeM;
}

static bool updatePointers(Runtime* runtime, FindAPI_t findAPI)
{
    // change memory protect for update pointer that hard encode
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
    uint32 old;
    if (!virtualProtect((uintptr)(&Hide), 8192, PAGE_EXECUTE_READWRITE, &old))
    {
        return false;
    }
    bool ok = false;

    uintptr addr = (uintptr)(&Hide);
    uintptr* ptr;
    for (uintptr i = 0; i < 64; i++)
    {
        ptr = (uintptr*)(addr);
        if (*ptr == 0x7FFFFFFFFFFFFFF0)
        {
            *ptr = (uintptr)runtime;

            ok = true;
            break;
        }
        addr++;
    }


    // recovery memory protect
    if (!virtualProtect((uintptr)(&Hide), 8192, old, &old))
    {
        return false;
    }
    return ok;
} 

__declspec(noinline) void Hide()
{
    // updatePointer will replace to the runtime actual address
#ifdef _WIN64
    Runtime* runtime = (Runtime*)(0x7FFFFFFFFFFFFFF0);
#elif _WIN32
    Runtime* runtime = (Runtime*)(0x7FFFFFF0);
#endif

    // return runtime;
}
