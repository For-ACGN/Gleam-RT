#include "go_types.h"
#include "hash_api.h"
#include "random.h"
#include "runtime.h"

typedef struct {
    FindAPI_t FindAPI;

    // *MemoryMgr MemoryMgr

    // *ThreadMgr ThreadMgr


} Runtime;

RuntimeM* NewRuntime(FindAPI_t findAPI)
{
    // allocate memory for store MemMgr structure.
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

    Runtime* runtime = (Runtime*)(address + 128 + RandInt(address) % 512);

    runtime->FindAPI = findAPI;


    return 1;
}
