#include "go_types.h"
#include "hash_api.h"
#include "windows_t.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "memory.h"

// hard encoded address in methods for replace
#ifdef _WIN64
    #define METHOD_ADDR_MEM_ALLOC       0x7FFFFFFFFFFFFF00
    #define METHOD_ADDR_MEM_FREE        0x7FFFFFFFFFFFFF01
    #define METHOD_ADDR_VIRTUAL_ALLOC   0x7FFFFFFFFFFFFF02
    #define METHOD_ADDR_VIRTUAL_FREE    0x7FFFFFFFFFFFFF03
    #define METHOD_ADDR_VIRTUAL_PROTECT 0x7FFFFFFFFFFFFF04
    #define METHOD_ADDR_ENCRYPT         0x7FFFFFFFFFFFFF05
    #define METHOD_ADDR_DECRYPT         0x7FFFFFFFFFFFFF06
    #define METHOD_ADDR_CLEAN           0x7FFFFFFFFFFFFF07
#elif _WIN32
    #define METHOD_ADDR_MEM_ALLOC       0x7FFFFF00
    #define METHOD_ADDR_MEM_FREE        0x7FFFFF01
    #define METHOD_ADDR_VIRTUAL_ALLOC   0x7FFFFF02
    #define METHOD_ADDR_VIRTUAL_FREE    0x7FFFFF03
    #define METHOD_ADDR_VIRTUAL_PROTECT 0x7FFFFF04
    #define METHOD_ADDR_ENCRYPT         0x7FFFFF05
    #define METHOD_ADDR_DECRYPT         0x7FFFFF06
    #define METHOD_ADDR_CLEAN           0x7FFFFF07
#endif

typedef struct {
    // API address from runtime
    VirtualAlloc   VirtualAlloc;
    VirtualFree    VirtualFree;
    VirtualProtect VirtualProtect;

} MemoryTracker;

// methods about memory tracker
void*   MT_MemAlloc(uint size);
void    MT_MemFree(void* address);
uintptr MT_VirtualAlloc(uintptr lpAddress, uint dwSize, uint32 flAllocationType, uint32 flProtect);
uintptr MT_VirtualFree(uintptr lpAddress, uint dwSize, uint32 dwFreeType);
uintptr MT_VirtualProtect(uintptr lpAddress, uint dwSize, uint32 flNewProtect, uint32* lpflOldProtect);
void    MT_Encrypt();
void    MT_Decrypt();
void    MT_Clean();


static bool initTrackerAPI(MemoryTracker* tracker, Context* context);
static bool updateTrackerPointers(MemoryTracker* tracker);

MemoryTracker_M* InitMemoryTracker(Context* context)
{
    // set structure address
    uintptr address = context->MemoryPage;
    uintptr trackerAddr = address + 1000 + RandUint(address) % 256;
    uintptr moduleAddr  = address + 1300 + RandUint(address) % 256;
    // initialize tracker
    MemoryTracker* tracker = (MemoryTracker*)trackerAddr;
    initTrackerAPI(tracker, context);
    bool success = true;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            success = false;
            break;
        }
        if (!updateTrackerPointers(tracker))
        {
            success = false;
            break;
        }
        break;
    }
    if (!success)
    {
        return NULL;
    }
    // create methods about tracker
    MemoryTracker_M* module = (MemoryTracker_M*)moduleAddr;
    module->MemAlloc = &MT_MemAlloc;
    module->MemFree  = &MT_MemFree;
    return module;
}

static bool initTrackerAPI(MemoryTracker* tracker, Context* context)
{
    tracker->VirtualAlloc   = context->VirtualAlloc;
    tracker->VirtualFree    = context->VirtualFree;
    tracker->VirtualProtect = context->VirtualProtect;
    return true;
}

static bool updateTrackerPointers(MemoryTracker* tracker)
{
    return true;
}

__declspec(noinline)
void* MT_MemAlloc(uint size)
{
    return (void*)MT_VirtualAlloc(0, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
}

__declspec(noinline)
void MT_MemFree(void* address)
{
    MT_VirtualFree((uintptr)address, 0, MEM_RELEASE);
}

__declspec(noinline) 
uintptr MT_VirtualAlloc(uintptr address, uint size, uint32 type, uint32 protect)
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_VIRTUAL_ALLOC);

    tracker->VirtualAlloc(address, size, type, protect);

}

__declspec(noinline)
uintptr MT_VirtualFree(uintptr address, uint size, uint32 type)
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_VIRTUAL_FREE);

    tracker->VirtualFree(address, size, type);
}

__declspec(noinline)
uintptr MT_VirtualProtect(uintptr address, uint size, uint32 newProtect, uint32* oldProtect)
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_VIRTUAL_PROTECT);

    tracker->VirtualProtect(address, size, newProtect, oldProtect);
}

__declspec(noinline)
void MT_Encrypt()
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_ENCRYPT);

    tracker->VirtualAlloc(0, 1, 0, 0);
}

__declspec(noinline)
void MT_Decrypt()
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_DECRYPT);

    tracker->VirtualAlloc(0, 1, 0, 0);
}

__declspec(noinline)
void MT_Clean()
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_CLEAN);

    tracker->VirtualAlloc(0, 1, 0, 0);
}
