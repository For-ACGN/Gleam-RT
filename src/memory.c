#include "go_types.h"
#include "hash_api.h"
#include "windows_t.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "memory.h"

// hard encoded address in methods for replace
#ifdef _WIN64
    #define METHOD_ADDR_MEMALLOC 0x7FFFFFFFFFFFFF00
    #define METHOD_ADDR_MEMFREE  0x7FFFFFFFFFFFFF01
#elif _WIN32
    #define METHOD_ADDR_MEMALLOC 0x7FFFFF00
    #define METHOD_ADDR_MEMFREE  0x7FFFFF01
#endif

typedef struct {
    // API address from runtime
    VirtualAlloc   VirtualAlloc;
    VirtualFree    VirtualFree;
    VirtualProtect VirtualProtect;

} MemoryTracker;

// methods about memory tracker
void* MemAlloc(uint size);
void  MemFree(void* address);

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
    module->MemAlloc = &MemAlloc;
    module->MemFree  = &MemFree;
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

__declspec(noinline) void* MemAlloc(uint size)
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_MEMALLOC);

}

__declspec(noinline) void MemFree(void* address)
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_MEMFREE);

}
