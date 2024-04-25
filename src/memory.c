#include "go_types.h"
#include "hash_api.h"
#include "windows_t.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "memory.h"

typedef struct {
    // API address from runtime
    VirtualAlloc   VirtualAlloc;
    VirtualFree    VirtualFree;
    VirtualProtect VirtualProtect;

} MemoryTracker;

// static bool initTrackerAPI(MemoryMgr* manager);

MemoryTracker_M* InitMemoryTracker(Context* context)
{
    return NULL;
}



__declspec(noinline) void* MemAlloc(uint size)
{

}

__declspec(noinline) void MemFree(void* address)
{

}
