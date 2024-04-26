#include "go_types.h"
#include "hash_api.h"
#include "windows_t.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "memory.h"

// hard encoded address in methods for replace
#ifdef _WIN64
    #define METHOD_ADDR_VIRTUAL_ALLOC   0x7FFFFFFFFFFFFF00
    #define METHOD_ADDR_VIRTUAL_FREE    0x7FFFFFFFFFFFFF01
    #define METHOD_ADDR_VIRTUAL_PROTECT 0x7FFFFFFFFFFFFF02
    #define METHOD_ADDR_ENCRYPT         0x7FFFFFFFFFFFFF03
    #define METHOD_ADDR_DECRYPT         0x7FFFFFFFFFFFFF04
    #define METHOD_ADDR_CLEAN           0x7FFFFFFFFFFFFF05
#elif _WIN32
    #define METHOD_ADDR_VIRTUAL_ALLOC   0x7FFFFF00
    #define METHOD_ADDR_VIRTUAL_FREE    0x7FFFFF01
    #define METHOD_ADDR_VIRTUAL_PROTECT 0x7FFFFF02
    #define METHOD_ADDR_ENCRYPT         0x7FFFFF03
    #define METHOD_ADDR_DECRYPT         0x7FFFFF04
    #define METHOD_ADDR_CLEAN           0x7FFFFF05
#endif

typedef struct {
    // API address from runtime
    VirtualAlloc   VirtualAlloc;
    VirtualFree    VirtualFree;
    VirtualProtect VirtualProtect;
    FlushInstCache FlushInstCache;

} MemoryTracker;

// methods about memory tracker
uintptr MT_VirtualAlloc(uintptr address, uint size, uint32 type, uint32 protect);
uintptr MT_VirtualFree(uintptr address, uint size, uint32 type);
uintptr MT_VirtualProtect(uintptr address, uint size, uint32 new, uint32* old);
void*   MT_MemAlloc(uint size);
void    MT_MemFree(void* address);
void    MT_Encrypt();
void    MT_Decrypt();
void    MT_Clean();

static bool initTrackerAPI(MemoryTracker* tracker, Context* context);
static bool updateTrackerPointers(MemoryTracker* tracker);
static bool updateTrackerPointer(MemoryTracker* tracker, void* method, uintptr address);

MemoryTracker_M* InitMemoryTracker(Context* context)
{
    // set structure address
    uintptr address = context->StructMemPage;
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

    module->VirtualAlloc   = (VirtualAlloc  )(&MT_VirtualAlloc);
    module->VirtualFree    = (VirtualFree   )(&MT_VirtualFree);
    module->VirtualProtect = (VirtualProtect)(&MT_VirtualProtect);

    module->MemAlloc   = &MT_MemAlloc;
    module->MemFree    = &MT_MemFree;
    module->MemEncrypt = &MT_Encrypt;
    module->MemDecrypt = &MT_Decrypt;
    module->MemClean   = &MT_Clean;
    return module;
}

static bool initTrackerAPI(MemoryTracker* tracker, Context* context)
{
    tracker->VirtualAlloc   = context->VirtualAlloc;
    tracker->VirtualFree    = context->VirtualFree;
    tracker->VirtualProtect = context->VirtualProtect;
    tracker->FlushInstCache = context->FlushInstCache;
    return true;
}

static bool updateTrackerPointers(MemoryTracker* tracker)
{
    uintptr memBegin = (uintptr)(&MT_VirtualAlloc);
    uint    memSize = 8192;
    // change memory protect
    uint32 old;
    if (!tracker->VirtualProtect(memBegin, memSize, PAGE_EXECUTE_READWRITE, &old))
    {
        return false;
    }
    // update pointer in methods
    typedef struct {
        void*   address;
        uintptr pointer;
    } method;
    method methods[] = 
    {
        {&MT_VirtualAlloc,   METHOD_ADDR_VIRTUAL_ALLOC},
        {&MT_VirtualFree,    METHOD_ADDR_VIRTUAL_FREE},
        {&MT_VirtualProtect, METHOD_ADDR_VIRTUAL_PROTECT},
        {&MT_Encrypt,        METHOD_ADDR_ENCRYPT},
        {&MT_Decrypt,        METHOD_ADDR_DECRYPT},
        {&MT_Clean,          METHOD_ADDR_CLEAN},
    };
    bool success = true;
    for (int i = 0; i < arrlen(methods); i++)
    {
        if (!updateTrackerPointer(tracker, methods[i].address, methods[i].pointer))
        {
            success = false;
            break;
        }
    }
    // recovery memory protect
    if (!tracker->VirtualProtect(memBegin, memSize, old, &old))
    {
        return false;
    }
    if (!success)
    {
        return false;
    }
    return tracker->FlushInstCache(-1, memBegin, memSize);
}

static bool updateTrackerPointer(MemoryTracker* tracker, void* method, uintptr address)
{
    bool success = false;
    uintptr target = (uintptr)method;
    for (uintptr i = 0; i < 32; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer == address)
        {
            *pointer = (uintptr)tracker;
            success = true;
            break;
        }
        target++;
    }
    return success;
}

__declspec(noinline)
uintptr MT_VirtualAlloc(uintptr address, uint size, uint32 type, uint32 protect)
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_VIRTUAL_ALLOC);

   return tracker->VirtualAlloc(address, size, type, protect);
}

#pragma optimize("", off)
__declspec(noinline)
uintptr MT_VirtualFree(uintptr address, uint size, uint32 type)
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_VIRTUAL_FREE);

    return tracker->VirtualFree(address, size, type);
}
#pragma optimize("", on)

#pragma optimize("", off)
__declspec(noinline)
uintptr MT_VirtualProtect(uintptr address, uint size, uint32 new, uint32* old)
{
    // updateTrackerPointers will replace it to the actual address
    MemoryTracker* tracker = (MemoryTracker*)(METHOD_ADDR_VIRTUAL_PROTECT);

    return tracker->VirtualProtect(address, size, new, old);
}
#pragma optimize("", on)

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
