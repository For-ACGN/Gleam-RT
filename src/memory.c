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
    // API addresses
    VirtualAlloc          VirtualAlloc;
    VirtualFree           VirtualFree;
    VirtualProtect        VirtualProtect;
    FlushInstructionCache FlushInstructionCache;
    CreateMutexA          CreateMutexA;
    ReleaseMutex          ReleaseMutex;
    WaitForSingleObject   WaitForSingleObject;
    CloseHandle           CloseHandle;

    HANDLE Mutex;
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
static bool initTrackerEnvironment(MemoryTracker* tracker);
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
        if (!initTrackerEnvironment(tracker))
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
    // clean context data in runtime structure
    tracker->FlushInstructionCache = NULL;
    // RandBuf((byte*)runtime + 8, sizeof(Runtime) - 8 - 16);

    // create methods about tracker
    MemoryTracker_M* module = (MemoryTracker_M*)moduleAddr;
    // Windows API hooks
    module->VirtualAlloc   = (VirtualAlloc  )(&MT_VirtualAlloc);
    module->VirtualFree    = (VirtualFree   )(&MT_VirtualFree);
    module->VirtualProtect = (VirtualProtect)(&MT_VirtualProtect);
    // methods for runtime
    module->MemAlloc   = &MT_MemAlloc;
    module->MemFree    = &MT_MemFree;
    module->MemEncrypt = &MT_Encrypt;
    module->MemDecrypt = &MT_Decrypt;
    module->MemClean   = &MT_Clean;
    return module;
}

static bool initTrackerAPI(MemoryTracker* tracker, Context* context)
{
    FindAPI_t findAPI = context->FindAPI;

#ifdef _WIN64
    uint64 hash = 0x31FE697F93D7510C;
    uint64 key  = 0x77C8F05FE04ED22D;
#elif _WIN32
    uint32 hash = 0x8F5BAED2;
    uint32 key  = 0x43487DC7;
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

    tracker->CreateMutexA        = createMutexA;
    tracker->ReleaseMutex        = releaseMutex;
    tracker->WaitForSingleObject = waitForSingleObject;
    tracker->CloseHandle         = closeHandle;

    tracker->VirtualAlloc          = context->VirtualAlloc;
    tracker->VirtualFree           = context->VirtualFree;
    tracker->VirtualProtect        = context->VirtualProtect;
    tracker->FlushInstructionCache = context->FlushInstructionCache;

    context->CreateMutexA        = createMutexA;
    context->ReleaseMutex        = releaseMutex;
    context->WaitForSingleObject = waitForSingleObject;
    context->CloseHandle         = closeHandle;
    return true;
}

static bool initTrackerEnvironment(MemoryTracker* tracker)
{
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
    return tracker->FlushInstructionCache(-1, memBegin, memSize);
}

static bool updateTrackerPointer(MemoryTracker* tracker, void* method, uintptr address)
{
    bool success = false;
    uintptr target = (uintptr)method;
    for (uintptr i = 0; i < 32; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != address)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)tracker;
        success = true;
        break;
    }
    return success;
}

// updateTrackerPointers will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateTrackerPointer will fail.
#pragma optimize("", off)
static MemoryTracker* getTrackerPointer(uintptr pointer)
{
    return (MemoryTracker*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
uintptr MT_VirtualAlloc(uintptr address, uint size, uint32 type, uint32 protect)
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_VIRTUAL_ALLOC);

   return tracker->VirtualAlloc(address, size, type, protect);
}

__declspec(noinline)
uintptr MT_VirtualFree(uintptr address, uint size, uint32 type)
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_VIRTUAL_FREE);

    return tracker->VirtualFree(address, size, type);
}

__declspec(noinline)
uintptr MT_VirtualProtect(uintptr address, uint size, uint32 new, uint32* old)
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_VIRTUAL_PROTECT);

    return tracker->VirtualProtect(address, size, new, old);
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
void MT_Encrypt()
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_ENCRYPT);

    tracker->VirtualAlloc(0, 1, 0, 0);
}

__declspec(noinline)
void MT_Decrypt()
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_DECRYPT);

    tracker->VirtualAlloc(0, 1, 0, 0);
}

__declspec(noinline)
void MT_Clean()
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_CLEAN);

    tracker->VirtualAlloc(0, 1, 0, 0);
}
