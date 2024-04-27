#include "go_types.h"
#include "windows_t.h"
#include "hash_api.h"
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

typedef struct memoryPage {
    uint   size;
    uint32 protect;
    byte   iv[CRYPTO_IV_SIZE];

    struct memoryPage* next;
} memoryPage;

// make sure the memory address is 16 bytes aligned.
#define MEMORY_PAGE_PAD_SIZE    sizeof(memoryPage) % 16
#define MEMORY_PAGE_HEADER_SIZE sizeof(memoryPage) + MEMORY_PAGE_PAD_SIZE

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

    memoryPage* FirstPage;

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
static bool initTrackerEnvironment(MemoryTracker* tracker, Context* context);
static bool updateTrackerPointers(MemoryTracker* tracker);
static bool updateTrackerPointer(MemoryTracker* tracker, void* method, uintptr address);
static uintptr allocatePage(MemoryTracker* tracker, uintptr page, uint size, uint32 protect);

MemoryTracker_M* InitMemoryTracker(Context* context)
{
    // set structure address
    uintptr address = context->StructMemPage;
    uintptr trackerAddr = address + 1000 + RandUint(address) % 256;
    uintptr moduleAddr  = address + 1300 + RandUint(address) % 256;
    // initialize tracker
    MemoryTracker* tracker = (MemoryTracker*)trackerAddr;
    bool success = true;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            success = false;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
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
    tracker->VirtualAlloc          = context->VirtualAlloc;
    tracker->VirtualFree           = context->VirtualFree;
    tracker->VirtualProtect        = context->VirtualProtect;
    tracker->FlushInstructionCache = context->FlushInstructionCache;
    tracker->CreateMutexA          = context->CreateMutexA;
    tracker->ReleaseMutex          = context->ReleaseMutex;
    tracker->WaitForSingleObject   = context->WaitForSingleObject;
    tracker->CloseHandle           = context->CloseHandle;
    return true;
}

static bool initTrackerEnvironment(MemoryTracker* tracker, Context* context)
{
    tracker->Mutex     = context->Mutex;
    tracker->FirstPage = NULL;
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
    for (uintptr i = 0; i < 64; i++)
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

    // lock recorded memory pages
    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return NULL;
    }
    uintptr page;
    bool success = true;
    for (;;)
    {
        page = tracker->VirtualAlloc(address, size + MEMORY_PAGE_HEADER_SIZE, type, protect);
        if (page == NULL)
        {
            success = false;
            break;
        }
        page = allocatePage(tracker, page, size, protect);
        break;
    }
    // unlock recorded memory pages
    tracker->ReleaseMutex(tracker->Mutex);
    if (!success)
    {
        return NULL;
    }
    return page;
}

// write memory header data at the front of the actual memory page
static uintptr allocatePage(MemoryTracker* tracker, uintptr page, uint size, uint32 protect)
{
    memoryPage* memPage = (memoryPage*)page;

    memPage->size    = size;
    memPage->protect = protect;
    RandBuf(&memPage->iv[0], CRYPTO_IV_SIZE);
    memPage->next = tracker->FirstPage;

    uintptr pad = page + MEMORY_PAGE_HEADER_SIZE - MEMORY_PAGE_PAD_SIZE;
    RandBuf((byte*)pad, MEMORY_PAGE_PAD_SIZE);
    return page + MEMORY_PAGE_HEADER_SIZE;
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
