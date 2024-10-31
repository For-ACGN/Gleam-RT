#include "c_types.h"
#include "windows_t.h"
#include "rel_addr.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "list_md.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "memory.h"
#include "debug.h"

typedef struct {
    uintptr address;
    uint    size;
    bool    lock;
} memRegion;

typedef struct {
    uintptr address;
    uint32  protect;
    bool    lock;

    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
} memPage;

typedef struct {
    HANDLE hHeap;
    uint32 options;
} heapObject;

typedef struct {
    uintptr address;
    uint    size;
    HANDLE  hHeap;

    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
} heapBlock;

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    VirtualQuery_t          VirtualQuery;
    VirtualLock_t           VirtualLock;
    VirtualUnlock_t         VirtualUnlock;
    GetProcessHeap_t        GetProcessHeap;
    HeapCreate_t            HeapCreate;
    HeapDestroy_t           HeapDestroy;
    HeapAlloc_t             HeapAlloc;
    HeapReAlloc_t           HeapReAlloc;
    HeapFree_t              HeapFree;
    ReleaseMutex_t          ReleaseMutex;
    WaitForSingleObject_t   WaitForSingleObject;
    FlushInstructionCache_t FlushInstructionCache;
    CloseHandle_t           CloseHandle;

    // runtime data
    uint32 PageSize; // memory page size
    HANDLE hMutex;   // protect data

    // store memory regions
    List Regions;
    byte RegionsKey[CRYPTO_KEY_SIZE];
    byte RegionsIV [CRYPTO_IV_SIZE];

    // store memory pages
    List Pages;
    byte PagesKey[CRYPTO_KEY_SIZE];
    byte PagesIV [CRYPTO_IV_SIZE];

    // store private heap objects
    List Heaps;
    byte HeapsKey[CRYPTO_KEY_SIZE];
    byte HeapsIV [CRYPTO_IV_SIZE];

    // store heap blocks
    List Blocks;
    byte BlocksKey[CRYPTO_KEY_SIZE];
    byte BlocksIV[CRYPTO_IV_SIZE];
} MemoryTracker;

// methods for IAT hooks
LPVOID MT_VirtualAlloc(LPVOID address, SIZE_T size, DWORD type, DWORD protect);
BOOL   MT_VirtualFree(LPVOID address, SIZE_T size, DWORD type);
BOOL   MT_VirtualProtect(LPVOID address, SIZE_T size, DWORD new, DWORD* old);
SIZE_T MT_VirtualQuery(LPCVOID address, POINTER buffer, SIZE_T length);
BOOL   MT_VirtualLock(LPVOID address, SIZE_T size);
BOOL   MT_VirtualUnlock(LPVOID address, SIZE_T size);
HANDLE MT_HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
BOOL   MT_HeapDestroy(HANDLE hHeap);
LPVOID MT_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
LPVOID MT_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
BOOL   MT_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

// methods for runtime and hooks about msvcrt.dll
void* MT_MemAlloc(uint size);
void* MT_MemCalloc(uint num, uint size);
void* MT_MemRealloc(void* ptr, uint size);
void  MT_MemFree(void* ptr);
uint  MT_MemSize(void* ptr);

bool  MT_Lock();
bool  MT_Unlock();
errno MT_Encrypt();
errno MT_Decrypt();
errno MT_FreeAll();
errno MT_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF111111C2
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCDC2
#endif
static MemoryTracker* getTrackerPointer();

static bool initTrackerAPI(MemoryTracker* tracker, Context* context);
static bool updateTrackerPointer(MemoryTracker* tracker);
static bool recoverTrackerPointer(MemoryTracker* tracker);
static bool initTrackerEnvironment(MemoryTracker* tracker, Context* context);
static bool allocPage(MemoryTracker* tracker, uintptr address, uint size, uint32 type, uint32 protect);
static bool reserveRegion(MemoryTracker* tracker, uintptr address, uint size);
static bool commitPage(MemoryTracker* tracker, uintptr address, uint size, uint32 protect);
static bool freePage(MemoryTracker* tracker, uintptr address, uint size, uint32 type);
static bool decommitPage(MemoryTracker* tracker, uintptr address, uint size);
static bool releasePage(MemoryTracker* tracker, uintptr address, uint size);
static bool deletePages(MemoryTracker* tracker, uintptr address, uint size);
static void protectPage(MemoryTracker* tracker, uintptr address, uint size, uint32 protect);
static bool lock_memory(MemoryTracker* tracker, uintptr address);
static bool unlock_memory(MemoryTracker* tracker, uintptr address);
static bool set_memory_locker(MemoryTracker* tracker, uintptr address, bool lock);
static bool addHeapObject(MemoryTracker* tracker, HANDLE hHeap, uint32 options);
static bool delHeapObject(MemoryTracker* tracker, HANDLE hHeap);

static uint32 replacePageProtect(uint32 protect);
static bool   isPageTypeTrackable(uint32 type);
static bool   isPageProtectWriteable(uint32 protect);
static bool   adjustPageProtect(MemoryTracker* tracker, memPage* page);
static bool   recoverPageProtect(MemoryTracker* tracker, memPage* page);

static bool encryptPage(MemoryTracker* tracker, memPage* page);
static bool decryptPage(MemoryTracker* tracker, memPage* page);
static bool isEmptyPage(MemoryTracker* tracker, memPage* page);
static void deriveKey(MemoryTracker* tracker, memPage* page, byte* key);
static bool cleanPage(MemoryTracker* tracker, memPage* page);

static void eraseTrackerMethods(Context* context);
static void cleanTracker(MemoryTracker* tracker);

MemoryTracker_M* InitMemoryTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 5500 + RandUintN(address, 128);
    uintptr moduleAddr  = address + 6500 + RandUintN(address, 128);
    // initialize tracker
    MemoryTracker* tracker = (MemoryTracker*)trackerAddr;
    mem_init(tracker, sizeof(MemoryTracker));
    // store options
    tracker->NotEraseInstruction = context->NotEraseInstruction;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errno = ERR_MEMORY_INIT_API;
            break;
        }
        if (!updateTrackerPointer(tracker))
        {
            errno = ERR_MEMORY_UPDATE_PTR;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errno = ERR_MEMORY_INIT_ENV;
            break;
        }
        break;
    }
    eraseTrackerMethods(context);
    if (errno != NO_ERROR)
    {
        cleanTracker(tracker);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for tracker
    MemoryTracker_M* module = (MemoryTracker_M*)moduleAddr;
    // Windows API hooks
    module->VirtualAlloc   = GetFuncAddr(&MT_VirtualAlloc);
    module->VirtualFree    = GetFuncAddr(&MT_VirtualFree);
    module->VirtualProtect = GetFuncAddr(&MT_VirtualProtect);
    module->VirtualQuery   = GetFuncAddr(&MT_VirtualQuery);
    module->VirtualLock    = GetFuncAddr(&MT_VirtualLock);
    module->VirtualUnlock  = GetFuncAddr(&MT_VirtualUnlock);
    module->HeapCreate     = GetFuncAddr(&MT_HeapCreate);
    module->HeapDestroy    = GetFuncAddr(&MT_HeapDestroy);
    module->HeapAlloc      = GetFuncAddr(&MT_HeapAlloc);
    module->HeapReAlloc    = GetFuncAddr(&MT_HeapReAlloc);
    module->HeapFree       = GetFuncAddr(&MT_HeapFree);
    // methods for runtime
    module->Alloc   = GetFuncAddr(&MT_MemAlloc);
    module->Calloc  = GetFuncAddr(&MT_MemCalloc);
    module->Realloc = GetFuncAddr(&MT_MemRealloc);
    module->Free    = GetFuncAddr(&MT_MemFree);
    module->Size    = GetFuncAddr(&MT_MemSize);
    module->Lock    = GetFuncAddr(&MT_Lock);
    module->Unlock  = GetFuncAddr(&MT_Unlock);
    module->Encrypt = GetFuncAddr(&MT_Encrypt);
    module->Decrypt = GetFuncAddr(&MT_Decrypt);
    module->FreeAll = GetFuncAddr(&MT_FreeAll);
    module->Clean   = GetFuncAddr(&MT_Clean);
    return module;
}

__declspec(noinline)
static bool initTrackerAPI(MemoryTracker* tracker, Context* context)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x69E4CD5EB08400FD, 0x648D50E649F8C06E }, // VirtualQuery
        { 0x24AB671FD240FDCB, 0x40A8B468E734C166 }, // VirtualLock
        { 0x5BE15B295B21235B, 0x5E6AFF64FB431502 }, // VirtualUnlock
        { 0xA9CA8BFA460B3D0E, 0x30FECC3CA9988F6A }, // GetProcessHeap
        { 0x3CF9F7C4C1B8FD43, 0x34B7FC51484FB2A3 }, // HeapCreate
        { 0xEBA36FC951FD2B34, 0x59504100D9684B0E }, // HeapDestroy
        { 0x8D604A3248B6EAFE, 0x496C489A6E3B8ECD }, // HeapAlloc
        { 0xE04E489AFF9C386C, 0x1A2E6AE0D610549B }, // HeapReAlloc
        { 0x76F81CD39D7A292A, 0x82332A8834C25FA2 }, // HeapFree
    };
#elif _WIN32
    {
        { 0x79D75104, 0x92F1D233 }, // VirtualQuery
        { 0x2149FD08, 0x6537772D }, // VirtualLock
        { 0xCE162EEC, 0x5D903E73 }, // VirtualUnlock
        { 0x758C3172, 0x23E44CDB }, // GetProcessHeap
        { 0x857D374F, 0x7DC1A133 }, // HeapCreate
        { 0x87A7067F, 0x5B6BA0B9 }, // HeapDestroy
        { 0x6E86E11A, 0x692C7E92 }, // HeapAlloc
        { 0x0E0168E2, 0xFBFF0866 }, // HeapReAlloc
        { 0x94D5662A, 0x266763A1 }, // HeapFree
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    tracker->VirtualQuery   = list[0].proc;
    tracker->VirtualLock    = list[1].proc;
    tracker->VirtualUnlock  = list[2].proc;
    tracker->GetProcessHeap = list[3].proc;
    tracker->HeapCreate     = list[4].proc;
    tracker->HeapDestroy    = list[5].proc;
    tracker->HeapAlloc      = list[6].proc;
    tracker->HeapReAlloc    = list[7].proc;
    tracker->HeapFree       = list[8].proc;

    tracker->VirtualAlloc          = context->VirtualAlloc;
    tracker->VirtualFree           = context->VirtualFree;
    tracker->VirtualProtect        = context->VirtualProtect;
    tracker->ReleaseMutex          = context->ReleaseMutex;
    tracker->WaitForSingleObject   = context->WaitForSingleObject;
    tracker->FlushInstructionCache = context->FlushInstructionCache;
    tracker->CloseHandle           = context->CloseHandle;
    return true;
}

// CANNOT merge updateTrackerPointer and recoverTrackerPointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateTrackerPointer(MemoryTracker* tracker)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getTrackerPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != TRACKER_POINTER)
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

__declspec(noinline)
static bool recoverTrackerPointer(MemoryTracker* tracker)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getTrackerPointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)tracker)
        {
            target++;
            continue;
        }
        *pointer = TRACKER_POINTER;
        success = true;
        break;
    }
    return success;
}

__declspec(noinline)
static bool initTrackerEnvironment(MemoryTracker* tracker, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    tracker->hMutex = hMutex;
    // initialize memory region and page list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Regions, &ctx, sizeof(memRegion));
    List_Init(&tracker->Pages,   &ctx, sizeof(memPage));
    List_Init(&tracker->Heaps,   &ctx, sizeof(heapObject));
    List_Init(&tracker->Blocks,  &ctx, sizeof(heapBlock));
    // set crypto context data
    RandBuffer(tracker->RegionsKey, CRYPTO_KEY_SIZE);
    RandBuffer(tracker->RegionsIV,  CRYPTO_IV_SIZE);
    RandBuffer(tracker->PagesKey,   CRYPTO_KEY_SIZE);
    RandBuffer(tracker->PagesIV,    CRYPTO_IV_SIZE);
    RandBuffer(tracker->HeapsKey,   CRYPTO_KEY_SIZE);
    RandBuffer(tracker->HeapsIV,    CRYPTO_IV_SIZE);
    RandBuffer(tracker->BlocksKey,  CRYPTO_KEY_SIZE);
    RandBuffer(tracker->BlocksIV,   CRYPTO_IV_SIZE);
    // copy runtime context data
    tracker->PageSize = context->PageSize;
    return true;
}

__declspec(noinline)
static void eraseTrackerMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initTrackerAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseTrackerMethods));
    uintptr size  = end - begin;
    RandBuffer((byte*)begin, (int64)size);
}

__declspec(noinline)
static void cleanTracker(MemoryTracker* tracker)
{
    if (tracker->CloseHandle != NULL && tracker->hMutex != NULL)
    {
        tracker->CloseHandle(tracker->hMutex);
    }
    List_Free(&tracker->Regions);
    List_Free(&tracker->Pages);
    List_Free(&tracker->Heaps);
    List_Free(&tracker->Blocks);
}

// updateTrackerPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateTrackerPointer will fail.
#pragma optimize("", off)
static MemoryTracker* getTrackerPointer()
{
    uintptr pointer = TRACKER_POINTER;
    return (MemoryTracker*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
LPVOID MT_VirtualAlloc(LPVOID address, SIZE_T size, DWORD type, DWORD protect)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    dbg_log(
        "[memory]", "VirtualAlloc: 0x%zX, 0x%zX, 0x%X, 0x%X",
        address, size, type, protect
    );

    // adjust protect at sometime
    protect = replacePageProtect(protect);

    LPVOID page;
    bool success = true;
    for (;;)
    {
        page = tracker->VirtualAlloc(address, size, type, protect);
        if (page == NULL)
        {
            success = false;
            break;
        }
        if (!allocPage(tracker, (uintptr)page, size, type, protect))
        {
            success = false;
            break;
        }
        break;
    }

    if (!MT_Unlock())
    {
        if (page != NULL)
        {
            tracker->VirtualFree(page, 0, MEM_RELEASE);
        }
        return NULL;
    }
    if (!success)
    {
        if (page != NULL)
        {
            tracker->VirtualFree(page, 0, MEM_RELEASE);
        }
        return NULL;
    }
    return page;
}

static bool allocPage(MemoryTracker* tracker, uintptr address, uint size, uint32 type, uint32 protect)
{
    if (!isPageTypeTrackable(type))
    {
        return true;
    }
    switch (type&0xF000)
    {
    case MEM_COMMIT:
        return commitPage(tracker, address, size, protect);
    case MEM_RESERVE:
        return reserveRegion(tracker, address, size);
    case MEM_COMMIT|MEM_RESERVE:
        if (!reserveRegion(tracker, address, size))
        {
            return false;
        }
        return commitPage(tracker, address, size, protect);
    default:
        return false;
    }
}

static bool reserveRegion(MemoryTracker* tracker, uintptr address, uint size)
{
    memRegion region = {
        .address = address,
        .size    = size,
        .lock    = false,
    };
    return List_Insert(&tracker->Regions, &region);
}

#pragma optimize("t", on)
static bool commitPage(MemoryTracker* tracker, uintptr address, uint size, uint32 protect)
{
    // copy memory to register for improve performance
    register uint pageSize = tracker->PageSize;
    register uint numPage  = size / pageSize;
    if ((size % pageSize) != 0)
    {
        numPage++;
    }
    memPage page = {
        .protect = protect,
        .lock    = false,
    };
    register List* pages = &tracker->Pages;
    for (uint i = 0; i < numPage; i++)
    {
        page.address = address + i * pageSize;
        if (!List_Insert(pages, &page))
        {
            return false;
        }
    }
    return true;
}
#pragma optimize("t", off)

__declspec(noinline)
BOOL MT_VirtualFree(LPVOID address, SIZE_T size, DWORD type)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    dbg_log(
        "[memory]", "VirtualFree: 0x%zX, 0x%zX, 0x%X",
        address, size, type
    );

    BOOL success = true;
    for (;;)
    {
        if (!tracker->VirtualFree(address, size, type))
        {
            success = false;
            break;
        }
        if (!freePage(tracker, (uintptr)address, size, type))
        {
            success = false;
            break;
        }
        break;
    }

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

static bool freePage(MemoryTracker* tracker, uintptr address, uint size, uint32 type)
{
    switch (type&0xF000)
    {
    case MEM_DECOMMIT:
        return decommitPage(tracker, address, size);
    case MEM_RELEASE:
        return releasePage(tracker, address, size);
    default:
        return false;
    }
}

static bool decommitPage(MemoryTracker* tracker, uintptr address, uint size)
{
    if (size != 0)
    {
        return deletePages(tracker, address, size);
    }
    // search memory regions list
    register List* regions = &tracker->Regions;
    register uint  len     = regions->Len;
    register uint  index   = 0;
    for (uint num = 0; num < len; index++)
    {
        memRegion* region = List_Get(regions, index);
        if (region->address == 0)
        {
            continue;
        }
        if (region->address != address)
        {
            num++;
            continue;
        }
        return deletePages(tracker, region->address, region->size);
    }
    return false;
}

static bool releasePage(MemoryTracker* tracker, uintptr address, uint size)
{
    if (size != 0)
    {
        return false;
    }
    // search memory regions list
    register List* regions = &tracker->Regions;
    register uint  len     = regions->Len;
    register uint  index   = 0;
    register memRegion* region;
    bool found = false;
    for (uint num = 0; num < len; index++)
    {
        region = List_Get(regions, index);
        if (region->address == 0)
        {
            continue;
        }
        if (region->address != address)
        {
            num++;
            continue;
        }
        if (!deletePages(tracker, region->address, region->size))
        {
            return false;
        }
        if (!List_Delete(regions, index))
        {
            return false;
        }
        found = true;
        // maybe exist same region, so need continue
        num++;
    }
    return found;
}

#pragma optimize("t", on)
static bool deletePages(MemoryTracker* tracker, uintptr address, uint size)
{
    register uint pageSize = tracker->PageSize;

    register List* pages = &tracker->Pages;
    register uint  len   = pages->Len;
    register uint  index = 0;
    for (uint num = 0; num < len; index++)
    {
        memPage* page = List_Get(pages, index);
        if (page->address == 0)
        {
            continue;
        }
        if ((page->address + pageSize <= address) || (page->address >= address + size))
        {
            num++;
            continue;
        }
        // remove page in list
        if (!List_Delete(pages, index))
        {
            return false;
        }
        num++;
    }
    return true;
}
#pragma optimize("t", off)

__declspec(noinline)
BOOL MT_VirtualProtect(LPVOID address, SIZE_T size, DWORD new, DWORD* old)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    dbg_log(
        "[memory]", "VirtualProtect: 0x%zX, 0x%zX, 0x%X", 
        address, size, new
    );

    BOOL success = true;
    for (;;)
    {
        if (!tracker->VirtualProtect(address, size, new, old))
        {
            success = false;
            break;
        }
        protectPage(tracker, (uintptr)address, size, new);
        break;
    }

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

static void protectPage(MemoryTracker* tracker, uintptr address, uint size, uint32 protect)
{
    register uint pageSize = tracker->PageSize;

    register List* pages = &tracker->Pages;
    register uint  len   = pages->Len;
    register uint  index = 0;
    register memPage* page;
    for (uint num = 0; num < len; index++)
    {
        page = List_Get(pages, index);
        if (page->address == 0)
        {
            continue;
        }
        if ((page->address + pageSize <= address) || (page->address >= address + size))
        {
            num++;
            continue;
        }
        page->protect = protect;
        num++;
    }
}

__declspec(noinline)
SIZE_T MT_VirtualQuery(LPCVOID address, POINTER buffer, SIZE_T length)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return 0;
    }

    dbg_log("[memory]", "VirtualQuery: 0x%zX", address);

    uint size = tracker->VirtualQuery(address, buffer, length);

    if (!MT_Unlock())
    {
        return 0;
    }
    return size;
}

__declspec(noinline)
BOOL MT_VirtualLock(LPVOID address, SIZE_T size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    dbg_log("[memory]", "VirtualLock: 0x%zX", address);

    // if size is zero, only set a flag to memory page and
    // region that prevent MT_FreeAll free these memory 
    BOOL success;
    if (size == 0)
    {
        success = lock_memory(tracker, (uintptr)address);
    } else {
        success = tracker->VirtualLock(address, size);
    }

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
BOOL MT_VirtualUnlock(LPVOID address, SIZE_T size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    dbg_log("[memory]", "VirtualUnlock: 0x%zX", address);

    // if size is zero, only unset a flag to memory page
    // and region that MT_FreeAll will free these memory 
    BOOL success;
    if (size == 0)
    {
        success = unlock_memory(tracker, (uintptr)address);
    } else {
        success = tracker->VirtualUnlock(address, size);
    }

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

__declspec(noinline)
HANDLE MT_HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    dbg_log(
        "[memory]", "HeapCreate: 0x%X, 0x%zX, 0x%zX",
        flOptions, dwInitialSize, dwMaximumSize
    );

    HANDLE hHeap;

    errno lastErr = NO_ERROR;
    bool  success = false;
    for (;;)
    {
        hHeap = tracker->HeapCreate(flOptions, dwInitialSize, dwMaximumSize);
        if (hHeap == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        if (!addHeapObject(tracker, hHeap, flOptions))
        {
            break;
        }
        success = true;
        break;
    }

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return hHeap;
}

static bool addHeapObject(MemoryTracker* tracker, HANDLE hHeap, uint32 options)
{
    heapObject heap = {
        .hHeap   = hHeap,
        .options = options,
    };
    if (!List_Insert(&tracker->Heaps, &heap))
    {
        tracker->HeapDestroy(hHeap);
        return false;
    }
    return true;
}

__declspec(noinline)
BOOL MT_HeapDestroy(HANDLE hHeap)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    dbg_log("[memory]", "HeapDestroy: 0x%X", hHeap);

    errno lastErr = NO_ERROR;
    bool  success = false;
    for (;;)
    {
        if (!tracker->HeapDestroy(hHeap))
        {
            lastErr = GetLastErrno();
            break;
        }
        if (!delHeapObject(tracker, hHeap))
        {
            break;
        }
        success = true;
        break;
    }

    if (!MT_Unlock())
    {
        return false;
    }

    SetLastErrno(lastErr);
    return success;
}

static bool delHeapObject(MemoryTracker* tracker, HANDLE hHeap)
{
    List* heaps = &tracker->Heaps;
    heapObject heap = {
        .hHeap = hHeap,
    };
    uint index;
    if (!List_Find(heaps, &heap, sizeof(heap.hHeap), &index))
    {
        return false;
    }
    if (!List_Delete(heaps, index))
    {
        return false;
    }
    return true;
}

__declspec(noinline)
LPVOID MT_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    return NULL;
}

__declspec(noinline)
LPVOID MT_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    return NULL;
}

__declspec(noinline)
BOOL MT_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    return true;
}

static bool lock_memory(MemoryTracker* tracker, uintptr address)
{
    return set_memory_locker(tracker, address, true);
}

static bool unlock_memory(MemoryTracker* tracker, uintptr address)
{
    return set_memory_locker(tracker, address, false);
}

#pragma optimize("t", on)
static bool set_memory_locker(MemoryTracker* tracker, uintptr address, bool lock)
{
    // search memory regions list
    register List* regions = &tracker->Regions;
    register uint  len     = regions->Len;
    register uint  index   = 0;
    register memRegion* region;

    // record region size and set locker
    uint regionSize = 0;
    bool found = false;
    for (uint num = 0; num < len; index++)
    {
        region = List_Get(regions, index);
        if (region->address == 0)
        {
            continue;
        }
        if (region->address != address)
        {
            num++;
            continue;
        }
        regionSize = region->size;
        region->lock = lock;
        found = true;
        break;
    }
    if (!found || regionSize == 0)
    {
        return false;
    }

    // set memory page locker
    register uint pageSize = tracker->PageSize;
    register List* pages   = &tracker->Pages;
    len   = pages->Len;
    index = 0;
    register memPage* page;
    found = false;
    for (uint num = 0; num < len; index++)
    {
        page = List_Get(pages, index);
        if (page->address == 0)
        {
            continue;
        }
        if ((page->address + pageSize <= address) || (page->address >= address + regionSize))
        {
            num++;
            continue;
        }
        page->lock = lock;
        found = true;
        num++;
    }
    return found;
}
#pragma optimize("t", off)

// replacePageProtect is used to make sure all the page are readable.
// avoid inadvertently using sensitive permissions.
static uint32 replacePageProtect(uint32 protect)
{
    switch (protect&0xFF)
    {
    case PAGE_NOACCESS:
        return (protect&0xFFFFFF00)+PAGE_READONLY;
    case PAGE_EXECUTE:
        return (protect&0xFFFFFF00)+PAGE_EXECUTE_READ;
    default:
        return protect;
    }
}

static bool isPageTypeTrackable(uint32 type)
{
    switch (type&0xF000)
    {
    case MEM_COMMIT:
        break;
    case MEM_RESERVE:
        break;
    case MEM_COMMIT|MEM_RESERVE:
        break;
    default:
        return false;
    }
    return true;
}

static bool isPageProtectWriteable(uint32 protect)
{
    switch (protect&0xFF)
    {
    case PAGE_READWRITE:
        break;
    case PAGE_WRITECOPY:
        break;
    case PAGE_EXECUTE_READWRITE:
        break;
    case PAGE_EXECUTE_WRITECOPY:
        break;
    default:
        return false;
    }
    return true;
}

// adjustPageProtect is used to make sure this page is writeable.
static bool adjustPageProtect(MemoryTracker* tracker, memPage* page)
{
    if (isPageProtectWriteable(page->protect))
    {
        return true;
    }
    LPVOID address = (LPVOID)(page->address);
    SIZE_T size    = (SIZE_T)(tracker->PageSize);
    uint32 old;
    return tracker->VirtualProtect(address, size, PAGE_READWRITE, &old);
}

// recoverPageProtect is used to recover to prevent protect.
static bool recoverPageProtect(MemoryTracker* tracker, memPage* page)
{
    if (isPageProtectWriteable(page->protect))
    {
        return true;
    }
    LPVOID address = (LPVOID)(page->address);
    SIZE_T size    = (SIZE_T)(tracker->PageSize);
    uint32 old;
    return tracker->VirtualProtect(address, size, page->protect, &old);
}

// +---------+----------+-------------+
// |  size   | capacity | user buffer |
// +---------+----------+-------------+
// |  uint   |   uint   |     var     |
// +---------+----------+-------------+

__declspec(noinline)
void* MT_MemAlloc(uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (size == 0)
    {
        return NULL;
    }
    // ensure the size is a multiple of memory page size.
    // it also for prevent track the special page size.
    uint pageSize = ((size / tracker->PageSize) + 1) * tracker->PageSize;
    void* addr = MT_VirtualAlloc(NULL, pageSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    // store the size at the head of the memory page
    // ensure the memory address is 16 bytes aligned
    byte* address = (byte*)addr;
    RandBuffer(address, 16);
    // record user input size
    mem_copy(address, &size, sizeof(uint));
    // record buffer capacity
    uint cap = pageSize - 16;
    mem_copy(address + sizeof(uint), &cap, sizeof(uint));
    dbg_log("[memory]", "malloc size: %zu", size);
    return (void*)(address + 16);
}

__declspec(noinline)
void* MT_MemCalloc(uint num, uint size)
{
    uint total = num * size;
    if (total == 0)
    {
        return NULL;
    }
    void* addr = MT_MemAlloc(total);
    if (addr == NULL)
    {
        return NULL;
    }
    mem_init(addr, total);
    dbg_log("[memory]", "calloc num: %zu, size: %zu", num, size);
    return addr;
}

__declspec(noinline)
void* MT_MemRealloc(void* ptr, uint size)
{
    if (ptr == NULL)
    {
        return MT_MemAlloc(size);
    }
    if (size == 0)
    {
        MT_MemFree(ptr);
        return NULL;
    }
    // check need expand capacity
    uint cap = *(uint*)((uintptr)(ptr)-16+sizeof(uint));
    if (size <= cap)
    {
        *(uint*)((uintptr)(ptr)-16) = size;
        return ptr;
    }
    // allocate new memory
    if (size < 65536)
    {
        cap = size * 2;
    } else {
        cap = size * 5 / 4; // size *= 1.25
    }
    void* newPtr = MT_MemAlloc(cap);
    if (newPtr == NULL)
    {
        return NULL;
    }
    // copy data to new memory
    uint oldSize = *(uint*)((uintptr)(ptr)-16);
    mem_copy(newPtr, ptr, oldSize);
    // free old memory
    MT_MemFree(ptr);
    dbg_log("[memory]", "realloc ptr: 0x%zX, size: %zu", ptr, size);
    return newPtr;
}

__declspec(noinline)
void MT_MemFree(void* ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    // clean the buffer data before call VirtualFree.
    void* addr = (LPVOID)((uintptr)(ptr)-16);
    uint  size = *(uint*)addr;
    mem_init((byte*)addr, size);
    if (MT_VirtualFree(addr, 0, MEM_RELEASE))
    {
        dbg_log("[memory]", "free ptr: 0x%zX", ptr);
        return;
    }
    dbg_log("[memory]", "failed to call VirtualFree: 0x%X", GetLastErrno());
}

__declspec(noinline)
uint MT_MemSize(void* ptr)
{
    if (ptr == NULL)
    {
        return 0;
    }
    return *(uint*)((uintptr)(ptr)-16);
}

__declspec(noinline)
bool MT_Lock()
{
    MemoryTracker* tracker = getTrackerPointer();

    uint32 event = tracker->WaitForSingleObject(tracker->hMutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

__declspec(noinline)
bool MT_Unlock()
{
    MemoryTracker* tracker = getTrackerPointer();

    return tracker->ReleaseMutex(tracker->hMutex);
}

__declspec(noinline)
errno MT_Encrypt()
{
    MemoryTracker* tracker = getTrackerPointer();

    List* pages = &tracker->Pages;
    uint  index = 0;
    for (uint num = 0; num < pages->Len; index++)
    {
        memPage* page = List_Get(pages, index);
        if (page->address == 0)
        {
            continue;
        }
        if (!encryptPage(tracker, page))
        {
            return ERR_MEMORY_ENCRYPT_PAGE;
        }
        num++;
    }

    // encrypt region and page list
    List* list = &tracker->Regions;
    byte* key  = tracker->RegionsKey;
    byte* iv   = tracker->RegionsIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);

    list = &tracker->Pages;
    key  = tracker->PagesKey;
    iv   = tracker->PagesIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);
    return NO_ERROR;
}

static bool encryptPage(MemoryTracker* tracker, memPage* page)
{
    if (isEmptyPage(tracker, page))
    {
        return true;
    }
    if (!adjustPageProtect(tracker, page))
    {
        return false;
    }
    // generate new key and IV
    RandBuffer(page->key, CRYPTO_KEY_SIZE);
    RandBuffer(page->iv, CRYPTO_IV_SIZE);
    byte key[CRYPTO_KEY_SIZE];
    deriveKey(tracker, page, key);
    EncryptBuf((byte*)(page->address), tracker->PageSize, key, page->iv);
    return true;
}

__declspec(noinline)
errno MT_Decrypt()
{
    MemoryTracker* tracker = getTrackerPointer();

    // decrypt region and page list
    List* list = &tracker->Regions;
    byte* key  = tracker->RegionsKey;
    byte* iv   = tracker->RegionsIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    list = &tracker->Pages;
    key  = tracker->PagesKey;
    iv   = tracker->PagesIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    // reverse order traversal is used to deal with the problem
    // that some memory pages may be encrypted twice, like use
    // VirtualAlloc to allocate multiple times to the same address
    List* pages = &tracker->Pages;
    uint  index = pages->Last;
    for (uint num = 0; num < pages->Len; index--)
    {
        memPage* page = List_Get(pages, index);
        if (page->address == 0)
        {
            continue;
        }
        if (!decryptPage(tracker, page))
        {
            return ERR_MEMORY_DECRYPT_PAGE;
        }
        num++;
    }
    dbg_log("[memory]", "regions: %zu", tracker->Regions.Len);
    dbg_log("[memory]", "pages:   %zu", tracker->Pages.Len);
    return NO_ERROR;
}

static bool decryptPage(MemoryTracker* tracker, memPage* page)
{
    if (isEmptyPage(tracker, page))
    {
        return true;
    }
    byte key[CRYPTO_KEY_SIZE];
    deriveKey(tracker, page, key);
    DecryptBuf((byte*)(page->address), tracker->PageSize, key, page->iv);
    if (!recoverPageProtect(tracker, page))
    {
        return false;
    }
    return true;
}

static bool isEmptyPage(MemoryTracker* tracker, memPage* page)
{
    register uint*  addr = (uint*)(page->address);
    register uint32 num  = tracker->PageSize/sizeof(uint*);
    for (uint32 i = 0; i < num; i++)
    {
        if (*addr != 0)
        {
            return false;
        }
        addr++;
    }
    return true;
}

static void deriveKey(MemoryTracker* tracker, memPage* page, byte* key)
{
    // copy original key
    mem_copy(key, page->key, CRYPTO_KEY_SIZE);
    // cover some bytes
    uintptr addr = (uintptr)page;
    addr += ((uintptr)tracker) << (sizeof(uintptr)/2);
    addr += ((uintptr)tracker->VirtualAlloc) >> 4;
    addr += ((uintptr)tracker->VirtualFree)  >> 6;
    mem_copy(key+4, &addr, sizeof(uintptr));
}

__declspec(noinline)
errno MT_FreeAll()
{
    MemoryTracker* tracker = getTrackerPointer();

    List* pages   = &tracker->Pages;
    List* regions = &tracker->Regions;
    errno errno   = NO_ERROR;

    // cover memory page data
    uint len   = pages->Len;
    uint index = 0;
    for (uint num = 0; num < len; index++)
    {
        memPage* page = List_Get(pages, index);
        if (page->address == 0)
        {
            continue;
        }
        // skip locked memory page
        if (page->lock)
        {
            num++;
            continue;
        }
        // cover memory page
        if (isPageProtectWriteable(page->protect))
        {
            RandBuffer((byte*)(page->address), tracker->PageSize);
        }
        num++;
    }

    // decommit memory pages
    index = 0;
    for (uint num = 0; num < len; index++)
    {
        memPage* page = List_Get(pages, index);
        if (page->address == 0)
        {
            continue;
        }
        // skip locked memory page
        if (page->lock)
        {
            num++;
            continue;
        }
        // free memory page
        if (!cleanPage(tracker, page))
        {
            errno = ERR_MEMORY_CLEAN_PAGE;
        }
        if (!List_Delete(pages, index))
        {
            errno = ERR_MEMORY_DELETE_PAGE;
        }
        num++;
    }

    // release reserved memory region
    len   = regions->Len;
    index = 0;
    for (uint num = 0; num < len; index++)
    {
        memRegion* region = List_Get(regions, index);
        if (region->address == 0)
        {
            continue;
        }
        // skip locked memory region
        if (region->lock)
        {
            num++;
            continue;
        }
        // release memory region
        if (!tracker->VirtualFree((LPVOID)(region->address), 0, MEM_RELEASE))
        {
            errno = ERR_MEMORY_CLEAN_REGION;
        }
        if (!List_Delete(regions, index))
        {
            errno = ERR_MEMORY_DELETE_REGION;
        }
        num++;
    }
    return errno;
}

__declspec(noinline)
errno MT_Clean()
{
    MemoryTracker* tracker = getTrackerPointer();

    List* pages   = &tracker->Pages;
    List* regions = &tracker->Regions;
    errno errno   = NO_ERROR;

    // cover memory page data
    uint index = 0;
    for (uint num = 0; num < pages->Len; index++)
    {
        memPage* page = List_Get(pages, index);
        if (page->address == 0)
        {
            continue;
        }
        // cover memory page
        if (isPageProtectWriteable(page->protect))
        {
            RandBuffer((byte*)(page->address), tracker->PageSize);
        }
        num++;
    }

    // decommit memory pages
    index = 0;
    for (uint num = 0; num < pages->Len; index++)
    {
        memPage* page = List_Get(pages, index);
        if (page->address == 0)
        {
            continue;
        }
        if (!cleanPage(tracker, page) && errno == NO_ERROR)
        {
            errno = ERR_MEMORY_CLEAN_PAGE;
        }
        num++;
    }

    // release reserved memory region
    index = 0;
    for (uint num = 0; num < regions->Len; index++)
    {
        memRegion* region = List_Get(regions, index);
        if (region->address == 0)
        {
            continue;
        }
        if (!tracker->VirtualFree((LPVOID)(region->address), 0, MEM_RELEASE))
        {
            if (errno == NO_ERROR)
            {
                errno = ERR_MEMORY_CLEAN_REGION;
            }
        }
        num++;
    }

    // clean memory region and page list
    RandBuffer(regions->Data, List_Size(regions));
    RandBuffer(pages->Data, List_Size(pages));
    if (!List_Free(regions) && errno == NO_ERROR)
    {
        errno = ERR_MEMORY_FREE_PAGE_LIST;
    }
    if (!List_Free(pages) && errno == NO_ERROR)
    {
        errno = ERR_MEMORY_FREE_REGION_LIST;
    }

    // close mutex
    if (!tracker->CloseHandle(tracker->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_MEMORY_CLOSE_MUTEX;
    }

    // recover instructions
    if (tracker->NotEraseInstruction)
    {
        if (!recoverTrackerPointer(tracker) && errno == NO_ERROR)
        {
            errno = ERR_MEMORY_RECOVER_INST;
        }
    }
    return errno;
}

static bool cleanPage(MemoryTracker* tracker, memPage* page)
{
    LPVOID addr = (LPVOID)(page->address);
    DWORD  size = (DWORD)(tracker->PageSize);
    return tracker->VirtualFree(addr, size, MEM_DECOMMIT);
}
