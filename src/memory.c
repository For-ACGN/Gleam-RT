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
    // API addresses
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    VirtualQuery_t          VirtualQuery;
    VirtualLock_t           VirtualLock;
    VirtualUnlock_t         VirtualUnlock;
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
} MemoryTracker;

// methods for IAT hooks
LPVOID MT_VirtualAlloc(LPVOID address, SIZE_T size, DWORD type, DWORD protect);
BOOL   MT_VirtualFree(LPVOID address, SIZE_T size, DWORD type);
BOOL   MT_VirtualProtect(LPVOID address, SIZE_T size, DWORD new, DWORD* old);
SIZE_T MT_VirtualQuery(LPCVOID address, POINTER buffer, SIZE_T length);
BOOL   MT_VirtualLock(LPVOID address, SIZE_T size);
BOOL   MT_VirtualUnlock(LPVOID address, SIZE_T size);

// methods for runtime
void* MT_MemAlloc(uint size);
void* MT_MemRealloc(void* address, uint size);
bool  MT_MemFree(void* address);
bool  MT_Lock();
bool  MT_Unlock();
errno MT_Encrypt();
errno MT_Decrypt();
errno MT_FreeAll();
errno MT_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF11111102
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCD02
#endif
static MemoryTracker* getTrackerPointer();

static bool initTrackerAPI(MemoryTracker* tracker, Context* context);
static bool updateTrackerPointer(MemoryTracker* tracker);
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

static void eraseTrackerMethods();
static void cleanTracker(MemoryTracker* tracker);

MemoryTracker_M* InitMemoryTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 4000 + RandUintN(address, 128);
    uintptr moduleAddr  = address + 4700 + RandUintN(address, 128);
    // initialize tracker
    MemoryTracker* tracker = (MemoryTracker*)trackerAddr;
    mem_clean(tracker, sizeof(MemoryTracker));
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
    eraseTrackerMethods();
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
    // methods for runtime
    module->Alloc   = GetFuncAddr(&MT_MemAlloc);
    module->Realloc = GetFuncAddr(&MT_MemRealloc);
    module->Free    = GetFuncAddr(&MT_MemFree);
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
    };
#elif _WIN32
    {
        { 0x79D75104, 0x92F1D233 }, // VirtualQuery
        { 0x2149FD08, 0x6537772D }, // VirtualLock
        { 0xCE162EEC, 0x5D903E73 }, // VirtualUnlock
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
    tracker->VirtualQuery  = list[0].proc;
    tracker->VirtualLock   = list[1].proc;
    tracker->VirtualUnlock = list[2].proc;

    tracker->VirtualAlloc          = context->VirtualAlloc;
    tracker->VirtualFree           = context->VirtualFree;
    tracker->VirtualProtect        = context->VirtualProtect;
    tracker->ReleaseMutex          = context->ReleaseMutex;
    tracker->WaitForSingleObject   = context->WaitForSingleObject;
    tracker->FlushInstructionCache = context->FlushInstructionCache;
    tracker->CloseHandle           = context->CloseHandle;
    return true;
}

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
    // set crypto context data
    RandBuf(&tracker->RegionsKey[0], CRYPTO_KEY_SIZE);
    RandBuf(&tracker->RegionsIV[0], CRYPTO_IV_SIZE);
    RandBuf(&tracker->PagesKey[0], CRYPTO_KEY_SIZE);
    RandBuf(&tracker->PagesIV[0], CRYPTO_IV_SIZE);
    // copy runtime context data
    tracker->PageSize = context->PageSize;
    return true;
}

__declspec(noinline)
static void eraseTrackerMethods()
{
    uintptr begin = (uintptr)(GetFuncAddr(&initTrackerAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseTrackerMethods));
    uintptr size  = end - begin;
    RandBuf((byte*)begin, (int64)size);
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
}

// updateTrackerPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateTrackerPointer will fail.
#pragma optimize("", off)
static MemoryTracker* getTrackerPointer()
{
    uint pointer = TRACKER_POINTER;
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
        "[memory]", "VirtualAlloc: 0x%zX, 0x%zX, 0x%X, 0x%X\n",
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
        "[memory]", "VirtualFree: 0x%zX, 0x%zX, 0x%X\n",
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
        "[memory]", "VirtualProtect: 0x%zX, 0x%zX, 0x%X\n", 
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
    bool found = false;
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

    dbg_log("[memory]", "VirtualQuery: 0x%zX\n", address);

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

    dbg_log("[memory]", "VirtualLock: 0x%zX\n", address);

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

static bool lock_memory(MemoryTracker* tracker, uintptr address)
{
    return set_memory_locker(tracker, address, true);
}

__declspec(noinline)
BOOL MT_VirtualUnlock(LPVOID address, SIZE_T size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    dbg_log("[memory]", "VirtualUnlock: 0x%zX\n", address);

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
    uint regionSize;
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
    if (!found)
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

__declspec(noinline)
void* MT_MemAlloc(uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    // ensure the size is a multiple of memory page size.
    // it also for prevent track the special page size.
    uint  pageSize = ((size / tracker->PageSize) + 1) * tracker->PageSize;
    void* addr = MT_VirtualAlloc(0, pageSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    // store the size at the head of the memory page
    // ensure the memory address is 16 bytes aligned
    byte* address = (byte*)addr;
    RandBuf(address, 16);
    mem_copy(address, &size, sizeof(uint));
    return (void*)(address + 16);
}

__declspec(noinline)
void* MT_MemRealloc(void* address, uint size)
{
    if (address == NULL)
    {
        return MT_MemAlloc(size);
    }
    // allocate new memory
    void* newAddr = MT_MemAlloc(size);
    if (newAddr == NULL)
    {
        return NULL;
    }
    // copy data to new memory
    uint oldSize = *(uint*)((uintptr)(address)-16);
    mem_copy(newAddr, address, oldSize);
    // free old memory
    if (!MT_MemFree(address))
    {
        return NULL;
    }
    return newAddr;
}

__declspec(noinline)
bool MT_MemFree(void* address)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (address == NULL)
    {
        return true;
    }
    // clean the buffer data before call VirtualFree.
    void* addr = (LPVOID)((uintptr)(address)-16);
    uint  size = *(uint*)addr;
    mem_clean((byte*)addr, size);
    return MT_VirtualFree(addr, 0, MEM_RELEASE);
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
    byte* key  = &tracker->RegionsKey[0];
    byte* iv   = &tracker->RegionsIV[0];
    RandBuf(key, CRYPTO_KEY_SIZE);
    RandBuf(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);

    list = &tracker->Pages;
    key  = &tracker->PagesKey[0];
    iv   = &tracker->PagesIV[0];
    RandBuf(key, CRYPTO_KEY_SIZE);
    RandBuf(iv, CRYPTO_IV_SIZE);
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
    RandBuf(&page->key[0], CRYPTO_KEY_SIZE);
    RandBuf(&page->iv[0], CRYPTO_IV_SIZE);
    // use "mem_clean" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    byte key[CRYPTO_KEY_SIZE];
    mem_clean(&key, sizeof(key));
    deriveKey(tracker, page, &key[0]);
    EncryptBuf((byte*)(page->address), tracker->PageSize, &key[0], &page->iv[0]);
    return true;
}

__declspec(noinline)
errno MT_Decrypt()
{
    MemoryTracker* tracker = getTrackerPointer();

    // decrypt region and page list
    List* list = &tracker->Regions;
    byte* key  = &tracker->RegionsKey[0];
    byte* iv   = &tracker->RegionsIV[0];
    DecryptBuf(list->Data, List_Size(list), key, iv);

    list = &tracker->Pages;
    key  = &tracker->PagesKey[0];
    iv   = &tracker->PagesIV[0];
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
    dbg_log("[memory]", "regions: %zu\n", tracker->Regions.Len);
    dbg_log("[memory]", "pages:   %zu\n", tracker->Pages.Len);
    return NO_ERROR;
}

static bool decryptPage(MemoryTracker* tracker, memPage* page)
{
    if (isEmptyPage(tracker, page))
    {
        return true;
    }
    // use "mem_clean" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    byte key[CRYPTO_KEY_SIZE];
    mem_clean(&key, sizeof(key));
    deriveKey(tracker, page, &key[0]);
    DecryptBuf((byte*)(page->address), tracker->PageSize, &key[0], &page->iv[0]);
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
    uintptr addr = (uintptr)page;
    addr += ((uintptr)tracker) << (sizeof(uintptr)/2);
    addr += ((uintptr)tracker->VirtualAlloc) >> 4;
    addr += ((uintptr)tracker->VirtualFree)  >> 6;
    mem_copy(key+0, &page->key[0], CRYPTO_KEY_SIZE);
    mem_copy(key+4, &addr, sizeof(uintptr));
}

__declspec(noinline)
errno MT_FreeAll()
{
    MemoryTracker* tracker = getTrackerPointer();

    List* pages   = &tracker->Pages;
    List* regions = &tracker->Regions;
    errno errno   = NO_ERROR;

    // decommit memory pages
    uint index = 0;
    for (uint num = 0; num < pages->Len; index++)
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
    
    // decommit memory pages
    uint index = 0;
    for (uint num = 0; num < pages->Len; index++)
    {
        memPage* page = List_Get(pages, index);
        if (page->address == 0)
        {
            continue;
        }
        if (!cleanPage(tracker, page))
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
            errno = ERR_MEMORY_CLEAN_REGION;
        }
        num++;
    }

    // clean memory region and page list
    RandBuf(regions->Data, List_Size(regions));
    RandBuf(pages->Data, List_Size(pages));
    if (!List_Free(regions))
    {
        errno = ERR_MEMORY_FREE_PAGE_LIST;
    }
    if (!List_Free(pages))
    {
        errno = ERR_MEMORY_FREE_REGION_LIST;
    }

    // close mutex
    if (!tracker->CloseHandle(tracker->hMutex))
    {
        errno = ERR_MEMORY_CLOSE_MUTEX;
    }
    return errno;
}

static bool cleanPage(MemoryTracker* tracker, memPage* page)
{
    // try to fill random data before decommit memory page.
    if (!adjustPageProtect(tracker, page))
    {
        return false;
    }
    byte* address = (byte*)(page->address);
    RandBuf(address, tracker->PageSize);
    if (!recoverPageProtect(tracker, page))
    {
        return false;
    }
    DWORD size = (DWORD)(tracker->PageSize);
    return tracker->VirtualFree(address, size, MEM_DECOMMIT);
}
