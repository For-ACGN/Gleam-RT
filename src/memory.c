#include <stdio.h>

#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "list_md.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "memory.h"

typedef struct {
    uintptr address;
    uint    size;
} memRegion;

typedef struct {
    uintptr address;
    uint32  protect;

    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
} memPage;

typedef struct {
    // API addresses
    VirtualAlloc_t        VirtualAlloc;
    VirtualFree_t         VirtualFree;
    VirtualProtect_t      VirtualProtect;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;

    // runtime data
    uint32 PageSize; // memory page size
    HANDLE Mutex;    // global mutex

    // store memory regions
    List Regions;
    byte RegionsKey[CRYPTO_KEY_SIZE];
    byte RegionsIV [CRYPTO_IV_SIZE];

    // store memory pages
    List Pages;
    byte PagesKey[CRYPTO_KEY_SIZE];
    byte PagesIV [CRYPTO_IV_SIZE];
} MemoryTracker;

// methods about memory tracker
uintptr MT_VirtualAlloc(uintptr address, uint size, uint32 type, uint32 protect);
bool    MT_VirtualFree(uintptr address, uint size, uint32 type);
bool    MT_VirtualProtect(uintptr address, uint size, uint32 new, uint32* old);
void*   MT_MemAlloc(uint size);
void*   MT_MemRealloc(void* address, uint size);
bool    MT_MemFree(void* address);
bool    MT_Encrypt();
bool    MT_Decrypt();
errno   MT_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF11111101
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCD01
#endif
static MemoryTracker* getTrackerPointer();

static bool mt_lock(MemoryTracker* tracker);
static bool mt_unlock(MemoryTracker* tracker);

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
static bool protectPage(MemoryTracker* tracker, uintptr address, uint size, uint32 protect);

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

MemoryTracker_M* InitMemoryTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 2000 + RandUint(address) % 128;
    uintptr moduleAddr  = address + 2600 + RandUint(address) % 128;
    // initialize tracker
    MemoryTracker* tracker = (MemoryTracker*)trackerAddr;
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
    if (errno != NO_ERROR)
    {
        return (MemoryTracker_M*)errno;
    }
    // create methods for tracker
    MemoryTracker_M* module = (MemoryTracker_M*)moduleAddr;
    // Windows API hooks
    module->VirtualAlloc   = (VirtualAlloc_t  )(&MT_VirtualAlloc);
    module->VirtualFree    = (VirtualFree_t   )(&MT_VirtualFree);
    module->VirtualProtect = (VirtualProtect_t)(&MT_VirtualProtect);
    // methods for runtime
    module->MemAlloc   = &MT_MemAlloc;
    module->MemRealloc = &MT_MemRealloc;
    module->MemFree    = &MT_MemFree;
    module->MemEncrypt = &MT_Encrypt;
    module->MemDecrypt = &MT_Decrypt;
    module->MemClean   = &MT_Clean;
    return module;
}

static bool initTrackerAPI(MemoryTracker* tracker, Context* context)
{
    tracker->VirtualAlloc        = context->VirtualAlloc;
    tracker->VirtualFree         = context->VirtualFree;
    tracker->VirtualProtect      = context->VirtualProtect;
    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    return true;
}

static bool updateTrackerPointer(MemoryTracker* tracker)
{
    bool success = false;
    uintptr target = (uintptr)(&getTrackerPointer);
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

static bool initTrackerEnvironment(MemoryTracker* tracker, Context* context)
{
    // copy runtime context data
    tracker->PageSize = context->PageSize;
    tracker->Mutex    = context->Mutex;
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
    return true;
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

static bool mt_lock(MemoryTracker* tracker)
{
    uint32 event = tracker->WaitForSingleObject(tracker->Mutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

static bool mt_unlock(MemoryTracker* tracker)
{
    return tracker->ReleaseMutex(tracker->Mutex);
}

__declspec(noinline)
uintptr MT_VirtualAlloc(uintptr address, uint size, uint32 type, uint32 protect)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!mt_lock(tracker))
    {
        return NULL;
    }

    // adjust protect at sometime
    protect = replacePageProtect(protect);

    uintptr page;
    bool success = true;
    for (;;)
    {
        page = tracker->VirtualAlloc(address, size, type, protect);
        if (page == NULL)
        {
            success = false;
            break;
        }
        if (!allocPage(tracker, page, size, type, protect))
        {
            success = false;
            break;
        }
        break;
    }

    if (!mt_unlock(tracker))
    {
        return NULL;
    }
    if (!success)
    {
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
    // printf("VirtualAlloc: 0x%llX, %llu, 0x%X, 0x%X\n", address, size, type, protect);
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
bool MT_VirtualFree(uintptr address, uint size, uint32 type)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!mt_lock(tracker))
    {
        return false;
    }

    bool success = true;
    for (;;)
    {
        if (!tracker->VirtualFree(address, size, type))
        {
            success = false;
            break;
        }
        if (!freePage(tracker, address, size, type))
        {
            success = false;
            break;
        }
        break;
    }

    if (!mt_unlock(tracker))
    {
        return false;
    }
    return success;
}

static bool freePage(MemoryTracker* tracker, uintptr address, uint size, uint32 type)
{
    // printf("VirtualFree: 0x%llX, %llu, 0x%X\n", address, size, type);
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
    register memRegion* region;
    bool found = false;
    for (uint num = 0; num < len; index++)
    {
        region = List_Get(regions, index);
        if (region->address == NULL)
        {
            continue;
        }
        if (region->address != address)
        {
            num++;
            continue;
        }
        found = true;
        break;
    }
    if (!found)
    {
        return false;
    }
    return deletePages(tracker, region->address, region->size);
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
        if (region->address == NULL)
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
    register memPage* page;
    for (uint num = 0; num < len; index++)
    {
        page = List_Get(pages, index);
        if (page->address == NULL)
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
bool MT_VirtualProtect(uintptr address, uint size, uint32 new, uint32* old)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!mt_lock(tracker))
    {
        return false;
    }

    bool success = true;
    for (;;)
    {
        if (!tracker->VirtualProtect(address, size, new, old))
        {
            success = false;
            break;
        }
        if (!protectPage(tracker, address, size, new))
        {
            success = false;
            break;
        }
        break;
    }

    if (!mt_unlock(tracker))
    {
        return false;
    }
    return success;
}

static bool protectPage(MemoryTracker* tracker, uintptr address, uint size, uint32 protect)
{
    // printf("VirtualProtect: 0x%llX, %llu, 0x%X\n", address, size, protect);
    register uint pageSize = tracker->PageSize;

    register List* pages = &tracker->Pages;
    register uint  len   = pages->Len;
    register uint  index = 0;
    register memPage* page;
    bool found = false;
    for (uint num = 0; num < len; index++)
    {
        page = List_Get(pages, index);
        if (page->address == NULL)
        {
            continue;
        }
        if ((page->address + pageSize <= address) || (page->address >= address + size))
        {
            num++;
            continue;
        }
        page->protect = protect;
        found = true;
        num++;
    }
    return found;
}

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
    uint32 old;
    return tracker->VirtualProtect(page->address, tracker->PageSize, PAGE_READWRITE, &old);
}

// recoverPageProtect is used to recover to prevent protect.
static bool recoverPageProtect(MemoryTracker* tracker, memPage* page)
{
    if (isPageProtectWriteable(page->protect))
    {
        return true;
    }
    uint32 old;
    return tracker->VirtualProtect(page->address, tracker->PageSize, page->protect, &old);
}

__declspec(noinline)
void* MT_MemAlloc(uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    // ensure the size is a multiple of memory page size.
    // it also for prevent track the special page size.
    uint pageSize = ((size / tracker->PageSize) + 1) * tracker->PageSize;
    uintptr addr = MT_VirtualAlloc(0, pageSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    // store the size at the head of the memory page
    // ensure the memory address is 16 bytes aligned
    byte* address = (byte*)addr;
    RandBuf(address, 16);
    mem_copy(address, &size, sizeof(uint));
    return (void*)(addr + 16);
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

    // clean the buffer data before call VirtualFree.
    uintptr addr = (uintptr)(address)-16;
    uint    size = *(uint*)addr;
    mem_clean((byte*)addr, size);
    return MT_VirtualFree(addr, 0, MEM_RELEASE);
}

__declspec(noinline)
bool MT_Encrypt()
{
    MemoryTracker* tracker = getTrackerPointer();

    List* pages = &tracker->Pages;
    uint  index = 0;
    for (uint num = 0; num < pages->Len; index++)
    {
        memPage* page = List_Get(pages, index);
        if (page->address == NULL)
        {
            continue;
        }
        if (!encryptPage(tracker, page))
        {
            return false;
        }
        num++;
    }

    printf("num pages: %llu\n", pages->Len);

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
    return true;
}

static bool encryptPage(MemoryTracker* tracker, memPage* page)
{
    if (!adjustPageProtect(tracker, page))
    {
        return false;
    }
    if (isEmptyPage(tracker, page))
    {
        return true;
    }
    // generate new key and IV
    RandBuf(&page->key[0], CRYPTO_KEY_SIZE);
    RandBuf(&page->iv[0], CRYPTO_IV_SIZE);
    byte key[CRYPTO_KEY_SIZE];
    deriveKey(tracker, page, &key[0]);
    EncryptBuf((byte*)(page->address), tracker->PageSize, &key[0], &page->iv[0]);
    return true;
}

__declspec(noinline)
bool MT_Decrypt()
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
        if (page->address == NULL)
        {
            continue;
        }
        if (!decryptPage(tracker, page))
        {
            return false;
        }
        num++;
    }
    return true;
}

static bool decryptPage(MemoryTracker* tracker, memPage* page)
{
    if (isEmptyPage(tracker, page))
    {
        return true;
    }
    byte key[CRYPTO_KEY_SIZE];
    deriveKey(tracker, page, &key[0]);
    DecryptBuf((byte*)(page->address), tracker->PageSize, &key[0], &page->iv[0]);
    return recoverPageProtect(tracker, page);
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
        if (page->address == NULL)
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
        if (region->address == NULL)
        {
            continue;
        }
        if (!tracker->VirtualFree(region->address, 0, MEM_RELEASE))
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
    return errno;
}

static bool cleanPage(MemoryTracker* tracker, memPage* page)
{
    // try to fill random data before decommit memory page.
    if (!adjustPageProtect(tracker, page))
    {
        return false;
    }
    RandBuf((byte*)(page->address), tracker->PageSize);
    if (!recoverPageProtect(tracker, page))
    {
        return false;
    }
    return tracker->VirtualFree(page->address, tracker->PageSize, MEM_DECOMMIT);
}
