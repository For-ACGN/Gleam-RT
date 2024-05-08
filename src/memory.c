// #include <stdio.h>

#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "list_md.h"
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
    uintptr address;
    uint    size;
    uint32  type;
    uint32  protect;

    byte key[CRYPTO_KEY_SIZE];
    byte iv[CRYPTO_IV_SIZE];
} memoryPage;

typedef struct {
    // API addresses
    VirtualAlloc_t        VirtualAlloc;
    VirtualFree_t         VirtualFree;
    VirtualProtect_t      VirtualProtect;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;

    // store memory pages
    List Pages; 

    // global mutex
    HANDLE Mutex;
} MemoryTracker;

// methods about memory tracker
uintptr MT_VirtualAlloc(uintptr address, uint size, uint32 type, uint32 protect);
bool    MT_VirtualFree(uintptr address, uint size, uint32 type);
bool    MT_VirtualProtect(uintptr address, uint size, uint32 new, uint32* old);
void*   MT_MemAlloc(uint size);
bool    MT_MemFree(void* address);
bool    MT_Encrypt();
bool    MT_Decrypt();
bool    MT_Clean();

static bool   initTrackerAPI(MemoryTracker* tracker, Context* context);
static bool   updateTrackerPointers(MemoryTracker* tracker);
static bool   updateTrackerPointer(MemoryTracker* tracker, void* method, uintptr address);
static bool   initTrackerEnvironment(MemoryTracker* tracker, Context* context);
static bool   allocPage(MemoryTracker* tracker, uintptr address, uint size, uint type, uint32 protect);
static bool   freePage(MemoryTracker* tracker, uintptr address);
static bool   protectPage(MemoryTracker* tracker, uintptr address, uint32 protect);
static bool   adjustPageProtect(MemoryTracker* tracker, memoryPage* page);
static bool   recoverPageProtect(MemoryTracker* tracker, memoryPage* page);
static uint32 replacePageProtect(uint32 protect);
static bool   isPageWriteable(uint32 protect);
static bool   encryptPage(MemoryTracker* tracker, memoryPage* page);
static bool   decryptPage(MemoryTracker* tracker, memoryPage* page);
static void   deriveKey(MemoryTracker* tracker, memoryPage* page, byte* key);
static bool   cleanPage(MemoryTracker* tracker, memoryPage* page);

MemoryTracker_M* InitMemoryTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 1300 + RandUint(address) % 256;
    uintptr moduleAddr  = address + 1900 + RandUint(address) % 256;
    // initialize tracker
    MemoryTracker* tracker = (MemoryTracker*)trackerAddr;
    uint errCode = 0;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errCode = 0x01;
            break;
        }
        if (!updateTrackerPointers(tracker))
        {
            errCode = 0x02;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errCode = 0x03;
            break;
        }
        break;
    }
    if (errCode != 0x00)
    {
        return (MemoryTracker_M*)errCode;
    }
    // create methods for tracker
    MemoryTracker_M* module = (MemoryTracker_M*)moduleAddr;
    // Windows API hooks
    module->VirtualAlloc   = (VirtualAlloc_t  )(&MT_VirtualAlloc);
    module->VirtualFree    = (VirtualFree_t   )(&MT_VirtualFree);
    module->VirtualProtect = (VirtualProtect_t)(&MT_VirtualProtect);
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
    tracker->VirtualAlloc        = context->VirtualAlloc;
    tracker->VirtualFree         = context->VirtualFree;
    tracker->VirtualProtect      = context->VirtualProtect;
    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    return true;
}

static bool updateTrackerPointers(MemoryTracker* tracker)
{
    typedef struct {
        void* address; uintptr pointer;
    } method;
    method methods[] = 
    {
        { &MT_VirtualAlloc,   METHOD_ADDR_VIRTUAL_ALLOC },
        { &MT_VirtualFree,    METHOD_ADDR_VIRTUAL_FREE },
        { &MT_VirtualProtect, METHOD_ADDR_VIRTUAL_PROTECT },
        { &MT_Encrypt,        METHOD_ADDR_ENCRYPT },
        { &MT_Decrypt,        METHOD_ADDR_DECRYPT },
        { &MT_Clean,          METHOD_ADDR_CLEAN },
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
    return success;
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

static bool initTrackerEnvironment(MemoryTracker* tracker, Context* context)
{
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Pages, &ctx, sizeof(memoryPage));
    tracker->Mutex = context->Mutex;
    return true;
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

    // printf("VirtualAlloc: 0x%llX, %llu, 0x%X, 0x%X\n", address, size, type, protect);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
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

    tracker->ReleaseMutex(tracker->Mutex);
    if (!success)
    {
        return NULL;
    }
    return page;
}

static bool allocPage(MemoryTracker* tracker, uintptr address, uint size, uint type, uint32 protect)
{
    memoryPage page = {
        .address = address,
        .size    = size,
        .type    = type,
        .protect = protect,
    };
    RandBuf(&page.key[0], CRYPTO_KEY_SIZE);
    RandBuf(&page.iv[0], CRYPTO_IV_SIZE);
    return List_Insert(&tracker->Pages, &page);
}

// replacePageProtect is used to make sure all the page are readable.
// avoid inadvertently using sensitive permissions.
static uint32 replacePageProtect(uint32 protect)
{
    switch (protect)
    {
    case PAGE_NOACCESS:
        return PAGE_READONLY;
    case PAGE_EXECUTE:
        return PAGE_EXECUTE_READ;
    default:
        return protect;
    }
}

// adjustPageProtect is used to make sure this page is writeable.
static bool adjustPageProtect(MemoryTracker* tracker, memoryPage* page)
{
    if (isPageWriteable(page->protect))
    {
        return true;
    }
    uint32 old;
    return tracker->VirtualProtect((uintptr)page, page->size, PAGE_READWRITE, &old);
}

// recoverPageProtect is used to recover to prevent protect.
static bool recoverPageProtect(MemoryTracker* tracker, memoryPage* page)
{
    if (isPageWriteable(page->protect))
    {
        return true;
    }
    uint32 old;
    return tracker->VirtualProtect((uintptr)page, page->size, page->protect, &old);
}

static bool isPageWriteable(uint32 type, uint32 protect)
{
    // check page type
    if (type & MEM_COMMIT)
    {

    }

    switch (protect)
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

__declspec(noinline)
bool MT_VirtualFree(uintptr address, uint size, uint32 type)
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_VIRTUAL_FREE);

    // printf("VirtualFree: 0x%llX, %llu, 0x%X\n", address, size, type);
    // return true;

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    bool success = true;
    for (;;)
    {
        if (!freePage(tracker, address))
        {
            success = false;
            break;
        }
        if (!tracker->VirtualFree(address, size, type))
        {
            success = false;
            break;
        }
        break;
    }

    tracker->ReleaseMutex(tracker->Mutex);
    return success;
}

static bool freePage(MemoryTracker* tracker, uintptr address)
{
    List* pages = &tracker->Pages;
    memoryPage page = {
        .address = address,
    };
    if (List_Delete(pages, &page, sizeof(uintptr)))
    {
        return false;
    }


    // fill random data before call VirtualFree
    if (isPageWriteable(page.protect))
    {
        RandBuf((byte*)page, size);
        return true;
    } 
 
    RandBuf((byte*)page, size);
    return tracker->VirtualProtect(page, size, old, &old);
}

__declspec(noinline)
bool MT_VirtualProtect(uintptr address, uint size, uint32 new, uint32* old)
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_VIRTUAL_PROTECT);

    // printf("VirtualProtect: 0x%llX, %llu, 0x%X\n", address, size, new);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
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
        if (!protectPage(tracker, address, new))
        {
            success = false;
            break;
        }
        break;
    }

    tracker->ReleaseMutex(tracker->Mutex);
    return success;
}

static bool protectPage(MemoryTracker* tracker, uintptr address, uint32 protect)
{
    memoryPage* memPage = (memoryPage*)(address - MEMORY_PAGE_HEADER_SIZE);

    // check this page is allocated by MemoryTracker
    for (memoryPage* page = tracker->PageHead; page != NULL; page = page->next)
    {
        if (page != memPage)
        {
            continue;
        }
        if (!adjustPageProtect(tracker, page))
        {
            return false;
        }
        page->protect = protect;
        if (!recoverPageProtect(tracker, page))
        {
            return false;
        }
        break;
    }
    return true;
}

__declspec(noinline)
void* MT_MemAlloc(uint size)
{
    // ensure the size is a multiple of 4096(memory page size).
    size = ((size / 4096) + 1) * 4096;
    uintptr addr = MT_VirtualAlloc(0, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    RandBuf((byte*)addr, (int64)size);
    return (void*)addr;
}

__declspec(noinline)
bool MT_MemFree(void* address)
{
    return MT_VirtualFree((uintptr)address, 0, MEM_RELEASE);
}

__declspec(noinline)
bool MT_Encrypt()
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_ENCRYPT);

    memoryPage* page = tracker->PageHead;
    if (page == NULL)
    {
        return true;
    }
    for (;;)
    {
        // must copy next page pointer before encrypt
        memoryPage* next = page->next;
        if (!encryptPage(tracker, page))
        {
            return false;
        }
        if (next == NULL)
        {
            break;
        }
        page = next;
    }
    return true;
}

static bool encryptPage(MemoryTracker* tracker, memoryPage* page)
{
    if (!adjustPageProtect(tracker, page))
    {
        return false;
    }

    // generate new key and IV
    RandBuf(&page->key[0], CRYPTO_KEY_SIZE);
    RandBuf(&page->iv0[0], CRYPTO_IV_SIZE);
    RandBuf(&page->iv1[0], CRYPTO_IV_SIZE);
    byte key[CRYPTO_KEY_SIZE];
    deriveKey(tracker, page, &key[0]);

    uint pageSize = page->size;

    // encrypt size
    byte* buf  = (byte*)(&page->size);
    uint  size = sizeof(uint);
    EncryptBuf(buf, size, &key[0], &page->iv0[0]);

    // encrypt other fields and page
    buf  = (byte*)(&page->protect);
    size = pageSize - offsetof(memoryPage, protect);
    EncryptBuf(buf, size, &key[0], &page->iv1[0]);

    return true;
}

__declspec(noinline)
bool MT_Decrypt()
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_DECRYPT);

    memoryPage* page = tracker->PageHead;
    if (page == NULL)
    {
        return true;
    }
    for (;;)
    {
        if (!decryptPage(tracker, page))
        {
            return false;
        }
        memoryPage* next = page->next;
        if (next == NULL)
        {
            break;
        }
        page = next;
    }
    return true;
}

static bool decryptPage(MemoryTracker* tracker, memoryPage* page)
{
    byte key[CRYPTO_KEY_SIZE];
    deriveKey(tracker, page, &key[0]);

    // decrypt size
    byte* buf  = (byte*)(&page->size);
    uint  size = sizeof(uint);
    DecryptBuf(buf, size, &key[0], &page->iv0[0]);

    // decrypt other fields and page
    buf  = (byte*)(&page->protect);
    size = page->size - offsetof(memoryPage, protect);
    DecryptBuf(buf, size, &key[0], &page->iv1[0]);

    if (!recoverPageProtect(tracker, page))
    {
        return false;
    }
    return true;
}

static void deriveKey(MemoryTracker* tracker, memoryPage* page, byte* key)
{
    uintptr addr = (uintptr)page;
    addr += ((uintptr)tracker) << (sizeof(uintptr)/2);
    addr += ((uintptr)tracker->VirtualAlloc) >> 4;
    addr += ((uintptr)tracker->VirtualFree)  >> 6;
    mem_copy(key+0, &page->key[0], CRYPTO_KEY_SIZE);
    mem_copy(key+4, &addr, sizeof(uintptr));
}

__declspec(noinline)
bool MT_Clean()
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_CLEAN);

    memoryPage* page = tracker->PageHead;
    if (page == NULL)
    {
        return true;
    }
    for (;;)
    {
        // must copy next page pointer before clean
        memoryPage* next = page->next;
        if (!cleanPage(tracker, page))
        {
            return false;
        }
        if (next == NULL)
        {
            break;
        }
        page = next;
    }
    return true;
}

static bool cleanPage(MemoryTracker* tracker, memoryPage* page)
{
    if (!adjustPageProtect(tracker, page))
    {
        return false;
    }
    // store fields before clean memory page
    uint   size    = page->size;
    uint32 protect = page->protect;
    // fill random data before free
    RandBuf((byte*)page, size);
    // recovery memory protect
    if (!isPageWriteable(protect))
    {
        uint32 old;
        if (!tracker->VirtualProtect((uintptr)page, size, protect, &old))
        {
            return false;
        }
    }
    return tracker->VirtualFree((uintptr)page, 0, MEM_RELEASE);
}
