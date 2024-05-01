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

// make sure the memory address is 16 bytes aligned.
#define MEMORY_PAGE_PAD_SIZE    (sizeof(memoryPage) % 16)
#define MEMORY_PAGE_HEADER_SIZE (sizeof(memoryPage) + MEMORY_PAGE_PAD_SIZE)

typedef struct memoryPage {
    byte   key[CRYPTO_KEY_SIZE];
    byte   iv0[CRYPTO_IV_SIZE];
    byte   iv1[CRYPTO_IV_SIZE];
    uint   size;
    uint32 protect;

    struct memoryPage* prev;
    struct memoryPage* next;
} memoryPage;

typedef struct {
    // API addresses
    VirtualAlloc        VirtualAlloc;
    VirtualFree         VirtualFree;
    VirtualProtect      VirtualProtect;
    ReleaseMutex        ReleaseMutex;
    WaitForSingleObject WaitForSingleObject;

    memoryPage* PageHead;

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
static bool   initTrackerEnvironment(MemoryTracker* tracker, Context* context);
static bool   updateTrackerPointers(MemoryTracker* tracker);
static bool   updateTrackerPointer(MemoryTracker* tracker, void* method, uintptr address);
static bool   allocPage(MemoryTracker* tracker, uintptr page, uint size, uint32 protect);
static bool   freePage(MemoryTracker* tracker, uintptr address);
static bool   deletePage(MemoryTracker* tracker, memoryPage* page);
static bool   protectPage(MemoryTracker* tracker, uintptr address, uint32 protect);
static bool   adjustPageProtect(MemoryTracker* tracker, memoryPage* page);
static bool   recoverPageProtect(MemoryTracker* tracker, memoryPage* page);
static uint32 replacePageProtect(uint32 protect);
static bool   isPageWriteable(uint32 protect);
static bool   encryptPage(MemoryTracker* tracker, memoryPage* page);
static bool   decryptPage(MemoryTracker* tracker, memoryPage* page);
static bool   cleanPage(MemoryTracker* tracker, memoryPage* page);

MemoryTracker_M* InitMemoryTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
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
    // create methods for tracker
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
    tracker->VirtualAlloc        = context->VirtualAlloc;
    tracker->VirtualFree         = context->VirtualFree;
    tracker->VirtualProtect      = context->VirtualProtect;
    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    return true;
}

static bool initTrackerEnvironment(MemoryTracker* tracker, Context* context)
{
    tracker->Mutex    = context->Mutex;
    tracker->PageHead = NULL;
    return true;
}

static bool updateTrackerPointers(MemoryTracker* tracker)
{
    // update pointer in methods
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

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return NULL;
    }

    // adjust size and protect at sometime
    if (size <= 4096 - MEMORY_PAGE_HEADER_SIZE)
    {
        size += MEMORY_PAGE_HEADER_SIZE;
    } else {
        size += 4096;
    }
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
        if (!allocPage(tracker, page, size, protect))
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
    return page + MEMORY_PAGE_HEADER_SIZE;
}

// write memory header data at the front of the actual memory page
static bool allocPage(MemoryTracker* tracker, uintptr page, uint size, uint32 protect)
{
    // adjust protect to write memory page data
    if (!isPageWriteable(protect))
    {
        uint32 old;
        if (!tracker->VirtualProtect(page, size, PAGE_READWRITE, &old))
        {
            return false;
        }
    }

    memoryPage* memPage = (memoryPage*)page;
    RandBuf(&memPage->key[0], CRYPTO_KEY_SIZE);
    RandBuf(&memPage->iv0[0], CRYPTO_IV_SIZE);
    RandBuf(&memPage->iv1[0], CRYPTO_IV_SIZE);
    memPage->size = size;
    memPage->protect = protect;
    memPage->prev = NULL;

    memoryPage* pageHead = tracker->PageHead;
    if (pageHead != NULL)
    {
        if (!adjustPageProtect(tracker, pageHead))
        {
            return false;
        }
        pageHead->prev = memPage;
        if (!recoverPageProtect(tracker, pageHead))
        {
            return false;
        }
    }
    memPage->next = pageHead;
    
    // fill random padding data
    if (MEMORY_PAGE_PAD_SIZE != 0)
    {
        uintptr pad = page + MEMORY_PAGE_HEADER_SIZE - MEMORY_PAGE_PAD_SIZE;
        RandBuf((byte*)pad, MEMORY_PAGE_PAD_SIZE);    
    }

    // recovery memory protect
    if (!isPageWriteable(protect))
    {
        uint32 old;
        if (!tracker->VirtualProtect(page, size, protect, &old))
        {
            return false;
        }
    }

    tracker->PageHead = memPage;
    return true;
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

static bool isPageWriteable(uint32 protect)
{
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

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    // adjust size at sometime
    if (size != 0)
    {
        if (size <= 4096 - MEMORY_PAGE_HEADER_SIZE)
        {
            size += MEMORY_PAGE_HEADER_SIZE;
        } else {
            size += 4096;
        }
    }
    address -= MEMORY_PAGE_HEADER_SIZE;

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

static bool freePage(MemoryTracker* tracker, uintptr page)
{
    memoryPage* memPage = (memoryPage*)page;
    if (!deletePage(tracker, memPage))
    {
        return false;
    }
    // fill random data before call VirtualFree
    uint size = memPage->size;
    if (isPageWriteable(memPage->protect))
    {
        RandBuf((byte*)page, size);
        return true;
    } 
    // if page is not writeable, adjust protect first
    uint32 old;
    if (!tracker->VirtualProtect(page, size, PAGE_READWRITE, &old))
    {
        return false;
    }
    RandBuf((byte*)page, size);
    return tracker->VirtualProtect(page, size, old, &old);
}

static bool deletePage(MemoryTracker* tracker, memoryPage* target)
{
    if (tracker->PageHead == target)
    {
        tracker->PageHead = target->next;
        if (tracker->PageHead == NULL)
        {
            return true;
        }
        if (!adjustPageProtect(tracker, target->next))
        {
            return false;
        }
        tracker->PageHead->prev = NULL;
        if (!recoverPageProtect(tracker, target->next))
        {
            return false;
        }
        return true;
    }

    memoryPage* prev = target->prev;
    memoryPage* next = target->next;

    if (!adjustPageProtect(tracker, prev))
    {
        return false;
    }
    prev->next = next;
    if (!recoverPageProtect(tracker, prev))
    {
        return false;
    }

    if (next == NULL)
    {
        return true;
    }

    if (!adjustPageProtect(tracker, next))
    {
        return false;
    }
    next->prev = prev;
    if (!recoverPageProtect(tracker, next))
    {
        return false;
    }
    return true;
}

__declspec(noinline)
bool MT_VirtualProtect(uintptr address, uint size, uint32 new, uint32* old)
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_VIRTUAL_PROTECT);

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
    }
    return true;
}

__declspec(noinline)
void* MT_MemAlloc(uint size)
{
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

    // set the actual key to stack
    uintptr pageAddr = (uintptr)page;
    byte key[CRYPTO_KEY_SIZE];
    copy(&key[0], &page->key[0], CRYPTO_KEY_SIZE);
    copy(&key[16], &pageAddr, sizeof(uintptr));

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
    // set the actual key to stack
    uintptr pageAddr = (uintptr)page;
    byte key[CRYPTO_KEY_SIZE];
    copy(&key[0], &page->key[0], CRYPTO_KEY_SIZE);
    copy(&key[16], &pageAddr, sizeof(uintptr));

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
