#include <stdio.h>

#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
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
    byte iv [CRYPTO_IV_SIZE];
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
    byte PagesKey[CRYPTO_KEY_SIZE];
    byte PagesIV [CRYPTO_IV_SIZE];

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
static bool   allocPage(MemoryTracker* tracker, uintptr address, uint size, uint32 type, uint32 protect);
static bool   decommitPage(MemoryTracker* tracker, uintptr address, uint size);
static bool   releasePage(MemoryTracker* tracker, uintptr address, uint size);
static bool   protectPage(MemoryTracker* tracker, uintptr address, uint32 protect);
static bool   isPageTypeTrackable(uint32 type);
static uint32 replacePageProtect(uint32 protect);
static bool   isPageTypeWriteable(uint32 type);
static bool   isPageProtectWriteable(uint32 protect);
static bool   adjustPageProtect(MemoryTracker* tracker, memoryPage* page);
static bool   recoverPageProtect(MemoryTracker* tracker, memoryPage* page);
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
    // initialize memory page list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Pages, &ctx, sizeof(memoryPage));
    RandBuf(&tracker->PagesKey[0], CRYPTO_KEY_SIZE);
    RandBuf(&tracker->PagesIV[0], CRYPTO_IV_SIZE);
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

static bool allocPage(MemoryTracker* tracker, uintptr address, uint size, uint32 type, uint32 protect)
{
    if (!isPageTypeTrackable(type))
    {
        return true;
    }
    printf("VirtualAlloc: 0x%llX, %llu, 0x%X, 0x%X\n", address, size, type, protect);
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

__declspec(noinline)
bool MT_VirtualFree(uintptr address, uint size, uint32 type)
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_VIRTUAL_FREE);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    printf("VirtualFree: 0x%llX, %llu, 0x%X\n", address, size, type);

    bool success = true;
    for (;;)
    {
        bool freeOK = true;
        switch (type&0xF000)
        {
        case MEM_DECOMMIT:
            freeOK = decommitPage(tracker, address, size);
            break;
        case MEM_RELEASE:
            freeOK = releasePage(tracker, address, size);
            break;
        }
        if (!freeOK)
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

static bool decommitPage(MemoryTracker* tracker, uintptr address, uint size)
{
    List* pages = &tracker->Pages;

    uint  index = 0;
    bool  find  = false;
    bool  base  = false;
    memoryPage* page;
    for (uint num = 0; num < pages->Len; index++)
    {
        page = List_Get(pages, index);
        if (page->address == NULL)
        {
            continue;
        }
        if (!isPageTypeWriteable(page->type))
        {
            num++;
            continue;
        }
        if (address == page->address)
        {
            find = true;
            base = true;
            break;
        }
        if (address > page->address && address < page->address+page->size)
        {
            find = true;
            base = false;
            break;
        }
        num++;
    }
    if (!find)
    {
        uint* a = 0x01;
        *a = 1;
        return true;
    }
    // debug
    // uint* a = 0x01;
    // *a = 1;
    if (base)
    {
        if (size == 0)
        {
            if (!List_Delete(pages, index))
            {
                return false;
            }
        } else {

            page->type = MEM_DECOMMIT;
        }
    } else {
       page->type = MEM_DECOMMIT;

    }


    // process split memory page
    // if (page->address != address || size != 0)
    // {
    //     memoryPage pageFront = *page;
    //     pageFront.size = address - page->address;
    //     if (pageFront.size != 0)
    //     {
    //         RandBuf(&pageFront.key[0], CRYPTO_KEY_SIZE);
    //         RandBuf(&pageFront.iv[0], CRYPTO_IV_SIZE);
    //         if (!List_Insert(pages, &pageFront))
    //         {
    //             return false;
    //         }
    //     }
    //     memoryPage pageBack = *page;
    //     pageBack.address = address + size;
    //     pageBack.size -= (pageFront.size + size);
    //     if (pageBack.size != 0)
    //     {
    //         RandBuf(&pageBack.key[0], CRYPTO_KEY_SIZE);
    //         RandBuf(&pageBack.iv[0], CRYPTO_IV_SIZE);
    //         if (!List_Insert(pages, &pageBack))
    //         {
    //             return false;
    //         }
    //     }
    // 
    //     printf("free break: 0x%llX, %llu\n", pageFront.address, pageFront.size);
    //     printf("free break: 0x%llX, %llu\n", pageBack.address, pageBack.size);
    // }

    // try to fill random data before call VirtualFree
    if (!adjustPageProtect(tracker, page))
    {
        return false;
    }
    uint randSize = size;
    if (randSize == 0)
    {
        randSize = page->size;
    }
    RandBuf((byte*)address, randSize);
    return recoverPageProtect(tracker, page);
}

static bool releasePage(MemoryTracker* tracker, uintptr address, uint size)
{
    if (size != 0)
    {
        return false;
    }
    List* pages = &tracker->Pages;
    memoryPage page = {
        .address = address,
    };
    uint index = 0;
    if (!List_Find(pages, &page, sizeof(page.address), &index))
    {
        return false;
    }
    if (!List_Delete(pages, index))
    {
        return false;
    }
    // try to fill random data before call VirtualFree
    if (!isPageTypeWriteable(page.type))
    {
        return true;
    }
    if (!adjustPageProtect(tracker, &page))
    {
        return false;
    }
    RandBuf((byte*)address, page.size);
    return recoverPageProtect(tracker, &page);
}

__declspec(noinline)
bool MT_VirtualProtect(uintptr address, uint size, uint32 new, uint32* old)
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_VIRTUAL_PROTECT);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    // printf("VirtualProtect: 0x%llX, %llu, 0x%X\n", address, size, new);

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
    List* pages = &tracker->Pages;
    memoryPage page = {
        .address = address,
    };
    uint index;
    if (!List_Find(pages, &page, sizeof(uintptr), &index))
    {
        return true;
    }
    // update protect in page list
    memoryPage* p = List_Get(pages, index);
    if (p == NULL)
    {
        return false;
    }
    p->protect = protect;
    return true;
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

static bool isPageTypeWriteable(uint32 type)
{
    if ((type&0xF000) == MEM_COMMIT)
    {
        return true;
    }
    return false;
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
static bool adjustPageProtect(MemoryTracker* tracker, memoryPage* page)
{
    if (isPageProtectWriteable(page->protect))
    {
        return true;
    }
    uint32 old;
    return tracker->VirtualProtect(page->address, page->size, PAGE_READWRITE, &old);
}

// recoverPageProtect is used to recover to prevent protect.
static bool recoverPageProtect(MemoryTracker* tracker, memoryPage* page)
{
    if (isPageProtectWriteable(page->protect))
    {
        return true;
    }
    uint32 old;
    return tracker->VirtualProtect(page->address, page->size, page->protect, &old);
}

__declspec(noinline)
void* MT_MemAlloc(uint size)
{
    // ensure the size is a multiple of 4096(memory page size).
    // it also for prevent track the special page size.
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

    List* pages = &tracker->Pages;
    uint  index = 0;
    for (uint num = 0; num < pages->Len; index++)
    {
        memoryPage* page = List_Get(pages, index);
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

    // TODO encrypt page list

    return true;
}

static bool encryptPage(MemoryTracker* tracker, memoryPage* page)
{
    if (!isPageTypeWriteable(page->type))
    {
        return true;
    }
    if (!adjustPageProtect(tracker, page))
    {
        return false;
    }

    printf
    (
        "enc Addr: 0x%llX, Size: 0x%llX, Protect: 0x%X, Type: 0x%X\n",
        page->address, page->size, page->protect, page->type
    );

    // generate new key and IV
    RandBuf(&page->key[0], CRYPTO_KEY_SIZE);
    RandBuf(&page->iv[0], CRYPTO_IV_SIZE);
    byte key[CRYPTO_KEY_SIZE];
    deriveKey(tracker, page, &key[0]);

    EncryptBuf((byte*)(page->address), page->size, &key[0], &page->iv[0]);

    return true;
}

__declspec(noinline)
bool MT_Decrypt()
{
    MemoryTracker* tracker = getTrackerPointer(METHOD_ADDR_DECRYPT);

    // TODO decrypt page list

    // reverse order traversal is used to deal with the problem
    // that some memory pages may be encrypted twice, like use
    // VirtualAlloc to allocate multiple times to the same address
    List* pages = &tracker->Pages;
    uint  index = pages->Last;
    for (uint num = 0; num < pages->Len; index--)
    {
        memoryPage* page = List_Get(pages, index);
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

static bool decryptPage(MemoryTracker* tracker, memoryPage* page)
{
    if (!isPageTypeWriteable(page->type))
    {
        return true;
    }

    // printf("dec Size: 0x%llX\n", page->size);

    byte key[CRYPTO_KEY_SIZE];
    deriveKey(tracker, page, &key[0]);

    DecryptBuf((byte*)(page->address), page->size, &key[0], &page->iv[0]);

    return recoverPageProtect(tracker, page);
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

    List* pages = &tracker->Pages;
    uint  index = 0;
    for (uint num = 0; num < pages->Len; index++)
    {
        memoryPage* page = List_Get(pages, index);
        if (page->address == NULL)
        {
            continue;
        }
        if (!cleanPage(tracker, page))
        {
            return false;
        }
        if (!tracker->VirtualFree(page->address, 0, MEM_RELEASE))
        {
            return false;
        }
        num++;
    }

    // clean page list
    RandBuf(pages->Data, List_Size(pages));
    return true;
}

static bool cleanPage(MemoryTracker* tracker, memoryPage* page)
{
    if (!isPageTypeWriteable(page->type))
    {
        return true;
    }
    if (!adjustPageProtect(tracker, page))
    {
        return false;
    }
    RandBuf((byte*)(page->address), page->size);
    return recoverPageProtect(tracker, page);
}
