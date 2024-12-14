#include "c_types.h"
#include "windows_t.h"
#include "msvcrt_t.h"
#include "ucrtbase_t.h"
#include "rel_addr.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "list_md.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "mod_memory.h"
#include "debug.h"

#define BLOCK_MARK_SIZE sizeof(uint)

#define OP_WALK_HEAP_ENCRYPT 1
#define OP_WALK_HEAP_DECRYPT 2
#define OP_WALK_HEAP_ERASE   3

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
    GetProcessHeaps_t       GetProcessHeaps;
    HeapCreate_t            HeapCreate;
    HeapDestroy_t           HeapDestroy;
    HeapAlloc_t             HeapAlloc;
    HeapReAlloc_t           HeapReAlloc;
    HeapFree_t              HeapFree;
    HeapSize_t              HeapSize;
    HeapLock_t              HeapLock;
    HeapUnlock_t            HeapUnlock;
    HeapWalk_t              HeapWalk;
    GlobalAlloc_t           GlobalAlloc;
    GlobalReAlloc_t         GlobalReAlloc;
    GlobalFree_t            GlobalFree;
    LocalAlloc_t            LocalAlloc;
    LocalReAlloc_t          LocalReAlloc;
    LocalFree_t             LocalFree;
    ReleaseMutex_t          ReleaseMutex;
    WaitForSingleObject_t   WaitForSingleObject;
    FlushInstructionCache_t FlushInstructionCache;
    CloseHandle_t           CloseHandle;

    // runtime methods
    malloc_t  RT_malloc;
    calloc_t  RT_calloc;
    realloc_t RT_realloc;
    free_t    RT_free;

    // runtime data
    uint32 PageSize; // memory page size
    HANDLE hMutex;   // protect data
    
    // tracked heap block
    uint HeapMark;
    int  NumBlocks;
    byte BlocksKey[CRYPTO_KEY_SIZE];
    byte BlocksIV [CRYPTO_IV_SIZE];

    // count global/local heap block
    int32 NumGlobals;
    int32 NumLocals;

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

HGLOBAL MT_GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
HGLOBAL MT_GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags);
HGLOBAL MT_GlobalFree(HGLOBAL lpMem);
HLOCAL  MT_LocalAlloc(UINT uFlags, SIZE_T dwBytes);
HLOCAL  MT_LocalReAlloc(HLOCAL hMem, SIZE_T dwBytes, UINT uFlags);
HLOCAL  MT_LocalFree(HLOCAL lpMem);

void* __cdecl MT_msvcrt_malloc(uint size);
void* __cdecl MT_msvcrt_calloc(uint num, uint size);
void* __cdecl MT_msvcrt_realloc(void* ptr, uint size);
void  __cdecl MT_msvcrt_free(void* ptr);

void* __cdecl MT_ucrtbase_malloc(uint size);
void* __cdecl MT_ucrtbase_calloc(uint num, uint size);
void* __cdecl MT_ucrtbase_realloc(void* ptr, uint size);
void  __cdecl MT_ucrtbase_free(void* ptr);

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
static bool lockPages(MemoryTracker* tracker, uintptr address);
static bool unlockPages(MemoryTracker* tracker, uintptr address);
static bool setPagesLocker(MemoryTracker* tracker, uintptr address, bool lock);
static bool addHeapObject(MemoryTracker* tracker, HANDLE hHeap, uint32 options);
static bool delHeapObject(MemoryTracker* tracker, HANDLE hHeap);
static uint calcHeapMark(uint mark, uintptr addr, uint size);

static uint32 replacePageProtect(uint32 protect);
static bool   isPageTypeTrackable(uint32 type);
static bool   isPageProtectWriteable(uint32 protect);
static bool   adjustPageProtect(MemoryTracker* tracker, memPage* page);
static bool   recoverPageProtect(MemoryTracker* tracker, memPage* page);

static bool encryptPage(MemoryTracker* tracker, memPage* page);
static bool decryptPage(MemoryTracker* tracker, memPage* page);
static bool isEmptyPage(MemoryTracker* tracker, memPage* page);
static void deriveKey(MemoryTracker* tracker, memPage* page, byte* key);
static bool encryptHeapBlocks(MemoryTracker* tracker, HANDLE hHeap);
static bool decryptHeapBlocks(MemoryTracker* tracker, HANDLE hHeap);
static bool eraseHeapBlocks(MemoryTracker* tracker, HANDLE hHeap);
static bool walkHeapBlocks(MemoryTracker* tracker, HANDLE hHeap, int operation);
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
    module->GlobalAlloc    = GetFuncAddr(&MT_GlobalAlloc);
    module->GlobalReAlloc  = GetFuncAddr(&MT_GlobalReAlloc);
    module->GlobalFree     = GetFuncAddr(&MT_GlobalFree);
    module->LocalAlloc     = GetFuncAddr(&MT_LocalAlloc);
    module->LocalReAlloc   = GetFuncAddr(&MT_LocalReAlloc);
    module->LocalFree      = GetFuncAddr(&MT_LocalFree);
    // hooks for msvcrt.dll
    module->msvcrt_malloc  = GetFuncAddr(&MT_msvcrt_malloc);
    module->msvcrt_calloc  = GetFuncAddr(&MT_msvcrt_calloc);
    module->msvcrt_realloc = GetFuncAddr(&MT_msvcrt_realloc);
    module->msvcrt_free    = GetFuncAddr(&MT_msvcrt_free);
    // hooks for ucrtbase.dll
    module->ucrtbase_malloc  = GetFuncAddr(&MT_ucrtbase_malloc);
    module->ucrtbase_calloc  = GetFuncAddr(&MT_ucrtbase_calloc);
    module->ucrtbase_realloc = GetFuncAddr(&MT_ucrtbase_realloc);
    module->ucrtbase_free    = GetFuncAddr(&MT_ucrtbase_free);
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
        { 0x075A8238EE27E826, 0xE930AB7A27AD9691 }, // GetProcessHeaps
        { 0x3CF9F7C4C1B8FD43, 0x34B7FC51484FB2A3 }, // HeapCreate
        { 0xEBA36FC951FD2B34, 0x59504100D9684B0E }, // HeapDestroy
        { 0x8D604A3248B6EAFE, 0x496C489A6E3B8ECD }, // HeapAlloc
        { 0xE04E489AFF9C386C, 0x1A2E6AE0D610549B }, // HeapReAlloc
        { 0x76F81CD39D7A292A, 0x82332A8834C25FA2 }, // HeapFree
        { 0xCBF3B50C5860708F, 0xED694821DB8B2EEC }, // HeapSize
        { 0x867B4ED0812B2DC2, 0xAA9EAFD21F21E1AD }, // HeapLock
        { 0x5ED7EC7D0E4BE01C, 0xCD72A9C05C1231B3 }, // HeapUnlock
        { 0x3E8966B69D68089B, 0x37E3CCE68E00C464 }, // HeapWalk
        { 0x6D12139E758D2222, 0x65801FD39795C655 }, // GlobalAlloc
        { 0x71850DBF6F0606DF, 0x9606F2F813AA08B8 }, // GlobalReAlloc
        { 0x93FC79448E2B42C0, 0x1585336F8D91CF6C }, // GlobalFree
        { 0xE26929AC886F3D5A, 0xCA1B7E486FE85707 }, // LocalAlloc
        { 0x06AB6D6AE82D629A, 0x6E607E20E105F7BB }, // LocalReAlloc
        { 0xB58311891BC88BE4, 0x6735D6D1569CD50C }, // LocalFree
    };
#elif _WIN32
    {
        { 0x79D75104, 0x92F1D233 }, // VirtualQuery
        { 0x2149FD08, 0x6537772D }, // VirtualLock
        { 0xCE162EEC, 0x5D903E73 }, // VirtualUnlock
        { 0x758C3172, 0x23E44CDB }, // GetProcessHeap
        { 0xD9EDA55E, 0x77F2EC35 }, // GetProcessHeaps
        { 0x857D374F, 0x7DC1A133 }, // HeapCreate
        { 0x87A7067F, 0x5B6BA0B9 }, // HeapDestroy
        { 0x6E86E11A, 0x692C7E92 }, // HeapAlloc
        { 0x0E0168E2, 0xFBFF0866 }, // HeapReAlloc
        { 0x94D5662A, 0x266763A1 }, // HeapFree
        { 0xB9E185DC, 0xEDE5B461 }, // HeapSize
        { 0x0EF3433F, 0x9391D7F0 }, // HeapLock
        { 0xF848F9C5, 0x7742CCD1 }, // HeapUnlock
        { 0x252C4D47, 0x1CE53ADF }, // HeapWalk
        { 0x9FB2283F, 0x47937CF8 }, // GlobalAlloc
        { 0x79D908FC, 0xDC71CC28 }, // GlobalReAlloc
        { 0xC173C03A, 0xA7963759 }, // GlobalFree
        { 0xFC9A5703, 0x272EDBFF }, // LocalAlloc
        { 0xC0D9E88A, 0x35443CE7 }, // LocalReAlloc
        { 0x396C4DF0, 0xBDFA6D7B }, // LocalFree
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
    tracker->VirtualQuery    = list[0x00].proc;
    tracker->VirtualLock     = list[0x01].proc;
    tracker->VirtualUnlock   = list[0x02].proc;
    tracker->GetProcessHeap  = list[0x03].proc;
    tracker->GetProcessHeaps = list[0x04].proc;
    tracker->HeapCreate      = list[0x05].proc;
    tracker->HeapDestroy     = list[0x06].proc;
    tracker->HeapAlloc       = list[0x07].proc;
    tracker->HeapReAlloc     = list[0x08].proc;
    tracker->HeapFree        = list[0x09].proc;
    tracker->HeapSize        = list[0x0A].proc;
    tracker->HeapLock        = list[0x0B].proc;
    tracker->HeapUnlock      = list[0x0C].proc;
    tracker->HeapWalk        = list[0x0D].proc;
    tracker->GlobalAlloc     = list[0x0E].proc;
    tracker->GlobalReAlloc   = list[0x0F].proc;
    tracker->GlobalFree      = list[0x10].proc;
    tracker->LocalAlloc      = list[0x11].proc;
    tracker->LocalReAlloc    = list[0x12].proc;
    tracker->LocalFree       = list[0x13].proc;

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
    // generate the random heap mark
    tracker->HeapMark = RandUint((uint64)hMutex);
    RandBuffer(tracker->BlocksKey, CRYPTO_KEY_SIZE);
    RandBuffer(tracker->BlocksIV,  CRYPTO_IV_SIZE);
    // initialize memory region and page list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Regions, &ctx, sizeof(memRegion));
    List_Init(&tracker->Pages,   &ctx, sizeof(memPage));
    List_Init(&tracker->Heaps,   &ctx, sizeof(heapObject));
    // set crypto context data
    RandBuffer(tracker->RegionsKey, CRYPTO_KEY_SIZE);
    RandBuffer(tracker->RegionsIV,  CRYPTO_IV_SIZE);
    RandBuffer(tracker->PagesKey,   CRYPTO_KEY_SIZE);
    RandBuffer(tracker->PagesIV,    CRYPTO_IV_SIZE);
    RandBuffer(tracker->HeapsKey,   CRYPTO_KEY_SIZE);
    RandBuffer(tracker->HeapsIV,    CRYPTO_IV_SIZE);
    // copy runtime methods
    tracker->RT_malloc  = context->malloc;
    tracker->RT_calloc  = context->calloc;
    tracker->RT_realloc = context->realloc;
    tracker->RT_free    = context->free;
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
        success = lockPages(tracker, (uintptr)address);
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
        success = unlockPages(tracker, (uintptr)address);
    } else {
        success = tracker->VirtualUnlock(address, size);
    }

    if (!MT_Unlock())
    {
        return false;
    }
    return success;
}

static bool lockPages(MemoryTracker* tracker, uintptr address)
{
    return setPagesLocker(tracker, address, true);
}

static bool unlockPages(MemoryTracker* tracker, uintptr address)
{
    return setPagesLocker(tracker, address, false);
}

#pragma optimize("t", on)
static bool setPagesLocker(MemoryTracker* tracker, uintptr address, bool lock)
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

__declspec(noinline)
HANDLE MT_HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    HANDLE hHeap;
    errno lastErr = NO_ERROR;
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
        break;
    }

    dbg_log(
        "[memory]", "HeapCreate: 0x%X, 0x%zX, 0x%zX",
        flOptions, dwInitialSize, dwMaximumSize
    );

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

    BOOL  success = false;
    errno lastErr = NO_ERROR;
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

    dbg_log("[memory]", "HeapDestroy: 0x%X", hHeap);

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

// +-------------+-------------+-------------+
// | heap header | user buffer | random mark |
// +-------------+-------------+-------------+
// |     var     |     var     |     uint    |
// +-------------+-------------+-------------+

__declspec(noinline)
LPVOID MT_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    LPVOID address;
    for (;;)
    {
        address = tracker->HeapAlloc(hHeap, dwFlags, dwBytes + BLOCK_MARK_SIZE);
        if (address == NULL)
        {
            break;
        }
        // write heap block mark
        uint* tail = (uint*)((uintptr)address + dwBytes);
        *tail = calcHeapMark(tracker->HeapMark, (uintptr)address, dwBytes);
        // update counter
        tracker->NumBlocks++;
        break;
    }

    dbg_log("[memory]", "HeapAlloc: 0x%zX, 0x%zX", address, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }
    return address;
}

__declspec(noinline)
LPVOID MT_HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    LPVOID address = NULL;
    for (;;)
    {
        if (lpMem == NULL)
        {
            break;
        }
        SIZE_T size = tracker->HeapSize(hHeap, dwFlags, lpMem);
        if (size == (SIZE_T)(-1))
        {
            break;
        }
        // erase old block mark before realloc
        bool marked = false;
        if (size >= BLOCK_MARK_SIZE)
        {
            uintptr block = (uintptr)lpMem;
            uint  bSize = size - BLOCK_MARK_SIZE;
            uint* mark  = (uint*)(block + bSize);
            if (calcHeapMark(tracker->HeapMark, block, bSize) == *mark)
            {
                mem_init(mark, BLOCK_MARK_SIZE);
                marked = true;
            }
        }
        address = tracker->HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes + BLOCK_MARK_SIZE);
        if (address == NULL)
        {
            break;
        }
        // write new heap block mark
        uint* tail = (uint*)((uintptr)address + dwBytes);
        *tail = calcHeapMark(tracker->HeapMark, (uintptr)address, dwBytes);
        // update counter
        if (!marked)
        {
            tracker->NumBlocks++;
        }
        break;
    }

    dbg_log("[memory]", "HeapReAlloc: 0x%zX, 0x%zX", address, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }
    return address;
}

__declspec(noinline)
BOOL MT_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    BOOL  success = false;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        // special case
        if (lpMem == NULL)
        {
            success = tracker->HeapFree(hHeap, dwFlags, lpMem);
            lastErr = GetLastErrno();
            break;
        }
        // check it is a marked block before free
        SIZE_T size = tracker->HeapSize(hHeap, dwFlags, lpMem);
        if (size == (SIZE_T)(-1))
        {
            break;
        }
        bool marked = false;
        if (size >= BLOCK_MARK_SIZE)
        {
            uintptr block = (uintptr)lpMem;
            uint  bSize = size - BLOCK_MARK_SIZE;
            uint* mark  = (uint*)(block + bSize);
            if (calcHeapMark(tracker->HeapMark, block, bSize) == *mark)
            {
                marked = true;
            }
        }
        // erase heap block data and mark before free
        mem_init(lpMem, size);
        if (!tracker->HeapFree(hHeap, dwFlags, lpMem))
        {
            lastErr = GetLastErrno();
            break;
        }
        // update counter
        if (marked)
        {
            tracker->NumBlocks--;
        }
        success = true;
        break;
    }

    dbg_log("[memory]", "HeapFree: 0x%zX", lpMem);

    if (!MT_Unlock())
    {
        return false;
    }

    SetLastErrno(lastErr);
    return success;
}

__declspec(noinline)
HGLOBAL MT_GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    HGLOBAL hGlobal;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hGlobal = tracker->GlobalAlloc(uFlags, dwBytes);
        if (hGlobal == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        // update counter
        tracker->NumGlobals++;
        break;
    }

    dbg_log("[memory]", "GlobalAlloc: 0x%zX, 0x%zX", hGlobal, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return hGlobal;
}

__declspec(noinline)
HGLOBAL MT_GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    HGLOBAL hGlobal;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hGlobal = tracker->GlobalReAlloc(hMem, dwBytes, uFlags);
        if (hGlobal == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        break;
    }

    dbg_log("[memory]", "GlobalReAlloc: 0x%zX, 0x%zX", hGlobal, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return hGlobal;
}

__declspec(noinline)
HGLOBAL MT_GlobalFree(HGLOBAL lpMem)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    HGLOBAL hGlobal;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hGlobal = tracker->GlobalFree(lpMem);
        if (hGlobal != NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        if (lpMem != NULL)
        {
            tracker->NumGlobals--;
        }
        break;
    }

    dbg_log("[memory]", "GlobalFree: 0x%zX", lpMem);

    if (!MT_Unlock())
    {
        return false;
    }

    SetLastErrno(lastErr);
    return hGlobal;
}

__declspec(noinline)
HLOCAL MT_LocalAlloc(UINT uFlags, SIZE_T dwBytes)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    HLOCAL hLocal;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hLocal = tracker->LocalAlloc(uFlags, dwBytes);
        if (hLocal == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        // update counter
        tracker->NumLocals++;
        break;
    }

    dbg_log("[memory]", "LocalAlloc: 0x%zX, 0x%zX", hLocal, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return hLocal;
}

__declspec(noinline)
HLOCAL MT_LocalReAlloc(HLOCAL hMem, SIZE_T dwBytes, UINT uFlags)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    HLOCAL hLocal;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hLocal = tracker->LocalReAlloc(hMem, dwBytes, uFlags);
        if (hLocal == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        break;
    }

    dbg_log("[memory]", "LocalReAlloc: 0x%zX, 0x%zX", hLocal, dwBytes);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return hLocal;
}

__declspec(noinline)
HLOCAL MT_LocalFree(HLOCAL lpMem)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return false;
    }

    HLOCAL hLocal;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        hLocal = tracker->LocalFree(lpMem);
        if (hLocal != NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        if (lpMem != NULL)
        {
            tracker->NumLocals--;
        }
        break;
    }

    dbg_log("[memory]", "LocalFree: 0x%zX", lpMem);

    if (!MT_Unlock())
    {
        return false;
    }

    SetLastErrno(lastErr);
    return hLocal;
}

__declspec(noinline) 
void* __cdecl MT_msvcrt_malloc(uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        msvcrt_malloc_t malloc;
    #ifdef _WIN64
        malloc = FindAPI(0xFD7DFE823F8533B7, 0xBEC6D4C78D168493);
    #elif _WIN32
        malloc = FindAPI(0x60E86880, 0xC8186851);
    #endif
        if (malloc == NULL)
        {
            lastErr = ERR_MEMORY_API_NOT_FOUND;
            break;
        }
        address = malloc(size + BLOCK_MARK_SIZE);
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        if (size == 0)
        {
            break;
        }
        // write heap block mark
        uint* tail = (uint*)((uintptr)address + size);
        *tail = calcHeapMark(tracker->HeapMark, (uintptr)address, size);
        // update counter
        tracker->NumBlocks++;
        break;
    }

    dbg_log("[memory]", "msvcrt malloc: 0x%zX, size: %zu", address, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void* __cdecl MT_msvcrt_calloc(uint num, uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    for (;;)
    {
        msvcrt_calloc_t calloc;
    #ifdef _WIN64
        calloc = FindAPI(0x286555ECFD620100, 0x58661E2CD9AFD903);
    #elif _WIN32
        calloc = FindAPI(0x5F5752CD, 0x9FEEAFA7);
    #endif
        if (calloc == NULL)
        {
            lastErr = ERR_MEMORY_API_NOT_FOUND;
            break;
        }
        address = calloc(num + BLOCK_MARK_SIZE, size);
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        if (size == 0)
        {
            break;
        }
        // write heap block mark
        uint total = (num + BLOCK_MARK_SIZE) * size - BLOCK_MARK_SIZE;
        uint* tail = (uint*)((uintptr)address + total);
        *tail = calcHeapMark(tracker->HeapMark, (uintptr)address, total);
        // update counter
        tracker->NumBlocks++;
        break;
    }

    dbg_log("[memory]", "msvcrt calloc: 0x%zX, num: %zu size: %zu", num, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void* __cdecl MT_msvcrt_realloc(void* ptr, uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    bool  success = false;
    for (;;)
    {
        msvcrt_realloc_t realloc;
    #ifdef _WIN64
        realloc = FindAPI(0x73C74D96B0628E11, 0x6B60E812280A1A13);
    #elif _WIN32
        realloc = FindAPI(0x02ECACC6, 0x7CEA5567);
    #endif
        if (realloc == NULL)
        {
            lastErr = ERR_MEMORY_API_NOT_FOUND;
            break;
        }
        if (size == 0)
        {
            address = realloc(ptr, size);
            lastErr = GetLastErrno();
            success = true;
            break;
        }
        address = realloc(ptr, size + sizeof(uint));
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        // write heap block mark
        uint* tail = (uint*)((uintptr)address + size);
        *tail = calcHeapMark(tracker->HeapMark, (uintptr)address, size);
        // update counter
        if (ptr == NULL)
        {
            tracker->NumBlocks++;
        }
        success = true;
        break;
    }

    dbg_log("[memory]", "msvcrt realloc: 0x%zX, ptr: 0x%zX size: %zu", address, ptr, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void __cdecl MT_msvcrt_free(void* ptr)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return;
    }

    errno lastErr = NO_ERROR;
    for (;;)
    {
        msvcrt_free_t free;
    #ifdef _WIN64
        free = FindAPI(0xDBBA3D4DD22EE2C3, 0xF050775619325CB5);
    #elif _WIN32
        free = FindAPI(0x9235925D, 0x6A110995);
    #endif
        if (free == NULL)
        {
            lastErr = ERR_MEMORY_API_NOT_FOUND;
            break;
        }
        free(ptr);
        lastErr = GetLastErrno();
        if (ptr == NULL)
        {
            break;
        }
        // update counter
        tracker->NumBlocks--;
        break;
    }

    dbg_log("[memory]", "msvcrt free, ptr: 0x%zX", ptr);

    if (!MT_Unlock())
    {
        return;
    }

    SetLastErrno(lastErr);
}

__declspec(noinline) 
void* __cdecl MT_ucrtbase_malloc(uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    bool  success = false;
    for (;;)
    {
        ucrtbase_malloc_t malloc;
    #ifdef _WIN64
        malloc = FindAPI(0x7789A1909ED9CCBF, 0x99717C0C8D37C14A);
    #elif _WIN32
        malloc = FindAPI(0x83F874FD, 0x1CA89591);
    #endif
        if (malloc == NULL)
        {
            lastErr = ERR_MEMORY_API_NOT_FOUND;
            break;
        }
        if (size == 0)
        {
            address = malloc(size);
            lastErr = GetLastErrno();
            success = true;
            break;
        }
        address = malloc(size + sizeof(uint));
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        // write heap block mark
        uint* tail = (uint*)((uintptr)address + size);
        *tail = calcHeapMark(tracker->HeapMark, (uintptr)address, size);
        // update counter
        tracker->NumBlocks++;
        success = true;
        break;
    }

    dbg_log("[memory]", "ucrtbase malloc: 0x%zX, size: %zu", address, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void* __cdecl MT_ucrtbase_calloc(uint num, uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    bool  success = false;
    for (;;)
    {
        ucrtbase_calloc_t calloc;
    #ifdef _WIN64
        calloc = FindAPI(0x70F10113639CEB83, 0xD2316AE480BF91B3);
    #elif _WIN32
        calloc = FindAPI(0x389EA34B, 0x69D8846F);
    #endif
        if (calloc == NULL)
        {
            lastErr = ERR_MEMORY_API_NOT_FOUND;
            break;
        }
        if (size == 0)
        {
            address = calloc(num, size);
            lastErr = GetLastErrno();
            success = true;
            break;
        }
        address = calloc(num + sizeof(uint), size);
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        // write heap block mark
        uint total = num* size;
        uint* tail = (uint*)((uintptr)address + total);
        *tail = calcHeapMark(tracker->HeapMark, (uintptr)address, total);
        // update counter
        tracker->NumBlocks++;
        success = true;
        break;
    }

    dbg_log("[memory]", "ucrtbase calloc: 0x%zX, num: %zu size: %zu", num, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void* __cdecl MT_ucrtbase_realloc(void* ptr, uint size)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return NULL;
    }

    void* address = NULL;
    errno lastErr = NO_ERROR;
    bool  success = false;
    for (;;)
    {
        ucrtbase_realloc_t realloc;
    #ifdef _WIN64
        realloc = FindAPI(0x63C81F2280566B03, 0x9F039B24B1B12251);
    #elif _WIN32
        realloc = FindAPI(0x275557CD, 0x663EE38E);
    #endif
        if (realloc == NULL)
        {
            lastErr = ERR_MEMORY_API_NOT_FOUND;
            break;
        }
        if (size == 0)
        {
            address = realloc(ptr, size);
            lastErr = GetLastErrno();
            success = true;
            break;
        }
        address = realloc(ptr, size + sizeof(uint));
        if (address == NULL)
        {
            lastErr = GetLastErrno();
            break;
        }
        // write heap block mark
        uint* tail = (uint*)((uintptr)address + size);
        *tail = calcHeapMark(tracker->HeapMark, (uintptr)address, size);
        // update counter
        if (ptr == NULL)
        {
            tracker->NumBlocks++;
        }
        success = true;
        break;
    }

    dbg_log("[memory]", "ucrtbase realloc: 0x%zX, ptr: 0x%zX size: %zu", address, ptr, size);

    if (!MT_Unlock())
    {
        return NULL;
    }

    SetLastErrno(lastErr);
    return address;
}

__declspec(noinline)
void __cdecl MT_ucrtbase_free(void* ptr)
{
    MemoryTracker* tracker = getTrackerPointer();

    if (!MT_Lock())
    {
        return;
    }

    errno lastErr = NO_ERROR;
    for (;;)
    {
        ucrtbase_free_t free;
    #ifdef _WIN64
        free = FindAPI(0x7D91AA1B038C76C5, 0x3059081C8654A25C);
    #elif _WIN32
        free = FindAPI(0x3E4E46A9, 0x4E12F93E);
    #endif
        if (free == NULL)
        {
            lastErr = ERR_MEMORY_API_NOT_FOUND;
            break;
        }
        free(ptr);
        lastErr = GetLastErrno();
        if (ptr == NULL)
        {
            break;
        }
        // update counter
        tracker->NumBlocks--;
        break;
    }

    dbg_log("[memory]", "ucrtbase free, ptr: 0x%zX", ptr);

    if (!MT_Unlock())
    {
        return;
    }

    SetLastErrno(lastErr);
}

static uint calcHeapMark(uint mark, uintptr addr, uint size)
{
    mark = XORShift(mark ^ addr);
    mark = XORShift(mark);
    return mark + size;
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

    // encrypt memory pages
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

    // encrypt heap blocks
    if (tracker->NumBlocks != 0)
    {
        // get the number of heaps
        HANDLE padding;
        DWORD  numHeaps = tracker->GetProcessHeaps(0, &padding);
        // get heap handles
        HANDLE* hHeaps = tracker->RT_calloc(numHeaps, sizeof(HANDLE));
        if (tracker->GetProcessHeaps(numHeaps, hHeaps) != 0)
        {
            HANDLE* hHeap = hHeaps;
            // walk and encrypt heap blocks
            for (uint32 i = 0; i < numHeaps; i++)
            {
                if (!encryptHeapBlocks(tracker, *hHeap))
                {
                    return ERR_MEMORY_ENCRYPT_BLOCK;
                }
                hHeap++;
            }
        }
        tracker->RT_free(hHeaps);
    }

    // encrypt lists
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

    list = &tracker->Heaps;
    key  = tracker->HeapsKey;
    iv   = tracker->HeapsIV;
    RandBuffer(key, CRYPTO_KEY_SIZE);
    RandBuffer(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno MT_Decrypt()
{
    MemoryTracker* tracker = getTrackerPointer();

    // decrypt lists
    List* list = &tracker->Regions;
    byte* key  = tracker->RegionsKey;
    byte* iv   = tracker->RegionsIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    list = &tracker->Pages;
    key  = tracker->PagesKey;
    iv   = tracker->PagesIV;
    DecryptBuf(list->Data, List_Size(list), key, iv);

    list = &tracker->Heaps;
    key  = tracker->HeapsKey;
    iv   = tracker->HeapsIV;
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

    // decrypt heap blocks
    if (tracker->NumBlocks != 0)
    {
        // get the number of heaps
        HANDLE padding;
        DWORD  numHeaps = tracker->GetProcessHeaps(0, &padding);
        // get heap handles
        HANDLE* hHeaps = tracker->RT_calloc(numHeaps, sizeof(HANDLE));
        if (tracker->GetProcessHeaps(numHeaps, hHeaps) != 0)
        {
            HANDLE* hHeap = hHeaps;
            // walk and decrypt heap blocks
            for (uint32 i = 0; i < numHeaps; i++)
            {
                if (!decryptHeapBlocks(tracker, *hHeap))
                {
                    return ERR_MEMORY_DECRYPT_BLOCK;
                }
                hHeap++;
            }
        }
        tracker->RT_free(hHeaps);
    }

    dbg_log("[memory]", "regions: %zu", tracker->Regions.Len);
    dbg_log("[memory]", "pages:   %zu", tracker->Pages.Len);
    dbg_log("[memory]", "heaps:   %zu", tracker->Heaps.Len);
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

static bool encryptHeapBlocks(MemoryTracker* tracker, HANDLE hHeap)
{
    return walkHeapBlocks(tracker, hHeap, OP_WALK_HEAP_ENCRYPT);
}

static bool decryptHeapBlocks(MemoryTracker* tracker, HANDLE hHeap)
{
    return walkHeapBlocks(tracker, hHeap, OP_WALK_HEAP_DECRYPT);
}

static bool eraseHeapBlocks(MemoryTracker* tracker, HANDLE hHeap)
{
    return walkHeapBlocks(tracker, hHeap, OP_WALK_HEAP_ERASE);
}

static bool walkHeapBlocks(MemoryTracker* tracker, HANDLE hHeap, int operation)
{
    if (!tracker->HeapLock(hHeap))
    {
        return false;
    }

    HEAP_ENTRY entry = {
        .lpData = NULL,
    };
    uint numFound = 0;
    for (;;)
    {
        if (!tracker->HeapWalk(hHeap, &entry))
        {
            break;
        }
        // skip too small block that not contain mark
        if (entry.cbData < BLOCK_MARK_SIZE)
        {
            continue;
        }
        // skip block that not used
        if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) == 0)
        {
            continue;
        }
        // skip empty block
        if (mem_is_zero(entry.lpData, entry.cbData))
        {
            continue;
        }
        // check is marked block
        uintptr block = (uintptr)(entry.lpData);
        uint size = entry.cbData - BLOCK_MARK_SIZE;
        uint mark = *(uint*)(block + size);
        if (calcHeapMark(tracker->HeapMark, block, size) != mark)
        {
            continue;
        }
        // encrypt/decrypt heap block
        byte* buf = (byte*)(entry.lpData);
        byte* key = tracker->BlocksKey;
        byte* iv  = tracker->BlocksIV;
        switch (operation)
        {
        case OP_WALK_HEAP_ENCRYPT:
            EncryptBuf(buf, size, key, iv);
            break;
        case OP_WALK_HEAP_DECRYPT:
            DecryptBuf(buf, size, key, iv);
            break;
        case OP_WALK_HEAP_ERASE:
            mem_init(buf, entry.cbData);
            if (!tracker->HeapFree(hHeap, HEAP_NO_SERIALIZE, buf))
            {
               continue;
            }
            break;
        default:
            panic(PANIC_UNREACHABLE_CODE);
        }
        numFound++;
    }
    errno lastErr = GetLastErrno();
    
    if (!tracker->HeapUnlock(hHeap))
    {
        return false;
    }

    dbg_log("[memory]", "heap block: %zu/%d", numFound, tracker->NumBlocks);

    bool success = lastErr == ERROR_NO_MORE_ITEMS;
    if (success)
    {
        SetLastErrno(NO_ERROR);
    } else {
        SetLastErrno(lastErr);
    }
    return success;
}

__declspec(noinline)
errno MT_FreeAll()
{
    MemoryTracker* tracker = getTrackerPointer();

    List* regions = &tracker->Regions;
    List* pages   = &tracker->Pages;
    List* heaps   = &tracker->Heaps;
    errno errno   = NO_ERROR;

    // cover memory page data
    uint len = pages->Len;
    uint idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memPage* page = List_Get(pages, idx);
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
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memPage* page = List_Get(pages, idx);
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
        if (!List_Delete(pages, idx))
        {
            errno = ERR_MEMORY_DELETE_PAGE;
        }
        num++;
    }

    // release reserved memory region
    len = regions->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        memRegion* region = List_Get(regions, idx);
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
        if (!List_Delete(regions, idx))
        {
            errno = ERR_MEMORY_DELETE_REGION;
        }
        num++;
    }

    // erase heap blocks
    if (tracker->NumBlocks != 0)
    {
        // get the number of heaps
        HANDLE padding;
        DWORD  numHeaps = tracker->GetProcessHeaps(0, &padding);
        // get heap handles
        HANDLE* hHeaps = tracker->RT_calloc(numHeaps, sizeof(HANDLE));
        if (tracker->GetProcessHeaps(numHeaps, hHeaps) != 0)
        {
            HANDLE* hHeap = hHeaps;
            // walk and encrypt heap blocks
            for (uint32 i = 0; i < numHeaps; i++)
            {
                if (!eraseHeapBlocks(tracker, *hHeap))
                {
                    errno = ERR_MEMORY_ERASE_BLOCK;
                }
                hHeap++;
            }
        }
        tracker->RT_free(hHeaps);
    }

    // release private heaps
    len = heaps->Len;
    idx = 0;
    for (uint num = 0; num < len; idx++)
    {
        heapObject* heap = List_Get(heaps, idx);
        if (heap->hHeap == NULL)
        {
            continue;
        }
        if (!tracker->HeapDestroy(heap->hHeap))
        {
            errno = ERR_MEMORY_CLEAN_HEAP;
        }
        if (!List_Delete(heaps, idx))
        {
            errno = ERR_MEMORY_DELETE_HEAP;
        }
        num++;
    }

    dbg_log("[memory]", "regions: %zu", tracker->Regions.Len);
    dbg_log("[memory]", "pages:   %zu", tracker->Pages.Len);
    dbg_log("[memory]", "heaps:   %zu", tracker->Heaps.Len);
    dbg_log("[memory]", "blocks:  %d",  tracker->NumBlocks);
    dbg_log("[memory]", "globals: %d",  tracker->NumGlobals);
    dbg_log("[memory]", "locals:  %d",  tracker->NumLocals);
    return errno;
}

__declspec(noinline)
errno MT_Clean()
{
    MemoryTracker* tracker = getTrackerPointer();

    List* regions = &tracker->Regions;
    List* pages   = &tracker->Pages;
    List* heaps   = &tracker->Heaps;
    errno errno   = NO_ERROR;

    // cover memory page data
    uint idx = 0;
    for (uint num = 0; num < pages->Len; idx++)
    {
        memPage* page = List_Get(pages, idx);
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
    idx = 0;
    for (uint num = 0; num < pages->Len; idx++)
    {
        memPage* page = List_Get(pages, idx);
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
    idx = 0;
    for (uint num = 0; num < regions->Len; idx++)
    {
        memRegion* region = List_Get(regions, idx);
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

    // erase heap blocks
    if (tracker->NumBlocks != 0)
    {
        // get the number of heaps
        HANDLE padding;
        DWORD  numHeaps = tracker->GetProcessHeaps(0, &padding);
        // get heap handles
        HANDLE* hHeaps = tracker->RT_calloc(numHeaps, sizeof(HANDLE));
        if (tracker->GetProcessHeaps(numHeaps, hHeaps) != 0)
        {
            HANDLE* hHeap = hHeaps;
            // walk and encrypt heap blocks
            for (uint32 i = 0; i < numHeaps; i++)
            {
                if (!eraseHeapBlocks(tracker, *hHeap))
                {
                    if (errno == NO_ERROR)
                    {
                        errno = ERR_MEMORY_ERASE_BLOCK;
                    }
                }
                hHeap++;
            }
        }
        tracker->RT_free(hHeaps);
    }

    // release private heaps
    idx = 0;
    for (uint num = 0; num < heaps->Len; idx++)
    {
        heapObject* heap = List_Get(heaps, idx);
        if (heap->hHeap == NULL)
        {
            continue;
        }
        if (!tracker->HeapDestroy(heap->hHeap))
        {
            if (errno == NO_ERROR)
            {
                errno = ERR_MEMORY_CLEAN_HEAP;
            }
        }
        num++;
    }

    // clean memory region and page list
    RandBuffer(regions->Data, List_Size(regions));
    RandBuffer(pages->Data, List_Size(pages));
    RandBuffer(heaps->Data, List_Size(heaps));
    if (!List_Free(regions) && errno == NO_ERROR)
    {
        errno = ERR_MEMORY_FREE_PAGE_LIST;
    }
    if (!List_Free(pages) && errno == NO_ERROR)
    {
        errno = ERR_MEMORY_FREE_REGION_LIST;
    }
    if (!List_Free(heaps) && errno == NO_ERROR)
    {
        errno = ERR_MEMORY_FREE_HEAP_LIST;
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

    dbg_log("[memory]", "regions: %zu", tracker->Regions.Len);
    dbg_log("[memory]", "pages:   %zu", tracker->Pages.Len);
    dbg_log("[memory]", "heaps:   %zu", tracker->Heaps.Len);
    dbg_log("[memory]", "blocks:  %d",  tracker->NumBlocks);
    dbg_log("[memory]", "globals: %d",  tracker->NumGlobals);
    dbg_log("[memory]", "locals:  %d",  tracker->NumLocals);
    return errno;
}

static bool cleanPage(MemoryTracker* tracker, memPage* page)
{
    LPVOID addr = (LPVOID)(page->address);
    DWORD  size = (DWORD)(tracker->PageSize);
    return tracker->VirtualFree(addr, size, MEM_DECOMMIT);
}
