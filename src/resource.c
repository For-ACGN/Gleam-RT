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
#include "resource.h"

#define SRC_CREATE_FILE_A 0x0001
#define SRC_CREATE_FILE_W 0x0002
#define SRC_OPEN_FILE     0x0006

#define RES_WSA 0x0000

typedef struct {
    HANDLE handle;
    uint16 source;
} handle;

typedef struct {
    // API addresses
    CreateFileA_t         CreateFileA;
    CreateFileW_t         CreateFileW;
    CloseHandle_t         CloseHandle;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;

    // runtime data
    HANDLE Mutex; // global mutex

    // store all tracked Handles
    List Handles;
    byte HandlesKey[CRYPTO_KEY_SIZE];
    byte HandlesIV [CRYPTO_IV_SIZE];

    // tracked Windows API
    WSAStartup_t WSAStartup;
    WSACleanup_t WSACleanup;

    // store all resource counters
    int64 Counters[1];
} ResourceTracker;

// methods about resource tracker
int RT_WSAStartup(uint16 wVersionRequired, void* lpWSAData);
int RT_WSACleanup();

errno RT_Encrypt();
errno RT_Decrypt();
errno RT_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF11111104
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCD04
#endif
static ResourceTracker* getTrackerPointer();

static bool rt_lock(ResourceTracker* tracker);
static bool rt_unlock(ResourceTracker* tracker);

static bool initTrackerAPI(ResourceTracker* tracker, Context* context);
static bool updateTrackerPointer(ResourceTracker* tracker);
static bool initTrackerEnvironment(ResourceTracker* tracker, Context* context);

static void eraseTrackerMethods();
static void cleanTracker(ResourceTracker* tracker);

ResourceTracker_M* InitResourceTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 6000 + RandUint(address) % 128;
    uintptr moduleAddr  = address + 6700 + RandUint(address) % 128;
    // initialize tracker
    ResourceTracker* tracker = (ResourceTracker*)trackerAddr;
    mem_clean(tracker, sizeof(ResourceTracker));
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errno = ERR_RESOURCE_INIT_API;
            break;
        }
        if (!updateTrackerPointer(tracker))
        {
            errno = ERR_RESOURCE_UPDATE_PTR;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errno = ERR_RESOURCE_INIT_ENV;
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
    ResourceTracker_M* module = (ResourceTracker_M*)moduleAddr;
    // Windows API hooks
    module->WSAStartup = (WSAStartup_t)(&RT_WSAStartup);
    module->WSACleanup = (WSACleanup_t)(&RT_WSACleanup);
    // methods for runtime
    module->ResEncrypt = &RT_Encrypt;
    module->ResDecrypt = &RT_Decrypt;
    module->ResClean   = &RT_Clean;
    return module;
}

__declspec(noinline)
static bool initTrackerAPI(ResourceTracker* tracker, Context* context)
{
    typedef struct { 
        uint hash; uint key; uintptr address;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x31399C47B70A8590, 0x5C59C3E176954594 }, // CreateFileA
        { 0xD1B5E30FA8812243, 0xFD9A53B98C9A437E }, // CreateFileW
    };
#elif _WIN32
    {
        { 0x0BB8EEBE, 0x28E70E8D }, // CreateFileA
        { 0x2CB7048A, 0x76AC9783 }, // CreateFileW
    };
#endif
    uintptr address;
    for (int i = 0; i < arrlen(list); i++)
    {
        address = FindAPI(list[i].hash, list[i].key);
        if (address == NULL)
        {
            return false;
        }
        list[i].address = address;
    }

    tracker->CreateFileA = (CreateFileA_t)(list[0].address);
    tracker->CreateFileW = (CreateFileW_t)(list[1].address);

    tracker->CloseHandle         = context->CloseHandle;
    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    return true;
}

__declspec(noinline)
static bool updateTrackerPointer(ResourceTracker* tracker)
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

__declspec(noinline)
static bool initTrackerEnvironment(ResourceTracker* tracker, Context* context)
{
    // copy runtime context data
    tracker->Mutex = context->Mutex;
    // initialize handle list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Handles, &ctx, sizeof(handle));
    // set crypto context data
    RandBuf(&tracker->HandlesKey[0], CRYPTO_KEY_SIZE);
    RandBuf(&tracker->HandlesIV[0], CRYPTO_IV_SIZE);
    // initialize structure fields
    tracker->WSAStartup = NULL;
    tracker->WSACleanup = NULL;
    // initialize counters
    for (int i = 0; i < arrlen(tracker->Counters); i++)
    {
        tracker->Counters[i] = 0;
    }
    return true;
}

__declspec(noinline)
static void eraseTrackerMethods()
{
    uintptr begin = (uintptr)(&initTrackerAPI);
    uintptr end   = (uintptr)(&eraseTrackerMethods);
    int64   size  = end - begin;
    RandBuf((byte*)begin, size);
}

__declspec(noinline)
static void cleanTracker(ResourceTracker* tracker)
{
    List_Free(&tracker->Handles);
    for (int i = 0; i < arrlen(tracker->Counters); i++)
    {
        tracker->Counters[i] = 0;
    }
}

// updateTrackerPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateTrackerPointer will fail.
#pragma optimize("", off)
static ResourceTracker* getTrackerPointer()
{
    uint pointer = TRACKER_POINTER;
    return (ResourceTracker*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool rt_lock(ResourceTracker* tracker)
{
    uint32 event = tracker->WaitForSingleObject(tracker->Mutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

__declspec(noinline)
static bool rt_unlock(ResourceTracker* tracker)
{
    return tracker->ReleaseMutex(tracker->Mutex);
}

__declspec(noinline)
int RT_WSAStartup(uint16 wVersionRequired, POINTER lpWSAData)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!rt_lock(tracker))
    {
        return WSASYSNOTREADY;
    }

    // check API is found
    if (tracker->WSAStartup == NULL)
    {
    #ifdef _WIN64
        WSAStartup_t proc = FindAPI(0x21A84954D72D9F93, 0xD549133F33DA137E);
    #elif _WIN32
        WSAStartup_t proc = FindAPI(0x8CD788B9, 0xA349D8A2);
    #endif
        if (proc == NULL)
        {
            return WSASYSNOTREADY;
        }
        tracker->WSAStartup = proc;
    }
    int ret = tracker->WSAStartup(wVersionRequired, lpWSAData);
    if (ret == 0)
    {
        tracker->Counters[RES_WSA]++;
        printf_s("ResourceTracker: WSAStartup\n");
    }

    if (!rt_unlock(tracker))
    {
        return WSASYSNOTREADY;
    }
    return ret;
}

__declspec(noinline)
int RT_WSACleanup()
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!rt_lock(tracker))
    {
        return WSAEINPROGRESS;
    }

    // check API is found
    if (tracker->WSACleanup == NULL)
    {
    #ifdef _WIN64
        WSACleanup_t proc = FindAPI(0x324EEA09CB7B262C, 0xE64CBAD3BBD4F522);
    #elif _WIN32
        WSACleanup_t proc = FindAPI(0xBD997AF1, 0x88F10695);
    #endif
        if (proc == NULL)
        {
            return WSAEINPROGRESS;
        }
        tracker->WSACleanup = proc;
    }
    int ret = tracker->WSACleanup();
    if (ret == 0)
    {
        tracker->Counters[RES_WSA]--;
        printf_s("ResourceTracker: WSACleanup\n");
    }

    if (!rt_unlock(tracker))
    {
        return WSAEINPROGRESS;
    }
    return ret;
}

__declspec(noinline)
errno RT_Encrypt()
{
    ResourceTracker* tracker = getTrackerPointer();

    return NO_ERROR;
}

__declspec(noinline)
errno RT_Decrypt()
{
    ResourceTracker* tracker = getTrackerPointer();

    return NO_ERROR;
}

__declspec(noinline)
errno RT_Clean()
{
    ResourceTracker* tracker = getTrackerPointer();

    errno errno   = NO_ERROR;
    int64 counter = 0;

    // WSACleanup
    counter = tracker->Counters[RES_WSA];
    for (int64 i = 0; i < counter; i++)
    {
        if (tracker->WSACleanup() != 0)
        {
            errno = ERR_RESOURCE_WSA_CLEANUP;
        }
    }

    return errno;
}
