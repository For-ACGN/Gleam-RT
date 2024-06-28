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

#define SRC_CREATE_FILE_A     0x0001
#define SRC_CREATE_FILE_W     0x0002
#define SRC_FIND_FIRST_FILE_A 0x0003
#define SRC_FIND_FIRST_FILE_W 0x0004

#define LIB_WSA_STARTUP 0x0000

typedef struct {
    void*  handle;
    uint16 source;
} handle;

typedef struct {
    // API addresses
    CreateFileA_t         CreateFileA;
    CreateFileW_t         CreateFileW;
    CloseHandle_t         CloseHandle;
    FindFirstFileA_t      FindFirstFileA;
    FindFirstFileW_t      FindFirstFileW;
    FindClose_t           FindClose;
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

// methods for IAT hooks
HANDLE RT_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
);
HANDLE RT_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
);
BOOL   RT_CloseHandle(HANDLE hObject);
HANDLE RT_FindFirstFileA(LPCSTR lpFileName, POINTER lpFindFileData);
HANDLE RT_FindFirstFileW(LPCWSTR lpFileName, POINTER lpFindFileData);
BOOL   RT_FindClose(HANDLE hFindFile);

int RT_WSAStartup(WORD wVersionRequired, POINTER lpWSAData);
int RT_WSACleanup();

// methods for runtime
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
    module->CreateFileA    = &RT_CreateFileA;
    module->CreateFileW    = &RT_CreateFileW;
    module->CloseHandle    = &RT_CloseHandle;
    module->FindFirstFileA = &RT_FindFirstFileA;
    module->FindFirstFileW = &RT_FindFirstFileW;
    module->FindClose      = &RT_FindClose;
    module->WSAStartup     = &RT_WSAStartup;
    module->WSACleanup     = &RT_WSACleanup;
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
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x31399C47B70A8590, 0x5C59C3E176954594 }, // CreateFileA
        { 0xD1B5E30FA8812243, 0xFD9A53B98C9A437E }, // CreateFileW
        { 0x60041DBB2B0D19DF, 0x7BD2C85D702B4DDC }, // FindFirstFileA
        { 0xFE81B7989672CCE3, 0xA7FD593F0ED3E8EA }, // FindFirstFileW
        { 0x98AC87F60ED8677D, 0x2DF5C74604B2E3A1 }, // FindClose
    };
#elif _WIN32
    {
        { 0x0BB8EEBE, 0x28E70E8D }, // CreateFileA
        { 0x2CB7048A, 0x76AC9783 }, // CreateFileW
        { 0x131B6345, 0x65478818 }, // FindFirstFileA
        { 0xD57E7557, 0x50BC5D0F }, // FindFirstFileW
        { 0xE992A699, 0x8B6ED092 }, // FindClose
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
    tracker->CreateFileA    = list[0x00].proc;
    tracker->CreateFileW    = list[0x01].proc;
    tracker->FindFirstFileA = list[0x02].proc;
    tracker->FindFirstFileW = list[0x03].proc;
    tracker->FindClose      = list[0x04].proc;

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
HANDLE RT_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!rt_lock(tracker))
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFile = tracker->CreateFileA(
        lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
    );

    printf_s("CreateFileA: %s\n", lpFileName);

    if (!rt_unlock(tracker))
    {
        if (hFile != INVALID_HANDLE_VALUE)
        {
            tracker->CloseHandle(hFile);
        }
        return INVALID_HANDLE_VALUE;
    }
    return hFile;
};

__declspec(noinline)
HANDLE RT_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!rt_lock(tracker))
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFile = tracker->CreateFileW(
        lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
    );

    printf_s("CreateFileW: %ls\n", lpFileName);

    if (!rt_unlock(tracker))
    {
        if (hFile != INVALID_HANDLE_VALUE)
        {
            tracker->CloseHandle(hFile);
        }
        return INVALID_HANDLE_VALUE;
    }
    return hFile;
};

__declspec(noinline)
BOOL RT_CloseHandle(HANDLE hObject)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!rt_lock(tracker))
    {
        return false;
    }

    BOOL ok = tracker->CloseHandle(hObject);

    if (!rt_unlock(tracker))
    {
        return false;
    }
    return ok;
};

__declspec(noinline)
HANDLE RT_FindFirstFileA(LPCSTR lpFileName, POINTER lpFindFileData)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!rt_lock(tracker))
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFindFile = tracker->FindFirstFileA(lpFileName, lpFindFileData);

    printf_s("FindFirstFileA: %s\n", lpFileName);

    if (!rt_unlock(tracker))
    {
        if (hFindFile != INVALID_HANDLE_VALUE)
        {
            tracker->FindClose(hFindFile);
        }
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

__declspec(noinline)
HANDLE RT_FindFirstFileW(LPCWSTR lpFileName, POINTER lpFindFileData)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!rt_lock(tracker))
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFindFile = tracker->FindFirstFileW(lpFileName, lpFindFileData);

    printf_s("FindFirstFileW: %ls\n", lpFileName);

    if (!rt_unlock(tracker))
    {
        if (hFindFile != INVALID_HANDLE_VALUE)
        {
            tracker->FindClose(hFindFile);
        }
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

__declspec(noinline)
BOOL RT_FindClose(HANDLE hFindFile)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!rt_lock(tracker))
    {
        return false;
    }

    BOOL ok = tracker->FindClose(hFindFile);

    if (!rt_unlock(tracker))
    {
        return false;
    }
    return ok;
};

__declspec(noinline)
int RT_WSAStartup(WORD wVersionRequired, POINTER lpWSAData)
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
        tracker->Counters[LIB_WSA_STARTUP]++;
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
        tracker->Counters[LIB_WSA_STARTUP]--;
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

    List* list = &tracker->Handles;
    byte* key  = &tracker->HandlesKey[0];
    byte* iv   = &tracker->HandlesIV[0];
    RandBuf(key, CRYPTO_KEY_SIZE);
    RandBuf(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno RT_Decrypt()
{
    ResourceTracker* tracker = getTrackerPointer();

    List* list = &tracker->Handles;
    byte* key  = &tracker->HandlesKey[0];
    byte* iv   = &tracker->HandlesIV[0];
    DecryptBuf(list->Data, List_Size(list), key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno RT_Clean()
{
    ResourceTracker* tracker = getTrackerPointer();

    List* handles = &tracker->Handles;
    errno errno   = NO_ERROR;
    
    // close all tracked handles
    uint index = 0;
    for (uint num = 0; num < handles->Len; index++)
    {
        handle* handle = List_Get(handles, index);
        if (handle->handle == NULL)
        {
            continue;
        }
        if (!tracker->CloseHandle(handle->handle))
        {
            errno = ERR_RESOURCE_CLOSE_HANDLE;
        }
        num++;
    }

    // clean handle list
    RandBuf(handles->Data, List_Size(handles));
    if (!List_Free(handles))
    {
        errno = ERR_RESOURCE_FREE_HANDLE_LIST;
    }

    // process init function tracker
    int64 counter = 0;
    // WSACleanup
    counter = tracker->Counters[LIB_WSA_STARTUP];
    for (int64 i = 0; i < counter; i++)
    {
        if (tracker->WSACleanup() != 0)
        {
            errno = ERR_RESOURCE_WSA_CLEANUP;
        }
    }
    return errno;
}
