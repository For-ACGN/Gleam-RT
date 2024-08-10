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
#include "resource.h"
#include "debug.h"

// handle types about release functions
#define TYPE_CLOSE_HANDLE 0x0100
#define TYPE_FIND_CLOSE   0x0200

// handles created by functions
#define SRC_CREATE_FILE_A (0x0001|TYPE_CLOSE_HANDLE)
#define SRC_CREATE_FILE_W (0x0002|TYPE_CLOSE_HANDLE)

#define SRC_FIND_FIRST_FILE_A    (0x0001|TYPE_FIND_CLOSE)
#define SRC_FIND_FIRST_FILE_W    (0x0002|TYPE_FIND_CLOSE)
#define SRC_FIND_FIRST_FILE_EX_A (0x0003|TYPE_FIND_CLOSE)
#define SRC_FIND_FIRST_FILE_EX_W (0x0004|TYPE_FIND_CLOSE)

// resource counters index
#define CTR_WSA_STARTUP 0x0000

typedef struct {
    void*  handle;
    uint16 source;
} handle;

typedef struct {
    // API addresses
    CreateFileA_t         CreateFileA;
    CreateFileW_t         CreateFileW;
    FindFirstFileA_t      FindFirstFileA;
    FindFirstFileW_t      FindFirstFileW;
    FindFirstFileExA_t    FindFirstFileExA;
    FindFirstFileExW_t    FindFirstFileExW;
    CloseHandle_t         CloseHandle;
    FindClose_t           FindClose;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;

    // protect data
    HANDLE hMutex;

    // store all tracked Handles
    List Handles;
    byte HandlesKey[CRYPTO_KEY_SIZE];
    byte HandlesIV [CRYPTO_IV_SIZE];

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
HANDLE RT_FindFirstFileA(LPCSTR lpFileName, POINTER lpFindFileData);
HANDLE RT_FindFirstFileW(LPCWSTR lpFileName, POINTER lpFindFileData);
HANDLE RT_FindFirstFileExA(
    LPCSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
);
HANDLE RT_FindFirstFileExW(
    LPCWSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
);
BOOL RT_CloseHandle(HANDLE hObject);
BOOL RT_FindClose(HANDLE hFindFile);

// resource counters
int RT_WSAStartup(WORD wVersionRequired, POINTER lpWSAData);
int RT_WSACleanup();

// methods for runtime
bool  RT_Lock();
bool  RT_Unlock();
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

static bool initTrackerAPI(ResourceTracker* tracker, Context* context);
static bool updateTrackerPointer(ResourceTracker* tracker);
static bool initTrackerEnvironment(ResourceTracker* tracker, Context* context);
static bool addHandle(ResourceTracker* tracker, void* hObject, uint16 source);
static void delHandle(ResourceTracker* tracker, void* hObject, uint16 type);

static void eraseTrackerMethods();
static void cleanTracker(ResourceTracker* tracker);

ResourceTracker_M* InitResourceTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 6000 + RandUintN(address, 128);
    uintptr moduleAddr  = address + 6700 + RandUintN(address, 128);
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
    module->CreateFileA      = GetFuncAddr(&RT_CreateFileA);
    module->CreateFileW      = GetFuncAddr(&RT_CreateFileW);
    module->FindFirstFileA   = GetFuncAddr(&RT_FindFirstFileA);
    module->FindFirstFileW   = GetFuncAddr(&RT_FindFirstFileW);
    module->FindFirstFileExA = GetFuncAddr(&RT_FindFirstFileExA);
    module->FindFirstFileExW = GetFuncAddr(&RT_FindFirstFileExW);
    module->CloseHandle      = GetFuncAddr(&RT_CloseHandle);
    module->FindClose        = GetFuncAddr(&RT_FindClose);
    module->WSAStartup       = GetFuncAddr(&RT_WSAStartup);
    module->WSACleanup       = GetFuncAddr(&RT_WSACleanup);
    // methods for runtime
    module->Lock    = GetFuncAddr(&RT_Lock);
    module->Unlock  = GetFuncAddr(&RT_Unlock);
    module->Encrypt = GetFuncAddr(&RT_Encrypt);
    module->Decrypt = GetFuncAddr(&RT_Decrypt);
    module->Clean   = GetFuncAddr(&RT_Clean);
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
        { 0xCAA3E575156CF368, 0x8A587657CB19E9BB }, // FindFirstFileExA
        { 0x7E4308DC46D7B281, 0x10C4F8ED60BC5EB5 }, // FindFirstFileExW
        { 0x98AC87F60ED8677D, 0x2DF5C74604B2E3A1 }, // FindClose
    };
#elif _WIN32
    {
        { 0x0BB8EEBE, 0x28E70E8D }, // CreateFileA
        { 0x2CB7048A, 0x76AC9783 }, // CreateFileW
        { 0x131B6345, 0x65478818 }, // FindFirstFileA
        { 0xD57E7557, 0x50BC5D0F }, // FindFirstFileW
        { 0xADD805AF, 0xD14251F2 }, // FindFirstFileExA
        { 0x0A45496A, 0x4A4A7F36 }, // FindFirstFileExW
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
    tracker->CreateFileA      = list[0x00].proc;
    tracker->CreateFileW      = list[0x01].proc;
    tracker->FindFirstFileA   = list[0x02].proc;
    tracker->FindFirstFileW   = list[0x03].proc;
    tracker->FindFirstFileExA = list[0x04].proc;
    tracker->FindFirstFileExW = list[0x05].proc;
    tracker->FindClose        = list[0x06].proc;

    tracker->CloseHandle         = context->CloseHandle;
    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    return true;
}

__declspec(noinline)
static bool updateTrackerPointer(ResourceTracker* tracker)
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
static bool initTrackerEnvironment(ResourceTracker* tracker, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    tracker->hMutex = hMutex;
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
    uintptr begin = (uintptr)(GetFuncAddr(&initTrackerAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseTrackerMethods));
    uintptr size  = end - begin;
    RandBuf((byte*)begin, (int64)size);
}

__declspec(noinline)
static void cleanTracker(ResourceTracker* tracker)
{
    if (tracker->CloseHandle != NULL && tracker->hMutex != NULL)
    {
        tracker->CloseHandle(tracker->hMutex);
    }
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
HANDLE RT_CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFile;

    bool success = true;
    for (;;)
    {
        hFile = tracker->CreateFileA(
            lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
        );
        if (hFile == INVALID_HANDLE_VALUE)
        {
            success = false;
            break;
        }
        if (!addHandle(tracker, hFile, SRC_CREATE_FILE_A))
        {
            success = false;
            break;
        }
        break;
    }

    dbg_log("[resource]", "CreateFileA: %s\n", lpFileName);

    if (!RT_Unlock())
    {
        if (success)
        {
            tracker->CloseHandle(hFile);
        }
        return INVALID_HANDLE_VALUE;
    }
    if (!success)
    {
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

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFile;

    bool success = true;
    for (;;)
    {
        hFile = tracker->CreateFileW(
            lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
        );
        if (hFile == INVALID_HANDLE_VALUE)
        {
            success = false;
            break;
        }
        if (!addHandle(tracker, hFile, SRC_CREATE_FILE_W))
        {
            success = false;
            break;
        }
        break;
    }

    dbg_log("[resource]", "CreateFileW: %ls\n", lpFileName);

    if (!RT_Unlock())
    {
        if (success)
        {
            tracker->CloseHandle(hFile);
        }
        return INVALID_HANDLE_VALUE;
    }
    if (!success)
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFile;
};

__declspec(noinline)
BOOL RT_CloseHandle(HANDLE hObject)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return false;
    }

    BOOL success;
    for (;;)
    {
        success = tracker->CloseHandle(hObject);
        if (!success)
        {
            break;
        }
        delHandle(tracker, hObject, TYPE_CLOSE_HANDLE);
        break;
    }    

    dbg_log("[resource]", "CloseHandle: 0x%zX\n", hObject);

    if (!RT_Unlock())
    {
        return false;
    }
    return success;
};

__declspec(noinline)
HANDLE RT_FindFirstFileA(LPCSTR lpFileName, POINTER lpFindFileData)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFindFile;

    bool success = true;
    for (;;)
    {
        hFindFile = tracker->FindFirstFileA(lpFileName, lpFindFileData);
        if (hFindFile == INVALID_HANDLE_VALUE)
        {
            success = false;
            break;
        }
        if (!addHandle(tracker, hFindFile, SRC_FIND_FIRST_FILE_A))
        {
            success = false;
            break;
        }
        break;
    }

    dbg_log("[resource]", "FindFirstFileA: %s\n", lpFileName);

    if (!RT_Unlock())
    {
        if (success)
        {
            tracker->FindClose(hFindFile);
        }
        return INVALID_HANDLE_VALUE;
    }
    if (!success)
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

__declspec(noinline)
HANDLE RT_FindFirstFileW(LPCWSTR lpFileName, POINTER lpFindFileData)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hFindFile;

    bool success = true;
    for (;;)
    {
        hFindFile = tracker->FindFirstFileW(lpFileName, lpFindFileData);
        if (hFindFile == INVALID_HANDLE_VALUE)
        {
            success = false;
            break;
        }
        if (!addHandle(tracker, hFindFile, SRC_FIND_FIRST_FILE_W))
        {
            success = false;
            break;
        }
        break;
    }

    dbg_log("[resource]", "FindFirstFileW: %ls\n", lpFileName);

    if (!RT_Unlock())
    {
        if (success)
        {
            tracker->FindClose(hFindFile);
        }
        return INVALID_HANDLE_VALUE;
    }
    if (!success)
    {
        return INVALID_HANDLE_VALUE;
    }
    return hFindFile;
};

HANDLE RT_FindFirstFileExA(
    LPCSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
)
{

};

HANDLE RT_FindFirstFileExW(
    LPCWSTR lpFileName, UINT fInfoLevelId, LPVOID lpFindFileData,
    UINT fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags
)
{

};

__declspec(noinline)
BOOL RT_FindClose(HANDLE hFindFile)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return false;
    }

    BOOL success;
    for (;;)
    {
        success = tracker->FindClose(hFindFile);
        if (!success)
        {
            break;
        }
        delHandle(tracker, hFindFile, TYPE_FIND_CLOSE);
        break;
    }

    dbg_log("[resource]", "FindClose: 0x%zX\n", hFindFile);

    if (!RT_Unlock())
    {
        return false;
    }
    return success;
};

static bool addHandle(ResourceTracker* tracker, void* hObject, uint16 source)
{
    if (hObject == NULL)
    {
        return false;
    }

    List*  handles = &tracker->Handles;
    handle handle  = {
        .handle = hObject,
        .source = source,
    };
    if (!List_Insert(handles, &handle))
    {
        tracker->CloseHandle(hObject);
        return false;
    }
    return true;
};

static void delHandle(ResourceTracker* tracker, void* hObject, uint16 type)
{
    if (hObject == NULL)
    {
        return;
    }

    List* handles = &tracker->Handles;
    uint  index   = 0;
    for (uint num = 0; num < handles->Len; index++)
    {
        handle* handle = List_Get(handles, index);
        if (handle->handle == NULL && handle->source == 0)
        {
            continue;
        }
        if ((handle->source & type) != type)
        {
            num++;
            continue;
        }
        if (handle->handle != hObject)
        {
            num++;
            continue;
        }
        List_Delete(handles, index);
        return;
    }
};

__declspec(noinline)
int RT_WSAStartup(WORD wVersionRequired, POINTER lpWSAData)
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return WSASYSNOTREADY;
    }

#ifdef _WIN64
    WSAStartup_t WSAStartup = FindAPI(0x21A84954D72D9F93, 0xD549133F33DA137E);
#elif _WIN32
    WSAStartup_t WSAStartup = FindAPI(0x8CD788B9, 0xA349D8A2);
#endif
    if (WSAStartup == NULL)
    {
        return WSASYSNOTREADY;
    }

    int ret = WSAStartup(wVersionRequired, lpWSAData);
    if (ret == 0)
    {
        tracker->Counters[CTR_WSA_STARTUP]++;
    }

    dbg_log("[resource]", "WSAStartup is called\n");

    if (!RT_Unlock())
    {
        return WSASYSNOTREADY;
    }
    return ret;
}

__declspec(noinline)
int RT_WSACleanup()
{
    ResourceTracker* tracker = getTrackerPointer();

    if (!RT_Lock())
    {
        return WSAEINPROGRESS;
    }

#ifdef _WIN64
    WSACleanup_t WSACleanup = FindAPI(0x324EEA09CB7B262C, 0xE64CBAD3BBD4F522);
#elif _WIN32
    WSACleanup_t WSACleanup = FindAPI(0xBD997AF1, 0x88F10695);
#endif
    if (WSACleanup == NULL)
    {
        return WSAEINPROGRESS;
    }

    int ret = WSACleanup();
    if (ret == 0)
    {
        tracker->Counters[CTR_WSA_STARTUP]--;
    }

    dbg_log("[resource]", "WSACleanup is called\n");

    if (!RT_Unlock())
    {
        return WSAEINPROGRESS;
    }
    return ret;
}

__declspec(noinline)
bool RT_Lock()
{
    ResourceTracker* tracker = getTrackerPointer();

    uint32 event = tracker->WaitForSingleObject(tracker->hMutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

__declspec(noinline)
bool RT_Unlock()
{
    ResourceTracker* tracker = getTrackerPointer();

    return tracker->ReleaseMutex(tracker->hMutex);
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

    dbg_log("[resource]", "handles: %zu\n", list->Len);
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
        switch (handle->source & 0xFF00)
        {
        case TYPE_CLOSE_HANDLE:
            if (!tracker->CloseHandle(handle->handle))
            {
                errno = ERR_RESOURCE_CLOSE_HANDLE;
            }
            break;
        case TYPE_FIND_CLOSE:
            if (!tracker->FindClose(handle->handle))
            {
                errno = ERR_RESOURCE_FIND_CLOSE;
            }
            break;
        default:
            errno = ERR_RESOURCE_INVALID_SRC_TYPE;
            break;
        }
        num++;
    }

    // clean handle list
    RandBuf(handles->Data, List_Size(handles));
    if (!List_Free(handles))
    {
        errno = ERR_RESOURCE_FREE_HANDLE_LIST;
    }

    // process init function trackers
#ifdef _WIN64
    WSACleanup_t WSACleanup = FindAPI(0x2D5ED79692C593E4, 0xF65130FCB6DB3FD4);
#elif _WIN32
    WSACleanup_t WSACleanup = FindAPI(0x59F727E0, 0x156A74C5);
#endif
    if (WSACleanup != NULL)
    {
        int64 counter = tracker->Counters[CTR_WSA_STARTUP];
        for (int64 i = 0; i < counter; i++)
        {
            if (WSACleanup() != 0)
            {
                errno = ERR_RESOURCE_WSA_CLEANUP;
            }
        }
    }

    // close mutex
    if (!tracker->CloseHandle(tracker->hMutex))
    {
        errno = ERR_RESOURCE_CLOSE_MUTEX;
    }
    return errno;
}
