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
#include "library.h"

typedef struct {
    HMODULE hModule;
    uint    counter;
} module;

typedef struct {
    // API addresses
    LoadLibraryA_t             LoadLibraryA;
    LoadLibraryW_t             LoadLibraryW;
    LoadLibraryExA_t           LoadLibraryExA;
    LoadLibraryExW_t           LoadLibraryExW;
    FreeLibrary_t              FreeLibrary;
    FreeLibraryAndExitThread_t FreeLibraryAndExitThread;
    ReleaseMutex_t             ReleaseMutex;
    WaitForSingleObject_t      WaitForSingleObject;

    // runtime data
    HANDLE Mutex; // global mutex

    // store all modules info
    List Modules;
    byte ModulesKey[CRYPTO_KEY_SIZE];
    byte ModulesIV [CRYPTO_IV_SIZE];
} LibraryTracker;

// methods for IAT hooks
HMODULE LT_LoadLibraryA(LPCSTR lpLibFileName);
HMODULE LT_LoadLibraryW(LPCWSTR lpLibFileName);
HMODULE LT_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
HMODULE LT_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
BOOL    LT_FreeLibrary(HMODULE hLibModule);
void    LT_FreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode);

// methods for runtime
errno LT_Encrypt();
errno LT_Decrypt();
errno LT_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF11111101
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCD01
#endif
static LibraryTracker* getTrackerPointer();

static bool lt_lock(LibraryTracker* tracker);
static bool lt_unlock(LibraryTracker* tracker);

static bool initTrackerAPI(LibraryTracker* tracker, Context* context);
static bool updateTrackerPointer(LibraryTracker* tracker);
static bool initTrackerEnvironment(LibraryTracker* tracker, Context* context);
static bool addModule(LibraryTracker* tracker, HMODULE hModule);
static bool delModule(LibraryTracker* tracker, HMODULE hModule);
static bool cleanModule(LibraryTracker* tracker, module* module);

static void eraseTrackerMethods();
static void cleanTracker(LibraryTracker* tracker);

LibraryTracker_M* InitLibraryTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 3000 + RandUint(address) % 128;
    uintptr moduleAddr  = address + 3700 + RandUint(address) % 128;
    // initialize tracker
    LibraryTracker* tracker = (LibraryTracker*)trackerAddr;
    mem_clean(tracker, sizeof(LibraryTracker));
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errno = ERR_LIBRARY_INIT_API;
            break;
        }
        if (!updateTrackerPointer(tracker))
        {
            errno = ERR_LIBRARY_UPDATE_PTR;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errno = ERR_LIBRARY_INIT_ENV;
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
    LibraryTracker_M* module = (LibraryTracker_M*)moduleAddr;
    // Windows API hooks
    module->LoadLibraryA             = &LT_LoadLibraryA;
    module->LoadLibraryW             = &LT_LoadLibraryW;
    module->LoadLibraryExA           = &LT_LoadLibraryExA;
    module->LoadLibraryExW           = &LT_LoadLibraryExW;
    module->FreeLibrary              = &LT_FreeLibrary;
    module->FreeLibraryAndExitThread = &LT_FreeLibraryAndExitThread;
    // methods for runtime   
    module->LibEncrypt = &LT_Encrypt;
    module->LibDecrypt = &LT_Decrypt;
    module->LibClean   = &LT_Clean;
    return module;
}

__declspec(noinline)
static bool initTrackerAPI(LibraryTracker* tracker, Context* context)
{
    typedef struct { 
        uint hash; uint key; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xFF631CDB135AB431, 0xF2D25F476CA15E97 }, // LoadLibraryA
        { 0x214DF62A80434DBF, 0xEB0FDC717FC827A5 }, // LoadLibraryW
        { 0x2F6B12D80C0B77BC, 0xDB036D7FA710BE44 }, // LoadLibraryExA
        { 0xC9297DE7F8C97F1C, 0x580EBCC7C3411C35 }, // LoadLibraryExW
        { 0xD0E21A35D744228B, 0x8283AFE6F719D579 }, // FreeLibrary
        { 0x0708BC7E2C7DA370, 0x39B9AC22BC408886 }, // FreeLibraryAndExitThread
    };
#elif _WIN32
    {
        { 0x434519BD, 0x621ABBD9 }, // LoadLibraryA
        { 0xCE3D1172, 0x0FB89CC3 }, // LoadLibraryW
        { 0x46B4638A, 0x213466F9 }, // LoadLibraryExA
        { 0xDBB0F0FE, 0x516334AA }, // LoadLibraryExW
        { 0xE44CF885, 0xF6D45D9F }, // FreeLibrary
        { 0x7730C1E2, 0xF5551C66 }, // FreeLibraryAndExitThread
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
    tracker->LoadLibraryA             = list[0].proc;
    tracker->LoadLibraryW             = list[1].proc;
    tracker->LoadLibraryExA           = list[2].proc;
    tracker->LoadLibraryExW           = list[3].proc;
    tracker->FreeLibrary              = list[4].proc;
    tracker->FreeLibraryAndExitThread = list[5].proc;

    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    return true;
}

__declspec(noinline)
static bool updateTrackerPointer(LibraryTracker* tracker)
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
static bool initTrackerEnvironment(LibraryTracker* tracker, Context* context)
{
    // copy runtime context data
    tracker->Mutex = context->Mutex;
    // initialize module list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Modules, &ctx, sizeof(module));
    // set crypto context data
    RandBuf(&tracker->ModulesKey[0], CRYPTO_KEY_SIZE);
    RandBuf(&tracker->ModulesIV[0], CRYPTO_IV_SIZE);
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
static void cleanTracker(LibraryTracker* tracker)
{
    List_Free(&tracker->Modules);
}

// updateTrackerPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateTrackerPointer will fail.
#pragma optimize("", off)
static LibraryTracker* getTrackerPointer()
{
    uint pointer = TRACKER_POINTER;
    return (LibraryTracker*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool lt_lock(LibraryTracker* tracker)
{
    uint32 event = tracker->WaitForSingleObject(tracker->Mutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

__declspec(noinline)
static bool lt_unlock(LibraryTracker* tracker)
{
    return tracker->ReleaseMutex(tracker->Mutex);
}

__declspec(noinline)
HMODULE LT_LoadLibraryA(LPCSTR lpLibFileName)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!lt_lock(tracker))
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = true;
    for (;;)
    {
        hModule = tracker->LoadLibraryA(lpLibFileName);
        if (hModule == NULL)
        {
            success = false;
            break;
        }
        if (!addModule(tracker, hModule))
        {
            success = false;
            break;
        }
        printf_s("LoadLibraryA: %llu\n", (uint64)hModule);
        break;
    }

    if (!lt_unlock(tracker))
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
HMODULE LT_LoadLibraryW(LPCWSTR lpLibFileName)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!lt_lock(tracker))
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = true;
    for (;;)
    {
        hModule = tracker->LoadLibraryW(lpLibFileName);
        if (hModule == NULL)
        {
            success = false;
            break;
        }
        if (!addModule(tracker, hModule))
        {
            success = false;
            break;
        }
        printf_s("LoadLibraryW: %llu\n", (uint64)hModule);
        break;
    }

    if (!lt_unlock(tracker))
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
HMODULE LT_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!lt_lock(tracker))
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = true;
    for (;;)
    {
        hModule = tracker->LoadLibraryExA(lpLibFileName, hFile, dwFlags);
        if (hModule == NULL)
        {
            success = false;
            break;
        }
        if (!addModule(tracker, hModule))
        {
            success = false;
            break;
        }
        printf_s("LoadLibraryExA: %llu\n", (uint64)hModule);
        break;
    }

    if (!lt_unlock(tracker))
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
HMODULE LT_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!lt_lock(tracker))
    {
        return NULL;
    }

    HMODULE hModule;

    bool success = true;
    for (;;)
    {
        hModule = tracker->LoadLibraryExW(lpLibFileName, hFile, dwFlags);
        if (hModule == NULL)
        {
            success = false;
            break;
        }
        if (!addModule(tracker, hModule))
        {
            success = false;
            break;
        }
        printf_s("LoadLibraryExW: %llu\n", (uint64)hModule);
        break;
    }

    if (!lt_unlock(tracker))
    {
        if (success)
        {
            tracker->FreeLibrary(hModule);
        }
        return NULL;
    }
    if (!success)
    {
        return NULL;
    }
    return hModule;
}

__declspec(noinline)
BOOL LT_FreeLibrary(HMODULE hLibModule)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!lt_lock(tracker))
    {
        return false;
    }

    bool success = true;
    for (;;)
    {
        if (!tracker->FreeLibrary(hLibModule))
        {
            success = false;
            break;
        }
        if (!delModule(tracker, hLibModule))
        {
            success = false;
            break;
        }
        printf_s("FreeLibrary: %llu\n", (uint64)hLibModule);
        break;
    }

    if (!lt_unlock(tracker))
    {
        return false;
    }
    return success;
}

__declspec(noinline)
void LT_FreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode)
{
    LibraryTracker* tracker = getTrackerPointer();

    if (!lt_lock(tracker))
    {
        return;
    }

    delModule(tracker, hLibModule);
    printf_s("FreeLibraryAndExitThread: %llu\n", (uint64)hLibModule);

    if (!lt_unlock(tracker))
    {
        return;
    }

    tracker->FreeLibraryAndExitThread(hLibModule, dwExitCode);
}

static bool addModule(LibraryTracker* tracker, HMODULE hModule)
{
    if (hModule == NULL)
    {
        return false;
    }
    // check this module is already exists
    List*  modules = &tracker->Modules;
    module mod = {
        .hModule = hModule,
    };
    uint index;
    if (List_Find(modules, &mod, sizeof(mod.hModule), &index))
    {
        module* module = List_Get(modules, index);
        module->counter++;
        return true;
    }
    // if not exist, add new item
    mod.counter = 1;
    if (!List_Insert(modules, &mod))
    {
        tracker->FreeLibrary(hModule);
        return false;
    }
    return true;
}

static bool delModule(LibraryTracker* tracker, HMODULE hModule)
{
    if (hModule == NULL)
    {
        return false;
    }
    // search module and decrease counter
    List*  modules = &tracker->Modules;
    module mod  = {
        .hModule = hModule,
    };
    uint index;
    if (!List_Find(modules, &mod, sizeof(mod.hModule), &index))
    {
        return false;
    }
    module* module = List_Get(modules, index);
    module->counter--;
    // if counter is zero, delete it in module list
    if (module->counter == 0)
    {
        if (!List_Delete(modules, index))
        {
            return false;
        }
    }
    return true;
}

__declspec(noinline)
errno LT_Encrypt()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* list = &tracker->Modules;
    byte* key  = &tracker->ModulesKey[0];
    byte* iv   = &tracker->ModulesIV[0];
    RandBuf(key, CRYPTO_KEY_SIZE);
    RandBuf(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno LT_Decrypt()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* list = &tracker->Modules;
    byte* key  = &tracker->ModulesKey[0];
    byte* iv   = &tracker->ModulesIV[0];
    DecryptBuf(list->Data, List_Size(list), key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno LT_Clean()
{
    LibraryTracker* tracker = getTrackerPointer();

    List* modules = &tracker->Modules;
    errno errno   = NO_ERROR;
    
    // clean modules
    uint index = 0;
    for (uint num = 0; num < modules->Len; index++)
    {
        module* module = List_Get(modules, index);
        if (module->hModule == NULL)
        {
            continue;
        }
        if (!cleanModule(tracker, module))
        {
            errno = ERR_LIBRARY_CLEAN_MODULE;
        }
        num++;
    }

    // clean module list
    RandBuf(modules->Data, List_Size(modules));
    if (!List_Free(modules))
    {
        errno = ERR_LIBRARY_FREE_LIST; 
    }
    return errno;
}

static bool cleanModule(LibraryTracker* tracker, module* module)
{
    uint num = module->counter;
    for (uint i = 0; i < num; i++)
    {
        if (!tracker->FreeLibrary(module->hModule))
        {
            return false;
        }
    }
    return true;
}
