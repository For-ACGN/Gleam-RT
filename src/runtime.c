#include <stdio.h>

#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "random.h"
#include "crypto.h"
#include "win_api.h"
#include "context.h"
#include "errno.h"
#include "library.h"
#include "memory.h"
#include "thread.h"
#include "resource.h"
#include "runtime.h"
#include "shield.h"
#include "epilogue.h"

#define MAIN_MEM_PAGE_SIZE 8192

#define EVENT_TYPE_SLEEP 0x01
#define EVENT_TYPE_STOP  0x02

// for IAT hooks
typedef struct {
    uintptr Func;
    uintptr Hook;
} Hook;

typedef struct {
    Runtime_Opts* Options;

    // store options
    uintptr InstAddress;
    bool    NotEraseInst;

    // store all structures
    uintptr MainMemPage;

    // API addresses
    GetSystemInfo_t         GetSystemInfo;
    VirtualAlloc_t          VirtualAlloc;
    VirtualFree_t           VirtualFree;
    VirtualProtect_t        VirtualProtect;
    FlushInstructionCache_t FlushInstructionCache;
    CreateMutexA_t          CreateMutexA;
    ReleaseMutex_t          ReleaseMutex;
    CreateEventA_t          CreateEventA;
    SetEvent_t              SetEvent;
    ResetEvent_t            ResetEvent;
    WaitForSingleObject_t   WaitForSingleObject;
    DuplicateHandle_t       DuplicateHandle;
    CloseHandle_t           CloseHandle;
    GetProcAddress_t        GetProcAddress;

    // IAT hooks about GetProcAddress
    Hook IAT_Hooks[23];

    // runtime data
    uint32 PageSize; // for memory management
    HANDLE hProcess; // for simulate kernel32.Sleep
    HANDLE Mutex;    // global mutex

    // sleep event trigger
    HANDLE hMutexSleep; // sleep method mutex
    HANDLE hEventCome;  // trigger events
    HANDLE hEventDone;  // finish event
    uint32 EventType;   // store event type
    uint32 SleepTime;   // store sleep argument
    errno  ReturnErrno; // store error number
    HANDLE hMutexEvent; // event data mutex
    HANDLE hThread;     // trigger thread

    // submodules
    LibraryTracker_M*  LibraryTracker;
    MemoryTracker_M*   MemoryTracker;
    ThreadTracker_M*   ThreadTracker;
    ResourceTracker_M* ResourceTracker;
} Runtime;

// export methods about Runtime
uintptr RT_FindAPI(uint hash, uint key);
void    RT_Sleep(uint32 milliseconds);

uintptr RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
uintptr RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool hook);
uintptr RT_GetProcAddressByHash(uint hash, uint key, bool hook);
uintptr RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName);

errno RT_SleepHR(uint32 milliseconds);
errno RT_Hide();
errno RT_Recover();
errno RT_Exit();

// internal methods for Runtime submodules
void* RT_malloc(uint size);
void* RT_realloc(void* address, uint size);
bool  RT_free(void* address);

// hard encoded address in getRuntimePointer for replacement
#ifdef _WIN64
    #define RUNTIME_POINTER 0x7FABCDEF111111FF
#elif _WIN32
    #define RUNTIME_POINTER 0x7FABCDFF
#endif
static Runtime* getRuntimePointer();

static bool rt_lock(Runtime* runtime);
static bool rt_unlock(Runtime* runtime);

static uintptr allocateRuntimeMemory();
static bool  initRuntimeAPI(Runtime* runtime);
static bool  adjustPageProtect(Runtime* runtime);
static bool  updateRuntimePointer(Runtime* runtime);
static errno initRuntimeEnvironment(Runtime* runtime);
static errno initLibraryTracker(Runtime* runtime, Context* context);
static errno initMemoryTracker(Runtime* runtime, Context* context);
static errno initThreadTracker(Runtime* runtime, Context* context);
static errno initResourceTracker(Runtime* runtime, Context* context);
static bool  initIATHooks(Runtime* runtime);
static bool  flushInstructionCache(Runtime* runtime);

static uintptr getRuntimeMethods(byte* module, LPCSTR lpProcName);
static uintptr getResTrackerHook(Runtime* runtime, uintptr proc);
static uintptr replaceToHook(Runtime* runtime, uintptr proc);

static void  trigger();
static errno processEvent(Runtime* runtime, bool* exit);
static errno sleepHR(Runtime* runtime, uint32 milliseconds);
static errno hide(Runtime* runtime);
static errno sleep(Runtime* runtime, uint32 milliseconds);
static errno recover(Runtime* runtime);

static void eraseRuntimeMethods();
static void cleanRuntime(Runtime* runtime);
static void eraseMemory(uintptr address, int64 size);
static void rt_epilogue();

__declspec(noinline)
Runtime_M* InitRuntime(Runtime_Opts* opts)
{
    uintptr address = allocateRuntimeMemory();
    if (address == NULL)
    {
        return NULL;
    }
    printf("main page: 0x%llX\n", address);
    // set structure address
    uintptr runtimeAddr = address + 1000 + RandUint(address) % 128;
    uintptr moduleAddr  = address + 2500 + RandUint(address) % 128;
    // initialize structure
    Runtime* runtime = (Runtime*)runtimeAddr;
    mem_clean(runtime, sizeof(Runtime));
    runtime->Options = opts;
    runtime->InstAddress  = opts->InstAddress;
    runtime->NotEraseInst = opts->NotEraseInst;
    runtime->MainMemPage  = address;
    // initialize runtime
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initRuntimeAPI(runtime))
        {
            errno = ERR_RUNTIME_INIT_API;
            break;
        }
        if (!adjustPageProtect(runtime))
        {
            errno = ERR_RUNTIME_ADJUST_PROTECT;
            break;
        }
        if (!updateRuntimePointer(runtime))
        {
            errno = ERR_RUNTIME_UPDATE_PTR;
            break;
        }
        errno = initRuntimeEnvironment(runtime);
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!initIATHooks(runtime))
        {
            errno = ERR_RUNTIME_INIT_IAT_HOOKS;
            break;
        }
        break;
    }
    if (errno == NO_ERROR || errno > ERR_RUNTIME_ADJUST_PROTECT)
    {
        eraseRuntimeMethods();
    }
    if (errno == NO_ERROR && !flushInstructionCache(runtime))
    {
        errno = ERR_RUNTIME_FLUSH_INST;
    }
    // start sleep event trigger
    if (errno == NO_ERROR)
    {
        runtime->hThread = runtime->ThreadTracker->ThdNew(&trigger, NULL, false);
        if (runtime->hThread == NULL)
        {
            errno = ERR_RUNTIME_START_TRIGGER;
        }
    }
    if (errno != NO_ERROR)
    {
        cleanRuntime(runtime);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for Runtime
    Runtime_M* module = (Runtime_M*)moduleAddr;
    // for develop shellcode
    module->MemAlloc   = runtime->MemoryTracker->MemAlloc;
    module->MemRealloc = runtime->MemoryTracker->MemRealloc;
    module->MemFree    = runtime->MemoryTracker->MemFree;
    module->NewThread  = runtime->ThreadTracker->ThdNew;
    module->ExitThread = runtime->ThreadTracker->ThdExit;
    module->FindAPI    = &RT_FindAPI;
    module->Sleep      = &RT_Sleep;
    // for IAT hooks
    module->GetProcAddress         = &RT_GetProcAddress;
    module->GetProcAddressByName   = &RT_GetProcAddressByName;
    module->GetProcAddressByHash   = &RT_GetProcAddressByHash;
    module->GetProcAddressOriginal = &RT_GetProcAddressOriginal;
    // runtime core methods
    module->Hide    = &RT_Hide;
    module->Recover = &RT_Recover;
    module->SleepHR = &RT_SleepHR;
    module->Exit    = &RT_Exit;
    return module;
}

// allocate memory for store structures.
static uintptr allocateRuntimeMemory()
{
#ifdef _WIN64
    uint hash = 0xB6A1D0D4A275D4B6;
    uint key  = 0x64CB4D66EC0BEFD9;
#elif _WIN32
    uint hash = 0xC3DE112E;
    uint key  = 0x8D9EA74F;
#endif
    VirtualAlloc_t virtualAlloc = (VirtualAlloc_t)FindAPI(hash, key);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }
    uintptr addr = virtualAlloc(0, MAIN_MEM_PAGE_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    RandBuf((byte*)addr, MAIN_MEM_PAGE_SIZE);
    return addr;
}

static bool initRuntimeAPI(Runtime* runtime)
{
    typedef struct { 
        uint hash; uint key; uintptr address;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x2A9C7D79595F39B2, 0x11FB7144E3CF94BD }, // GetSystemInfo
        { 0x6AC498DF641A4FCB, 0xFF3BB21B9BA46CEA }, // VirtualAlloc
        { 0xAC150252A6CA3960, 0x12EFAEA421D60C3E }, // VirtualFree
        { 0xEA5B0C76C7946815, 0x8846C203C35DE586 }, // VirtualProtect
        { 0x8172B49F66E495BA, 0x8F0D0796223B56C2 }, // FlushInstructionCache
        { 0x31FE697F93D7510C, 0x77C8F05FE04ED22D }, // CreateMutexA
        { 0xEEFDEA7C0785B561, 0xA7B72CC8CD55C1D4 }, // ReleaseMutex
        { 0xDDB64F7D0952649B, 0x7F49C6179CD1D05C }, // CreateEventA
        { 0x4A7C9AD08B398C90, 0x4DA8D0C65ECE8AB5 }, // SetEvent
        { 0xDCC7DDE90F8EF5E5, 0x779EBCBF154A323E }, // ResetEvent
        { 0xA524CD56CF8DFF7F, 0x5519595458CD47C8 }, // WaitForSingleObject
        { 0xF7A5A49D19409FFC, 0x6F23FAA4C20FF4D3 }, // DuplicateHandle
        { 0xA25F7449D6939A01, 0x85D37F1D89B30D2E }, // CloseHandle
        { 0x7C1C9D36D30E0B75, 0x1ACD25CE8A87875A }, // GetProcAddress
    };
#elif _WIN32
    {
        { 0xD7792A53, 0x6DDE32BA }, // GetSystemInfo
        { 0xB47741D5, 0x8034C451 }, // VirtualAlloc
        { 0xF76A2ADE, 0x4D8938BD }, // VirtualFree
        { 0xB2AC456D, 0x2A690F63 }, // VirtualProtect
        { 0x87A2CEE8, 0x42A3C1AF }, // FlushInstructionCache
        { 0x8F5BAED2, 0x43487DC7 }, // CreateMutexA
        { 0xFA42E55C, 0xEA9F1081 }, // ReleaseMutex
        { 0x013C9D2B, 0x5A4D045A }, // CreateEventA
        { 0x1F65B288, 0x8502DDE2 }, // SetEvent
        { 0xCB15B6B4, 0x6D95B453 }, // ResetEvent
        { 0xC21AB03D, 0xED3AAF22 }, // WaitForSingleObject
        { 0x0E7ED8B9, 0x025067E9 }, // DuplicateHandle
        { 0x60E108B2, 0x3C2DFF52 }, // CloseHandle
        { 0x1CE92A4E, 0xBFF4B241 }, // GetProcAddress
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
    runtime->GetSystemInfo         = (GetSystemInfo_t        )(list[0x00].address);
    runtime->VirtualAlloc          = (VirtualAlloc_t         )(list[0x01].address);
    runtime->VirtualFree           = (VirtualFree_t          )(list[0x02].address);
    runtime->VirtualProtect        = (VirtualProtect_t       )(list[0x03].address);
    runtime->FlushInstructionCache = (FlushInstructionCache_t)(list[0x04].address);
    runtime->CreateMutexA          = (CreateMutexA_t         )(list[0x05].address);
    runtime->ReleaseMutex          = (ReleaseMutex_t         )(list[0x06].address);
    runtime->CreateEventA          = (CreateEventA_t         )(list[0x07].address);
    runtime->SetEvent              = (SetEvent_t             )(list[0x08].address);
    runtime->ResetEvent            = (ResetEvent_t           )(list[0x09].address);
    runtime->WaitForSingleObject   = (WaitForSingleObject_t  )(list[0x0A].address);
    runtime->DuplicateHandle       = (DuplicateHandle_t      )(list[0x0B].address);
    runtime->CloseHandle           = (CloseHandle_t          )(list[0x0C].address);
    runtime->GetProcAddress        = (GetProcAddress_t       )(list[0x0D].address);
    return true;
}

// change memory protect for dynamic update pointer that hard encode.
static bool adjustPageProtect(Runtime* runtime)
{
    if (runtime->Options->NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    int64   size  = end - begin;
    uint32  old;
    return runtime->VirtualProtect(begin, size, PAGE_EXECUTE_READWRITE, &old);
}

static bool updateRuntimePointer(Runtime* runtime)
{
    bool success = false;
    uintptr target = (uintptr)(&getRuntimePointer);
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != RUNTIME_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)runtime;
        success = true;
        break;
    }
    return success;
}

static errno initRuntimeEnvironment(Runtime* runtime)
{
    // get memory page size
    SYSTEM_INFO sysInfo;
    runtime->GetSystemInfo(&sysInfo);
    runtime->PageSize = sysInfo.PageSize;
    // duplicate current process handle
    HANDLE dupHandle;
    if (!runtime->DuplicateHandle(
        CURRENT_PROCESS, CURRENT_PROCESS, CURRENT_PROCESS, &dupHandle,
        0, false, DUPLICATE_SAME_ACCESS
    )){
        return ERR_RUNTIME_DUP_PROCESS_HANDLE;
    }
    runtime->hProcess = dupHandle;
    // create global mutex
    HANDLE hMutex = runtime->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return ERR_RUNTIME_CREATE_GLOBAL_MUTEX;
    }
    runtime->Mutex = hMutex;
    // create sleep method mutex
    HANDLE hMutexSleep = runtime->CreateMutexA(NULL, false, NULL);
    if (hMutexSleep == NULL)
    {
        return ERR_RUNTIME_CREATE_SLEEP_MUTEX;
    }
    runtime->hMutexSleep = hMutexSleep;
    // create come and done events
    HANDLE hEventCome = runtime->CreateEventA(NULL, true, false, NULL);
    if (hEventCome == NULL)
    {
        return ERR_RUNTIME_CREATE_EVENT_COME;
    }
    runtime->hEventCome = hEventCome;
    HANDLE hEventDone = runtime->CreateEventA(NULL, true, false, NULL);
    if (hEventDone == NULL)
    {
        return ERR_RUNTIME_CREATE_EVENT_DONE;
    }
    runtime->hEventDone = hEventDone;
    // create event type mutex
    HANDLE hMutexEvent = runtime->CreateMutexA(NULL, false, NULL);
    if (hMutexEvent == NULL)
    {
        return ERR_RUNTIME_CREATE_EVENT_MUTEX;
    }
    runtime->hMutexEvent = hMutexEvent;
    // create context data for initialize other modules
    Context context = {
        .MainMemPage = runtime->MainMemPage,

        .TrackCurrentThread = runtime->Options->TrackCurrentThread,

        .VirtualAlloc          = runtime->VirtualAlloc,
        .VirtualFree           = runtime->VirtualFree,
        .VirtualProtect        = runtime->VirtualProtect,
        .ReleaseMutex          = runtime->ReleaseMutex,
        .WaitForSingleObject   = runtime->WaitForSingleObject,
        .FlushInstructionCache = runtime->FlushInstructionCache,
        .DuplicateHandle       = runtime->DuplicateHandle,
        .CloseHandle           = runtime->CloseHandle,

        .malloc  = &RT_malloc,
        .realloc = &RT_realloc,
        .free    = &RT_free,

        .PageSize = runtime->PageSize,
        .Mutex    = runtime->Mutex,
    };
    errno errno;
    errno = initLibraryTracker(runtime, &context);
    if (errno != NO_ERROR)
    {
        return errno;
    }
    errno = initMemoryTracker(runtime, &context);
    if (errno != NO_ERROR)
    {
        return errno;
    }
    errno = initThreadTracker(runtime, &context);
    if (errno != NO_ERROR)
    {
        return errno;
    }
    errno = initResourceTracker(runtime, &context);
    if (errno != NO_ERROR)
    {
        return errno;
    }
    // clean useless API functions in runtime structure
    RandBuf((byte*)(&runtime->GetSystemInfo), sizeof(uintptr));
    RandBuf((byte*)(&runtime->CreateMutexA),  sizeof(uintptr));
    RandBuf((byte*)(&runtime->CreateEventA),  sizeof(uintptr));
    return NO_ERROR;
}

static errno initLibraryTracker(Runtime* runtime, Context* context)
{
    LibraryTracker_M* tracker = InitLibraryTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->LibraryTracker = tracker;
    return NO_ERROR;
}

static errno initMemoryTracker(Runtime* runtime, Context* context)
{
    MemoryTracker_M* tracker = InitMemoryTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->MemoryTracker = tracker;
    return NO_ERROR;
}

static errno initThreadTracker(Runtime* runtime, Context* context)
{
    ThreadTracker_M* tracker = InitThreadTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->ThreadTracker = tracker;
    return NO_ERROR;
}

static errno initResourceTracker(Runtime* runtime, Context* context)
{
    ResourceTracker_M* tracker = InitResourceTracker(context);
    if (tracker == NULL)
    {
        return GetLastErrno();
    }
    runtime->ResourceTracker = tracker;
    return NO_ERROR;
}

static bool initIATHooks(Runtime* runtime)
{
    typedef struct {
        uint hash; uint key; void* hook;
    } item;
    item items[] =
#ifdef _WIN64
    {
        { 0xCAA4843E1FC90287, 0x2F19F60181B5BFE3, &RT_GetProcAddress },
        { 0xCED5CC955152CD43, 0xAA22C83C068CB037, &RT_SleepHR },
        { 0xD823D640CA9D87C3, 0x15821AE3463EFBE8, runtime->LibraryTracker->LoadLibraryA },
        { 0xDE75B0371B7500C0, 0x2A1CF678FC737D0F, runtime->LibraryTracker->LoadLibraryW },
        { 0x448751B1385751E8, 0x3AE522A4E9435111, runtime->LibraryTracker->LoadLibraryExA },
        { 0x7539E619D8B4166E, 0xE52EE8B2C2D15D9B, runtime->LibraryTracker->LoadLibraryExW },
        { 0x80B0A97C97E9FE79, 0x675B0BA55C1758F9, runtime->LibraryTracker->FreeLibrary },
        { 0x66F288FB8CF6CADD, 0xC48D2119FF3ADC6A, runtime->LibraryTracker->FreeLibraryAndExitThread },
        { 0x18A3895F35B741C8, 0x96C9890F48D55E7E, runtime->MemoryTracker->VirtualAlloc },
        { 0xDB54AA6683574A8B, 0x3137DE2D71D3FF3E, runtime->MemoryTracker->VirtualFree },
        { 0xF5469C21B43D23E5, 0xF80028997F625A05, runtime->MemoryTracker->VirtualProtect },
        { 0xE9ECDC63F6D3DC53, 0x815C2FDFE640307E, runtime->MemoryTracker->VirtualQuery },
        { 0x84AC57FA4D95DE2E, 0x5FF86AC14A334443, runtime->ThreadTracker->CreateThread },
        { 0xA6E10FF27A1085A8, 0x24815A68A9695B16, runtime->ThreadTracker->ExitThread },
        { 0x82ACE4B5AAEB22F1, 0xF3132FCE3AC7AD87, runtime->ThreadTracker->SuspendThread },
        { 0x226860209E13A99A, 0xE1BD9D8C64FAF97D, runtime->ThreadTracker->ResumeThread },
        { 0x374E149C710B1006, 0xE5D0E3FA417FA6CF, runtime->ThreadTracker->GetThreadContext },
        { 0xCFE3FFD5F0023AE3, 0x9044E42F1C020CF5, runtime->ThreadTracker->SetThreadContext },
        { 0xF0587A11F433BC0C, 0x9AB5CF006BC5744A, runtime->ThreadTracker->SwitchToThread },
        { 0x248E1CDD11AB444F, 0x195932EA70030929, runtime->ThreadTracker->TerminateThread },
    };
#elif _WIN32
    {
        { 0x5E5065D4, 0x63CDAD01, &RT_GetProcAddress },
        { 0x705D4FAD, 0x94CF33BF, &RT_SleepHR },
        { 0x0149E478, 0x86A603D3, runtime->LibraryTracker->LoadLibraryA },
        { 0x90E21596, 0xEBEA7D19, runtime->LibraryTracker->LoadLibraryW },
        { 0xD6C482CE, 0xC6063014, runtime->LibraryTracker->LoadLibraryExA },
        { 0x158D5700, 0x24540418, runtime->LibraryTracker->LoadLibraryExW },
        { 0x5CDBC79F, 0xA1B99CF2, runtime->LibraryTracker->FreeLibrary },
        { 0x929869F4, 0x7D668185, runtime->LibraryTracker->FreeLibraryAndExitThread },
        { 0xD5B65767, 0xF3A27766, runtime->MemoryTracker->VirtualAlloc },
        { 0x4F0FC063, 0x182F3CC6, runtime->MemoryTracker->VirtualFree },
        { 0xEBD60441, 0x280A4A9F, runtime->MemoryTracker->VirtualProtect },
        { 0xD17B0461, 0xFB4E5DB5, runtime->MemoryTracker->VirtualQuery },
        { 0x20744CA1, 0x4FA1647D, runtime->ThreadTracker->CreateThread },
        { 0xED42C0F0, 0xC59EBA39, runtime->ThreadTracker->ExitThread },
        { 0x133B00D5, 0x48E02627, runtime->ThreadTracker->SuspendThread },
        { 0xA02B4251, 0x5287173F, runtime->ThreadTracker->ResumeThread },
        { 0xCF0EC7B7, 0xBAC33715, runtime->ThreadTracker->GetThreadContext },
        { 0xC59EF832, 0xEF75D2EA, runtime->ThreadTracker->SetThreadContext },
        { 0xA031E829, 0xDD1BB334, runtime->ThreadTracker->SwitchToThread },
        { 0x6EF0E2AA, 0xE014E29F, runtime->ThreadTracker->TerminateThread },
    };
#endif
    uintptr func;
    for (int i = 0; i < arrlen(items); i++)
    {
        func = FindAPI(items[i].hash, items[i].key);
        if (func == NULL)
        {
            return false;
        }
        runtime->IAT_Hooks[i].Func = func;
        runtime->IAT_Hooks[i].Hook = (uintptr)items[i].hook;
    }
    return true;
}

__declspec(noinline)
static void eraseRuntimeMethods()
{
    uintptr begin = (uintptr)(&allocateRuntimeMemory);
    uintptr end   = (uintptr)(&eraseRuntimeMethods);
    int64   size  = end - begin;
    RandBuf((byte*)begin, size);
}

__declspec(noinline)
static bool flushInstructionCache(Runtime* runtime)
{
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    int64   size  = end - begin;
    if (!runtime->FlushInstructionCache(CURRENT_PROCESS, begin, size))
    {
        return false;
    }
    // clean useless API functions in runtime structure
    RandBuf((byte*)(&runtime->VirtualProtect), sizeof(uintptr));
    return true;
}

static void cleanRuntime(Runtime* runtime)
{
    // must copy api address before call RandBuf
    CloseHandle_t closeHandle = runtime->CloseHandle;
    VirtualFree_t virtualFree = runtime->VirtualFree;
    // close handles
    if (closeHandle != NULL)
    {
        if (runtime->hProcess != NULL)
        {
            closeHandle(runtime->hProcess);
        }
        if (runtime->Mutex != NULL)
        {
            closeHandle(runtime->Mutex);
        }
        if (runtime->hEventCome != NULL)
        {
            closeHandle(runtime->hEventCome);
        }
        if (runtime->hEventDone != NULL)
        {
            closeHandle(runtime->hEventDone);
        }
        if (runtime->hMutexEvent != NULL)
        {
            closeHandle(runtime->hMutexEvent);
        }
        if (runtime->hThread != NULL)
        {
            closeHandle(runtime->hThread);
        }
    }
    // release main memory page
    RandBuf((byte*)runtime->MainMemPage, MAIN_MEM_PAGE_SIZE);
    if (virtualFree != NULL)
    {
        virtualFree(runtime->MainMemPage, 0, MEM_RELEASE);
    }
}

// updateRuntimePointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateRuntimePointer will fail.
#pragma optimize("", off)
static Runtime* getRuntimePointer()
{
    uint pointer = RUNTIME_POINTER;
    return (Runtime*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
static bool rt_lock(Runtime* runtime)
{
    uint32 event = runtime->WaitForSingleObject(runtime->Mutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

__declspec(noinline)
static bool rt_unlock(Runtime* runtime)
{
    return runtime->ReleaseMutex(runtime->Mutex);
}

__declspec(noinline)
void* RT_malloc(uint size)
{
    Runtime* runtime = getRuntimePointer();

    // ensure the size is a multiple of memory page size.
    // it also for prevent track the special page size.
    uint pageSize = ((size / runtime->PageSize) + 1) * runtime->PageSize;
    uintptr addr = runtime->VirtualAlloc(0, pageSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }

    // printf_s("rt_malloc: 0x%llX, %llu\n", addr, size);

    // store the size at the head of the memory page
    // ensure the memory address is 16 bytes aligned
    byte* address = (byte*)addr;
    RandBuf(address, 16);
    mem_copy(address, &size, sizeof(uint));
    return (void*)(addr+16);
}

__declspec(noinline)
void* RT_realloc(void* address, uint size)
{
    if (address == NULL)
    {
        return RT_malloc(size);
    }
    // allocate new memory
    void* newAddr = RT_malloc(size);
    if (newAddr == NULL)
    {
        return NULL;
    }
    // copy data to new memory
    uint oldSize = *(uint*)((uintptr)(address)-16);
    mem_copy(newAddr, address, oldSize);
    // free old memory
    if (!RT_free(address))
    {
        return NULL;
    }
    return newAddr;
}

__declspec(noinline)
bool RT_free(void* address)
{
    Runtime* runtime = getRuntimePointer();

    if (address == NULL)
    {
        return true;
    }

    // printf_s("rt_free: 0x%llX\n", (uintptr)address);

    // clean the buffer data before call VirtualFree.
    uintptr addr = (uintptr)(address)-16;
    uint    size = *(uint*)addr;
    mem_clean((byte*)addr, size);
    return runtime->VirtualFree(addr, 0, MEM_RELEASE);
}

__declspec(noinline)
uintptr RT_FindAPI(uint hash, uint key)
{
    return RT_GetProcAddressByHash(hash, key, true);
}

__declspec(noinline)
void RT_Sleep(uint32 milliseconds)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return;
    }

    // copy resource before unlock
    WaitForSingleObject_t wait = runtime->WaitForSingleObject;
    HANDLE hProcess = runtime->hProcess;

    if (!rt_unlock(runtime))
    {
        return;
    }

    wait(hProcess, milliseconds);
}

__declspec(noinline)
uintptr RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    return RT_GetProcAddressByName(hModule, lpProcName, true);
}

__declspec(noinline)
uintptr RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool hook)
{
    // get module file name
    byte module[MAX_PATH];
    mem_clean(&module[0], sizeof(module));
    if (GetModuleFileName(hModule, &module[0], sizeof(module)) == 0)
    {
        return NULL;
    }
    // check is internal methods
    uintptr method = getRuntimeMethods(&module[0], lpProcName);
    if (method != NULL)
    {
        return method;
    }
    // generate key for calculate Windows API hash
    uint key  = RandUint((uint64)(hModule + lpProcName));
    uint hash = HashAPI_W(&module[0], lpProcName, key);
    return RT_GetProcAddressByHash(hash, key, hook);
}

__declspec(noinline)
uintptr RT_GetProcAddressByHash(uint hash, uint key, bool hook)
{
    Runtime* runtime = getRuntimePointer();

    uintptr proc = FindAPI(hash, key);
    if (proc == NULL)
    {
        return NULL;
    }
    if (!hook)
    {
        return proc;
    }
    uintptr rth = getResTrackerHook(runtime, proc);
    if (rth != proc)
    {
        return rth;
    }
    return replaceToHook(runtime, proc);
}

// disable optimize for use call NOT jmp to runtime->GetProcAddress.
#pragma optimize("", off)
__declspec(noinline)
uintptr RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer();

    return runtime->GetProcAddress(hModule, lpProcName);
}
#pragma optimize("", on)

static uintptr getRuntimeMethods(byte* module, LPCSTR lpProcName)
{
    typedef struct {
        uint hash; uint key; void* method;
    } method;
    method methods[] =
#ifdef _WIN64
    {
        { 0xA23FAC0E6398838A, 0xE4990D7D4933EE6A, &RT_GetProcAddressByName },
        { 0xABD1E8F0D28E9F46, 0xAF34F5979D300C70, &RT_GetProcAddressByHash },
        { 0xC9C5D350BB118FAE, 0x061A602F681F2636, &RT_GetProcAddressOriginal },
    };
#elif _WIN32
    {
        { 0xCF983018, 0x3ECBF2DF, &RT_GetProcAddressByName },
        { 0x40D5BD08, 0x302D5D2B, &RT_GetProcAddressByHash },
        { 0x45556AA5, 0xB3BEF31D, &RT_GetProcAddressOriginal },
    };
#endif
    for (int i = 0; i < arrlen(methods); i++)
    {
        uint hash = HashAPI_W(module, lpProcName, methods[i].key);
        if (hash != methods[i].hash)
        {
            continue;
        }
        return (uintptr)(methods[i].method);
    }
    return NULL;
}

static uintptr getResTrackerHook(Runtime* runtime, uintptr proc)
{
    typedef struct {
        uint hash; uint key; void* method;
    } hook;
    hook hooks[] =
#ifdef _WIN64
    {
        { 0x7749934E33C18703, 0xCFB41E32B03DC637, runtime->ResourceTracker->WSAStartup },
        { 0x46C76E87C13DF670, 0x37B6B54E4B2FBECC, runtime->ResourceTracker->WSACleanup },
    };
#elif _WIN32
    {
        { 0xE487BC0B, 0x283C1684, runtime->ResourceTracker->WSAStartup },
        { 0x175B553E, 0x541A996E, runtime->ResourceTracker->WSACleanup },
    };
#endif
    for (int i = 0; i < arrlen(hooks); i++)
    {
        uintptr func = FindAPI(hooks[i].hash, hooks[i].key);
        if (func != proc)
        {
            continue;
        }
        return (uintptr)(hooks[i].method);
    }
    return proc;
}

static uintptr replaceToHook(Runtime* runtime, uintptr proc)
{
    for (int i = 0; i < arrlen(runtime->IAT_Hooks); i++)
    {
        if (proc != runtime->IAT_Hooks[i].Func)
        {
            continue;
        }
        return runtime->IAT_Hooks[i].Hook;
    }
    return proc;
}

__declspec(noinline)
errno RT_SleepHR(uint32 milliseconds)
{
    Runtime* runtime = getRuntimePointer();

    if (runtime->WaitForSingleObject(runtime->hMutexSleep, INFINITE) != WAIT_OBJECT_0)
    {
        return ERR_RUNTIME_LOCK;
    }

    // TODO adjust it
    if (milliseconds < 10)
    {
        milliseconds = 10;
    }
    milliseconds = 10;

    errno errno = NO_ERROR;
    for (;;)
    {
        // set sleep arguments
        if (runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE) != WAIT_OBJECT_0)
        {
            errno = ERR_RUNTIME_LOCK_EVENT;
            break;
        }
        runtime->EventType = EVENT_TYPE_SLEEP;
        runtime->SleepTime = milliseconds;
        if (!runtime->ReleaseMutex(runtime->hMutexEvent))
        {
            errno = ERR_RUNTIME_UNLOCK_EVENT;
            break;
        }
        // notice trigger
        if (!runtime->SetEvent(runtime->hEventCome))
        {
            errno = ERR_RUNTIME_NOTICE_TRIGGER;
            break;
        }
        // wait trigger process event
        if (runtime->WaitForSingleObject(runtime->hEventDone, INFINITE) != WAIT_OBJECT_0)
        {
            errno = ERR_RUNTIME_WAIT_TRIGGER;
            break;
        }
        // receive return errno
        if (runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE) != WAIT_OBJECT_0)
        {
            errno = ERR_RUNTIME_LOCK_EVENT;
            break;
        }
        errno = runtime->ReturnErrno;
        if (!runtime->ReleaseMutex(runtime->hMutexEvent))
        {
            errno = ERR_RUNTIME_UNLOCK_EVENT;
            break;
        }
        // reset event
        if (!runtime->ResetEvent(runtime->hEventDone))
        {
            errno = ERR_RUNTIME_RESET_EVENT;
            break;
        }
        break;
    }

    if (!runtime->ReleaseMutex(runtime->hMutexSleep))
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
static void trigger()
{
    Runtime* runtime = getRuntimePointer();

    uint64 maxSleep  = RandUint((uint64)runtime);
    uint32 waitEvent = WAIT_OBJECT_0;

    bool  exit  = false;
    errno errno = NO_ERROR;

    for (;;)
    {
        // select random maximum event trigger time.
        maxSleep = RandUint(maxSleep);
        uint32 sleepMS = (300 + maxSleep % 300) * 1000;
        waitEvent = runtime->WaitForSingleObject(runtime->hEventCome, sleepMS);
        switch (waitEvent)
        {
        case WAIT_OBJECT_0:
            errno = processEvent(runtime, &exit);
            if (exit)
            {
                return;
            }
            break;
        case WAIT_TIMEOUT: // force trigger sleep
            errno = sleepHR(runtime, 1000); 
            break;
        default:
            return;
        }
        // store return error
        waitEvent = runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE);
        if (waitEvent != WAIT_OBJECT_0)
        {
            return;
        }
        runtime->ReturnErrno = errno;
        if (!runtime->ReleaseMutex(runtime->hMutexEvent))
        {
            return;
        }
        // notice caller
        if (!runtime->ResetEvent(runtime->hEventCome))
        {
            return;
        }
        if (!runtime->SetEvent(runtime->hEventDone))
        {
            return;
        }
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            return;
        }
    }
}

static errno processEvent(Runtime* runtime, bool* exit)
{
    // get event type and arguments
    uint32 waitEvent = WAIT_OBJECT_0;
    waitEvent = runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE);
    if (waitEvent != WAIT_OBJECT_0)
    {
        *exit = true;
        return ERR_RUNTIME_LOCK_EVENT;
    }
    uint32 eventType = runtime->EventType;
    uint32 sleepTime = runtime->SleepTime;
    if (!runtime->ReleaseMutex(runtime->hMutexEvent))
    {
        *exit = true;
        return ERR_RUNTIME_UNLOCK_EVENT;
    }
    switch (eventType)
    {
    case EVENT_TYPE_SLEEP:
        return sleepHR(runtime, sleepTime);
    case EVENT_TYPE_STOP:
        *exit = true;
        return NO_ERROR;
    default:
        panic(PANIC_UNREACHABLE_CODE);
    }
    return NO_ERROR;
}

__declspec(noinline)
static errno sleepHR(Runtime* runtime, uint32 milliseconds)
{
    if (!rt_lock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }

    errno errno = NO_ERROR;
    for (;;)
    {
        errno = hide(runtime);
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = sleep(runtime, milliseconds);
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = recover(runtime);
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        break;
    }

    if (!rt_unlock(runtime))
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
static errno hide(Runtime* runtime)
{
    errno errno = NO_ERROR;
    for (;;)
    {
        errno = runtime->ThreadTracker->ThdSuspend();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->MemoryTracker->MemEncrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->ResourceTracker->ResEncrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->LibraryTracker->LibEncrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        break;
    }
    return errno;
}

__declspec(noinline)
static errno sleep(Runtime* runtime, uint32 milliseconds)
{
    // store core Windows API before encrypt
    FlushInstructionCache_t flush = runtime->FlushInstructionCache;
    // build shield context before encrypt
    uintptr runtimeAddr = (uintptr)(&InitRuntime);
    uintptr instAddress = runtime->InstAddress;
    if (instAddress == NULL || instAddress >= runtimeAddr)
    {
        instAddress = runtimeAddr;
    }
    Shield_Ctx ctx = {
        .InstAddress = instAddress,
        .SleepTime   = milliseconds,
        .hProcess    = runtime->hProcess,

        .WaitForSingleObject = runtime->WaitForSingleObject,
    };
    // build crypto context
    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
    RandBuf(key, CRYPTO_KEY_SIZE);
    RandBuf(iv, CRYPTO_IV_SIZE);
    byte* buf = (byte*)(runtime->MainMemPage);
    // encrypt main page
    EncryptBuf(buf, MAIN_MEM_PAGE_SIZE, &key[0], &iv[0]);
    // call shield!!!
    if (!DefenseRT(&ctx))
    {
        return ERR_RUNTIME_DEFENSE_RT;
    }
    // flush instruction cache after decrypt
    uintptr baseAddr = instAddress;
    uint    instSize = (uintptr)(&DefenseRT) - baseAddr;
    if (!flush(CURRENT_PROCESS, baseAddr, instSize))
    {
        return ERR_RUNTIME_FLUSH_INST_CACHE;
    }
    // decrypt main page
    DecryptBuf(buf, MAIN_MEM_PAGE_SIZE, &key[0], &iv[0]);
    return NO_ERROR;
}

__declspec(noinline)
static errno recover(Runtime* runtime)
{
    errno errno = NO_ERROR;
    for (;;)
    {
        errno = runtime->LibraryTracker->LibDecrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->ResourceTracker->ResDecrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->MemoryTracker->MemDecrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->ThreadTracker->ThdResume();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        break;
    }
    return errno;
}

__declspec(noinline)
errno RT_Hide()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }

    errno errno = hide(runtime);

    if (!rt_unlock(runtime))
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
errno RT_Recover()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }

    errno errno = recover(runtime);

    if (!rt_unlock(runtime))
    {
        return ERR_RUNTIME_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
errno RT_Exit()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }

    errno exit_err = NO_ERROR;

    // must record options before clean runtime
    bool notEraseInst = runtime->NotEraseInst;

    // clean runtime modules
    errno errno = runtime->ThreadTracker->ThdClean();
    if (errno != NO_ERROR && exit_err == NO_ERROR)
    {
        exit_err = errno;
    }
    errno = runtime->ResourceTracker->ResClean();
    if (errno != NO_ERROR && exit_err == NO_ERROR)
    {
        exit_err = errno;
    }
    errno = runtime->MemoryTracker->MemClean();
    if (errno != NO_ERROR && exit_err == NO_ERROR)
    {
        exit_err = errno;
    }
    errno = runtime->LibraryTracker->LibClean();
    if (errno != NO_ERROR && exit_err == NO_ERROR)
    {
        exit_err = errno;
    }
    cleanRuntime(runtime);

    // erase runtime instructions except this function
    if (!notEraseInst)
    {
        uintptr begin = (uintptr)(&InitRuntime);
        uintptr end   = (uintptr)(&RT_Exit);
        int64   size  = end - begin;
        eraseMemory(begin, size);
        begin = (uintptr)(&rt_epilogue);
        end   = (uintptr)(&Epilogue);
        size  = end - begin;
        eraseMemory(begin, size);
    }
    return exit_err;
}

// must disable compiler optimize, otherwise eraseMemory()
// will be replaced to the mem_set() in lib_memory.c.
#pragma optimize("", off)
static void eraseMemory(uintptr address, int64 size)
{
    byte* addr = (byte*)address;
    for (int64 i = 0; i < size; i++)
    {
        *addr = 0xFF;
        addr++;
    }
}
#pragma optimize("", on)

// prevent be linked to Epilogue.
#pragma optimize("", off)
static void rt_epilogue()
{
    byte var = 1;
    return;
}
#pragma optimize("", on)
