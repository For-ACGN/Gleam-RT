#include "c_types.h"
#include "windows_t.h"
#include "rel_addr.h"
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
#include "argument.h"
#include "shield.h"
#include "runtime.h"
#include "epilogue.h"
#include "debug.h"

#define MAIN_MEM_PAGE_SIZE 8192

#define EVENT_TYPE_SLEEP 0x01
#define EVENT_TYPE_STOP  0x02

// for IAT hooks
typedef struct {
    void* Proc;
    void* Hook;
} Hook;

typedef struct {
    Runtime_Opts* Options;

    // store options
    void* BootInstAddress;
    bool  NotEraseInstruction;

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

    // runtime data
    void*  MainMemPage; // store all structures
    uint32 PageSize;    // for memory management
    HANDLE hProcess;    // for simulate kernel32.Sleep
    HANDLE hMutex;      // global method mutex

    // sleep event trigger
    HANDLE hMutexSleep;  // sleep method mutex
    HANDLE hEventArrive; // arrive event
    HANDLE hEventDone;   // finish event
    uint32 EventType;    // store event type
    uint32 SleepTime;    // store sleep argument
    errno  ReturnErrno;  // store error number
    HANDLE hMutexEvent;  // event data mutex
    HANDLE hThread;      // trigger thread

    // IAT hooks about GetProcAddress
    Hook IATHooks[20];

    // submodules
    LibraryTracker_M*  LibraryTracker;
    MemoryTracker_M*   MemoryTracker;
    ThreadTracker_M*   ThreadTracker;
    ResourceTracker_M* ResourceTracker;
    ArgumentStore_M*   ArgumentStore;
} Runtime;

// export methods and IAT hooks about Runtime
void* RT_FindAPI(uint hash, uint key);
void  RT_Sleep(DWORD dwMilliseconds);

void* RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
void* RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool hook);
void* RT_GetProcAddressByHash(uint hash, uint key, bool hook);
void* RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName);

errno RT_ExitProcess(UINT uExitCode);
errno RT_SleepHR(DWORD dwMilliseconds);

errno RT_Hide();
errno RT_Recover();
errno RT_Exit();

// internal methods for Runtime submodules
void* RT_malloc(uint size);
void* RT_realloc(void* address, uint size);
bool  RT_free(void* address);

errno RT_lock_mods();
errno RT_unlock_mods();

// hard encoded address in getRuntimePointer for replacement
#ifdef _WIN64
    #define RUNTIME_POINTER 0x7FABCDEF111111FF
#elif _WIN32
    #define RUNTIME_POINTER 0x7FABCDFF
#endif
static Runtime* getRuntimePointer();

static bool rt_lock(Runtime* runtime);
static bool rt_unlock(Runtime* runtime);

static void* allocateRuntimeMemory();
static bool  initRuntimeAPI(Runtime* runtime);
static bool  adjustPageProtect(Runtime* runtime);
static bool  updateRuntimePointer(Runtime* runtime);
static errno initRuntimeEnvironment(Runtime* runtime);
static errno initLibraryTracker(Runtime* runtime, Context* context);
static errno initMemoryTracker(Runtime* runtime, Context* context);
static errno initThreadTracker(Runtime* runtime, Context* context);
static errno initResourceTracker(Runtime* runtime, Context* context);
static errno initArgumentStore(Runtime* runtime, Context* context);
static bool  initIATHooks(Runtime* runtime);
static bool  flushInstructionCache(Runtime* runtime);

static void* getRuntimeMethods(byte* module, LPCSTR lpProcName);
static void* getResTrackerHook(Runtime* runtime, void* proc);
static void* replaceToHook(Runtime* runtime, void* proc);

static void  trigger();
static errno processEvent(Runtime* runtime, bool* exit);
static errno sleepHR(Runtime* runtime, uint32 milliseconds);
static errno hide(Runtime* runtime);
static errno recover(Runtime* runtime);
static errno sleep(Runtime* runtime, uint32 milliseconds);

static void  eraseRuntimeMethods();
static errno cleanRuntime(Runtime* runtime);
static errno exitTrigger(Runtime* runtime);
static errno closeHandles(Runtime* runtime);
static void  eraseMemory(uintptr address, uintptr size);
static void  rt_epilogue();

__declspec(noinline)
Runtime_M* InitRuntime(Runtime_Opts* opts)
{
    if (!InitDebugger())
    {
        SetLastErrno(ERR_RUNTIME_INIT_DEBUGGER);
        return NULL;
    }
    // alloc memory for store runtime structure
    void* memPage = allocateRuntimeMemory();
    if (memPage == NULL)
    {
        SetLastErrno(ERR_RUNTIME_ALLOC_MEMORY);
        return NULL;
    }
    // set structure address
    uintptr address = (uintptr)memPage;
    uintptr runtimeAddr = address + 1000 + RandUintN(address, 128);
    uintptr moduleAddr  = address + 2500 + RandUintN(address, 128);
    // initialize structure
    Runtime* runtime = (Runtime*)runtimeAddr;
    mem_clean(runtime, sizeof(Runtime));
    // store runtime options
    if (opts == NULL)
    {
        Runtime_Opts opt = {
            .BootInstAddress     = NULL,
            .NotEraseInstruction = false,
            .NotAdjustProtect    = false,
            .TrackCurrentThread  = false,
        };
        opts = &opt;
    }
    runtime->Options = opts;
    runtime->BootInstAddress     = opts->BootInstAddress;
    runtime->NotEraseInstruction = opts->NotEraseInstruction;
    runtime->MainMemPage = memPage;
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
        void* addr = GetFuncAddr(&trigger);
        runtime->hThread = runtime->ThreadTracker->New(addr, NULL, false);
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
    module->FindAPI       = GetFuncAddr(&RT_FindAPI);
    module->Sleep         = GetFuncAddr(&RT_Sleep);
    module->MemAlloc      = runtime->MemoryTracker->Alloc;
    module->MemRealloc    = runtime->MemoryTracker->Realloc;
    module->MemFree       = runtime->MemoryTracker->Free;
    module->NewThread     = runtime->ThreadTracker->New;
    module->ExitThread    = runtime->ThreadTracker->Exit;
    module->GetArgument   = runtime->ArgumentStore->Get;
    module->EraseArgument = runtime->ArgumentStore->Erase;
    module->EraseAllArgs  = runtime->ArgumentStore->EraseAll;
    // for IAT hooks
    module->GetProcAddress         = GetFuncAddr(&RT_GetProcAddress);
    module->GetProcAddressByName   = GetFuncAddr(&RT_GetProcAddressByName);
    module->GetProcAddressByHash   = GetFuncAddr(&RT_GetProcAddressByHash);
    module->GetProcAddressOriginal = GetFuncAddr(&RT_GetProcAddressOriginal);
    // runtime core methods
    module->SleepHR = GetFuncAddr(&RT_SleepHR);
    module->Hide    = GetFuncAddr(&RT_Hide);
    module->Recover = GetFuncAddr(&RT_Recover);
    module->Exit    = GetFuncAddr(&RT_Exit);
    return module;
}

// allocate memory for store structures.
static void* allocateRuntimeMemory()
{
#ifdef _WIN64
    uint hash = 0xB6A1D0D4A275D4B6;
    uint key  = 0x64CB4D66EC0BEFD9;
#elif _WIN32
    uint hash = 0xC3DE112E;
    uint key  = 0x8D9EA74F;
#endif
    VirtualAlloc_t virtualAlloc = FindAPI(hash, key);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }
    LPVOID addr = virtualAlloc(0, MAIN_MEM_PAGE_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    RandBuf(addr, MAIN_MEM_PAGE_SIZE);
    dbg_log("[runtime]", "Main Page: 0x%zX\n", addr);
    return addr;
}

static bool initRuntimeAPI(Runtime* runtime)
{
    typedef struct { 
        uint hash; uint key; void* proc;
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
    for (int i = 0; i < arrlen(list); i++)
    {
        void* proc = FindAPI(list[i].hash, list[i].key);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }
    runtime->GetSystemInfo         = list[0x00].proc;
    runtime->VirtualAlloc          = list[0x01].proc;
    runtime->VirtualFree           = list[0x02].proc;
    runtime->VirtualProtect        = list[0x03].proc;
    runtime->FlushInstructionCache = list[0x04].proc;
    runtime->CreateMutexA          = list[0x05].proc;
    runtime->ReleaseMutex          = list[0x06].proc;
    runtime->CreateEventA          = list[0x07].proc;
    runtime->SetEvent              = list[0x08].proc;
    runtime->ResetEvent            = list[0x09].proc;
    runtime->WaitForSingleObject   = list[0x0A].proc;
    runtime->DuplicateHandle       = list[0x0B].proc;
    runtime->CloseHandle           = list[0x0C].proc;
    runtime->GetProcAddress        = list[0x0D].proc;
    return true;
}

// change memory protect for dynamic update pointer that hard encode.
static bool adjustPageProtect(Runtime* runtime)
{
    if (runtime->Options->NotAdjustProtect)
    {
        return true;
    }
    void* init = GetFuncAddr(&InitRuntime);
    void* addr = runtime->BootInstAddress;
    if (addr == NULL || (uintptr)addr > (uintptr)init)
    {
        addr = init;
    }
    uintptr begin = (uintptr)(addr);
    uintptr end   = (uintptr)(GetFuncAddr(&Epilogue));
    uint    size  = end - begin;
    uint32  old;
    return runtime->VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old);
}

static bool updateRuntimePointer(Runtime* runtime)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getRuntimePointer));
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
    runtime->hMutex = hMutex;
    // create sleep method mutex
    HANDLE hMutexSleep = runtime->CreateMutexA(NULL, false, NULL);
    if (hMutexSleep == NULL)
    {
        return ERR_RUNTIME_CREATE_SLEEP_MUTEX;
    }
    runtime->hMutexSleep = hMutexSleep;
    // create arrive and done events
    HANDLE hEventArrive = runtime->CreateEventA(NULL, true, false, NULL);
    if (hEventArrive == NULL)
    {
        return ERR_RUNTIME_CREATE_EVENT_ARRIVE;
    }
    runtime->hEventArrive = hEventArrive;
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
        .TrackCurrentThread = runtime->Options->TrackCurrentThread,

        .MainMemPage = (uintptr)(runtime->MainMemPage),
        .PageSize    = runtime->PageSize,

        .VirtualAlloc          = runtime->VirtualAlloc,
        .VirtualFree           = runtime->VirtualFree,
        .VirtualProtect        = runtime->VirtualProtect,
        .CreateMutexA          = runtime->CreateMutexA,
        .ReleaseMutex          = runtime->ReleaseMutex,
        .WaitForSingleObject   = runtime->WaitForSingleObject,
        .FlushInstructionCache = runtime->FlushInstructionCache,
        .DuplicateHandle       = runtime->DuplicateHandle,
        .CloseHandle           = runtime->CloseHandle,

        .malloc  = GetFuncAddr(&RT_malloc),
        .realloc = GetFuncAddr(&RT_realloc),
        .free    = GetFuncAddr(&RT_free),
        .lock    = GetFuncAddr(&RT_lock_mods),
        .unlock  = GetFuncAddr(&RT_unlock_mods),
    };
    typedef errno (*submodule_t)(Runtime* runtime, Context* context);
    submodule_t submodules[] = 
    {
        GetFuncAddr(&initLibraryTracker),
        GetFuncAddr(&initMemoryTracker),
        GetFuncAddr(&initThreadTracker),
        GetFuncAddr(&initResourceTracker),
        GetFuncAddr(&initArgumentStore),
    };
    errno errno;
    for (int i = 0; i < arrlen(submodules); i++)
    {
        errno = submodules[i](runtime, &context);
        if (errno != NO_ERROR)
        {
            return errno;
        }
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

static errno initArgumentStore(Runtime* runtime, Context* context)
{
    ArgumentStore_M* store = InitArgumentStore(context);
    if (store == NULL)
    {
        return GetLastErrno();
    }
    runtime->ArgumentStore = store;
    return NO_ERROR;
}

static bool initIATHooks(Runtime* runtime)
{
    LibraryTracker_M* libraryTracker = runtime->LibraryTracker;
    MemoryTracker_M*  memoryTracker  = runtime->MemoryTracker;
    ThreadTracker_M*  threadTracker  = runtime->ThreadTracker;

    typedef struct {
        uint hash; uint key; void* hook;
    } item;
    item items[] =
#ifdef _WIN64
    {
        { 0xCAA4843E1FC90287, 0x2F19F60181B5BFE3, GetFuncAddr(&RT_GetProcAddress) },
        { 0xB8D0B91323A24997, 0xBC36CA6282477A43, GetFuncAddr(&RT_ExitProcess) },
        { 0xCED5CC955152CD43, 0xAA22C83C068CB037, GetFuncAddr(&RT_SleepHR) },
        { 0xD823D640CA9D87C3, 0x15821AE3463EFBE8, libraryTracker->LoadLibraryA },
        { 0xDE75B0371B7500C0, 0x2A1CF678FC737D0F, libraryTracker->LoadLibraryW },
        { 0x448751B1385751E8, 0x3AE522A4E9435111, libraryTracker->LoadLibraryExA },
        { 0x7539E619D8B4166E, 0xE52EE8B2C2D15D9B, libraryTracker->LoadLibraryExW },
        { 0x80B0A97C97E9FE79, 0x675B0BA55C1758F9, libraryTracker->FreeLibrary },
        { 0x66F288FB8CF6CADD, 0xC48D2119FF3ADC6A, libraryTracker->FreeLibraryAndExitThread },
        { 0x18A3895F35B741C8, 0x96C9890F48D55E7E, memoryTracker->VirtualAlloc },
        { 0xDB54AA6683574A8B, 0x3137DE2D71D3FF3E, memoryTracker->VirtualFree },
        { 0xF5469C21B43D23E5, 0xF80028997F625A05, memoryTracker->VirtualProtect },
        { 0xE9ECDC63F6D3DC53, 0x815C2FDFE640307E, memoryTracker->VirtualQuery },
        { 0x84AC57FA4D95DE2E, 0x5FF86AC14A334443, threadTracker->CreateThread },
        { 0xA6E10FF27A1085A8, 0x24815A68A9695B16, threadTracker->ExitThread },
        { 0x82ACE4B5AAEB22F1, 0xF3132FCE3AC7AD87, threadTracker->SuspendThread },
        { 0x226860209E13A99A, 0xE1BD9D8C64FAF97D, threadTracker->ResumeThread },
        { 0x374E149C710B1006, 0xE5D0E3FA417FA6CF, threadTracker->GetThreadContext },
        { 0xCFE3FFD5F0023AE3, 0x9044E42F1C020CF5, threadTracker->SetThreadContext },
        { 0x248E1CDD11AB444F, 0x195932EA70030929, threadTracker->TerminateThread },
    };
#elif _WIN32
    {
        { 0x5E5065D4, 0x63CDAD01, GetFuncAddr(&RT_GetProcAddress) },
        { 0xB6CEC366, 0xA0CF5E10, GetFuncAddr(&RT_ExitProcess) },
        { 0x705D4FAD, 0x94CF33BF, GetFuncAddr(&RT_SleepHR) },
        { 0x0149E478, 0x86A603D3, libraryTracker->LoadLibraryA },
        { 0x90E21596, 0xEBEA7D19, libraryTracker->LoadLibraryW },
        { 0xD6C482CE, 0xC6063014, libraryTracker->LoadLibraryExA },
        { 0x158D5700, 0x24540418, libraryTracker->LoadLibraryExW },
        { 0x5CDBC79F, 0xA1B99CF2, libraryTracker->FreeLibrary },
        { 0x929869F4, 0x7D668185, libraryTracker->FreeLibraryAndExitThread },
        { 0xD5B65767, 0xF3A27766, memoryTracker->VirtualAlloc },
        { 0x4F0FC063, 0x182F3CC6, memoryTracker->VirtualFree },
        { 0xEBD60441, 0x280A4A9F, memoryTracker->VirtualProtect },
        { 0xD17B0461, 0xFB4E5DB5, memoryTracker->VirtualQuery },
        { 0x20744CA1, 0x4FA1647D, threadTracker->CreateThread },
        { 0xED42C0F0, 0xC59EBA39, threadTracker->ExitThread },
        { 0x133B00D5, 0x48E02627, threadTracker->SuspendThread },
        { 0xA02B4251, 0x5287173F, threadTracker->ResumeThread },
        { 0xCF0EC7B7, 0xBAC33715, threadTracker->GetThreadContext },
        { 0xC59EF832, 0xEF75D2EA, threadTracker->SetThreadContext },
        { 0x6EF0E2AA, 0xE014E29F, threadTracker->TerminateThread },
    };
#endif
    for (int i = 0; i < arrlen(items); i++)
    {
        void* proc = FindAPI(items[i].hash, items[i].key);
        if (proc == NULL)
        {
            return false;
        }
        runtime->IATHooks[i].Proc = proc;
        runtime->IATHooks[i].Hook = items[i].hook;
    }
    return true;
}

__declspec(noinline)
static void eraseRuntimeMethods()
{
    uintptr begin = (uintptr)(GetFuncAddr(&allocateRuntimeMemory));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseRuntimeMethods));
    uintptr size  = end - begin;
    RandBuf((byte*)begin, (int64)size);
}

__declspec(noinline)
static bool flushInstructionCache(Runtime* runtime)
{
    void*   addr  = GetFuncAddr(&InitRuntime);
    uintptr begin = (uintptr)(addr);
    uintptr end   = (uintptr)(GetFuncAddr(&Epilogue));
    uintptr size  = end - begin;
    if (!runtime->FlushInstructionCache(CURRENT_PROCESS, addr, size))
    {
        return false;
    }
    // clean useless API functions in runtime structure
    RandBuf((byte*)(&runtime->VirtualProtect), sizeof(uintptr));
    return true;
}

static errno cleanRuntime(Runtime* runtime)
{
    errno err = NO_ERROR;
    // exit trigger thread
    errno enetg = exitTrigger(runtime);
    if (enetg != NO_ERROR && err == NO_ERROR)
    {
        err = enetg;
    }
    // close all handles in runtime
    errno enchd = closeHandles(runtime);
    if (enchd != NO_ERROR && err == NO_ERROR)
    {
        err = enchd;
    }
    // must copy variables in Runtime before call RandBuf
    VirtualFree_t virtualFree = runtime->VirtualFree;
    void* memPage = runtime->MainMemPage;
    // release main memory page
    RandBuf(memPage, MAIN_MEM_PAGE_SIZE);
    if (virtualFree != NULL)
    {
        if (!virtualFree(memPage, 0, MEM_RELEASE) && err == NO_ERROR)
        {
            err = ERR_RUNTIME_CLEAN_FREE_MEM;
        }
    }
    return err;
}

static errno exitTrigger(Runtime* runtime)
{
    if (runtime->hThread == NULL)
    {
        return NO_ERROR;
    }
    errno errno = NO_ERROR;
    for (;;)
    {
        // set event type
        if (runtime->WaitForSingleObject(runtime->hMutexEvent, INFINITE) != WAIT_OBJECT_0)
        {
            errno = ERR_RUNTIME_LOCK_EVENT;
            break;
        }
        runtime->EventType = EVENT_TYPE_STOP;
        if (!runtime->ReleaseMutex(runtime->hMutexEvent))
        {
            errno = ERR_RUNTIME_UNLOCK_EVENT;
            break;
        }
        // notice trigger
        if (!runtime->SetEvent(runtime->hEventArrive))
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
    if (errno != NO_ERROR)
    {
        return errno;
    }
    // wait trigger thread exit
    if (runtime->WaitForSingleObject(runtime->hThread, INFINITE) != WAIT_OBJECT_0)
    {
        if (errno == NO_ERROR)
        {
            errno = ERR_RUNTIME_CLEAN_EXIT_TRIGGER;
        }
    }
    return errno;
}

static errno closeHandles(Runtime* runtime)
{
    if (runtime->CloseHandle == NULL)
    {
        return NO_ERROR;
    }
    typedef struct { 
        HANDLE handle; errno errno;
    } handle;
    handle list[] = 
    {
        { runtime->hProcess,     ERR_RUNTIME_CLEAN_H_PROCESS      },
        { runtime->hMutex,       ERR_RUNTIME_CLEAN_H_MUTEX        },
        { runtime->hMutexSleep,  ERR_RUNTIME_CLEAN_H_MUTEX_SLEEP  },
        { runtime->hEventArrive, ERR_RUNTIME_CLEAN_H_EVENT_ARRIVE },
        { runtime->hEventDone,   ERR_RUNTIME_CLEAN_H_EVENT_DONE   },
        { runtime->hMutexEvent,  ERR_RUNTIME_CLEAN_H_MUTEX_EVENT  },
        { runtime->hThread,      ERR_RUNTIME_CLEAN_H_THREAD       },
    };
    errno errno = NO_ERROR;
    for (int i = 0; i < arrlen(list); i++)
    {
        if (list[i].handle == NULL)
        {
            continue;
        }
        if (!runtime->CloseHandle(list[i].handle) && errno == NO_ERROR)
        {
            errno = list[i].errno;
        }
    }
    return errno;
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
    uint32 event = runtime->WaitForSingleObject(runtime->hMutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

__declspec(noinline)
static bool rt_unlock(Runtime* runtime)
{
    return runtime->ReleaseMutex(runtime->hMutex);
}

__declspec(noinline)
void* RT_malloc(uint size)
{
    Runtime* runtime = getRuntimePointer();

    // ensure the size is a multiple of memory page size.
    // it also for prevent track the special page size.
    uint pageSize = ((size / runtime->PageSize) + 1) * runtime->PageSize;
    void* addr = runtime->VirtualAlloc(0, pageSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
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
    return (void*)(address + 16);
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
    void* addr = (void*)((uintptr)(address)-16);
    uint  size = *(uint*)addr;
    mem_clean((byte*)addr, size);
    return runtime->VirtualFree(addr, 0, MEM_RELEASE);
}

__declspec(noinline)
errno RT_lock_mods()
{
    Runtime* runtime = getRuntimePointer();

    if (!runtime->LibraryTracker->Lock())
    {
        return ERR_RUNTIME_LOCK_LIBRARY;
    }
    if (!runtime->MemoryTracker->Lock())
    {
        return ERR_RUNTIME_LOCK_MEMORY;
    }
    if (!runtime->ResourceTracker->Lock())
    {
        return ERR_RUNTIME_LOCK_RESOURCE;
    }
    if (!runtime->ArgumentStore->Lock())
    {
        return ERR_RUNTIME_LOCK_ARGUMENT;
    }
    if (!runtime->ThreadTracker->Lock())
    {
        return ERR_RUNTIME_LOCK_THREAD;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno RT_unlock_mods()
{
    Runtime* runtime = getRuntimePointer();

    if (!runtime->ThreadTracker->Unlock())
    {
        return ERR_RUNTIME_UNLOCK_THREAD;
    }
    if (!runtime->ArgumentStore->Unlock())
    {
        return ERR_RUNTIME_UNLOCK_ARGUMENT;
    }
    if (!runtime->ResourceTracker->Unlock())
    {
        return ERR_RUNTIME_UNLOCK_RESOURCE;
    }
    if (!runtime->MemoryTracker->Unlock())
    {
        return ERR_RUNTIME_UNLOCK_MEMORY;
    }
    if (!runtime->LibraryTracker->Unlock())
    {
        return ERR_RUNTIME_UNLOCK_LIBRARY;
    }
    return NO_ERROR;
}

__declspec(noinline)
void* RT_FindAPI(uint hash, uint key)
{
    return RT_GetProcAddressByHash(hash, key, true);
}

__declspec(noinline)
void RT_Sleep(DWORD dwMilliseconds)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return;
    }

    // copy API address and handle
    WaitForSingleObject_t wait = runtime->WaitForSingleObject;
    HANDLE hProcess = runtime->hProcess;

    if (!rt_unlock(runtime))
    {
        return;
    }

    wait(hProcess, dwMilliseconds);
}

__declspec(noinline)
void* RT_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    return RT_GetProcAddressByName(hModule, lpProcName, true);
}

__declspec(noinline)
void* RT_GetProcAddressByName(HMODULE hModule, LPCSTR lpProcName, bool hook)
{
    // use "mem_clean" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    byte module[MAX_PATH];
    mem_clean(&module, sizeof(module));
    // get module file name
    if (GetModuleFileName(hModule, &module[0], sizeof(module)) == 0)
    {
        return NULL;
    }
    // check is internal methods
    void* method = getRuntimeMethods(&module[0], lpProcName);
    if (method != NULL)
    {
        return method;
    }
    // generate key for calculate Windows API hash
    uint key  = RandUint((uint64)(hModule) + (uint64)(lpProcName));
    uint hash = HashAPI_W((uint16*)(&module[0]), (byte*)lpProcName, key);
    return RT_GetProcAddressByHash(hash, key, hook);
}

__declspec(noinline)
void* RT_GetProcAddressByHash(uint hash, uint key, bool hook)
{
    Runtime* runtime = getRuntimePointer();

    void* proc = FindAPI(hash, key);
    if (proc == NULL)
    {
        return NULL;
    }
    if (!hook)
    {
        return proc;
    }
    void* rth = getResTrackerHook(runtime, proc);
    if (rth != proc)
    {
        return rth;
    }
    return replaceToHook(runtime, proc);
}

// disable optimize for use call NOT jmp to runtime->GetProcAddress.
#pragma optimize("", off)
__declspec(noinline)
void* RT_GetProcAddressOriginal(HMODULE hModule, LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer();

    return runtime->GetProcAddress(hModule, lpProcName);
}
#pragma optimize("", on)

static void* getRuntimeMethods(byte* module, LPCSTR lpProcName)
{
    Runtime* runtime = getRuntimePointer();

    ArgumentStore_M* argumentStore = runtime->ArgumentStore;

    typedef struct {
        uint hash; uint key; void* method;
    } method;
    method methods[] =
#ifdef _WIN64
    {
        { 0xA23FAC0E6398838A, 0xE4990D7D4933EE6A, GetFuncAddr(&RT_GetProcAddressByName)   },
        { 0xABD1E8F0D28E9F46, 0xAF34F5979D300C70, GetFuncAddr(&RT_GetProcAddressByHash)   },
        { 0xC9C5D350BB118FAE, 0x061A602F681F2636, GetFuncAddr(&RT_GetProcAddressOriginal) },
        { 0x126369AAC565B208, 0xEA01652E5DDE482E, argumentStore->Get         },
        { 0x2FEB65B0CF6A233A, 0x24B8204DA5F3FA2F, argumentStore->Erase       },
        { 0x2AE3C13B09353949, 0x2FDD5041391C2A93, argumentStore->EraseAll    },
    };
#elif _WIN32
    {
        { 0xCF983018, 0x3ECBF2DF, GetFuncAddr(&RT_GetProcAddressByName)   },
        { 0x40D5BD08, 0x302D5D2B, GetFuncAddr(&RT_GetProcAddressByHash)   },
        { 0x45556AA5, 0xB3BEF31D, GetFuncAddr(&RT_GetProcAddressOriginal) },
        { 0x7D57C76D, 0xD67871A6, argumentStore->Get      },
        { 0xC33C2108, 0x8A90E020, argumentStore->Erase    },
        { 0x9BD86FED, 0xFEA640B8, argumentStore->EraseAll },
    };
#endif
    for (int i = 0; i < arrlen(methods); i++)
    {
        uint hash = HashAPI_W((uint16*)module, (byte*)lpProcName, methods[i].key);
        if (hash != methods[i].hash)
        {
            continue;
        }
        return methods[i].method;
    }
    return NULL;
}

// getResTrackerHook is used to FindAPI after LoadLibrary
// hooks in initIATHooks are all in kernel32.dll
static void* getResTrackerHook(Runtime* runtime, void* proc)
{
    ResourceTracker_M* resourceTracker = runtime->ResourceTracker;

    typedef struct {
        uint hash; uint key; void* hook;
    } hook;
    hook hooks[] =
#ifdef _WIN64
    {
        { 0x94DAFAE03484102D, 0x300F881516DC2FF5, resourceTracker->CreateFileA    },
        { 0xC3D28B35396A90DA, 0x8BA6316E5F5DC86E, resourceTracker->CreateFileW    },
        { 0x78AEE64CADBBC72F, 0x480A328AEFFB1A39, resourceTracker->CloseHandle    },
        { 0x4015A18370E27D65, 0xA5B47007B7B8DD26, resourceTracker->FindFirstFileA },
        { 0x7C520EB61A85181B, 0x933C760F029EF1DD, resourceTracker->FindFirstFileW },
        { 0x3D3A73632A3BCEDA, 0x72E6CA3A0850F779, resourceTracker->FindClose      },
        { 0x7749934E33C18703, 0xCFB41E32B03DC637, resourceTracker->WSAStartup     },
        { 0x46C76E87C13DF670, 0x37B6B54E4B2FBECC, resourceTracker->WSACleanup     },
    };
#elif _WIN32
    {
        { 0x79796D6E, 0x6DBBA55C, resourceTracker->CreateFileA    },
        { 0x0370C4B8, 0x76254EF3, resourceTracker->CreateFileW    },
        { 0xCB5BD447, 0x49A6FC78, resourceTracker->CloseHandle    },
        { 0x629ADDFA, 0x749D1CC9, resourceTracker->FindFirstFileA },
        { 0x612273CD, 0x563EDF55, resourceTracker->FindFirstFileW },
        { 0x6CD807C4, 0x812C40E9, resourceTracker->FindClose      },
        { 0xE487BC0B, 0x283C1684, resourceTracker->WSAStartup     },
        { 0x175B553E, 0x541A996E, resourceTracker->WSACleanup     },
    };
#endif
    for (int i = 0; i < arrlen(hooks); i++)
    {
        if (FindAPI(hooks[i].hash, hooks[i].key) != proc)
        {
            continue;
        }
        return hooks[i].hook;
    }
    return proc;
}

static void* replaceToHook(Runtime* runtime, void* proc)
{
    for (int i = 0; i < arrlen(runtime->IATHooks); i++)
    {
        if (proc != runtime->IATHooks[i].Proc)
        {
            continue;
        }
        return runtime->IATHooks[i].Hook;
    }
    return proc;
}

__declspec(noinline)
errno RT_ExitProcess(UINT uExitCode)
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }

    errno errno = NO_ERROR;

    errno = RT_lock_mods();
    if (errno != NO_ERROR)
    {
        return errno;
    }

    // terminate all tracked thrreads
    errno = runtime->ThreadTracker->Terminate();
    if (errno != NO_ERROR)
    {
        return errno;
    }

    errno = RT_unlock_mods();
    if (errno != NO_ERROR)
    {
        return errno;
    }

    if (!rt_unlock(runtime))
    {
        return ERR_RUNTIME_UNLOCK;
    }

    // exit current thread
    runtime->ThreadTracker->Exit();
    return NO_ERROR;
}

__declspec(noinline)
errno RT_SleepHR(DWORD dwMilliseconds)
{
    Runtime* runtime = getRuntimePointer();

    if (runtime->WaitForSingleObject(runtime->hMutexSleep, INFINITE) != WAIT_OBJECT_0)
    {
        return ERR_RUNTIME_LOCK_SLEEP;
    }

    if (dwMilliseconds <= 100)
    {
        // prevent sleep too frequent
        dwMilliseconds = 100;
    } else {
        // make sure the sleep time is a multiple of 1s
        dwMilliseconds = (dwMilliseconds / 1000) * 1000;
        if (dwMilliseconds == 0)
        {
            dwMilliseconds = 1000;
        }
    }
    dwMilliseconds = 10; // TODO remove it

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
        runtime->SleepTime = dwMilliseconds;
        if (!runtime->ReleaseMutex(runtime->hMutexEvent))
        {
            errno = ERR_RUNTIME_UNLOCK_EVENT;
            break;
        }
        // notice trigger
        if (!runtime->SetEvent(runtime->hEventArrive))
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
        return ERR_RUNTIME_UNLOCK_SLEEP;
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
        waitEvent = runtime->WaitForSingleObject(runtime->hEventArrive, sleepMS);
        switch (waitEvent)
        {
        case WAIT_OBJECT_0:
            errno = processEvent(runtime, &exit);
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
        if (!runtime->ResetEvent(runtime->hEventArrive))
        {
            return;
        }
        if (!runtime->SetEvent(runtime->hEventDone))
        {
            return;
        }
        // check is exit event
        if (exit)
        {
            return;
        }
        // check error for exit trigger
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

    errno err = RT_lock_mods();
    if (err != NO_ERROR)
    {
        return err;
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

    err = RT_unlock_mods();
    if (err != NO_ERROR)
    {
        return err;
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
        errno = runtime->ThreadTracker->Suspend();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->ArgumentStore->Encrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->ResourceTracker->Encrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->MemoryTracker->Encrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->LibraryTracker->Encrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        break;
    }
    return errno;
}

__declspec(noinline)
static errno recover(Runtime* runtime)
{
    errno errno = NO_ERROR;
    for (;;)
    {
        errno = runtime->LibraryTracker->Decrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->MemoryTracker->Decrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->ResourceTracker->Decrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->ArgumentStore->Decrypt();
        if (errno != NO_ERROR && (errno & ERR_FLAG_CAN_IGNORE) == 0)
        {
            break;
        }
        errno = runtime->ThreadTracker->Resume();
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
    uintptr beginAddress = (uintptr)(runtime->BootInstAddress);
    uintptr runtimeAddr  = (uintptr)(GetFuncAddr(&InitRuntime));
    if (beginAddress == 0 || beginAddress > runtimeAddr)
    {
        beginAddress = runtimeAddr;
    }
    uintptr endAddress = (uintptr)(GetFuncAddr(&Shield_Stub));
    Shield_Ctx ctx = {
        .BeginAddress = beginAddress,
        .EndAddress   = endAddress,
        .SleepTime    = milliseconds,
        .hProcess     = runtime->hProcess,

        .WaitForSingleObject = runtime->WaitForSingleObject,
    };
    // generate random key for shield
    RandBuf(&ctx.CryptoKey[0], sizeof(ctx.CryptoKey));
    // build crypto context
    byte key[CRYPTO_KEY_SIZE];
    byte iv [CRYPTO_IV_SIZE];
    RandBuf(key, CRYPTO_KEY_SIZE);
    RandBuf(iv, CRYPTO_IV_SIZE);
    void* buf = runtime->MainMemPage;
    // encrypt main page
    EncryptBuf(buf, MAIN_MEM_PAGE_SIZE, &key[0], &iv[0]);
    // call shield!!!
    if (!DefenseRT(&ctx))
    {
        return ERR_RUNTIME_DEFENSE_RT;
    }
    // flush instruction cache after decrypt
    void* baseAddr = (void*)beginAddress;
    uint  instSize = (uintptr)(GetFuncAddr(&DefenseRT)) - beginAddress;
    if (!flush(CURRENT_PROCESS, baseAddr, instSize))
    {
        return ERR_RUNTIME_FLUSH_INST_CACHE;
    }
    // decrypt main page
    DecryptBuf(buf, MAIN_MEM_PAGE_SIZE, &key[0], &iv[0]);
    return NO_ERROR;
}

__declspec(noinline)
errno RT_Hide()
{
    Runtime* runtime = getRuntimePointer();

    if (!rt_lock(runtime))
    {
        return ERR_RUNTIME_LOCK;
    }

    errno err = RT_lock_mods();
    if (err != NO_ERROR)
    {
        return err;
    }

    errno errno = hide(runtime);

    err = RT_unlock_mods();
    if (err != NO_ERROR)
    {
        return err;
    }

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

    errno err = RT_lock_mods();
    if (err != NO_ERROR)
    {
        return err;
    }

    errno errno = recover(runtime);

    err = RT_unlock_mods();
    if (err != NO_ERROR)
    {
        return err;
    }

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

    errno err = RT_lock_mods();
    if (err != NO_ERROR)
    {
        return err;
    }

    // must record options before clean runtime
    bool notEraseInst = runtime->NotEraseInstruction;

    // clean runtime modules
    typedef errno (*submodule_t)();
    submodule_t submodules[] = 
    {
        runtime->ThreadTracker->Clean,
        runtime->ArgumentStore->Clean,
        runtime->ResourceTracker->Clean,
        runtime->MemoryTracker->Clean,
        runtime->LibraryTracker->Clean,
    };
    errno enmod = NO_ERROR;
    for (int i = 0; i < arrlen(submodules); i++)
    {
        enmod = submodules[i]();
        if (enmod != NO_ERROR && err == NO_ERROR)
        {
            err = enmod;
        }
    }

    // clean runtime resource
    errno enclr = cleanRuntime(runtime);
    if (enclr != NO_ERROR && err == NO_ERROR)
    {
        err = enclr;
    }

    // erase runtime instructions except this function
    if (!notEraseInst)
    {
        uintptr begin = (uintptr)(GetFuncAddr(&InitRuntime));
        uintptr end   = (uintptr)(GetFuncAddr(&RT_Exit));
        uintptr size  = end - begin;
        eraseMemory(begin, size);
        begin = (uintptr)(GetFuncAddr(&rt_epilogue));
        end   = (uintptr)(GetFuncAddr(&Epilogue));
        size  = end - begin;
        eraseMemory(begin, size);
    }
    return err;
}

// must disable compiler optimize, otherwise eraseMemory()
// will be replaced to the mem_set() in lib_memory.c.
#pragma optimize("", off)
static void eraseMemory(uintptr address, uintptr size)
{
    byte* addr = (byte*)address;
    for (uintptr i = 0; i < size; i++)
    {
        *addr = 0xFF;
        addr++;
    }
}
#pragma optimize("", on)

// prevent it be linked to Epilogue.
#pragma optimize("", off)
static void rt_epilogue()
{
    byte var = 1;
    return;
}
#pragma optimize("", on)
