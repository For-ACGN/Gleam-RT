#include "go_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "context.h"
#include "random.h"
#include "thread.h"

// hard encoded address in methods for replace
#ifdef _WIN64
    #define METHOD_ADDR_CREATE_THREAD     0x7FFFFFFFFFFFFF10
    #define METHOD_ADDR_EXIT_THREAD       0x7FFFFFFFFFFFFF11
    #define METHOD_ADDR_SUSPEND_THREAD    0x7FFFFFFFFFFFFF12
    #define METHOD_ADDR_RESUME_THREAD     0x7FFFFFFFFFFFFF13
    #define METHOD_ADDR_TERMINATE_THREAD  0x7FFFFFFFFFFFFF14
    #define METHOD_ADDR_SUSPEND_ALL       0x7FFFFFFFFFFFFF15
    #define METHOD_ADDR_RESUME_ALL        0x7FFFFFFFFFFFFF15
    #define METHOD_ADDR_CLEAN             0x7FFFFFFFFFFFFF16
#elif _WIN32
    #define METHOD_ADDR_CREATE_THREAD     0x7FFFFF10
    #define METHOD_ADDR_EXIT_THREAD       0x7FFFFF11
    #define METHOD_ADDR_SUSPEND_THREAD    0x7FFFFF12
    #define METHOD_ADDR_RESUME_THREAD     0x7FFFFF13
    #define METHOD_ADDR_TERMINATE_THREAD  0x7FFFFF14
    #define METHOD_ADDR_SUSPEND_ALL       0x7FFFFF15
    #define METHOD_ADDR_RESUME_ALL        0x7FFFFF15
    #define METHOD_ADDR_CLEAN             0x7FFFFF16
#endif

typedef struct {
    // API addresses
    CreateThread        CreateThread;
    ExitThread          ExitThread;
    SuspendThread       SuspendThread;
    ResumeThread        ResumeThread;
    GetCurrentThread    GetCurrentThread;
    TerminateThread     TerminateThread;
    ReleaseMutex        ReleaseMutex;
    WaitForSingleObject WaitForSingleObject;
    DuplicateHandle     DuplicateHandle;

    HANDLE Mutex;
} ThreadTracker;

// methods about thread tracker
HANDLE TT_CreateThread
(
    uintptr lpThreadAttributes, uint dwStackSize, uintptr lpStartAddress,
    uintptr lpParameter, uint32 dwCreationFlags, uint32* lpThreadId
);
void   TT_ExitThread(uint32 dwExitCode);
uint32 TT_SuspendThread(HANDLE hThread);
uint32 TT_ResumeThread(HANDLE hThread);
bool   TT_TerminateThread(HANDLE hThread, uint32 dwExitCode);
bool   TT_SuspendAll();
bool   TT_ResumeAll();
bool   TT_Clean();

static bool initTrackerAPI(ThreadTracker* tracker, Context* context);
static bool initTrackerEnvironment(ThreadTracker* tracker, Context* context);
static bool updateTrackerPointers(ThreadTracker* tracker);
static bool updateTrackerPointer(ThreadTracker* tracker, void* method, uintptr address);

ThreadTracker_M* InitThreadTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 2000 + RandUint(address) % 256;
    uintptr moduleAddr  = address + 2300 + RandUint(address) % 256;
    // initialize tracker
    ThreadTracker* tracker = (ThreadTracker*)trackerAddr;
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
    ThreadTracker_M* module = (ThreadTracker_M*)moduleAddr;
    // Windows API hooks
    module->CreateThread    = (CreateThread   )(&TT_CreateThread);
    module->ExitThread      = (ExitThread     )(&TT_ExitThread);
    module->SuspendThread   = (SuspendThread  )(&TT_SuspendThread);
    module->ResumeThread    = (ResumeThread   )(&TT_ResumeThread);
    module->TerminateThread = (TerminateThread)(&TT_TerminateThread);
    // methods for runtime
    module->ThdSuspendAll = &TT_SuspendAll;
    module->ThdResumeAll  = &TT_ResumeAll;
    module->ThdClean      = &TT_Clean;
    return module;
}

static bool initTrackerAPI(ThreadTracker* tracker, Context* context)
{

    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    return true;
}

static bool initTrackerEnvironment(ThreadTracker* tracker, Context* context)
{

}

static bool updateTrackerPointers(ThreadTracker* tracker)
{
    typedef struct {
        void* address; uintptr pointer;
    } method;
    method methods[] = 
    {
        { &TT_ExitThread,      METHOD_ADDR_CREATE_THREAD },
        { &TT_SuspendThread,   METHOD_ADDR_EXIT_THREAD },
        { &TT_ResumeThread,    METHOD_ADDR_SUSPEND_THREAD },
        { &TT_TerminateThread, METHOD_ADDR_RESUME_THREAD },
        { &TT_SuspendAll,      METHOD_ADDR_TERMINATE_THREAD },
        { &TT_ResumeAll,       METHOD_ADDR_SUSPEND_ALL },
        { &TT_Clean,           METHOD_ADDR_RESUME_ALL },
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

static bool updateTrackerPointer(ThreadTracker* tracker, void* method, uintptr address)
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
static ThreadTracker* getTrackerPointer(uintptr pointer)
{
    return (ThreadTracker*)(pointer);
}
#pragma optimize("", on)

__declspec(noinline)
HANDLE TT_CreateThread
(
    uintptr lpThreadAttributes, uint dwStackSize, uintptr lpStartAddress,
    uintptr lpParameter, uint32 dwCreationFlags, uint32* lpThreadId
)
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_CREATE_THREAD);

    return NULL;
}

__declspec(noinline)
void TT_ExitThread(uint32 dwExitCode)
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_EXIT_THREAD);

}

__declspec(noinline)
uint32 TT_SuspendThread(HANDLE hThread)
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_SUSPEND_THREAD);

    return NULL;
}

__declspec(noinline)
uint32 TT_ResumeThread(HANDLE hThread)
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_RESUME_THREAD);

    return NULL;
}

__declspec(noinline)
bool TT_TerminateThread(HANDLE hThread, uint32 dwExitCode)
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_TERMINATE_THREAD);

    return NULL;
}

__declspec(noinline)
bool TT_SuspendAll()
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_SUSPEND_ALL);

    return NULL;
}

__declspec(noinline)
bool TT_ResumeAll()
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_RESUME_ALL);

    return NULL;
}

__declspec(noinline)
bool TT_Clean()
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_CLEAN);

    return NULL;
}
