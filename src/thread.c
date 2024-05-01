#include "go_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "context.h"
#include "random.h"
#include "thread.h"

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

    tracker->ReleaseMutex = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    return true;
}

static bool initTrackerEnvironment(ThreadTracker* tracker, Context* context)
{

}

static bool updateTrackerPointers(ThreadTracker* tracker)
{


}

static bool updateTrackerPointer(ThreadTracker* tracker, void* method, uintptr address)
{
    bool    success = false;
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

__declspec(noinline)
HANDLE TT_CreateThread
(
    uintptr lpThreadAttributes, uint dwStackSize, uintptr lpStartAddress,
    uintptr lpParameter, uint32 dwCreationFlags, uint32* lpThreadId
)
{

}

__declspec(noinline)
void TT_ExitThread(uint32 dwExitCode)
{

}

__declspec(noinline)
uint32 TT_SuspendThread(HANDLE hThread)
{

}

__declspec(noinline)
uint32 TT_ResumeThread(HANDLE hThread)
{

}

__declspec(noinline)
bool TT_TerminateThread(HANDLE hThread, uint32 dwExitCode)
{

}

__declspec(noinline)
bool TT_SuspendAll()
{

}

__declspec(noinline)
bool TT_ResumeAll()
{

}

__declspec(noinline)
bool TT_Clean()
{

}
