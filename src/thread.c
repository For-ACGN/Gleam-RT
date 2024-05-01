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
