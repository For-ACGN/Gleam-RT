#include "go_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "context.h"
#include "random.h"
#include "thread.h"

// hard encoded address in methods for replace
#ifdef _WIN64
    #define METHOD_ADDR_CREATE_THREAD    0x7FFFFFFFFFFFFF10
    #define METHOD_ADDR_EXIT_THREAD      0x7FFFFFFFFFFFFF11
    #define METHOD_ADDR_SUSPEND_THREAD   0x7FFFFFFFFFFFFF12
    #define METHOD_ADDR_RESUME_THREAD    0x7FFFFFFFFFFFFF13
    #define METHOD_ADDR_TERMINATE_THREAD 0x7FFFFFFFFFFFFF14
    #define METHOD_ADDR_SUSPEND_ALL      0x7FFFFFFFFFFFFF15
    #define METHOD_ADDR_RESUME_ALL       0x7FFFFFFFFFFFFF16
    #define METHOD_ADDR_CLEAN            0x7FFFFFFFFFFFFF17
#elif _WIN32
    #define METHOD_ADDR_CREATE_THREAD    0x7FFFFF10
    #define METHOD_ADDR_EXIT_THREAD      0x7FFFFF11
    #define METHOD_ADDR_SUSPEND_THREAD   0x7FFFFF12
    #define METHOD_ADDR_RESUME_THREAD    0x7FFFFF13
    #define METHOD_ADDR_TERMINATE_THREAD 0x7FFFFF14
    #define METHOD_ADDR_SUSPEND_ALL      0x7FFFFF15
    #define METHOD_ADDR_RESUME_ALL       0x7FFFFF16
    #define METHOD_ADDR_CLEAN            0x7FFFFF17
#endif

#define MAX_NUM_THREADS (THREADS_PAGE_SIZE / sizeof(thread))

typedef struct {
    uint32 threadID;
    HANDLE hThread;
} thread;

typedef struct {
    // API addresses
    CreateThread        CreateThread;
    ExitThread          ExitThread;
    SuspendThread       SuspendThread;
    ResumeThread        ResumeThread;
    GetThreadID         GetThreadID;
    GetCurrentThreadID  GetCurrentThreadID;
    TerminateThread     TerminateThread;
    ReleaseMutex        ReleaseMutex;
    WaitForSingleObject WaitForSingleObject;
    DuplicateHandle     DuplicateHandle;
    CloseHandle         CloseHandle;

    // store all threads info
    uint32  NumThreads;
    thread* Threads;

    HANDLE Mutex;
} ThreadTracker;

// methods about thread tracker
HANDLE TT_CreateThread(
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
static bool addThread(ThreadTracker* tracker, uint32 threadID, HANDLE hThread);
static bool delThread(ThreadTracker* tracker, uint32 threadID);

ThreadTracker_M* InitThreadTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 2000 + RandUint(address) % 256;
    uintptr moduleAddr  = address + 2300 + RandUint(address) % 256;
    // initialize tracker
    ThreadTracker* tracker = (ThreadTracker*)trackerAddr;
    uint errCode = 0;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errCode = 0x11;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errCode = 0x12;
            break;
        }
        if (!updateTrackerPointers(tracker))
        {
            errCode = 0x13;
            break;
        }
        break;
    }
    if (errCode != 0x00)
    {
        return (ThreadTracker_M*)errCode;
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
    typedef struct { 
        uint hash; uint key; uintptr address;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0x430932D6A2AC04EA, 0x9AF52A6480DA3C93 }, // CreateThread
        { 0x91238A1B4E365AB0, 0x6C621931AE641330 }, // ExitThread
        { 0x3A4D5132CF0D20D8, 0x89E05A81B86A26AE }, // SuspendThread
        { 0xB1917786CE5B5A94, 0x6BC3328C112C6DDA }, // ResumeThread
        { 0x5133BE509803E44E, 0x20498B6AFFAED91B }, // GetThreadId
        { 0x9AF119F551D952CF, 0x5A1B9D61A26B22D7 }, // GetCurrentThreadId
        { 0xFB891A810F1ABF9A, 0x253BBD721EBD81F0 }, // TerminateThread
        { 0xF7A5A49D19409FFC, 0x6F23FAA4C20FF4D3 }, // DuplicateHandle
    };
#elif _WIN32
    {
        { 0xB9D69C9D, 0xCAB90EB6 }, // CreateThread
        { 0x1D1F85DD, 0x41A9BD17 }, // ExitThread
        { 0x26C71141, 0xF3C390BD }, // SuspendThread
        { 0x20FFDC31, 0x1D4EA347 }, // ResumeThread
        { 0xFE77EB3E, 0x81CB68B1 }, // GetThreadId
        { 0x2884E5D9, 0xA933632C }, // GetCurrentThreadId
        { 0xBA134972, 0x295F9DD2 }, // TerminateThread
        { 0x0E7ED8B9, 0x025067E9 }, // DuplicateHandle
    };
#endif
    uintptr address;
    for (int i = 0; i < arrlen(list); i++)
    {
        address = context->FindAPI(list[i].hash, list[i].key);
        if (address == NULL)
        {
            return false;
        }
        list[i].address = address;
    }

    tracker->CreateThread       = (CreateThread      )(list[0].address);
    tracker->ExitThread         = (ExitThread        )(list[1].address);
    tracker->SuspendThread      = (SuspendThread     )(list[2].address);
    tracker->ResumeThread       = (ResumeThread      )(list[3].address);
    tracker->GetThreadID        = (GetThreadID       )(list[4].address);
    tracker->GetCurrentThreadID = (GetCurrentThreadID)(list[5].address);
    tracker->TerminateThread    = (TerminateThread   )(list[6].address);
    tracker->DuplicateHandle    = (DuplicateHandle   )(list[7].address);

    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    tracker->CloseHandle         = context->CloseHandle;
    return true;
}

static bool initTrackerEnvironment(ThreadTracker* tracker, Context* context)
{
    thread* threads = (thread*)context->TTMemPage;
    tracker->NumThreads = 0;
    tracker->Threads    = threads;
    // clean memory page
    for (int i = 0; i < MAX_NUM_THREADS; i++)
    {
        threads->threadID = 0;
        threads->hThread = NULL;
        threads++;
    }
    tracker->Mutex = context->Mutex;
    return true;
}

static bool updateTrackerPointers(ThreadTracker* tracker)
{
    typedef struct {
        void* address; uintptr pointer;
    } method;
    method methods[] = 
    {
        { &TT_CreateThread,    METHOD_ADDR_CREATE_THREAD },
        { &TT_ExitThread,      METHOD_ADDR_EXIT_THREAD },
        { &TT_SuspendThread,   METHOD_ADDR_SUSPEND_THREAD },
        { &TT_ResumeThread,    METHOD_ADDR_RESUME_THREAD },
        { &TT_TerminateThread, METHOD_ADDR_TERMINATE_THREAD },
        { &TT_SuspendAll,      METHOD_ADDR_SUSPEND_ALL },
        { &TT_ResumeAll,       METHOD_ADDR_RESUME_ALL },
        { &TT_Clean,           METHOD_ADDR_CLEAN},
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
HANDLE TT_CreateThread(
    uintptr lpThreadAttributes, uint dwStackSize, uintptr lpStartAddress,
    uintptr lpParameter, uint32 dwCreationFlags, uint32* lpThreadId
)
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_CREATE_THREAD);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return NULL;
    }

    uint32 threadID;
    HANDLE hThread;

    bool success = true;
    for (;;)
    {
        hThread = tracker->CreateThread(
            lpThreadAttributes, dwStackSize, lpStartAddress,
            lpParameter, dwCreationFlags, &threadID
        );
        if (hThread == NULL)
        {
            success = false;
            break;
        }
        if (!addThread(tracker, threadID, hThread))
        {
            success = false;
            break;
        }
        break;
    }

    tracker->ReleaseMutex(tracker->Mutex);

    if (!success)
    {
        return NULL;
    }
    *lpThreadId = threadID;
    return hThread;
}

static bool addThread(ThreadTracker* tracker, uint32 threadID, HANDLE hThread)
{
    if (tracker->NumThreads >= MAX_NUM_THREADS)
    {
        return false;
    }

    // clone handle

    // search space for store structure
    thread* threads = tracker->Threads;
    thread* thread  = NULL; 
    for (int i = 0; i <= MAX_NUM_THREADS; i++)
    {
        if (threads->threadID != 0 || threads->hThread != NULL)
        {
            threads++;
            continue;
        }
        thread = threads;
        break;
    }
    if (thread == NULL)
    {
        return false;
    }
    threads->threadID = threadID;
    threads->hThread  = hThread;
    tracker->NumThreads++;
    return true;
}

__declspec(noinline)
void TT_ExitThread(uint32 dwExitCode)
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_EXIT_THREAD);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return;
    }

    tracker->ReleaseMutex(tracker->Mutex);
}

static bool delThread(ThreadTracker* tracker, uint32 threadID)
{
    // search the target structure
    thread* threads = tracker->Threads;
    thread* thread  = NULL;
    for (int i = 0; i <= MAX_NUM_THREADS; i++)
    {
        if (threads->threadID != threadID)
        {
            threads++;
            continue;
        }
        thread = threads;
        break;
    }
    if (thread == NULL)
    {
        return false;
    }

    // Close Handle

    threads->threadID = 0;
    threads->hThread  = NULL;
    tracker->NumThreads--;
    return true;
}

__declspec(noinline)
uint32 TT_SuspendThread(HANDLE hThread)
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_SUSPEND_THREAD);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return -1;
    }

    tracker->ReleaseMutex(tracker->Mutex);

    return NULL;
}

__declspec(noinline)
uint32 TT_ResumeThread(HANDLE hThread)
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_RESUME_THREAD);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return -1;
    }

    tracker->ReleaseMutex(tracker->Mutex);

    return NULL;
}

__declspec(noinline)
bool TT_TerminateThread(HANDLE hThread, uint32 dwExitCode)
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_TERMINATE_THREAD);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    tracker->ReleaseMutex(tracker->Mutex);

    return NULL;
}

__declspec(noinline)
bool TT_SuspendAll()
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_SUSPEND_ALL);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    tracker->ReleaseMutex(tracker->Mutex);

    return NULL;
}

__declspec(noinline)
bool TT_ResumeAll()
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_RESUME_ALL);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    tracker->ReleaseMutex(tracker->Mutex);
    return NULL;
}

__declspec(noinline)
bool TT_Clean()
{
    ThreadTracker* tracker = getTrackerPointer(METHOD_ADDR_CLEAN);

    if (tracker->WaitForSingleObject(tracker->Mutex, INFINITE) != WAIT_OBJECT_0)
    {
        return false;
    }

    tracker->ReleaseMutex(tracker->Mutex);
    return NULL;
}
