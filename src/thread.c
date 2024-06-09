#include <stdio.h>

#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
#include "hash_api.h"
#include "list_md.h"
#include "win_api.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "thread.h"

typedef struct {
    uint32 threadID;
    HANDLE hThread;
} thread;

typedef struct {
    // API addresses
    CreateThread_t        CreateThread;
    ExitThread_t          ExitThread;
    SuspendThread_t       SuspendThread;
    ResumeThread_t        ResumeThread;
    GetThreadContext_t    GetThreadContext;
    SetThreadContext_t    SetThreadContext;
    SwitchToThread_t      SwitchToThread;
    GetThreadID_t         GetThreadID;
    GetCurrentThreadID_t  GetCurrentThreadID;
    TerminateThread_t     TerminateThread;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    DuplicateHandle_t     DuplicateHandle;
    CloseHandle_t         CloseHandle;

    // runtime data
    HANDLE Mutex; // global mutex

    // store all threads info
    List Threads;
    byte ThreadsKey[CRYPTO_KEY_SIZE];
    byte ThreadsIV [CRYPTO_IV_SIZE];
} ThreadTracker;

// methods about thread tracker
HANDLE TT_CreateThread(
    uintptr lpThreadAttributes, uint dwStackSize, uintptr lpStartAddress,
    uintptr lpParameter, uint32 dwCreationFlags, uint32* lpThreadId
);
void   TT_ExitThread(uint32 dwExitCode);
uint32 TT_SuspendThread(HANDLE hThread);
uint32 TT_ResumeThread(HANDLE hThread);
bool   TT_GetThreadContext(HANDLE hThread, CONTEXT* lpContext);
bool   TT_SetThreadContext(HANDLE hThread, CONTEXT* lpContext);
bool   TT_SwitchToThread();
bool   TT_TerminateThread(HANDLE hThread, uint32 dwExitCode);
HANDLE TT_ThdNew(uintptr address, void* parameter);
void   TT_ThdExit();
errno  TT_Suspend();
errno  TT_Resume();
errno  TT_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF11111103
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCD03
#endif
static ThreadTracker* getTrackerPointer();

static bool tt_lock(ThreadTracker* tracker);
static bool tt_unlock(ThreadTracker* tracker);

static bool  initTrackerAPI(ThreadTracker* tracker, Context* context);
static bool  updateTrackerPointer(ThreadTracker* tracker);
static bool  initTrackerEnvironment(ThreadTracker* tracker, Context* context);
static void* camouflageStartAddress(uintptr seed);
static bool  addThread(ThreadTracker* tracker, uint32 threadID, HANDLE hThread);
static void  delThread(ThreadTracker* tracker, uint32 threadID);

static void eraseTrackerMethods();
static void cleanTracker(ThreadTracker* tracker);

ThreadTracker_M* InitThreadTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 3000 + RandUint(address) % 128;
    uintptr moduleAddr  = address + 3600 + RandUint(address) % 128;
    // initialize tracker
    ThreadTracker* tracker = (ThreadTracker*)trackerAddr;
    mem_clean(tracker, sizeof(ThreadTracker));
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errno = ERR_THREAD_INIT_API;
            break;
        }
        if (!updateTrackerPointer(tracker))
        {
            errno = ERR_THREAD_UPDATE_PTR;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errno = ERR_THREAD_INIT_ENV;
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
    ThreadTracker_M* module = (ThreadTracker_M*)moduleAddr;
    // Windows API hooks
    module->CreateThread     = (CreateThread_t    )(&TT_CreateThread);
    module->ExitThread       = (ExitThread_t      )(&TT_ExitThread);
    module->SuspendThread    = (SuspendThread_t   )(&TT_SuspendThread);
    module->ResumeThread     = (ResumeThread_t    )(&TT_ResumeThread);
    module->GetThreadContext = (GetThreadContext_t)(&TT_GetThreadContext);
    module->SetThreadContext = (SetThreadContext_t)(&TT_SetThreadContext);
    module->SwitchToThread   = (SwitchToThread_t  )(&TT_SwitchToThread);
    module->TerminateThread  = (TerminateThread_t )(&TT_TerminateThread);
    // methods for runtime
    module->ThdNew     = &TT_ThdNew;
    module->ThdExit    = &TT_ThdExit;
    module->ThdSuspend = &TT_Suspend;
    module->ThdResume  = &TT_Resume;
    module->ThdClean   = &TT_Clean;
    return module;
}

__declspec(noinline)
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
        { 0x59361F47711B4B27, 0xB97411CC715D4940 }, // GetThreadContext
        { 0xFB9A4AF393D77518, 0xA0CA2E8823A27560 }, // SetThreadContext
        { 0x57E7340503265A2F, 0x0318A4D79F9670AC }, // SwitchToThread
        { 0x5133BE509803E44E, 0x20498B6AFFAED91B }, // GetThreadId
        { 0x9AF119F551D952CF, 0x5A1B9D61A26B22D7 }, // GetCurrentThreadId
        { 0xFB891A810F1ABF9A, 0x253BBD721EBD81F0 }, // TerminateThread
    };
#elif _WIN32
    {
        { 0xB9D69C9D, 0xCAB90EB6 }, // CreateThread
        { 0x1D1F85DD, 0x41A9BD17 }, // ExitThread
        { 0x26C71141, 0xF3C390BD }, // SuspendThread
        { 0x20FFDC31, 0x1D4EA347 }, // ResumeThread
        { 0x25EF3A63, 0xAFA67C4F }, // GetThreadContext
        { 0x2729A1C9, 0x3A57FF5D }, // SetThreadContext
        { 0xAA143570, 0x2398ADFB }, // SwitchToThread
        { 0xFE77EB3E, 0x81CB68B1 }, // GetThreadId
        { 0x2884E5D9, 0xA933632C }, // GetCurrentThreadId
        { 0xBA134972, 0x295F9DD2 }, // TerminateThread
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

    tracker->CreateThread       = (CreateThread_t      )(list[0].address);
    tracker->ExitThread         = (ExitThread_t        )(list[1].address);
    tracker->SuspendThread      = (SuspendThread_t     )(list[2].address);
    tracker->ResumeThread       = (ResumeThread_t      )(list[3].address);
    tracker->GetThreadContext   = (GetThreadContext_t  )(list[4].address);
    tracker->SetThreadContext   = (SetThreadContext_t  )(list[5].address);
    tracker->SwitchToThread     = (SwitchToThread_t    )(list[6].address);
    tracker->GetThreadID        = (GetThreadID_t       )(list[7].address);
    tracker->GetCurrentThreadID = (GetCurrentThreadID_t)(list[8].address);
    tracker->TerminateThread    = (TerminateThread_t   )(list[9].address);

    tracker->ReleaseMutex        = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    tracker->DuplicateHandle     = context->DuplicateHandle;
    tracker->CloseHandle         = context->CloseHandle;
    return true;
}

__declspec(noinline)
static bool updateTrackerPointer(ThreadTracker* tracker)
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
static bool initTrackerEnvironment(ThreadTracker* tracker, Context* context)
{
    // copy runtime context data
    tracker->Mutex = context->Mutex;
    // initialize thread list
    List_Ctx ctx = {
        .malloc  = context->malloc,
        .realloc = context->realloc,
        .free    = context->free,
    };
    List_Init(&tracker->Threads, &ctx, sizeof(thread));
    // set crypto context data
    RandBuf(&tracker->ThreadsKey[0], CRYPTO_KEY_SIZE);
    RandBuf(&tracker->ThreadsIV[0], CRYPTO_IV_SIZE);
    // add current thread for special executable file like Golang
    if (context->TrackCurrentThread)
    {
        uint32 threadID = tracker->GetCurrentThreadID();
        if (threadID == 0)
        {
            return false;
        }
        if (!addThread(tracker, threadID, CURRENT_THREAD))
        {
            return false;
        }
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
static void cleanTracker(ThreadTracker* tracker)
{
    List* threads = &tracker->Threads;

    // close already tracked handles
    uint index = 0;
    for (uint num = 0; num < threads->Len; index++)
    {
        thread* thread = List_Get(threads, index);
        if (thread->threadID == 0)
        {
            continue;
        }
        if (tracker->CloseHandle != NULL)
        {
            tracker->CloseHandle(thread->hThread);
        }
        num++;
    }

    List_Free(threads);
}

// updateTrackerPointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateTrackerPointer will fail.
#pragma optimize("", off)
static ThreadTracker* getTrackerPointer()
{
    uint pointer = TRACKER_POINTER;
    return (ThreadTracker*)(pointer);
}
#pragma optimize("", on)

static bool tt_lock(ThreadTracker* tracker)
{
    uint32 event = tracker->WaitForSingleObject(tracker->Mutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

static bool tt_unlock(ThreadTracker* tracker)
{
    return tracker->ReleaseMutex(tracker->Mutex);
}

__declspec(noinline)
HANDLE TT_CreateThread(
    uintptr lpThreadAttributes, uint dwStackSize, uintptr lpStartAddress,
    uintptr lpParameter, uint32 dwCreationFlags, uint32* lpThreadId
)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!tt_lock(tracker))
    {
        return NULL;
    }

    uint32 threadID;
    HANDLE hThread = NULL;

    bool success = true;
    for (;;)
    {
        // create thread from camouflaged start address and pause it
        bool    resume   = (dwCreationFlags & 0xF) != CREATE_SUSPENDED;
        uintptr fakeAddr = camouflageStartAddress(lpStartAddress);
        dwCreationFlags  |= CREATE_SUSPENDED;

 

        hThread = tracker->CreateThread(
            lpThreadAttributes, dwStackSize, lpStartAddress,
            lpParameter, dwCreationFlags, &threadID
        );
        if (hThread == NULL)
        {
            success = false;
            break;
        }


        // set the RIP/EIP to the actual start address
        // tracker->WaitForSingleObject(hThread, 1000);


        CONTEXT ctx;
        if (!tracker->GetThreadContext(hThread, &ctx))
        {
            success = false;
            break;
        }
    #ifdef _WIN64
        printf("rsp: 0x%X\n", dwCreationFlags);

        printf("rsp: 0x%llX\n", ctx.RSP);

        if (ctx.RSP > 16)
        {
            // ctx.RSP -= sizeof(uintptr);
            // mem_copy((void*)(ctx.RSP), &fakeAddr, sizeof(uintptr));
        }

        


        ctx.RIP = lpStartAddress;
    #elif _WIN32
        ctx.EIP = lpStartAddress;
    #endif
        if (!tracker->SetThreadContext(hThread, &ctx))
        {
            success = false;
            break;
        }
        // resume the thread
        if (resume && !tracker->ResumeThread(hThread))
        {
            success = false;
            break;
        }
        if (!addThread(tracker, threadID, hThread))
        {
            tracker->TerminateThread(hThread, 0);
            success = false;
            break;
        }
        printf("fake start: %llX\n", fakeAddr);
        printf("CreateThread: 0x%llX, %lu\n", lpStartAddress, threadID);
        break;
    }

    if (!tt_unlock(tracker))
    {
        return NULL;
    }

    if (!success)
    {
        if (hThread != NULL)
        {
            tracker->CloseHandle(hThread);
        }
        return NULL;
    }
    if (lpThreadId != NULL)
    {
        *lpThreadId = threadID;
    }
    return hThread;
}

static void* camouflageStartAddress(uintptr seed)
{
    // get current process module from PEB
#ifdef _WIN64
    uintptr peb = __readgsqword(96);
    uintptr ldr = *(uintptr*)(peb + 24);
    uintptr mod = *(uintptr*)(ldr + 32);
#elif _WIN32
    uintptr peb = __readfsdword(48);
    uintptr ldr = *(uintptr*)(peb + 12);
    uintptr mod = *(uintptr*)(ldr + 20);
#endif
    // get current process module address
#ifdef _WIN64
    uintptr modAddr = *(uintptr*)(mod + 32);
#elif _WIN32
    uintptr modAddr = *(uintptr*)(mod + 16);
#endif
    // parse module information
    PE_Info info;
    ParsePEImage(modAddr, &info);
    // select a random start address
    uintptr begin = modAddr + info.TextVirtualAddress;
    uintptr range = RandUint((uint64)seed) % info.TextSizeOfRawData;


    // TODO change it
    begin += 7;
    return begin;




    return begin+range;
}

static bool addThread(ThreadTracker* tracker, uint32 threadID, HANDLE hThread)
{
    // duplicate thread handle
    HANDLE dupHandle;
    if (!tracker->DuplicateHandle(
        CURRENT_PROCESS, hThread, CURRENT_PROCESS, &dupHandle,
        0, false, DUPLICATE_SAME_ACCESS
    )){
        return false;
    }
    thread thread = {
        .threadID = threadID,
        .hThread  = dupHandle,
    };
    if (!List_Insert(&tracker->Threads, &thread))
    {
        tracker->CloseHandle(dupHandle);
        return false;
    }
    return true;
}

__declspec(noinline)
void TT_ExitThread(uint32 dwExitCode)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!tt_lock(tracker))
    {
        return;
    }

    uint32 threadID = tracker->GetCurrentThreadID();
    if (threadID != 0)
    {
        delThread(tracker, threadID);
    }

    printf("ExitThread: %lu\n", threadID);

    if (!tt_unlock(tracker))
    {
        return;
    }
    tracker->ExitThread(dwExitCode);
}

static void delThread(ThreadTracker* tracker, uint32 threadID)
{
    List* threads = &tracker->Threads;
    thread thread = {
        .threadID = threadID,
    };
    uint index;
    if (!List_Find(threads, &thread, sizeof(thread.threadID), &index))
    {
        return;
    }
    if (!List_Delete(threads, index))
    {
        return;
    }
    tracker->CloseHandle(thread.hThread);
}

__declspec(noinline)
uint32 TT_SuspendThread(HANDLE hThread)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!tt_lock(tracker))
    {
        return -1;
    }
   
    uint32 count;
    uint32 threadID = tracker->GetThreadID(hThread);
    printf("SuspendThread: %lu\n", threadID);
    if (threadID == tracker->GetCurrentThreadID() || threadID == 0)
    {
        if (!tt_unlock(tracker))
        {
            return -1;
        }
        count = tracker->SuspendThread(hThread);
    } else {
        count = tracker->SuspendThread(hThread);
        if (!tt_unlock(tracker))
        {
            return -1;
        }
    }
    return count;
}

__declspec(noinline)
uint32 TT_ResumeThread(HANDLE hThread)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!tt_lock(tracker))
    {
        return -1;
    }

    uint32 count = tracker->ResumeThread(hThread);

    printf("ResumeThread: %llu\n", hThread);

    if (!tt_unlock(tracker))
    {
        return -1;
    }
    return count;
}

__declspec(noinline)
bool TT_GetThreadContext(HANDLE hThread, CONTEXT* lpContext)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!tt_lock(tracker))
    {
        return false;
    }

    bool success = tracker->GetThreadContext(hThread, lpContext);

    printf("GetThreadContext: %llu\n", hThread);

    if (!tt_unlock(tracker))
    {
        return false;
    }
    return success;
}

__declspec(noinline)
bool TT_SetThreadContext(HANDLE hThread, CONTEXT* lpContext)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!tt_lock(tracker))
    {
        return false;
    }

    bool success = tracker->SetThreadContext(hThread, lpContext);

    printf("SetThreadContext: %llu\n", hThread);

    if (!tt_unlock(tracker))
    {
        return false;
    }
    return success;
}

__declspec(noinline)
bool TT_SwitchToThread()
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!tt_lock(tracker))
    {
        return false;
    }

    bool success = tracker->SwitchToThread();

    printf("SwitchToThread\n");

    if (!tt_unlock(tracker))
    {
        return false;
    }
    return success;
}

__declspec(noinline)
bool TT_TerminateThread(HANDLE hThread, uint32 dwExitCode)
{
    ThreadTracker* tracker = getTrackerPointer();

    if (!tt_lock(tracker))
    {
        return false;
    }

    uint32 threadID = tracker->GetThreadID(hThread);
    if (threadID != 0)
    {
        delThread(tracker, threadID);
    }

    printf("TerminateThread: %lu\n", threadID);

    if (!tt_unlock(tracker))
    {
        return false;
    }
    return tracker->TerminateThread(hThread, dwExitCode);
}

__declspec(noinline)
HANDLE TT_ThdNew(uintptr address, void* parameter)
{
    return TT_CreateThread(0, 0, address, (uintptr)parameter, 0, NULL);
}

__declspec(noinline)
void TT_ThdExit()
{
    TT_ExitThread(0);
}

__declspec(noinline)
errno TT_Suspend()
{
    ThreadTracker* tracker = getTrackerPointer();

    uint32 currentTID = tracker->GetCurrentThreadID();
    if (currentTID == 0)
    {
        return ERR_THREAD_GET_CURRENT_TID;
    }

    List* threads = &tracker->Threads;
    errno errno   = NO_ERROR;

    // suspend threads
    uint index = 0;
    for (uint num = 0; num < threads->Len; index++)
    {
        thread* thread = List_Get(threads, index);
        if (thread->threadID == 0)
        {
            continue;
        }
        // skip self thread
        if (thread->threadID == currentTID)
        {
            num++;
            continue;
        }
        uint32 count = tracker->SuspendThread(thread->hThread);
        if (count == -1)
        {
            delThread(tracker, thread->threadID);
            errno = ERR_THREAD_SUSPEND;
        }
        num++;
    }

    // encrypt thread list
    List* list = &tracker->Threads;
    byte* key  = &tracker->ThreadsKey[0];
    byte* iv   = &tracker->ThreadsIV[0];
    RandBuf(key, CRYPTO_KEY_SIZE);
    RandBuf(iv, CRYPTO_IV_SIZE);
    EncryptBuf(list->Data, List_Size(list), key, iv);
    return errno;
}

__declspec(noinline)
errno TT_Resume()
{
    ThreadTracker* tracker = getTrackerPointer();

    uint32 currentTID = tracker->GetCurrentThreadID();
    if (currentTID == 0)
    {
        return ERR_THREAD_GET_CURRENT_TID;
    }

    // decrypt thread list
    List* list = &tracker->Threads;
    byte* key  = &tracker->ThreadsKey[0];
    byte* iv   = &tracker->ThreadsIV[0];
    DecryptBuf(list->Data, List_Size(list), key, iv);

    List* threads = &tracker->Threads;
    errno errno   = NO_ERROR;

    // resume threads
    uint index = 0;
    for (uint num = 0; num < threads->Len; index++)
    {
        thread* thread = List_Get(threads, index);
        if (thread->threadID == 0)
        {
            continue;
        }
        // skip self thread
        if (thread->threadID == currentTID)
        {
            num++;
            continue;
        }
        // resume loop until count is zero
        for (;;)
        {
            uint32 count = tracker->ResumeThread(thread->hThread);
            if (count == -1)
            {
                delThread(tracker, thread->threadID);
                errno = ERR_THREAD_RESUME;
                break;
            }
            if (count <= 1)
            {
                break;
            }
        }
        num++;
    }
    return errno;
}

__declspec(noinline)
errno TT_Clean()
{
    ThreadTracker* tracker = getTrackerPointer();

    uint32 currentTID = tracker->GetCurrentThreadID();
    if (currentTID == 0)
    {
        return ERR_THREAD_GET_CURRENT_TID;
    }

    List* threads = &tracker->Threads;
    errno errno   = NO_ERROR;

    // terminate threads
    uint index = 0;
    for (uint num = 0; num < threads->Len; index++)
    {
        thread* thread = List_Get(threads, index);
        if (thread->threadID == 0)
        {
            continue;
        }
        // skip self thread
        if (thread->threadID != currentTID)
        {
            if (!tracker->TerminateThread(thread->hThread, 0))
            {
                errno = ERR_THREAD_TERMINATE;
            }
        }
        if (!tracker->CloseHandle(thread->hThread))
        {
            errno = ERR_THREAD_CLOSE_HANDLE;
        }
        num++;
    }

    // clean thread list
    RandBuf(threads->Data, List_Size(threads));
    if (!List_Free(threads))
    {
        errno = ERR_THREAD_FREE_LIST;
    }
    return errno;
}
