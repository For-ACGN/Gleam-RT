#ifndef THREAD_H
#define THREAD_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"
#include "errno.h"

typedef HANDLE (*ThdNew_t)(uintptr address, void* parameter);
typedef void   (*ThdExit_t)();
typedef errno  (*ThdSuspend_t)();
typedef errno  (*ThdResume_t)();
typedef errno  (*ThdClean_t)();

typedef struct {
    CreateThread_t     CreateThread;
    ExitThread_t       ExitThread;
    SuspendThread_t    SuspendThread;
    ResumeThread_t     ResumeThread;
    GetThreadContext_t GetThreadContext;
    SetThreadContext_t SetThreadContext;
    SwitchToThread_t   SwitchToThread;
    TerminateThread_t  TerminateThread;

    ThdNew_t     ThdNew;
    ThdExit_t    ThdExit;
    ThdSuspend_t ThdSuspend;
    ThdResume_t  ThdResume;
    ThdClean_t   ThdClean;
} ThreadTracker_M;

ThreadTracker_M* InitThreadTracker(Context* context);

#endif // THREAD_H
