#ifndef THREAD_H
#define THREAD_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"

typedef bool (*ThdSuspend_t)();
typedef bool (*ThdResume_t)();
typedef bool (*ThdClean_t)();

typedef struct {
    CreateThread_t    CreateThread;
    ExitThread_t      ExitThread;
    SuspendThread_t   SuspendThread;
    ResumeThread_t    ResumeThread;
    TerminateThread_t TerminateThread;

    ThdSuspend_t ThdSuspend;
    ThdResume_t  ThdResume;
    ThdClean_t   ThdClean;
} ThreadTracker_M;

ThreadTracker_M* InitThreadTracker(Context* context);

#endif // THREAD_H
