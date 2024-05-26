#ifndef THREAD_H
#define THREAD_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"

typedef bool (*ThdSuspendAll_t)();
typedef bool (*ThdResumeAll_t)();
typedef bool (*ThdClean_t)();

typedef struct {
    CreateThread_t    CreateThread;
    ExitThread_t      ExitThread;
    SuspendThread_t   SuspendThread;
    ResumeThread_t    ResumeThread;
    TerminateThread_t TerminateThread;

    ThdSuspendAll_t ThdSuspendAll;
    ThdResumeAll_t  ThdResumeAll;
    ThdClean_t      ThdClean;
} ThreadTracker_M;

ThreadTracker_M* InitThreadTracker(Context* context);

#endif // THREAD_H
