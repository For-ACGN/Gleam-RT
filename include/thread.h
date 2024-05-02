#ifndef THREAD_H
#define THREAD_H

#include "go_types.h"
#include "windows_t.h"
#include "context.h"

// 63KB will extend to 64KB by MemoryTracker.
#define THREADS_PAGE_SIZE (63 * 1024)

typedef bool (*ThdSuspendAll_t)();
typedef bool (*ThdResumeAll_t)();
typedef bool (*ThdClean_t)();

typedef struct {
    CreateThread    CreateThread;
    ExitThread      ExitThread;
    SuspendThread   SuspendThread;
    ResumeThread    ResumeThread;
    TerminateThread TerminateThread;

    ThdSuspendAll_t ThdSuspendAll;
    ThdResumeAll_t  ThdResumeAll;
    ThdClean_t      ThdClean;
} ThreadTracker_M;

ThreadTracker_M* InitThreadTracker(Context* context);

#endif // THREAD_H
