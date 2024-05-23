#include <stdio.h>
#include "c_types.h"
#include "runtime.h"
#include "test.h"

static bool TestRuntimeMemory(Runtime_M* runtime);

bool TestRuntime()
{
    Runtime_Opts opts = {
        .NotAdjustProtect = false,
    };
    Runtime_M* runtime = InitRuntime(&opts);
    if (runtime <= (Runtime_M*)(0xFF))
    {
        printf("failed to initialize runtime");
        return false;
    }

    if (!TestRuntimeMemory(runtime))
    {
        return false;
    }

    return true;
}

static bool TestRuntimeMemory(Runtime_M* runtime)
{
    printf("======TestRuntimeAlloc begin=======\n");

    uint64* test1 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test1 == NULL)
    {
        return -1;
    }
    *test1 = 0x1234567812345600;

    uint64* test2 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test2 == NULL)
    {
        return -1;
    }
    *test2 = 0x1234567812345601;

    uint64* test3 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test3 == NULL)
    {
        return -1;
    }
    *test3 = 0x1234567812345602;

    if (!runtime->Hide())
    {
        return -8;
    }
    if (!runtime->Recover())
    {
        return -9;
    }

    uint64* test4 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test3 == NULL)
    {
        return -1;
    }
    *test4 = 0x1234567812345603;

    if (!runtime->MemFree(test3))
    {
        return -1;
    }
    if (!runtime->MemFree(test1))
    {
        return -1;
    }
    uint64* test5 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test5 == NULL)
    {
        return -1;
    }
    *test5 = 0x1234567812345600;


    if (!runtime->Hide())
    {
        return -3;
    }
    if (!runtime->Recover())
    {
        return -4;
    }

    if (!runtime->Sleep(1000))
    {
        return -100;
    }

    if (!runtime->MemFree(test2))
    {
        return -1;
    }
    if (!runtime->MemFree(test4))
    {
        return -1;
    }
    if (!runtime->MemFree(test5))
    {
        return -1;
    }

    if (!runtime->Stop())
    {
        return -5;
    }

    printf("======TestRuntimeAlloc passed======\n\n");
    return true;
}
