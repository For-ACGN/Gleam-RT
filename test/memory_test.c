#include <stdio.h>
#include "c_types.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

 bool TestRuntime_Memory()
{
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

    errno errno;

    errno = runtime->Hide();
    if (errno != NO_ERROR)
    {
        printf_s("error: %X\n", errno);
        return false;
    }
    errno = runtime->Recover();
    if (errno != NO_ERROR)
    {
        printf_s("error: %X\n", errno);
        return false;
    }

    uint64* test4 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test4 == NULL)
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

    errno = runtime->Hide();
    if (errno != NO_ERROR)
    {
        printf_s("error: %X\n", errno);
        return false;
    }
    errno = runtime->Recover();
    if (errno != NO_ERROR)
    {
        printf_s("error: %X\n", errno);
        return false;
    }
    errno = runtime->SleepHR(1000);
    if (errno != NO_ERROR)
    {
        printf_s("error: %X\n", errno);
        return false;
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

    return true;
}
