#include <stdio.h>
#include "c_types.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

bool TestRuntime_Memory()
{
    uint64* test1 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test1 == NULL)
    {
        return false;
    }
    *test1 = 0x1234567812345600;

    uint64* test2 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test2 == NULL)
    {
        return false;
    }
    *test2 = 0x1234567812345601;

    uint64* test3 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test3 == NULL)
    {
        return false;
    }
    *test3 = 0x1234567812345602;

    errno errno = runtime->Core.Hide();
    if (errno != NO_ERROR)
    {
        printf_s("failed to hide: 0x%X\n", errno);
        return false;
    }
    errno = runtime->Core.Recover();
    if (errno != NO_ERROR)
    {
        printf_s("failed to recover: 0x%X\n", errno);
        return false;
    }

    uint64* test4 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test4 == NULL)
    {
        return false;
    }
    *test4 = 0x1234567812345603;

    runtime->Memory.Free(test3);
    runtime->Memory.Free(test1);

    uint64* test5 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test5 == NULL)
    {
        return false;
    }
    *test5 = 0x1234567812345600;

    errno = runtime->Core.Hide();
    if (errno != NO_ERROR)
    {
        printf_s("failed to hide: 0x%X\n", errno);
        return false;
    }
    errno = runtime->Core.Recover();
    if (errno != NO_ERROR)
    {
        printf_s("failed to recover: 0x%X\n", errno);
        return false;
    }
    errno = runtime->Core.Sleep(1000);
    if (errno != NO_ERROR)
    {
        printf_s("failed to call SleepHR: 0x%X\n", errno);
        return false;
    }

    runtime->Memory.Free(test2);
    runtime->Memory.Free(test4);
    runtime->Memory.Free(test5);
    return true;
}
