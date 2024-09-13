#include <stdio.h>
#include "c_types.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

bool TestInitRuntime()
{
    Runtime_Opts opts = {
        .BootInstAddress     = NULL,
        .NotEraseInstruction = true,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
    runtime = InitRuntime(&opts);
    if (runtime == NULL)
    {
        printf_s("failed to initialize runtime: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}

bool TestRuntime_Exit()
{
    errno errno = runtime->Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit runtime: 0x%X\n", errno);
        return false;
    }
    errno = GetLastErrno();
    if (errno != NO_ERROR)
    {
        printf_s("find last errno: 0x%X\n", errno);
        return false;
    }
    return true;
}
