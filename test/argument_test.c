#include <stdio.h>
#include "c_types.h"
#include "lib_string.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

bool TestRuntime_Argument()
{
    // get argument 0 pointer with size
    uint32* arg0 = NULL;
    uint32  size = 0;
    bool ok = runtime->GetArgument(0, &arg0, &size);
    if (!ok)
    {
        printf_s("failed to get argument 0\n");
        return false;
    }
    if (*arg0 != 0x12345678)
    {
        printf_s("argument 0 is invalid data\n");
        return false;
    }
    if (size != 4)
    {
        printf_s("argument 0 size is invalid\n");
        return false;
    }
    printf_s("arg0: 0x%X, size: %d\n", *arg0, size);

    // get argument 1 pointer with size
    byte* arg1 = NULL;
    ok = runtime->GetArgument(1, &arg1, &size);
    if (!ok)
    {
        printf_s("failed to get argument 1\n");
        return false;
    }
    if (strcmp_a(arg1, "aaaabbbbccc") != 0)
    {
        printf_s("argument 1 is invalid data\n");
        return false;
    }
    if (size != 12)
    {
        printf_s("argument 1 size is invalid\n");
        return false;
    }
    printf_s("arg1: %s, size: %d\n", arg1, size);

    // not receive argument size
    arg0 = NULL;
    ok = runtime->GetArgument(0, &arg0, NULL);
    if (!ok)
    {
        printf_s("failed to get argument 0\n");
        return false;
    }
    if (*arg0 != 0x12345678)
    {
        printf_s("argument 0 is invalid data\n");
        return false;
    }
    printf_s("arg0: 0x%X\n", *arg0);
    return true;
}
