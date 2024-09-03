#include <stdio.h>
#include "c_types.h"
#include "lib_string.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

static bool TestArgument_GetValue();
static bool TestArgument_GetPointer();
static bool TestArgument_Erase();
static bool TestArgument_EraseAll();

bool TestRuntime_Argument()
{
    test_t tests[] = {
        { TestArgument_GetValue   },
        { TestArgument_GetPointer },
        { TestArgument_Erase      },
        { TestArgument_EraseAll   },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        printf_s("--------------------------------\n");
        if (!tests[i]())
        {
            return false;
        }
        printf_s("--------------------------------\n\n");
    }
    return true;
}

static bool TestArgument_GetValue()
{
    // get argument 0 pointer with size
    uint32 arg0 = 0;
    uint32 size = 0;
    if (!runtime->GetArgValue(0, &arg0, &size))
    {
        printf_s("failed to get argument 0\n");
        return false;
    }
    if (arg0 != 0x12345678)
    {
        printf_s("argument 0 is invalid data\n");
        return false;
    }
    if (size != 4)
    {
        printf_s("argument 0 size is invalid\n");
        return false;
    }
    printf_s("arg0: 0x%X, size: %d\n", arg0, size);

    // get argument 1 pointer with size
    byte arg1[12+1];
    if (!runtime->GetArgValue(1, &arg1, &size))
    {
        printf_s("failed to get argument 1\n");
        return false;
    }
    arg1[12] = 0x00; // set string end
    if (strcmp_a(&arg1[0], "aaaabbbbccc") != 0)
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
    arg0 = 0;
    if (!runtime->GetArgValue(0, &arg0, NULL))
    {
        printf_s("failed to get argument 0\n");
        return false;
    }
    if (arg0 != 0x12345678)
    {
        printf_s("argument 0 is invalid data\n");
        return false;
    }
    printf_s("arg0: 0x%X\n", arg0);

    // invalid index
    if (runtime->GetArgValue(2, &arg0, NULL))
    {
        printf_s("get argument with invalid index\n");
        return false;
    }
    return true;
}

static bool TestArgument_GetPointer()
{
    // get argument 0 pointer with size
    uint32* arg0 = NULL;
    uint32  size = 0;
    if (!runtime->GetArgPointer(0, &arg0, &size))
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
    if (!runtime->GetArgPointer(1, &arg1, &size))
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
    if (!runtime->GetArgPointer(0, &arg0, NULL))
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

    // invalid index
    if (runtime->GetArgPointer(2, &arg0, NULL))
    {
        printf_s("get argument with invalid index\n");
        return false;
    }
    return true;
}

static bool TestArgument_Erase()
{
    if (!runtime->EraseArgument(1))
    {
        printf_s("failed to earse argument 1\n");
        return false;
    }
    printf_s("earse argument 1\n");

    byte*  arg1 = NULL;
    uint32 size = 0;
    if (!runtime->GetArgPointer(1, &arg1, &size))
    {
        printf_s("failed to get argument 1\n");
        return false;
    }
    if (strcmp_a(arg1, "aaaabbbbccc") == 0)
    {
        printf_s("argument 1 is not be erased\n");
        return false;
    }
    if (size == 12)
    {
        printf_s("argument 1 size is not be erased\n");
        return false;
    }
    printf_s("check erased argument 1\n");
    return true;
}

static bool TestArgument_EraseAll()
{
    runtime->EraseAllArgs();
    printf_s("earse all arguments\n");

    uint32* arg0 = NULL;
    uint32  size = 0;
    if (!runtime->GetArgPointer(0, &arg0, &size))
    {
        printf_s("failed to get argument 0\n");
        return false;
    }
    if (*arg0 == 0x12345678)
    {
        printf_s("argument 0 is not be erased\n");
        return false;
    }
    if (size == 4)
    {
        printf_s("argument 0 size is not be erased\n");
        return false;
    }
    printf_s("check erased argument 0\n");
    return true;
}
