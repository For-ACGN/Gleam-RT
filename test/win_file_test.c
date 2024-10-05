#include <stdio.h>
#include "c_types.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

static bool TestWinFile_ReadFileA();
static bool TestWinFile_ReadFileW();
static bool TestWinFile_WriteFileA();
static bool TestWinFile_WriteFileW();

bool TestRuntime_WinFile()
{
    test_t tests[] = {
        { TestWinFile_ReadFileA  },
        { TestWinFile_ReadFileW  },
        { TestWinFile_WriteFileA },
        { TestWinFile_WriteFileW },
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

static bool TestWinFile_ReadFileA()
{
    return true;
}

static bool TestWinFile_ReadFileW()
{
    return true;
}

static bool TestWinFile_WriteFileA()
{
    return true;
}

static bool TestWinFile_WriteFileW()
{
    return true;
}
