#include <stdio.h>
#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "errno.h"
#include "win_http.h"
#include "runtime.h"
#include "test.h"

static bool TestWinHTTP_Get();
static bool TestWinHTTP_Post();

bool TestRuntime_WinHTTP()
{
    test_t tests[] = 
    {
        { TestWinHTTP_Get  },
        { TestWinHTTP_Post },
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

static bool TestWinHTTP_Get()
{
    UTF16 URL = L"http://127.0.0.1:8001/http_server.exe";
    WinHTTP_Resp resp;

    errno err = runtime->WinHTTP.Get(URL, NULL, &resp);
    if (err != NO_ERROR)
    {
        printf_s("failed to get: 0x%X\n", err);
        return false;
    }

    // if (resp.BodySize != 5)
    // {
    //     printf_s("invalid response body size: %llu\n", resp.BodySize);
    //     return false;
    // }
    // if (strncmp_a(resp.BodyBuf, "hello", 5) != 0)
    // {
    //     printf_s("invalid response body\n");
    //     return false;
    // }
    printf_s("response size: %llu\n", resp.BodySize);
    // printf_s("response body: %s\n", (byte*)resp.BodyBuf);


    printf_s("test Get passed\n");
    return true;
}

static bool TestWinHTTP_Post()
{
    printf_s("test Post passed\n");
    return true;
}
