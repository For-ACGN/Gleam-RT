#include <stdio.h>
#include "c_types.h"
#include "lib_string.h"
#include "test.h"

static bool TestStrlen();
static bool TestStrcmp();

bool TestLibString()
{
    test_t tests[] = 
    {
        { TestStrlen },
        { TestStrcmp },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        if (!tests[i]())
        {
            return false;
        }
    }
    return true;
}

bool TestStrlen()
{
    byte*   str_a = "ascii";
    uint16* str_w = L"unicode";

    if (strlen_a(str_a) != 5)
    {
        printf_s("strlen_a return incorrect length\n");
        return false;
    }
    printf_s("test strlen_a passed\n");

    if (strlen_w(str_w) != 7)
    {
        printf_s("strlen_w return incorrect length\n");
        return false;
    }
    printf_s("test strlen_w passed\n");

    str_a = "";
    str_w = L"";

    if (strlen_a(str_a) != 0)
    {
        printf_s("strlen_a return incorrect length\n");
        return false;
    }
    printf_s("test strlen_a with null passed\n");

    if (strlen_w(str_w) != 0)
    {
        printf_s("strlen_w return incorrect length\n");
        return false;
    }
    printf_s("test strlen_w with null passed\n");
    return true;
}

bool TestStrcmp()
{



    return true;
}
