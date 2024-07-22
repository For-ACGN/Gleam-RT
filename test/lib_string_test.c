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
    ascii str_a = "ascii";
    utf16 str_w = L"unicode";

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
    ascii s0 = "abc";
    ascii s1 = "abc";
    if (strcmp_a(s0, s1) != 0)
    {
        printf_s("strcmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_a with s0=s1 passed\n");

    s0 = "acc";
    s1 = "abc";
    if (strcmp_a(s0, s1) != 1)
    {
        printf_s("strcmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_a with s0>s1 passed\n");

    s0 = "aac";
    s1 = "abc";
    if (strcmp_a(s0, s1) != -1)
    {
        printf_s("strcmp_a return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_a with s0<s1 passed\n");
    return true;
}
