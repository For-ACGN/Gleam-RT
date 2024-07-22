#include <stdio.h>
#include "c_types.h"
#include "lib_string.h"
#include "test.h"

static bool TestStrlen_a();
static bool TestStrlen_w();
static bool TestStrcmp_a();
static bool TestStrcmp_w();

bool TestLibString()
{
    test_t tests[] = 
    {
        { TestStrlen_a },
        { TestStrlen_w },
        { TestStrcmp_a },
        { TestStrcmp_w },
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

bool TestStrlen_a()
{
    ascii str = "ascii";

    if (strlen_a(str) != 5)
    {
        printf_s("strlen_a return incorrect length\n");
        return false;
    }
    printf_s("test strlen_a passed\n");

    str = "";
    if (strlen_a(str) != 0)
    {
        printf_s("strlen_a return incorrect length\n");
        return false;
    }
    printf_s("test strlen_a with null passed\n");
    return true;
}

bool TestStrlen_w()
{
    utf16 str = L"unicode";

    if (strlen_w(str) != 7)
    {
        printf_s("strlen_w return incorrect length\n");
        return false;
    }
    printf_s("test strlen_w passed\n");

    str = L"";
    if (strlen_w(str) != 0)
    {
        printf_s("strlen_w return incorrect length\n");
        return false;
    }
    printf_s("test strlen_w with null passed\n");
    return true;
}

bool TestStrcmp_a()
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

bool TestStrcmp_w()
{

    return true;
}
