#include <stdio.h>
#include "c_types.h"
#include "lib_string.h"
#include "test.h"

static bool TestStrlen_a();
static bool TestStrlen_w();
static bool TestStrcmp_a();
static bool TestStrcmp_w();
static bool TestStrncmp_a();
static bool TestStrncmp_w();
static bool TestStrcpy_a();
static bool TestStrcpy_w();
static bool TestStrncpy_a();
static bool TestStrncpy_w();

bool TestLibString()
{
    test_t tests[] = 
    {
        { TestStrlen_a  },
        { TestStrlen_w  },
        { TestStrcmp_a  },
        { TestStrcmp_w  },
        { TestStrncmp_a },
        { TestStrncmp_w },
        { TestStrcpy_a  },
        { TestStrcpy_w  },
        { TestStrncpy_a },
        { TestStrncpy_w },
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

bool TestStrlen_a()
{
    ANSI str = "ansi";

    if (strlen_a(str) != 4)
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
    UTF16 str = L"unicode";

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
    ANSI s0 = "abc";
    ANSI s1 = "abc";
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
    UTF16 s0 = L"abc";
    UTF16 s1 = L"abc";
    if (strcmp_w(s0, s1) != 0)
    {
        printf_s("strcmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_w with s0=s1 passed\n");

    s0 = L"acc";
    s1 = L"abc";
    if (strcmp_w(s0, s1) != 1)
    {
        printf_s("strcmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_w with s0>s1 passed\n");

    s0 = L"aac";
    s1 = L"abc";
    if (strcmp_w(s0, s1) != -1)
    {
        printf_s("strcmp_w return incorrect value\n");
        return false;
    }
    printf_s("test strcmp_w with s0<s1 passed\n");
    return true;
}

static bool TestStrncmp_a()
{
}

static bool TestStrncmp_w()
{
}

static bool TestStrcpy_a()
{
}

static bool TestStrcpy_w()
{
}

static bool TestStrncpy_a()
{
}

static bool TestStrncpy_w()
{
}
