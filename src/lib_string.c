#include "c_types.h"
#include "lib_string.h"

// Optimization of this library must be disabled,
// otherwise when using builder to build shellcode,
// the compiler will mistakenly skip the following
// functions and instead use <stdio.h> or built-in
// functions, causing the function address in the
// shellcode to be incorrect.
#pragma optimize("", off)

uint strlen_a(ANSI s)
{
    uint l = 0;
    for (;;)
    {
        if (*s == 0x00)
        {
            break;
        }
        l++;
        s++;
    }
    return l;
}

uint strlen_w(UTF16 s)
{
    uint l = 0;
    for (;;)
    {
        if (*s == 0x0000)
        {
            break;
        }
        l++;
        s++;
    }
    return l;
}

int strcmp_a(ANSI a, ANSI b)
{
    for (;;)
    {
        byte s0 = *a;
        byte s1 = *b;
        if (s0 == s1)
        {
            if (s0 == 0x00)
            {
                return 0;
            }
            a++;
            b++;
            continue;
        }
        if (s0 > s1)
        {
            return 1;
        } else {
            return -1;
        }
    }
}

int strcmp_w(UTF16 a, UTF16 b)
{
    for (;;)
    {
        uint16 s0 = *a;
        uint16 s1 = *b;
        if (s0 == s1)
        {
            if (s0 == 0x0000)
            {
                return 0;
            }
            a++;
            b++;
            continue;
        }
        if (s0 > s1)
        {
            return 1;
        } else
        {
            return -1;
        }
    }
}

int strncmp_a(ANSI a, ANSI b, int64 n)
{
    for (int64 i = 0; i < n; i++)
    {
        byte s0 = *a;
        byte s1 = *b;
        if (s0 == s1)
        {
            if (s0 == 0x00)
            {
                return 0;
            }
            a++;
            b++;
            continue;
        }
        if (s0 > s1)
        {
            return 1;
        } else {
            return -1;
        }
    }
    return 0;
}

int strncmp_w(UTF16 a, UTF16 b, int64 n)
{
    for (int64 i = 0; i < n; i++)
    {
        uint16 s0 = *a;
        uint16 s1 = *b;
        if (s0 == s1)
        {
            if (s0 == 0x0000)
            {
                return 0;
            }
            a++;
            b++;
            continue;
        }
        if (s0 > s1)
        {
            return 1;
        } else
        {
            return -1;
        }
    }
    return 0;
}

uint strcpy_a(ANSI dst, ANSI src)
{
    uint l = 0;
    for (;;)
    {
        byte s = *src;
        if (s == 0x00)
        {
            break;
        }
        *dst = s;

        l++;
        dst++;
        src++;
    }
    return l;
}

uint strcpy_w(UTF16 dst, UTF16 src)
{
    uint l = 0;
    for (;;)
    {
        uint16 s = *src;
        if (s == 0x0000)
        {
            break;
        }
        *dst = s;

        l++;
        dst++;
        src++;
    }
    return l;
}

uint strncpy_a(ANSI dst, ANSI src, int64 n)
{
    uint l = 0;
    for (int64 i = 0; i < n; i++)
    {
        byte s = *src;
        if (s == 0x00)
        {
            break;
        }
        *dst = s;

        l++;
        dst++;
        src++;
    }
    return l;
}

uint strncpy_w(UTF16 dst, UTF16 src, int64 n)
{
    uint l = 0;
    for (int64 i = 0; i < n; i++)
    {
        uint16 s = *src;
        if (s == 0x0000)
        {
            break;
        }
        *dst = s;

        l++;
        dst++;
        src++;
    }
    return l;
}

#pragma optimize("", on)
