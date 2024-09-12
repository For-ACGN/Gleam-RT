#include "c_types.h"
#include "lib_string.h"

// Optimization of this library must be disabled,
// otherwise when using builder to build shellcode,
// the compiler will mistakenly skip the following
// functions and instead use <stdio.h> or built-in
// functions, causing the function address in the
// shellcode to be incorrect.
#pragma optimize("", off)

uint strlen_a(ascii s)
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

uint strlen_w(utf16 s)
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

int strcmp_a(ascii a, ascii b)
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

int strcmp_w(utf16 a, utf16 b)
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

#pragma optimize("", on)
