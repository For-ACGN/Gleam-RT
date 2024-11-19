#include "c_types.h"
#include "lib_string.h"

#pragma optimize("t", on)

byte   lowercase_a(byte c);
uint16 lowercase_w(uint16 c);

__declspec(noinline)
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

__declspec(noinline)
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

__declspec(noinline)
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

__declspec(noinline)
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

__declspec(noinline)
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

__declspec(noinline)
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

__declspec(noinline)
int stricmp_a(ANSI a, ANSI b)
{
    for (;;)
    {
        byte s0 = lowercase_a(*a);
        byte s1 = lowercase_a(*b);
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

__declspec(noinline)
int stricmp_w(UTF16 a, UTF16 b)
{
    for (;;)
    {
        uint16 s0 = lowercase_w(*a);
        uint16 s1 = lowercase_w(*b);
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

__declspec(noinline)
int strnicmp_a(ANSI a, ANSI b, int64 n)
{
    for (int64 i = 0; i < n; i++)
    {
        byte s0 = lowercase_a(*a);
        byte s1 = lowercase_a(*b);
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

__declspec(noinline)
int strnicmp_w(UTF16 a, UTF16 b, int64 n)
{
    for (int64 i = 0; i < n; i++)
    {
        uint16 s0 = lowercase_w(*a);
        uint16 s1 = lowercase_w(*b);
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

__declspec(noinline)
byte lowercase_a(byte c)
{
    if (c >= 'A' && c <= 'Z')
    {
        c += 0x20;
    }
    return c;
}

__declspec(noinline)
uint16 lowercase_w(uint16 c)
{
    if (c >= L'A' && c <= L'Z')
    {
        c += 0x20;
    }
    return c;
}

__declspec(noinline)
uint strcpy_a(ANSI dst, ANSI src)
{
    uint l = 0;
    for (;;)
    {
        byte s = *src;
        *dst = s;
        if (s == 0x00)
        {
            break;
        }

        l++;
        dst++;
        src++;
    }
    return l;
}

__declspec(noinline)
uint strcpy_w(UTF16 dst, UTF16 src)
{
    uint l = 0;
    for (;;)
    {
        uint16 s = *src;
        *dst = s;
        if (s == 0x0000)
        {
            break;
        }

        l++;
        dst++;
        src++;
    }
    return l;
}

__declspec(noinline)
uint strncpy_a(ANSI dst, ANSI src, int64 n)
{
    uint l = 0;
    for (int64 i = 0; i < n; i++)
    {
        byte s = *src;
        *dst = s;
        if (s == 0x00)
        {
            break;
        }

        l++;
        dst++;
        src++;
    }
    return l;
}

__declspec(noinline)
uint strncpy_w(UTF16 dst, UTF16 src, int64 n)
{
    uint l = 0;
    for (int64 i = 0; i < n; i++)
    {
        uint16 s = *src;
        *dst = s;
        if (s == 0x0000)
        {
            break;
        }

        l++;
        dst++;
        src++;
    }
    return l;
}

#pragma optimize("t", off)
