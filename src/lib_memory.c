#include "c_types.h"
#include "lib_memory.h"

// Optimization of this library must be disabled,
// otherwise when using builder to build shellcode,
// the compiler will mistakenly skip the following
// functions and instead use <stdio.h> or built-in
// functions, causing the function address in the
// shellcode to be incorrect.
#pragma optimize("", off)

void mem_copy(void* dst, void* src, uint size)
{
    if (size == 0)
    {
        return;
    }
    byte* d = (byte*)dst;
    byte* s = (byte*)src;
    for (uint i = 0; i < size; i++)
    {
        *d = *s;
        d++;
        s++;
    }
}

void mem_init(void* ptr, uint num)
{
    if (num == 0)
    {
        return;
    }
    mem_set(ptr, 0, num);
}

void mem_set(void* ptr, byte val, uint num)
{
    if (num == 0)
    {
        return;
    }
    byte* p = (byte*)ptr;
    for (uint i = 0; i < num; i++)
    {
        *p = val;
        p++;
    }
}

int mem_cmp(void* a, void* b, uint size)
{
    if (size == 0)
    {
        return 0;
    }
    byte* p0 = (byte*)a;
    byte* p1 = (byte*)b;
    for (uint i = 0; i < size; i++)
    {
        if (*p0 == *p1)
        {
            p0++;
            p1++;
            continue;
        }
        if (*p0 > *p1)
        {
            return 1;
        } else {
            return -1;
        }
    }
    return 0;
}

bool mem_equal(void* a, void* b, uint size)
{
    if (size == 0)
    {
        return true;
    }
    byte* p0 = (byte*)a;
    byte* p1 = (byte*)b;
    for (uint i = 0; i < size; i++)
    {
        if (*p0 != *p1)
        {
            return false;
        }
        p0++;
        p1++;
    }
    return true;
}

bool mem_is_zero(void* ptr, uint size)
{
    if (size == 0)
    {
        return true;
    }
    byte* p = (byte*)ptr;
    for (uint i = 0; i < size; i++)
    {
        if (*p != 0)
        {
            return false;
        }
        p++;
    }
    return true;
}

#pragma optimize("", on)
