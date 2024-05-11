#include "c_types.h"
#include "lib_mem.h"

// Optimization of this library must be disabled,
// otherwise when using builder to build shellcode,
// the compiler will mistakenly skip the following
// functions and instead use <stdio.h> or built-in
// functions, causing the function address in the
// shellcode to be incorrect.
#pragma optimize("", off)

__declspec(noinline)
bool mem_equal(void* dst, void* src, uint size)
{
    byte* d = (byte*)dst;
    byte* s = (byte*)src;
    for (uint i = 0; i < size; i++)
    {
        if (*d != *s)
        {
            return false;
        }
        d++;
        s++;
    }
    return true;
}

__declspec(noinline)
bool mem_zero(void* dst, uint size)
{
    byte* d = (byte*)dst;
    for (uint i = 0; i < size; i++)
    {
        if (*d != 0)
        {
            return false;
        }
        d++;
    }
    return true;
}

__declspec(noinline)
void mem_copy(void* dst, void* src, uint size)
{
    byte* d = (byte*)dst;
    byte* s = (byte*)src;
    for (uint i = 0; i < size; i++)
    {
        *d = *s;
        d++;
        s++;
    }
}

__declspec(noinline)
void mem_set(void* ptr, byte val, uint num)
{
    byte* addr = (byte*)ptr;
    for (uint i = 0; i < num; i++)
    {
        *addr = val;
        addr++;
    }
}

__declspec(noinline)
void mem_clean(void* ptr, uint num)
{
    mem_set(ptr, 0, num);
}

#pragma optimize("", on)
