#include <stdio.h>
#include "c_types.h"
#include "runtime.h"
#include "rel_addr.h"
#include "epilogue.h"

int fixFuncOffset();
int saveShellcode();
int testShellcode();

int __cdecl main()
{
    int ret;
    // fix offset about function address
    ret = fixFuncOffset();
    if (ret != 0)
    {
        return ret;
    }
    // create file for save shellcode 
    ret = saveShellcode();
    if (ret != 0)
    {
        return ret;
    }
    // test shellcode
    ret = testShellcode();
    if (ret != 0)
    {
        return ret;
    }
    printf_s("save shellcode successfully");
    return 0;
}

int fixFuncOffset()
{
#ifndef _WIN64
    uintptr stub  = (uintptr)(&GetFuncAddr);
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    // search the instructions about "call GetFuncAddr"
    uint counter = 0;
    for (uintptr eip = begin; eip < end; eip++)
    {
        // EIP + call rel + len(call)
        if (eip + *(uint32*)(eip + 1) + 5 != stub)
        {
            continue;
        }
        // search the instruction that store function absolute address
        uintptr target = eip - 5;
        for (int offset = 0; offset < 8; offset++)
        {
            uintptr addr = target - offset;
            uintptr func = *(uintptr*)addr;
            if (func < begin || func > end)
            {
                continue;
            }
            // replace the absolute address to relative address
            *(uintptr*)addr = func - stub;
            counter++;
            break;
        }
    }
    printf_s("total fix: %zu\n", counter);
    if (counter != 2)
    {
        printf_s("invalid fix counter\n");
        return 1;
    }
#endif
    return 0;
}

int saveShellcode()
{
#ifdef _WIN64
    FILE* file = fopen("../dist/GleamRT_x64.bin", "wb");
#elif _WIN32
    FILE* file = fopen("../dist/GleamRT_x86.bin", "wb");
#endif
    if (file == NULL)
    {
        printf_s("failed to open file");
        return 1;
    }
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    uintptr size  = end - begin;
    size_t  n = fwrite((byte*)begin, (size_t)size, 1, file);
    if (n != 1)
    {
        printf_s("failed to save shellcode");
        return 2;
    }
    fclose(file);
    return 0;
}

int testShellcode()
{
    Runtime_M* RuntimeM = InitRuntime(NULL);
    printf_s("RuntimeM: 0x%llX\n", (uint64)RuntimeM);
    if (RuntimeM == NULL)
    {
        printf_s("failed to test shellcode");
        return 3;
    }
    return 0;
}
