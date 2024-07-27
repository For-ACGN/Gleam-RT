#include <stdio.h>
#include "c_types.h"
#include "runtime.h"
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
    int ret = saveShellcode();
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
    uintptr end = (uintptr)(&Epilogue);
    uintptr size = end - begin;
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
