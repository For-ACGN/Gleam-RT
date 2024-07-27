#include <stdio.h>
#include "c_types.h"
#include "runtime.h"
#include "epilogue.h"

void fixFuncOffset();

int __cdecl main()
{
    // fix offset about function address
    fixFuncOffset();

    // create file for save shellcode 
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
    size_t n = fwrite((byte*)begin, (size_t)size, 1, file);
    if (n != 1)
    {
        printf_s("failed to save shellcode");
        return 2;
    }
    fclose(file);

    // test shellcode
    Runtime_M* RuntimeM = InitRuntime(NULL);
    printf_s("RuntimeM: 0x%llX\n", (uint64)RuntimeM);
    if (RuntimeM == NULL)
    {
        printf_s("failed to test shellcode");
        return 3;
    }
    printf_s("save shellcode successfully");
    return 0;
}

void fixFuncOffset()
{
#ifndef _WIN64

#endif
}
