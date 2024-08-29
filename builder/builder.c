﻿#include <stdio.h>
#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "errno.h"
#include "argument.h"
#include "runtime.h"

int testShellcode();
int saveShellcode();

int __cdecl main()
{
    int ret = testShellcode();
    if (ret != 0)
    {
        return ret;
    }
    ret = saveShellcode();
    if (ret != 0)
    {
        return ret;
    }
    printf_s("save shellcode successfully");
    return 0;
}

int testShellcode()
{
    Runtime_Opts opt = {
        .NotEraseInstruction = true,
    };
    Runtime_M* RuntimeM = InitRuntime(&opt);
    if (RuntimeM == NULL)
    {
        printf_s("failed to test shellcode: 0x%lX\n", GetLastErrno());
        return 1;
    }
    printf_s("RuntimeM: 0x%llX\n", (uint64)RuntimeM);
    errno errno = RuntimeM->Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit runtime: 0x%lX\n", errno);
        return 2;
    }
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
        printf_s("failed to create output file");
        return 2;
    }
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Argument_Stub);
    uintptr size  = end - begin;
    size_t  n = fwrite((byte*)begin, (size_t)size, 1, file);
    if (n != 1)
    {
        printf_s("failed to save shellcode");
        return 3;
    }
    fclose(file);
    return 0;
}
