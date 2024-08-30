#include <stdio.h>
#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "errno.h"
#include "argument.h"
#include "runtime.h"

bool testShellcode();
bool saveShellcode();

int __cdecl main()
{
    if (!testShellcode())
    {
        return 1;
    }
    if (!saveShellcode())
    {
        return 2;
    }
    printf_s("save shellcode successfully");
    return 0;
}

bool testShellcode()
{
    Runtime_Opts opt = {
        .NotEraseInstruction = true,
    };
    Runtime_M* RuntimeM = InitRuntime(&opt);
    if (RuntimeM == NULL)
    {
        printf_s("failed to test shellcode: 0x%lX\n", GetLastErrno());
        return false;
    }
    printf_s("RuntimeM: 0x%llX\n", (uint64)RuntimeM);
    errno errno = RuntimeM->Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit runtime: 0x%lX\n", errno);
        return false;
    }
    return true;
}

bool saveShellcode()
{
#ifdef _WIN64
    FILE* file = fopen("../dist/GleamRT_x64.bin", "wb");
#elif _WIN32
    FILE* file = fopen("../dist/GleamRT_x86.bin", "wb");
#endif
    if (file == NULL)
    {
        printf_s("failed to create output file");
        return false;
    }
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Argument_Stub);
    uintptr size  = end - begin;
    // skip 0xCC instructions at the tail
    uint num0xCC = 0;
    for (;;)
    {
        end--;
        if (*(byte*)end != 0xCC)
        {
            break;
        }
        num0xCC++;
    }
    size -= num0xCC;
    // write shellcode
    size_t  n = fwrite((byte*)begin, (size_t)size, 1, file);
    if (n != 1)
    {
        printf_s("failed to save shellcode");
        return false;
    }
    fclose(file);
    return true;
}
