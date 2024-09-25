#include <stdio.h>
#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "errno.h"
#include "argument.h"
#include "runtime.h"

bool testShellcode(bool erase);
bool saveShellcode();

int __cdecl main()
{
    if (!testShellcode(false))
    {
        return 1;
    }
    if (!saveShellcode())
    {
        return 2;
    }
    if (!testShellcode(true))
    {
        return 3;
    }
    printf_s("save shellcode successfully\n");
    return 0;
}

bool testShellcode(bool erase)
{
    Runtime_Opts opt = {
        .BootInstAddress     = NULL,
        .NotEraseInstruction = !erase,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
    Runtime_M* RuntimeM = InitRuntime(&opt);
    if (RuntimeM == NULL)
    {
        printf_s("failed to initialize runtime: 0x%X\n", GetLastErrno());
        return false;
    }
    printf_s("RuntimeM: 0x%llX\n", (uint64)RuntimeM);
    errno errno = RuntimeM->Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit runtime: 0x%X\n", errno);
        return false;
    }
    return true;
}

bool saveShellcode()
{
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Argument_Stub);
    uintptr size  = end - begin;

    // check runtime option stub is valid
    end -= OPTION_STUB_SIZE;
    if (*(byte*)end != OPTION_STUB_MAGIC)
    {
        printf_s("invalid runtime option stub\n");
        return false;
    }

    // conut 0xFF for check the shellcode tail is valid
    uint num0xFF = 0;
    for (int i = 0; i < 16; i++)
    {
        end--;
        if (*(byte*)end != 0xFF)
        {
            break;
        }
        num0xFF++;
    }
    if (num0xFF != 16)
    {
        printf_s("invalid shellcode tail\n");
        return false;
    }

    // extract shellcode to file
#ifdef _WIN64
    FILE* file = fopen("../dist/GleamRT_x64.bin", "wb");
#elif _WIN32
    FILE* file = fopen("../dist/GleamRT_x86.bin", "wb");
#endif
    if (file == NULL)
    {
        printf_s("failed to create shellcode output file\n");
        return false;
    }
    size_t n = fwrite((byte*)begin, (size_t)size, 1, file);
    if (n != 1)
    {
        printf_s("failed to save shellcode\n");
        return false;
    }
    fclose(file);
    return true;
}
