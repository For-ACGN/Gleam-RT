#include <stdio.h>
#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "errno.h"
#include "runtime.h"
#include "rel_addr.h"
#include "epilogue.h"

#define FUNC_OFFSET_RUNTIME (\
    1 + 2 + 4 + 4 + 2 + 1 + 5 +\
    5 + 2 + 2 + 2 + 3 + 3 + 4 +\
    (2 + 1)\
)
#define FUNC_OFFSET_LIBRARY  (6 + 5 + 1 + 2)
#define FUNC_OFFSET_MEMORY   (4 + 8 + 1 + 2)
#define FUNC_OFFSET_THREAD   (7 + 7 + 1 + 2)
#define FUNC_OFFSET_RESOURCE (8 + 5 + 1 + 2)
#define FUNC_OFFSET_ARGUMENT (3 + 5 + 1 + 1 + 2)

#define FUNC_OFFSET_COUNTER (\
    FUNC_OFFSET_RUNTIME  + FUNC_OFFSET_LIBRARY +\
    FUNC_OFFSET_MEMORY   + FUNC_OFFSET_THREAD  +\
    FUNC_OFFSET_RESOURCE + FUNC_OFFSET_ARGUMENT \
)

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
    // test initialize runtime
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
    // adjust memory page protect
    VirtualProtect_t VirtualProtect = FindAPI(0xB4365E5D, 0x46833E39);
    SIZE_T size = end - begin;
    DWORD old;
    if (!VirtualProtect(&InitRuntime, size, PAGE_EXECUTE_READWRITE, &old))
    {
        return 1;
    }
    // search the instructions about "call GetFuncAddr"
    uint counter = 0;
    for (uintptr eip = begin; eip < end; eip++)
    {
        // instruction about call
        if (*(byte*)eip != 0xE8)
        {
            continue;
        }
        // EIP + call rel + len(call)
        if (eip + *(uint32*)(eip + 1) + 5 != stub)
        {
            continue;
        }
        // search the instruction that store function absolute address
        uintptr target = eip - 4;
        for (int offset = 0; offset < 128; offset++)
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
    if (counter != FUNC_OFFSET_COUNTER)
    {
        printf_s("invalid fix counter\n");
        return 2;
    }
#endif
    return 0;
}

int saveShellcode()
{
#ifdef _WIN64
    FILE* file = fopen("../../dist/GleamRT_x64.bin", "wb");
#elif _WIN32
    FILE* file = fopen("../../dist/GleamRT_x86.bin", "wb");
#endif
    if (file == NULL)
    {
        printf_s("failed to open file");
        return 3;
    }
    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    uintptr size  = end - begin;
    size_t  n = fwrite((byte*)begin, (size_t)size, 1, file);
    if (n != 1)
    {
        printf_s("failed to save shellcode");
        return 4;
    }
    fclose(file);
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
        return 5;
    }
    printf_s("RuntimeM: 0x%llX\n", (uint64)RuntimeM);
    return 0;
}
