#include <stdio.h>
#include "build.h"
#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
#include "rel_addr.h"
#include "hash_api.h"
#include "errno.h"
#include "argument.h"
#include "runtime.h"
#include "test.h"

static void* copyShellcode();
static void* calcEpilogue();

bool TestInitRuntime()
{
    Runtime_Opts opts = {
        .BootInstAddress     = NULL,
        .NotEraseInstruction = true,
        .NotAdjustProtect    = false,
        .TrackCurrentThread  = false,
    };
#ifdef SHELLCODE_MODE
    typedef Runtime_M* (*InitRuntime_t)(Runtime_Opts* opts);
    InitRuntime_t initRuntime = copyShellcode();
    runtime = initRuntime(&opts);
#else
    runtime = InitRuntime(&opts);
#endif // SHELLCODE_MODE
    if (runtime == NULL)
    {
        printf_s("failed to initialize runtime: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}

bool TestRuntime_Exit()
{
    errno errno = runtime->Core.Exit();
    if (errno != NO_ERROR)
    {
        printf_s("failed to exit runtime: 0x%X\n", errno);
        return false;
    }
    errno = GetLastErrno();
    if (errno != NO_ERROR)
    {
        printf_s("find last errno: 0x%X\n", errno);
        return false;
    }
    return true;
}

static void* copyShellcode()
{
    VirtualAlloc_t VirtualAlloc = FindAPI_A("kernel32.dll", "VirtualAlloc");

    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(calcEpilogue());
    uintptr size  = end - begin;
    void* mem = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem == NULL)
    {
        printf_s("failed to allocate memory: 0x%X\n", GetLastErrno());
        return NULL;
    }
    mem_copy(mem, (void*)begin, size);
    printf_s("shellcode: 0x%zX\n", (uintptr)mem);
    return mem;
}

static void* calcEpilogue()
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    uint32  size = *(uint32*)(stub + ARG_OFFSET_ARGS_SIZE);
    size += ARG_OFFSET_FIRST_ARG;
    return (void*)(stub + size);
}
