#include <stdio.h>
#include "c_types.h"
#include "msvcrt_t.h"
#include "errno.h"
#include "runtime.h"
#include "test.h"

static bool TestMemory_Virtual();
static bool TestMemory_Heap();
static bool TestMemory_Msvcrt();
static bool TestMemory_Ucrtbase();

bool TestRuntime_Memory()
{
    test_t tests[] = {
        { TestMemory_Virtual  },
        { TestMemory_Heap     },
        { TestMemory_Msvcrt   },
        { TestMemory_Ucrtbase },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        printf_s("--------------------------------\n");
        if (!tests[i]())
        {
            return false;
        }
        printf_s("--------------------------------\n\n");
    }
    return true;
}

bool TestMemory_Virtual()
{
    uint64* test1 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test1 == NULL)
    {
        return false;
    }
    *test1 = 0x1234567812345600;

    uint64* test2 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test2 == NULL)
    {
        return false;
    }
    *test2 = 0x1234567812345601;

    uint64* test3 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test3 == NULL)
    {
        return false;
    }
    *test3 = 0x1234567812345602;

    errno errno = runtime->Core.Hide();
    if (errno != NO_ERROR)
    {
        printf_s("failed to hide: 0x%X\n", errno);
        return false;
    }
    errno = runtime->Core.Recover();
    if (errno != NO_ERROR)
    {
        printf_s("failed to recover: 0x%X\n", errno);
        return false;
    }

    uint64* test4 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test4 == NULL)
    {
        return false;
    }
    *test4 = 0x1234567812345603;

    runtime->Memory.Free(test3);
    runtime->Memory.Free(test1);

    uint64* test5 = (uint64*)runtime->Memory.Alloc(sizeof(uint64));
    if (test5 == NULL)
    {
        return false;
    }
    *test5 = 0x1234567812345600;

    errno = runtime->Core.Hide();
    if (errno != NO_ERROR)
    {
        printf_s("failed to hide: 0x%X\n", errno);
        return false;
    }
    errno = runtime->Core.Recover();
    if (errno != NO_ERROR)
    {
        printf_s("failed to recover: 0x%X\n", errno);
        return false;
    }
    errno = runtime->Core.Sleep(100);
    if (errno != NO_ERROR)
    {
        printf_s("failed to call SleepHR: 0x%X\n", errno);
        return false;
    }

    runtime->Memory.Free(test2);
    runtime->Memory.Free(test4);
    runtime->Memory.Free(test5);
    return true;
}

static bool TestMemory_Heap()
{
    HMODULE kernel32 = runtime->Library.LoadA("kernel32.dll");

    GetProcessHeap_t GetProcessHeap = runtime->Library.GetProc(kernel32, "GetProcessHeap");
    HANDLE hHeap = GetProcessHeap();

    // test common heap
    HeapAlloc_t   HeapAlloc   = runtime->Library.GetProc(kernel32, "HeapAlloc");
    HeapReAlloc_t HeapReAlloc = runtime->Library.GetProc(kernel32, "HeapReAlloc");
    HeapFree_t    HeapFree    = runtime->Library.GetProc(kernel32, "HeapFree");
    HeapSize_t    HeapSize    = runtime->Library.GetProc(kernel32, "HeapSize");

    void* mem = HeapAlloc(hHeap, 0, 16);
    if (HeapSize(hHeap, 0, mem) != (uint)(16 + sizeof(uint)))
    {
        printf_s("incorrect heap block size\n");
        return false;
    }
    if (!HeapFree(hHeap, 0, mem))
    {
        printf_s("failed to free heap 0x%X\n", GetLastErrno());
        return false;
    }
    runtime->Core.Sleep(10);







    // test global and local heap


    // compare the hook function address
    HMODULE ntdll = runtime->Library.LoadA("ntdll.dll");
    HeapAlloc_t   RtlAllocateHeap   = runtime->Library.GetProc(ntdll, "RtlAllocateHeap");
    HeapReAlloc_t RtlReAllocateHeap = runtime->Library.GetProc(ntdll, "RtlReAllocateHeap");
    HeapFree_t    RtlFreeHeap       = runtime->Library.GetProc(ntdll, "RtlFreeHeap");

    if (RtlAllocateHeap != HeapAlloc)
    {
        printf_s("incorrect RtlAllocateHeap address\n");
        return false;
    }
    if (RtlReAllocateHeap != HeapReAlloc)
    {
        printf_s("incorrect RtlReAllocateHeap address\n");
        return false;
    }
    if (RtlFreeHeap != HeapFree)
    {
        printf_s("incorrect RtlFreeHeap address\n");
        return false;
    }
    if (!runtime->Library.Free(ntdll))
    {
        printf_s("failed to free ntdll.dll: 0x%X\n", GetLastErrno());
        return false;
    }

    if (!runtime->Library.Free(kernel32))
    {
        printf_s("failed to free kernel32.dll: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}

static bool TestMemory_Msvcrt()
{
    HMODULE hModule = runtime->Library.LoadA("msvcrt.dll");

    msvcrt_malloc_t  malloc  = runtime->Library.GetProc(hModule, "malloc");
    msvcrt_calloc_t  calloc  = runtime->Library.GetProc(hModule, "calloc");
    msvcrt_realloc_t realloc = runtime->Library.GetProc(hModule, "realloc");
    msvcrt_free_t    free    = runtime->Library.GetProc(hModule, "free");

    uint* test1 = malloc(8);
    uint* test2 = calloc(4, 8);
    uint* test3 = realloc(test1, 27);
    
    *test2 = 0x5678;
    *test3 = 0x1212;

    runtime->Core.Sleep(10);
    free(test2);
    runtime->Core.Sleep(10);
    free(test3);
    runtime->Core.Sleep(10);

    // not free
    test1 = malloc(8);
    *test1 = 0x1234;
    runtime->Core.Sleep(10);

    if (!runtime->Library.Free(hModule))
    {
        printf_s("failed to free kernel32.dll: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}

static bool TestMemory_Ucrtbase()
{
    return true;
}
