#include "go_types.h"
#include "hash_api.h"
#include "runtime.h"

#pragma comment(linker, "/ENTRY:EntryMain")
uint EntryMain()
{
    Runtime_Args args = {
        .EntryPoint = 123,
        .SizeOfCode = 456,
        .FindAPI    = &FindAPI,
    };
    Runtime_M* runtime = InitRuntime(&args);
    if (runtime == NULL)
    {
        return -1;
    }


    uint64* test1 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test1 == NULL)
    {
        return -1;
    } 
    *test1 = 0x1234567812345600;

    uint64* test2 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test2 == NULL)
    {
        return -1;
    } 
    *test2 = 0x1234567812345601;

    uint64* test3 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test3 == NULL)
    {
        return -1;
    }
    *test3 = 0x1234567812345602;

    if (!runtime->Hide())
    {
        return -1;
    }
    if (!runtime->Recover())
    {
        return -1;
    }

    uint64* test4 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test3 == NULL)
    {
        return -1;
    }
    *test4 = 0x1234567812345603;

    if (!runtime->MemFree(test3))
    {
        return -1;
    }
    if (!runtime->MemFree(test1))
    {
        return -1;
    }
    uint64* test5 = (uint64*)runtime->MemAlloc(sizeof(uint64));
    if (test5 == NULL)
    {
        return -1;
    }
    *test5 = 0x1234567812345600;


    if (!runtime->Hide())
    {
        return -1;
    }
    if (!runtime->Recover())
    {
        return -1;
    }


    if (!runtime->MemFree(test2))
    {
        return -1;
    }
    if (!runtime->MemFree(test4))
    {
        return -1;
    }
    if (!runtime->MemFree(test5))
    {
        return -1;
    }
    
    return 0;
}
