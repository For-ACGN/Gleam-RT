#include "go_types.h"
#include "hash_api.h"
#include "memory.h"

typedef struct {
    uint pages;
} MemMgr;


uint InitMemMgr(FindAPI_t findAPI)
{
    // findAPI();

    (uintptr)(&MemAlloc);
    (uintptr)(&MemFree);

    return genRandomUint(0);
}

void* MemAlloc(uint size)
{

}

void MemFree(uintptr address)
{

}
