#include "go_types.h"
#include "hash_api.h"
#include "memory.h"

typedef struct {
    uint pages;
} MemMgr;

bool InitMemMgr(FindAPI_t findAPI)
{
    findAPI();



    (uintptr)(&MemAlloc);
    (uintptr)(&MemFree);
}

void* MemAlloc(uint size)
{

}

void MemFree(uintptr address)
{

}
