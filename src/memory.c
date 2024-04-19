#include "go_types.h"
#include "hash_api.h"
#include "memory.h"

typedef struct {
    uint pages;
} MemMgr;

static byte genRandomByte(uint seed);
static uint getStackAddr();
static uint ror(uint value, uint8 bits);


uint InitMemMgr(FindAPI_t findAPI)
{
    // findAPI();

    (uintptr)(&MemAlloc);
    (uintptr)(&MemFree);

    return genRandomByte(0);
}

void* MemAlloc(uint size)
{

}

void MemFree(uintptr address)
{

}

static byte genRandomByte(uint seed)
{
    if (seed < 16)
    {
        seed += (uint)(&genRandomByte) << 4;
        seed += getStackAddr();
    }
    uint a = (uint)(&InitMemMgr) >> 2;
    uint c = (uint)(&MemAlloc) >> 4;
    uint m = (uint)(&MemFree) << 8;
    a += getStackAddr();
    c += getStackAddr();
    m += getStackAddr();
    a = ror(a, 3);
    c = ror(c, 6);
    m = ror(m, 9);
    return (byte)((a * seed + c) % m);
}

#pragma warning(push)
#pragma warning(disable: 4172)
static uintptr getStackAddr()
{
    uint stack = 0;
    return (uintptr)(&stack);
}
#pragma warning(pop)

static uint ror(uint value, uint8 bits)
{
    #ifdef _WIN64
    return value >> bits | value << (64 - bits);
    #elif _WIN32
    return value >> bits | value << (32 - bits);
    #endif
}
