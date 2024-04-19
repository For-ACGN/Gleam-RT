#include "go_types.h"
#include "random.h"

static uint getStackAddr();
static uint ror(uint value, uint8 bits);

void RandBuffer(uintptr buf, uint size)
{
    uint data = RandUint(0);
    for (uintptr i = 0; i < size; i++)
    {
        data = RandUint(data);
        *(byte*)(buf + i) = (byte)data;
    }
}

byte RandByte(uint seed)
{
    return (byte)RandUint(seed);
}

uint RandUint(uint seed)
{
    if (seed % 16 < 8)
    {
        seed += getStackAddr();
    }
    uint a = (uint)(&ror) >> 2;
    uint c = (uint)(&getStackAddr) >> 4;
    uint m = (uint)(&RandUint) << 8;
    a += getStackAddr();
    c += getStackAddr();
    m += getStackAddr();
    a = ror(a, 3);
    c = ror(c, 6);
    m = ror(m, 9);
    seed = ror(seed + a, 12);
    seed = ror(seed + c, 13);
    seed = ror(seed + m, 14);
    if (seed % 32 < 16)
    {
        seed = ror(seed, 7);
    }
    return (uint)((a * seed + c) % m);
}

#pragma warning(push)
#pragma warning(disable : 4172)
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
