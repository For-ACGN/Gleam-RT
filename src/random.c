#include "go_types.h"
#include "random.h"

static uint getStackAddr();
static uint ror(uint value, uint8 bits);

void RandBuf(byte* buf, uint size)
{
    uint data = RandUint((uint)(buf));
    for (uint i = 0; i < size; i++)
    {
        data = RandUint(data);
        *(buf + i) = (byte)data;
    }
}

byte RandByte(uint seed)
{
    return (byte)RandUint(seed);
}

uint RandUint(uint seed)
{
    uint a = (uint)(&ror);
    uint c = (uint)(&getStackAddr);
    uint m = (uint)(&RandUint);
    a += getStackAddr();
    c += getStackAddr();
    m += getStackAddr();
    a = ror(a, 11);
    c = ror(c, 17);
    m = ror(m, 28);
    if (m < UINT32_MAX / 2)
    {
        m = UINT32_MAX;
    }
    seed = ror(seed + a, 12);
    seed = ror(seed + c, 13);
    seed = ror(seed + m, 14);
    return (uint)((a * seed + c) % m);
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
