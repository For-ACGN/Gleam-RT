#include "go_types.h"
#include "random.h"

static uintptr getStackAddr();
static uint64  ror(uint64 value, uint8 bits);

void RandBuf(byte* buf, int64 size)
{
    uint64 data = RandUint64((uint64)(buf));
    for (int64 i = 0; i < size; i++)
    {
        data = RandUint64(data);
        *(buf + i) = (byte)data;
    }
}

byte RandByte(uint64 seed)
{
    return (byte)RandUint64(seed);
}

bool RandBool(uint64 seed)
{
    if (RandUint64(seed) % 2 == 0)
    {
        return false;
    }
    return true;
}

int RandInt(uint64 seed)
{
    return (int)RandUint64(seed);
}

uint RandUint(uint64 seed)
{
    return (uint)RandUint64(seed);
}

int64 RandInt64(uint64 seed)
{
    return (int64)RandUint64(seed);
}

uint64 RandUint64(uint64 seed)
{
    if (seed < INT32_MAX / 16)
    {
        seed += INT32_MAX / 16;
    }
    uint64 a = (uint64)(&ror);
    uint64 c = (uint64)(&getStackAddr);
    uint64 m = (uint64)(&RandUint);
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
    return (uint64)((a * seed + c) % m);
}

#pragma warning(push)
#pragma warning(disable: 4172)
static uintptr getStackAddr()
{
    uint stack = 0;
    return (uintptr)(&stack);
}
#pragma warning(pop)

static uint64 ror(uint64 value, uint8 bits)
{
    return value >> bits | value << (64 - bits);
}
