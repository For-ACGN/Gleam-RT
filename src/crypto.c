#include "go_types.h"
#include "crypto.h"

static byte swapBit(byte b, uint8 p1, uint8 p2);
static uint ror(uint value, uint8 bits);
static uint rol(uint value, uint8 bits);

bool EncryptBuf(uintptr buf, uint size, uintptr key)
{
    byte  counter = 0;
    byte  data;
    byte* ptr;
    for (uintptr i = 0; i < size; i++)
    {
        ptr = (*byte)(buf + i);
        data = *ptr;

    }
}

bool DecryptBuf(uintptr buf, uint size, uintptr key)
{

}

static byte swapBit(byte b, uint8 p1, uint8 p2)
{
    // extract the bits at pos1 and pos2
    int bit1 = (b >> p1) & 1;
    int bit2 = (b >> p2) & 1;
    if (bit1 == bit2)
    {
        return b;
    }
    // use XOR to flip the bits
    b ^= (1 << p1);
    b ^= (1 << p2);
    return b;
}

static uint ror(uint value, uint8 bits)
{
    #ifdef _WIN64
    return value >> bits | value << (64 - bits);
    #elif _WIN32
    return value >> bits | value << (32 - bits);
    #endif
}

static uint rol(uint value, uint8 bits)
{
    #ifdef _WIN64
    return value << bits | value >> (64 - bits);
    #elif _WIN32
    return value << bits | value >> (32 - bits);
    #endif
}
