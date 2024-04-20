#include "go_types.h"
#include "crypto.h"

static byte swapBit(byte b, uint8 p1, uint8 p2);
static uint ror(uint value, uint8 bits);
static uint rol(uint value, uint8 bits);

__declspec(noinline) void EncryptBuf(byte* buf, uint size, byte* key)
{
    // initialize S-Box byte array
    byte sBox[256];
    for (int i = 0; i < 256; i++)
    {
        sBox[i] = i;
    }
    // initialize seed for LCG;
    uint seed = 1;
    for (int i = 0; i < ENCRYPT_KEY_SIZE; i++)
    {
        seed *= *(key + i);
    }
    uint a = *(uint32*)(key+10);
    uint c = *(uint32*)(key+24);
    // generate S-Box from key
    for (int i = 0; i < ENCRYPT_KEY_SIZE; i++)
    {
        byte k = *(key + i);
        byte t = k;
        byte idx;
        byte swap;
        for (int j = 0; j < t; j++)
        {
            idx = (byte)(seed) + k;
            swap = sBox[idx];
            sBox[idx] = sBox[0];
            sBox[0] = swap;

            seed = (a * seed + c) % UINT32_MAX;
            k++;
        }
    }

    *(buf + 0) = sBox[7] + sBox[2] + sBox[13] + sBox[5];
    *(buf + 1) = sBox[6] + sBox[22] + sBox[59] + sBox[15];
    *(buf + 2) = sBox[87] + sBox[47] + sBox[23] + sBox[5];
    *(buf + 3) = sBox[12] + sBox[211] + sBox[3] + sBox[65];


    return;

    // (uint)((a * seed + c) % m)



    byte counter = 0;
    byte data;
    for (uintptr i = 0; i < size; i++)
    {
        data = *(buf + i);

    }
}

void DecryptBuf(byte* buf, uint size, byte* key)
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
