#include "go_types.h"
#include "crypto.h"

static void generateSBox(byte* box, byte* key);
static byte swapBit(byte b, uint8 p1, uint8 p2);
static byte ror(byte value, uint8 bits);
static byte rol(byte value, uint8 bits);

void EncryptBuf(byte* buf, uint size, byte* key)
{
    if (size == 0)
    {
        return;
    } 
    // initialize S-Box
    byte sBox[256];
    generateSBox(&sBox[0], key);
    // initialize status
    uint kIdx = 0;
    byte last = 255;
    byte xor  = 170;
    byte cKey;
    byte data;
    for (uintptr i = 0; i < size; i++)
    {
        // update current key byte
        cKey = *(key + kIdx);

        // read byte from buffer
        data = *(buf + i);

        data ^= cKey;
        data ^= last;

        // permutation
        data = sBox[data];


        // write byte to the buffer
        *(buf + i) = data;

        // update key index
        kIdx++;
        if (kIdx >= CRYPTO_KEY_SIZE)
        {
            kIdx = 0;
        }

        last = data;


        continue;

        // xor with the data
        xor += ror(xor, last % 8);
        xor += swapBit(xor, last % 8, data % 8);
        data ^= xor;
        // xor, swap bit and ror
        for (int i = 0; i < CRYPTO_KEY_SIZE; i++)
        {
            byte kb = *(key + i);
            data ^= kb;
            
            data = swapBit(data, last % 8, xor % 8);
            data = ror(data, last % 8);
            data = swapBit(data, xor % 8, kb % 8);
            data = ror(data, xor % 8);
            data = swapBit(data, xor % 8, last % 8);
            data = ror(data, kb % 8);
            
            data ^= xor;
            // permutation
            data = sBox[data];
            // update status
            last = data;
            xor  = data ^ kb;
        }
        // write byte to the buffer
        *(buf + i) = data;
    }
}

void DecryptBuf(byte* buf, uint size, byte* key)
{
    if (size == 0)
    {
        return;
    }
    // initialize S-Box
    byte sBox[256];
    generateSBox(&sBox[0], key);
    // initialize reverse S-Box
    byte rBox[256];
    for (int i = 0; i < 256; i++)
    {
        rBox[sBox[i]] = i;
    }
    // set the new S-Box
    for (int i = 0; i < 256; i++)
    {
        sBox[i] = rBox[i];
    }
    // initialize status
    byte data;
    for (int64 i = (int64)size - 1; i > -1; i--)
    {
        // read byte from buffer
        data = *(buf + i);

        *(buf + i) = sBox[data];
        continue;
    }
}

static void generateSBox(byte* box, byte* key)
{
    // initialize S-Box byte array
    for (int i = 0; i < 256; i++)
    {
        box[i] = i;
    }
    // initialize seed for LCG;
    uint seed = 1;
    for (int i = 0; i < CRYPTO_KEY_SIZE; i++)
    {
        seed *= *(key + i);
    }
    uint a = *(uint32*)(key + 10);
    uint c = *(uint32*)(key + 24);
    // generate S-Box from key
    for (int i = 0; i < CRYPTO_KEY_SIZE; i++)
    {
        byte k = *(key + i);
        byte t = k;
        byte idx;
        byte swap;
        for (int j = 0; j < t; j++)
        {
            idx = (byte)(seed) + k;
            swap = box[idx];
            box[idx] = box[0];
            box[0] = swap;
            // update LCG status
            seed = (a * seed + c) % UINT32_MAX;
            k++;
        }
    }
}

static byte swapBit(byte b, uint8 p1, uint8 p2)
{
    // extract the bits at pos1 and pos2
    byte bit1 = (b >> p1) & 1;
    byte bit2 = (b >> p2) & 1;
    if (bit1 == bit2)
    {
        return b;
    }
    // use XOR to flip the bits
    b ^= (1 << p1);
    b ^= (1 << p2);
    return b;
}

static byte ror(byte value, uint8 bits)
{
    return value >> bits | value << (8 - bits);
}

static byte rol(byte value, uint8 bits)
{
    return value << bits | value >> (8 - bits);
}
