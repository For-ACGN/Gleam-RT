#include "go_types.h"
#include "crypto.h"

static void encryptBuf(byte* buf, uint size, byte* key, byte* sBox, byte* pLast);
static void decryptBuf(byte* buf, uint size, byte* key, byte* sBox, byte* pLast);
static void initSBox(byte* box, byte* key);
static byte swapBit(byte b, uint8 p1, uint8 p2);
static byte ror(byte value, uint8 bits);
static byte rol(byte value, uint8 bits);

void EncryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    if (size == 0)
    {
        return;
    } 
    // initialize S-Box
    byte sBox[256];
    initSBox(&sBox[0], key);
    // encrypt iv and data
    byte last = 255;
    encryptBuf(iv, CRYPTO_IV_SIZE, key, &sBox[0], &last);
    encryptBuf(buf, size, key, &sBox[0], &last);
}

static void encryptBuf(byte* buf, uint size, byte* key, byte* sBox, byte* pLast)
{
    // initialize status
    uint kIdx = 0;
    byte last = *pLast;
    byte cKey;
    byte data;
    // encrypt buffer
    for (uintptr i = 0; i < size; i++)
    {
        // update current key byte
        cKey = *(key + kIdx);

        // read byte from buffer
        data = *(buf + i);

        data ^= last;
        data = swapBit(data, last % 8, cKey % 8);
        data = ror(data, last % 8);

        data ^= cKey;
        data = swapBit(data, last % 8, cKey % 8);
        data = ror(data, cKey % 8);

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

        // update last byte
        last = data;
    }
    // save status
    *pLast = last;
}

void DecryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    if (size == 0)
    {
        return;
    }
    // initialize S-Box
    byte sBox[256];
    initSBox(&sBox[0], key);
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
    // decrypt iv and data
    byte last = 255;
    decryptBuf(iv, CRYPTO_IV_SIZE, key, &sBox[0], &last);
    decryptBuf(buf, size, key, &sBox[0], &last);
}

static void decryptBuf(byte* buf, uint size, byte* key, byte* sBox, byte* pLast)
{
    // initialize status
    uint kIdx = 0;
    byte last = *pLast;
    byte cKey;
    byte data;
    // decrypt buffer
    for (uintptr i = 0; i < size; i++)
    {
        // update current key byte
        cKey = *(key + kIdx);

        // read byte from buffer
        data = *(buf + i);

        // permutation
        data = sBox[data];

        data = rol(data, cKey % 8);
        data = swapBit(data, last % 8, cKey % 8);
        data ^= cKey;

        data = rol(data, last % 8);
        data = swapBit(data, last % 8, cKey % 8);
        data ^= last;

        // update last byte
        last = *(buf + i);

        // write byte to the buffer
        *(buf + i) = data;

        // update key index
        kIdx++;
        if (kIdx >= CRYPTO_KEY_SIZE)
        {
            kIdx = 0;
        }
    }
    // save status
    *pLast = last;
}

static void initSBox(byte* box, byte* key)
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
