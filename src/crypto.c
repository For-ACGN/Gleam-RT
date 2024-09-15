#include "build.h"
#include "c_types.h"
#include "lib_memory.h"
#include "crypto.h"

// !!!!!!!!  It is NOT cryptographically secure  !!!!!!!!!
// 
// The main purpose of this symmetric encryption algorithm
// is to encrypt the data in the memory so that it looks 
// like there is no obvious pattern. 
// 
// It's main design goal is to be as small as possible and 
// not to use a simple XOR encryption.

#ifndef FAST_CRYPTO

#define PARALLEL_LEVEL 8

static void encryptBuf(byte* buf, uint size, byte* key, byte* sBox);
static void decryptBuf(byte* buf, uint size, byte* key, byte* sBox);
static void initSBox(byte* sBox, byte* key, byte* iv);
static void permuteSBox(byte* sBox);
static uint xorShift(uint seed);
static byte negBit(byte b, uint8 n);
static byte swapBit(byte b, uint8 p1, uint8 p2);
static byte ror(byte value, uint8 bits);
static byte rol(byte value, uint8 bits);

#pragma optimize("t", on)

void EncryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    if (size == 0)
    {
        return;
    }
    byte sBox[256];
    initSBox(sBox, key, iv);
    encryptBuf(buf, size, key, sBox);
}

static void encryptBuf(byte* buf, uint size, byte* key, byte* sBox)
{
    uintptr i = 0;
    uint limit = size - (size % PARALLEL_LEVEL);
    for (; i < limit; i += PARALLEL_LEVEL)
    {
        // load plain data
        byte b0 = buf[i + 0];
        byte b1 = buf[i + 1];
        byte b2 = buf[i + 2];
        byte b3 = buf[i + 3];
        byte b4 = buf[i + 4];
        byte b5 = buf[i + 5];
        byte b6 = buf[i + 6];
        byte b7 = buf[i + 7];

        // permutation
        b0 = sBox[b0];
        b1 = sBox[b1];
        b2 = sBox[b2];
        b3 = sBox[b3];
        b4 = sBox[b4];
        b5 = sBox[b5];
        b6 = sBox[b6];
        b7 = sBox[b7];

        // store cipher data
        buf[i + 0] = b0;
        buf[i + 1] = b1;
        buf[i + 2] = b2;
        buf[i + 3] = b3;
        buf[i + 4] = b4;
        buf[i + 5] = b5;
        buf[i + 6] = b6;
        buf[i + 7] = b7;
    }
    // process remaining not aligned data
    for (; i < size; i++)
    {
        buf[i] = sBox[buf[i]];
    }

    return;



    // initialize status
    uint kIdx = 0;
    byte dCtr = 0;
    uint bCtr = 0;
    byte last = 1;
    byte cKey;
    byte data;
    // encrypt buffer
    for (uintptr i = 0; i < size; i++)
    {
        // update current key byte
        cKey = *(key + kIdx);

        // read byte from buffer
        data = *(buf + i);

        data ^= dCtr;
        data = negBit(data, dCtr % 8);
        data = swapBit(data, dCtr % 8, cKey % 8);
        data = ror(data, dCtr % 8);
        data = sBox[data]; // permutation

        data ^= last;
        data = negBit(data, last % 8);
        data = swapBit(data, last % 8, cKey % 8);
        data = ror(data, last % 8);
        data = sBox[data]; // permutation

        data ^= cKey;
        data = negBit(data, cKey % 8);
        data = swapBit(data, last % 8, cKey % 8);
        data = ror(data, cKey % 8);
        data = sBox[data]; // permutation

        // write byte to the buffer
        *(buf + i) = data;

        // update last
        last = data;

        // update key index
        kIdx++;
        if (kIdx >= CRYPTO_KEY_SIZE)
        {
            kIdx = 0;
        }

        // update counter
        dCtr += (kIdx + cKey + last) % 16;
        bCtr += (kIdx + cKey + last) % 32;
    }
}

void DecryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    if (size == 0)
    {
        return;
    }
    byte sBox[256];
    initSBox(sBox, key, iv);
    permuteSBox(sBox);
    decryptBuf(buf, size, key, sBox);
}

static void decryptBuf(byte* buf, uint size, byte* key, byte* sBox)
{
    uintptr i  = 0;
    uint limit = size - (size % PARALLEL_LEVEL);
    for (; i < limit; i += PARALLEL_LEVEL)
    {
        // load cipher data
        byte b0 = buf[i + 0];
        byte b1 = buf[i + 1];
        byte b2 = buf[i + 2];
        byte b3 = buf[i + 3];
        byte b4 = buf[i + 4];
        byte b5 = buf[i + 5];
        byte b6 = buf[i + 6];
        byte b7 = buf[i + 7];


        // permutation
        b0 = sBox[b0];
        b1 = sBox[b1];
        b2 = sBox[b2];
        b3 = sBox[b3];
        b4 = sBox[b4];
        b5 = sBox[b5];
        b6 = sBox[b6];
        b7 = sBox[b7];

        // store plain data
        buf[i + 0] = b0;
        buf[i + 1] = b1;
        buf[i + 2] = b2;
        buf[i + 3] = b3;
        buf[i + 4] = b4;
        buf[i + 5] = b5;
        buf[i + 6] = b6;
        buf[i + 7] = b7;
    }
    // process remaining not aligned data
    for (; i < size; i++)
    {
        buf[i] = sBox[buf[i]];
    }

    return;




    // initialize status
    uint kIdx = 0;
    byte dCtr = 0;
    uint bCtr = 0;
    byte last = 1;
    byte cKey;
    byte data;
    // decrypt buffer
    for (uintptr i = 0; i < size; i++)
    {
        // update current key byte
        cKey = *(key + kIdx);

        // read byte from buffer
        data = *(buf + i);

        data = sBox[data];
        data = rol(data, cKey % 8);
        data = swapBit(data, last % 8, cKey % 8);
        data = negBit(data, cKey % 8);
        data ^= cKey;

        data = sBox[data];
        data = rol(data, last % 8);
        data = swapBit(data, last % 8, cKey % 8);
        data = negBit(data, last % 8);
        data ^= last;

        data = sBox[data];
        data = rol(data, dCtr % 8);
        data = swapBit(data, dCtr % 8, cKey % 8);
        data = negBit(data, dCtr % 8);
        data ^= dCtr;

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

        // update counter
        dCtr += (kIdx + cKey + last) % 16;
        bCtr += (kIdx + cKey + last) % 32;
    }
}

static void initSBox(byte* sBox, byte* key, byte* iv)
{
    // initialize S-Box byte array
    for (int i = 0; i < 256; i++)
    {
        // + key[0] is used to prevent 
        // incorrect compiler optimization
        sBox[i] = (byte)i + key[0];
    }
    // initialize seed for XOR Shift;
    uint seed = 1;
    for (int i = 0; i < CRYPTO_KEY_SIZE; i++)
    {
        seed += *(key + i);
    }
    for (int i = 0; i < CRYPTO_IV_SIZE; i++)
    {
        seed *= *(iv + i);
    }
    // generate S-Box from random index
    for (int i = 0; i < 128; i++)
    {
        // swap array item
        seed = xorShift(seed);
        byte idx0 = (byte)(seed+32);
        byte idx1 = (byte)(seed+64);
        byte swap = sBox[idx0];
        sBox[idx0] = sBox[idx1];
        sBox[idx1] = swap;
    }
}

static void permuteSBox(byte* sBox)
{
    byte buf[256];
    mem_copy(buf, sBox, sizeof(buf));
    for (int i = 0; i < 256; i++)
    {
        sBox[buf[i]] = (byte)i;
    }
}

static uint xorShift(uint seed)
{
#ifdef _WIN64
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
#elif _WIN32
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
#endif
    return seed;
}

static byte negBit(byte b, uint8 n)
{
    return b ^ (1 << n);
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

#pragma optimize("t", off)

#else

void EncryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    byte b = *key + *iv;
    for (uint i = 0; i < size; i++)
    {
        *buf ^= b;
        buf++;
    }
}

void DecryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    byte b = *key + *iv;
    for (uint i = 0; i < size; i++)
    {
        *buf ^= b;
        buf++;
    }
}

#endif
