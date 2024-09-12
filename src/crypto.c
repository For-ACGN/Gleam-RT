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

static void encryptBuf(byte* buf, uint size, byte* key, byte* sBox);
static void decryptBuf(byte* buf, uint size, byte* key, byte* sBox);
static void initSBox(byte* sBox, byte* key, byte* iv);
static void permuteSBox(byte* sBox);
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
    // offset is used to prevent incorrect optimization
    byte offset = key[0];
    // initialize S-Box byte array
    for (int i = 0; i < 256; i++)
    {
        sBox[i] = (byte)i + offset;
    }
    // initialize seed for XOR Shift;
    uint seed = 1;
    for (int i = 0; i < CRYPTO_KEY_SIZE; i++)
    {
        seed *= *(key + i);
    }
    for (int i = 0; i < CRYPTO_IV_SIZE; i++)
    {
        seed *= *(iv + i);
    }
    // generate S-Box from key and iv
    for (int i = 0; i < CRYPTO_KEY_SIZE; i++)
    {
        byte k = *(key + i);
        for (int j = 0; j < CRYPTO_IV_SIZE; j++)
        {
            k += *(iv + j);
            // swap array item
            byte idx  = (byte)(seed) + k;
            byte swap = sBox[idx];
            sBox[idx] = sBox[0];
            sBox[0] = swap;
            // update xor shift 64 seed
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
        }
    }
}

static void permuteSBox(byte* sBox)
{
    // use "mem_clean" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    byte sBox_cp[256];
    mem_clean(&sBox_cp, sizeof(sBox_cp));
    mem_copy(&sBox_cp[0], sBox, sizeof(sBox_cp));
    for (int i = 0; i < 256; i++)
    {
        sBox[sBox_cp[i]] = (byte)i;
    }
    mem_clean(&sBox_cp[0], sizeof(sBox_cp));
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
    for (uint i = 0; i < size; i++)
    {
        *buf ^= *key + *iv;
        buf++;
    }
}

void DecryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    for (uint i = 0; i < size; i++)
    {
        *buf ^= *key + *iv;
        buf++;
    }
}

#endif
