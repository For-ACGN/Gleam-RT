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

static void encryptBuf(byte* buf, uint size, byte* key, byte* sBox, byte* pLast);
static void decryptBuf(byte* buf, uint size, byte* key, byte* sBox, byte* pLast);
static void initSBox(byte* sBox, byte* key);
static void initStatus(byte* iv, byte* sBox, byte* pLast);
static void rotateSBox(byte* sBox, byte key);
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
    // use "mem_clean" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    byte sBox[256];
    mem_clean(&sBox, sizeof(sBox));
    initSBox(&sBox[0], key);
    byte last = 170;
    initStatus(iv, &sBox[0], &last);
    encryptBuf(buf, size, key, &sBox[0], &last);
}

static void encryptBuf(byte* buf, uint size, byte* key, byte* sBox, byte* pLast)
{
    // initialize status
    uint kIdx = 0;
    byte dCtr = 0;
    uint bCtr = 0;
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

        // rotate S-Box
        if (bCtr >= 65536)
        {
            rotateSBox(sBox, cKey);
            bCtr = 0;
        }

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
    // save status
    *pLast = last;
}

void DecryptBuf(byte* buf, uint size, byte* key, byte* iv)
{
    if (size == 0)
    {
        return;
    }
    // use "mem_clean" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    byte sBox[256];
    mem_clean(&sBox, sizeof(sBox)); 
    initSBox(&sBox[0], key);
    byte last = 170;
    initStatus(iv, &sBox[0], &last);
    permuteSBox(&sBox[0]);
    decryptBuf(buf, size, key, &sBox[0], &last);
}

static void decryptBuf(byte* buf, uint size, byte* key, byte* sBox, byte* pLast)
{
    // initialize status
    uint kIdx = 0;
    byte dCtr = 0;
    uint bCtr = 0;
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

        // rotate S-Box
        if (bCtr >= 65536)
        {
            permuteSBox(&sBox[0]);
            rotateSBox(sBox, cKey);
            permuteSBox(&sBox[0]);
            bCtr = 0;
        }

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
    // save status
    *pLast = last;
}

// must disable compiler optimization for  
// prevent generate incorrect shellcode
#pragma optimize("", off)
static void initSBox(byte* sBox, byte* key)
{
    // initialize S-Box byte array
    for (int i = 0; i < 256; i++)
    {
        sBox[i] = i;
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
            swap = sBox[idx];
            sBox[idx] = sBox[0];
            sBox[0] = swap;
            // update LCG status
            seed = (a * seed + c) % UINT32_MAX;
            k++;
        }
    }
}
#pragma optimize("", on)

static void initStatus(byte* iv, byte* sBox, byte* pLast)
{
    byte idxA = 100;
    byte idxB = 170;
    for (int i = 0; i < CRYPTO_IV_SIZE; i++)
    {
        // swap S-Box item
        idxA += *(iv + i) + 1;
        idxB *= *(iv + i) + 2;
        byte prev  = sBox[idxA];
        sBox[idxA] = sBox[idxB];
        sBox[idxB] = prev;
        // update last byte
        *pLast += idxA % ((idxB % 64) + 1);
        *pLast += idxB % ((idxA % 64) + 1);
        // update swap index
        idxA += *pLast;
        idxB *= *pLast;
    }
}

// must disable compiler optimization for
// prevent generate incorrect shellcode
#pragma optimize("", off)
static void rotateSBox(byte* sBox, byte offset)
{
    byte first = sBox[0]+70;
    for (int i = 0; i < 255; i++)
    {
        sBox[i] = sBox[i + 1]+70;
    }
    sBox[255] = first;
}
#pragma optimize("", on)

static void permuteSBox(byte* sBox)
{
    // use "mem_clean" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    byte sBox_cp[256];
    mem_clean(&sBox_cp, sizeof(sBox_cp));
    mem_copy(&sBox_cp[0], sBox, sizeof(sBox_cp));
    for (int i = 0; i < 256; i++)
    {
        sBox[sBox_cp[i]] = i;
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
