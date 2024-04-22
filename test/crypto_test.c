#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "go_types.h"
#include "random.h"
#include "crypto.h"

static bool TestEncryptBuf();
static bool TestDecryptBuf();
static void printHexBytes(byte* buf, uint size);

bool TestCrypto()
{
    if (!TestEncryptBuf())
    {
        return false;    
    }
    if (!TestDecryptBuf())
    {
        return false;
    }
    return true;
}

static bool TestEncryptBuf()
{
    printf("=======TestEncryptBuf begin========\n");
    byte key[CRYPTO_KEY_SIZE];
    RandBuf(&key[0], sizeof(key));

    byte data1[64];
    byte data2[64];
    RandBuf(&data1[0], sizeof(data1));

    // write repetitive and orderly data
    for (uint i = 0; i < 16; i++)
    {
        data1[i] = i;
    }
    for (uint i = 0; i < 16; i++)
    {
        data1[i+16] = i;
    }
    memcpy(&data2[0], &data1[0], sizeof(data1));
    data2[0]++;

    byte iv1[CRYPTO_IV_SIZE];
    byte iv2[CRYPTO_IV_SIZE];
    // RandBuf(&iv1[0], sizeof(iv1));
    // memcpy(&iv2[0], &iv1[0], sizeof(iv1));

    printf("plain data:\n");
    printHexBytes(&data1[0], sizeof(data1));
    printHexBytes(&data2[0], sizeof(data2));

    printf("cipher data:\n");
    EncryptBuf(&data1[0], sizeof(data1), &key[0], &iv1[0]);
    printHexBytes(&data1[0], sizeof(data1));

    EncryptBuf(&data2[0], sizeof(data2), &key[0], &iv2[0]);
    printHexBytes(&data2[0], sizeof(data2));

    printf("=======TestEncryptBuf passed=======\n\n");
    return true;
}

static bool TestDecryptBuf()
{
    return true;
}

static void printHexBytes(byte* buf, uint size)
{
    int counter = 0;
    for (uint i = 0; i < size; i++)
    {
        printf("%02X ", *buf);

        buf++;
        counter++;
        if (counter >= 16)
        {
            counter = 0;
            printf("\n");
        }
    }
    printf("\n");
}
