#include <stdio.h>
#include "c_types.h"
#include "lib_memory.h"
#include "random.h"
#include "crypto.h"
#include "test.h"

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

    byte data1[128];
    byte data2[128];
    RandBuf(&data1[0], 64);

    // write repetitive and orderly data
    for (byte i = 0; i < 16; i++)
    {
        data1[i] = i;
    }
    for (byte i = 0; i < 16; i++)
    {
        data1[i+16] = i;
    }
    for (byte i = 0; i < 64; i++)
    {
        data1[i + 64] = 0;
    }
    mem_copy(&data2[0], &data1[0], sizeof(data1));
    data2[0]++;

    // write repetitive and orderly iv
    byte iv1[CRYPTO_IV_SIZE];
    byte iv2[CRYPTO_IV_SIZE];
    RandBuf(&iv1[0], sizeof(iv1));
    RandBuf(&iv2[0], sizeof(iv2));
    // for (byte i = 0; i < CRYPTO_IV_SIZE; i++)
    // {
    //     iv1[i] = i;
    // }
    // mem_copy(&iv2[0], &iv1[0], sizeof(iv1));

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
    printf("=======TestDecryptBuf begin========\n");

    byte key[CRYPTO_KEY_SIZE];
    RandBuf(&key[0], sizeof(key));

    byte data1[64];
    byte data2[64];
    RandBuf(&data1[0], sizeof(data1));
    mem_copy(&data2[0], &data1[0], sizeof(data1));

    byte iv[CRYPTO_IV_SIZE];
    RandBuf(&iv[0], sizeof(iv));

    printf("plain data:\n");
    printHexBytes(&data2[0], sizeof(data2));

    EncryptBuf(&data2[0], sizeof(data2), &key[0], &iv[0]);

    printf("cipher data:\n");
    printHexBytes(&data2[0], sizeof(data2));

    DecryptBuf(&data2[0], sizeof(data2), &key[0], &iv[0]);

    // compare the decrypted data
    for (uint i = 0; i < sizeof(data1); i++)
    {
        if (data1[i] != data2[i])
        {
            printf("[error] plain data is incorrect");
            return false;
        }
    }

    printf("=======TestDecryptBuf passed=======\n\n");
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
