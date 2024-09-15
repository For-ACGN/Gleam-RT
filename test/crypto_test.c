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
    test_t tests[] = 
    {
        { TestEncryptBuf },
        { TestDecryptBuf },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        if (!tests[i]())
        {
            return false;
        }
    }
    return true;
}

static bool TestEncryptBuf()
{
    printf_s("=======TestEncryptBuf begin========\n");

    byte key[CRYPTO_KEY_SIZE];
    RandBuf(key, sizeof(key));

    byte data1[128];
    byte data2[128];
    RandBuf(data1, 64);

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
    mem_copy(data2, data1, sizeof(data1));
    data2[0]++;

    // write repetitive and orderly iv
    byte iv1[CRYPTO_IV_SIZE];
    byte iv2[CRYPTO_IV_SIZE];
    RandBuf(iv1, sizeof(iv1));
    RandBuf(iv2, sizeof(iv2));
    // for (byte i = 0; i < CRYPTO_IV_SIZE; i++)
    // {
    //     iv1[i] = i;
    // }
    // mem_copy(iv2, iv1, sizeof(iv1));

    printf_s("plain data:\n");
    printHexBytes(data1, sizeof(data1));
    printHexBytes(data2, sizeof(data2));

    printf_s("cipher data:\n");
    EncryptBuf(data1, sizeof(data1), key, iv1);
    printHexBytes(data1, sizeof(data1));

    EncryptBuf(data2, sizeof(data2), key, iv2);
    printHexBytes(data2, sizeof(data2));

    printf_s("=======TestEncryptBuf passed=======\n\n");
    return true;
}

static bool TestDecryptBuf()
{
    printf_s("=======TestDecryptBuf begin========\n");

    byte key[CRYPTO_KEY_SIZE];
    RandBuf(key, sizeof(key));

    byte data1[64+4];
    byte data2[64+4];
    RandBuf(data1, sizeof(data1));
    mem_copy(data2, data1, sizeof(data1));

    byte iv[CRYPTO_IV_SIZE];
    RandBuf(iv, sizeof(iv));

    printf_s("plain data:\n");
    printHexBytes(data2, sizeof(data2));

    EncryptBuf(data2, sizeof(data2), key, iv);

    printf_s("cipher data:\n");
    printHexBytes(data2, sizeof(data2));

    DecryptBuf(data2, sizeof(data2), key, iv);

    // compare the decrypted data
    for (uint i = 0; i < sizeof(data1); i++)
    {
        if (data1[i] != data2[i])
        {
            printf_s("[error] plain data is incorrect");
            return false;
        }
    }

    printf_s("=======TestDecryptBuf passed=======\n\n");
    return true;
}

static void printHexBytes(byte* buf, uint size)
{
    int counter = 0;
    for (uint i = 0; i < size; i++)
    {
        printf_s("%02X ", *buf);

        buf++;
        counter++;
        if (counter >= 16)
        {
            counter = 0;
            printf_s("\n");
        }
    }
    printf_s("\n");
}
