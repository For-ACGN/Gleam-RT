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

    // generate key and iv
    byte key[CRYPTO_KEY_SIZE];
    byte iv1[CRYPTO_IV_SIZE];
    byte iv2[CRYPTO_IV_SIZE];
    RandBuf(key, sizeof(key));
    RandBuf(iv1, sizeof(iv1));
    RandBuf(iv2, sizeof(iv2));

    // write repetitive and orderly data
    byte testdata[128];
    mem_init(testdata, sizeof(testdata));
    for (byte i = 0; i < 16; i++)
    {
        testdata[i+0]  = i;
        testdata[i+16] = i;
    }

    // copy test data
    byte data1[128];
    byte data2[128];
    mem_init(data1, sizeof(data1));
    mem_init(data2, sizeof(data2));
    mem_copy(data1, testdata, sizeof(data1));
    mem_copy(data2, testdata, sizeof(data2));
    data2[0]++;

    printf_s("plain data:\n");
    printHexBytes(data1, sizeof(data1));
    printHexBytes(data2, sizeof(data2));

    printf_s("cipher data with the different iv:\n");
    EncryptBuf(data1, sizeof(data1), key, iv1);
    EncryptBuf(data2, sizeof(data2), key, iv2);
    printHexBytes(data1, sizeof(data1));
    printHexBytes(data2, sizeof(data2));

    printf_s("cipher data with the same iv:\n");
    mem_init(data1, sizeof(data1));
    mem_init(data2, sizeof(data2));
    mem_copy(data1, testdata, sizeof(data1));
    mem_copy(data2, testdata, sizeof(data2));
    data2[0]++;

    EncryptBuf(data1, sizeof(data1), key, iv1);
    EncryptBuf(data2, sizeof(data2), key, iv1);
    printHexBytes(data1, sizeof(data1));
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
            printf_s("[error] plain data is incorrect\n");
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
