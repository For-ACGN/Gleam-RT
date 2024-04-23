#include <stdio.h>
#include "go_types.h"
#include "random.h"

static void TestRandBuf();
static void TestRandByte();
static void TestRandUint64();

bool TestRandom()
{
    TestRandBuf();
    TestRandByte();
    TestRandUint64();
    return true;
}

static void TestRandBuf()
{
    printf("========TestRandBuf begin==========\n");

    byte buf[16];
    RandBuf(&buf[0], 16);

    printf("buf: ");
    for (int i = 0; i < sizeof(buf); i++)
    {
        printf("%d ", buf[i]);
    }
    printf("\n");

    printf("========TestRandBuf passed=========\n\n");
}

static void TestRandByte()
{
    printf("========TestRandByte begin=========\n");

    // will same
    for (uint i = 0; i < 3; i++)
    {
        printf("byte: %d\n", RandByte(0));
    }
    printf("\n");

    // will different
    uint last = (uint)(&TestRandBuf);
    for (uint i = 0; i < 3; i++)
    {
        last += RandByte(last);
        printf("byte: %d\n", (byte)last);
    }

    printf("========TestRandByte passed========\n\n");
}

static void TestRandUint64()
{
    printf("========TestRandUint begin=========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf("uint: %lld\n", RandUint64(0));
    }
    printf("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 3; i++)
    {
        last += RandUint64(last);
        printf("uint: %lld\n", last);
    }

    printf("========TestRandUint passed========\n\n");
}