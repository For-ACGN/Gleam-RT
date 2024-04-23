#include <stdio.h>
#include "go_types.h"
#include "random.h"

static void TestRandBuf();
static void TestRandByte();
static void TestRandBool();
static void TestRandInt();
static void TestRandUint();
static void TestRandInt64();
static void TestRandUint64();

bool TestRandom()
{
    TestRandBuf();
    TestRandByte();
    TestRandBool();
    TestRandInt();
    TestRandUint();
    TestRandInt64();
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
    uint64 last = (uint64)(&TestRandBuf);
    for (uint i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandByte(last);
        printf("byte: %lld\n", val);
        last += val;
    }

    printf("========TestRandByte passed========\n\n");
}

static void TestRandBool()
{
    printf("=========TestRandBool begin========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf("bool: %d\n", RandBool(0));
    }
    printf("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandBool(last);
        printf("bool: %lld\n", val);
        last += last + val + 1;
    }

    printf("========TestRandBool passed========\n\n");
}

static void TestRandInt()
{
    printf("=========TestRandInt begin=========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf("int: %lld\n", (uint64)RandInt(0));
    }
    printf("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt(last);
        printf("int: %lld\n", val);
        last += val;
    }

    printf("=========TestRandInt passed========\n\n");
}

static void TestRandUint()
{
    printf("=========TestRandUint begin========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf("uint: %lld\n", (uint64)RandUint(0));
    }
    printf("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandUint(last);
        printf("uint: %lld\n", val);
        last += val;
    }

    printf("========TestRandUint passed========\n\n");
}

static void TestRandInt64()
{
    printf("========TestRandInt64 begin========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf("int64: %lld\n", (uint64)RandInt64(0));
    }
    printf("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt64(last);
        printf("int64: %lld\n", val);
        last += val;
    }

    printf("========TestRandInt64 passed=======\n\n");
}

static void TestRandUint64()
{
    printf("=======TestRandUint64 begin========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf("uint64: %lld\n", RandUint64(0));
    }
    printf("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = RandUint64(last);
        printf("uint64: %lld\n", val);
        last += val;
    }

    printf("=======TestRandUint64 passed=======\n\n");
}
