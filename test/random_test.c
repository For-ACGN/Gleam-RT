#include <stdio.h>
#include "c_types.h"
#include "random.h"
#include "test.h"

static void TestRandBuf();
static void TestRandByte();
static void TestRandBool();
static void TestRandInt();
static void TestRandUint();
static void TestRandInt64();
static void TestRandUint64();

bool TestRandom()
{
    typedef void (*test_t)();
    test_t tests[] = 
    {
        { TestRandBuf    },
        { TestRandByte   },
        { TestRandBool   },
        { TestRandInt    },
        { TestRandUint   },
        { TestRandInt64  },
        { TestRandUint64 },
    };
    for (int i = 0; i < arrlen(tests); i++)
    {
        tests[i]();
    }
    return true;
}

static void TestRandBuf()
{
    printf_s("========TestRandBuf begin==========\n");

    byte buf[16];
    RandBuf(&buf[0], 16);

    printf_s("buf: ");
    for (int i = 0; i < sizeof(buf); i++)
    {
        printf_s("%d ", buf[i]);
    }
    printf_s("\n");

    printf_s("========TestRandBuf passed=========\n\n");
}

static void TestRandByte()
{
    printf_s("========TestRandByte begin=========\n");

    // will same
    for (uint i = 0; i < 3; i++)
    {
        printf_s("byte: %d\n", RandByte(0));
    }
    printf_s("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (uint i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandByte(last);
        printf_s("byte: %lld\n", val);
        last += val;
    }

    printf_s("========TestRandByte passed========\n\n");
}

static void TestRandBool()
{
    printf_s("=========TestRandBool begin========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf_s("bool: %d\n", RandBool(0));
    }
    printf_s("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandBool(last);
        printf_s("bool: %lld\n", val);
        last += last + val + 1;
    }

    printf_s("========TestRandBool passed========\n\n");
}

static void TestRandInt()
{
    printf_s("=========TestRandInt begin=========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf_s("int: %lld\n", (uint64)RandInt(0));
    }
    printf_s("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt(last);
        printf_s("int: %lld\n", val);
        last += val;
    }

    printf_s("=========TestRandInt passed========\n\n");
}

static void TestRandUint()
{
    printf_s("=========TestRandUint begin========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf_s("uint: %llu\n", (uint64)RandUint(0));
    }
    printf_s("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandUint(last);
        printf_s("uint: %llu\n", val);
        last += val;
    }

    printf_s("========TestRandUint passed========\n\n");
}

static void TestRandInt64()
{
    printf_s("========TestRandInt64 begin========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf_s("int64: %lld\n", (uint64)RandInt64(0));
    }
    printf_s("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = (uint64)RandInt64(last);
        printf_s("int64: %lld\n", val);
        last += val;
    }

    printf_s("========TestRandInt64 passed=======\n\n");
}

static void TestRandUint64()
{
    printf_s("=======TestRandUint64 begin========\n");

    // will same
    for (int i = 0; i < 3; i++)
    {
        printf_s("uint64: %llu\n", RandUint64(0));
    }
    printf_s("\n");

    // will different
    uint64 last = (uint64)(&TestRandBuf);
    for (int i = 0; i < 5; i++)
    {
        uint64 val = RandUint64(last);
        printf_s("uint64: %llu\n", val);
        last += val;
    }

    printf_s("=======TestRandUint64 passed=======\n\n");
}
