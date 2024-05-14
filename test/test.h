#ifndef TEST_H
#define TEST_H

#include "c_types.h"

bool TestRandom();
bool TestCrypto();
bool TestRuntime();

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = {
    { "TestRandom",  TestRandom },
    { "TestCrypto",  TestCrypto },
    { "TestRuntime", TestRuntime },
};

#endif // TEST_H
