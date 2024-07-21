#ifndef TEST_H
#define TEST_H

#include "c_types.h"

bool TestRandom();
bool TestCrypto();

bool TestInitRuntime();
bool TestRuntime_Exit();

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = {
    { "Random", TestRandom },
    { "Crypto", TestCrypto },

    { "InitRuntime",  TestInitRuntime  },


    { "Runtime_Exit", TestRuntime_Exit },
};

#endif // TEST_H
