#ifndef TEST_H
#define TEST_H

#include "c_types.h"
#include "runtime.h"

// define global variables for tests
Runtime_M* runtime;

// define unit tests
bool TestLibString();
bool TestRandom();
bool TestCrypto();

bool TestInitRuntime();
bool TestRuntime_Memory();
bool TestRuntime_Argument();
bool TestRuntime_Exit();

typedef bool (*test_t)();
typedef struct { byte* Name; test_t Test; } unit;

static unit tests[] = 
{
    { "Lib_String", TestLibString },
    { "Random",     TestRandom    },
    { "Crypto",     TestCrypto    },

    { "InitRuntime",      TestInitRuntime      },
    { "Runtime_Memory",   TestRuntime_Memory   },
    { "Runtime_Argument", TestRuntime_Argument },
    { "Runtime_Exit",     TestRuntime_Exit     },
};

#endif // TEST_H
