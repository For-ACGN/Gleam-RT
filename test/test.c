#include <stdio.h>
#include "test.h"

int main()
{
    if (!TestRandom())
    {
        return 1;
    }
    if (!TestCrypto())
    {
        return 2;
    }
    if (!TestRuntime())
    {
        return 3;
    }
    printf("All tests passed!\n");
    return 0;
}
