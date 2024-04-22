#include <stdio.h>
#include "test.h"

int main()
{
    if (!TestRandom())
    {
        return -1;
    }
    if (!TestCrypto())
    {
        return -1;
    }
    printf("all tests passed!\n");
}
