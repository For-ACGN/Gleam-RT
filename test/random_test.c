#include <stdio.h>

#include "go_types.h"
#include "random.h"

void TestRandBuf();

bool TestRandom()
{
    TestRandBuf();

    
    





    return true;
}

void TestRandBuf()
{
    printf("========TestRandBuf begin=========\n");

    byte buf[16];
    RandBuf(&buf[0], 16);

    printf("buf: ");
    for (int i = 0; i < sizeof(buf); i++)
    {
        printf("%d ", buf[i]);
    }
    printf("\n");

    printf("========TestRandBuf passed========\n");
}
