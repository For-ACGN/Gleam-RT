#include <stdio.h>
#include "c_types.h"
#include "lib_string.h"
#include "test.h"

#define BANNER_BEGIN_SIZE 10 // strlen("Test Begin")
#define BANNER_END_SIZE   11 // strlen("Test Passed")
#define BANNER_FAIL_SIZE  11 // strlen("Test Failed")

static printBannerBegin(byte* name, uint len);
static printBannerEnd  (byte* name, uint len, bool pass);

int main()
{
    // calculate the banner length
    uint maxNameLen = 0;
    for (int i = 0; i < arrlen(tests); i++)
    {
        uint len = strlen_a(tests[i].Name);
        if (len > maxNameLen)
        {
            maxNameLen = len;
        }
    }
    // ================TestHashAPI begin================
    uint bannerLen = (uint)16 + BANNER_END_SIZE + maxNameLen + 16;

    // run unit tests
    bool fail = false;
    for (int i = 0; i < arrlen(tests); i++)
    {
        printBannerBegin(tests[i].Name, bannerLen);
        bool pass = tests[i].Test();
        if (!pass)
        {
            fail = true;
        }
        printBannerEnd(tests[i].Name, bannerLen, pass);
    }

    if (fail)
    {
        printf("Failed to test\n");
        return 1;
    }
    printf("All tests passed!\n");
    return 0;
}

static printBannerBegin(byte* name, uint len)
{
    uint padLen = ( len - BANNER_BEGIN_SIZE - strlen_a(name)) / 2;
    bool equal  = ( len - BANNER_BEGIN_SIZE - strlen_a(name)) % 2 == 0;
    // print prefix
    for (uint i = 0; i < padLen; i++)
    {
        printf("=");
    }
    printf("Test%s Begin", name);
    // print suffix
    for (uint i = 0; i < padLen; i++)
    {
        printf("=");
    }
    // padding data
    if (!equal)
    {
        printf("=");
    }
    printf("\n");
}

static printBannerEnd(byte* name, uint len, bool pass)
{
    uint padLen = ( len - BANNER_END_SIZE - strlen_a(name)) / 2;
    bool equal  = ( len - BANNER_END_SIZE - strlen_a(name)) % 2 == 0;
    // print prefix
    for (uint i = 0; i < padLen; i++)
    {
        printf("=");
    }
    if (pass)
    {
        printf("Test%s Passed", name);
    } else {
        printf("Test%s FAILED", name);
    }
    // print suffix
    for (uint i = 0; i < padLen; i++)
    {
        printf("=");
    }
    // padding data
    if (!equal)
    {
        printf("=");
    }
    printf("\n\n");
}
