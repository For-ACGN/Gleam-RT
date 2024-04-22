#include <stdio.h>

#include "go_types.h"
#include "crypto.h"

static bool TestEncryptBuf();
static bool TestDecryptBuf();

bool TestCrypto()
{
    if (!TestEncryptBuf())
    {
        return false;    
    }
    if (!TestDecryptBuf())
    {
        return false;
    }
    return true;
}

static bool TestEncryptBuf()
{
    return true;
}

static bool TestDecryptBuf()
{
    return true;
}
