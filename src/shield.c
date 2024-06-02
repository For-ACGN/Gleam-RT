#include "stdio.h"

#include "c_types.h"
#include "random.h"
#include "shield.h"

#define XOR_KEY_SIZE 256

__declspec(noinline)
bool DefenseRT(Shield_Ctx* ctx)
{
    // generate random key
    byte key[XOR_KEY_SIZE];
    RandBuf(&key[0], XOR_KEY_SIZE);
    // calculate shellcode position
    uintptr beginAddr = ctx->InstAddress;
    uintptr endAddr   = (uintptr)(&DefenseRT);

    printf("begin: %llX\n", beginAddr);
    printf("end: %llX\n", endAddr);

    // hide runtime(or with shellcode) instructions
    byte last   = 170;
    uint keyIdx = 0;
    for (uintptr addr = beginAddr; addr < endAddr; addr++)
    {
        byte* data = (byte*)addr;
        byte  enc  = *data ^ key[keyIdx] ^ last;
        // update status
        *data = enc;
        last  = enc;
        // update key index
        keyIdx++;
        if (keyIdx >= XOR_KEY_SIZE)
        {
            keyIdx = 0;
        }
    }
    // simulate kernel32.Sleep()
    bool success = ctx->WaitForSingleObject(ctx->hProcess, ctx->milliseconds);
    // recover runtime(or with shellcode) instructions
    last   = 170;
    keyIdx = 0;
    for (uintptr addr = beginAddr; addr < endAddr; addr++)
    {
        byte* data = (byte*)addr;
        byte  enc = *data ^ key[keyIdx] ^ last;
        // update status
        *data = enc;
        last = enc;
        // update key index
        keyIdx++;
        if (keyIdx >= XOR_KEY_SIZE)
        {
            keyIdx = 0;
        }
    }
    return success;
}
