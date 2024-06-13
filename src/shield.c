#include <intrin.h>
#include "c_types.h"
#include "random.h"
#include "shield.h"

#define XOR_KEY_SIZE 256

void xorInstructions(Shield_Ctx* ctx, byte* key);

__declspec(noinline)
bool DefenseRT(Shield_Ctx* ctx)
{
    // generate random key
    byte key[XOR_KEY_SIZE];
    RandBuf(&key[0], XOR_KEY_SIZE);
    // hide runtime(or with shellcode) instructions
    xorInstructions(ctx, &key[0]);
    // simulate kernel32.Sleep()
    bool success = ctx->WaitForSingleObject(ctx->hProcess, ctx->milliseconds);
    _mm_mfence();
    // recover runtime(or with shellcode) instructions
    xorInstructions(ctx, &key[0]);
    // must flush instruction cache
    uintptr baseAddr = ctx->InstAddress;
    uint    instSize = (uintptr)(&DefenseRT) - baseAddr;
    if (!ctx->FlushInstructionCache(CURRENT_PROCESS, baseAddr, instSize))
    {
        return false;
    }
    return success;
}

void xorInstructions(Shield_Ctx* ctx, byte* key)
{
    // calculate shellcode position
    uintptr beginAddr = ctx->InstAddress;
    uintptr endAddr   = (uintptr)(&DefenseRT);
    _mm_mfence();
    // hide runtime(or with shellcode) instructions
    byte keyIdx = 0;
    for (uintptr addr = beginAddr; addr < endAddr; addr++)
    {
        byte* data = (byte*)addr;
        byte k = key[keyIdx];
        *data ^= k;
        // select key
        keyIdx = k+1;
    }
    _mm_mfence();
}
