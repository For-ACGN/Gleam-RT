#include "build.h"
#include "c_types.h"
#include "rel_addr.h"

#ifndef _WIN64

#pragma optimize("", off)
void* GetFuncAddr(void* func)
{
#ifndef RELEASE_MODE
    return func;
#else
    uintptr addr = 0; // get address about GetFuncAddr
    _asm {
        call get_eip
        jmp exit_asm    
    get_eip:
        pop eax       ; pop return address from stack
        mov addr, eax ; mov address to variable addr
        sub addr, 8+5 ; function prologue + call
        push eax
    exit_asm:
    }
    return (void*)(addr + (uintptr)func);
#endif
}
#pragma optimize("", on)

#endif
