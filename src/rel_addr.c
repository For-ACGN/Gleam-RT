#include "c_types.h"
#include "rel_addr.h"

#ifndef _WIN64

#pragma optimize("", off)
void* GetFuncAddr(void* func)
{
    uintptr addr = 0; // store address about GetFuncAddr
    _asm {
        call get_eip
        jmp exit_asm    
    get_eip:
        pop eax       ; pop return address from stack
        mov addr, eax ; mov address to variable addr
        sub addr, 9+5 ; this function prologue + call
        push eax      ; restore eax
        ret
    exit_asm:
    }
    uintptr offset = (uintptr)(func) - (uintptr)(&GetFuncAddr);
    return (void*)(addr + offset);
}
#pragma optimize("", on)

#endif
