#ifndef SHIELD_H
#define SHIELD_H

#include "c_types.h"
#include "windows_t.h"

typedef struct {
    uintptr InstAddress;
    uint32  milliseconds;
	HANDLE  hProcess;
	
	WaitForSingleObject_t   WaitForSingleObject;
    FlushInstructionCache_t FlushInstructionCache;
} Shield_Ctx;

bool DefenseRT(Shield_Ctx* ctx);

#endif // SHIELD_H
