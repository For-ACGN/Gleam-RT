#ifndef SHIELD_H
#define SHIELD_H

#include "c_types.h"
#include "windows_t.h"

typedef struct {
    uintptr BeginAddress;
    uintptr EndAddress;
    byte    CryptoKey[32];

    uint32  SleepTime;
    HANDLE  hProcess;

    WaitForSingleObject_t WaitForSingleObject;
} Shield_Ctx;

bool DefenseRT(Shield_Ctx* ctx);

// reserve stub for generate random shield instructions
extern void Shield_Stub();

#endif // SHIELD_H
