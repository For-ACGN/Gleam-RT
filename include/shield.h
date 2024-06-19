#ifndef SHIELD_H
#define SHIELD_H

#include "c_types.h"
#include "windows_t.h"

typedef bool (*sleep_t)(uint32 milliseconds);

typedef struct {
    uintptr InstAddress;
    uint32  SleepTime;
	sleep_t Sleep;
} Shield_Ctx;

bool DefenseRT(Shield_Ctx* ctx);

#endif // SHIELD_H
