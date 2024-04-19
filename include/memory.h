#ifndef MEMORY_H
#define MEMORY_H

#include "go_types.h"
#include "hash_api.h"

uint InitMemMgr(FindAPI_t findAPI);

void* MemAlloc(uint size);

void MemFree(uintptr address);

#endif // MEMORY_H
