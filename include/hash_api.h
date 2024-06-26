#ifndef HASH_API_H
#define HASH_API_H

#include "c_types.h"

typedef void* (*FindAPI_t)(uint hash, uint key);

// FindAPI is used to FindAPI address by hash and key.
void* FindAPI(uint hash, uint key);

// HashAPI_A is used to calculate Windows API hash by module
// and function with key, module and function are ASCII.
uint   HashAPI_A  (byte* module, byte* function, uint key);
uint64 HashAPI64_A(byte* module, byte* function, uint64 key);
uint32 HashAPI32_A(byte* module, byte* function, uint32 key);

// HashAPI_W is used to calculate Windows API hash by module
// and function with key, module is Unicode, function is ASCII.
uint   HashAPI_W  (uint16* module, byte* function, uint key);
uint64 HashAPI64_W(uint16* module, byte* function, uint64 key);
uint32 HashAPI32_W(uint16* module, byte* function, uint32 key);

#endif // HASH_API_H
