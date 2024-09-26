#ifndef HASH_API_H
#define HASH_API_H

#include "c_types.h"

// FindAPI will not call GetProcAddress, if this module 
// is not loaded, it cannot find the target proc address.
//
// FindAPI is support forwarded function.
// FindAPI is NOT support API Sets.

typedef void* (*FindAPI_t)(uint hash, uint key);
typedef void* (*FindAPI_A_t)(byte* module, byte* function);
typedef void* (*FindAPI_W_t)(uint16* module, byte* function);

// FindAPI is used to find Windows API address by hash and key.
void* FindAPI(uint hash, uint key);

// FindAPI_A is used to find Windows API address by module name
// and function name with ANSI, it is a wrapper about FindAPI.
void* FindAPI_A(byte* module, byte* function);

// FindAPI_W is used to find Windows API address by module name
// and function name with Unicode, it is a wrapper about FindAPI.
void* FindAPI_W(uint16* module, byte* function);

// HashAPI_A is used to calculate Windows API hash by module
// and function with key, module and function are ANSI.
uint   HashAPI_A  (byte* module, byte* function, uint key);
uint64 HashAPI64_A(byte* module, byte* function, uint64 key);
uint32 HashAPI32_A(byte* module, byte* function, uint32 key);

// HashAPI_W is used to calculate Windows API hash by module
// and function with key, module is Unicode, function is ANSI.
uint   HashAPI_W  (uint16* module, byte* function, uint key);
uint64 HashAPI64_W(uint16* module, byte* function, uint64 key);
uint32 HashAPI32_W(uint16* module, byte* function, uint32 key);

#endif // HASH_API_H
