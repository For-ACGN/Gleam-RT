#ifndef HASH_API_H
#define HASH_API_H

#include "go_types.h"

#ifdef _WIN64
typedef uintptr (*FindAPI_t)(uint64 hash, uint64 key);
#elif _WIN32
typedef uintptr (*FindAPI_t)(uint32 hash, uint32 key);
#endif

// FindAPI is used to FindAPI address by hash and key.
#ifdef _WIN64
uintptr FindAPI(uint64 hash, uint64 key);
#elif _WIN32
uintptr FindAPI(uint32 hash, uint32 key);
#endif

#endif // HASH_API_H
