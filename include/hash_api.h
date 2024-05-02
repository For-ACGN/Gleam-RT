#ifndef HASH_API_H
#define HASH_API_H

#include "go_types.h"

typedef uintptr (*FindAPI_t)(uint hash, uint key);

// FindAPI is used to FindAPI address by hash and key.
uintptr FindAPI(uint hash, uint key);

#endif // HASH_API_H
