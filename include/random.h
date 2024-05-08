#ifndef RANDOM_H
#define RANDOM_H

#include "c_types.h"

// RandBuf is used to fill random bytes to the memory.
void RandBuf(byte* buf, int64 size);

// RandByte is used to generate random byte.
byte RandByte(uint64 seed);

// RandBool is used to generate random bool.
bool RandBool(uint64 seed);

// RandInt is used to generate random int.
int RandInt(uint64 seed);

// RandUint is used to generate random uint.
uint RandUint(uint64 seed);

// RandInt64 is used to generate random int64.
int64 RandInt64(uint64 seed);

// RandUint64 is used to generate random uint64.
uint64 RandUint64(uint64 seed);

#endif // RANDOM_H
