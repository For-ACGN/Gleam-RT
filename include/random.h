#ifndef RANDOM_H
#define RANDOM_H

#include "go_types.h"

// RandBuffer is used to fill random bytes to the memory.
void RandBuffer(byte* buf, uint size);

// RandByte is used to generate random byte.
byte RandByte(uint seed);

// RandUint is used to generate random unsigned integer.
uint RandUint(uint seed);

#endif // RANDOM_H
