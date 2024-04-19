#ifndef RANDOM_H
#define RANDOM_H

#include "go_types.h"

void RandBuffer(uintptr address, uint size);
byte RandByte(uint seed);
uint RandUint(uint seed);

#endif // RANDOM_H
