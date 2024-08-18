#ifndef COMPRESS_H
#define COMPRESS_H

#include "c_types.h"

// Compress is used to compress data with aPLib.
uint Compress(void* dst, void* src);

// Decompress is used to decompress data with aPLib.
uint Decompress(void* dst, void* src);

#endif // COMPRESS_H
