#ifndef LIB_MEM_H
#define LIB_MEM_H

#include "c_types.h"

typedef void* (*malloc_t)(uint size);
typedef void* (*realloc_t)(void* address, uint size);
typedef bool  (*free_t)(void* address);

// mem_equal is used to compare the memory is equal.
bool mem_equal(void* dst, void* src, uint size);

// mem_zero is used to check the destination memory are all zero.
bool mem_zero(void* dst, uint size);

// mem_copy is used to copy source memory data to the destination.
void mem_copy(void* dst, void* src, uint size);

// mem_set is used to fill the memory with value.
void mem_set(void* ptr, byte val, uint num);

// mem_clean is used to fill the memory with zero.
void mem_clean(void* ptr, uint num);

#endif // LIB_MEM_H
