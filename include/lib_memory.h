#ifndef LIB_MEMORY_H
#define LIB_MEMORY_H

#include "c_types.h"

typedef void* (*malloc_t)(uint size);
typedef void* (*calloc_t)(uint num, uint size);
typedef void* (*realloc_t)(void* ptr, uint size);
typedef bool  (*free_t)(void* ptr);

// mem_copy is used to copy source memory data to the destination.
void mem_copy(void* dst, void* src, uint size);

// mem_init is used to fill the memory with zero.
void mem_init(void* ptr, uint num);

// mem_set is used to fill the memory with value.
void mem_set(void* ptr, byte val, uint num);

// mem_equal is used to compare the memory is equal.
bool mem_equal(void* dst, void* src, uint size);

// mem_zero is used to check the memory are all zero.
bool mem_is_zero(void* ptr, uint size);

#endif // LIB_MEMORY_H
