#ifndef MSVCRT_T_H
#define MSVCRT_T_H

#include "c_types.h"

typedef void* (*msvcrt_malloc_t)
(
	uint size
);

typedef void* (*msvcrt_calloc_t)
(
	uint num, uint size
);

typedef void* (*msvcrt_realloc_t)
(
	void* ptr, uint size
);

typedef void (*msvcrt_free_t)
(
	void* ptr
);

#endif // MSVCRT_T_H
