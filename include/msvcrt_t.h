#ifndef MSVCRT_T_H
#define MSVCRT_T_H

#include "c_types.h"

typedef void* (__cdecl *msvcrt_malloc_t)
(
	uint size
);

typedef void* (__cdecl *msvcrt_calloc_t)
(
	uint num, uint size
);

typedef void* (__cdecl *msvcrt_realloc_t)
(
	void* ptr, uint size
);

typedef void (__cdecl *msvcrt_free_t)
(
	void* ptr
);

#endif // MSVCRT_T_H
