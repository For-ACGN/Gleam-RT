#ifndef UCRTBASE_T_H
#define UCRTBASE_T_H

#include "c_types.h"

typedef void* (__cdecl *ucrtbase_malloc_t)
(
	uint size
);

typedef void* (__cdecl *ucrtbase_calloc_t)
(
	uint num, uint size
);

typedef void* (__cdecl *ucrtbase_realloc_t)
(
	void* ptr, uint size
);

typedef void (__cdecl *ucrtbase_free_t)
(
	void* ptr
);

#endif // UCRTBASE_T_H
