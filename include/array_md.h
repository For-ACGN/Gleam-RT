#ifndef ARRAY_MD_H
#define ARRAY_MD_H

#include "go_types.h"

typedef struct {
    void* (*malloc) (uint size);
    void* (*realloc)(void* address, uint size);
    bool  (*free)   (void* address);
} ArrayMD_Ctx;

typedef struct {
    ArrayMD_Ctx ctx;

    void* data;
    uint  len;
    uint  cap;
    uint  elem;
} ArrayMD;

#endif // ARRAY_MD_H
