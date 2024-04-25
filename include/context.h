#ifndef CONTEXT_H
#define CONTEXT_H

#include "go_types.h"
#include "windows_t.h"

typedef struct {
    VirtualAlloc   VirtualAlloc;
    VirtualFree    VirtualFree;
    VirtualProtect VirtualProtect;
    FlushInstCache FlushInstCache;
} Context;

#endif // CONTEXT_H
