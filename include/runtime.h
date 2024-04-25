#ifndef RUNTIME_H
#define RUNTIME_H

#include "go_types.h"
#include "windows_t.h"

typedef void* (*MemAlloc_t)(uint size);
typedef void  (*MemFree_t)(void* addr);

typedef void (*Hide_t)();
typedef void (*Recover_t)();
typedef void (*Clean_t)();

typedef struct {
    MemAlloc_t   MemAlloc;
    MemFree_t    MemFree;
    VirtualAlloc VirtualAlloc;
    VirtualFree  VirtualFree;
    CreateThread CreateThread;

    Hide_t    Hide;
    Recover_t Recover;
    Clean_t   Clean;
} RuntimeM;

RuntimeM* NewRuntime(FindAPI_t findAPI);

#endif // RUNTIME_H
