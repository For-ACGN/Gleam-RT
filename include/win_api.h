#ifndef WIN_API_H
#define WIN_API_H

#include "c_types.h"
#include "windows_t.h"

typedef struct {
    uintptr EntryPoint;
    uintptr ImageBase;
    uint32  ImageSize;
} PE_Info;

uint32 GetModuleFileName(HMODULE hModule, byte* name, uint32 size);
void   ParsePEImage(void* address, PE_Info* info);

#endif // WIN_API_H
