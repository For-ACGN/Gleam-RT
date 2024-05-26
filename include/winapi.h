#ifndef WINAPI_H
#define WINAPI_H

#include "c_types.h"
#include "windows_t.h"

uint32 GetModuleFileName(HMODULE hModule, byte* name, uint32 size);

#endif // WINAPI_H
