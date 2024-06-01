#ifndef WIN_API_H
#define WIN_API_H

#include "c_types.h"
#include "windows_t.h"

uint32 GetModuleFileName(HMODULE hModule, byte* name, uint32 size);

#endif // WIN_API_H
