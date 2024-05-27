#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"

uint32 GetModuleFileName(HMODULE hModule, byte* name, uint32 size)
{
#ifdef _WIN64
    uintptr peb = __readgsqword(96);
    uintptr ldr = *(uintptr*)(peb + 24);
    uintptr mod = *(uintptr*)(ldr + 32);
#elif _WIN32
    uintptr peb = __readfsdword(48);
    uintptr ldr = *(uintptr*)(peb + 12);
    uintptr mod = *(uintptr*)(ldr + 20);
#endif
    for (;; mod = *(uintptr*)(mod))
    {
    #ifdef _WIN64
        uintptr modName = *(uintptr*)(mod + 80);
    #elif _WIN32
        uintptr modName = *(uintptr*)(mod + 40);
    #endif
        if (modName == 0x00)
        {
            break;
        }
    #ifdef _WIN64
        uintptr modBase = *(uintptr*)(mod + 32);
    #elif _WIN32
        uintptr modBase = *(uintptr*)(mod + 16);
    #endif
        if (modBase != hModule)
        {
            continue;
        }
    #ifdef _WIN64
        uint16 nameLen = *(uint16*)(mod + 74);
    #elif _WIN32
        uint16 nameLen = *(uint16*)(mod + 38);
    #endif
        if (nameLen > size)
        {
            nameLen = size;
        }
        mem_copy(name, (byte*)modName, nameLen);
        return nameLen;
    }
    return 0;
}
