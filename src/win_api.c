#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
#include "win_api.h"

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

void ParsePEImage(byte* address, PE_Info* info)
{
    uintptr imageAddr = (uintptr)address;
    uint32  peOffset  = *(uint32*)(imageAddr + 60);
    // parse file header
    uint16 numSections   = *(uint16*)(imageAddr + peOffset + 6);
    uint16 optHeaderSize = *(uint16*)(imageAddr + peOffset + 20);
    // parse optional header
    uint32  entryPoint = *(uint32*)(imageAddr + peOffset + 40);
#ifdef _WIN64
    uintptr imageBase = *(uintptr*)(imageAddr + peOffset + 48);
#elif _WIN32
    uintptr imageBase = *(uintptr*)(imageAddr + peOffset + 52);
#endif
    uint32 imageSize = *(uint32*)(imageAddr + peOffset + 80);
    // parse sections and search .text
    uintptr section = imageAddr + PE_FILE_HEADER_SIZE + peOffset + optHeaderSize;
    for (uint16 i = 0; i < numSections; i++)
    {
        // not record the original ".text" bytes
        uint64 name = *(uint64*)section ^ 0x000000FFFFFFFFFF;
        if (name != (0x000000747865742E ^ 0x000000FFFFFFFFFF))
        {
            section += PE_SECTION_HEADER_SIZE;
            continue;
        }
        info->TextVirtualSize      = *(uint32*)(section + 8); 
        info->TextVirtualAddress   = *(uint32*)(section + 12); 
        info->TextSizeOfRawData    = *(uint32*)(section + 16); 
        info->TextPointerToRawData = *(uint32*)(section + 20);
        break;
    }
    info->EntryPoint = imageAddr + entryPoint;
    info->ImageBase  = imageBase;
    info->ImageSize  = imageSize;
}
