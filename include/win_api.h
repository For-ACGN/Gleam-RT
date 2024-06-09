#ifndef WIN_API_H
#define WIN_API_H

#include "c_types.h"
#include "windows_t.h"

#define PE_FILE_HEADER_SIZE    24
#define PE_SECTION_HEADER_SIZE 40

typedef struct {
    // optional header
    uintptr EntryPoint;
    uintptr ImageBase;
    uint32  ImageSize;

    // section information
    uint32 TextVirtualSize;
    uint32 TextVirtualAddress;
    uint32 TextSizeOfRawData;
    uint32 TextPointerToRawData;
} PE_Info;

uint32 GetModuleFileName(HMODULE hModule, byte* name, uint32 size);
void   ParsePEImage(void* address, PE_Info* info);

#endif // WIN_API_H
