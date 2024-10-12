#include "c_types.h"
#include "windows_t.h"
#include "pe_image.h"

void ParsePEImage(void* address, PE_Image* image)
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
        image->TextVirtualSize      = *(uint32*)(section + 8); 
        image->TextVirtualAddress   = *(uint32*)(section + 12); 
        image->TextSizeOfRawData    = *(uint32*)(section + 16); 
        image->TextPointerToRawData = *(uint32*)(section + 20);
        break;
    }
    image->EntryPoint = imageAddr + entryPoint;
    image->ImageBase  = imageBase;
    image->ImageSize  = imageSize;
}
