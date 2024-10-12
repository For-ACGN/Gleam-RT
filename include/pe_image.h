#ifndef PE_IMAGE_H
#define PE_IMAGE_H

#include "c_types.h"

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

void ParsePEImage(void* address, PE_Info* info);

#endif // PE_IMAGE_H
