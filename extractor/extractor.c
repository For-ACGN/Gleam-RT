#include <stdio.h>
#include "c_types.h"
#include "runtime.h"
#include "epilogue.h"

int main()
{
#ifdef _WIN64
    FILE* file = fopen("../bin/GleamRT_x64.bin", "wb");
#elif _WIN32
    FILE* file = fopen("../bin/GleamRT_x86.bin", "wb");
#endif
    if (file == NULL)
    {
        printf("failed to open file");
        return 1;
    }

    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    uint64  size  = end - begin;

    uint64 n = fwrite((byte*)begin, size, 1, file);
    if (n != 1)
    {
        printf("failed to save shellcode");
        return 2;
    }
    fclose(file);

    printf("save shellcode successfully");
    return 0;
}
