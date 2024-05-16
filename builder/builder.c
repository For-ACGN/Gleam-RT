#include <stdio.h>
#include "c_types.h"
#include "runtime.h"
#include "epilogue.h"

int main()
{
    FILE* file = fopen("../bin/runtime.bin", "wb");
    if (file == NULL)
    {
        printf("failed to open file");
        return -1;
    }

    uintptr begin = (uintptr)(&InitRuntime);
    uintptr end   = (uintptr)(&Epilogue);
    uint64  size  = end - begin + 3;

    uint64 n = fwrite((byte*)begin, size, 1, file);
    if (n != 1)
    {
        printf("failed to save shellcode");
        return -1;
    }
    fclose(file);

    printf("save shellcode successfully");
    return 0;
}
