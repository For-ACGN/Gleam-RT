#ifndef WIN_FILE_H
#define WIN_FILE_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"

// The memory that from ReadFile will not be encrypted,
// use it as quickly as possible, then call FreeBuf.

typedef bool (*WFReadFileA_t)(LPSTR path, byte** buf, uint* size);
typedef bool (*WFReadFileW_t)(LPWSTR path, byte** buf, uint* size);
typedef bool (*WFWriteFileA_t)(LPSTR path, byte* buf, uint size);
typedef bool (*WFWriteFileW_t)(LPWSTR path, byte* buf, uint size);

typedef struct {
    WFReadFileA_t  ReadFileA;
    WFReadFileW_t  ReadFileW;
    WFWriteFileA_t WriteFileA;
    WFWriteFileW_t WriteFileW;
} WinFile_M;

WinFile_M* InitWinFile(Context* context);

#endif // WIN_FILE_H
