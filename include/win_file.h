#ifndef WIN_FILE_H
#define WIN_FILE_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"
#include "errno.h"

// The buffer allocated from ReadFile must call Runtime_M.MemFree.

typedef errno (*WFReadFileA_t)(LPSTR path, byte** buf, int64* size);
typedef errno (*WFReadFileW_t)(LPWSTR path, byte** buf, int64* size);
typedef errno (*WFWriteFileA_t)(LPSTR path, byte* buf, int64 size);
typedef errno (*WFWriteFileW_t)(LPWSTR path, byte* buf, int64 size);

typedef errno (*WFUninstall_t)();

typedef struct {
    WFReadFileA_t  ReadFileA;
    WFReadFileW_t  ReadFileW;
    WFWriteFileA_t WriteFileA;
    WFWriteFileW_t WriteFileW;

    WFUninstall_t Uninstall;
} WinFile_M;

WinFile_M* InitWinFile(Context* context);

#endif // WIN_FILE_H
