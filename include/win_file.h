#ifndef WIN_FILE_H
#define WIN_FILE_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"
#include "errno.h"

// The memory buffer that from ReadFile must call Runtime_M.MemFree.

typedef bool (*WFReadFileA_t)(LPSTR path, byte** buf, uint* size);
typedef bool (*WFReadFileW_t)(LPWSTR path, byte** buf, uint* size);
typedef bool (*WFWriteFileA_t)(LPSTR path, byte* buf, uint size);
typedef bool (*WFWriteFileW_t)(LPWSTR path, byte* buf, uint size);

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
