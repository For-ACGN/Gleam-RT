#ifndef RESOURCE_H
#define RESOURCE_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"
#include "errno.h"

typedef errno (*ResEncrypt_t)();
typedef errno (*ResDecrypt_t)();
typedef errno (*ResClean_t)();

typedef struct {
    CreateFileA_t    CreateFileA;
    CreateFileW_t    CreateFileW;
    CloseHandle_t    CloseHandle;
    FindFirstFileA_t FindFirstFileA;
    FindFirstFileW_t FindFirstFileW;
    FindClose_t      FindClose;

    WSAStartup_t WSAStartup;
    WSACleanup_t WSACleanup;

    ResEncrypt_t ResEncrypt;
    ResDecrypt_t ResDecrypt;
    ResClean_t   ResClean;
} ResourceTracker_M;

ResourceTracker_M* InitResourceTracker(Context* context);

#endif // RESOURCE_H
