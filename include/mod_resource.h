#ifndef RESOURCE_H
#define RESOURCE_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"
#include "errno.h"

typedef bool  (*ResLock_t)();
typedef bool  (*ResUnlock_t)();
typedef errno (*ResEncrypt_t)();
typedef errno (*ResDecrypt_t)();
typedef errno (*ResClean_t)();

typedef struct {
    CreateFileA_t      CreateFileA;
    CreateFileW_t      CreateFileW;
    FindFirstFileA_t   FindFirstFileA;
    FindFirstFileW_t   FindFirstFileW;
    FindFirstFileExA_t FindFirstFileExA;
    FindFirstFileExW_t FindFirstFileExW;
    CloseHandle_t      CloseHandle;
    FindClose_t        FindClose;

    WSAStartup_t WSAStartup;
    WSACleanup_t WSACleanup;

    ResLock_t    Lock;
    ResUnlock_t  Unlock;
    ResEncrypt_t Encrypt;
    ResDecrypt_t Decrypt;
    ResClean_t   Clean;
} ResourceTracker_M;

ResourceTracker_M* InitResourceTracker(Context* context);

#endif // RESOURCE_H
