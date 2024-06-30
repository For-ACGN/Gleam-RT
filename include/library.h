#ifndef LIBRARY_H
#define LIBRARY_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"
#include "errno.h"

typedef bool  (*LibLock_t)();
typedef bool  (*LibUnlock_t)();
typedef errno (*LibEncrypt_t)();
typedef errno (*LibDecrypt_t)();
typedef errno (*LibClean_t)();

typedef struct {
    LoadLibraryA_t             LoadLibraryA;
    LoadLibraryW_t             LoadLibraryW;
    LoadLibraryExA_t           LoadLibraryExA;
    LoadLibraryExW_t           LoadLibraryExW;
    FreeLibrary_t              FreeLibrary;
    FreeLibraryAndExitThread_t FreeLibraryAndExitThread;

    LibLock_t    LibLock;
    LibUnlock_t  LibUnlock;
    LibEncrypt_t LibEncrypt;
    LibDecrypt_t LibDecrypt;
    LibClean_t   LibClean;
} LibraryTracker_M;

LibraryTracker_M* InitLibraryTracker(Context* context);

#endif // LIBRARY_H
