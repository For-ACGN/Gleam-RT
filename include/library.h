#ifndef LIBRARY_H
#define LIBRARY_H

#include "c_types.h"
#include "windows_t.h"
#include "context.h"
#include "errno.h"

typedef bool  (*LibEncrypt_t)();
typedef bool  (*LibDecrypt_t)();
typedef errno (*LibClean_t)();

typedef struct {
    LoadLibraryA_t             LoadLibraryA;
    LoadLibraryW_t             LoadLibraryW;
    LoadLibraryExA_t           LoadLibraryExA;
    LoadLibraryExW_t           LoadLibraryExW;
    FreeLibrary_t              FreeLibrary;
    FreeLibraryAndExitThread_t FreeLibraryAndExitThread;

    LibEncrypt_t LibEncrypt;
    LibDecrypt_t LibDecrypt;
    LibClean_t   LibClean;
} LibraryTracker_M;

LibraryTracker_M* InitLibraryTracker(Context* context);

#endif // LIBRARY_H
