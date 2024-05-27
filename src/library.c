#include <stdio.h>

#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "list_md.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "library.h"

typedef struct {
    HMODULE hModule;
} module;

typedef struct {
    // API addresses
    LoadLibraryA_t             LoadLibraryA;
    LoadLibraryW_t             LoadLibraryW;
    LoadLibraryExA_t           LoadLibraryExA;
    LoadLibraryExW_t           LoadLibraryExW;
    FreeLibrary_t              FreeLibrary;
    FreeLibraryAndExitThread_t FreeLibraryAndExitThread;

    // runtime data
    HANDLE Mutex; // global mutex

    // store all modules info
    List Modules;
    byte ModulesKey[CRYPTO_KEY_SIZE];
    byte ModulesIV [CRYPTO_IV_SIZE];
} LibraryTracker;

LibraryTracker_M* InitLibraryTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 1000 + RandUint(address) % 128;
    uintptr moduleAddr  = address + 1600 + RandUint(address) % 128;
    // initialize tracker
    LibraryTracker* tracker = (LibraryTracker*)trackerAddr;
    uint errCode = 0;
    return NULL;
}
