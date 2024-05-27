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

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF11111100
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCD00
#endif
static LibraryTracker* getTrackerPointer();

static bool initTrackerAPI(LibraryTracker* tracker, Context* context);
static bool updateTrackerPointer(LibraryTracker* tracker);
static bool initTrackerEnvironment(LibraryTracker* tracker, Context* context);

LibraryTracker_M* InitLibraryTracker(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr trackerAddr = address + 1000 + RandUint(address) % 128;
    uintptr moduleAddr  = address + 1600 + RandUint(address) % 128;
    // initialize tracker
    LibraryTracker* tracker = (LibraryTracker*)trackerAddr;
    uint errCode = 0;
    for (;;)
    {
        if (!initTrackerAPI(tracker, context))
        {
            errCode = 0x01;
            break;
        }
        if (!updateTrackerPointer(tracker))
        {
            errCode = 0x02;
            break;
        }
        if (!initTrackerEnvironment(tracker, context))
        {
            errCode = 0x03;
            break;
        }
        break;
    }
    if (errCode != 0x00)
    {
        return (LibraryTracker_M*)errCode;
    }


    return NULL;
}

static bool initTrackerAPI(LibraryTracker* tracker, Context* context)
{
    typedef struct { 
        uint hash; uint key; uintptr address;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xFF631CDB135AB431, 0xF2D25F476CA15E97 }, // LoadLibraryA
        { 0x214DF62A80434DBF, 0xEB0FDC717FC827A5 }, // LoadLibraryW
        { 0x2F6B12D80C0B77BC, 0xDB036D7FA710BE44 }, // LoadLibraryExA
        { 0xC9297DE7F8C97F1C, 0x580EBCC7C3411C35 }, // LoadLibraryExW
        { 0xD0E21A35D744228B, 0x8283AFE6F719D579 }, // FreeLibrary
        { 0x0708BC7E2C7DA370, 0x39B9AC22BC408886 }, // FreeLibraryAndExitThread
    };
#elif _WIN32
    {
        { 0x434519BD, 0x621ABBD9 }, // LoadLibraryA
        { 0xCE3D1172, 0x0FB89CC3 }, // LoadLibraryW
        { 0x46B4638A, 0x213466F9 }, // LoadLibraryExA
        { 0xDBB0F0FE, 0x516334AA }, // LoadLibraryExW
        { 0xE44CF885, 0xF6D45D9F }, // FreeLibrary
        { 0x7730C1E2, 0xF5551C66 }, // FreeLibraryAndExitThread
    };
#endif
    uintptr address;
    for (int i = 0; i < arrlen(list); i++)
    {
        address = FindAPI(list[i].hash, list[i].key);
        if (address == NULL)
        {
            return false;
        }
        list[i].address = address;
    }

    tracker->LoadLibraryA             = (LoadLibraryA_t            )(list[0].address);
    tracker->LoadLibraryW             = (LoadLibraryW_t            )(list[1].address);
    tracker->LoadLibraryExA           = (LoadLibraryExA_t          )(list[2].address);
    tracker->LoadLibraryExW           = (LoadLibraryExW_t          )(list[3].address);
    tracker->FreeLibrary              = (FreeLibrary_t             )(list[4].address);
    tracker->FreeLibraryAndExitThread = (FreeLibraryAndExitThread_t)(list[5].address);
    return true;
}

static bool updateTrackerPointer(LibraryTracker* tracker)
{

}

static bool initTrackerEnvironment(LibraryTracker* tracker, Context* context)
{

}

