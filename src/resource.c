#include <stdio.h>

#include "c_types.h"
#include "windows_t.h"
#include "hash_api.h"
#include "list_md.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "resource.h"

#define RES_WSA 0x0000

typedef struct {
    // API addresses
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;

    // track API
    WSAStartup_t WSAStartup;
    WSACleanup_t WSACleanup;

    // runtime data
    HANDLE Mutex; // global mutex

    // store all resource counters
    uint Counters[1];
} ResourceTracker;

// methods about resource tracker
int RT_WSAStartup(uint16 wVersionRequired, void* lpWSAData);
int RT_WSACleanup();

errno RT_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define TRACKER_POINTER 0x7FABCDEF11111104
#elif _WIN32
    #define TRACKER_POINTER 0x7FABCD04
#endif
static ResourceTracker* getTrackerPointer();

static bool rt_lock(ResourceTracker* tracker);
static bool rt_unlock(ResourceTracker* tracker);

static bool initTrackerAPI(ResourceTracker* tracker, Context* context);
static bool updateTrackerPointer(ResourceTracker* tracker);
static bool initTrackerEnvironment(ResourceTracker* tracker, Context* context);

ResourceTracker_M* InitResourceTracker(Context* context)
{





}

static bool initTrackerAPI(ResourceTracker* tracker, Context* context)
{
    tracker->ReleaseMutex = context->ReleaseMutex;
    tracker->WaitForSingleObject = context->WaitForSingleObject;
    return true;
}


int RT_WSAStartup(uint16 wVersionRequired, void* lpWSAData)
{

}

int RT_WSACleanup()
{

}

errno RT_Clean()
{

}

