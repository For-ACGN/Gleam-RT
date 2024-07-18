#include "c_types.h"
#include "windows_t.h"
#include "lib_memory.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "argument.h"
#include "debug.h"

// +----------+----------+----------+----------+----------+
// |    key   |   size   | num args | arg size | arg data |
// +----------+----------+----------+----------+----------+
// | 32 bytes |  uint32  |  uint32  |  uint32  |    var   |
// +----------+----------+----------+----------+----------+

#define ARG_OFFSET_CRYPTO_KEY (0+0)
#define ARG_OFFSET_TOTAL_SIZE (0+32)
#define ARG_OFFSET_NUM_ARGS   (32+4)
#define ARG_OFFSET_FIRST_ARG  (36+4)

typedef struct {
    // API addresses
    VirtualAlloc_t VirtualAlloc;
    VirtualFree_t  VirtualFree;

    // store arguments
    byte* Address;
    uint  Size;

    byte Key[CRYPTO_KEY_SIZE];
    byte IV [CRYPTO_IV_SIZE];
} ArgumentStore;

// methods for runtime
void* AS_Get();
errno AS_Encrypt();
errno AS_Decrypt();
errno AS_Clean();

// hard encoded address in getTrackerPointer for replacement
#ifdef _WIN64
    #define STORE_POINTER 0x7FABCDEF11111105
#elif _WIN32
    #define STORE_POINTER 0x7FABCD05
#endif
static ArgumentStore* getStorePointer();

static bool initStoreAPI(ArgumentStore* store, Context* context);
static bool updateStorePointer(ArgumentStore* store);
static bool initStoreEnvironment(ArgumentStore* store, Context* context);

static void eraseStoreMethods();
static void cleanStore(ArgumentStore* store);

ArgumentStore_M* InitArgumentStore(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr storeAddr  = address + 7000 + RandUintN(address, 128);
    uintptr moduleAddr = address + 7700 + RandUintN(address, 128);
    // initialize tracker
    ArgumentStore* store = (ArgumentStore*)storeAddr;
    mem_clean(store, sizeof(ArgumentStore));
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initStoreAPI(store, context))
        {
            errno = ERR_ARGUMENT_INIT_API;
            break;
        }
        if (!updateStorePointer(store))
        {
            errno = ERR_ARGUMENT_UPDATE_PTR;
            break;
        }
        if (!initStoreEnvironment(store, context))
        {
            errno = ERR_ARGUMENT_INIT_ENV;
            break;
        }
        break;
    }
    eraseStoreMethods();
    if (errno != NO_ERROR)
    {
        cleanStore(store);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for store
    ArgumentStore_M* module = (ArgumentStore_M*)moduleAddr;
    // methods for runtime
    module->Get     = &AS_Get;
    module->Encrypt = &AS_Encrypt;
    module->Decrypt = &AS_Decrypt;
    module->Clean   = &AS_Clean;
    return module;
}

__declspec(noinline)
static bool initStoreAPI(ArgumentStore* store, Context* context)
{
    store->VirtualAlloc = context->VirtualAlloc;
    store->VirtualFree  = context->VirtualFree;
    return true;
}

__declspec(noinline)
static bool updateStorePointer(ArgumentStore* store)
{
    bool success = false;
    uintptr target = (uintptr)(&getStorePointer);
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != STORE_POINTER)
        {
            target++;
            continue;
        }
        *pointer = (uintptr)store;
        success = true;
        break;
    }
    return success;
}

static bool initStoreEnvironment(ArgumentStore* store, Context* context)
{



    // uintptr stub = (uintptr)(&Argument_Stub);
    // byte*   key  = (byte*)(stub + ARG_OFFSET_CRYPTO_KEY);
    // uint32  size = *(uint32*)(stub + ARG_OFFSET_TOTAL_SIZE);


    return NO_ERROR;
}

// updateStorePointer will replace hard encode address to the actual address.
// Must disable compiler optimize, otherwise updateStorePointer will fail.
#pragma optimize("", off)
static ArgumentStore* getStorePointer()
{
    uint pointer = STORE_POINTER;
    return (ArgumentStore*)(pointer);
}
#pragma optimize("", on)

