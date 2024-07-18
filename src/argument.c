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
    uint  NumArgs;

    byte Key[CRYPTO_KEY_SIZE];
    byte IV [CRYPTO_IV_SIZE];
} ArgumentStore;

// methods for runtime
void* AS_Get(uint index);
errno AS_Encrypt();
errno AS_Decrypt();
errno AS_Clean();

// hard encoded address in getStorePointer for replacement
#ifdef _WIN64
    #define STORE_POINTER 0x7FABCDEF11111105
#elif _WIN32
    #define STORE_POINTER 0x7FABCD05
#endif
static ArgumentStore* getStorePointer();

static bool  initStoreAPI(ArgumentStore* store, Context* context);
static bool  updateStorePointer(ArgumentStore* store);
static bool  initStoreEnvironment(ArgumentStore* store);
static errno loadArguments(ArgumentStore* store);

static void eraseStoreMethods();
static void cleanStore(ArgumentStore* store);

ArgumentStore_M* InitArgumentStore(Context* context)
{
    // set structure address
    uintptr address = context->MainMemPage;
    uintptr storeAddr  = address + 7000 + RandUintN(address, 128);
    uintptr moduleAddr = address + 7700 + RandUintN(address, 128);
    // initialize store
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
        if (!initStoreEnvironment(store))
        {
            errno = ERR_ARGUMENT_INIT_ENV;
            break;
        }
        errno = loadArguments(store);
        if (errno != NO_ERROR)
        {
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

static bool initStoreEnvironment(ArgumentStore* store)
{
    // set crypto context data
    RandBuf(&store->Key[0], CRYPTO_KEY_SIZE);
    RandBuf(&store->IV[0], CRYPTO_IV_SIZE);
    return true;
}

static errno loadArguments(ArgumentStore* store)
{
    // uintptr stub = (uintptr)(&Argument_Stub);
    // byte*   key  = (byte*)(stub + ARG_OFFSET_CRYPTO_KEY);
    // uint32  size = *(uint32*)(stub + ARG_OFFSET_TOTAL_SIZE);
    dbg_log("[argument]", "arguments: %zu\n", store->NumArgs);
    return NO_ERROR;
}

__declspec(noinline)
static void eraseStoreMethods()
{
    uintptr begin = (uintptr)(&initStoreAPI);
    uintptr end   = (uintptr)(&eraseStoreMethods);
    uintptr size  = end - begin;
    RandBuf((byte*)begin, (int64)size);
}

__declspec(noinline)
static void cleanStore(ArgumentStore* store)
{
    if (store->VirtualFree != NULL && store->Address != NULL)
    {
        store->VirtualFree(store->Address, 0, MEM_RELEASE);
    }
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

__declspec(noinline)
void* AS_Get(uint index)
{
    ArgumentStore* store = getStorePointer();

    return NULL;
}

__declspec(noinline)
errno AS_Encrypt()
{
    ArgumentStore* store = getStorePointer();

    byte* key = &store->Key[0];
    byte* iv  = &store->IV[0];
    RandBuf(key, CRYPTO_KEY_SIZE);
    RandBuf(iv, CRYPTO_IV_SIZE);
    EncryptBuf(store->Address, store->Size, key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno AS_Decrypt()
{
    ArgumentStore* store = getStorePointer();

    byte* key = &store->Key[0];
    byte* iv  = &store->IV[0];
    DecryptBuf(store->Address, store->Size, key, iv);
    return NO_ERROR;
}

__declspec(noinline)
errno AS_Clean()
{
    ArgumentStore* store = getStorePointer();

    errno errno = NO_ERROR;

    RandBuf(store->Address, store->Size);
    if (!store->VirtualFree(store->Address, 0, MEM_RELEASE))
    {
        errno = ERR_ARGUMENT_FREE_MEM;
    }
    return errno;
}
