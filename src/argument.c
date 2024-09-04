#include "c_types.h"
#include "windows_t.h"
#include "rel_addr.h"
#include "lib_memory.h"
#include "context.h"
#include "random.h"
#include "crypto.h"
#include "errno.h"
#include "argument.h"
#include "debug.h"

// +---------+----------+----------+-----------+----------+----------+
// |   key   | checksum | num args | args size | arg size | arg data |
// +---------+----------+----------+-----------+----------+----------+
// | 32 byte |  uint32  |  uint32  |  uint32   |  uint32  |   var    |
// +---------+----------+----------+-----------+----------+----------+

#define ARG_CRYPTO_KEY_SIZE 32
#define ARG_HEADER_SIZE     (32 + 4 + 4 + 4)

#define ARG_OFFSET_CRYPTO_KEY (0)
#define ARG_OFFSET_CHECKSUM   (32)
#define ARG_OFFSET_NUM_ARGS   (32 + 4)
#define ARG_OFFSET_ARGS_SIZE  (32 + 4 + 4)
#define ARG_OFFSET_FIRST_ARG  (32 + 4 + 4 + 4)

typedef struct {
    // store options
    bool NotEraseInstruction;

    // API addresses
    VirtualAlloc_t        VirtualAlloc;
    VirtualFree_t         VirtualFree;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CloseHandle_t         CloseHandle;

    // store arguments
    byte*  Address;
    uint   Size;
    uint32 NumArgs;
    HANDLE hMutex;

    byte Key[CRYPTO_KEY_SIZE];
    byte IV [CRYPTO_IV_SIZE];
} ArgumentStore;

// methods for upper module
bool AS_GetValue(uint index, void* value, uint32* size);
bool AS_GetPointer(uint index, void** pointer, uint32* size);
bool AS_Erase(uint index);
void AS_EraseAll();

// methods for runtime
bool  AS_Lock();
bool  AS_Unlock();
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
static bool  recoverStorePointer(ArgumentStore* store);
static bool  initStoreEnvironment(ArgumentStore* store, Context* context);
static errno loadArguments(ArgumentStore* store, Context* context);

static void eraseStoreMethods(Context* context);
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
    // store options
    store->NotEraseInstruction = context->NotEraseInstruction;
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
        errno = loadArguments(store, context);
        if (errno != NO_ERROR)
        {
            break;
        }
        break;
    }
    eraseStoreMethods(context);
    if (errno != NO_ERROR)
    {
        cleanStore(store);
        SetLastErrno(errno);
        return NULL;
    }
    // create methods for store
    ArgumentStore_M* module = (ArgumentStore_M*)moduleAddr;
    // methods for upper module
    module->GetValue   = GetFuncAddr(&AS_GetValue);
    module->GetPointer = GetFuncAddr(&AS_GetPointer);
    module->Erase      = GetFuncAddr(&AS_Erase);
    module->EraseAll   = GetFuncAddr(&AS_EraseAll);
    // methods for runtime
    module->Lock    = GetFuncAddr(&AS_Lock);
    module->Unlock  = GetFuncAddr(&AS_Unlock);
    module->Encrypt = GetFuncAddr(&AS_Encrypt);
    module->Decrypt = GetFuncAddr(&AS_Decrypt);
    module->Clean   = GetFuncAddr(&AS_Clean);
    return module;
}

__declspec(noinline)
static bool initStoreAPI(ArgumentStore* store, Context* context)
{
    store->VirtualAlloc        = context->VirtualAlloc;
    store->VirtualFree         = context->VirtualFree;
    store->ReleaseMutex        = context->ReleaseMutex;
    store->WaitForSingleObject = context->WaitForSingleObject;
    store->CloseHandle         = context->CloseHandle;
    return true;
}

// CANNOT merge updateStorePointer and recoverStorePointer
// to one function with two arguments, otherwise the compiler
// will generate the incorrect instructions.

__declspec(noinline)
static bool updateStorePointer(ArgumentStore* store)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getStorePointer));
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

__declspec(noinline)
static bool recoverStorePointer(ArgumentStore* store)
{
    bool success = false;
    uintptr target = (uintptr)(GetFuncAddr(&getStorePointer));
    for (uintptr i = 0; i < 64; i++)
    {
        uintptr* pointer = (uintptr*)(target);
        if (*pointer != (uintptr)store)
        {
            target++;
            continue;
        }
        *pointer = STORE_POINTER;
        success = true;
        break;
    }
    return success;
}

static bool initStoreEnvironment(ArgumentStore* store, Context* context)
{
    // create mutex
    HANDLE hMutex = context->CreateMutexA(NULL, false, NULL);
    if (hMutex == NULL)
    {
        return false;
    }
    store->hMutex = hMutex;
    // set crypto context data
    RandBuf(&store->Key[0], CRYPTO_KEY_SIZE);
    RandBuf(&store->IV[0], CRYPTO_IV_SIZE);
    return true;
}

static errno loadArguments(ArgumentStore* store, Context* context)
{
    uintptr stub = (uintptr)(GetFuncAddr(&Argument_Stub));
    byte*   addr = (byte*)(stub + ARG_OFFSET_FIRST_ARG);
    uint32  size = *(uint32*)(stub + ARG_OFFSET_ARGS_SIZE);
    // allocate memory page for store them
    uint32 pageSize = ((size / context->PageSize) + 1) * context->PageSize;
    void* mem = store->VirtualAlloc(NULL, pageSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (mem == NULL)
    {
        return ERR_ARGUMENT_ALLOC_MEM;
    }
    store->Address = mem;
    store->Size    = pageSize;
    store->NumArgs = *(uint32*)(stub + ARG_OFFSET_NUM_ARGS);
    // copy encrypted arguments to new memory page
    mem_copy(mem, addr, size);
    // check decrypted data
    uint32 checksum = 0;
    // decrypted arguments
    byte* key  = (byte*)(stub + ARG_OFFSET_CRYPTO_KEY);
    byte* data = (byte*)mem;
    byte  last = 0xFF;
    uint  keyIdx = 0;
    for (uint32 i = 0; i < size; i++)
    {
        byte b = *data ^ last;
        b ^= *(key + keyIdx);
        *data = b;
        last = b;
        // update checksum
        checksum += checksum << 1;
        checksum += b;
        // update key index
        keyIdx++;
        if (keyIdx >= ARG_CRYPTO_KEY_SIZE)
        {
            keyIdx = 0;
        }
        data++;
    }
    // clean argument stub after decrypt
    if (!context->NotEraseInstruction)
    {
        RandBuf((byte*)stub, ARG_HEADER_SIZE + size);
    }
    // validate checksum
    uint32 expected = *(uint32*)(stub + ARG_OFFSET_CHECKSUM);
    if (checksum != expected)
    {
        return ERR_ARGUMENT_CHECKSUM;
    }
    dbg_log("[argument]", "mem page: 0x%zX", store->Address);
    dbg_log("[argument]", "num args: %zu", store->NumArgs);
    return NO_ERROR;
}

__declspec(noinline)
static void eraseStoreMethods(Context* context)
{
    if (context->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&initStoreAPI));
    uintptr end   = (uintptr)(GetFuncAddr(&eraseStoreMethods));
    uintptr size  = end - begin;
    RandBuf((byte*)begin, (int64)size);
}

__declspec(noinline)
static void cleanStore(ArgumentStore* store)
{
    if (store->Address != NULL)
    {
        RandBuf(store->Address, (int64)(store->Size));
    }
    if (store->VirtualFree != NULL && store->Address != NULL)
    {
        store->VirtualFree(store->Address, 0, MEM_RELEASE);
    }
    if (store->CloseHandle != NULL && store->hMutex != NULL)
    {
        store->CloseHandle(store->hMutex);
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
bool AS_GetValue(uint index, void* value, uint32* size)
{
    ArgumentStore* store = getStorePointer();

    // check argument index is valid
    if (index + 1 > store->NumArgs)
    {
        return false;
    }

    if (!AS_Lock())
    {
        return false;
    }

    // calculate the offset to target argument
    uint32 offset = 0;
    bool found = false;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        if (i != index)
        {
            // skip argument size and data
            offset += 4 + *(uint32*)(store->Address + offset);
            continue;
        }
        // copy argument data to value pointer
        void* src = store->Address + offset + 4;
        uint32 sz = *(uint32*)(store->Address + offset);
        mem_copy(value, src, sz);
        // receive argument size
        if (size != NULL)
        {
            *size = sz;
        }
        found = true;
        break;
    }

    if (!AS_Unlock())
    {
        return false;
    }
    return found;
}

__declspec(noinline)
bool AS_GetPointer(uint index, void** pointer, uint32* size)
{
    ArgumentStore* store = getStorePointer();

    // check argument index is valid
    if (index + 1 > store->NumArgs)
    {
        return false;
    }

    if (!AS_Lock())
    {
        return false;
    }

    // calculate the offset to target argument
    uint32 offset = 0;
    bool found = false;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        if (i != index)
        {
            // skip argument size and data
            offset += 4 + *(uint32*)(store->Address + offset);
            continue;
        }
        // get argument size
        uint32 sz = *(uint32*)(store->Address + offset);
        // receive argument pointer
        if (sz != 0)
        {
            *pointer = (void*)(store->Address + offset + 4);
        } else {
            *pointer = NULL;
        }
        // receive argument size
        if (size != NULL)
        {
            *size = sz;
        }
        found = true;
        break;
    }

    if (!AS_Unlock())
    {
        return false;
    }
    return found;
}

__declspec(noinline)
bool AS_Erase(uint index)
{
    ArgumentStore* store = getStorePointer();

    // check argument index is valid
    if (index + 1 > store->NumArgs)
    {
        return false;
    }

    if (!AS_Lock())
    {
        return false;
    }

    // calculate the offset to target argument
    uint32 offset = 0;
    bool   found  = false;
    for (uint32 i = 0; i < store->NumArgs; i++)
    {
        if (i != index)
        {
            // skip argument size and data
            offset += 4 + *(uint32*)(store->Address + offset);
            continue;
        }
        byte*  addr = store->Address + offset;
        uint32 size = *(uint32*)(store->Address + offset);
        RandBuf(addr, (int64)(4+size));
        found = true;
        break;
    }

    if (!AS_Unlock())
    {
        return false;
    }
    return found;
}

__declspec(noinline)
void AS_EraseAll()
{
    ArgumentStore* store = getStorePointer();

    RandBuf(store->Address, store->Size);
}

__declspec(noinline)
bool AS_Lock()
{
    ArgumentStore* store = getStorePointer();

    uint32 event = store->WaitForSingleObject(store->hMutex, INFINITE);
    return event == WAIT_OBJECT_0;
}

__declspec(noinline)
bool AS_Unlock()
{
    ArgumentStore* store = getStorePointer();

    return store->ReleaseMutex(store->hMutex);
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

    // free memory page
    RandBuf(store->Address, store->Size);
    if (!store->VirtualFree(store->Address, 0, MEM_RELEASE) && errno == NO_ERROR)
    {
        errno = ERR_ARGUMENT_FREE_MEM;
    }

    // close mutex
    if (!store->CloseHandle(store->hMutex) && errno == NO_ERROR)
    {
        errno = ERR_ARGUMENT_CLOSE_MUTEX;
    }

    // recover instructions
    if (store->NotEraseInstruction)
    {
        if (!recoverStorePointer(store) && errno == NO_ERROR)
        {
            errno = ERR_ARGUMENT_RECOVER_INST;
        }
    }
    return errno;
}
