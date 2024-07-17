#include "c_types.h"
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

ArgumentStore_M* InitArgumentStore(Context* context)
{

}

static errno loadArguments()
{
    uintptr stub = (uintptr)(&Argument_Stub);
    byte*   key  = (byte*)(stub + ARG_OFFSET_CRYPTO_KEY);
    uint32  size = *(uint32*)(stub + ARG_OFFSET_TOTAL_SIZE);

    return NO_ERROR;
}
