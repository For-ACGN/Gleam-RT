#ifndef ARGUMENT_H
#define ARGUMENT_H

#include "c_types.h"
#include "context.h"
#include "errno.h"

typedef bool  (*ArgGet_t)(uint index, void** data, uint32* size);
typedef bool  (*ArgErase_t)(uint index);
typedef void  (*ArgEraseAll_t)();

typedef errno (*ArgEncrypt_t)();
typedef errno (*ArgDecrypt_t)();
typedef errno (*ArgClean_t)();

typedef struct {
    ArgGet_t      Get;
    ArgErase_t    Erase;
    ArgEraseAll_t EraseAll;

    ArgEncrypt_t Encrypt;
    ArgDecrypt_t Decrypt;
    ArgClean_t   Clean;
} ArgumentStore_M;

ArgumentStore_M* InitArgumentStore(Context* context);

// reserve stub for store arguments
#pragma warning(push)
#pragma warning(disable: 4276)
extern void Argument_Stub();
#pragma warning(pop)

#endif // ARGUMENT_H
