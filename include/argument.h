#ifndef ARGUMENT_H
#define ARGUMENT_H

#include "c_types.h"
#include "context.h"
#include "errno.h"

typedef void* (*ArgGet_t)(uint index);
typedef errno (*ArgEncrypt_t)();
typedef errno (*ArgDecrypt_t)();
typedef errno (*ArgClean_t)();

typedef struct {
    ArgGet_t Get;

    ArgEncrypt_t Encrypt;
    ArgDecrypt_t Decrypt;
    ArgClean_t   Clean;
} ArgumentStore_M;

ArgumentStore_M* InitArgumentStore(Context* context);

#pragma warning(push)
#pragma warning(disable: 4276)
// reserve stub for store arguments
extern void Args_Stub();
#pragma warning(pop)

#endif // ARGUMENT_H
