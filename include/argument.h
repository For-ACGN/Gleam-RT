#ifndef ARGUMENT_H
#define ARGUMENT_H

#include "c_types.h"
#include "context.h"
#include "errno.h"

typedef bool (*ArgGetValue_t)(uint index, void* value, uint32* size);
typedef bool (*ArgGetPointer_t)(uint index, void** pointer, uint32* size);
typedef bool (*ArgErase_t)(uint index);
typedef void (*ArgEraseAll_t)();

typedef bool  (*ArgLock_t)();
typedef bool  (*ArgUnlock_t)();
typedef errno (*ArgEncrypt_t)();
typedef errno (*ArgDecrypt_t)();
typedef errno (*ArgClean_t)();

typedef struct {
    ArgGetValue_t   GetValue;
    ArgGetPointer_t GetPointer;
    ArgErase_t      Erase;
    ArgEraseAll_t   EraseAll;

    ArgLock_t    Lock;
    ArgUnlock_t  Unlock;
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
