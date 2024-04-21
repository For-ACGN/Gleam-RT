#ifndef CRYPTO_H
#define CRYPTO_H

#include "go_types.h"

#define CRYPTO_IV_SIZE  16
#define CRYPTO_KEY_SIZE 32

// EncryptBuf is used to encrypt data in buffer with 256 bit key.
void EncryptBuf(byte* buf, uint size, byte* key, byte* iv);

// DecryptBuf is used to decrypt data in buffer with 256 bit key.
void DecryptBuf(byte* buf, uint size, byte* key, byte* iv);

#endif // CRYPTO_H
