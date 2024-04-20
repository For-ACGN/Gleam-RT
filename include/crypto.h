#ifndef CRYPTO_H
#define CRYPTO_H

#include "go_types.h"

#define ENCRYPT_KEY_SIZE 32

// EncryptBuf is used to encrypt data in buffer with 256 bit key.
void EncryptBuf(byte* buf, uint size, byte* key);

// DecryptBuf is used to decrypt data in buffer with 256 bit key.
void DecryptBuf(byte* buf, uint size, byte* key);

#endif // CRYPTO_H
